#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Full Gold Rush, demurrage, staking, and wallet-policy integration soak.

Extended, on-demand soak (NOT a default-suite test). It composes the
per-feature soaks into a single two-node run and adds cross-cutting invariants
that the individual tests cannot assert alone:

  * feature_quantum_demurrage_soak.py proves 50-actor decay/lock + per-pool cap bootstrap, but is
    single-node, never stakes, and has no independent supply oracle.
  * feature_quantum_demurrage.py proves 2-node decayed-coin PoS staking + a full
    getcirculatingsupply replay oracle, but at ~7 actors with no pool/scale.

This soak runs BOTH together on two nodes and asserts, at every phase boundary, that:
  - No inflation: nominal UTXO amount == gettxoutsetinfo total_amount, recomputed by an
    independent block-walk oracle (this is the real inflation proof). Shadow `claimed_amount`
    is bounded [0, SHADOW_MAX_EMISSION] as a secondary cross-node smoke check (consensus already
    hard-caps it, so that check cannot fail by design).
  - Demurrage burn is real and matches an independent block-walk recompute of every UTXO.
  - A demurrage-DECAYED tiered staking output still produces a coinstake that the SECOND
    node validates as an end-to-end staking proof.
  - Both nodes agree on FULL state, not just the tip: gettxoutsetinfo muhash,
    getcirculatingsupply, and getgoldrushstate are identical across node[0] and node[1].
  - Dormant actors decay to lock; active actors refresh (sweeping effective value) and never
    lock; cold-stake principal stays exempt and fully intact.
  - dumptxoutset over the live demurrage+shadow+coldstake UTXO set succeeds (A5 marker-skip).

The helper set is intentionally shared with the focused demurrage and staking
tests where possible, while this test adds read-only cross-node agreement and
independent no-inflation checks.
"""

from decimal import Decimal
import hashlib
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 5_008
COIN = 100_000_000
SHADOW_MAX_EMISSION = 51_437_700 * COIN          # src/shadow.h cap constant (verified)
DEMURRAGE_PPM = 1_000_000
DEMURRAGE_BLOCKS_PER_MONTH = 4
DEMURRAGE_GRACE_BLOCKS = 6 * DEMURRAGE_BLOCKS_PER_MONTH      # 24
DEMURRAGE_ZERO_BLOCKS = 24 * DEMURRAGE_BLOCKS_PER_MONTH      # 96
DEMURRAGE_DECAY_WINDOW_BLOCKS = DEMURRAGE_ZERO_BLOCKS - DEMURRAGE_GRACE_BLOCKS
ML_DSA_PUBLICKEY_BYTES = 1312
ML_DSA_SIGNATURE_BYTES = 2420
QQATTEST_TAG = b"QQATTEST"
VAULT_7D_BLOCKS = 9450
KERNEL_STAKE_AMOUNT = Decimal("12000")
FEE_AMOUNT = Decimal("1")
DIRECT_AMOUNT = Decimal("2")
COLD_BOOTSTRAP_AMOUNT = Decimal("100")
COLD_SMALL_AMOUNT = Decimal("1")
QUANTUM_SPEND_FEE = Decimal("0.01")
N_DORMANT = 20
N_ACTIVE = 20
N_COLD = 10
SOAK_BLOCKS = 36 * DEMURRAGE_BLOCKS_PER_MONTH               # ~3 compressed years
ACTIVE_REFRESH_INTERVAL = 4 * DEMURRAGE_BLOCKS_PER_MONTH


class QuantumIntegrationSoakTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = [
            "-txindex=1",
            "-staketimio=50",
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
            "-qqstaketierheight=1",
            "-qqstakesplitheight=1",
            "-qqdemurrageheight=1",
            "-qqdemurrageblockspermonth=4",
        ]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # --- mocktime + two-node mining (proven) --------------------------------
    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _generate(self, count, address):
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(self.nodes[0], 1, address, sync_fun=self.no_op))
            self._bump_mocktime()
        self.sync_blocks(self.nodes)
        return hashes

    def _mine_until_demurrage_active(self, address, max_blocks=24):
        node = self.nodes[0]
        for _ in range(max_blocks):
            supply = node.getcirculatingsupply()
            final_lockout = node.getquantumquasarinfo()["phase"] == "final_lockout"
            assert_equal(supply["demurrage_active"], final_lockout)
            self._assert_nodes_agree()
            if supply["demurrage_active"]:
                return supply
            self._generate(1, address)
        raise AssertionError("timed out waiting for demurrage/final-lockout atomic MTP activation")

    def _one_output(self, wallet, address, min_conf=1):
        utxos = wallet.listunspent(min_conf, 9999999, [address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    # --- proven kernel-search PoS staking (feature_quantum_demurrage.py) -----
    def _staking_inputs(self, wallet, address):
        return [{"txid": utxo["txid"], "vout": utxo["vout"]}
                for utxo in wallet.listunspent(1, 9999999, [address])]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "kernel staking wallet must have mature inputs"
        for _ in range(30000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic demurrage-aware staking kernel")

    def _stake_block(self, wallet, stake_address):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet, stake_address)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
            block_hash = node.getbestblockhash()
            self.sync_blocks(self.nodes)
            assert_equal(self.nodes[1].getbestblockhash(), block_hash)
            block = node.getblock(block_hash, 2)
            assert "proof-of-stake" in block["flags"]
            return block_hash, block
        finally:
            wallet.staking(False)

    # --- actor + spend helpers (feature_quantum_demurrage_soak.py) -----------
    def _wallet_output(self, wallet, address):
        matches = [o for o in wallet.getdemurragewalletinfo()["outputs"] if o["address"] == address]
        assert_equal(len(matches), 1)
        return matches[0]

    def _signed_quantum_spend(self, wallet, address, destination):
        node = self.nodes[0]
        utxo = self._one_output(wallet, address)
        # A demurrage-decayed input may only fund up to its EFFECTIVE value: sizing the
        # output off nominal would exceed value-in and fail bad-txns-in-belowout. The wallet
        # reports the spend-height effective value (evaluated at tip+1, the inclusion height),
        # so size off it. When demurrage is inactive/young, effective == nominal (no change).
        effective = Decimal(str(self._wallet_output(wallet, address)["effective_amount"]))
        amount = effective - QUANTUM_SPEND_FEE
        assert_greater_than(amount, Decimal("0"))
        raw = node.createrawtransaction([{"txid": utxo["txid"], "vout": utxo["vout"]}],
                                        [{destination: amount}])
        key = wallet.dumpquantumkey(address)
        signed = node.signrawtransactionwithquantumkey(
            raw, [{"public_key": key["public_key"], "private_key": key["private_key"]}])
        assert_equal(signed["complete"], True)
        return node.sendrawtransaction(signed["hex"])

    def _new_cold_actor(self, owner, staker, label, amount):
        staker_key = staker.dumpquantumkey(staker.getnewquantumaddress()["address"])
        delegation = owner.getnewquantumcoldstakingaddress(staker_key["public_key"], label)
        owner_key = owner.dumpquantumkey(delegation["owner_quantum_address"])
        return {"address": delegation["address"], "staker_pubkey": staker_key["public_key"],
                "owner_pubkey": owner_key["public_key"], "amount": amount, "utxo": None}

    # --- proven independent supply oracle (feature_quantum_demurrage.py) ------
    def _amount_to_sats(self, amount):
        return int((Decimal(str(amount)) * COIN).to_integral_value())

    def _sats_to_amount(self, sats):
        return Decimal(sats) / COIN

    def _remaining_ppm(self, inactive_blocks):
        if inactive_blocks <= DEMURRAGE_GRACE_BLOCKS:
            return DEMURRAGE_PPM
        if inactive_blocks >= DEMURRAGE_ZERO_BLOCKS:
            return 0
        elapsed = inactive_blocks - DEMURRAGE_GRACE_BLOCKS
        t_ppm = (elapsed * DEMURRAGE_PPM) // DEMURRAGE_DECAY_WINDOW_BLOCKS
        return DEMURRAGE_PPM - ((t_ppm * t_ppm) // DEMURRAGE_PPM)

    def _read_script_pushes(self, script_hex):
        script = bytes.fromhex(script_hex)
        pushes = []
        cursor = 0
        while cursor < len(script):
            opcode = script[cursor]
            cursor += 1
            if opcode <= 75:
                size = opcode
            elif opcode == 0x4c:
                size = script[cursor]; cursor += 1
            elif opcode == 0x4d:
                size = int.from_bytes(script[cursor:cursor + 2], "little"); cursor += 2
            elif opcode == 0x4e:
                size = int.from_bytes(script[cursor:cursor + 4], "little"); cursor += 4
            else:
                pushes.append((opcode, None)); continue
            pushes.append((opcode, script[cursor:cursor + size]))
            cursor += size
        return pushes

    def _quantum_key_hash_for_script(self, script_hex):
        script = bytes.fromhex(script_hex)
        if len(script) == 34 and script[0] == 0x60 and script[1] == 0x20:
            return script[2:34]
        if len(script) == 42 and script[0] == 0x60 and script[1] == 0x28:
            return script[10:42]
        return None

    def _attestation_key_hash(self, script_hex):
        pushes = self._read_script_pushes(script_hex)
        if len(pushes) != 3 or pushes[0] != (0x6a, None) or pushes[1][1] != QQATTEST_TAG:
            return None
        payload = pushes[2][1]
        expected_size = 1 + 32 + 4 + ML_DSA_PUBLICKEY_BYTES + ML_DSA_SIGNATURE_BYTES
        if payload is None or len(payload) != expected_size or payload[0] != 1:
            return None
        pubkey_start = 1 + 32 + 4
        pubkey = payload[pubkey_start:pubkey_start + ML_DSA_PUBLICKEY_BYTES]
        return hashlib.sha256(pubkey).digest()

    def _replay_supply_oracle(self, supply):
        node = self.nodes[0]
        height = supply["height"]
        effective_activation = supply["demurrage_effective_activation_height"]
        utxos = {}
        latest_attestation = {}
        parent_mtp = node.getblockheader(node.getblockhash(0))["mediantime"]
        for block_height in range(1, height + 1):
            block = node.getblock(node.getblockhash(block_height), 2)
            block_active = block_height >= effective_activation and parent_mtp > MIGRATION_DEADLINE_TIME
            for tx in block["tx"]:
                for txin in tx["vin"]:
                    if "coinbase" not in txin:
                        utxos.pop((txin["txid"], txin["vout"]), None)
                for vout in tx["vout"]:
                    script_hex = vout["scriptPubKey"]["hex"]
                    if script_hex.startswith("6a"):
                        continue
                    utxos[(tx["txid"], vout["n"])] = {
                        "value": self._amount_to_sats(vout["value"]),
                        "height": block_height, "script": script_hex}
                if block_active:
                    for vout in tx["vout"]:
                        key_hash = self._attestation_key_hash(vout["scriptPubKey"]["hex"])
                        if key_hash is not None:
                            latest_attestation[key_hash] = block_height
            parent_mtp = block["mediantime"]

        nominal = circulating = decayed_txouts = locked_txouts = 0
        for coin in utxos.values():
            nominal += coin["value"]
            effective = coin["value"]
            key_hash = self._quantum_key_hash_for_script(coin["script"])
            if supply["demurrage_active"] and key_hash is not None:
                effective_last_active = max(coin["height"], effective_activation,
                                            latest_attestation.get(key_hash, 0))
                inactive_blocks = max(0, height - effective_last_active)
                remaining = self._remaining_ppm(inactive_blocks)
                effective = (coin["value"] * remaining) // DEMURRAGE_PPM
                if remaining == 0:
                    locked_txouts += 1
                if effective < coin["value"]:
                    decayed_txouts += 1
            circulating += effective
        return {"nominal_amount": self._sats_to_amount(nominal),
                "circulating_amount": self._sats_to_amount(circulating),
                "decayed_amount": self._sats_to_amount(nominal - circulating),
                "decayed_txouts": decayed_txouts, "locked_txouts": locked_txouts}

    def _assert_supply_matches_txoutset(self, label):
        supply = self.nodes[0].getcirculatingsupply()
        txoutset = self.nodes[0].gettxoutsetinfo()
        assert_equal(supply["height"], txoutset["height"])
        assert_equal(supply["bestblock"], txoutset["bestblock"])
        # the independent monetary invariant: nominal == total UTXO value (no inflation)
        assert_equal(Decimal(supply["nominal_amount"]), Decimal(str(txoutset["total_amount"])))
        assert_equal(Decimal(supply["circulating_amount"]) + Decimal(supply["decayed_amount"]),
                     Decimal(supply["nominal_amount"]))
        replay = self._replay_supply_oracle(supply)
        assert_equal(Decimal(supply["nominal_amount"]), replay["nominal_amount"])
        assert_equal(Decimal(supply["circulating_amount"]), replay["circulating_amount"])
        assert_equal(Decimal(supply["decayed_amount"]), replay["decayed_amount"])
        assert_equal(supply["decayed_txouts"], replay["decayed_txouts"])
        assert_equal(supply["locked_txouts"], replay["locked_txouts"])
        self.log.info(f"  [{label}] oracle ok: nominal={supply['nominal_amount']} "
                      f"decayed={supply['decayed_amount']} locked={supply['locked_txouts']}")

    # --- ADDED invariants (cross-node + shadow cap; RPC fields verified vs src) -
    def _assert_shadow_cap(self, label):
        # Secondary smoke check only: consensus already hard-caps claimed_amount at
        # SHADOW_MAX_EMISSION, so this cannot fail by design. The REAL no-inflation proof is
        # _assert_supply_matches_txoutset (nominal == gettxoutsetinfo total_amount). This just
        # confirms the field reads sanely (0 <= claimed <= cap) at each checkpoint.
        claimed = int(self.nodes[0].getgoldrushstate()["claimed_amount"])
        assert 0 <= claimed <= SHADOW_MAX_EMISSION, f"{label}: shadow emission {claimed} out of [0, cap]"

    def _assert_nodes_agree(self):
        self.sync_blocks(self.nodes)
        n0, n1 = self.nodes
        assert_equal(n0.getbestblockhash(), n1.getbestblockhash())
        assert_equal(n0.gettxoutsetinfo("muhash")["muhash"], n1.gettxoutsetinfo("muhash")["muhash"])
        assert_equal(n0.getcirculatingsupply(), n1.getcirculatingsupply())
        assert_equal(n0.getgoldrushstate(), n1.getgoldrushstate())

    # --- the soak ------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        for node_rpc in self.nodes:
            node_rpc.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Phase 0: wallets + mature pre-deadline funding (50 actors + a 12000 tiered staker)")
        for name in ("funder", "owner", "staker_a", "staker_b", "staker_c", "kernel_staker"):
            node.createwallet(wallet_name=name)
        funder = node.get_wallet_rpc("funder")
        owner = node.get_wallet_rpc("owner")
        stakers = tuple(node.get_wallet_rpc(n) for n in ("staker_a", "staker_b", "staker_c"))
        kernel_staker = node.get_wallet_rpc("kernel_staker")
        for w in (funder, owner, kernel_staker, *stakers):
            w.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        mining_address = node.createquantumkey()["address"]
        kernel_stake_address = kernel_staker.getnewquantumstakeaddress("kernel", VAULT_7D_BLOCKS)["address"]
        kernel_fee_address = kernel_staker.getnewquantumaddress()["address"]

        # early Gold Rush coinbases (heights 1..10) fund the 12000 staker; then mature it
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        self._generate(COINBASE_MATURITY + 2, funder_address)
        assert_equal(node.getblockcount() >= 12, True)
        kernel_stake_txid = funder.sendtoaddress(kernel_stake_address, KERNEL_STAKE_AMOUNT)
        self._generate(1, funder_address)
        assert_equal(self._one_output(kernel_staker, kernel_stake_address)["txid"], kernel_stake_txid)
        self._generate(COINBASE_MATURITY, funder_address)
        kernel_stake_utxo = self._one_output(kernel_staker, kernel_stake_address)
        funder.sendtoaddress(kernel_fee_address, FEE_AMOUNT)
        self._generate(1, funder_address)

        # 50 demurrage actors funded in one transaction
        dormant = [funder.getnewquantumaddress()["address"] for _ in range(N_DORMANT)]
        active = [funder.getnewquantumaddress()["address"] for _ in range(N_ACTIVE)]
        cold = [self._new_cold_actor(owner, stakers[0], "bootstrap-a", COLD_BOOTSTRAP_AMOUNT)]
        for i in range(1, N_COLD):
            cold.append(self._new_cold_actor(owner, stakers[i % len(stakers)], f"cold-{i}", COLD_SMALL_AMOUNT))
        outputs = {a: DIRECT_AMOUNT for a in dormant + active}
        for c in cold:
            outputs[c["address"]] = c["amount"]
        funding_txid = funder.sendmany("", outputs)
        self._generate(1, funder_address)
        for c in cold:
            c["utxo"] = self._one_output(owner, c["address"])
            assert_equal(c["utxo"]["txid"], funding_txid)
        self._assert_nodes_agree()

        self.log.info("Phase 1: demurrage inert before the migration deadline; supply oracle holds")
        assert node.getblockheader(node.getbestblockhash())["time"] <= MIGRATION_DEADLINE_TIME
        assert_equal(node.getcirculatingsupply()["demurrage_active"], False)
        self._assert_supply_matches_txoutset("pre-deadline")
        self._assert_shadow_cap("pre-deadline")

        self.log.info("Phase 2: cross the migration deadline -> demurrage activates after the post-migration guard")
        self._set_mocktime(MIGRATION_DEADLINE_TIME + 16)
        self._mine_until_demurrage_active(mining_address)
        self._assert_nodes_agree()

        self.log.info("Phase 3: per-pool cap bootstrap pool-cap selection across the cold-stake actors")
        first = cold[0]
        claim = node.submitquantumpoolclaim(first["staker_pubkey"], [{
            "txid": first["utxo"]["txid"], "vout": first["utxo"]["vout"],
            "owner_pubkey": first["owner_pubkey"]}])
        assert_equal(claim["accepted"], True)
        bootstrap = owner.getnewquantumcoldstakingaddress(first["staker_pubkey"], "bootstrap-over-cap-ok",
                                                          {"delegation_amount": Decimal("1")})
        assert_equal(bootstrap["pool_cap_preflight"]["would_exceed_cap"], True)
        assert_equal(bootstrap["pool_cap_preflight"]["cap_filter_unlocked"], True)
        for actor in cold[1:]:
            c = node.submitquantumpoolclaim(actor["staker_pubkey"], [{
                "txid": actor["utxo"]["txid"], "vout": actor["utxo"]["vout"],
                "owner_pubkey": actor["owner_pubkey"]}])
            assert_equal(c["accepted"], True)

        self.log.info("Phase 4: a demurrage-DECAYED tiered output stakes a block the second node validates")
        kernel_attestation = kernel_staker.senddemurrageattestation(kernel_stake_address)
        assert_equal(kernel_attestation["txid"] in node.getrawmempool(), True)
        self._generate(1, mining_address)
        # age the (now clock-reset) staking output past the 6-month grace but before the 24-month lock
        self._generate(DEMURRAGE_GRACE_BLOCKS + 12, mining_address)
        kernel_output = self._wallet_output(kernel_staker, kernel_stake_address)
        assert_equal(kernel_output["locked"], False)
        assert_greater_than(DEMURRAGE_PPM, kernel_output["remaining_ppm"])
        assert_greater_than(Decimal(kernel_output["burned_if_spent_amount"]), Decimal("0"))
        self.sync_blocks(self.nodes)
        self._sync_mocktime_to_tip()
        block_hash, block = self._stake_block(kernel_staker, kernel_stake_address)
        coinstake = block["tx"][1]
        assert_equal(coinstake["vin"][0]["txid"], kernel_stake_utxo["txid"])
        assert_equal(coinstake["vin"][0]["vout"], kernel_stake_utxo["vout"])
        assert_equal(self.nodes[1].getblock(block_hash)["confirmations"], 1)
        self._assert_supply_matches_txoutset("post-decayed-stake")
        self._assert_nodes_agree()

        self.log.info("Phase 5: three compressed years; active actors refresh, dormant actors decay")
        for step in range(1, SOAK_BLOCKS + 1):
            if step % ACTIVE_REFRESH_INTERVAL == 0:
                refreshed = []
                for address in active:
                    dst = funder.getnewquantumaddress()["address"]
                    self._signed_quantum_spend(funder, address, dst)
                    refreshed.append(dst)
                active = refreshed
            self._generate(1, mining_address)
            if step % (6 * DEMURRAGE_BLOCKS_PER_MONTH) == 0:
                self._assert_supply_matches_txoutset(f"soak-{step}")
                self._assert_shadow_cap(f"soak-{step}")
                self._assert_nodes_agree()

        self.log.info("Phase 6: dormant locked; active whole; cold-stake principal exempt + intact")
        info = funder.getdemurragewalletinfo()
        assert_equal(info["demurrage_active"], True)
        for address in dormant:
            output = self._wallet_output(funder, address)
            assert_equal(output["locked"], True)
            assert_equal(output["remaining_ppm"], 0)
            assert_equal(Decimal(output["effective_amount"]), Decimal("0E-8"))
        for address in active:
            output = self._wallet_output(funder, address)
            assert_equal(output["locked"], False)
            assert_equal(Decimal(output["burned_if_spent_amount"]), Decimal("0E-8"))
        for actor in cold:
            txout = node.gettxout(actor["utxo"]["txid"], actor["utxo"]["vout"], False)
            assert txout is not None
            assert_equal(Decimal(str(txout["value"])), actor["amount"])
        # a locked dormant coin cannot be spent (hard 24-month lock)
        locked_utxo = self._one_output(funder, dormant[0])
        raw = node.createrawtransaction([{"txid": locked_utxo["txid"], "vout": locked_utxo["vout"]}],
                                        [{funder.getnewquantumaddress()["address"]: DIRECT_AMOUNT - QUANTUM_SPEND_FEE}])
        key = funder.dumpquantumkey(dormant[0])
        locked_spend = node.signrawtransactionwithquantumkey(
            raw, [{"public_key": key["public_key"], "private_key": key["private_key"]}])
        # signing a locked coin completes (the lock is enforced at send, not sign); assert that
        # so the -26 below catches the lock, not a signing regression masquerading as a pass
        assert_equal(locked_spend["complete"], True)
        assert_raises_rpc_error(-26, "bad-txns-spends-locked-coin", node.sendrawtransaction, locked_spend["hex"])

        supply = node.getcirculatingsupply()
        assert_greater_than(supply["locked_txouts"], N_DORMANT - 1)
        assert_greater_than(Decimal(supply["decayed_amount"]), Decimal("0"))
        self._assert_supply_matches_txoutset("final")
        self._assert_shadow_cap("final")
        self._assert_nodes_agree()

        self.log.info("Phase 7: dumptxoutset over the live demurrage+shadow+coldstake set (A5 marker-skip)")
        dump = node.dumptxoutset("integration_soak_utxos.dat")
        assert_greater_than(dump["coins_written"], 0)

        self.log.info("Integration soak complete: no inflation, burn matches oracle, "
                      "decayed-coin staking validated cross-node, both nodes fully agree.")


if __name__ == "__main__":
    QuantumIntegrationSoakTest().main()
