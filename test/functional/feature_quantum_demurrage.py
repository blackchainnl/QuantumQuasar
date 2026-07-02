#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise demurrage activation and effective-value behavior.

The consensus unit tests cover the fixed-point curve and attestation index. This
functional test proves the live node wiring: a low configured demurrage height
does not activate decay before the quantum migration deadline, the Gold Rush
height clamp is reflected through RPC, and decay begins only after the post-
migration guard is satisfied. It also proves manual and automatic liveness
attestations, effective-value recomputation, sweep realization, locked-spend
rejection, and gate-off parity on the same aged chain.
"""

from decimal import Decimal
import hashlib
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 5_008
QUANTUM_AMOUNT = Decimal("25")
ATTEST_AMOUNT = Decimal("11")
LOCK_AMOUNT = Decimal("7")
FEE_AMOUNT = Decimal("1")
AUTO_AMOUNT = Decimal("9")
AUTO_FEE_SOURCE_AMOUNT = Decimal("5")
KERNEL_STAKE_AMOUNT = Decimal("12000")
COIN = 100_000_000
DEMURRAGE_PPM = 1_000_000
DEMURRAGE_BLOCKS_PER_MONTH = 4
DEMURRAGE_GRACE_BLOCKS = 6 * DEMURRAGE_BLOCKS_PER_MONTH
DEMURRAGE_ZERO_BLOCKS = 24 * DEMURRAGE_BLOCKS_PER_MONTH
DEMURRAGE_DECAY_WINDOW_BLOCKS = DEMURRAGE_ZERO_BLOCKS - DEMURRAGE_GRACE_BLOCKS
ML_DSA_PUBLICKEY_BYTES = 1312
ML_DSA_SIGNATURE_BYTES = 2420
QQATTEST_TAG = b"QQATTEST"
VAULT_7D_BLOCKS = 9450


class QuantumDemurrageTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.active_args = [
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
        self.gate_off_args = [
            "-txindex=1",
            "-staketimio=50",
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
            "-qqstaketierheight=1",
            "-qqstakesplitheight=1",
            "-qqdemurrageblockspermonth=4",
        ]
        self.extra_args = [self.active_args, self.active_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

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
        return hashes

    def _assert_lockout_demurrage_atomic(self):
        node = self.nodes[0]
        info = node.getquantumquasarinfo()
        supply = node.getcirculatingsupply()
        final_lockout = info["phase"] == "final_lockout"
        assert_equal(supply["demurrage_active"], final_lockout)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], final_lockout)
        return supply

    def _mine_until_demurrage_active(self, address, max_blocks=24):
        for _ in range(max_blocks):
            supply = self._assert_lockout_demurrage_atomic()
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

    def _staking_inputs(self, wallet, address):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999, [address])
        ]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "demurrage kernel staking wallet must have mature inputs"
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

    def _wallet_output(self, wallet, address):
        info = wallet.getdemurragewalletinfo()
        matches = [output for output in info["outputs"] if output["address"] == address]
        assert_equal(len(matches), 1)
        return info, matches[0]

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

    def _assert_output_recomputes(self, output):
        remaining = self._remaining_ppm(output["inactive_blocks"])
        nominal_sats = self._amount_to_sats(output["nominal_amount"])
        effective_sats = (nominal_sats * remaining) // DEMURRAGE_PPM
        assert_equal(output["remaining_ppm"], remaining)
        assert_equal(Decimal(output["effective_amount"]), self._sats_to_amount(effective_sats))
        assert_equal(Decimal(output["burned_if_spent_amount"]), self._sats_to_amount(nominal_sats - effective_sats))

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
                size = script[cursor]
                cursor += 1
            elif opcode == 0x4d:
                size = int.from_bytes(script[cursor:cursor + 2], "little")
                cursor += 2
            elif opcode == 0x4e:
                size = int.from_bytes(script[cursor:cursor + 4], "little")
                cursor += 4
            else:
                pushes.append((opcode, None))
                continue
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
            block_hash = node.getblockhash(block_height)
            block = node.getblock(block_hash, 2)
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
                        "height": block_height,
                        "script": script_hex,
                    }
                if block_active:
                    for vout in tx["vout"]:
                        key_hash = self._attestation_key_hash(vout["scriptPubKey"]["hex"])
                        if key_hash is not None:
                            latest_attestation[key_hash] = block_height
            parent_mtp = block["mediantime"]

        nominal = 0
        circulating = 0
        decayed_txouts = 0
        locked_txouts = 0
        for coin in utxos.values():
            nominal += coin["value"]
            effective = coin["value"]
            key_hash = self._quantum_key_hash_for_script(coin["script"])
            if supply["demurrage_active"] and key_hash is not None:
                effective_last_active = max(coin["height"], effective_activation, latest_attestation.get(key_hash, 0))
                inactive_blocks = max(0, height - effective_last_active)
                remaining = self._remaining_ppm(inactive_blocks)
                effective = (coin["value"] * remaining) // DEMURRAGE_PPM
                if remaining == 0:
                    locked_txouts += 1
                if effective < coin["value"]:
                    decayed_txouts += 1
            circulating += effective

        return {
            "nominal_amount": self._sats_to_amount(nominal),
            "circulating_amount": self._sats_to_amount(circulating),
            "decayed_amount": self._sats_to_amount(nominal - circulating),
            "decayed_txouts": decayed_txouts,
            "locked_txouts": locked_txouts,
        }

    def _assert_supply_matches_txoutset(self, supply):
        txoutset = self.nodes[0].gettxoutsetinfo()
        assert_equal(supply["height"], txoutset["height"])
        assert_equal(supply["bestblock"], txoutset["bestblock"])
        # getcirculatingsupply walks raw coin entries, including zero-value
        # protocol metadata coins that gettxoutsetinfo excludes from txouts.
        # The independent monetary invariant is the nominal amount.
        assert_equal(Decimal(supply["nominal_amount"]), Decimal(str(txoutset["total_amount"])))
        assert_equal(Decimal(supply["circulating_amount"]) + Decimal(supply["decayed_amount"]), Decimal(supply["nominal_amount"]))
        replay = self._replay_supply_oracle(supply)
        assert_equal(Decimal(supply["nominal_amount"]), replay["nominal_amount"])
        assert_equal(Decimal(supply["circulating_amount"]), replay["circulating_amount"])
        assert_equal(Decimal(supply["decayed_amount"]), replay["decayed_amount"])
        assert_equal(supply["decayed_txouts"], replay["decayed_txouts"])
        assert_equal(supply["locked_txouts"], replay["locked_txouts"])

    def _signed_quantum_spend(self, wallet, utxo, destination, fee=Decimal("0.01")):
        node = self.nodes[0]
        amount = Decimal(str(utxo["amount"])) - fee
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        assert_equal(signed["complete"], True)
        return signed["hex"]

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        for node_rpc in self.nodes:
            node_rpc.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Create wallet-owned direct quantum outputs during the migration window")
        node.createwallet(wallet_name="demurrage")
        wallet = node.get_wallet_rpc("demurrage")
        wallet.staking(False)
        node.createwallet(wallet_name="auto_demurrage")
        auto_wallet = node.get_wallet_rpc("auto_demurrage")
        auto_wallet.staking(False)
        node.createwallet(wallet_name="unsafe_fee_demurrage")
        unsafe_wallet = node.get_wallet_rpc("unsafe_fee_demurrage")
        unsafe_wallet.staking(False)
        node.createwallet(wallet_name="kernel_demurrage_staker")
        kernel_staker = node.get_wallet_rpc("kernel_demurrage_staker")
        kernel_staker.staking(False)

        funder_address = wallet.getnewaddress("", "legacy")
        kernel_stake_info = kernel_staker.getnewquantumstakeaddress("demurrage-kernel", VAULT_7D_BLOCKS)
        kernel_stake_address = kernel_stake_info["address"]
        kernel_fee_address = kernel_staker.getnewquantumaddress()["address"]
        quantum_address = wallet.getnewquantumaddress()["address"]
        attest_address = wallet.getnewquantumaddress()["address"]
        lock_address = wallet.getnewquantumaddress()["address"]
        fee_address = wallet.getnewquantumaddress()["address"]
        auto_fee_source_address = wallet.getnewquantumaddress()["address"]
        auto_address = auto_wallet.getnewquantumaddress()["address"]
        unsafe_fee_address = unsafe_wallet.getnewquantumaddress()["address"]
        mining_quantum_address = node.createquantumkey()["address"]

        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        self._generate(COINBASE_MATURITY + 2, funder_address)
        assert_equal(node.getblockcount() >= 12, True)

        kernel_stake_txid = wallet.sendtoaddress(kernel_stake_address, KERNEL_STAKE_AMOUNT)
        self._generate(1, funder_address)
        assert_equal(self._one_output(kernel_staker, kernel_stake_address)["txid"], kernel_stake_txid)
        self._generate(COINBASE_MATURITY, funder_address)
        kernel_stake_utxo = self._one_output(kernel_staker, kernel_stake_address)
        assert_equal(kernel_stake_utxo["txid"], kernel_stake_txid)
        kernel_fee_txid = wallet.sendtoaddress(kernel_fee_address, FEE_AMOUNT)
        self._generate(1, funder_address)
        assert_equal(self._one_output(kernel_staker, kernel_fee_address)["txid"], kernel_fee_txid)

        txid = wallet.sendtoaddress(quantum_address, QUANTUM_AMOUNT)
        attest_txid = wallet.sendtoaddress(attest_address, ATTEST_AMOUNT)
        lock_txid = wallet.sendtoaddress(lock_address, LOCK_AMOUNT)
        fee_txid = wallet.sendtoaddress(fee_address, FEE_AMOUNT)
        auto_txid = wallet.sendtoaddress(auto_address, AUTO_AMOUNT)
        auto_fee_source_txid = wallet.sendtoaddress(auto_fee_source_address, AUTO_FEE_SOURCE_AMOUNT)
        unsafe_fee_txid = wallet.sendtoaddress(unsafe_fee_address, FEE_AMOUNT)
        self._generate(1, funder_address)
        utxo = self._one_output(wallet, quantum_address)
        assert_equal(utxo["txid"], txid)
        assert_equal(self._one_output(wallet, attest_address)["txid"], attest_txid)
        assert_equal(self._one_output(wallet, lock_address)["txid"], lock_txid)
        assert_equal(self._one_output(wallet, fee_address)["txid"], fee_txid)
        assert_equal(self._one_output(auto_wallet, auto_address)["txid"], auto_txid)
        assert_equal(self._one_output(wallet, auto_fee_source_address)["txid"], auto_fee_source_txid)
        assert_equal(self._one_output(unsafe_wallet, unsafe_fee_address)["txid"], unsafe_fee_txid)

        self.log.info("Demurrage stays inert before the migration deadline even with -qqdemurrageheight=1")
        assert node.getblockheader(node.getbestblockhash())["time"] <= MIGRATION_DEADLINE_TIME
        supply = node.getcirculatingsupply()
        self._assert_supply_matches_txoutset(supply)
        assert_equal(supply["demurrage_active"], False)
        assert_equal(supply["demurrage_activation_height"], 1)
        assert_equal(supply["demurrage_effective_activation_height"], 12)
        assert_equal(supply["quantum_migration_deadline_time"], MIGRATION_DEADLINE_TIME)
        assert_equal(supply["demurrage_height_guard_satisfied"], True)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], False)

        wallet_info, output = self._wallet_output(wallet, quantum_address)
        assert_equal(wallet_info["demurrage_active"], False)
        assert_equal(wallet_info["quantum_migration_deadline_time"], MIGRATION_DEADLINE_TIME)
        assert_equal(wallet_info["demurrage_height_guard_satisfied"], True)
        assert_equal(wallet_info["demurrage_post_migration_guard_satisfied"], False)
        assert_equal(output["exemption"], "inactive")
        assert_equal(Decimal(output["effective_amount"]), Decimal(output["nominal_amount"]))
        assert_equal(Decimal(output["burned_if_spent_amount"]), Decimal("0E-8"))
        assert_raises_rpc_error(-4, "demurrage is not active for the next block", wallet.sweepdemurragedecay)

        self.log.info("Demurrage is still inert on a block exactly at the migration deadline")
        self._set_mocktime(MIGRATION_DEADLINE_TIME)
        self._generate(1, funder_address)
        assert_equal(node.getblockheader(node.getbestblockhash())["time"], MIGRATION_DEADLINE_TIME)
        supply = self._assert_lockout_demurrage_atomic()
        self._assert_supply_matches_txoutset(supply)
        assert_equal(supply["demurrage_active"], False)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], False)
        wallet_info, output = self._wallet_output(wallet, quantum_address)
        assert_equal(wallet_info["demurrage_active"], False)
        assert_equal(wallet_info["demurrage_post_migration_guard_satisfied"], False)
        assert_equal(output["exemption"], "inactive")
        assert_equal(Decimal(output["effective_amount"]), Decimal(output["nominal_amount"]))
        assert_equal(Decimal(output["burned_if_spent_amount"]), Decimal("0E-8"))

        self.log.info("Cross the migration deadline; demurrage activates atomically with final lockout once parent MTP passes the guard")
        self._set_mocktime(MIGRATION_DEADLINE_TIME + 16)
        supply = self._mine_until_demurrage_active(mining_quantum_address)
        self._assert_supply_matches_txoutset(supply)
        assert_equal(supply["demurrage_active"], True)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], True)
        assert_equal(node.getquantumquasarinfo()["phase"], "final_lockout")
        wallet_info = wallet.getdemurragewalletinfo()
        assert_equal(wallet_info["demurrage_active"], True)
        assert_equal(wallet_info["demurrage_post_migration_guard_satisfied"], True)

        self.log.info("Manual attestation refreshes one quantum key before decay starts")
        self._generate(12, mining_quantum_address)
        _, attest_output = self._wallet_output(wallet, attest_address)
        assert_equal(attest_output["attestation_due"], True)
        assert_equal(attest_output["burned_if_spent_amount"], Decimal("0E-8"))
        attestation = wallet.senddemurrageattestation(attest_address)
        assert_equal(attestation["txid"] in node.getrawmempool(), True)
        self._generate(1, mining_quantum_address)
        _, attested_output = self._wallet_output(wallet, attest_address)
        assert "latest_attestation_height" in attested_output
        assert_equal(attested_output["exemption"], "attested")
        assert_equal(attested_output["burned_if_spent_amount"], Decimal("0E-8"))

        self.log.info("Preparing a mature quantum staking output for demurrage-aware kernel validation")
        assert_equal(self._one_output(kernel_staker, kernel_fee_address)["txid"], kernel_fee_txid)
        kernel_attestation = kernel_staker.senddemurrageattestation(kernel_stake_address)
        assert_equal(kernel_attestation["txid"] in node.getrawmempool(), True)
        self._generate(1, mining_quantum_address)

        self.log.info("With a compressed regtest month, direct quantum outputs decay after the grace window")
        self._generate(13, mining_quantum_address)
        supply = node.getcirculatingsupply()
        self._assert_supply_matches_txoutset(supply)
        assert_equal(supply["demurrage_active"], True)
        assert_greater_than(supply["decayed_txouts"], 0)
        assert_greater_than(Decimal(supply["decayed_amount"]), Decimal("0"))

        wallet_info, output = self._wallet_output(wallet, quantum_address)
        assert_equal(wallet_info["demurrage_active"], True)
        assert_greater_than(wallet_info["decaying_outputs"], 0)
        assert_equal(output["locked"], False)
        assert_equal(output["exemption"], "")
        assert_greater_than(1_000_000, output["remaining_ppm"])
        assert_greater_than(Decimal(output["burned_if_spent_amount"]), Decimal("0"))
        self._assert_output_recomputes(output)

        _, attested_output = self._wallet_output(wallet, attest_address)
        assert_equal(attested_output["exemption"], "attested")
        assert_equal(attested_output["burned_if_spent_amount"], Decimal("0E-8"))

        self.log.info("A demurrage-decayed quantum staking output still produces a block that a second node validates")
        self._generate(DEMURRAGE_GRACE_BLOCKS - 1, mining_quantum_address)
        _, kernel_output = self._wallet_output(kernel_staker, kernel_stake_address)
        assert_equal(kernel_output["locked"], False)
        assert_greater_than(DEMURRAGE_PPM, kernel_output["remaining_ppm"])
        assert_greater_than(Decimal(kernel_output["burned_if_spent_amount"]), Decimal("0"))
        self.sync_blocks(self.nodes)
        self._sync_mocktime_to_tip()
        demurrage_block_hash, demurrage_block = self._stake_block(kernel_staker, kernel_stake_address)
        demurrage_coinstake = demurrage_block["tx"][1]
        assert_equal(demurrage_coinstake["vin"][0]["txid"], kernel_stake_utxo["txid"])
        assert_equal(demurrage_coinstake["vin"][0]["vout"], kernel_stake_utxo["vout"])
        assert_equal(self.nodes[1].getblock(demurrage_block_hash)["confirmations"], 1)

        self.log.info("Manual attestation refuses to burn decaying quantum value as its fee input")
        _, unsafe_output = self._wallet_output(unsafe_wallet, unsafe_fee_address)
        assert_greater_than(Decimal(unsafe_output["burned_if_spent_amount"]), Decimal("0"))
        unsafe_mempool_before = set(node.getrawmempool())
        assert_raises_rpc_error(
            -4,
            "Unable to select a safe non-decaying fee input for demurrage attestation",
            unsafe_wallet.senddemurrageattestation,
            unsafe_fee_address,
        )
        assert_equal(set(node.getrawmempool()), unsafe_mempool_before)

        self.log.info("Staking-enabled wallets auto-attest due keys with a young quantum fee input")
        auto_fee_address = wallet.getnewquantumaddress()["address"]
        auto_fee_key = wallet.dumpquantumkey(auto_fee_address)
        imported_auto_fee = auto_wallet.importquantumkey(
            auto_fee_key["public_key"],
            auto_fee_key["private_key"],
            "auto-fee",
            False,
        )
        assert_equal(imported_auto_fee["address"], auto_fee_address)
        auto_fee_sweep = wallet.sweepdemurragedecay({
            "source_address": auto_fee_source_address,
            "destination_address": auto_fee_address,
        })
        assert_equal(auto_fee_sweep["txid"] in node.getrawmempool(), True)
        self._generate(1, mining_quantum_address)
        assert_equal(len(auto_wallet.listunspent(1, 9999999, [auto_fee_address])), 1)

        mempool_before = set(node.getrawmempool())
        _, auto_due_output = self._wallet_output(auto_wallet, auto_address)
        assert_equal(auto_due_output["attestation_due"], True)
        assert "latest_attestation_height" not in auto_due_output
        assert_equal(auto_due_output["action"], "senddemurrageattestation recommended")
        auto_wallet.staking(True)
        try:
            self.wait_until(lambda: bool(set(node.getrawmempool()) - mempool_before), timeout=20)
        finally:
            auto_wallet.staking(False)
        auto_attest_txids = list(set(node.getrawmempool()) - mempool_before)
        assert_equal(len(auto_attest_txids), 1)
        auto_attest_txid = auto_attest_txids[0]
        decoded_auto = node.decoderawtransaction(node.getrawtransaction(auto_attest_txid))
        auto_fee_input = decoded_auto["vin"][0]
        assert_equal(auto_fee_input["txid"], auto_fee_sweep["txid"])
        fee_prev_tx = node.decoderawtransaction(node.getrawtransaction(auto_fee_input["txid"]))
        fee_prevout = fee_prev_tx["vout"][auto_fee_input["vout"]]
        fee_prev_address = fee_prevout["scriptPubKey"]["address"]
        assert_equal(node.validateaddress(fee_prev_address)["isquantummigration"], True)
        assert_equal(sum(1 for vout in decoded_auto["vout"] if Decimal(vout["value"]) == Decimal("0E-8") and vout["scriptPubKey"]["type"] == "nulldata"), 1)
        self._generate(1, mining_quantum_address)
        assert_equal(auto_wallet.gettransaction(auto_attest_txid)["confirmations"], 1)
        _, auto_output = self._wallet_output(auto_wallet, auto_address)
        assert "latest_attestation_height" in auto_output
        assert_equal(auto_output["latest_attestation_height"], node.getblockcount())
        assert_equal(auto_output["exemption"], "attested")
        assert_equal(auto_output["burned_if_spent_amount"], Decimal("0E-8"))
        assert_equal(auto_output["attestation_due"], False)

        self.log.info("Dry-run sweep realizes the same decayed output without touching locked coins")
        assert_raises_rpc_error(
            -8,
            "dry_run requires destination_address",
            wallet.sweepdemurragedecay,
            {"source_address": quantum_address, "dry_run": True},
        )
        dry_run_destination = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        sweep = wallet.sweepdemurragedecay({
            "source_address": quantum_address,
            "destination_address": dry_run_destination,
            "dry_run": True,
        })
        assert_equal(sweep["dry_run"], True)
        assert_equal(sweep["destination"], dry_run_destination)
        assert_equal(sweep["selected_inputs"], 1)
        assert_equal(sweep["skipped_locked_outputs"], 0)
        assert_greater_than(Decimal(sweep["burned_amount"]), Decimal("0"))
        assert_greater_than(Decimal(sweep["effective_amount"]), Decimal("0"))
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)

        self.log.info("Broadcast and mine the demurrage sweep through consensus")
        sweep_tx = wallet.sweepdemurragedecay({"source_address": quantum_address})
        assert_equal(sweep_tx["selected_inputs"], 1)
        assert_equal(sweep_tx["txid"] in node.getrawmempool(), True)
        self._generate(1, mining_quantum_address)
        assert_equal(wallet.gettransaction(sweep_tx["txid"])["confirmations"], 1)
        assert_equal(wallet.listunspent(0, 9999999, [quantum_address]), [])

        self.log.info("Fully inactive quantum outputs lock at the 24-month zero point")
        self._generate(70, mining_quantum_address)
        _, locked_output = self._wallet_output(wallet, lock_address)
        assert_equal(locked_output["locked"], True)
        assert_equal(locked_output["remaining_ppm"], 0)
        assert_equal(Decimal(locked_output["effective_amount"]), Decimal("0E-8"))
        assert_raises_rpc_error(-6, "No spendable wallet-owned quantum outputs are currently decaying", wallet.sweepdemurragedecay, {"source_address": lock_address})

        locked_utxo = self._one_output(wallet, lock_address)
        locked_spend = self._signed_quantum_spend(wallet, locked_utxo, wallet.getnewquantumaddress()["address"])
        assert_raises_rpc_error(-26, "bad-txns-spends-locked-coin", node.sendrawtransaction, locked_spend)

        self.log.info("Restart with the demurrage gate off; aged outputs return to nominal behavior")
        self.restart_node(0, extra_args=self.gate_off_args + [f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        node.loadwallet("demurrage")
        wallet = node.get_wallet_rpc("demurrage")
        off_supply = node.getcirculatingsupply()
        self._assert_supply_matches_txoutset(off_supply)
        assert_equal(off_supply["demurrage_active"], False)
        assert_equal(Decimal(off_supply["circulating_amount"]), Decimal(off_supply["nominal_amount"]))
        assert_equal(Decimal(off_supply["decayed_amount"]), Decimal("0E-8"))
        assert_equal(off_supply["decayed_txouts"], 0)
        assert_equal(off_supply["locked_txouts"], 0)

        wallet_info, unlocked_again = self._wallet_output(wallet, lock_address)
        assert_equal(wallet_info["demurrage_active"], False)
        assert_equal(unlocked_again["locked"], False)
        assert_equal(unlocked_again["exemption"], "inactive")
        assert_equal(Decimal(unlocked_again["effective_amount"]), Decimal(unlocked_again["nominal_amount"]))
        assert_equal(Decimal(unlocked_again["burned_if_spent_amount"]), Decimal("0E-8"))
        assert_raises_rpc_error(-4, "demurrage is not active for the next block", wallet.sweepdemurragedecay, {"source_address": lock_address})
        assert_equal(node.testmempoolaccept([locked_spend])[0]["allowed"], True)


if __name__ == "__main__":
    QuantumDemurrageTest().main()
