#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Quantum Cold-Stake delegation through live wallet and node paths."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY, WITNESS_COMMITMENT_HEADER, get_witness_script
from test_framework.messages import CBlock, CTransaction, CTxInWitness, from_hex, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


COLD_STAKE_AMOUNT = Decimal("9000")
COLD_SPEND_FEE = Decimal("0.01")
HALF_POS_SUBSIDY = Decimal("0.75")
HALF_POS_SUBSIDY_SATS = 75_000_000


class QuantumColdStakingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-staketimio=50",
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=1",
            "-qqgoldrushendtime=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _generate(self, count, address):
        node = self.nodes[0]
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(node, 1, address, sync_fun=self.no_op))
            self._bump_mocktime(16)
        return hashes

    def _wait_for_txindex(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getindexinfo().get("txindex", {}).get("synced", False), timeout=30)

    def _staking_inputs(self, wallet, address):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999, [address])
        ]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "cold-staking wallet must have mature QCS inputs"
        for _ in range(20000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic QCS staking kernel")

    def _stake_cold_block(self, wallet, qcs_address):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet, qcs_address)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
            block_hash = node.getbestblockhash()
            block = node.getblock(block_hash, 2)
            assert "proof-of-stake" in block["flags"]
            return block_hash, block
        finally:
            wallet.staking(False)

    def _one_qcs_utxo(self, wallet, qcs_address):
        utxos = wallet.listunspent(1, 9999999, [qcs_address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def _qcs_utxos(self, wallet, qcs_address):
        utxos = wallet.listunspent(1, 9999999, [qcs_address])
        assert utxos, "wallet must have mature QCS outputs"
        return utxos

    def _build_owner_spend(self, owner_wallet, utxo, destination):
        node = self.nodes[0]
        amount = Decimal(str(utxo["amount"])) - COLD_SPEND_FEE
        assert amount > 0
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: amount}],
        )
        return raw, owner_wallet.signrawtransactionwithwallet(raw)

    def _prevtx_for_qcs_utxo(self, utxo):
        return {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": utxo["scriptPubKey"],
            "amount": utxo["amount"],
        }

    def _script_for_address(self, address):
        return bytes.fromhex(self.nodes[0].validateaddress(address)["scriptPubKey"])

    def _qcs_branch_signed_coinstake(self, coinstake, quantum_key, other_pubkey_hash, branch_selector, prevtx):
        tx = CTransaction(coinstake)
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            b"",
            b"",
            bytes.fromhex(other_pubkey_hash),
            branch_selector,
        ]
        tx.sha256 = None
        tx.hash = None
        signed = self.nodes[0].signrawtransactionwithquantumkey(
            tx.serialize().hex(),
            [{
                "public_key": quantum_key["public_key"],
                "private_key": quantum_key["private_key"],
            }],
            [prevtx],
        )
        return signed, tx_from_hex(signed["hex"])

    def _signed_candidate_block(self, raw_block_hex, signed_coinstake, signing_key):
        block = from_hex(CBlock(), raw_block_hex)
        block.vtx[1] = signed_coinstake
        coinbase = CTransaction(block.vtx[0])
        coinbase.wit.vtxinwit = [CTxInWitness() for _ in coinbase.vin]
        coinbase.wit.vtxinwit[0].scriptWitness.stack = [b"\x00" * 32]
        block.vtx[0] = coinbase
        witness_root = block.calc_witness_merkle_root()
        witness_script = get_witness_script(witness_root, 0)
        for txout in reversed(block.vtx[0].vout):
            if bytes(txout.scriptPubKey).startswith(b"\x6a\x24" + WITNESS_COMMITMENT_HEADER):
                txout.scriptPubKey = witness_script
                break
        else:
            raise AssertionError("candidate cold-stake block is missing a witness commitment output")
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.sha256 = None
        block.hash = None
        block.vchBlockSig = b""
        signed_block = self.nodes[0].signrawblockwithquantumkey(
            block.serialize().hex(),
            signing_key["public_key"],
            signing_key["private_key"],
        )
        return signed_block["hex"]

    def _assert_invalid_coldstake_blocks(self, raw_block_hex, qcs_utxo, qcs_template, staker_key, owner_key, owner_wallet):
        node = self.nodes[0]
        prevtx = self._prevtx_for_qcs_utxo(qcs_utxo)
        qcs_script = bytes.fromhex(qcs_utxo["scriptPubKey"])
        original_block = from_hex(CBlock(), raw_block_hex)

        self.log.info("Rejecting a QCS coinstake that redirects delegated principal")
        redirected = CTransaction(original_block.vtx[1])
        redirected_script = self._script_for_address(owner_wallet.getnewquantumaddress()["address"])
        redirected_outputs = 0
        for txout in redirected.vout:
            if txout.nValue > 0 and txout.scriptPubKey == qcs_script:
                txout.scriptPubKey = redirected_script
                redirected_outputs += 1
        assert redirected_outputs > 0
        redirected.sha256 = None
        redirected.hash = None
        redirected_signed, redirected_coinstake = self._qcs_branch_signed_coinstake(
            redirected,
            staker_key,
            qcs_template["owner_pubkey_hash"],
            b"\x01",
            prevtx,
        )
        if not redirected_signed["complete"]:
            raise AssertionError(f"redirected QCS coinstake did not verify after signing: {redirected_signed}")
        redirected_block_hex = self._signed_candidate_block(raw_block_hex, redirected_coinstake, staker_key)
        assert_equal(node.getblocktemplate({"mode": "proposal", "data": redirected_block_hex}), "bad-coldstake-covenant")

        self.log.info("Rejecting owner-branch QCS witnesses inside coinstakes")
        owner_signed, owner_branch_coinstake = self._qcs_branch_signed_coinstake(
            original_block.vtx[1],
            owner_key,
            qcs_template["staking_pubkey_hash"],
            b"",
            prevtx,
        )
        assert_equal(owner_signed["complete"], False)
        assert "Quantum cold-stake owner branch cannot be used inside a coinstake" in owner_signed["errors"][0]["error"]
        owner_branch_block_hex = self._signed_candidate_block(raw_block_hex, owner_branch_coinstake, staker_key)
        owner_branch_result = node.getblocktemplate({"mode": "proposal", "data": owner_branch_block_hex})
        assert owner_branch_result is not None, "owner-branch coinstake block must not be accepted"

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")

        self.log.info("Creating funder, owner, and staker wallets")
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)
        node.createwallet(wallet_name="cold_funder")
        node.createwallet(wallet_name="cold_owner")
        node.createwallet(wallet_name="cold_staker")
        funder = node.get_wallet_rpc("cold_funder")
        owner = node.get_wallet_rpc("cold_owner")
        staker = node.get_wallet_rpc("cold_staker")
        for wallet in (funder, owner, staker):
            wallet.staking(False)

        self.log.info("Creating and importing a Quantum Cold-Stake delegation")
        staker_quantum = staker.getnewquantumaddress()["address"]
        staker_key = staker.dumpquantumkey(staker_quantum)
        delegation = owner.getnewquantumcoldstakingaddress(staker_key["public_key"], "delegated")
        owner_key = owner.dumpquantumkey(delegation["owner_quantum_address"])
        qcs_template = node.createcoldstakingaddress(owner_key["public_key"], staker_key["public_key"])
        qcs_address = delegation["address"]
        assert_equal(qcs_template["address"], qcs_address)
        assert_equal(delegation["has_owner_key"], True)
        assert_equal(delegation["has_staker_key"], False)
        assert_equal(node.validateaddress(qcs_address)["isquantumcoldstake"], True)

        imported = staker.importquantumcoldstakingdelegation(delegation["owner_pubkey"], staker_key["public_key"], "delegated")
        assert_equal(imported["address"], qcs_address)
        assert_equal(imported["has_owner_key"], False)
        assert_equal(imported["has_staker_key"], True)
        assert_equal(staker.listquantumcoldstakingdelegations()[0]["address"], qcs_address)

        self.log.info("Funding and maturing the delegated QCS output")
        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)
        self._wait_for_txindex()
        funding_txid = funder.sendtoaddress(qcs_address, COLD_STAKE_AMOUNT)
        self._generate(1, funder_address)
        self.wait_until(lambda: len(staker.listunspent(1, 9999999, [qcs_address])) == 1, timeout=30)
        self._generate(COINBASE_MATURITY, funder_address)
        self._wait_for_txindex()
        qcs_utxo = self._one_qcs_utxo(staker, qcs_address)
        assert_equal(qcs_utxo["txid"], funding_txid)
        assert_equal(Decimal(str(qcs_utxo["amount"])), COLD_STAKE_AMOUNT)

        self.log.info("Staking the QCS output from the hot/staker wallet")
        self._sync_mocktime_to_tip()
        block_hash, block = self._stake_cold_block(staker, qcs_address)
        coinstake = block["tx"][1]
        assert_equal(coinstake["vin"][0]["txid"], qcs_utxo["txid"])
        assert_equal(coinstake["vin"][0]["vout"], qcs_utxo["vout"])
        assert_equal(coinstake["vin"][0]["txinwitness"][-1], "01")
        total_out = sum(Decimal(str(vout["value"])) for vout in coinstake["vout"])
        reward = total_out - COLD_STAKE_AMOUNT
        assert_equal(reward, HALF_POS_SUBSIDY)
        assert_equal(node.getblockstats(block_hash, ["subsidy"])["subsidy"], HALF_POS_SUBSIDY_SATS)

        self.log.info("Rewinding the valid QCS block to exercise invalid coinstake variants")
        raw_cold_block = node.getblock(block_hash, 0)
        pre_cold_tip = block["previousblockhash"]
        node.invalidateblock(block_hash)
        assert_equal(node.getbestblockhash(), pre_cold_tip)
        self._assert_invalid_coldstake_blocks(raw_cold_block, qcs_utxo, qcs_template, staker_key, owner_key, owner)
        node.reconsiderblock(block_hash)
        self.wait_until(lambda: node.getbestblockhash() == block_hash, timeout=30)

        self.log.info("Maturing the new QCS output and proving only the owner branch can spend it normally")
        self._generate(COINBASE_MATURITY, funder_address)
        self._wait_for_txindex()
        owner_qcs_utxos = self._qcs_utxos(owner, qcs_address)
        owner_qcs_total = sum(Decimal(str(utxo["amount"])) for utxo in owner_qcs_utxos)
        assert_equal(owner_qcs_total, COLD_STAKE_AMOUNT + HALF_POS_SUBSIDY)
        owner_qcs = owner_qcs_utxos[0]
        destination = owner.getnewquantumaddress()["address"]
        raw, staker_signed = self._build_owner_spend(staker, owner_qcs, destination)
        assert_equal(staker_signed["complete"], False)
        raw, owner_signed = self._build_owner_spend(owner, owner_qcs, destination)
        assert_equal(owner_signed["complete"], True)
        accepted = node.testmempoolaccept([owner_signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"owner QCS spend rejected: {accepted}")
        spend_txid = node.sendrawtransaction(owner_signed["hex"])
        spend_block = self._generate(1, funder_address)[0]
        assert spend_txid in node.getblock(spend_block)["tx"]
        assert node.gettxout(owner_qcs["txid"], owner_qcs["vout"], False) is None


if __name__ == "__main__":
    QuantumColdStakingTest().main()
