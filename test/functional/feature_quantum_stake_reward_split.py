#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise stake-reward splitting through live node paths."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY, WITNESS_COMMITMENT_HEADER, get_witness_script
from test_framework.messages import CBlock, CTransaction, CTxInWitness, from_hex, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


MIGRATION_DEADLINE_TIME = 2_200_000_000
SELF_STAKE_AMOUNT = Decimal("12000")
COLD_STAKE_AMOUNT = Decimal("9000")
BASE_POS_SUBSIDY = Decimal("1.5")
OPERATOR_FLOOR = Decimal("0.075")
VAULT_7D_BLOCKS = 9450


class QuantumStakeRewardSplitTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        args = [
            "-txindex=1",
            "-staketimio=50",
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=1",
            "-qqgoldrushendtime=1",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
            "-qqstaketierheight=1",
            "-qqstakesplitheight=1",
        ]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _generate(self, count, address):
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(self.nodes[0], 1, address))
            self._bump_mocktime(16)
        return hashes

    def _wait_for_txindex(self):
        self.wait_until(lambda: self.nodes[0].getindexinfo().get("txindex", {}).get("synced", False), timeout=30)

    def _staking_inputs(self, wallet, address):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999, [address])
        ]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "staking wallet must have mature inputs"
        for _ in range(20000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic staking kernel")

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

    def _one_utxo(self, wallet, address):
        utxos = wallet.listunspent(1, 9999999, [address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def _script_for_address(self, address):
        return bytes.fromhex(self.nodes[0].validateaddress(address)["scriptPubKey"])

    def _prevtx_for_utxo(self, utxo):
        return {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": utxo["scriptPubKey"],
            "amount": utxo["amount"],
        }

    def _qcs_branch_signed_coinstake(self, coinstake, staker_key, owner_pubkey_hash, prevtx):
        tx = CTransaction(coinstake)
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            b"",
            b"",
            bytes.fromhex(owner_pubkey_hash),
            b"\x01",
        ]
        tx.sha256 = None
        tx.hash = None
        signed = self.nodes[0].signrawtransactionwithquantumkey(
            tx.serialize().hex(),
            [{
                "public_key": staker_key["public_key"],
                "private_key": staker_key["private_key"],
            }],
            [prevtx],
        )
        if not signed["complete"]:
            raise AssertionError(f"mutated QCS coinstake did not verify after signing: {signed}")
        return tx_from_hex(signed["hex"])

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
            raise AssertionError("candidate stake-reward split block is missing a witness commitment output")

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

    def _assert_operator_redirect_rejected(self, raw_block_hex, qcs_utxo, qcs_template, staker_key, operator_script, replacement_script):
        node = self.nodes[0]
        original_block = from_hex(CBlock(), raw_block_hex)
        redirected = CTransaction(original_block.vtx[1])
        redirected_outputs = 0
        for txout in redirected.vout:
            if txout.nValue > 0 and txout.scriptPubKey == operator_script:
                txout.scriptPubKey = replacement_script
                redirected_outputs += 1
        assert_equal(redirected_outputs, 1)
        redirected.sha256 = None
        redirected.hash = None

        signed_coinstake = self._qcs_branch_signed_coinstake(
            redirected,
            staker_key,
            qcs_template["owner_pubkey_hash"],
            self._prevtx_for_utxo(qcs_utxo),
        )
        invalid_block_hex = self._signed_candidate_block(raw_block_hex, signed_coinstake, staker_key)
        assert_equal(node.getblocktemplate({"mode": "proposal", "data": invalid_block_hex}), "bad-stake-reward-split-output")

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        for node_rpc in self.nodes:
            assert_equal(node_rpc.getquantumquasarinfo()["phase"], "migration")

        for node_rpc in self.nodes:
            node_rpc.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Creating funder and stake-reward split staking wallets")
        node.createwallet(wallet_name="b4_funder")
        node.createwallet(wallet_name="b4_self_staker")
        node.createwallet(wallet_name="b4_cold_owner")
        node.createwallet(wallet_name="b4_cold_staker")
        funder = node.get_wallet_rpc("b4_funder")
        self_staker = node.get_wallet_rpc("b4_self_staker")
        owner = node.get_wallet_rpc("b4_cold_owner")
        cold_staker = node.get_wallet_rpc("b4_cold_staker")
        for wallet in (funder, self_staker, owner, cold_staker):
            wallet.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)
        self._wait_for_txindex()

        self.log.info("Proving self-stake keeps the full fixed 1.5 BLK pie")
        self_stake_info = self_staker.getnewquantumstakeaddress("b4-self", VAULT_7D_BLOCKS)
        self_stake_address = self_stake_info["address"]
        self_stake_script = self._script_for_address(self_stake_address)
        self_stake_txid = funder.sendtoaddress(self_stake_address, SELF_STAKE_AMOUNT)
        self._generate(1, funder_address)
        self.wait_until(lambda: len(self_staker.listunspent(1, 9999999, [self_stake_address])) == 1, timeout=30)
        self._generate(COINBASE_MATURITY, funder_address)
        self._wait_for_txindex()
        self_stake_utxo = self._one_utxo(self_staker, self_stake_address)
        assert_equal(self_stake_utxo["txid"], self_stake_txid)

        self._sync_mocktime_to_tip()
        self_block_hash, self_block = self._stake_block(self_staker, self_stake_address)
        self_coinstake = self_block["tx"][1]
        assert_equal(self_coinstake["vin"][0]["txid"], self_stake_utxo["txid"])
        self_stake_outputs = [
            Decimal(str(vout["value"]))
            for vout in self_coinstake["vout"]
            if bytes.fromhex(vout["scriptPubKey"]["hex"]) == self_stake_script
        ]
        assert self_stake_outputs, "self-stake must pay the staking script"
        assert_equal(sum(self_stake_outputs), SELF_STAKE_AMOUNT + BASE_POS_SUBSIDY)

        self.log.info("Creating and funding a delegated QCS output")
        staker_quantum = cold_staker.getnewquantumaddress()["address"]
        staker_key = cold_staker.dumpquantumkey(staker_quantum)
        operator_script = self._script_for_address(staker_quantum)
        delegation = owner.getnewquantumcoldstakingaddress(staker_key["public_key"], "b4-delegated")
        owner_key = owner.dumpquantumkey(delegation["owner_quantum_address"])
        qcs_template = node.createcoldstakingaddress(owner_key["public_key"], staker_key["public_key"])
        qcs_address = delegation["address"]
        qcs_script = self._script_for_address(qcs_address)
        assert_equal(qcs_template["address"], qcs_address)
        imported = cold_staker.importquantumcoldstakingdelegation(delegation["owner_pubkey"], staker_key["public_key"], "b4-delegated")
        assert_equal(imported["has_staker_key"], True)

        qcs_txid = funder.sendtoaddress(qcs_address, COLD_STAKE_AMOUNT)
        self._generate(1, funder_address)
        self.wait_until(lambda: len(cold_staker.listunspent(1, 9999999, [qcs_address])) == 1, timeout=30)
        self._generate(COINBASE_MATURITY, funder_address)
        self._wait_for_txindex()
        qcs_utxo = self._one_utxo(cold_staker, qcs_address)
        assert_equal(qcs_utxo["txid"], qcs_txid)

        self.log.info("Proving delegated cold-stake splits the fixed pie and pays operator compensation")
        self._sync_mocktime_to_tip()
        cold_block_hash, cold_block = self._stake_block(cold_staker, qcs_address)
        cold_coinstake = cold_block["tx"][1]
        assert_equal(cold_coinstake["vin"][0]["txid"], qcs_utxo["txid"])
        assert_equal(cold_coinstake["vin"][0]["txinwitness"][-1], "01")

        qcs_outputs = [
            Decimal(str(vout["value"]))
            for vout in cold_coinstake["vout"]
            if bytes.fromhex(vout["scriptPubKey"]["hex"]) == qcs_script
        ]
        operator_outputs = [
            Decimal(str(vout["value"]))
            for vout in cold_coinstake["vout"]
            if bytes.fromhex(vout["scriptPubKey"]["hex"]) == operator_script
        ]
        assert qcs_outputs, "delegated coinstake must preserve delegated principal"
        assert_equal(sum(qcs_outputs), COLD_STAKE_AMOUNT + BASE_POS_SUBSIDY - OPERATOR_FLOOR)
        assert_equal(sum(operator_outputs), OPERATOR_FLOOR)

        self.log.info("Rejecting a signed block that redirects operator compensation")
        raw_cold_block = node.getblock(cold_block_hash, 0)
        pre_cold_tip = cold_block["previousblockhash"]
        for node_rpc in self.nodes:
            node_rpc.invalidateblock(cold_block_hash)
            assert_equal(node_rpc.getbestblockhash(), pre_cold_tip)
        replacement_script = self._script_for_address(owner.getnewquantumaddress()["address"])
        self._assert_operator_redirect_rejected(raw_cold_block, qcs_utxo, qcs_template, staker_key, operator_script, replacement_script)

        self.log.info("Reconsidering the valid cold-stake reward-split block")
        for node_rpc in self.nodes:
            node_rpc.reconsiderblock(cold_block_hash)
        self.wait_until(lambda: all(node_rpc.getbestblockhash() == cold_block_hash for node_rpc in self.nodes), timeout=30)


if __name__ == "__main__":
    QuantumStakeRewardSplitTest().main()
