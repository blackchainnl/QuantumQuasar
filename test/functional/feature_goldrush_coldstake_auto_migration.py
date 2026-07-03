#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify cold-stake funding safely auto-migrates Gold Rush reward outputs."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 40_000
WALLET_NAME = "goldrush_coldstake_auto_migration"


class GoldRushColdStakeAutoMigrationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
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

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(1000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block_with_claim(self, wallet, claim_txid):
        node = self.nodes[0]
        last_error = None
        for _ in range(4):
            start_height = node.getblockcount()
            kernel_time = self._find_next_kernel_time(wallet)
            self._set_mocktime(kernel_time - 16)
            wallet.staking(True)
            try:
                self._set_mocktime(kernel_time)
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                assert claim_txid in [tx["txid"] for tx in block["tx"][2:]]
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        options = {"include_immature_coinbase": True}
        self.wait_until(lambda: len(wallet.listunspent(min_conf, 9999999, [address], True, options)) == 1, timeout=30)
        return wallet.listunspent(min_conf, 9999999, [address], True, options)[0]

    def _mine_until_quantum_spends_active(self, address):
        node = self.nodes[0]
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        for _ in range(1000):
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            info = node.getquantumquasarinfo()
            if info["phase"] == "migration" and info["quantum_spend_enforcement_active"]:
                return
        raise AssertionError("timed out waiting for post-Gold-Rush quantum spend activation")

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating mature staking and QQSPROOF funding coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)

        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")
        self.generatetoaddress(node, 1, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, claim_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Mining and maturing a Gold Rush reward output")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        self._mine_pos_block_with_claim(wallet, claim["txid"])
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address, min_conf=COINBASE_MATURITY + 1)
        status = wallet.getmigrationstatus()
        assert_equal(status["goldrush_reward_outputs_needing_move"], 1)
        for utxo in wallet.listunspent(1, 9999999):
            if utxo["txid"] == payout_utxo["txid"] and utxo["vout"] == payout_utxo["vout"]:
                continue
            wallet.lockunspent(False, [{"txid": utxo["txid"], "vout": utxo["vout"]}])

        self.log.info("Advancing to migration before auto-migrating the Gold Rush reward into cold stake")
        self._mine_until_quantum_spends_active(node.get_deterministic_priv_key().address)

        self.log.info("Default cold-stake funding first migrates the Gold Rush reward")
        staker_key = wallet.dumpquantumkey(wallet.getnewquantumaddress()["address"])
        coldstake_address = wallet.getnewquantumcoldstakingaddress(staker_key["public_key"], "auto-coldstake")["address"]
        result = wallet.fundquantumcoldstakeaddress(coldstake_address, Decimal("1"))
        assert_equal(result["created_goldrush_migration"], True)
        assert_equal(result["completed_delegation"], False)
        assert result["migration_txid"] in node.getrawmempool()
        assert_equal(result["txid"], result["migration_txid"])

        self.log.info("The migration must confirm before the delegation can spend it")
        self._bump_mocktime(32)
        block_hash = self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        block_txids = node.getblock(block_hash)["tx"]
        assert result["migration_txid"] in block_txids

        self.log.info("After confirmation, the same RPC funds the cold-stake delegation")
        self._sync_mocktime_to_tip()
        delegation = wallet.fundquantumcoldstakeaddress(coldstake_address, Decimal("1"))
        assert_equal(delegation["created_goldrush_migration"], False)
        assert_equal(delegation["completed_delegation"], True)
        assert delegation["txid"] in node.getrawmempool()

        self._bump_mocktime(32)
        block_hash = self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        assert delegation["txid"] in node.getblock(block_hash)["tx"]


if __name__ == "__main__":
    GoldRushColdStakeAutoMigrationTest().main()
