#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Gold Rush synthetic payouts across a competing-chain reorg."""

import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000


class GoldRushReorgTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common_args = [
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]
        self.extra_args = [common_args, common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        )
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block(self, node, wallet, *, expected_txid=None, excluded_txid=None):
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
                txids = [tx["txid"] for tx in block["tx"]]
                if expected_txid is not None:
                    assert expected_txid in txids[2:]
                if excluded_txid is not None:
                    assert excluded_txid not in txids
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _get_quantum_utxos(self, wallet, address):
        return wallet.listunspent(0, 9999999, [address], True, {"include_immature_coinbase": True})

    def _wait_for_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address)[0]

    def run_test(self):
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        for node in self.nodes:
            node.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Preparing a shared parent with mature staking and QQSPROOF funding coins")
        self.nodes[0].createwallet(wallet_name="goldrush_reorg")
        wallet = self.nodes[0].get_wallet_rpc("goldrush_reorg")
        wallet.staking(False)
        self.nodes[1].createwallet(wallet_name="goldrush_competing")
        competing_wallet = self.nodes[1].get_wallet_rpc("goldrush_competing")
        competing_wallet.staking(False)
        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")
        competing_staking_address = competing_wallet.getnewaddress("", "legacy")

        self.generatetoaddress(self.nodes[0], 1, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, claim_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 5, competing_staking_address)
        self.sync_blocks()
        self._sync_mocktime_to_tip()
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Splitting before broadcasting a PoW claim")
        payout_address = wallet.getnewquantumaddress()["address"]
        self.disconnect_nodes(0, 1)
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        assert claim["txid"] in self.nodes[0].getrawmempool()
        assert claim["txid"] not in self.nodes[1].getrawmempool()

        self.log.info("Mining the claim on node0's branch materializes the synthetic payout")
        claim_block_hash = self._mine_pos_block(self.nodes[0], wallet, expected_txid=claim["txid"])
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert self.nodes[0].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None

        self.log.info("Mining a longer competing PoS branch without the claim")
        competing_blocks = [
            self._mine_pos_block(self.nodes[1], competing_wallet, excluded_txid=claim["txid"])
            for _ in range(2)
        ]
        assert_equal(len(competing_blocks), 2)
        self._sync_mocktime_to_tip()

        self.log.info("Reconnecting reorgs node0 off the claim branch and removes the synthetic payout")
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=60)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        assert self.nodes[0].getbestblockhash() != claim_block_hash
        assert_equal(self.nodes[0].getbestblockhash(), competing_blocks[-1])
        assert self.nodes[0].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        assert_equal(self._get_quantum_utxos(wallet, payout_address), [])
        assert claim["txid"] not in self.nodes[0].getrawmempool()
        assert claim["txid"] not in self.nodes[1].getrawmempool()


if __name__ == "__main__":
    GoldRushReorgTest().main()
