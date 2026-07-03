#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Core Developers
# Copyright (c) 2026 Blackcoin More Developers
# Copyright (c) 2026 Quantum Quasar Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Regression test for multiwallet PoS staking timer starvation.

An empty wallet must not consume a process-global staking search timestamp in a
way that prevents another loaded wallet from searching and producing a block at
its valid kernel time.
"""

import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletPoSMultiwalletStakingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-staketimio=1",
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
        assert inputs, "funded wallet must have mature staking inputs"
        for _ in range(300):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _prime_empty_wallet_search(self, empty, kernel_time):
        self._set_mocktime(kernel_time - 96)
        with self.nodes[0].wait_for_debug_log([b"Set proof-of-stake timeout"], timeout=5):
            empty.staking(True)

        for offset in (80, 64, 48):
            search_time = kernel_time - offset
            self._set_mocktime(search_time)
            stop_time = time.time() + 5
            while time.time() < stop_time:
                if empty.getstakinginfo()["search-interval"] > 0:
                    return search_time
                time.sleep(0.05)

        raise AssertionError("empty wallet did not perform an initial staking search")

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        node.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Creating one funded wallet and one empty wallet")
        node.createwallet(wallet_name="staking_funded")
        node.createwallet(wallet_name="staking_empty")
        funded = node.get_wallet_rpc("staking_funded")
        empty = node.get_wallet_rpc("staking_empty")
        funded.staking(False)
        empty.staking(False)

        self.log.info("Mining a mature staking coin for the funded wallet")
        staking_address = funded.getnewaddress("", "legacy")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, staking_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert self._staking_inputs(funded)
        assert_equal(empty.listunspent(), [])

        self.log.info("Finding a deterministic future kernel for the funded wallet")
        self._bump_mocktime(96)
        kernel_time = self._find_next_kernel_time(funded)
        start_height = node.getblockcount()

        self.log.info("Letting the empty wallet search before the funded wallet reaches its kernel")
        primed_time = self._prime_empty_wallet_search(empty, kernel_time)
        self._set_mocktime(kernel_time)
        self.wait_until(
            lambda: empty.getstakinginfo()["search-interval"] >= kernel_time - primed_time,
            timeout=5,
        )
        assert_equal(node.getblockcount(), start_height)

        self.log.info("Starting the funded wallet at the same kernel time")
        try:
            funded.staking(True)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=8)
            block = node.getblock(node.getbestblockhash(), 2)
            assert "proof-of-stake" in block["flags"]
            assert funded.getstakinginfo()["search-interval"] > 0
        finally:
            funded.staking(False)
            empty.staking(False)


if __name__ == "__main__":
    WalletPoSMultiwalletStakingTest().main()
