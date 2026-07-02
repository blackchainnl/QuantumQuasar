#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dedicated testnet Gold Rush schedule controls.

This file is intentionally branch-only. The public release line keeps the
production schedule fixed; this testnet branch exposes guarded schedule knobs
so live testnet wallets can exercise the whitelist and Gold Rush paths without
waiting for mainnet heights.
"""

import os
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class GoldRushScheduleControlsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "testnet3"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Rejecting malformed schedule controls before startup")
        node.assert_start_raises_init_error(
            extra_args=[
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=100",
                "-shadowgoldrushblocks=10",
            ],
            expected_msg="-shadowgoldrushstartheight must be greater than -shadowwhitelistheight",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Rejecting schedule controls on mainnet")
        mainnet_datadir = os.path.join(self.options.tmpdir, "mainnet_schedule_guard")
        os.makedirs(mainnet_datadir, exist_ok=True)
        mainnet_result = subprocess.run(
            [
                self.options.bitcoind,
                f"-datadir={mainnet_datadir}",
                "-chain=main",
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=110",
                "-shadowgoldrushblocks=10",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        assert mainnet_result.returncode != 0
        assert "only supported on testnet/regtest" in (mainnet_result.stdout + mainnet_result.stderr)

        self.log.info("Starting testnet with an explicit whitelist/start/end schedule")
        self.start_node(0, [
            "-shadowwhitelistheight=100",
            "-shadowgoldrushstartheight=110",
            "-shadowgoldrushblocks=10",
        ])

        info = node.getquantumquasarinfo()
        assert_equal(info["shadow_reward_start_height"], 110)
        assert_equal(info["shadow_reward_end_height"], 119)
        assert_equal(info["shadow_reward_next_height"], 1)
        assert_equal(info["shadow_reward_height_active"], False)


if __name__ == "__main__":
    GoldRushScheduleControlsTest().main()
