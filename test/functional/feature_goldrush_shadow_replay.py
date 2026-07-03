#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify startup replay repairs a legacy-consistent Gold Rush chainstate.

A user may upgrade after Gold Rush has started with blocks already stored and
connected by older software. Those blocks are base-ledger valid, but their coins
DB is missing Blackcoin shadow-ledger pool/claim state. Startup must rewind
only to the local fork boundary and replay local blocks, not require a full
redownload or manual reindex.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


COIN = 100_000_000
FUTURE_V4_TIME = 2_000_000_000
FUTURE_GOLD_RUSH_END_TIME = FUTURE_V4_TIME + 1_000
GOLD_RUSH_BLOCKS = 20
REWARD_BLOCKS_CONNECTED = 5
BASE_ARGS = [
    "-shadowwhitelistheight=1",
    f"-shadowgoldrushblocks={GOLD_RUSH_BLOCKS}",
    f"-qqgoldrushendtime={FUTURE_GOLD_RUSH_END_TIME}",
]


class GoldRushShadowReplayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [BASE_ARGS + [f"-qqv4time={FUTURE_V4_TIME}"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Creating locally stored blocks while V4/Gold Rush accounting is inactive")
        self.generatetoaddress(node, 1 + REWARD_BLOCKS_CONNECTED, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 1 + REWARD_BLOCKS_CONNECTED)
        legacy_state = node.getgoldrushstate()
        assert_equal(legacy_state["pow_amount"], 0)
        assert_equal(legacy_state["pos_amount"], 0)
        assert_equal(legacy_state["claimed_amount"], 0)

        self.log.info("Restarting as upgraded V30 software; startup should replay shadow state from local blocks")
        self.restart_node(0, BASE_ARGS)

        repaired_state = self.nodes[0].getgoldrushstate()
        expected_half_pool = REWARD_BLOCKS_CONNECTED * 290 * COIN
        assert_equal(repaired_state["pow_amount"], expected_half_pool)
        assert_equal(repaired_state["pos_amount"], expected_half_pool)
        assert_equal(repaired_state["claimed_amount"], 0)
        assert_equal(self.nodes[0].getblockcount(), 1 + REWARD_BLOCKS_CONNECTED)


if __name__ == "__main__":
    GoldRushShadowReplayTest().main()
