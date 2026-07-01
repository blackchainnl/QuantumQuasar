#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test regtest weak-subjectivity checkpoint enforcement.

The production checkpoint mechanism is static release data in chainparams. This
test uses a regtest-only checkpoint override so the suite can prove matching
headers/blocks survive restart while conflicting histories are rejected.
"""

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
    create_block,
    create_coinbase,
)
from test_framework.messages import CBlockHeader
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


REGTEST_GENESIS_HASH = int("0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d", 16)


def make_height_one_block(*, salt):
    block = create_block(
        hashprev=REGTEST_GENESIS_HASH,
        coinbase=create_coinbase(1),
        ntime=TIME_GENESIS_BLOCK + 1 + salt,
    )
    block.hashMerkleRoot = (block.hashMerkleRoot + salt) % (1 << 256)
    block.solve()
    return block


class WeakSubjectivityCheckpointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.good_block = make_height_one_block(salt=0)
        self.conflicting_block = make_height_one_block(salt=1)
        self.extra_args = [[
            "-minimumchainwork=0x0",
            f"-testcheckpoint=1@{self.good_block.hash}",
        ]]

    def run_test(self):
        node = self.nodes[0]
        good_header = CBlockHeader(self.good_block).serialize().hex()
        conflicting_header = CBlockHeader(self.conflicting_block).serialize().hex()

        self.log.info("Accept the chain that matches the shipped checkpoint")
        assert_equal(node.submitblock(self.good_block.serialize().hex()), None)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), self.good_block.hash)

        self.log.info("Keep the checkpoint-consistent chain across restart")
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), self.good_block.hash)
        node.submitheader(good_header)

        self.log.info("Reject a conflicting header at the checkpoint height")
        assert_raises_rpc_error(
            -25,
            "bad-fork-hardened-checkpoint",
            node.submitheader,
            hexdata=conflicting_header,
        )
        assert self.conflicting_block.hash not in [tip["hash"] for tip in node.getchaintips()]

        self.log.info("The explicit debug escape hatch still disables checkpoint enforcement")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-nocheckpoints"])
        node = self.nodes[0]
        node.submitheader(conflicting_header)
        assert self.conflicting_block.hash in [tip["hash"] for tip in node.getchaintips()]


if __name__ == "__main__":
    WeakSubjectivityCheckpointTest().main()
