#!/usr/bin/env python3
# Copyright (c) 2019-2022 Blackcoin Core Developers
# Copyright (c) 2019-2022 Blackcoin More Developers
# Copyright (c) 2019-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from io import BytesIO

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    sha256sum_file,
)


def deser_varint(f):
    n = 0
    while True:
        ch = f.read(1)
        if not ch:
            raise EOFError("unexpected EOF in varint")
        ch = ch[0]
        n = (n << 7) | (ch & 0x7f)
        if ch & 0x80:
            n += 1
        else:
            return n


def skip_compressed_script(f):
    size = deser_varint(f)
    if size < 6:
        special_sizes = (20, 20, 32, 32, 32, 32)
        f.seek(special_sizes[size], 1)
        return
    f.seek(size - 6, 1)


def skip_serialized_coin(f):
    deser_varint(f)  # height + coinbase/coinstake flags
    deser_varint(f)  # nTime
    deser_varint(f)  # compressed amount
    skip_compressed_script(f)


def count_snapshot_coins(snapshot_path):
    data = snapshot_path.read_bytes()
    metadata_count = int.from_bytes(data[32:40], "little")
    stream = BytesIO(data[40:])
    serialized_count = 0
    while stream.tell() < len(data) - 40:
        stream.read(36)  # COutPoint
        skip_serialized_coin(stream)
        serialized_count += 1
    assert_equal(stream.tell(), len(data) - 40)
    return metadata_count, serialized_count


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)

        FILENAME = 'txoutset.dat'
        out = node.dumptxoutset(FILENAME)
        expected_path = node.datadir_path / self.chain / FILENAME

        assert expected_path.is_file()

        assert_equal(out['coins_written'], 10)
        assert_equal(out['base_height'], 10)
        assert_equal(out['path'], str(expected_path))
        # Blockhash should be deterministic based on mocked time.
        assert_equal(
            out['base_hash'],
            'f9f826ed12126c2b1f7cae28b52c3e0aabcf1063153449aa69f9a464f9438ee4')

        # UTXO snapshot hash should be deterministic based on mocked time.
        assert_equal(
            sha256sum_file(str(expected_path)).hex(),
            'ba591f7b9b2b3f5b22438160f951c59bd66c74b5c1c9f658ecede18036d54a71')

        assert_equal(
            out['txoutset_hash'], '77f367400070814dec24af7881735e239c17b65a025d7d449be0d5ac2669afa3')
        assert_equal(out['nchaintx'], 11)

        # Specifying a path to an existing or invalid file will fail.
        assert_raises_rpc_error(
            -8, '{} already exists'.format(FILENAME),  node.dumptxoutset, FILENAME)
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path)

        self.log.info("Check snapshots omit Blackcoin internal marker coins")
        self.restart_node(0, extra_args=["-shadowwhitelistheight=20", "-shadowgoldrushblocks=500"])
        node = self.nodes[0]
        node.setmocktime(node.getblockheader(node.getbestblockhash())['time'] + 1)
        self.generate(node, 15)

        marker_filename = "txoutset_with_markers.dat"
        marker_out = node.dumptxoutset(marker_filename)
        marker_path = node.datadir_path / self.chain / marker_filename
        metadata_count, serialized_count = count_snapshot_coins(marker_path)
        assert_equal(metadata_count, marker_out["coins_written"])
        assert_equal(serialized_count, marker_out["coins_written"])


if __name__ == '__main__':
    DumptxoutsetTest().main()
