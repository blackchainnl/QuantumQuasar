#!/usr/bin/env python3
# Copyright (c) 2017-2021 Blackcoin Core Developers
# Copyright (c) 2017-2021 Blackcoin More Developers
# Copyright (c) 2017-2021 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test loadblock option

Test the option to start a node with the option loadblock which loads
a serialized blockchain from a file (usually called bootstrap.dat).
To generate that file this test uses the helper scripts available
in contrib/linearize.
"""

from pathlib import Path
import subprocess
import sys
import tempfile
import urllib

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

LOADBLOCK_HEIGHT = 100


class LoadblockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False

    def run_test(self):
        self.nodes[1].setnetworkactive(state=False)
        # Blackcoin/Blackcoin regtest coinbase maturity is 10, while the
        # inherited Bitcoin fixture used maturity 100 as the bootstrap height.
        # Keep this test's intended 100-block bootstrap file independent of the
        # fork's shorter coinbase maturity.
        assert COINBASE_MATURITY < LOADBLOCK_HEIGHT
        self.generate(self.nodes[0], LOADBLOCK_HEIGHT, sync_fun=self.no_op)

        # Parsing the url of our node to get settings for config file
        data_dir = self.nodes[0].datadir_path
        node_url = urllib.parse.urlparse(self.nodes[0].url)
        cfg_file = data_dir / "linearize.cfg"
        bootstrap_file = Path(self.options.tmpdir) / "bootstrap.dat"
        genesis_block = self.nodes[0].getblockhash(0)
        blocks_dir = self.nodes[0].blocks_path
        hash_list = tempfile.NamedTemporaryFile(dir=data_dir,
                                                mode='w',
                                                delete=False,
                                                encoding="utf-8")

        self.log.info("Create linearization config file")
        with open(cfg_file, "a", encoding="utf-8") as cfg:
            cfg.write(f"datadir={data_dir}\n")
            cfg.write(f"rpcuser={node_url.username}\n")
            cfg.write(f"rpcpassword={node_url.password}\n")
            cfg.write(f"port={node_url.port}\n")
            cfg.write(f"host={node_url.hostname}\n")
            cfg.write(f"output_file={bootstrap_file}\n")
            cfg.write(f"min_height=1\n")
            cfg.write(f"max_height={LOADBLOCK_HEIGHT}\n")
            cfg.write(f"netmagic=70352206\n")
            cfg.write(f"block_header_size=84\n")
            cfg.write(f"hash_header_size=80\n")
            cfg.write(f"input={blocks_dir}\n")
            cfg.write(f"genesis={genesis_block}\n")
            cfg.write(f"hashlist={hash_list.name}\n")

        base_dir = self.config["environment"]["SRCDIR"]
        linearize_dir = Path(base_dir) / "contrib" / "linearize"

        self.log.info("Run linearization of block hashes")
        linearize_hashes_file = linearize_dir / "linearize-hashes.py"
        subprocess.run([sys.executable, linearize_hashes_file, cfg_file],
                       stdout=hash_list,
                       check=True)

        self.log.info("Run linearization of block data")
        linearize_data_file = linearize_dir / "linearize-data.py"
        subprocess.run([sys.executable, linearize_data_file, cfg_file],
                       check=True)

        self.log.info("Restart second, unsynced node with bootstrap file")
        self.restart_node(1, extra_args=[f"-loadblock={bootstrap_file}"])
        assert_equal(self.nodes[1].getblockcount(), LOADBLOCK_HEIGHT)  # start_node is blocking on all block files being imported

        assert_equal(self.nodes[1].getblockchaininfo()['blocks'], LOADBLOCK_HEIGHT)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())


if __name__ == '__main__':
    LoadblockTest().main()
