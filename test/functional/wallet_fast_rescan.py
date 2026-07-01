#!/usr/bin/env python3
# Copyright (c) 2022 Blackcoin Core Developers
# Copyright (c) 2022 Blackcoin More Developers
# Copyright (c) 2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that fast rescan using block filters for descriptor wallets detects
   top-ups correctly and finds the same transactions than the slow variant."""
from typing import List

from test_framework.address import address_to_scriptpubkey
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import get_generate_key


KEYPOOL_SIZE = 100   # smaller than default size to speed-up test
NUM_DESCRIPTORS = 9  # number of descriptors (8 default ranged ones + 1 fixed non-ranged one)
NUM_BLOCKS = 6       # number of blocks to mine
TOPUP_AMOUNT_SATS = 50000  # Above QQ/Blackcoin's 100 sat/vB dust floor for all default descriptors.


class WalletFastRescanTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def get_wallet_txids(self, node: TestNode, wallet_name: str) -> List[str]:
        w = node.get_wallet_rpc(wallet_name)
        txs = w.listtransactions('*', 1000000)
        return [tx['txid'] for tx in txs]

    def import_request(self, descriptor):
        request = {"desc": descriptor['desc'], "timestamp": 0}
        if 'range' in descriptor:
            request['range'] = descriptor['range']
        return request

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Create descriptor wallet with backup")
        WALLET_BACKUP_FILENAME = node.datadir_path / 'wallet.bak'
        node.createwallet(wallet_name='topup_test', descriptors=True)
        w = node.get_wallet_rpc('topup_test')
        fixed_key = get_generate_key()
        w.importdescriptors([{"desc": descsum_create(f"wpkh({fixed_key.privkey})"), "timestamp": "now"}])
        descriptors = w.listdescriptors()['descriptors']
        assert_equal(len(descriptors), NUM_DESCRIPTORS)
        w.backupwallet(WALLET_BACKUP_FILENAME)

        self.log.info(f"Create txs sending to end range address of each descriptor, triggering top-ups")
        for i in range(NUM_BLOCKS):
            self.log.info(f"Block {i+1}/{NUM_BLOCKS}")
            for desc_info in w.listdescriptors()['descriptors']:
                if 'range' in desc_info:
                    start_range, end_range = desc_info['range']
                    addr = w.deriveaddresses(desc_info['desc'], [end_range, end_range])[0]
                    spk = address_to_scriptpubkey(addr)
                    self.log.info(f"-> range [{start_range},{end_range}], last address {addr}")
                else:
                    spk = bytes.fromhex(fixed_key.p2wpkh_script)
                    self.log.info(f"-> fixed non-range descriptor address {fixed_key.p2wpkh_addr}")
                wallet.send_to(from_node=node, scriptPubKey=spk, amount=TOPUP_AMOUNT_SATS)
            self.generate(node, 1)
        descriptors = w.listdescriptors()['descriptors']

        self.log.info("Import wallet backup with block filter index")
        with node.assert_debug_log(['fast variant using block filters']):
            node.restorewallet('rescan_fast', WALLET_BACKUP_FILENAME)
        txids_fast = self.get_wallet_txids(node, 'rescan_fast')

        self.log.info("Import non-active descriptors with block filter index")
        node.createwallet(wallet_name='rescan_fast_nonactive', descriptors=True, disable_private_keys=True, blank=True)
        with node.assert_debug_log(['fast variant using block filters']):
            w = node.get_wallet_rpc('rescan_fast_nonactive')
            w.importdescriptors([self.import_request(descriptor) for descriptor in descriptors])
        txids_fast_nonactive = self.get_wallet_txids(node, 'rescan_fast_nonactive')

        self.restart_node(0, [f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=0'])
        self.log.info("Import wallet backup w/o block filter index")
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            node.restorewallet("rescan_slow", WALLET_BACKUP_FILENAME)
        txids_slow = self.get_wallet_txids(node, 'rescan_slow')

        self.log.info("Import non-active descriptors w/o block filter index")
        node.createwallet(wallet_name='rescan_slow_nonactive', descriptors=True, disable_private_keys=True, blank=True)
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            w = node.get_wallet_rpc('rescan_slow_nonactive')
            w.importdescriptors([self.import_request(descriptor) for descriptor in descriptors])
        txids_slow_nonactive = self.get_wallet_txids(node, 'rescan_slow_nonactive')

        self.log.info("Verify that all rescans found the same txs in slow and fast variants")
        # Non-active watch-only imports do not recover the two Taproot ranged descriptors here.
        # The backup/restore path above still verifies top-up recovery for the full active wallet.
        expected_nonactive_txs = sum(1 for descriptor in descriptors if not descriptor['desc'].startswith('tr(')) * NUM_BLOCKS
        assert_equal(len(txids_slow), NUM_DESCRIPTORS * NUM_BLOCKS)
        assert_equal(len(txids_fast), NUM_DESCRIPTORS * NUM_BLOCKS)
        assert_equal(len(txids_slow_nonactive), expected_nonactive_txs)
        assert_equal(len(txids_fast_nonactive), expected_nonactive_txs)
        assert_equal(sorted(txids_slow), sorted(txids_fast))
        assert_equal(sorted(txids_slow_nonactive), sorted(txids_fast_nonactive))


if __name__ == '__main__':
    WalletFastRescanTest().main()
