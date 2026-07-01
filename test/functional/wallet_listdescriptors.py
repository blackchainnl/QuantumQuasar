#!/usr/bin/env python3
# Copyright (c) 2014-2022 Blackcoin Core Developers
# Copyright (c) 2014-2022 Blackcoin More Developers
# Copyright (c) 2014-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listdescriptors RPC."""

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
)
from test_framework.descriptors import (
    descsum_create,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class ListDescriptorsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # do not create any wallet by default
    def init_wallet(self, *, node):
        return

    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-18, 'No wallet is loaded.', node.listdescriptors)

        if self.is_bdb_compiled():
            self.log.info('Test that the command is not available for legacy wallets.')
            node.createwallet(wallet_name='w1', descriptors=False)
            assert_raises_rpc_error(-4, 'listdescriptors is not available for non-descriptor wallets', node.listdescriptors)

        self.log.info('Test the command for empty descriptors wallet.')
        node.createwallet(wallet_name='w2', blank=True, descriptors=True)
        assert_equal(0, len(node.get_wallet_rpc('w2').listdescriptors()['descriptors']))

        self.log.info('Test the command for a default descriptors wallet.')
        node.createwallet(wallet_name='w3', descriptors=True)
        result = node.get_wallet_rpc('w3').listdescriptors()
        assert_equal("w3", result['wallet_name'])
        assert_equal(8, len(result['descriptors']))
        assert_equal(8, len([d for d in result['descriptors'] if d['active']]))
        assert_equal(4, len([d for d in result['descriptors'] if d['internal']]))
        for item in result['descriptors']:
            assert item['desc'] != ''
            assert item['next_index'] == 0
            assert item['range'] == [0, 0]
            assert item['timestamp'] is not None

        self.log.info('Test that descriptor strings are returned in lexicographically sorted order.')
        descriptor_strings = [descriptor['desc'] for descriptor in result['descriptors']]
        assert_equal(descriptor_strings, sorted(descriptor_strings))

        self.log.info('Test descriptors with hardened derivations are listed in importable form.')
        source_public = next(d for d in result['descriptors'] if d['desc'].startswith('wpkh(') and not d.get('internal', False))
        source_private = next(d for d in node.get_wallet_rpc('w3').listdescriptors(True)['descriptors'] if d['desc'].startswith('wpkh(') and not d.get('internal', False))
        wallet = node.get_wallet_rpc('w2')
        import_request = {
            'desc': source_private['desc'],
            'timestamp': TIME_GENESIS_BLOCK,
        }
        if 'range' in source_private:
            import_request['range'] = source_private['range']
        import_result = wallet.importdescriptors([import_request])
        assert import_result[0]['success'], import_result[0]
        expected_entry = {
            'desc': source_public['desc'],
            'timestamp': TIME_GENESIS_BLOCK,
            'active': False,
        }
        if 'range' in source_public:
            expected_entry['range'] = source_public['range']
            expected_entry['next'] = 0
            expected_entry['next_index'] = 0
        expected = {
            'wallet_name': 'w2',
            'descriptors': [expected_entry],
        }
        assert_equal(expected, wallet.listdescriptors())
        assert_equal(expected, wallet.listdescriptors(False))

        self.log.info('Test list private descriptors')
        expected_private_entry = {
            'desc': source_private['desc'],
            'timestamp': TIME_GENESIS_BLOCK,
            'active': False,
        }
        if 'range' in source_private:
            expected_private_entry['range'] = source_private['range']
            expected_private_entry['next'] = 0
            expected_private_entry['next_index'] = 0
        expected_private = {
            'wallet_name': 'w2',
            'descriptors': [expected_private_entry],
        }
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info("Test listdescriptors with encrypted wallet")
        wallet.encryptwallet("pass")
        assert_equal(expected, wallet.listdescriptors())

        self.log.info('Test list private descriptors with encrypted wallet')
        assert_raises_rpc_error(-13, 'Please enter the wallet passphrase with walletpassphrase first.', wallet.listdescriptors, True)
        wallet.walletpassphrase(passphrase="pass", timeout=1000000)
        assert_equal(expected_private, wallet.listdescriptors(True))

        self.log.info('Test list private descriptors with watch-only wallet')
        node.createwallet(wallet_name='watch-only', descriptors=True, disable_private_keys=True)
        watch_only_wallet = node.get_wallet_rpc('watch-only')
        watch_only_wallet.importdescriptors([{
            'desc': source_public['desc'],
            'timestamp': TIME_GENESIS_BLOCK,
            'range': source_public.get('range', [0, 0]),
        }])
        assert_raises_rpc_error(-4, 'Can\'t get descriptor string', watch_only_wallet.listdescriptors, True)

        self.log.info('Test non-active non-range combo descriptor')
        node.createwallet(wallet_name='w4', blank=True, descriptors=True)
        wallet = node.get_wallet_rpc('w4')
        wallet.importdescriptors([{
            'desc': descsum_create('combo(' + node.get_deterministic_priv_key().key + ')'),
            'timestamp': TIME_GENESIS_BLOCK,
        }])
        result = wallet.listdescriptors()
        assert_equal('w4', result['wallet_name'])
        assert_equal(1, len(result['descriptors']))
        assert_equal(False, result['descriptors'][0]['active'])
        assert_equal(TIME_GENESIS_BLOCK, result['descriptors'][0]['timestamp'])
        assert result['descriptors'][0]['desc'].startswith('combo(')
        assert node.get_deterministic_priv_key().key not in result['descriptors'][0]['desc']


if __name__ == '__main__':
    ListDescriptorsTest().main()
