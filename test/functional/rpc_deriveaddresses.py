#!/usr/bin/env python3
# Copyright (c) 2018-2022 Blackcoin Core Developers
# Copyright (c) 2018-2022 Blackcoin More Developers
# Copyright (c) 2018-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the deriveaddresses rpc call."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create, descsum_create_with_main_xkeys
from test_framework.util import assert_equal, assert_raises_rpc_error

class DeriveaddressesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        assert_raises_rpc_error(-5, "Missing checksum", self.nodes[0].deriveaddresses, "a")

        descriptor = descsum_create_with_main_xkeys("wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)")
        address = self.nodes[0].deriveaddresses(descriptor)[0]
        assert_equal(self.nodes[0].deriveaddresses(descriptor), [address])

        descriptor = descriptor[:-9]
        assert_raises_rpc_error(-5, "Missing checksum", self.nodes[0].deriveaddresses, descriptor)

        descriptor_pubkey = descsum_create_with_main_xkeys("wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)")
        assert_equal(self.nodes[0].deriveaddresses(descriptor_pubkey), [address])

        ranged_descriptor = descsum_create_with_main_xkeys("wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*)")
        ranged = self.nodes[0].deriveaddresses(ranged_descriptor, 2)
        assert_equal(self.nodes[0].deriveaddresses(ranged_descriptor, [1, 2]), ranged[1:3])
        assert_equal(ranged[0], address)

        assert_raises_rpc_error(-8, "Range should not be specified for an un-ranged descriptor", self.nodes[0].deriveaddresses, descsum_create_with_main_xkeys("wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)"), [0, 2])

        assert_raises_rpc_error(-8, "Range must be specified for a ranged descriptor", self.nodes[0].deriveaddresses, ranged_descriptor)

        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].deriveaddresses, ranged_descriptor, 10000000000)

        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].deriveaddresses, ranged_descriptor, [1000000000, 2000000000])

        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].deriveaddresses, ranged_descriptor, [2, 0])

        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].deriveaddresses, ranged_descriptor, [-1, 0])

        combo_descriptor = descsum_create_with_main_xkeys("combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)")
        combo_addresses = self.nodes[0].deriveaddresses(combo_descriptor)
        assert len(combo_addresses) >= 3
        assert address in combo_addresses

        # P2PK does not have a valid address
        assert len(self.nodes[0].deriveaddresses(descsum_create_with_main_xkeys("pk(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK)"))) >= 1

        # Before #26275, bitcoind would crash when deriveaddresses was
        # called with derivation index 2147483647, which is the maximum
        # positive value of a signed int32, and - currently - the
        # maximum value that the deriveaddresses bitcoin RPC call
        # accepts as derivation index.
        assert_equal(len(self.nodes[0].deriveaddresses(ranged_descriptor, [2147483647, 2147483647])), 1)

        hardened_without_privkey_descriptor = descsum_create_with_main_xkeys("wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/1/0)")
        assert_raises_rpc_error(-5, "Cannot derive script without private keys", self.nodes[0].deriveaddresses, hardened_without_privkey_descriptor)

        bare_multisig_descriptor = descsum_create_with_main_xkeys("multi(1,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/1)")
        assert_raises_rpc_error(-5, "Descriptor does not have a corresponding address", self.nodes[0].deriveaddresses, bare_multisig_descriptor)

if __name__ == '__main__':
    DeriveaddressesTest().main()
