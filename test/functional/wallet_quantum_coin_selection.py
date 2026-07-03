#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Core Developers
# Copyright (c) 2026 Blackcoin More Developers
# Copyright (c) 2026 Quantum Quasar Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Regression tests for mixed legacy/quantum wallet coin selection."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletQuantumCoinSelectionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining_address = node.getnewaddress("legacy-mining")

        self.log.info("Mine mature legacy funds")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, mining_address, sync_fun=self.no_op)

        self.log.info("Funding a quantum address from legacy coins remains supported")
        quantum_address = node.getnewquantumaddress("quantum-target")["address"]
        quantum_txid = node.sendtoaddress(quantum_address, Decimal("10"))
        self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        quantum_utxos = node.listunspent(1, 9999999, [quantum_address])
        assert_equal(len(quantum_utxos), 1)
        assert_equal(quantum_utxos[0]["txid"], quantum_txid)

        self.log.info("A legacy send must not fall through to the available quantum UTXO")
        legacy_locks = [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in node.listunspent()
            if utxo.get("address") != quantum_address
        ]
        assert legacy_locks
        assert_equal(node.lockunspent(False, legacy_locks), True)
        assert_raises_rpc_error(
            -6,
            "Insufficient funds",
            node.sendtoaddress,
            node.getnewaddress("legacy-recipient"),
            Decimal("1"),
        )

        self.log.info("Unlocking legacy coins allows the same legacy send")
        assert_equal(node.lockunspent(True, legacy_locks), True)
        legacy_txid = node.sendtoaddress(node.getnewaddress("legacy-recipient"), Decimal("1"))
        legacy_tx = node.gettransaction(legacy_txid)
        assert_equal(legacy_tx["txid"], legacy_txid)


if __name__ == "__main__":
    WalletQuantumCoinSelectionTest().main()
