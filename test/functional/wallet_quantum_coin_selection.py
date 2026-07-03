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

    def _outpoint(self, utxo):
        return (utxo["txid"], utxo["vout"])

    def _selected_outpoints(self, decoded_tx):
        return {(vin["txid"], vin["vout"]) for vin in decoded_tx["vin"]}

    def _assert_quantum_not_selected(self, label, decoded_tx, quantum_outpoint):
        selected = self._selected_outpoints(decoded_tx)
        assert selected, f"{label} transaction must select at least one input"
        assert quantum_outpoint not in selected, f"{label} selected quantum-family input {quantum_outpoint[0]}:{quantum_outpoint[1]}"

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
        quantum_outpoint = self._outpoint(quantum_utxos[0])

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

        self.log.info("Legacy funding RPCs must not select the quantum UTXO when legacy coins are available")
        assert_equal(node.lockunspent(True, legacy_locks), True)
        raw = node.createrawtransaction([], [{node.getnewaddress("legacy-fundraw-recipient"): Decimal("1")}])
        funded = node.fundrawtransaction(raw)
        self._assert_quantum_not_selected("fundrawtransaction", node.decoderawtransaction(funded["hex"]), quantum_outpoint)

        sendall = node.sendall(recipients=[node.getnewaddress("legacy-sendall-recipient")], add_to_wallet=False)
        self._assert_quantum_not_selected("sendall", node.decoderawtransaction(sendall["hex"]), quantum_outpoint)

        legacy_txid = node.sendtoaddress(node.getnewaddress("legacy-recipient"), Decimal("1"))
        legacy_tx = node.gettransaction(txid=legacy_txid, verbose=True)
        assert_equal(legacy_tx["txid"], legacy_txid)
        self._assert_quantum_not_selected("sendtoaddress", legacy_tx["decoded"], quantum_outpoint)


if __name__ == "__main__":
    WalletQuantumCoinSelectionTest().main()
