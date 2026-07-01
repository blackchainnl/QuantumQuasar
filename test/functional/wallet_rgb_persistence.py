#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet persistence for imported RGB and EUTXO state metadata."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletRGBPersistenceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _funded_eutxo_commitment(self, node, datum, validator):
        mining_address = node.getnewaddress("", "legacy")
        block_hashes = self.generatetoaddress(node, 101, mining_address, sync_fun=self.no_op)
        coinbase_txid = node.getblock(block_hashes[0])["tx"][0]
        coinbase = node.getrawtransaction(coinbase_txid, True, block_hashes[0])
        coinbase_value = Decimal(str(coinbase["vout"][0]["value"]))
        amount = coinbase_value - Decimal("0.001")

        raw = node.createrawtransaction(
            [{"txid": coinbase_txid, "vout": 0}],
            [{"eutxo": {"amount": amount, "datum": datum, "validator": validator}}],
        )
        signed = node.signrawtransactionwithwallet(
            raw,
            [{"txid": coinbase_txid, "vout": 0, "scriptPubKey": coinbase["vout"][0]["scriptPubKey"]["hex"], "amount": coinbase_value}],
        )
        assert_equal(signed["complete"], True)
        accepted = node.testmempoolaccept([signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"EUTXO funding transaction rejected: {accepted}")
        txid = node.sendrawtransaction(signed["hex"])
        self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        return txid, amount

    def _assert_wallet_state(self, node, contract_id, assignment_txid, eutxo_txid, eutxo_amount):
        assets = node.listrgbassets()
        assert_equal(len(assets), 1)
        assert_equal(assets[0]["contract_id"], contract_id)
        assert_equal(assets[0]["ticker"], "QQT")
        assert_equal(assets[0]["name"], "Blackcoin Test Asset")
        assert_equal(assets[0]["total_supply"], 1000)
        assert_equal(assets[0]["balance"], 1000)
        assert_equal(assets[0]["proof_available"], False)
        assert_equal(assets[0]["proof_transition_count"], 0)
        assert_equal(len(assets[0]["assignments"]), 1)
        assert_equal(assets[0]["assignments"][0]["txid"], assignment_txid)
        assert_equal(assets[0]["assignments"][0]["vout"], 0)
        assert_equal(assets[0]["assignments"][0]["amount"], 1000)
        assert_equal(assets[0]["assignments"][0]["spent"], False)

        states = node.listeutxostates()
        assert_equal(len(states), 1)
        assert_equal(states[0]["txid"], eutxo_txid)
        assert_equal(states[0]["vout"], 0)
        assert_equal(Decimal(str(states[0]["amount"])), eutxo_amount)
        assert_equal(states[0]["datum"], "01")
        assert_equal(states[0]["validator"], "52885187")
        assert_equal(states[0]["spent"], False)

    def _assert_spent_eutxo_state(self, node, eutxo_txid, eutxo_amount):
        assert_equal(node.listeutxostates(), [])
        states = node.listeutxostates(True)
        assert_equal(len(states), 1)
        assert_equal(states[0]["txid"], eutxo_txid)
        assert_equal(states[0]["vout"], 0)
        assert_equal(Decimal(str(states[0]["amount"])), eutxo_amount)
        assert_equal(states[0]["datum"], "01")
        assert_equal(states[0]["validator"], "52885187")
        assert_equal(states[0]["spent"], True)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Importing RGB contract and owned assignment metadata")
        contract_id = "11" * 32
        assignment_txid = "22" * 32
        imported_contract = node.importrgbcontract({
            "contract_id": contract_id,
            "ticker": "QQT",
            "name": "Blackcoin Test Asset",
            "total_supply": 1000,
            "timestamp": 123,
        })
        assert_equal(imported_contract["contract_id"], contract_id)

        imported_assignment = node.importrgbassignment({
            "contract_id": contract_id,
            "txid": assignment_txid,
            "vout": 0,
            "amount": 1000,
            "timestamp": 124,
        })
        assert_equal(imported_assignment["contract_id"], contract_id)
        assert_equal(imported_assignment["txid"], assignment_txid)
        assert_raises_rpc_error(
            -4,
            "RGB proof graph is not available",
            node.exportrgbconsignment,
            contract_id,
        )

        self.log.info("Rejecting inconsistent RGB import metadata")
        assert_raises_rpc_error(
            -4,
            "Failed to import RGB contract metadata",
            node.importrgbcontract,
            {
                "contract_id": contract_id,
                "ticker": "BAD",
                "name": "Blackcoin Test Asset",
                "total_supply": 1000,
            },
        )
        assert_raises_rpc_error(
            -4,
            "Failed to import RGB assignment",
            node.importrgbassignment,
            {
                "contract_id": "33" * 32,
                "txid": assignment_txid,
                "vout": 1,
                "amount": 1000,
            },
        )

        self.log.info("Importing live EUTXO state metadata")
        eutxo_txid, eutxo_amount = self._funded_eutxo_commitment(node, datum="01", validator="52885187")
        assert_raises_rpc_error(
            -26,
            "Live UTXO does not match supplied EUTXO state metadata",
            node.importeutxostate,
            {
                "txid": eutxo_txid,
                "vout": 0,
                "amount": eutxo_amount,
                "datum": "02",
                "validator": "52885187",
            },
        )
        imported_state = node.importeutxostate({
            "txid": eutxo_txid,
            "vout": 0,
            "amount": eutxo_amount,
            "datum": "01",
            "validator": "52885187",
            "timestamp": 125,
        })
        assert_equal(imported_state["txid"], eutxo_txid)
        self._assert_wallet_state(node, contract_id, assignment_txid, eutxo_txid, eutxo_amount)

        self.log.info("Restarting node and verifying wallet metadata reload")
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        self._assert_wallet_state(node, contract_id, assignment_txid, eutxo_txid, eutxo_amount)

        self.log.info("Spending imported EUTXO state and verifying list reconciliation")
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        spend_amount = eutxo_amount - Decimal("0.001")
        spend = node.createeutxospend(
            {"txid": eutxo_txid, "vout": 0, "datum": "01", "validator": "52885187", "redeemer": "02"},
            [{node.getnewaddress(): spend_amount}],
        )
        accepted = node.testmempoolaccept([spend["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"EUTXO state spend rejected: {accepted}")
        node.sendrawtransaction(spend["hex"])
        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        self._assert_spent_eutxo_state(node, eutxo_txid, eutxo_amount)

        self.restart_node(0, extra_args=self.extra_args[0])
        self._assert_spent_eutxo_state(self.nodes[0], eutxo_txid, eutxo_amount)


if __name__ == "__main__":
    WalletRGBPersistenceTest().main()
