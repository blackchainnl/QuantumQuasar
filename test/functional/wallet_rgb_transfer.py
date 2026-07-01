#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet-originated RGB transfer between two wallets."""

from decimal import Decimal
import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletRGBTransferTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-qqgoldrushendtime=1"],
            ["-qqgoldrushendtime=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _seal(self, txid_or_outpoint, vout=None, amount=None):
        if isinstance(txid_or_outpoint, dict):
            seal = {"txid": txid_or_outpoint["txid"], "vout": txid_or_outpoint["vout"]}
        else:
            seal = {"txid": txid_or_outpoint, "vout": vout}
        if amount is not None:
            seal["amount"] = amount
        return seal

    def _confirm_wallet_tx(self, node, txid):
        for _ in range(3):
            tx = node.gettransaction(txid)
            if tx["confirmations"] > 0:
                self.sync_blocks()
                return
            if txid not in node.getrawmempool():
                try:
                    node.sendrawtransaction(tx["hex"])
                except JSONRPCException as exc:
                    if exc.error["code"] != -27:
                        raise
            self.generatetoaddress(self.nodes[0], 1, self.nodes[0].getnewaddress(), sync_fun=self.no_op)
            self.sync_blocks()
        assert node.gettransaction(txid)["confirmations"] > 0

    def _make_funded_seal(self, funder, owner):
        funder.setmocktime(int(time.time()) + funder.getblockcount() + 1)
        address = owner.getnewaddress()
        txid = funder.sendtoaddress(address, Decimal("0.01"))
        self._confirm_wallet_tx(funder, txid)
        decoded = funder.gettransaction(txid=txid, verbose=True)["decoded"]
        matches = [
            vout for vout in decoded["vout"]
            if vout["scriptPubKey"].get("address") == address
        ]
        assert_equal(len(matches), 1)
        outpoint = {"txid": txid, "vout": matches[0]["n"]}
        owner.lockunspent(False, [outpoint])
        return outpoint

    def run_test(self):
        sender = self.nodes[0]
        recipient = self.nodes[1]

        self.log.info("Maturing sender funds")
        self.generatetoaddress(sender, COINBASE_MATURITY + 1, sender.getnewaddress(), sync_fun=self.no_op)
        self.sync_blocks()

        self.log.info("Creating sender and recipient RGB seal UTXOs")
        input_seal = self._make_funded_seal(sender, sender)
        recipient_seal = self._make_funded_seal(sender, recipient)

        self.log.info("Importing sender RGB genesis assignment")
        genesis_consignment = {
            "genesis": {
                "ticker": "R2W",
                "name": "RGB Two Wallet Transfer",
                "total_supply": 500,
                "allocations": [self._seal(input_seal, amount=500)],
            },
            "transitions": [],
        }
        verification = sender.verifyrgbconsignment(genesis_consignment)
        assert_equal(verification["valid"], True)
        contract_id = verification["contract_id"]
        accepted = sender.acceptrgbconsignment(genesis_consignment)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["imported_assignments"], 1)
        assert_equal(accepted["balance"], 500)

        self.log.info("Creating sender-originated transfer to recipient seal")
        sender.lockunspent(True, [input_seal])
        transfer = sender.creatergbtransfer(
            contract_id,
            [self._seal(input_seal)],
            [self._seal(recipient_seal, amount=500)],
            {"fee_rate": 100},
        )
        assert_equal(transfer["complete"], True)
        assert_equal(transfer["committed"], True)
        assert_equal(transfer["imported_assignments"], 0)
        assert_equal(transfer["anchor_transition_ids"], [transfer["transition_id"]])
        assert_equal(transfer["input_asset_amount"], 500)
        assert_equal(transfer["output_asset_amount"], 500)

        scoped = sender.verifyrgbconsignment(transfer["consignment"], transfer["anchor_transition_ids"])
        assert_equal(scoped["valid"], True)
        assert_equal(scoped["transfer_anchor_commitment"], transfer["transfer_anchor_commitment"])

        self.generatetoaddress(sender, 1, sender.getnewaddress(), sync_fun=self.no_op)
        self.sync_blocks()
        assert_equal(sender.gettxout(input_seal["txid"], input_seal["vout"]), None)
        assert recipient.gettxout(recipient_seal["txid"], recipient_seal["vout"]) is not None

        self.log.info("Recipient accepts the scoped consignment anchored by sender transaction")
        received = recipient.acceptrgbconsignment(
            transfer["consignment"],
            transfer["hex"],
            transfer["anchor_transition_ids"],
        )
        assert_equal(received["valid"], True)
        assert_equal(received["anchor_checked"], True)
        assert_equal(received["contract_id"], contract_id)
        assert_equal(received["transfer_anchor_commitment"], transfer["transfer_anchor_commitment"])
        assert_equal(received["imported_assignments"], 1)
        assert_equal(received["skipped_assignments"], 0)
        assert_equal(received["balance"], 500)

        recipient_assets = recipient.listrgbassets()
        assert_equal(len(recipient_assets), 1)
        assert_equal(recipient_assets[0]["contract_id"], contract_id)
        assert_equal(recipient_assets[0]["balance"], 500)
        expected_assignment = self._seal(recipient_seal, amount=500)
        expected_assignment.update({
            "contract_id": contract_id,
            "spent": False,
            "timestamp": recipient_assets[0]["assignments"][0]["timestamp"],
        })
        assert_equal(recipient_assets[0]["assignments"], [expected_assignment])

        sender_assets = sender.listrgbassets(True)
        sender_asset = [asset for asset in sender_assets if asset["contract_id"] == contract_id][0]
        assert_equal(sender_asset["balance"], 0)
        spent_inputs = [
            assignment for assignment in sender_asset["assignments"]
            if assignment["txid"] == input_seal["txid"] and assignment["vout"] == input_seal["vout"]
        ]
        assert_equal(len(spent_inputs), 1)
        assert_equal(spent_inputs[0]["spent"], True)

        self.log.info("Restarting both wallets and checking RGB state reloads")
        self.restart_node(0, extra_args=self.extra_args[0])
        self.restart_node(1, extra_args=self.extra_args[1])
        recipient_assets = self.nodes[1].listrgbassets()
        assert_equal(len(recipient_assets), 1)
        assert_equal(recipient_assets[0]["contract_id"], contract_id)
        assert_equal(recipient_assets[0]["balance"], 500)
        exported = self.nodes[1].exportrgbconsignment(contract_id)
        assert_equal(exported["transition_count"], 1)
        assert_equal(exported["transition_ids"], [transfer["transition_id"]])
        assert_equal(exported["consignment"], transfer["consignment"])


if __name__ == "__main__":
    WalletRGBTransferTest().main()
