#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet-level RGB consignment acceptance and persistence."""

from copy import deepcopy
from decimal import Decimal
import time

from test_framework.address import key_to_p2pkh
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class WalletRGBConsignmentTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _seal(self, tag_or_utxo, amount=None):
        if isinstance(tag_or_utxo, dict):
            seal = {"txid": tag_or_utxo["txid"], "vout": tag_or_utxo["vout"]}
        else:
            seal = {"txid": f"{tag_or_utxo:064x}", "vout": 0}
        if amount is not None:
            seal["amount"] = amount
        return seal

    def _seal_sort_key(self, seal):
        return (bytes.fromhex(seal["txid"])[::-1], seal["vout"])

    def _consignment(self, input_seal, wallet_seal, external_seal):
        outputs = [self._seal(wallet_seal, 400), self._seal(external_seal, 600)]
        outputs.sort(key=self._seal_sort_key)
        return {
            "genesis": {
                "ticker": "RQC",
                "name": "RGB Quantum Consignment",
                "total_supply": 1000,
                "allocations": [self._seal(input_seal, 1000)],
            },
            "transitions": [{
                "inputs": [self._seal(input_seal)],
                "outputs": outputs,
            }],
        }

    def _order_sensitive_consignment(self):
        first = {
            "inputs": [self._seal(0x20)],
            "outputs": [self._seal(0x40, 200)],
        }
        second = {
            "inputs": [self._seal(0x10)],
            "outputs": [self._seal(0x30, 100)],
        }
        return {
            "genesis": {
                "ticker": "RQO",
                "name": "RGB Ordered Export",
                "total_supply": 300,
                "allocations": [self._seal(0x10, 100), self._seal(0x20, 200)],
            },
            "transitions": [first, second],
        }

    def _extended_consignment(self, consignment, input_seal, wallet_seal, external_seal):
        outputs = [self._seal(wallet_seal, 250), self._seal(external_seal, 150)]
        outputs.sort(key=self._seal_sort_key)
        extended = deepcopy(consignment)
        extended["transitions"].append({
            "inputs": [self._seal(input_seal)],
            "outputs": outputs,
        })
        return extended

    def _make_wallet_seal(self, node):
        node.setmocktime(int(time.time()) + node.getblockcount() + 1)
        address = node.getnewaddress()
        txid = node.sendtoaddress(address, Decimal("0.01"))
        self._confirm_wallet_tx(node, txid)
        tx = node.gettransaction(txid=txid, verbose=True)["decoded"]
        matches = [
            vout for vout in tx["vout"]
            if vout["scriptPubKey"].get("address") == address
        ]
        assert_equal(len(matches), 1)
        return {"txid": txid, "vout": matches[0]["n"]}

    def _make_external_seal(self, node):
        node.setmocktime(int(time.time()) + node.getblockcount() + 1)
        _, pubkey = generate_keypair(wif=True)
        external_address = key_to_p2pkh(pubkey)
        txid = node.sendtoaddress(external_address, Decimal("0.01"))
        self._confirm_wallet_tx(node, txid)
        tx = node.gettransaction(txid=txid, verbose=True)["decoded"]
        matches = [
            vout for vout in tx["vout"]
            if vout["scriptPubKey"].get("address") == external_address
        ]
        assert_equal(len(matches), 1)
        return {"txid": txid, "vout": matches[0]["n"]}

    def _confirm_wallet_tx(self, node, txid):
        for _ in range(3):
            tx = node.gettransaction(txid)
            if tx["confirmations"] > 0:
                return
            if txid not in node.getrawmempool():
                try:
                    node.sendrawtransaction(tx["hex"])
                except JSONRPCException as exc:
                    if exc.error["code"] != -27:
                        raise
            self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        assert node.gettransaction(txid)["confirmations"] > 0

    def _signed_anchor_tx(self, node, input_seal, anchor_commitment):
        node.setmocktime(int(time.time()) + node.getblockcount())
        input_outpoint = {"txid": input_seal["txid"], "vout": input_seal["vout"]}
        if input_outpoint in node.listlockunspent():
            node.lockunspent(True, [input_outpoint])
        raw = node.createrawtransaction(
            [input_outpoint],
            [{"rgb_commitment": anchor_commitment}],
        )
        funded = node.fundrawtransaction(raw)
        signed = node.signrawtransactionwithwallet(funded["hex"])
        assert_equal(signed.get("errors", []), [])
        assert_equal(signed["complete"], True)
        return signed["hex"]

    def _anchored_tx(self, node, input_seal, anchor_commitment):
        signed_hex = self._signed_anchor_tx(node, input_seal, anchor_commitment)
        accept = node.testmempoolaccept([signed_hex])[0]
        if not accept["allowed"]:
            raise AssertionError(f"anchor transaction rejected: {accept}")
        txid = node.sendrawtransaction(signed_hex)
        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        assert_equal(node.gettransaction(txid)["confirmations"], 1)
        return signed_hex

    def _assert_pre_anchor_assignment_live(self, node, contract_id, input_seal):
        assets = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == contract_id]
        assert_equal(len(assets), 1)
        assert_equal(assets[0]["proof_transition_count"], 0)
        assignments = [
            assignment for assignment in assets[0]["assignments"]
            if assignment["txid"] == input_seal["txid"] and assignment["vout"] == input_seal["vout"]
        ]
        assert_equal(len(assignments), 1)
        assert_equal(assignments[0]["spent"], False)

    def _assert_imported_asset(self, node, contract_id, input_seal, wallet_seal, external_seal, anchor_txid, anchor_vout, anchor_commitment):
        assets = node.listrgbassets()
        assert_equal(len(assets), 1)
        asset = assets[0]
        assert_equal(asset["contract_id"], contract_id)
        assert_equal(asset["ticker"], "RQC")
        assert_equal(asset["name"], "RGB Quantum Consignment")
        assert_equal(asset["total_supply"], 1000)
        assert_equal(asset["balance"], 400)
        assert_equal(asset["proof_available"], True)
        assert_equal(asset["proof_transition_count"], 1)

        assert_equal(len(asset["transitions"]), 1)
        transition = asset["transitions"][0]
        assert_equal(transition["contract_id"], contract_id)
        assert_equal(transition["anchor_commitment"], anchor_commitment)
        assert_equal(transition["anchor_checked"], True)
        assert_equal(transition["anchor_txid"], anchor_txid)
        assert_equal(transition["anchor_vout"], anchor_vout)
        assert_equal(transition["inputs"], [{"txid": input_seal["txid"], "vout": input_seal["vout"]}])
        assert_equal(len(transition["outputs"]), 2)
        assert {"txid": wallet_seal["txid"], "vout": wallet_seal["vout"]} in transition["outputs"]
        assert {"txid": external_seal["txid"], "vout": external_seal["vout"]} in transition["outputs"]

        assert_equal(len(asset["assignments"]), 1)
        assert_equal(asset["assignments"][0]["txid"], wallet_seal["txid"])
        assert_equal(asset["assignments"][0]["vout"], wallet_seal["vout"])
        assert_equal(asset["assignments"][0]["amount"], 400)

        all_assets = node.listrgbassets(True)
        assert_equal(len(all_assets), 1)
        assert_equal(all_assets[0]["balance"], 400)
        assert_equal(len(all_assets[0]["assignments"]), 2)
        input_assignment = [
            assignment for assignment in all_assets[0]["assignments"]
            if assignment["txid"] == input_seal["txid"] and assignment["vout"] == input_seal["vout"]
        ]
        assert_equal(len(input_assignment), 1)
        assert_equal(input_assignment[0]["amount"], 1000)
        assert_equal(input_assignment[0]["spent"], True)

    def _assert_exported_consignment(self, node, contract_id, input_seal, wallet_seal, external_seal, anchor_commitment):
        exported = node.exportrgbconsignment(contract_id)
        assert_equal(exported["proof_complete"], True)
        assert_equal(exported["contract_id"], contract_id)
        assert_equal(exported["transition_count"], 1)
        assert_equal(exported["bundle_anchor_commitment"], anchor_commitment)
        assert_equal(len(exported["transition_ids"]), 1)

        consignment = exported["consignment"]
        genesis = consignment["genesis"]
        assert_equal(genesis["ticker"], "RQC")
        assert_equal(genesis["name"], "RGB Quantum Consignment")
        assert_equal(genesis["total_supply"], 1000)
        assert_equal(genesis["allocations"], [self._seal(input_seal, 1000)])

        assert_equal(len(consignment["transitions"]), 1)
        transition = consignment["transitions"][0]
        assert_equal(transition["contract_id"], contract_id)
        assert_equal(transition["inputs"], [self._seal(input_seal)])
        assert_equal(len(transition["outputs"]), 2)
        assert self._seal(wallet_seal, 400) in transition["outputs"]
        assert self._seal(external_seal, 600) in transition["outputs"]

        verification = node.verifyrgbconsignment(consignment)
        assert_equal(verification["valid"], True)
        assert_equal(verification["errors"], [])
        assert_equal(verification["contract_id"], contract_id)
        assert_equal(verification["anchor_commitment"], anchor_commitment)
        assert_equal(verification["transition_ids"], exported["transition_ids"])

    def _assert_extended_asset(self, node, contract_id, input_seal, wallet_seal, next_wallet_seal, first_anchor_txid, second_anchor_txid):
        assets = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == contract_id]
        assert_equal(len(assets), 1)
        asset = assets[0]
        assert_equal(asset["balance"], 250)
        assert_equal(asset["proof_available"], True)
        assert_equal(asset["proof_transition_count"], 2)

        spent_inputs = {
            (assignment["txid"], assignment["vout"])
            for assignment in asset["assignments"]
            if assignment["spent"]
        }
        assert (input_seal["txid"], input_seal["vout"]) in spent_inputs
        assert (wallet_seal["txid"], wallet_seal["vout"]) in spent_inputs
        live_assignments = [
            assignment for assignment in asset["assignments"]
            if not assignment["spent"]
        ]
        assert_equal(len(live_assignments), 1)
        assert_equal(live_assignments[0]["txid"], next_wallet_seal["txid"])
        assert_equal(live_assignments[0]["vout"], next_wallet_seal["vout"])
        assert_equal(live_assignments[0]["amount"], 250)

        assert_equal(len(asset["transitions"]), 2)
        transitions_by_input = {
            (transition["inputs"][0]["txid"], transition["inputs"][0]["vout"]): transition
            for transition in asset["transitions"]
        }
        first_transition = transitions_by_input[(input_seal["txid"], input_seal["vout"])]
        second_transition = transitions_by_input[(wallet_seal["txid"], wallet_seal["vout"])]
        assert_equal(first_transition["anchor_checked"], True)
        assert_equal(first_transition["anchor_txid"], first_anchor_txid)
        assert_equal(second_transition["anchor_checked"], True)
        assert_equal(second_transition["anchor_txid"], second_anchor_txid)

    def _assert_scoped_anchor_import(self, node, contract_id, consignment, input_seal, wallet_seal, next_wallet_seal, external_seal):
        extended = self._extended_consignment(consignment, wallet_seal, next_wallet_seal, external_seal)

        full_verification = node.verifyrgbconsignment(extended)
        assert_equal(full_verification["valid"], True)
        assert_equal(full_verification["errors"], [])
        new_transition_id = full_verification["transition_ids"][-1]
        scoped_verification = node.verifyrgbconsignment(extended, [new_transition_id])
        assert_equal(scoped_verification["valid"], True)
        assert_equal(scoped_verification["anchor_transition_ids"], [new_transition_id])
        assert_equal(scoped_verification["anchor_commitment"], full_verification["anchor_commitment"])
        assert scoped_verification["transfer_anchor_commitment"] != full_verification["anchor_commitment"]

        second_anchor = self._anchored_tx(node, wallet_seal, scoped_verification["transfer_anchor_commitment"])
        second_anchor_txid = node.decoderawtransaction(second_anchor)["txid"]
        accepted = node.acceptrgbconsignment(extended, second_anchor, [new_transition_id])
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["anchor_checked"], True)
        assert_equal(accepted["anchor_transition_ids"], [new_transition_id])
        assert_equal(accepted["anchor_commitment"], full_verification["anchor_commitment"])
        assert_equal(accepted["consignment_anchor_commitment"], full_verification["anchor_commitment"])
        assert_equal(accepted["transfer_anchor_commitment"], scoped_verification["transfer_anchor_commitment"])
        assert_equal(accepted["spent_assignments"], 0)
        assert_equal(accepted["imported_assignments"], 1)
        assert_equal(accepted["balance"], 250)

        first_anchor_txid = [
            transition["anchor_txid"]
            for transition in node.listrgbassets(True)[0]["transitions"]
            if transition["inputs"] == [self._seal(input_seal)]
        ][0]
        self._assert_extended_asset(node, contract_id, input_seal, wallet_seal, next_wallet_seal, first_anchor_txid, second_anchor_txid)

        exported = node.exportrgbconsignment(contract_id)
        assert_equal(exported["transition_count"], 2)
        assert_equal(exported["bundle_anchor_commitment"], full_verification["consignment_anchor_commitment"])
        verify_exported = node.verifyrgbconsignment(exported["consignment"])
        assert_equal(verify_exported["valid"], True)
        assert_equal(verify_exported["transition_ids"], full_verification["transition_ids"])
        return first_anchor_txid, second_anchor_txid

    def _assert_ordered_export(self, node):
        consignment = self._order_sensitive_consignment()
        verification = node.verifyrgbconsignment(consignment)
        assert_equal(verification["valid"], True)
        assert_equal(verification["errors"], [])

        accepted = node.acceptrgbconsignment(consignment)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["imported_transitions"], 2)
        assert_equal(accepted["anchor_commitment"], verification["anchor_commitment"])

        exported = node.exportrgbconsignment(verification["contract_id"])
        assert_equal(exported["proof_complete"], True)
        assert_equal(exported["transition_count"], 2)
        assert_equal(exported["transition_ids"], verification["transition_ids"])
        assert_equal(exported["bundle_anchor_commitment"], verification["anchor_commitment"])
        transitions = exported["consignment"]["transitions"]
        assert_equal(len(transitions), 2)
        assert_equal(transitions[0]["inputs"], consignment["transitions"][0]["inputs"])
        assert_equal(transitions[0]["outputs"], consignment["transitions"][0]["outputs"])
        assert_equal(transitions[1]["inputs"], consignment["transitions"][1]["inputs"])
        assert_equal(transitions[1]["outputs"], consignment["transitions"][1]["outputs"])

    def _assert_unanchored_consignment_cannot_spend_wallet_assignment(self, node):
        input_seal = self._make_wallet_seal(node)
        genesis = {
            "ticker": "RGF",
            "name": "RGB Griefing Guard",
            "total_supply": 500,
            "allocations": [self._seal(input_seal, 500)],
        }
        base_consignment = {
            "genesis": genesis,
            "transitions": [],
        }
        contract_id = node.verifyrgbconsignment(base_consignment)["contract_id"]
        accepted = node.acceptrgbconsignment(base_consignment)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["imported_assignments"], 1)
        assert_equal(accepted["balance"], 500)

        attack_consignment = {
            "genesis": genesis,
            "transitions": [{
                "inputs": [self._seal(input_seal)],
                "outputs": [self._seal(0x500, 500)],
            }],
        }
        assert_raises_rpc_error(
            -4,
            "Unanchored RGB transition spends an unspent wallet-owned assignment",
            node.acceptrgbconsignment,
            attack_consignment,
        )

        assets = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == contract_id]
        assert_equal(len(assets), 1)
        assert_equal(assets[0]["balance"], 500)
        assignments = [
            assignment for assignment in assets[0]["assignments"]
            if assignment["txid"] == input_seal["txid"] and assignment["vout"] == input_seal["vout"]
        ]
        assert_equal(len(assignments), 1)
        assert_equal(assignments[0]["spent"], False)
        assert_equal(assets[0]["proof_transition_count"], 0)

    def _assert_wallet_originated_transfer(self, node):
        input_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [self._seal(input_seal)])
        wallet_output_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [self._seal(wallet_output_seal)])
        second_wallet_output_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [self._seal(second_wallet_output_seal)])
        consignment = {
            "genesis": {
                "ticker": "RWT",
                "name": "RGB Wallet Transfer",
                "total_supply": 500,
                "allocations": [self._seal(input_seal, 500)],
            },
            "transitions": [],
        }
        verification = node.verifyrgbconsignment(consignment)
        assert_equal(verification["valid"], True)
        contract_id = verification["contract_id"]

        accepted = node.acceptrgbconsignment(consignment)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["imported_transitions"], 0)
        assert_equal(accepted["imported_assignments"], 1)
        assert_equal(accepted["balance"], 500)

        node.lockunspent(True, [self._seal(input_seal)])
        outputs = [self._seal(wallet_output_seal, 200), self._seal(second_wallet_output_seal, 300)]
        transfer = node.creatergbtransfer(
            contract_id,
            [self._seal(input_seal)],
            outputs,
            {"fee_rate": 100},
        )
        assert_equal(transfer["complete"], True)
        assert_equal(transfer["committed"], True)
        assert_equal(transfer["contract_id"], contract_id)
        assert_equal(transfer["input_asset_amount"], 500)
        assert_equal(transfer["output_asset_amount"], 500)
        assert_equal(transfer["imported_assignments"], 2)
        assert_equal(transfer["anchor_transition_ids"], [transfer["transition_id"]])
        assert transfer["anchor_txid"] in node.getrawmempool()

        scoped_verification = node.verifyrgbconsignment(transfer["consignment"], transfer["anchor_transition_ids"])
        assert_equal(scoped_verification["valid"], True)
        assert_equal(scoped_verification["errors"], [])
        assert_equal(scoped_verification["transfer_anchor_commitment"], transfer["transfer_anchor_commitment"])

        decoded_anchor = node.decoderawtransaction(transfer["hex"])
        assert_equal(decoded_anchor["txid"], transfer["anchor_txid"])
        rgb_vouts = [
            vout for vout in decoded_anchor["vout"]
            if vout["scriptPubKey"]["type"] == "rgb_commitment"
        ]
        assert_equal(len(rgb_vouts), 1)
        assert_equal(rgb_vouts[0]["n"], transfer["anchor_vout"])
        assert_equal(rgb_vouts[0]["scriptPubKey"]["rgb_state_hash"], transfer["transfer_anchor_commitment"])

        assets = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == contract_id]
        assert_equal(len(assets), 1)
        asset = assets[0]
        assert_equal(asset["balance"], 500)
        assert_equal(asset["proof_available"], True)
        assert_equal(asset["proof_transition_count"], 1)
        spent = [
            assignment for assignment in asset["assignments"]
            if assignment["txid"] == input_seal["txid"] and assignment["vout"] == input_seal["vout"]
        ]
        assert_equal(len(spent), 1)
        assert_equal(spent[0]["spent"], True)
        live = [
            assignment for assignment in asset["assignments"]
            if not assignment["spent"]
        ]
        assert_equal(len(live), 2)
        live_by_outpoint = {
            (assignment["txid"], assignment["vout"]): assignment["amount"]
            for assignment in live
        }
        assert_equal(live_by_outpoint[(wallet_output_seal["txid"], wallet_output_seal["vout"])], 200)
        assert_equal(live_by_outpoint[(second_wallet_output_seal["txid"], second_wallet_output_seal["vout"])], 300)

        exported = node.exportrgbconsignment(contract_id)
        assert_equal(exported["transition_count"], 1)
        assert_equal(exported["transition_ids"], [transfer["transition_id"]])
        assert_equal(exported["consignment"], transfer["consignment"])

        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        assert_equal(node.gettxout(input_seal["txid"], input_seal["vout"]), None)
        assert node.gettxout(wallet_output_seal["txid"], wallet_output_seal["vout"]) is not None
        assert node.gettxout(second_wallet_output_seal["txid"], second_wallet_output_seal["vout"]) is not None
        return contract_id, input_seal, wallet_output_seal

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Creating a live wallet-owned seal UTXO")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, node.getnewaddress(), sync_fun=self.no_op)
        input_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [{"txid": input_seal["txid"], "vout": input_seal["vout"]}])
        wallet_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [{"txid": wallet_seal["txid"], "vout": wallet_seal["vout"]}])
        external_seal = self._make_external_seal(node)

        consignment = self._consignment(input_seal, wallet_seal, external_seal)
        verification = node.verifyrgbconsignment(consignment)
        assert_equal(verification["errors"], [])
        assert_equal(verification["valid"], True)
        contract_id = verification["contract_id"]
        anchor_commitment = verification["anchor_commitment"]

        self.log.info("Importing the starting RGB assignment that the anchor will close")
        node.importrgbcontract({
            "contract_id": contract_id,
            "ticker": "RQC",
            "name": "RGB Quantum Consignment",
            "total_supply": 1000,
        })
        node.importrgbassignment({
            "contract_id": contract_id,
            "txid": input_seal["txid"],
            "vout": input_seal["vout"],
            "amount": 1000,
        })

        self.log.info("Rejecting invalid and badly anchored consignments")
        invalid = self._consignment(input_seal, wallet_seal, external_seal)
        invalid["transitions"][0]["outputs"] = [self._seal(wallet_seal, 1001)]
        assert_raises_rpc_error(
            -26,
            "RGB consignment validation failed",
            node.acceptrgbconsignment,
            invalid,
        )

        bad_anchor = node.createrawtransaction([], [{"rgb_commitment": "aa" * 32}])
        assert_raises_rpc_error(
            -26,
            "first RGB anchor does not match expected commitment",
            node.acceptrgbconsignment,
            consignment,
            bad_anchor,
        )

        missing_closure_anchor = node.createrawtransaction([], [{"rgb_commitment": anchor_commitment}])
        assert_raises_rpc_error(
            -26,
            "RGB anchor does not close input seal",
            node.acceptrgbconsignment,
            consignment,
            missing_closure_anchor,
        )

        decoded_only_anchor = self._signed_anchor_tx(node, input_seal, anchor_commitment)
        assert_raises_rpc_error(
            -4,
            "RGB anchor transaction is not live in this wallet",
            node.acceptrgbconsignment,
            consignment,
            decoded_only_anchor,
        )
        self._assert_pre_anchor_assignment_live(node, contract_id, input_seal)

        self.log.info("Accepting a valid anchored consignment into the wallet")
        good_anchor = self._anchored_tx(node, input_seal, anchor_commitment)
        anchor_decoded = node.decoderawtransaction(good_anchor)
        anchor_txid = anchor_decoded["txid"]
        anchor_vout = [
            vout["n"] for vout in anchor_decoded["vout"]
            if vout["scriptPubKey"]["type"] == "rgb_commitment"
        ][0]
        accepted = node.acceptrgbconsignment(consignment, good_anchor)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["contract_id"], contract_id)
        assert_equal(accepted["anchor_commitment"], anchor_commitment)
        assert_equal(accepted["anchor_checked"], True)
        assert_equal(accepted["imported_transitions"], 1)
        assert_equal(accepted["spent_assignments"], 0)
        assert_equal(accepted["validated_assignments"], 2)
        assert_equal(accepted["imported_assignments"], 1)
        assert_equal(accepted["skipped_assignments"], 1)
        assert_equal(accepted["balance"], 400)
        self._assert_imported_asset(node, contract_id, input_seal, wallet_seal, external_seal, anchor_txid, anchor_vout, anchor_commitment)
        self._assert_exported_consignment(node, contract_id, input_seal, wallet_seal, external_seal, anchor_commitment)
        next_wallet_seal = self._make_wallet_seal(node)
        node.lockunspent(False, [{"txid": next_wallet_seal["txid"], "vout": next_wallet_seal["vout"]}])
        scoped_external_seal = self._make_external_seal(node)

        self.log.info("Restarting and verifying accepted RGB state reloads")
        self.restart_node(0, extra_args=self.extra_args[0])
        self._assert_imported_asset(self.nodes[0], contract_id, input_seal, wallet_seal, external_seal, anchor_txid, anchor_vout, anchor_commitment)
        self._assert_exported_consignment(self.nodes[0], contract_id, input_seal, wallet_seal, external_seal, anchor_commitment)

        self.log.info("Accepting a full-history RGB consignment with only the newest transition anchored")
        first_anchor_txid, second_anchor_txid = self._assert_scoped_anchor_import(self.nodes[0], contract_id, consignment, input_seal, wallet_seal, next_wallet_seal, scoped_external_seal)
        self.restart_node(0, extra_args=self.extra_args[0])
        self._assert_extended_asset(self.nodes[0], contract_id, input_seal, wallet_seal, next_wallet_seal, first_anchor_txid, second_anchor_txid)

        self.log.info("Verifying multi-transition RGB export preserves accepted order")
        self._assert_ordered_export(self.nodes[0])

        self.log.info("Rejecting unanchored inbound consignments that spend wallet-owned RGB assignments")
        self._assert_unanchored_consignment_cannot_spend_wallet_assignment(self.nodes[0])

        self.log.info("Creating and committing a wallet-originated RGB transfer")
        transfer_contract_id, transfer_input_seal, transfer_wallet_seal = self._assert_wallet_originated_transfer(self.nodes[0])
        self.restart_node(0, extra_args=self.extra_args[0])
        transfer_assets = [
            asset for asset in self.nodes[0].listrgbassets(True)
            if asset["contract_id"] == transfer_contract_id
        ]
        assert_equal(len(transfer_assets), 1)
        assert_equal(transfer_assets[0]["balance"], 500)
        live_outputs = [
            assignment for assignment in transfer_assets[0]["assignments"]
            if assignment["txid"] == transfer_wallet_seal["txid"] and assignment["vout"] == transfer_wallet_seal["vout"]
        ]
        assert_equal(len(live_outputs), 1)
        assert_equal(live_outputs[0]["amount"], 200)
        assert_equal(live_outputs[0]["spent"], False)
        spent_inputs = [
            assignment for assignment in transfer_assets[0]["assignments"]
            if assignment["txid"] == transfer_input_seal["txid"] and assignment["vout"] == transfer_input_seal["vout"]
        ]
        assert_equal(len(spent_inputs), 1)
        assert_equal(spent_inputs[0]["spent"], True)


if __name__ == "__main__":
    WalletRGBConsignmentTest().main()
