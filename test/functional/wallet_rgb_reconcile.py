#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Regression test for RGB ledger reorg/abandon desynchronization.

An owned RGB seal's `spent` flag must mirror whether the seal outpoint is spent
by an active (non-abandoned, non-conflicted) wallet transaction. Before the fix
nothing reconciled this, so:
  - a seal spent out-of-band left the asset shown as still-owned, and
  - a reorged-out / abandoned transfer left the input stuck "spent",
both permanent and unrecoverable. CWallet::ReconcileRGBAssignments() now runs on
every block connect/disconnect and on abandon, so the RGB ledger self-heals from
the wallet's authoritative IsSpent() view.

Part A verifies the spend direction (-> spent=true); Part B verifies the
abandon/un-spend direction (-> spent=false), which is the core desync harm.
Part C verifies the same reconciliation runs after an explicit rescan.
"""

from decimal import Decimal
import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletRGBReconcileTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _make_seal(self, node):
        node.setmocktime(int(time.time()) + node.getblockcount() + 1)
        addr = node.getnewaddress()
        txid = node.sendtoaddress(addr, Decimal("0.05"))
        if txid not in node.getrawmempool():
            try:
                node.sendrawtransaction(node.gettransaction(txid)["hex"])
            except JSONRPCException as exc:
                if exc.error["code"] != -27:
                    raise
        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        assert node.gettransaction(txid)["confirmations"] > 0
        dec = node.gettransaction(txid=txid, verbose=True)["decoded"]
        vout = next(v["n"] for v in dec["vout"] if v["scriptPubKey"].get("address") == addr)
        return {"txid": txid, "vout": vout}

    def _fake_seal(self, tag):
        return {"txid": f"{tag:064x}", "vout": 0}

    def _import_asset(self, node, seal, ticker):
        consignment = {
            "genesis": {
                "ticker": ticker,
                "name": ticker + " asset",
                "total_supply": 500,
                "allocations": [{"txid": seal["txid"], "vout": seal["vout"], "amount": 500}],
            },
            "transitions": [],
        }
        cid = node.verifyrgbconsignment(consignment)["contract_id"]
        assert_equal(node.acceptrgbconsignment(consignment)["balance"], 500)
        return cid

    def _contract_id_for_seal(self, node, seal, ticker):
        consignment = {
            "genesis": {
                "ticker": ticker,
                "name": ticker + " asset",
                "total_supply": 500,
                "allocations": [{"txid": seal["txid"], "vout": seal["vout"], "amount": 500}],
            },
            "transitions": [],
        }
        return node.verifyrgbconsignment(consignment)["contract_id"]

    def _asset(self, node, cid):
        matches = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == cid]
        assert_equal(len(matches), 1)
        return matches[0]

    def _assignment_spent(self, node, cid, seal):
        for asset in node.listrgbassets(True):
            if asset["contract_id"] != cid:
                continue
            for asn in asset["assignments"]:
                if asn["txid"] == seal["txid"] and asn["vout"] == seal["vout"]:
                    return asn["spent"]
        raise AssertionError("RGB assignment not found for seal")

    def run_test(self):
        node = self.nodes[0]
        self.generatetoaddress(node, COINBASE_MATURITY + 5, node.getnewaddress(), sync_fun=self.no_op)

        # ---- Part A: a seal spent out-of-band reconciles to spent=true on the next block ----
        self.log.info("Part A: external spend of a seal -> RGB flag reconciles to spent=true")
        seal_a = self._make_seal(node)
        cid_a = self._import_asset(node, seal_a, "RCA")
        assert_equal(self._assignment_spent(node, cid_a, seal_a), False)

        # Spend seal_a deliberately via an explicit input, bypassing automatic seal protection.
        raw = node.createrawtransaction(
            [{"txid": seal_a["txid"], "vout": seal_a["vout"]}],
            [{node.getnewaddress(): Decimal("0.049")}],
        )
        signed = node.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        node.sendrawtransaction(signed["hex"])
        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)  # blockConnected -> reconcile
        spend_height_a = node.getblockcount()
        assert_equal(self._assignment_spent(node, cid_a, seal_a), True)  # was stuck False without the fix

        # ---- Part B: an abandoned transfer reconciles the input back to spent=false ----
        self.log.info("Part B: abandoned transfer -> input RGB flag reconciles back to spent=false")
        seal_b = self._make_seal(node)
        cid_b = self._import_asset(node, seal_b, "RCB")  # import first so seal_b becomes protected
        dest_b = self._make_seal(node)                   # creating this must not consume the protected seal_b
        transfer = node.creatergbtransfer(
            cid_b,
            [{"txid": seal_b["txid"], "vout": seal_b["vout"]}],
            [{"txid": dest_b["txid"], "vout": dest_b["vout"], "amount": 500}],
            {"fee_rate": 100},
        )
        anchor_txid = transfer["anchor_txid"]
        assert_equal(self._assignment_spent(node, cid_b, seal_b), True)  # transfer marked the input spent

        # Take the unconfirmed anchor out of the mempool (and stop the wallet rebroadcasting it)
        # so it can be abandoned -- the realistic "transfer never confirmed" desync.
        self.restart_node(0, extra_args=self.extra_args[0] + ["-persistmempool=0", "-walletbroadcast=0"])
        node = self.nodes[0]
        assert anchor_txid not in node.getrawmempool()
        node.abandontransaction(anchor_txid)  # AbandonTransaction -> ReconcileRGBAssignments -> un-spend
        assert_equal(self._assignment_spent(node, cid_b, seal_b), False)  # was stuck True without the fix
        asset_b = [asset for asset in node.listrgbassets(True) if asset["contract_id"] == cid_b][0]
        assert_equal(asset_b["balance"], 500)
        assert_equal(asset_b["proof_transition_count"], 0)
        stale_outputs = [
            assignment for assignment in asset_b["assignments"]
            if assignment["txid"] == dest_b["txid"] and assignment["vout"] == dest_b["vout"]
        ]
        assert_equal(stale_outputs, [])

        # ---- Part C: an explicit rescan reconciles stale RGB metadata imported after a spend ----
        self.log.info("Part C: rescan -> stale imported RGB flag reconciles to spent=true")
        cid_c = self._contract_id_for_seal(node, seal_a, "RCC")
        node.importrgbcontract({
            "contract_id": cid_c,
            "ticker": "RCC",
            "name": "RCC asset",
            "total_supply": 500,
        })
        node.importrgbassignment({
            "contract_id": cid_c,
            "txid": seal_a["txid"],
            "vout": seal_a["vout"],
            "amount": 500,
        })
        assert_equal(self._assignment_spent(node, cid_c, seal_a), False)
        node.rescanblockchain(spend_height_a, spend_height_a)
        assert_equal(self._assignment_spent(node, cid_c, seal_a), True)

        # ---- Part D: a checked transition with an unprovable external anchor is pruned ----
        self.log.info("Part D: unprovable checked RGB anchor -> transition and output assignment are pruned")
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        external_input = self._fake_seal(0xD0)
        wallet_output = self._make_seal(node)
        consignment_d = {
            "genesis": {
                "ticker": "RCD",
                "name": "RCD asset",
                "total_supply": 500,
                "allocations": [{"txid": external_input["txid"], "vout": external_input["vout"], "amount": 500}],
            },
            "transitions": [{
                "inputs": [{"txid": external_input["txid"], "vout": external_input["vout"]}],
                "outputs": [{"txid": wallet_output["txid"], "vout": wallet_output["vout"], "amount": 500}],
            }],
        }
        verified_d = node.verifyrgbconsignment(consignment_d)
        cid_d = verified_d["contract_id"]
        decoded_only_anchor = node.createrawtransaction(
            [{"txid": external_input["txid"], "vout": external_input["vout"]}],
            [{"rgb_commitment": verified_d["anchor_commitment"]}],
        )
        accepted_d = node.acceptrgbconsignment(consignment_d, decoded_only_anchor)
        assert_equal(accepted_d["valid"], True)
        assert_equal(accepted_d["imported_transitions"], 1)
        assert_equal(accepted_d["imported_assignments"], 1)
        assert_equal(self._asset(node, cid_d)["balance"], 500)

        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        asset_d = self._asset(node, cid_d)
        assert_equal(asset_d["balance"], 0)
        assert_equal(asset_d["proof_transition_count"], 0)
        assert_equal(asset_d["transitions"], [])
        assert_equal(asset_d["assignments"], [])

        self.log.info("PASS: RGB ledger self-heals on out-of-band spend (A), abandon (B), rescan (C), and unprovable anchors (D).")


if __name__ == "__main__":
    WalletRGBReconcileTest().main()
