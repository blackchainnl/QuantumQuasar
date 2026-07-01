#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Regression test for RGB single-use-seal protection.

A UTXO that carries live RGB single-use-seal state ("a seal") must NEVER be
auto-selected by ordinary coin selection or by staking: spending it as plain
coin consumes the single-use seal with no RGB transition and permanently burns
the asset. This test records an RGB asset onto a seal UTXO, *unlocks* that seal
(so the only thing that can protect it is the fix, not a manual lock), then runs
`sendall` -- which sweeps every spendable coin -- and asserts the seal survives
and the asset is intact.

Without the fix, `sendall` sweeps the seal and the asset is burned.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletRGBSealProtectionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _seal_dict(self, seal, amount=None):
        d = {"txid": seal["txid"], "vout": seal["vout"]}
        if amount is not None:
            d["amount"] = amount
        return d

    def _confirm(self, node, txid):
        for _ in range(4):
            if node.gettransaction(txid)["confirmations"] > 0:
                return
            if txid not in node.getrawmempool():
                try:
                    node.sendrawtransaction(node.gettransaction(txid)["hex"])
                except JSONRPCException as exc:
                    if exc.error["code"] != -27:
                        raise
            self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)
        assert node.gettransaction(txid)["confirmations"] > 0

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Maturing wallet funds")
        self.generatetoaddress(node, COINBASE_MATURITY + 5, node.getnewaddress(), sync_fun=self.no_op)

        self.log.info("Creating a wallet UTXO and recording an RGB asset onto it (the seal)")
        seal_address = node.getnewaddress()
        seal_txid = node.sendtoaddress(seal_address, Decimal("0.01"))
        self._confirm(node, seal_txid)
        decoded = node.gettransaction(txid=seal_txid, verbose=True)["decoded"]
        seal_vout = next(v["n"] for v in decoded["vout"]
                         if v["scriptPubKey"].get("address") == seal_address)
        seal = {"txid": seal_txid, "vout": seal_vout}

        genesis = {
            "genesis": {
                "ticker": "SEAL",
                "name": "Seal Protection Regression",
                "total_supply": 500,
                "allocations": [self._seal_dict(seal, amount=500)],
            },
            "transitions": [],
        }
        assert_equal(node.verifyrgbconsignment(genesis)["valid"], True)
        contract_id = node.verifyrgbconsignment(genesis)["contract_id"]
        accepted = node.acceptrgbconsignment(genesis)
        assert_equal(accepted["valid"], True)
        assert_equal(accepted["balance"], 500)

        self.log.info("Confirming the seal is NOT locked, so only wallet seal protection can protect it")
        # acceptrgbconsignment does not auto-lock the seal, so it is an ordinary spendable UTXO.
        # The only thing that can keep coin selection from sweeping it is the GetProtectedRGBSeals fix.
        locked = [{"txid": l["txid"], "vout": l["vout"]} for l in node.listlockunspent()]
        assert {"txid": seal["txid"], "vout": seal["vout"]} not in locked, \
            "seal unexpectedly locked; the wallet must not rely on a manual lock to protect seals"

        self.log.info("sendall must sweep every spendable coin EXCEPT the RGB seal")
        external = node.getnewaddress()
        node.sendall([external])
        self.generatetoaddress(node, 1, node.getnewaddress(), sync_fun=self.no_op)

        # 1) The seal UTXO must still be unspent on-chain (not swept / burned).
        survived = node.gettxout(seal["txid"], seal["vout"])
        assert survived is not None, "FAIL: sendall spent the RGB seal -- asset burned"

        # 2) The RGB asset must still be intact and owned.
        assets = node.listrgbassets()
        seal_asset = next(a for a in assets if a["contract_id"] == contract_id)
        assert_equal(seal_asset["balance"], 500)

        self.log.info("PASS: RGB seal survived coin selection; asset balance intact (500).")
        self.log.info("Note: staking uses the identical GetProtectedRGBSeals() guard in "
                      "AvailableCoinsForStaking, so the same exclusion protects seals from being staked.")


if __name__ == "__main__":
    WalletRGBSealProtectionTest().main()
