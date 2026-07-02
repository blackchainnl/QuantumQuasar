#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise non-consensus Quantum Cold-Stake pool-cap accounting."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class QuantumPoolCapTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-donatetodevfund=0",
            "-qqgoldrushendtime=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _generate(self, count, address):
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(self.nodes[0], 1, address, sync_fun=self.no_op))
            self._bump_mocktime(16)
        return hashes

    def _one_utxo(self, wallet, address, txid):
        self.wait_until(lambda: len(wallet.listunspent(0, 9999999, [address])) == 1, timeout=30)
        utxo = wallet.listunspent(0, 9999999, [address])[0]
        assert_equal(utxo["txid"], txid)
        return utxo

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating wallets and mature funding")
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)
        for name in ("pool_funder", "pool_owner_a", "pool_owner_b", "pool_staker_a", "pool_staker_b", "pool_staker_c"):
            node.createwallet(wallet_name=name)
        funder = node.get_wallet_rpc("pool_funder")
        owner_a = node.get_wallet_rpc("pool_owner_a")
        owner_b = node.get_wallet_rpc("pool_owner_b")
        staker_a = node.get_wallet_rpc("pool_staker_a")
        staker_b = node.get_wallet_rpc("pool_staker_b")
        staker_c = node.get_wallet_rpc("pool_staker_c")
        for wallet in (funder, owner_a, owner_b, staker_a, staker_b, staker_c):
            wallet.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)

        self.log.info("Funding two live QCS outputs for an exact cold-stake denominator")
        staker_a_key = staker_a.dumpquantumkey(staker_a.getnewquantumaddress()["address"])
        staker_b_key = staker_b.dumpquantumkey(staker_b.getnewquantumaddress()["address"])
        staker_c_key = staker_c.dumpquantumkey(staker_c.getnewquantumaddress()["address"])

        delegation_a = owner_a.getnewquantumcoldstakingaddress(staker_a_key["public_key"], "pool-a")
        owner_a_key = owner_a.dumpquantumkey(delegation_a["owner_quantum_address"])
        delegation_b = owner_b.getnewquantumcoldstakingaddress(staker_b_key["public_key"], "pool-b")
        owner_b_key = owner_b.dumpquantumkey(delegation_b["owner_quantum_address"])

        txid_a = funder.sendtoaddress(delegation_a["address"], Decimal("100"))
        txid_b = funder.sendtoaddress(delegation_b["address"], Decimal("400"))
        self._generate(1, funder_address)
        utxo_a = self._one_utxo(owner_a, delegation_a["address"], txid_a)
        self._one_utxo(owner_b, delegation_b["address"], txid_b)

        self.log.info("Rejecting a forged discovery claim and accepting the genuine claim")
        forged = node.submitquantumpoolclaim(staker_a_key["public_key"], [{
            "txid": utxo_a["txid"],
            "vout": utxo_a["vout"],
            "owner_pubkey": owner_b_key["public_key"],
        }])
        assert_equal(forged["accepted"], False)
        assert_equal(forged["operator"]["verified_claims"], 0)
        assert_equal(forged["operator"]["invalid_claims"], 1)

        genuine = node.submitquantumpoolclaim(staker_a_key["public_key"], [{
            "txid": utxo_a["txid"],
            "vout": utxo_a["vout"],
            "owner_pubkey": owner_a_key["public_key"],
        }])
        assert_equal(genuine["accepted"], True)
        assert_equal(genuine["total_coldstake"], Decimal("500.00000000"))
        assert_equal(genuine["operator"]["verified_value"], Decimal("100.00000000"))
        assert_equal(genuine["operator"]["share_bps"], 2000)

        info = node.getquantumpoolinfo(staker_a_key["public_key"], Decimal("1"))
        assert_equal(info["total_coldstake"], Decimal("500.00000000"))
        assert_equal(info["operator_count"], 1)
        assert_equal(info["operators"][0]["verified_value"], Decimal("100.00000000"))
        assert_equal(info["operators"][0]["would_exceed_cap"], True)

        self.log.info("Wallet allows over-cap inflow when no under-cap registered alternative exists")
        over = owner_a.getnewquantumcoldstakingaddress(
            staker_a_key["public_key"],
            "pool-a-over",
            {"delegation_amount": Decimal("1")},
        )
        assert_equal(over["pool_cap_preflight"]["would_exceed_cap"], True)
        assert_equal(over["pool_cap_preflight"]["enforced"], True)
        assert_equal(over["pool_cap_preflight"]["cap_filter_unlocked"], True)

        under = owner_a.getnewquantumcoldstakingaddress(
            staker_c_key["public_key"],
            "pool-c-under",
            {"delegation_amount": Decimal("1")},
        )
        assert_equal(under["pool_cap_preflight"]["would_exceed_cap"], False)
        assert_equal(under["pool_cap_preflight"]["cap_filter_unlocked"], False)
        assert_equal(under["pool_cap_preflight"]["total_coldstake"], Decimal("500.00000000"))
        assert_equal(under["pool_cap_preflight"]["operator_value"], Decimal("0.00000000"))

        self.log.info("Accepting a bonded operator with no delegators yet for bootstrap discovery")
        operator_only = staker_c.getnewquantumstakeaddress("pool-c-operator", 40500)
        operator_txid = funder.sendtoaddress(operator_only["address"], Decimal("1"))
        self._generate(1, funder_address)
        operator_utxo = self._one_utxo(staker_c, operator_only["address"], operator_txid)

        bootstrap = node.submitquantumpoolclaim(
            operator_only["public_key"],
            [],
            {
                "txid": operator_utxo["txid"],
                "vout": operator_utxo["vout"],
            },
        )
        assert_equal(bootstrap["accepted"], True)
        assert_equal(bootstrap["operator"]["verified_value"], Decimal("0E-8"))
        assert_equal(bootstrap["operator"]["verified_claims"], 0)
        assert_equal(bootstrap["operator"]["operator_commitment_verified"], True)

        bootstrap_info = node.getquantumpoolinfo(operator_only["public_key"])
        assert_equal(bootstrap_info["operator_count"], 1)
        assert_equal(bootstrap_info["operators"][0]["operator_commitment_verified"], True)


if __name__ == "__main__":
    QuantumPoolCapTest().main()
