#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Quantum Cold-Stake redelegation dry-run policy."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class QuantumRedelegationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=1",
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

    def _register_operator(self, node, funder, funder_address, owner, staker, label, cold_amount):
        stake_info = staker.getnewquantumstakeaddress(f"{label}-operator", 40500)
        delegation = owner.getnewquantumcoldstakingaddress(stake_info["public_key"], f"{label}-delegation")
        owner_key = owner.dumpquantumkey(delegation["owner_quantum_address"])
        imported = staker.importquantumcoldstakingdelegation(owner_key["public_key"], stake_info["public_key"], f"{label}-delegation")
        assert_equal(imported["has_owner_key"], False)
        assert_equal(imported["has_staker_key"], True)

        cold_txid = funder.sendtoaddress(delegation["address"], cold_amount)
        operator_txid = funder.sendtoaddress(stake_info["address"], Decimal("1"))
        self._generate(1, funder_address)
        cold_utxo = self._one_utxo(owner, delegation["address"], cold_txid)
        operator_utxo = self._one_utxo(staker, stake_info["address"], operator_txid)

        return {
            "address": delegation["address"],
            "staking_pubkey": stake_info["public_key"],
            "owner_pubkey": owner_key["public_key"],
            "cold_utxo": cold_utxo,
            "operator_utxo": operator_utxo,
        }

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating wallets and funding operators")
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)
        for name in ("redeleg_funder", "redeleg_owner_a", "redeleg_owner_b", "redeleg_owner_c", "redeleg_staker_a", "redeleg_staker_b", "redeleg_staker_c"):
            node.createwallet(wallet_name=name)
        funder = node.get_wallet_rpc("redeleg_funder")
        owner_a = node.get_wallet_rpc("redeleg_owner_a")
        owner_b = node.get_wallet_rpc("redeleg_owner_b")
        owner_c = node.get_wallet_rpc("redeleg_owner_c")
        staker_a = node.get_wallet_rpc("redeleg_staker_a")
        staker_b = node.get_wallet_rpc("redeleg_staker_b")
        staker_c = node.get_wallet_rpc("redeleg_staker_c")
        for wallet in (funder, owner_a, owner_b, owner_c, staker_a, staker_b, staker_c):
            wallet.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)

        current = self._register_operator(node, funder, funder_address, owner_a, staker_a, "current", Decimal("100"))
        small = self._register_operator(node, funder, funder_address, owner_b, staker_b, "small", Decimal("50"))
        oversized = self._register_operator(node, funder, funder_address, owner_c, staker_c, "oversized", Decimal("300"))

        self.log.info("Registering pool claims with operator proofs")
        for operator in (current, small, oversized):
            result = node.submitquantumpoolclaim(
                operator["staking_pubkey"],
                [{
                    "txid": operator["cold_utxo"]["txid"],
                    "vout": operator["cold_utxo"]["vout"],
                    "owner_pubkey": operator["owner_pubkey"],
                }],
                {
                    "txid": operator["operator_utxo"]["txid"],
                    "vout": operator["operator_utxo"]["vout"],
                },
            )
            assert_equal(result["accepted"], True)
            assert_equal(result["operator"]["operator_commitment_verified"], True)

        self.log.info("Dry-running redelegation recommendation")
        info = owner_a.getquantumredelegationinfo(
            current["staking_pubkey"],
            Decimal("1"),
            600,
            100,
            {"stampede_jitter_blocks": 0},
        )
        assert_equal(info["should_redelegate"], True)
        assert_equal(info["trigger_blocks"], 600)
        assert_equal(info["rate_limited"], False)
        assert_equal(info["probation"], False)
        assert_equal(len(info["candidates"]), 1)
        assert_equal(info["candidates"][0]["staking_pubkey"], small["staking_pubkey"])
        assert_equal(info["candidates"][0]["verified_value"], Decimal("50.00000000"))
        assert_equal(info["candidates"][0]["would_exceed_cap"], False)

        rate_limited = owner_a.getquantumredelegationinfo(
            current["staking_pubkey"],
            Decimal("1"),
            600,
            100,
            {
                "last_redelegation_height": node.getblockcount(),
                "stampede_jitter_blocks": 0,
            },
        )
        assert_equal(rate_limited["should_redelegate"], False)
        assert_equal(rate_limited["rate_limited"], True)

        self.log.info("Rejecting unverified targets without mutating QCS wallet metadata")
        before_addresses = {entry["address"] for entry in owner_a.listquantumcoldstakingdelegations()}
        unverified_key = staker_c.dumpquantumkey(staker_c.getnewquantumaddress()["address"])
        assert_raises_rpc_error(
            -4,
            "Target Quantum cold-stake operator commitment is not verified in the local registry",
            owner_a.redelegatequantumcoldstake,
            current["address"],
            unverified_key["public_key"],
            {"dry_run": True, "enforce_pool_cap": False},
        )
        after_addresses = {entry["address"] for entry in owner_a.listquantumcoldstakingdelegations()}
        assert_equal(after_addresses, before_addresses)

        self.log.info("Allowing over-cap redelegation when no under-cap alternative exists")
        bootstrap_plan = owner_a.redelegatequantumcoldstake(
            current["address"],
            small["staking_pubkey"],
            {"dry_run": True},
        )
        assert_equal(bootstrap_plan["pool_policy"]["would_exceed_cap"], True)
        assert_equal(bootstrap_plan["pool_policy"]["cap_enforced"], True)
        assert_equal(bootstrap_plan["pool_policy"]["cap_filter_unlocked"], True)

        self.log.info("Dry-running the explicit owner-spend redelegation transaction")
        before_dry_addresses = {entry["address"] for entry in owner_a.listquantumcoldstakingdelegations()}
        dry_plan = owner_a.redelegatequantumcoldstake(
            current["address"],
            small["staking_pubkey"],
            {
                "dry_run": True,
                "enforce_pool_cap": False,
                "label": "dry-run-redelegated",
            },
        )
        assert_equal(dry_plan["dry_run"], True)
        assert_equal(dry_plan["source_address"], current["address"])
        assert_equal(node.validateaddress(dry_plan["target_address"])["isquantumcoldstake"], True)
        assert_equal(dry_plan["target_wallet_backed"], False)
        after_dry_addresses = {entry["address"] for entry in owner_a.listquantumcoldstakingdelegations()}
        assert_equal(after_dry_addresses, before_dry_addresses)
        assert_equal(dry_plan["input_amount"], Decimal("100.00000000"))
        assert dry_plan["output_amount"] < dry_plan["input_amount"]
        assert dry_plan["fee"] > Decimal("0")
        assert dry_plan["fee"] < Decimal("0.10000000")
        assert_equal(dry_plan["pool_policy"]["operator_commitment_verified"], True)
        assert_equal(dry_plan["pool_policy"]["would_exceed_cap"], True)
        assert_equal(dry_plan["pool_policy"]["cap_enforced"], False)
        assert "txid" not in dry_plan

        higher_fee_plan = owner_a.redelegatequantumcoldstake(
            current["address"],
            small["staking_pubkey"],
            {
                "dry_run": True,
                "enforce_pool_cap": False,
                "fee_rate": Decimal("150"),
                "label": "dry-run-high-fee-redelegated",
            },
        )
        assert higher_fee_plan["fee"] > dry_plan["fee"]

        self.log.info("Rejecting redelegation from a wallet that lacks the owner key")
        assert_raises_rpc_error(
            -4,
            "Wallet does not have the owner key for source_coldstake_address",
            staker_a.redelegatequantumcoldstake,
            current["address"],
            small["staking_pubkey"],
            {"dry_run": True, "enforce_pool_cap": False},
        )

        self.log.info("Broadcasting and mining the explicit owner-spend redelegation")
        sent = owner_a.redelegatequantumcoldstake(
            current["address"],
            small["staking_pubkey"],
            {
                "dry_run": False,
                "enforce_pool_cap": False,
                "label": "executed-redelegated",
            },
        )
        assert_equal(sent["dry_run"], False)
        assert "txid" in sent
        assert_equal(sent["source_address"], current["address"])
        assert_equal(node.validateaddress(sent["target_address"])["isquantumcoldstake"], True)
        assert_equal(sent["target_wallet_backed"], True)
        assert sent["output_amount"] < sent["input_amount"]
        assert sent["fee"] > Decimal("0")
        assert sent["fee"] < Decimal("0.10000000")
        self._generate(1, funder_address)

        assert node.gettxout(current["cold_utxo"]["txid"], current["cold_utxo"]["vout"], False) is None
        self.wait_until(lambda: owner_a.gettransaction(sent["txid"])["confirmations"] >= 1, timeout=30)
        self.wait_until(lambda: len(owner_a.listunspent(0, 9999999, [sent["target_address"]])) == 1, timeout=30)
        target_utxo = owner_a.listunspent(0, 9999999, [sent["target_address"]])[0]
        assert_equal(target_utxo["txid"], sent["txid"])
        assert_equal(target_utxo["amount"], sent["output_amount"])


if __name__ == "__main__":
    QuantumRedelegationTest().main()
