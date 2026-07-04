#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise autonomous Quantum Cold-Stake redelegation."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class QuantumRedelegationAutoTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-donatetodevfund=0",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=1",
            "-qqgoldrushendtime=1",
            "-qqautoredelegate=1",
            "-qqredelegationtriggermultiplier=1",
            "-qqredelegationmaxpatienceblocks=1",
            "-qqredelegationmintriggerblocks=10",
            "-qqredelegationratelimitblocks=20",
            "-qqredelegationprobationblocks=20",
            "-qqredelegationjitterblocks=0",
            "-qqredelegationlivenessimprovementblocks=1",
            "-qqredelegationtopcandidates=4",
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

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _staking_inputs(self, wallet, address):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999, [address])
        ]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "redelegation test needs a mature QCS input"
        for _ in range(20000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic QCS kernel")

    def _stake_cold_block(self, wallet, qcs_address):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet, qcs_address)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
            block_hash = node.getbestblockhash()
            block = node.getblock(block_hash, 2)
            assert "proof-of-stake" in block["flags"]
            return block_hash, block
        finally:
            wallet.staking(False)

    def _register_operator(self, funder, funder_address, owner, staker, label, cold_amount):
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

    def _submit_pool_claim(self, node, operator):
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

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating owner/staker wallets and verified pool claims")
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)
        for name in ("auto_funder", "auto_owner", "auto_staker_current", "auto_staker_target"):
            node.createwallet(wallet_name=name)
        funder = node.get_wallet_rpc("auto_funder")
        owner = node.get_wallet_rpc("auto_owner")
        staker_current = node.get_wallet_rpc("auto_staker_current")
        staker_target = node.get_wallet_rpc("auto_staker_target")
        for wallet in (funder, owner, staker_current, staker_target):
            wallet.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)

        current = self._register_operator(funder, funder_address, owner, staker_current, "auto-current", Decimal("100"))
        target = self._register_operator(funder, funder_address, owner, staker_target, "auto-target", Decimal("5000"))
        self._submit_pool_claim(node, current)
        self._submit_pool_claim(node, target)

        self.log.info("Maturing and staking the target operator once so the owner wallet records real liveness")
        self._generate(COINBASE_MATURITY, funder_address)
        self._sync_mocktime_to_tip()
        _, target_block = self._stake_cold_block(staker_target, target["address"])
        target_coinstake = target_block["tx"][1]
        assert_equal(target_coinstake["vin"][0]["txid"], target["cold_utxo"]["txid"])
        assert_equal(target_coinstake["vin"][0]["vout"], target["cold_utxo"]["vout"])
        target_outputs = [
            vout for vout in target_coinstake["vout"]
            if vout["scriptPubKey"].get("address") == target["address"]
        ]
        assert target_outputs, "target QCS coinstake must preserve delegated principal to the target script"
        target_output = max(target_outputs, key=lambda vout: Decimal(str(vout["value"])))
        target["cold_utxo"] = {
            "txid": target_coinstake["txid"],
            "vout": target_output["n"],
        }
        self._submit_pool_claim(node, target)

        self._generate(11, funder_address)
        assert_equal(len(node.getrawmempool()), 0)

        self.log.info("Triggering scheduler-driven autonomous redelegation")
        node.mockscheduler(61)
        self.wait_until(lambda: len(node.getrawmempool()) == 1, timeout=30)
        auto_txid = node.getrawmempool()[0]
        decoded = node.decoderawtransaction(node.getrawtransaction(auto_txid))
        assert_equal(len(decoded["vout"]), 1)
        target_address = decoded["vout"][0]["scriptPubKey"]["address"]
        assert_equal(node.validateaddress(target_address)["isquantumcoldstake"], True)
        assert target_address != current["address"]

        self._generate(1, funder_address)
        assert node.gettxout(current["cold_utxo"]["txid"], current["cold_utxo"]["vout"], False) is None
        self.wait_until(lambda: owner.gettransaction(auto_txid)["confirmations"] >= 1, timeout=30)
        self.wait_until(lambda: len(owner.listunspent(0, 9999999, [target_address])) == 1, timeout=30)

        self.log.info("Confirming autonomous probation/rate dampers prevent an immediate second redelegation")
        assert_equal(len(node.getrawmempool()), 0)
        node.mockscheduler(61)
        assert_equal(len(node.getrawmempool()), 0)
        self._generate(1, funder_address)
        node.mockscheduler(61)
        assert_equal(len(node.getrawmempool()), 0)


if __name__ == "__main__":
    QuantumRedelegationAutoTest().main()
