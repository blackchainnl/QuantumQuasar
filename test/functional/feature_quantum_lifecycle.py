#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Drive one node through the Blackcoin 24-month lifecycle.

This test exercises the live MTP phase boundaries instead of booting separate
phase-pinned nodes. It proves Gold Rush payouts must move to a fresh quantum
address before use, can move once quantum reward spends are active, and expire
after final lockout if left unmigrated. It also proves legacy inputs are
disabled after the deadline.
"""

from decimal import Decimal
import hashlib
import struct
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 400
QUANTUM_SPEND_FEE = Decimal("0.01")
LEGACY_SPEND_FEE = Decimal("0.01")
GOLD_RUSH_PAYOUT_MARKER_DOMAIN = b"Quantum Quasar Direct Gold Rush Payout"


class QuantumLifecycleTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
            if utxo.get("spendable", True)
            and utxo.get("confirmations", 0) > COINBASE_MATURITY
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(1000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block_with_claim(self, wallet, claim_txid):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=15)
            block_hash = node.getbestblockhash()
            block = node.getblock(block_hash, 2)
            assert "proof-of-stake" in block["flags"]
            txids = [tx["txid"] for tx in block["tx"]]
            assert claim_txid in txids[2:], "QQSPROOF claim must be a fee-paying transaction"
            return block_hash
        finally:
            wallet.staking(False)

    def _mine_until_phase(self, phase, target_time, address):
        node = self.nodes[0]
        self._set_mocktime(target_time)
        for _ in range(20):
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            if node.getquantumquasarinfo()["phase"] == phase:
                return
        raise AssertionError(f"timed out waiting for phase {phase}")

    def _get_quantum_utxos(self, wallet, address, *, min_conf=0):
        options = {"include_immature_coinbase": True}
        return wallet.listunspent(min_conf, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address, min_conf=min_conf)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address, min_conf=min_conf)[0]

    def _build_quantum_spend(self, wallet, utxo, destination):
        node = self.nodes[0]
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        assert spend_amount > 0
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        return raw, signed

    def _build_legacy_spend(self, wallet, utxo, destination):
        node = self.nodes[0]
        spend_amount = Decimal(str(utxo["amount"])) - LEGACY_SPEND_FEE
        assert spend_amount > 0
        return node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )

    def _compact_size(self, size):
        if size < 253:
            return bytes([size])
        if size <= 0xffff:
            return b"\xfd" + struct.pack("<H", size)
        if size <= 0xffffffff:
            return b"\xfe" + struct.pack("<I", size)
        return b"\xff" + struct.pack("<Q", size)

    def _goldrush_marker_outpoint(self, payout_utxo):
        serialized = (
            self._compact_size(len(GOLD_RUSH_PAYOUT_MARKER_DOMAIN))
            + GOLD_RUSH_PAYOUT_MARKER_DOMAIN
            + bytes.fromhex(payout_utxo["txid"])[::-1]
            + struct.pack("<I", payout_utxo["vout"])
        )
        digest = hashlib.sha256(hashlib.sha256(serialized).digest()).digest()
        return digest[::-1].hex(), 0

    def _assert_goldrush_marker_exists(self, payout_utxo):
        marker_txid, marker_vout = self._goldrush_marker_outpoint(payout_utxo)
        marker = self.nodes[0].gettxout(marker_txid, marker_vout, False)
        if marker is None:
            raise AssertionError(f"missing Gold Rush companion marker for {payout_utxo['txid']}:{payout_utxo['vout']}")
        assert_equal(marker["value"], 0)

    def _assert_phase_status(self, wallet, phase, *, quantum_spends_active, remigration_active, deadline_passed):
        node = self.nodes[0]
        info = node.getquantumquasarinfo()
        status = wallet.getmigrationstatus()
        assert_equal(info["phase"], phase)
        assert_equal(status["phase"], phase)
        assert_equal(status["quantum_spends_active"], quantum_spends_active)
        assert_equal(status["goldrush_remigration_active"], remigration_active)
        assert_equal(status["deadline_passed"], deadline_passed)

    def _assert_generateblock_rejects(self, rawtx, output_address, reject_reason):
        assert_raises_rpc_error(
            -25,
            f"TestBlockValidity failed: {reject_reason}",
            self.generateblock,
            self.nodes[0],
            output=output_address,
            transactions=[rawtx],
        )

    def _reconsider_tip(self, block_hash):
        node = self.nodes[0]
        node.reconsiderblock(block_hash)
        self.wait_until(lambda: node.getbestblockhash() == block_hash, timeout=30)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating mature legacy staking, claim, and lockout-test coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name="quantum_lifecycle")
        node.createwallet(wallet_name="quantum_lifecycle_staker_b")
        wallet = node.get_wallet_rpc("quantum_lifecycle")
        staker_b = node.get_wallet_rpc("quantum_lifecycle_staker_b")
        wallet.staking(False)
        staker_b.staking(False)

        staking_address = wallet.getnewaddress("", "legacy")
        staking_address_b = staker_b.getnewaddress("", "legacy")
        claim_address_a = wallet.getnewaddress("", "legacy")
        claim_address_b = wallet.getnewaddress("", "legacy")
        legacy_lockout_address = wallet.getnewaddress("", "legacy")

        self.generatetoaddress(node, 1, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, staking_address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, claim_address_a, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, claim_address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, legacy_lockout_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address_b, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        self._assert_phase_status(wallet, "gold_rush", quantum_spends_active=True, remigration_active=True, deadline_passed=False)

        legacy_lockout_utxo = wallet.listunspent(1, 9999999, [legacy_lockout_address])[0]
        claim_b_funding_utxo = wallet.listunspent(1, 9999999, [claim_address_b])[0]
        wallet.lockunspent(False, [{"txid": legacy_lockout_utxo["txid"], "vout": legacy_lockout_utxo["vout"]}])
        wallet.lockunspent(False, [{"txid": claim_b_funding_utxo["txid"], "vout": claim_b_funding_utxo["vout"]}])

        self.log.info("Mining two independent QQSPROOF payouts before Gold Rush ends")
        payout_address_a = wallet.getnewquantumaddress()["address"]
        claim_a = wallet.sendshadowpowclaim(claim_address_a, payout_address_a, 500000)
        self._mine_pos_block_with_claim(wallet, claim_a["txid"])
        payout_utxo_a = self._wait_for_quantum_utxo(wallet, payout_address_a)
        self._assert_goldrush_marker_exists(payout_utxo_a)

        payout_address_b = wallet.getnewquantumaddress()["address"]
        wallet.lockunspent(True, [{"txid": claim_b_funding_utxo["txid"], "vout": claim_b_funding_utxo["vout"]}])
        claim_b = wallet.sendshadowpowclaim(claim_address_b, payout_address_b, 500000)
        self._mine_pos_block_with_claim(staker_b, claim_b["txid"])
        payout_utxo_b = self._wait_for_quantum_utxo(wallet, payout_address_b)
        self._assert_goldrush_marker_exists(payout_utxo_b)

        self.log.info("Maturing both synthetic payouts while Gold Rush is still active")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo_a = self._wait_for_quantum_utxo(wallet, payout_address_a, min_conf=COINBASE_MATURITY + 1)
        payout_utxo_b = self._wait_for_quantum_utxo(wallet, payout_address_b, min_conf=COINBASE_MATURITY + 1)
        self._assert_phase_status(wallet, "gold_rush", quantum_spends_active=True, remigration_active=True, deadline_passed=False)
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 2)

        self.log.info("Gold Rush payout spends can move to a fresh quantum address during Gold Rush")
        migration_destination_a = wallet.getnewquantumaddress()["address"]
        _, same_goldrush_signed = self._build_quantum_spend(wallet, payout_utxo_a, payout_address_a)
        assert_equal(same_goldrush_signed["complete"], True)
        same_goldrush_accept = node.testmempoolaccept([same_goldrush_signed["hex"]])[0]
        assert_equal(same_goldrush_accept["allowed"], False)
        assert_equal(same_goldrush_accept["reject-reason"], "goldrush-remigration-same-address")
        self._assert_generateblock_rejects(same_goldrush_signed["hex"], node.get_deterministic_priv_key().address, "goldrush-remigration-same-address")

        valid_raw, valid_signed = self._build_quantum_spend(wallet, payout_utxo_a, migration_destination_a)
        assert_equal(valid_signed["complete"], True)
        valid_accept = node.testmempoolaccept([valid_signed["hex"]])[0]
        if not valid_accept["allowed"]:
            raise AssertionError(f"Gold Rush reward move rejected: {valid_accept}")
        spend_txid = node.sendrawtransaction(valid_signed["hex"])
        spend_block_hash = self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        assert spend_txid in node.getblock(spend_block_hash)["tx"]
        assert node.gettxout(payout_utxo_a["txid"], payout_utxo_a["vout"], False) is None
        assert node.gettxout(payout_utxo_b["txid"], payout_utxo_b["vout"], False) is not None
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 1)

        self.log.info("Crossing the Gold Rush end boundary into the migration window")
        migration_mining_address = wallet.getnewquantumaddress()["address"]
        self._mine_until_phase("migration", GOLD_RUSH_END_TIME + 16, migration_mining_address)
        migration_tip = node.getbestblockhash()
        self._assert_phase_status(wallet, "migration", quantum_spends_active=True, remigration_active=True, deadline_passed=False)

        self.log.info("Gold Rush payouts must move to a different quantum address during migration")
        _, same_signed = self._build_quantum_spend(wallet, payout_utxo_b, payout_address_b)
        assert_equal(same_signed["complete"], True)
        same_accept = node.testmempoolaccept([same_signed["hex"]])[0]
        assert_equal(same_accept["allowed"], False)
        assert_equal(same_accept["reject-reason"], "goldrush-remigration-same-address")
        self._assert_generateblock_rejects(same_signed["hex"], migration_mining_address, "goldrush-remigration-same-address")

        self.log.info("Crossing the migration deadline into final lockout")
        final_mining_address = wallet.getnewquantumaddress()["address"]
        self._mine_until_phase("final_lockout", MIGRATION_DEADLINE_TIME + 16, final_mining_address)
        final_tip = node.getbestblockhash()
        self._assert_phase_status(wallet, "final_lockout", quantum_spends_active=True, remigration_active=False, deadline_passed=True)

        self.log.info("Reorging below migration deadline restores remigration spend rules")
        node.invalidateblock(final_tip)
        self._assert_phase_status(wallet, "migration", quantum_spends_active=True, remigration_active=True, deadline_passed=False)
        reorg_migration_destination = wallet.getnewquantumaddress()["address"]
        _, reorg_migration_signed = self._build_quantum_spend(wallet, payout_utxo_b, reorg_migration_destination)
        assert_equal(reorg_migration_signed["complete"], True)
        reorg_migration_accept = node.testmempoolaccept([reorg_migration_signed["hex"]])[0]
        if not reorg_migration_accept["allowed"]:
            raise AssertionError(f"remigration spend rejected after deadline reorg: {reorg_migration_accept}")
        self._reconsider_tip(final_tip)
        self._assert_phase_status(wallet, "final_lockout", quantum_spends_active=True, remigration_active=False, deadline_passed=True)

        self.log.info("Legacy inputs are rejected after final lockout")
        legacy_destination = wallet.getnewquantumaddress()["address"]
        legacy_hex = self._build_legacy_spend(wallet, legacy_lockout_utxo, legacy_destination)
        legacy_accept = node.testmempoolaccept([legacy_hex])[0]
        assert_equal(legacy_accept["allowed"], False)
        assert_equal(legacy_accept["reject-reason"], "legacy-spend-disabled")
        self._assert_generateblock_rejects(legacy_hex, final_mining_address, "legacy-spend-disabled")

        self.log.info("Unmoved Gold Rush payouts expire after final lockout")
        expired_destination = wallet.getnewquantumaddress()["address"]
        expired_raw, _ = self._build_quantum_spend(wallet, payout_utxo_b, expired_destination)
        expired_accept = node.testmempoolaccept([expired_raw])[0]
        assert_equal(expired_accept["allowed"], False)
        assert_equal(expired_accept["reject-reason"], "goldrush-remigration-expired")
        self._assert_generateblock_rejects(expired_raw, final_mining_address, "goldrush-remigration-expired")


if __name__ == "__main__":
    QuantumLifecycleTest().main()
