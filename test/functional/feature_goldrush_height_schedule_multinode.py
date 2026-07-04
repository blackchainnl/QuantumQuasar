#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Drive a 5-node private testnet through a height-scheduled Quantum Quasar lifecycle.

The test schedule branch exposes height-based boundary overrides so a live
testnet can be steered by block heights instead of wall-clock times:

  -shadowgoldrushstartheight  Gold Rush reward window start height
  -shadowgoldrushendheight    Gold Rush reward window end height (inclusive)
  -qqgoldrushendheight        Gold Rush -> Migration phase boundary height
  -qqmigrationendheight       Migration -> Final Lockout phase boundary height

Scenario (mirrors the planned mainnet rollout, compressed):
1. A single node bootstraps the chain with PoW, then reaches the Gold Rush
   start height.
2. During Gold Rush the node produces PoS blocks, plain PoW blocks, and a
   QQSPROOF shadow-PoW claim that pays out to a quantum address.
3. Before the Gold Rush end height, four more nodes join, sync the chain, and
   a second node also produces a PoS block that the network accepts.
4. The network crosses the Gold Rush end height at the exact configured
   height, moves through Migration (a Gold Rush payout is re-migrated), and
   crosses the migration end height into Final Lockout where legacy spends
   are refused. All five nodes agree on every boundary.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

WHITELIST_HEIGHT = 1
GOLD_RUSH_START_HEIGHT = 30
GOLD_RUSH_END_HEIGHT = 90
MIGRATION_END_HEIGHT = 140
QUANTUM_SPEND_FEE = Decimal("0.01")


class GoldRushHeightScheduleMultiNodeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.chain = "testnet3"
        self.num_nodes = 5
        self.setup_clean_chain = True
        # Testnet PoW is scrypt at a 16-bit floor: individual blocks can take
        # tens of seconds, so keep RPCs comfortably inside the socket timeout.
        self.rpc_timeout = 600
        common = [
            "-txindex=1",
            "-staketimio=50",
            "-solostaking=1",
            f"-shadowwhitelistheight={WHITELIST_HEIGHT}",
            f"-shadowgoldrushstartheight={GOLD_RUSH_START_HEIGHT}",
            f"-shadowgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
            "-minimumchainwork=0x00",
            "-assumevalid=0",
        ]
        self.extra_args = [list(common) for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Start only the bootstrap node; the other four join mid-Gold-Rush.
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        self.started = [0]

    # --- mocktime helpers -------------------------------------------------
    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for i in self.started:
            self.nodes[i].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime(max(self.mock_time, (tip_time & ~0xF) + 16))

    # --- staking helpers --------------------------------------------------
    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
            if utxo.get("spendable", True)
            and utxo.get("confirmations", 0) > COINBASE_MATURITY
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "staker wallet must have mature staking inputs"
        for _ in range(2000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block(self, node, wallet, expect_txid=None):
        last_error = None
        for _ in range(6):
            start_height = node.getblockcount()
            kernel_time = self._find_next_kernel_time(wallet)
            self._set_mocktime(kernel_time - 16)
            wallet.staking(True)
            try:
                self._set_mocktime(kernel_time)
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=30)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"], "expected a PoS block"
                if expect_txid is not None:
                    txids = [tx["txid"] for tx in block["tx"]]
                    assert expect_txid in txids[2:], "QQSPROOF claim must be included as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _mine_pos_to_height(self, node, wallet, target_height):
        while node.getblockcount() < target_height:
            self._mine_pos_block(node, wallet)
            self._sync_started()

    def _sync_started(self):
        nodes = [self.nodes[i] for i in self.started]
        if len(nodes) > 1:
            self.sync_all(nodes)

    def _assert_network_agrees(self):
        tips = {self.nodes[i].getbestblockhash() for i in self.started}
        assert_equal(len(tips), 1)

    def _assert_phase_everywhere(self, phase):
        for i in self.started:
            info = self.nodes[i].getquantumquasarinfo()
            assert_equal((i, info["phase"]), (i, phase))

    # --- test body ----------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.started = [0]
        self._set_mocktime((int(time.time()) & ~0xF) + 16)

        self.log.info("Verifying the height schedule is reported by getquantumquasarinfo")
        info = node.getquantumquasarinfo()
        assert_equal(info["shadow_reward_start_height"], GOLD_RUSH_START_HEIGHT)
        assert_equal(info["shadow_reward_end_height"], GOLD_RUSH_END_HEIGHT)
        assert_equal(info["gold_rush_end_height"], GOLD_RUSH_END_HEIGHT)
        assert_equal(info["quantum_migration_end_height"], MIGRATION_END_HEIGHT)
        assert_equal(info["phase"], "gold_rush")

        self.log.info("Bootstrapping funds with PoW blocks (scrypt, testnet floor difficulty)")
        # setup_network is overridden (no default wallet); create the test wallets directly.
        node.createwallet(wallet_name="gr_staker_a")
        node.createwallet(wallet_name="gr_claims")
        staker_a = node.get_wallet_rpc("gr_staker_a")
        claims = node.get_wallet_rpc("gr_claims")
        staker_a.staking(False)
        claims.staking(False)

        staking_address = staker_a.getnewaddress("", "legacy")
        claim_fee_address = claims.getnewaddress("", "legacy")
        legacy_lockout_address = claims.getnewaddress("", "legacy")

        # PoW funding: 2 fee/lockout coinbases + enough staking coinbases that
        # the staker always has mature inputs. Mine in bounded-maxtries chunks
        # so no single RPC outlives the HTTP socket timeout mid-grind.
        def mine_pow_block(address):
            start_height = node.getblockcount()
            for _ in range(400):
                if node.generatetoaddress(nblocks=1, address=address, maxtries=25000, invalid_call=False):
                    break
                # A fresh header time opens a new nonce search space; with
                # frozen mocktime every retry would regrind the same header.
                self._bump_mocktime(16)
            assert_equal(node.getblockcount(), start_height + 1)
            self._bump_mocktime()

        mine_pow_block(claim_fee_address)
        mine_pow_block(legacy_lockout_address)
        for _ in range(COINBASE_MATURITY + 4):
            mine_pow_block(staking_address)
        self._sync_mocktime_to_tip()
        assert node.getblockcount() >= COINBASE_MATURITY + 6

        self.log.info("Reaching the Gold Rush reward start height %d with PoS blocks", GOLD_RUSH_START_HEIGHT)
        self._mine_pos_to_height(node, staker_a, GOLD_RUSH_START_HEIGHT)
        info = node.getquantumquasarinfo()
        assert_equal(info["phase"], "gold_rush")
        assert_equal(info["shadow_reward_height_active"], True)

        self.log.info("Gold Rush: plain PoW blocks are still accepted")
        mine_pow_block(claim_fee_address)
        pow_hash = node.getbestblockhash()
        assert "proof-of-work" in node.getblock(pow_hash)["flags"]
        self._sync_mocktime_to_tip()

        self.log.info("Gold Rush: mining a QQSPROOF shadow-PoW claim into a PoS block")
        payout_address_a = claims.getnewquantumaddress()["address"]
        claim_a = claims.sendshadowpowclaim(claim_fee_address, payout_address_a, 500000)
        self._mine_pos_block(node, staker_a, expect_txid=claim_a["txid"])
        payout_utxos = lambda w, addr: w.listunspent(0, 9999999, [addr], True, {"include_immature_coinbase": True})
        self.wait_until(lambda: len(payout_utxos(claims, payout_address_a)) == 1, timeout=30)
        self.log.info("Shadow PoW payout recorded at %s", payout_address_a)

        self.log.info("Scaling out to 5 nodes before the Gold Rush end height")
        assert node.getblockcount() < GOLD_RUSH_END_HEIGHT - 20
        for i in range(1, 5):
            self.start_node(i)
            self.started.append(i)
            self.nodes[i].setmocktime(self.mock_time)
            self.connect_nodes(0, i)
        # Mesh the joiners a bit so relay does not depend on node0 alone.
        self.connect_nodes(1, 2)
        self.connect_nodes(3, 4)
        self._sync_started()
        self._assert_network_agrees()
        self._assert_phase_everywhere("gold_rush")
        self.log.info("All 5 nodes synced the Gold Rush chain")

        self.log.info("Funding node 1 so a second staker secures the network")
        staker_b_wallet_name = "gr_staker_b"
        self.nodes[1].createwallet(wallet_name=staker_b_wallet_name)
        staker_b = self.nodes[1].get_wallet_rpc(staker_b_wallet_name)
        staker_b.staking(False)
        staker_b_address = staker_b.getnewaddress("", "legacy")
        # Much of staker_a's balance is tied up in immature coinstakes; size the
        # grants from what is actually spendable right now.
        grant = int(staker_a.getbalance()) // 6
        assert grant > 0, "staker_a must have spendable funds for node 1"
        for _ in range(3):
            staker_a.sendtoaddress(staker_b_address, grant)
        self._mine_pos_block(node, staker_a)
        self._sync_started()

        # Mature node 1's coins (> COINBASE_MATURITY confirmations for kernels).
        for _ in range(COINBASE_MATURITY + 1):
            self._mine_pos_block(node, staker_a)
            self._sync_started()

        self.log.info("Node 1 produces a PoS block accepted by all 5 nodes")
        start_height = self.nodes[1].getblockcount()
        self._mine_pos_block(self.nodes[1], staker_b)
        self._sync_started()
        self._assert_network_agrees()
        assert self.nodes[0].getblockcount() > start_height

        self.log.info("Gold Rush: a second QQSPROOF claim with 5 nodes online")
        payout_address_b = claims.getnewquantumaddress()["address"]
        claim_b = claims.sendshadowpowclaim(claim_fee_address, payout_address_b, 500000)
        self._sync_started()
        self._mine_pos_block(node, staker_a, expect_txid=claim_b["txid"])
        self._sync_started()
        self._assert_network_agrees()

        self.log.info("Crossing the Gold Rush end height %d into Migration", GOLD_RUSH_END_HEIGHT)
        self._mine_pos_to_height(node, staker_a, GOLD_RUSH_END_HEIGHT)
        self._assert_phase_everywhere("gold_rush")  # block AT the boundary is still Gold Rush
        self._mine_pos_block(node, staker_a)
        self._sync_started()
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT + 1)
        self._assert_phase_everywhere("migration")
        for i in self.started:
            info = self.nodes[i].getquantumquasarinfo()
            assert_equal(info["quantum_spend_enforcement_active"], True)
            assert_equal(info["shadow_reward_height_active"], False)
        self.log.info("All 5 nodes flipped to Migration at exactly height %d", GOLD_RUSH_END_HEIGHT + 1)

        self.log.info("Migration: moving a Gold Rush payout to a fresh quantum address")
        self.wait_until(lambda: len(payout_utxos(claims, payout_address_a)) == 1, timeout=30)
        payout_utxo = payout_utxos(claims, payout_address_a)[0]
        migration_destination = claims.getnewquantumaddress()["address"]
        spend_amount = Decimal(str(payout_utxo["amount"])) - QUANTUM_SPEND_FEE
        raw = node.createrawtransaction(
            [{"txid": payout_utxo["txid"], "vout": payout_utxo["vout"]}],
            [{migration_destination: spend_amount}],
        )
        key = claims.dumpquantumkey(payout_utxo["address"])
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        assert_equal(signed["complete"], True)
        accept = node.testmempoolaccept([signed["hex"]])[0]
        assert accept["allowed"], f"Gold Rush reward move rejected: {accept}"
        move_txid = node.sendrawtransaction(signed["hex"])
        self._sync_started()
        move_block = self._mine_pos_block(node, staker_a)
        assert move_txid in node.getblock(move_block)["tx"]
        self._sync_started()
        self._assert_network_agrees()

        self.log.info("Crossing the migration end height %d into Final Lockout", MIGRATION_END_HEIGHT)
        self._mine_pos_to_height(node, staker_a, MIGRATION_END_HEIGHT)
        self._assert_phase_everywhere("migration")  # block AT the boundary is still Migration
        self._mine_pos_block(node, staker_a)
        self._sync_started()
        assert_equal(node.getblockcount(), MIGRATION_END_HEIGHT + 1)
        self._assert_phase_everywhere("final_lockout")
        self.log.info("All 5 nodes flipped to Final Lockout at exactly height %d", MIGRATION_END_HEIGHT + 1)

        self.log.info("Final Lockout: legacy spends are refused on every node")
        lockout_utxo = claims.listunspent(1, 9999999, [legacy_lockout_address])[0]
        legacy_raw = node.createrawtransaction(
            [{"txid": lockout_utxo["txid"], "vout": lockout_utxo["vout"]}],
            [{claims.getnewquantumaddress()["address"]: Decimal(str(lockout_utxo["amount"])) - QUANTUM_SPEND_FEE}],
        )
        for i in self.started:
            result = self.nodes[i].testmempoolaccept([legacy_raw])[0]
            assert_equal((i, result["allowed"]), (i, False))
            assert_equal((i, result["reject-reason"]), (i, "legacy-spend-disabled"))

        self._assert_network_agrees()
        self.log.info("Height-scheduled lifecycle complete: 5 nodes in consensus end to end")


if __name__ == "__main__":
    GoldRushHeightScheduleMultiNodeTest().main()
