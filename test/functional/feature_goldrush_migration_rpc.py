#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the migrategoldrushrewards wallet RPC end to end."""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 400
QUANTUM_SPEND_FEE = Decimal("0.01")
WALLET_NAME = "goldrush_migration_rpc"


class GoldRushMigrationRpcTest(BitcoinTestFramework):
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
        last_error = None
        for _ in range(4):
            start_height = node.getblockcount()
            kernel_time = self._find_next_kernel_time(wallet)
            self._set_mocktime(kernel_time - 16)
            wallet.staking(True)
            try:
                self._set_mocktime(kernel_time)
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:], "QQSPROOF claim must be included as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

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

    def _assert_one_reward_needs_move(self, wallet, amount):
        status = wallet.getmigrationstatus()
        assert_equal(status["phase"], "gold_rush")
        assert_equal(status["goldrush_remigration_active"], True)
        assert_equal(status["goldrush_reward_outputs_needing_move"], 1)
        assert_equal(Decimal(status["goldrush_reward_amount_needing_move"]), amount)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating a wallet with mature staking and QQSPROOF funding coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)

        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")
        self.generatetoaddress(node, 1, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, claim_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("migratetoquantum dry-runs require an existing wallet-backed destination and do not create keys")
        assert_raises_rpc_error(
            -8,
            "dry_run requires existing_address",
            wallet.migratetoquantum,
            {"dry_run": True},
        )
        legacy_dry_destination = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        wallet.encryptwallet("test-passphrase")
        legacy_dry_run = wallet.migratetoquantum({"dry_run": True, "existing_address": legacy_dry_destination})
        assert_equal(legacy_dry_run["destination"], legacy_dry_destination)
        assert_equal(legacy_dry_run["newly_generated"], False)
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        wallet.walletpassphrase("test-passphrase", 600)

        self.log.info("Mining a Gold Rush payout to a wallet-backed quantum address")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        self._mine_pos_block_with_claim(wallet, claim["txid"])
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)

        self.log.info("Maturing the synthetic payout before attempting migration")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address, min_conf=COINBASE_MATURITY + 1)
        payout_amount = Decimal(str(payout_utxo["amount"]))
        self._assert_one_reward_needs_move(wallet, payout_amount)

        self.log.info("Cold-stake funding honors explicit opt-out from Gold Rush migration side effects")
        staker_key = wallet.dumpquantumkey(wallet.getnewquantumaddress()["address"])
        coldstake_address = wallet.getnewquantumcoldstakingaddress(staker_key["public_key"], "rpc-coldstake")["address"]
        mempool_before = set(node.getrawmempool())
        assert_raises_rpc_error(
            -4,
            "allow_goldrush_migration=true",
            wallet.fundquantumcoldstakeaddress,
            coldstake_address,
            Decimal("1"),
            {"allow_goldrush_migration": False},
        )
        assert_equal(set(node.getrawmempool()), mempool_before)
        self._assert_one_reward_needs_move(wallet, payout_amount)

        self.log.info("migrategoldrushrewards can dry-run during Gold Rush once quantum reward spends are active")
        assert_raises_rpc_error(
            -8,
            "dry_run requires existing_address",
            wallet.migrategoldrushrewards,
            {"dry_run": True},
        )
        goldrush_destination = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        wallet.walletlock()
        goldrush_dry_run = wallet.migrategoldrushrewards({"dry_run": True, "existing_address": goldrush_destination})
        assert_equal(goldrush_dry_run["phase"], "gold_rush")
        assert_equal(goldrush_dry_run["eligible_inputs"], 1)
        assert_equal(Decimal(goldrush_dry_run["eligible_amount"]), payout_amount)
        assert_equal(goldrush_dry_run["destination"], goldrush_destination)
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 1)
        wallet.walletpassphrase("test-passphrase", 600)

        self.log.info("Advancing to the migration window")
        mining_address = wallet.getnewquantumaddress()["address"]
        self._mine_until_phase("migration", GOLD_RUSH_END_TIME + 16, mining_address)
        status = wallet.getmigrationstatus()
        assert_equal(status["phase"], "migration")
        assert_equal(status["goldrush_remigration_active"], True)
        assert_equal(status["goldrush_reward_outputs_needing_move"], 1)

        self.log.info("The RPC refuses to remigrate a payout back to the same quantum address")
        assert_raises_rpc_error(
            -6,
            "No wallet-owned Gold Rush reward outputs need migration",
            wallet.migrategoldrushrewards,
            {"existing_address": payout_address},
        )

        self.log.info("Dry run reports fees and leaves the reward output unmoved")
        migration_address = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        dry_run = wallet.migrategoldrushrewards({"dry_run": True, "existing_address": migration_address})
        assert_equal(dry_run["phase"], "migration")
        assert_equal(dry_run["eligible_inputs"], 1)
        assert_equal(Decimal(dry_run["eligible_amount"]), payout_amount)
        assert_equal(dry_run["destination"], migration_address)
        assert_equal(dry_run["newly_generated"], False)
        assert_equal(dry_run["stored_in_wallet"], True)
        assert "txid" not in dry_run
        assert Decimal(dry_run["fee"]) > 0
        assert Decimal(dry_run["amount"]) == payout_amount - Decimal(dry_run["fee"])
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 1)

        self.log.info("Migrating the reward creates a wallet transaction and clears the need-to-move count")
        migration = wallet.migrategoldrushrewards({"existing_address": migration_address})
        assert_equal(migration["phase"], "migration")
        assert_equal(migration["eligible_inputs"], 1)
        assert_equal(migration["destination"], migration_address)
        assert_equal(migration["newly_generated"], False)
        assert migration["txid"] in node.getrawmempool()
        migration_block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        assert migration["txid"] in node.getblock(migration_block)["tx"]
        node.syncwithvalidationinterfacequeue()
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 0)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None

        migrated_utxo = self._wait_for_quantum_utxo(wallet, migration_address, min_conf=1)
        assert_equal(Decimal(str(migrated_utxo["amount"])), Decimal(migration["amount"]))

        self.log.info("Reloading and rescanning preserves migrated reward state and quantum key usability")
        wallet.unloadwallet()
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.walletpassphrase("test-passphrase", 600)
        wallet.rescanblockchain(0)
        node.syncwithvalidationinterfacequeue()
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 0)
        migrated_utxo = self._wait_for_quantum_utxo(wallet, migration_address, min_conf=1)
        assert_equal(Decimal(str(migrated_utxo["amount"])), Decimal(migration["amount"]))

        self.log.info("The migrated quantum output signs and spends as a normal migration-window quantum coin")
        final_destination = wallet.getnewquantumaddress()["address"]
        _, spend_signed = self._build_quantum_spend(wallet, migrated_utxo, final_destination)
        assert_equal(spend_signed["complete"], True)
        accepted = node.testmempoolaccept([spend_signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"migrated quantum spend rejected: {accepted}")
        spend_txid = node.sendrawtransaction(spend_signed["hex"])
        spend_block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        assert spend_txid in node.getblock(spend_block)["tx"]
        assert node.gettxout(migrated_utxo["txid"], migrated_utxo["vout"], False) is None


if __name__ == "__main__":
    GoldRushMigrationRpcTest().main()
