#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check Gold Rush shadow-ledger payouts against coinstatsindex.

Gold Rush reward credits are synthetic quantum UTXOs created by upgraded nodes
after connecting otherwise legacy-compatible PoS blocks. This test verifies that
two upgraded nodes converge on the same UTXO commitment and that a node running
coinstatsindex reports the same state as its live chainstate across apply/undo.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
QUANTUM_SPEND_FEE = Decimal("0.01")
STATS_KEYS = ["height", "bestblock", "txouts", "bogosize", "muhash", "total_amount"]
ZERO_AMOUNT = Decimal("0E-8")


class GoldRushCoinStatsIndexTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common_args = [
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=20",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]
        self.extra_args = [
            common_args,
            common_args + ["-coinstatsindex"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        )
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(300):
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
                assert claim_txid in txids[2:], "QQSPROOF claim must be a fee-paying transaction"
                self.sync_blocks()
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _wait_index_synced(self):
        index_node = self.nodes[1]

        def synced_to_tip():
            info = index_node.getindexinfo()["coinstatsindex"]
            return info["synced"] and info.get("best_block_height", index_node.getblockcount()) == index_node.getblockcount()

        self.wait_until(synced_to_tip, timeout=60)

    def _stats_fingerprint(self, stats):
        return {key: stats[key] for key in STATS_KEYS}

    def _live_stats(self, node):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=None, use_index=False))

    def _indexed_stats(self, node):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=None, use_index=True))

    def _indexed_stats_at(self, node, block_hash_or_height):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=block_hash_or_height, use_index=True))

    def _indexed_full_stats_at(self, node, block_hash_or_height):
        return node.gettxoutsetinfo(hash_type="muhash", hash_or_height=block_hash_or_height, use_index=True)

    def _amount(self, value):
        return Decimal(str(value))

    def _assert_cross_node_live_stats_match(self):
        assert_equal(self._live_stats(self.nodes[0]), self._live_stats(self.nodes[1]))

    def _assert_index_matches_live(self):
        assert_equal(self._indexed_stats(self.nodes[1]), self._live_stats(self.nodes[1]))

    def _get_quantum_utxos(self, wallet, address):
        return wallet.listunspent(0, 9999999, [address], True, {"include_immature_coinbase": True})

    def _wait_for_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address)[0]

    def _advance_to_migration_window(self):
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        for _ in range(12):
            self.generatetoaddress(self.nodes[0], 1, self.nodes[0].get_deterministic_priv_key().address)
            self._bump_mocktime(16)
        self._wait_index_synced()
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "migration")
        assert_equal(self.nodes[1].getquantumquasarinfo()["phase"], "migration")

    def _build_quantum_spend(self, wallet, utxo, destination):
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        assert spend_amount > 0
        raw = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        return self.nodes[0].signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )

    def run_test(self):
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Preparing a wallet with mature staking and QQSPROOF funding coins")
        for node in self.nodes:
            node.get_wallet_rpc(self.default_wallet_name).staking(False)
        self.nodes[0].createwallet(wallet_name="goldrush_coinstats")
        wallet = self.nodes[0].get_wallet_rpc("goldrush_coinstats")
        wallet.staking(False)
        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")

        self.generatetoaddress(self.nodes[0], 1, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, claim_address)
        self._sync_mocktime_to_tip()
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "gold_rush")
        self._wait_index_synced()
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()

        parent_hash = self.nodes[0].getbestblockhash()
        parent_height = self.nodes[0].getblockcount()
        parent_stats = self._live_stats(self.nodes[1])
        parent_indexed_full = self._indexed_full_stats_at(self.nodes[1], parent_hash)

        self.log.info("Mining a PoS block with a fee-paying QQSPROOF claim")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        assert claim["txid"] in self.nodes[0].getrawmempool()
        claim_block_hash = self._mine_pos_block_with_claim(wallet, claim["txid"])
        claim_block_height = self.nodes[0].getblockcount()
        self._wait_index_synced()

        self.log.info("Checking cross-node UTXO commitments include the synthetic quantum payout")
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert Decimal(str(payout_utxo["amount"])) > 0
        assert self.nodes[0].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        claim_stats = self._live_stats(self.nodes[1])
        claim_indexed_full = self._indexed_full_stats_at(self.nodes[1], claim_block_hash)
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()
        assert_equal(self._indexed_stats_at(self.nodes[1], parent_hash), parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], parent_height), parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], claim_block_hash), claim_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], claim_block_height), claim_stats)
        assert_equal(self._amount(claim_indexed_full["block_info"]["coinbase"]), self._amount(payout_utxo["amount"]))
        assert_equal(self._amount(claim_indexed_full["block_info"]["unspendable"]), ZERO_AMOUNT)
        assert_equal(self._amount(claim_indexed_full["block_info"]["unspendables"]["unclaimed_rewards"]), ZERO_AMOUNT)
        assert_equal(claim_indexed_full["total_unspendable_amount"], parent_indexed_full["total_unspendable_amount"])

        self.log.info("Invalidating the claim block on the index node rewinds indexed shadow payouts")
        self.nodes[1].invalidateblock(claim_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == parent_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        assert_equal(self._live_stats(self.nodes[1]), parent_stats)
        self._assert_index_matches_live()

        self.log.info("Reconsidering the claim block restores the indexed synthetic payout")
        self.nodes[1].reconsiderblock(claim_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == claim_block_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert_equal(self._live_stats(self.nodes[1]), claim_stats)
        self._assert_index_matches_live()
        self._assert_cross_node_live_stats_match()

        self.log.info("Spending the synthetic payout and checking the index tracks the spend/undo path")
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY, self.nodes[0].get_deterministic_priv_key().address)
        self._sync_mocktime_to_tip()
        matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert matured_utxo["confirmations"] > COINBASE_MATURITY

        self._advance_to_migration_window()
        migration_parent_hash = self.nodes[0].getbestblockhash()
        migration_parent_height = self.nodes[0].getblockcount()
        migration_parent_stats = self._live_stats(self.nodes[1])
        migration_parent_indexed_full = self._indexed_full_stats_at(self.nodes[1], migration_parent_hash)
        next_quantum = wallet.getnewquantumaddress()["address"]
        signed = self._build_quantum_spend(wallet, matured_utxo, next_quantum)
        assert_equal(signed["complete"], True)
        spend_txid = self.nodes[0].sendrawtransaction(signed["hex"])
        spend_block_hash = self.generatetoaddress(self.nodes[0], 1, self.nodes[0].get_deterministic_priv_key().address)[0]
        spend_block_height = self.nodes[0].getblockcount()
        self._wait_index_synced()
        assert spend_txid in self.nodes[0].getblock(spend_block_hash)["tx"]
        assert self.nodes[0].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        spend_stats = self._live_stats(self.nodes[1])
        spend_indexed_full = self._indexed_full_stats_at(self.nodes[1], spend_block_hash)
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()
        assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_hash), migration_parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_height), migration_parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_hash), spend_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_height), spend_stats)
        assert_equal(self._amount(spend_indexed_full["block_info"]["prevout_spent"]), self._amount(matured_utxo["amount"]))
        assert_equal(self._amount(spend_indexed_full["block_info"]["unspendable"]), ZERO_AMOUNT)
        assert_equal(self._amount(spend_indexed_full["block_info"]["unspendables"]["unclaimed_rewards"]), ZERO_AMOUNT)
        assert_equal(spend_indexed_full["total_unspendable_amount"], migration_parent_indexed_full["total_unspendable_amount"])

        self.log.info("Invalidating the spend block restores the synthetic payout in indexed chainstate")
        self.nodes[1].invalidateblock(spend_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == migration_parent_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is not None
        assert_equal(self._live_stats(self.nodes[1]), migration_parent_stats)
        self._assert_index_matches_live()

        self.log.info("Reconsidering the spend block removes the payout from indexed chainstate again")
        self.nodes[1].reconsiderblock(spend_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == spend_block_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert_equal(self._live_stats(self.nodes[1]), spend_stats)
        self._assert_index_matches_live()
        self._assert_cross_node_live_stats_match()

        self.log.info("Restarting and rebuilding coinstatsindex preserves synthetic payout spend state")
        final_stats = self._live_stats(self.nodes[1])
        for restart_args in (
            self.extra_args[1],
            self.extra_args[1] + ["-reindex"],
            self.extra_args[1] + ["-reindex-chainstate"],
        ):
            self.restart_node(1, extra_args=restart_args + [f"-mocktime={self.mock_time}"])
            self.nodes[1].setmocktime(self.mock_time)
            self.connect_nodes(0, 1)
            self.sync_blocks()
            self._wait_index_synced()
            assert_equal(self.nodes[1].getbestblockhash(), spend_block_hash)
            assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
            assert_equal(self._live_stats(self.nodes[1]), final_stats)
            self._assert_index_matches_live()
            assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_hash), migration_parent_stats)
            assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_hash), spend_stats)
            self._assert_cross_node_live_stats_match()


if __name__ == "__main__":
    GoldRushCoinStatsIndexTest().main()
