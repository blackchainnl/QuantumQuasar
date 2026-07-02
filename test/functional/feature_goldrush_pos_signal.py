#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Gold Rush PoS QQSIGNAL payouts through a live node.

This covers the wallet/consensus value path that unit tests model directly:
a whitelisted legacy staking address solves a PoS block, broadcasts one
fee-paying QQSIGNAL linked to a quantum payout address, then receives
synthetic quantum UTXOs from later PoS blocks without per-block signaling.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
QUANTUM_SPEND_FEE = Decimal("0.01")
WALLET_NAME = "goldrush_pos_signal"
QQSIGNAL_HEX = "51515349474e414c"
QQSPROOF_HEX = "51515350524f4f46"


class GoldRushPosSignalTest(BitcoinTestFramework):
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
        for _ in range(300):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block(self, wallet, expected_txid=None):
        node = self.nodes[0]
        last_error = None
        for _ in range(3):
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
                if expected_txid is not None:
                    txids = [tx["txid"] for tx in block["tx"]]
                    assert expected_txid in txids[2:], "QQSIGNAL must be included as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error

    def _get_quantum_utxos(self, wallet, address, *, include_immature=True, min_conf=0):
        options = {"include_immature_coinbase": include_immature}
        return wallet.listunspent(min_conf, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address, min_conf=min_conf)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address, min_conf=min_conf)[0]

    def _wait_for_specific_quantum_utxo(self, wallet, address, txid, vout, *, min_conf=0):
        self.wait_until(
            lambda: any(u["txid"] == txid and u["vout"] == vout for u in self._get_quantum_utxos(wallet, address, min_conf=min_conf)),
            timeout=30,
        )
        return next(u for u in self._get_quantum_utxos(wallet, address, min_conf=min_conf) if u["txid"] == txid and u["vout"] == vout)

    def _assert_no_quantum_utxo(self, wallet, address):
        assert_equal(self._get_quantum_utxos(wallet, address), [])

    def _lock_non_whitelist_script_utxos(self, wallet, whitelist_script):
        locked = [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
            if utxo["scriptPubKey"] != whitelist_script
        ]
        if locked:
            wallet.lockunspent(False, locked)
        return locked

    def _assert_no_onchain_block_output_to(self, block_hash, address):
        block = self.nodes[0].getblock(block_hash, 2)
        for tx in block["tx"]:
            for vout in tx["vout"]:
                assert vout["scriptPubKey"].get("address") != address

    def _advance_to_migration_window(self):
        node = self.nodes[0]
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        generated = 0
        while node.getquantumquasarinfo()["phase"] != "migration":
            self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            generated += 1
            assert generated < COINBASE_MATURITY, "migration phase should activate before the synthetic payout matures"
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")

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

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating a whitelisted wallet address with mature staking coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)
        signal_address = wallet.getnewaddress("", "legacy")
        whitelist_script = wallet.getaddressinfo(signal_address)["scriptPubKey"]

        self.generatetoaddress(node, 1, signal_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 8, signal_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Solving a PoS block with the whitelisted address to create a solver marker")
        solve_block_hash = self._mine_pos_block(wallet)
        solve_height = node.getblock(solve_block_hash)["height"]
        goldrush_after_solve = wallet.getgoldrushinfo()
        if not goldrush_after_solve["wallet_recent_solve_qualified"]:
            raise AssertionError(f"wallet does not see recent solver marker: {goldrush_after_solve}")

        self.log.info("Funding a non-whitelisted PoW claim address after the whitelist snapshot")
        pow_claim_address = wallet.getnewaddress("", "legacy")
        self.generatetoaddress(node, COINBASE_MATURITY + 2, pow_claim_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()

        self.log.info("Pre-creating wallet-backed PoS and PoW Gold Rush quantum payout addresses")
        payout_address = wallet.getnewquantumaddress("goldrush-pos")["address"]
        pow_payout_address = wallet.getnewquantumaddress("goldrush-pow")["address"]

        self.log.info("Broadcasting a fee-paying QQSPROOF claim before the next PoS block")
        pow_claim = wallet.sendshadowpowclaim(pow_claim_address, pow_payout_address, 500000)
        assert pow_claim["txid"] in node.getrawmempool()

        self.log.info("Mining a later PoS block that includes both auto QQSIGNAL and pending QQSPROOF")
        locked_non_whitelist_for_combo = self._lock_non_whitelist_script_utxos(wallet, whitelist_script)
        try:
            payout_block_hash = self._mine_pos_block(wallet)
        finally:
            if locked_non_whitelist_for_combo:
                wallet.lockunspent(True, locked_non_whitelist_for_combo)
        payout_block = node.getblock(payout_block_hash, 2)
        payout_height = payout_block["height"]
        signal_txids = [
            tx["txid"]
            for tx in payout_block["tx"][2:]
            if any(QQSIGNAL_HEX in vout["scriptPubKey"]["hex"] for vout in tx["vout"])
        ]
        assert_equal(len(signal_txids), 1)
        assert pow_claim["txid"] in [tx["txid"] for tx in payout_block["tx"][2:]]
        assert any(
            QQSPROOF_HEX in vout["scriptPubKey"]["hex"]
            for tx in payout_block["tx"][2:]
            for vout in tx["vout"]
        ), "combined payout block must include the fee-paying QQSPROOF"
        signal_txid = signal_txids[0]
        wallet_signals = [
            tx for tx in wallet.listtransactions("*", 100, 0, True)
            if tx.get("txid") == signal_txid and tx.get("comment") == "Blackcoin shadow signal"
        ]
        assert_equal(len(wallet_signals), 1)
        self._assert_no_onchain_block_output_to(payout_block_hash, payout_address)
        self._assert_no_onchain_block_output_to(payout_block_hash, pow_payout_address)

        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        pow_payout_utxo = self._wait_for_quantum_utxo(wallet, pow_payout_address)
        assert_equal(payout_utxo["confirmations"], 1)
        assert_equal(pow_payout_utxo["confirmations"], 1)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert node.gettxout(pow_payout_utxo["txid"], pow_payout_utxo["vout"], False) is not None
        assert Decimal(str(payout_utxo["amount"])) > 0
        assert Decimal(str(pow_payout_utxo["amount"])) > 0
        combined_info = wallet.getgoldrushinfo()
        assert_equal(combined_info["last_pos_height"], payout_height)
        assert_equal(combined_info["last_pow_height"], payout_height)
        assert combined_info["pos_count"] >= 1
        assert combined_info["pow_count"] >= 1

        self.log.info("Disconnecting and reconnecting the combined payout block removes and restores both synthetic coins")
        node.invalidateblock(payout_block_hash)
        self._assert_no_quantum_utxo(wallet, payout_address)
        self._assert_no_quantum_utxo(wallet, pow_payout_address)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        assert node.gettxout(pow_payout_utxo["txid"], pow_payout_utxo["vout"], False) is None
        node.reconsiderblock(payout_block_hash)
        self.wait_until(lambda: node.getbestblockhash() == payout_block_hash)
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        pow_payout_utxo = self._wait_for_quantum_utxo(wallet, pow_payout_address)
        assert_equal(payout_utxo["confirmations"], 1)
        assert_equal(pow_payout_utxo["confirmations"], 1)

        self.log.info("Mining a follow-up PoS block with no QQSIGNAL still pays the active 14-day look-back signaler")
        locked_non_whitelist = self._lock_non_whitelist_script_utxos(wallet, whitelist_script)
        try:
            lookback_block_hash = self._mine_pos_block(wallet)
        finally:
            if locked_non_whitelist:
                wallet.lockunspent(True, locked_non_whitelist)
        lookback_block = node.getblock(lookback_block_hash, 2)
        assert not any(
            QQSIGNAL_HEX in vout["scriptPubKey"]["hex"]
            for tx in lookback_block["tx"][2:]
            for vout in tx["vout"]
        ), "look-back payout block should not need a per-block QQSIGNAL transaction"
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, payout_address)) == 2, timeout=30)
        lookback_utxos = self._get_quantum_utxos(wallet, payout_address)
        lookback_utxo = next(u for u in lookback_utxos if u["txid"] != payout_utxo["txid"] or u["vout"] != payout_utxo["vout"])
        assert Decimal(str(lookback_utxo["amount"])) > 0

        self.log.info("Rejecting QQSIGNAL payout spends before the migration window")
        next_quantum = wallet.getnewquantumaddress()["address"]
        premature_raw, _ = self._build_quantum_spend(wallet, payout_utxo, next_quantum)
        premature_accept = node.testmempoolaccept([premature_raw])[0]
        assert_equal(premature_accept["allowed"], False)
        assert premature_accept["reject-reason"] in (
            "goldrush-remigration-premature",
            "bad-txns-premature-spend-of-coinbase",
        ), premature_accept

        self.log.info("Advancing to migration and rejecting the still-immature QQSIGNAL payout")
        self._advance_to_migration_window()
        _, immature_signed = self._build_quantum_spend(wallet, payout_utxo, next_quantum)
        assert_equal(immature_signed["complete"], True)
        immature_accept = node.testmempoolaccept([immature_signed["hex"]])[0]
        assert_equal(immature_accept["allowed"], False)
        assert_equal(immature_accept["reject-reason"], "bad-txns-premature-spend-of-coinbase")

        self.log.info("Maturing and spending the QQSIGNAL payout to a fresh quantum address")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        matured_utxo = self._wait_for_specific_quantum_utxo(
            wallet,
            payout_address,
            payout_utxo["txid"],
            payout_utxo["vout"],
            min_conf=COINBASE_MATURITY + 1,
        )
        raw, signed = self._build_quantum_spend(wallet, matured_utxo, next_quantum)
        assert_equal(signed["complete"], True)
        accepted = node.testmempoolaccept([signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"migration quantum spend rejected: {accepted}")
        spend_txid = node.sendrawtransaction(signed["hex"])
        spend_block_hash = self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        spend_block = node.getblock(spend_block_hash)
        assert spend_txid in spend_block["tx"]
        assert node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        migrated_utxo = self._wait_for_quantum_utxo(wallet, next_quantum)

        self.log.info("Disconnecting and reconnecting the spend block restores and consumes the QQSIGNAL payout")
        node.invalidateblock(spend_block_hash)
        restored = node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False)
        assert restored is not None
        assert_equal(Decimal(str(restored["value"])), Decimal(str(matured_utxo["amount"])))
        node.reconsiderblock(spend_block_hash)
        self.wait_until(lambda: node.getbestblockhash() == spend_block_hash)
        assert node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        migrated_utxo = self._wait_for_quantum_utxo(wallet, next_quantum)

        self.log.info("Reorging below the QQSIGNAL payout block removes both payout generations")
        node.invalidateblock(payout_block_hash)
        self._assert_no_quantum_utxo(wallet, payout_address)
        self._assert_no_quantum_utxo(wallet, pow_payout_address)
        self._assert_no_quantum_utxo(wallet, next_quantum)
        assert node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert node.gettxout(pow_payout_utxo["txid"], pow_payout_utxo["vout"], False) is None
        assert node.gettxout(migrated_utxo["txid"], migrated_utxo["vout"], False) is None


if __name__ == "__main__":
    GoldRushPosSignalTest().main()
