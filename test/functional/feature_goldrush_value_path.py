#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the Gold Rush shadow-ledger value path through a live node.

The unit tests cover the low-level marker/companion-coin helpers. This test
drives the node-level path: a fee-paying QQSPROOF transaction is included by a
real wallet staker in a PoS block, which materializes an out-of-band synthetic
quantum payout coin in the upgraded UTXO set.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
QUANTUM_SPEND_FEE = Decimal("0.01")
WALLET_NAME = "goldrush_value"


class GoldRushValuePathTest(BitcoinTestFramework):
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
                assert claim_txid in txids[2:], "QQSPROOF claim must be a fee-paying non-coinbase/non-coinstake transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _get_quantum_utxos(self, wallet, address, *, include_immature=True):
        options = {"include_immature_coinbase": include_immature}
        return wallet.listunspent(0, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address)[0]

    def _assert_no_quantum_utxo(self, wallet, address):
        assert_equal(self._get_quantum_utxos(wallet, address), [])

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
        claim_entries = [entry for entry in wallet.getgoldrushinfo()["wallet_scripts"] if entry["address"] == claim_address]
        assert claim_entries, "PoW claim target must be visible in wallet Gold Rush status"
        assert_equal(claim_entries[0]["whitelisted"], False)

        self.log.info("A QQSPROOF mined by a proof-of-work block remains legacy-visible but earns no shadow credit")
        pow_block_payout = wallet.getnewquantumaddress()["address"]
        pow_block_state_before = node.getgoldrushstate()
        pow_block_claim = wallet.sendshadowpowclaim(claim_address, pow_block_payout, 500000)
        assert pow_block_claim["txid"] in node.getrawmempool()
        pow_block_hash = self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        pow_block = node.getblock(pow_block_hash, 2)
        assert "proof-of-work" in pow_block["flags"]
        assert pow_block_claim["txid"] in [tx["txid"] for tx in pow_block["tx"]]
        self._assert_no_onchain_block_output_to(pow_block_hash, pow_block_payout)
        self._assert_no_quantum_utxo(wallet, pow_block_payout)
        pow_block_state_after = node.getgoldrushstate()
        assert_equal(pow_block_state_after["claimed_amount"], pow_block_state_before["claimed_amount"])
        assert_equal(pow_block_state_after["pow_count"], pow_block_state_before["pow_count"])
        assert_equal(pow_block_state_after["last_pow_height"], pow_block_state_before["last_pow_height"])
        assert pow_block_state_after["pow_amount"] > pow_block_state_before["pow_amount"]

        self.log.info("Disconnecting and reconnecting the proof-of-work block preserves no-credit accounting")
        node.invalidateblock(pow_block_hash)
        self._assert_no_quantum_utxo(wallet, pow_block_payout)
        assert_equal(node.getgoldrushstate()["claimed_amount"], pow_block_state_before["claimed_amount"])
        node.reconsiderblock(pow_block_hash)
        self.wait_until(lambda: node.getbestblockhash() == pow_block_hash)
        self._assert_no_quantum_utxo(wallet, pow_block_payout)
        pow_block_state_reconnected = node.getgoldrushstate()
        assert_equal(pow_block_state_reconnected["claimed_amount"], pow_block_state_after["claimed_amount"])
        assert_equal(pow_block_state_reconnected["pow_count"], pow_block_state_after["pow_count"])
        assert_equal(pow_block_state_reconnected["pow_amount"], pow_block_state_after["pow_amount"])
        self._sync_mocktime_to_tip()

        self.log.info("Broadcasting a fee-paying QQSPROOF claim to a wallet-backed quantum address")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        assert claim["txid"] in node.getrawmempool()

        self.log.info("Minting a real PoS block that includes the QQSPROOF claim")
        claim_block_hash = self._mine_pos_block_with_claim(wallet, claim["txid"])
        claim_block = node.getblock(claim_block_hash, 2)
        assert claim["txid"] in [tx["txid"] for tx in claim_block["tx"]]
        self._assert_no_onchain_block_output_to(claim_block_hash, payout_address)

        self.log.info("Verifying the synthetic quantum payout coin is wallet-visible and in chainstate")
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert_equal(payout_utxo["confirmations"], 1)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        goldrush_info = wallet.getgoldrushinfo()
        claimed_amount = Decimal(goldrush_info["claimed_amount"]) / Decimal(100000000)
        assert claimed_amount >= Decimal(str(payout_utxo["amount"]))

        self.log.info("Disconnecting and reconnecting the claim block removes and restores the companion coin")
        node.invalidateblock(claim_block_hash)
        self._assert_no_quantum_utxo(wallet, payout_address)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        node.reconsiderblock(claim_block_hash)
        self.wait_until(lambda: node.getbestblockhash() == claim_block_hash)
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)

        self.log.info("Immature Gold Rush payout spends are rejected during Gold Rush")
        next_quantum = wallet.getnewquantumaddress()["address"]
        _, premature_signed = self._build_quantum_spend(wallet, payout_utxo, next_quantum)
        assert_equal(premature_signed["complete"], True)
        premature_accept = node.testmempoolaccept([premature_signed["hex"]])[0]
        assert_equal(premature_accept["allowed"], False)
        assert_equal(premature_accept["reject-reason"], "bad-txns-premature-spend-of-coinbase")

        self.log.info("Maturing the synthetic coin during Gold Rush")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert matured_utxo["confirmations"] > COINBASE_MATURITY

        self.log.info("Reloading, rescanning, and restarting preserves the synthetic payout")
        wallet.unloadwallet()
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.rescanblockchain(0)
        node.syncwithvalidationinterfacequeue()
        matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert matured_utxo["confirmations"] > COINBASE_MATURITY

        self.restart_node(0, extra_args=self.extra_args[0] + [f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        if WALLET_NAME not in node.listwallets():
            node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        node.syncwithvalidationinterfacequeue()
        matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert matured_utxo["confirmations"] > COINBASE_MATURITY

        self.log.info("Spending the matured payout to a new quantum address")
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

        self.log.info("Disconnecting the spend block restores the matured synthetic payout coin")
        node.invalidateblock(spend_block_hash)
        restored = node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False)
        assert restored is not None
        assert_equal(Decimal(str(restored["value"])), Decimal(str(matured_utxo["amount"])))

        self.log.info("Reconnecting the spend block consumes the synthetic payout again")
        node.reconsiderblock(spend_block_hash)
        self.wait_until(lambda: node.getbestblockhash() == spend_block_hash)
        assert node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        migrated_utxo = self._wait_for_quantum_utxo(wallet, next_quantum)

        self.log.info("Reorging below the claim block after spend removes both payout generations")
        node.invalidateblock(claim_block_hash)
        self._assert_no_quantum_utxo(wallet, payout_address)
        self._assert_no_quantum_utxo(wallet, next_quantum)
        assert node.gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert node.gettxout(migrated_utxo["txid"], migrated_utxo["vout"], False) is None


if __name__ == "__main__":
    GoldRushValuePathTest().main()
