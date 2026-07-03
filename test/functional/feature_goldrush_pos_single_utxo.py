#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the one-UTXO Gold Rush PoS signal edge case.

A wallet that qualified for the whitelist with exactly one legacy UTXO has to
spend that UTXO to solve its first PoS block. It must still be able to signal
after the resulting coinstake output matures, and the pending signal must not
be double-spent by the next coinstake.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
QQSIGNAL_HEX = "51515349474e414c"
QQSPROOF_HEX = "51515350524f4f46"
WALLET_NAME = "goldrush_single_utxo"


class GoldRushPosSingleUtxoTest(BitcoinTestFramework):
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
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block(self, wallet, *, expected_txids=None):
        node = self.nodes[0]
        expected_txids = expected_txids or []
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
                for expected_txid in expected_txids:
                    assert expected_txid in txids[2:], f"pending Gold Rush claim {expected_txid} must be mined as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _target_utxos(self, wallet, script_pub_key, min_conf=1):
        return [
            utxo for utxo in wallet.listunspent(min_conf, 9999999)
            if utxo["scriptPubKey"] == script_pub_key
        ]

    def _get_quantum_utxos(self, wallet, address):
        return wallet.listunspent(0, 9999999, [address], True, {"include_immature_coinbase": True})

    def _wait_for_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address)[0]

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)

        signal_address = wallet.getnewaddress("", "legacy")
        whitelist_script = wallet.getaddressinfo(signal_address)["scriptPubKey"]
        funder_address = node.get_wallet_rpc(self.default_wallet_name).getnewaddress("", "legacy")

        self.log.info("Snapshotting exactly one 10,000 BLK UTXO for the whitelisted address")
        self.generatetoaddress(node, 1, signal_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 8, funder_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        target_utxos = self._target_utxos(wallet, whitelist_script)
        assert_equal(len(target_utxos), 1)
        assert_equal(Decimal(str(target_utxos[0]["amount"])), Decimal("10000.00000000"))

        self.log.info("Solving a PoS block spends the only whitelisted UTXO")
        solve_block_hash = self._mine_pos_block(wallet)
        solve_block = node.getblock(solve_block_hash)
        solve_height = solve_block["height"]
        assert_equal(self._target_utxos(wallet, whitelist_script), [])

        payout_address = wallet.getnewquantumaddress("single-utxo-pos-payout")["address"]
        assert_raises_rpc_error(
            -6,
            "No spendable non-dust UTXO found for the signaling address",
            wallet.sendshadowsignal,
            signal_address,
            solve_height,
            solve_block_hash,
            payout_address,
        )

        self.log.info("Maturing the coinstake output keeps the recent solve signalable")
        self.generatetoaddress(node, COINBASE_MATURITY, funder_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        matured_utxos = wallet.listunspent(1, 9999999)
        assert len(matured_utxos) >= 2, "coinstake should leave enough matured stake for signal+stake"
        assert sum(Decimal(str(utxo["amount"])) for utxo in matured_utxos) > Decimal("10000")
        goldrush_info = wallet.getgoldrushinfo()
        assert_equal(goldrush_info["wallet_recent_solve_qualified"], True)

        self.log.info("Broadcasting one QQSIGNAL from a matured canonical P2PK coinstake output")
        signal = wallet.sendshadowsignal(signal_address, solve_height, solve_block_hash, payout_address)
        assert signal["txid"] in node.getrawmempool()
        decoded_signal = node.decoderawtransaction(signal["hex"])
        assert any(QQSIGNAL_HEX in vout["scriptPubKey"]["hex"] for vout in decoded_signal["vout"])

        self.log.info("Mining a PoS block with the pending signal does not double-spend the signaling input")
        payout_block_hash = self._mine_pos_block(wallet, expected_txids=[signal["txid"]])
        payout_block = node.getblock(payout_block_hash, 2)
        signal_txs = [
            tx for tx in payout_block["tx"][2:]
            if any(QQSIGNAL_HEX in vout["scriptPubKey"]["hex"] for vout in tx["vout"])
        ]
        assert_equal([tx["txid"] for tx in signal_txs], [signal["txid"]])

        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert Decimal(str(payout_utxo["amount"])) > 0
        final_info = wallet.getgoldrushinfo()
        assert_equal(final_info["last_pos_height"], node.getblock(payout_block_hash)["height"])
        assert final_info["pos_count"] >= 1

        self.log.info("Submitting a QQSPROOF from a matured P2PK coinstake output uses the same canonical identity")
        pow_payout_address = wallet.getnewquantumaddress("single-utxo-pow-payout")["address"]
        self.generatetoaddress(node, COINBASE_MATURITY, funder_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        pow_claim = wallet.sendshadowpowclaim(signal_address, pow_payout_address, 500000)
        assert pow_claim["txid"] in node.getrawmempool()
        decoded_pow = node.decoderawtransaction(pow_claim["hex"])
        assert any(QQSPROOF_HEX in vout["scriptPubKey"]["hex"] for vout in decoded_pow["vout"])
        pow_block_hash = self._mine_pos_block(wallet, expected_txids=[pow_claim["txid"]])
        pow_block = node.getblock(pow_block_hash, 2)
        assert "proof-of-stake" in pow_block["flags"]
        assert pow_claim["txid"] in [tx["txid"] for tx in pow_block["tx"][1:]]
        pow_payout_utxo = self._wait_for_quantum_utxo(wallet, pow_payout_address)
        assert Decimal(str(pow_payout_utxo["amount"])) > 0
        pow_info = wallet.getgoldrushinfo()
        assert_equal(pow_info["last_pow_height"], node.getblock(pow_block_hash)["height"])
        assert pow_info["pow_count"] >= 1


if __name__ == "__main__":
    GoldRushPosSingleUtxoTest().main()
