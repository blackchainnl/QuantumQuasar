#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test final-lockout sighash behavior for legacy signrawtransactionwithkey inputs."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 400
PRE_LOCKOUT_TIME = GOLD_RUSH_END_TIME - 10_000
LEGACY_SPEND_FEE = Decimal("0.001")
SIGHASH_FORKID = 0x40


class QuantumFinalLockoutSighashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
        ]]

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _mine_until_phase(self, phase, target_time, address):
        node = self.nodes[0]
        self._set_mocktime(target_time)
        for _ in range(20):
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime()
            if node.getquantumquasarinfo()["phase"] == phase:
                return
        raise AssertionError(f"timed out waiting for phase {phase}")

    def _legacy_signature_has_forkid(self, node, tx_hex):
        decoded = node.decoderawtransaction(tx_hex)
        script_sig = bytes.fromhex(decoded["vin"][0]["scriptSig"]["hex"])
        assert script_sig, "legacy input must have a scriptSig"
        sig_len = script_sig[0]
        assert sig_len + 1 <= len(script_sig), "legacy signature push is truncated"
        sighash_byte = script_sig[sig_len]
        return (sighash_byte & SIGHASH_FORKID) != 0

    def run_test(self):
        node = self.nodes[0]
        funding_key = node.get_deterministic_priv_key()
        self._set_mocktime(PRE_LOCKOUT_TIME)

        self.log.info("Create a mature legacy UTXO before final lockout")
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        block_hashes = self.generatetoaddress(node, COINBASE_MATURITY + 1, funding_key.address, sync_fun=self.no_op)
        funding_block_hash = block_hashes[0]
        funding_txid = node.getblock(funding_block_hash)["tx"][0]
        funding_tx = node.getrawtransaction(funding_txid, True, funding_block_hash)
        funding_amount = Decimal(str(funding_tx["vout"][0]["value"]))
        prevtx = {
            "txid": funding_txid,
            "vout": 0,
            "scriptPubKey": funding_tx["vout"][0]["scriptPubKey"]["hex"],
            "amount": funding_amount,
        }

        self.log.info("Cross the migration deadline into final lockout")
        quantum_address = node.createquantumkey()["address"]
        self._mine_until_phase("final_lockout", MIGRATION_DEADLINE_TIME + 16, quantum_address)
        info = node.getquantumquasarinfo()
        assert_equal(info["phase"], "final_lockout")
        assert_equal(info["replay_protection_active"], True)

        spend_amount = funding_amount - LEGACY_SPEND_FEE
        raw_spend = node.createrawtransaction(
            [{"txid": funding_txid, "vout": 0}],
            [{quantum_address: spend_amount}],
        )

        self.log.info("Omitted sighash defaults legacy signing to ALL|FORKID after final lockout")
        default_signed = node.signrawtransactionwithkey(raw_spend, [funding_key.key], [prevtx])
        assert_equal(default_signed["complete"], True)
        assert_equal(self._legacy_signature_has_forkid(node, default_signed["hex"]), True)

        self.log.info("Explicit ALL remains non-FORKID and is not broadcastable after final lockout")
        explicit_all_signed = node.signrawtransactionwithkey(raw_spend, [funding_key.key], [prevtx], "ALL")
        assert_equal(explicit_all_signed["complete"], True)
        assert_equal(self._legacy_signature_has_forkid(node, explicit_all_signed["hex"]), False)
        explicit_all_accept = node.testmempoolaccept([explicit_all_signed["hex"]])[0]
        assert_equal(explicit_all_accept["allowed"], False)
        assert_equal(explicit_all_accept["reject-reason"], "legacy-spend-disabled")


if __name__ == "__main__":
    QuantumFinalLockoutSighashTest().main()
