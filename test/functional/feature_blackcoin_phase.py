#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Blackcoin phase gates on regtest.

Regtest defaults to V4 active with a perpetual Gold Rush. Explicit phase
overrides let this test cover the post-Gold-Rush migration and final-lockout
states without waiting on wall-clock schedule boundaries.
"""

from decimal import Decimal

from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.address import key_to_p2pkh
from test_framework.script import CScript, OP_FALSE, OP_RETURN
from test_framework.script_util import key_to_p2pkh_script
from test_framework.wallet_util import generate_keypair


SIGHASH_FORKID = 0x40
LEGACY_BLOCK_WEIGHT = 4_000_000
LEGACY_BLOCK_SIGOPS = 80_000
V4_BLOCK_WEIGHT = 32_000_000
V4_BLOCK_SIGOPS = 640_000

class BlackcoinPhaseTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            ["-shadowwhitelistheight=1", "-shadowgoldrushblocks=500"],
            ["-shadowwhitelistheight=1", "-shadowgoldrushblocks=1", "-qqgoldrushendtime=1"],
            ["-shadowwhitelistheight=1", "-shadowgoldrushblocks=1", "-qqgoldrushendtime=1", "-qqmigrationdeadlinetime=2"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def _default_signature_has_forkid(self, node):
        privkey, pubkey = generate_keypair(wif=True)
        address = key_to_p2pkh(pubkey)
        script_pub_key = key_to_p2pkh_script(pubkey).hex()
        prev_txid = "00" * 32
        raw = node.createrawtransaction(
            [{"txid": prev_txid, "vout": 0}],
            [{address: 0.5}],
        )
        signed = node.signrawtransactionwithkey(
            raw,
            [privkey],
            [{"txid": prev_txid, "vout": 0, "scriptPubKey": script_pub_key, "amount": 1}],
        )
        assert signed["complete"]
        decoded = node.decoderawtransaction(signed["hex"])
        script_sig = bytes.fromhex(decoded["vin"][0]["scriptSig"]["hex"])
        sig_len = script_sig[0]
        sighash_byte = script_sig[sig_len]
        return (sighash_byte & SIGHASH_FORKID) != 0

    def _signed_eutxo_output_tx(self, node):
        privkey, pubkey = generate_keypair(wif=True)
        address = key_to_p2pkh(pubkey)
        script_pub_key = key_to_p2pkh_script(pubkey).hex()
        block_hashes = self.generatetoaddress(node, 101, address, sync_fun=self.no_op)
        coinbase_txid = node.getblock(block_hashes[0])["tx"][0]
        coinbase = node.getrawtransaction(coinbase_txid, True, block_hashes[0])
        value = Decimal(str(coinbase["vout"][0]["value"]))
        spend_value = value - Decimal("0.001")
        raw = node.createrawtransaction(
            [{"txid": coinbase_txid, "vout": 0}],
            [{"eutxo": {"amount": spend_value, "datum": "01", "validator": "51"}}],
        )
        signed = node.signrawtransactionwithkey(
            raw,
            [privkey],
            [{"txid": coinbase_txid, "vout": 0, "scriptPubKey": script_pub_key, "amount": value}],
        )
        assert signed["complete"]
        return signed["hex"]

    def _signed_shadow_marker_output_tx(self, node):
        privkey, pubkey = generate_keypair(wif=True)
        address = key_to_p2pkh(pubkey)
        script_pub_key = key_to_p2pkh_script(pubkey).hex()
        block_hashes = self.generatetoaddress(node, 101, address, sync_fun=self.no_op)
        coinbase_txid = node.getblock(block_hashes[0])["tx"][0]
        coinbase = node.getrawtransaction(coinbase_txid, True, block_hashes[0])
        value = Decimal(str(coinbase["vout"][0]["value"]))

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(coinbase_txid, 16), 0))]
        tx.vout = [CTxOut(int((value - Decimal("0.001")) * COIN), CScript([OP_FALSE, OP_RETURN, b"QQPOOL"]))]
        signed = node.signrawtransactionwithkey(
            tx.serialize().hex(),
            [privkey],
            [{"txid": coinbase_txid, "vout": 0, "scriptPubKey": script_pub_key, "amount": value}],
        )
        assert signed["complete"]
        return signed["hex"]

    def _assert_goldrush_info_rpc(self, node):
        if not self.is_wallet_compiled():
            return
        wallet_name = "shadow_signal"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        address = wallet.getnewaddress()
        self.generatetoaddress(node, 101, address, sync_fun=self.no_op)
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        info = wallet.getgoldrushinfo()
        assert_equal(info["active"], True)
        assert info["pow_target_bits"] >= 10
        assert any(entry["address"] == address for entry in info["wallet_scripts"])

    def _assert_rgb_commitment_rpc(self, node):
        state_hash = "11" * 32
        raw = node.createrawtransaction([], [{"rgb_commitment": state_hash}])
        decoded = node.decoderawtransaction(raw)
        script_pub_key = decoded["vout"][0]["scriptPubKey"]
        assert_equal(script_pub_key["type"], "rgb_commitment")
        assert_equal(script_pub_key["rgb_magic"], "RGB1")
        assert_equal(script_pub_key["rgb_state_hash"], state_hash)

        commitment = node.decodergbcommitment(script_pub_key["hex"])
        assert_equal(commitment["type"], "rgb_commitment")
        assert_equal(commitment["magic"], "RGB1")
        assert_equal(commitment["state_hash"], state_hash)
        assert_equal(commitment["spendable"], False)
        assert_raises_rpc_error(-8, "scriptPubKey is not an RGB commitment", node.decodergbcommitment, "6a")

    def run_test(self):
        self.log.info("Gold Rush remains base-network staking compatible")
        gold_rush = self.nodes[0].getquantumquasarinfo()
        assert_equal(gold_rush["phase"], "gold_rush")
        assert_equal(gold_rush["base_network_stake_compatible"], True)
        assert_equal(gold_rush["shadow_merge_mining_active"], False)
        assert_equal(gold_rush["shadow_reward_height_active"], False)
        assert_equal(gold_rush["shadow_reward_next_height"], 1)
        assert_equal(gold_rush["new_network_stake_only"], False)
        assert_equal(gold_rush["replay_protection_active"], False)
        assert_equal(gold_rush["quantum_spend_enforcement_active"], False)
        assert_equal(self._default_signature_has_forkid(self.nodes[0]), False)
        gold_rush_template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        assert_equal(gold_rush_template["weightlimit"], LEGACY_BLOCK_WEIGHT)
        assert_equal(gold_rush_template["sigoplimit"], LEGACY_BLOCK_SIGOPS)
        self._assert_goldrush_info_rpc(self.nodes[0])
        self._assert_rgb_commitment_rpc(self.nodes[0])
        assert_raises_rpc_error(
            -25,
            "TestBlockValidity failed: shadow-marker-output",
            self.generateblock,
            self.nodes[0],
            self.nodes[0].get_deterministic_priv_key().address,
            [self._signed_shadow_marker_output_tx(self.nodes[0])],
        )
        gold_rush_eutxo = self.nodes[0].testmempoolaccept([self._signed_eutxo_output_tx(self.nodes[0])])[0]
        assert_equal(gold_rush_eutxo["allowed"], False)
        assert_equal(gold_rush_eutxo["reject-reason"], "eutxo-output-premature")

        self.log.info("Migration phase activates quantum spends while legacy staking remains accepted")
        self.generatetoaddress(self.nodes[1], 3, self.nodes[1].get_deterministic_priv_key().address, sync_fun=self.no_op)
        migration = self.nodes[1].getquantumquasarinfo()
        assert_equal(migration["phase"], "migration")
        assert_equal(migration["base_network_stake_compatible"], True)
        assert_equal(migration["shadow_merge_mining_active"], False)
        assert_equal(migration["new_network_stake_only"], False)
        assert_equal(migration["replay_protection_active"], False)
        assert_equal(migration["quantum_spend_enforcement_active"], True)
        assert_equal(self._default_signature_has_forkid(self.nodes[1]), False)
        migration_template = self.nodes[1].getblocktemplate({"rules": ["segwit"]})
        assert_equal(migration_template["weightlimit"], V4_BLOCK_WEIGHT)
        assert_equal(migration_template["sigoplimit"], V4_BLOCK_SIGOPS)
        migration_eutxo = self.nodes[1].testmempoolaccept([self._signed_eutxo_output_tx(self.nodes[1])])[0]
        assert_equal(migration_eutxo["allowed"], True)

        self.log.info("Final lockout keeps new-network-only staking and requires quantum addresses")
        final_lockout = self.nodes[2].getquantumquasarinfo()
        assert_equal(final_lockout["phase"], "final_lockout")
        assert_equal(final_lockout["base_network_stake_compatible"], False)
        assert_equal(final_lockout["shadow_merge_mining_active"], False)
        assert_equal(final_lockout["new_network_stake_only"], True)
        assert_equal(final_lockout["replay_protection_active"], True)
        assert_equal(final_lockout["quantum_address_required"], True)


if __name__ == "__main__":
    BlackcoinPhaseTest().main()
