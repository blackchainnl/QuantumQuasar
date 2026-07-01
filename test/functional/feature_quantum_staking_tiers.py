#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise tiered quantum staking through live wallet and node paths.

The fixed-point unit harness proves the curve and script-derived context. This
functional test proves the live path: a wallet creates a bonded 40-byte v16
tiered staking output, mines a quantum PoS block from it, an independent node
accepts the same block, and a signed-but-mutated block that redirects tiered
principal is rejected by consensus proposal validation.
"""

from decimal import Decimal
import json
import os
import time

from test_framework.blocktools import COINBASE_MATURITY, WITNESS_COMMITMENT_HEADER, get_witness_script
from test_framework.messages import CBlock, CTransaction, CTxInWitness, from_hex, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


CANONICAL_JSON = os.path.join(
    os.path.dirname(__file__), "..", "..", "contrib", "staking", "staking_mr_canonical.json"
)
MIGRATION_DEADLINE_TIME = 2_200_000_000
STAKE_AMOUNT = Decimal("12000")
VAULT_7D_BLOCKS = 9450


def load_canonical():
    with open(CANONICAL_JSON, encoding="utf8") as f:
        return json.load(f)


class QuantumStakingTiersTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        args = [
            "-txindex=1",
            "-staketimio=50",
            "-donatetodevfund=0",
            "-qqgoldrushendtime=1",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
            "-qqstaketierheight=1",
        ]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.canon = load_canonical()
        assert_equal(self.canon["liquid_ppm10k"], 2500)
        assert_equal(self.canon["full_ppm10k"], 10000)
        assert_equal(self.canon["tier_points"]["vault_7d"], 10000)

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _generate(self, count, address):
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(self.nodes[0], 1, address))
            self._bump_mocktime(16)
        return hashes

    def _staking_inputs(self, wallet, address):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999, [address])
        ]

    def _find_next_kernel_time(self, wallet, address):
        inputs = self._staking_inputs(wallet, address)
        assert inputs, "tiered staking wallet must have mature inputs"
        for _ in range(20000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic tiered staking kernel")

    def _stake_tiered_block(self, wallet, stake_address):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet, stake_address)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
            block_hash = node.getbestblockhash()
            self.sync_blocks(self.nodes)
            assert_equal(self.nodes[1].getbestblockhash(), block_hash)
            block = node.getblock(block_hash, 2)
            assert "proof-of-stake" in block["flags"]
            return block_hash, block
        finally:
            wallet.staking(False)

    def _one_tiered_utxo(self, wallet, stake_address):
        utxos = wallet.listunspent(1, 9999999, [stake_address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def _script_for_address(self, address):
        return bytes.fromhex(self.nodes[0].validateaddress(address)["scriptPubKey"])

    def _prevtx_for_utxo(self, utxo):
        return {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": utxo["scriptPubKey"],
            "amount": utxo["amount"],
        }

    def _sign_quantum_tx(self, tx, quantum_key, prevtx):
        signed = self.nodes[0].signrawtransactionwithquantumkey(
            tx.serialize().hex(),
            [{
                "public_key": quantum_key["public_key"],
                "private_key": quantum_key["private_key"],
            }],
            [prevtx],
        )
        if not signed["complete"]:
            raise AssertionError(f"tiered quantum transaction did not verify after signing: {signed}")
        return tx_from_hex(signed["hex"])

    def _signed_candidate_block(self, raw_block_hex, signed_coinstake, signing_key):
        block = from_hex(CBlock(), raw_block_hex)
        block.vtx[1] = signed_coinstake

        coinbase = CTransaction(block.vtx[0])
        coinbase.wit.vtxinwit = [CTxInWitness() for _ in coinbase.vin]
        coinbase.wit.vtxinwit[0].scriptWitness.stack = [b"\x00" * 32]
        block.vtx[0] = coinbase

        witness_root = block.calc_witness_merkle_root()
        witness_script = get_witness_script(witness_root, 0)
        for txout in reversed(block.vtx[0].vout):
            if bytes(txout.scriptPubKey).startswith(b"\x6a\x24" + WITNESS_COMMITMENT_HEADER):
                txout.scriptPubKey = witness_script
                break
        else:
            raise AssertionError("candidate tiered staking block is missing a witness commitment output")

        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.sha256 = None
        block.hash = None
        block.vchBlockSig = b""
        signed_block = self.nodes[0].signrawblockwithquantumkey(
            block.serialize().hex(),
            signing_key["public_key"],
            signing_key["private_key"],
        )
        return signed_block["hex"]

    def _assert_redirected_tiered_principal_rejected(self, raw_block_hex, stake_utxo, stake_key, stake_script):
        node = self.nodes[0]
        original_block = from_hex(CBlock(), raw_block_hex)
        redirected = CTransaction(original_block.vtx[1])
        redirected_script = self._script_for_address(node.get_wallet_rpc("tier_staker").getnewquantumaddress()["address"])
        redirected_outputs = 0
        for txout in redirected.vout:
            if txout.nValue > 0 and txout.scriptPubKey == stake_script:
                txout.scriptPubKey = redirected_script
                redirected_outputs += 1
        assert redirected_outputs > 0
        redirected.sha256 = None
        redirected.hash = None

        signed_coinstake = self._sign_quantum_tx(redirected, stake_key, self._prevtx_for_utxo(stake_utxo))
        invalid_block_hex = self._signed_candidate_block(raw_block_hex, signed_coinstake, stake_key)
        assert_equal(node.getblocktemplate({"mode": "proposal", "data": invalid_block_hex}), "bad-stake-tier-covenant")

    def run_test(self):
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        for node in self.nodes:
            assert_equal(node.getquantumquasarinfo()["phase"], "migration")

        self.log.info("Creating funder and tiered staking wallets")
        for node in self.nodes:
            node.get_wallet_rpc(self.default_wallet_name).staking(False)
        self.nodes[0].createwallet(wallet_name="tier_funder")
        self.nodes[0].createwallet(wallet_name="tier_staker")
        funder = self.nodes[0].get_wallet_rpc("tier_funder")
        staker = self.nodes[0].get_wallet_rpc("tier_staker")
        funder.staking(False)
        staker.staking(False)

        self.log.info("Creating a wallet-backed 7-day Vault quantum staking address")
        stake_info = staker.getnewquantumstakeaddress("vault-7d", VAULT_7D_BLOCKS)
        stake_address = stake_info["address"]
        assert_equal(stake_info["witness_version"], 16)
        assert_equal(len(stake_info["witness_program"]), 80)
        assert_equal(stake_info["tier_state"], "bonded")
        assert_equal(stake_info["unbonding_blocks"], VAULT_7D_BLOCKS)
        assert_equal(stake_info["unlock_height"], 0)
        assert_equal(stake_info["stored_in_wallet"], True)
        validate = self.nodes[0].validateaddress(stake_address)
        assert_equal(validate["isvalid"], True)
        assert_equal(validate["isquantummigration"], True)
        stake_script = bytes.fromhex(validate["scriptPubKey"])
        stake_key = staker.dumpquantumkey(stake_address)
        assert_equal(stake_key["public_key"], stake_info["public_key"])

        self.log.info("Funding and maturing the tiered staking output")
        funder_address = funder.getnewaddress("", "legacy")
        self._generate(COINBASE_MATURITY + 2, funder_address)
        funding_txid = funder.sendtoaddress(stake_address, STAKE_AMOUNT)
        self._generate(1, funder_address)
        self.wait_until(lambda: len(staker.listunspent(1, 9999999, [stake_address])) == 1, timeout=30)
        self._generate(COINBASE_MATURITY, funder_address)
        stake_utxo = self._one_tiered_utxo(staker, stake_address)
        assert_equal(stake_utxo["txid"], funding_txid)
        assert_equal(Decimal(str(stake_utxo["amount"])), STAKE_AMOUNT)
        assert_equal(bytes.fromhex(stake_utxo["scriptPubKey"]), stake_script)

        self.log.info("Mining a tiered quantum PoS block and validating it on an independent node")
        self._sync_mocktime_to_tip()
        block_hash, block = self._stake_tiered_block(staker, stake_address)
        coinstake = block["tx"][1]
        assert_equal(coinstake["vin"][0]["txid"], stake_utxo["txid"])
        assert_equal(coinstake["vin"][0]["vout"], stake_utxo["vout"])
        assert_equal(coinstake["vin"][0]["txinwitness"][1], stake_key["public_key"])

        tiered_outputs = [
            Decimal(str(vout["value"]))
            for vout in coinstake["vout"]
            if bytes.fromhex(vout["scriptPubKey"]["hex"]) == stake_script
        ]
        assert tiered_outputs, "tiered quantum coinstake must return principal to the same tiered script"
        assert sum(tiered_outputs) >= STAKE_AMOUNT

        self.log.info("Rejecting a signed tiered coinstake that redirects bonded principal")
        raw_tiered_block = self.nodes[0].getblock(block_hash, 0)
        pre_tiered_tip = block["previousblockhash"]
        for node in self.nodes:
            node.invalidateblock(block_hash)
            assert_equal(node.getbestblockhash(), pre_tiered_tip)
        self._assert_redirected_tiered_principal_rejected(raw_tiered_block, stake_utxo, stake_key, stake_script)

        self.log.info("Reconsidering the valid tiered staking block")
        for node in self.nodes:
            node.reconsiderblock(block_hash)
        self.wait_until(lambda: all(node.getbestblockhash() == block_hash for node in self.nodes), timeout=30)


if __name__ == "__main__":
    QuantumStakingTiersTest().main()
