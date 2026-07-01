#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.messages import CTransaction

class RGBRPCTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _funded_eutxo_commitment(self, node, datum, validator):
        address = node.getnewaddress()
        block_hashes = self.generatetoaddress(node, 101, address, sync_fun=self.no_op)
        coinbase_txid = node.getblock(block_hashes[0])["tx"][0]
        coinbase = node.getrawtransaction(coinbase_txid, True, block_hashes[0])
        coinbase_value = Decimal(str(coinbase["vout"][0]["value"]))
        amount = coinbase_value - Decimal("0.001")
        raw = node.createrawtransaction(
            [{"txid": coinbase_txid, "vout": 0}],
            [{"eutxo": {"amount": amount, "datum": datum, "validator": validator}}],
        )
        signed = node.signrawtransactionwithwallet(
            raw,
            [{"txid": coinbase_txid, "vout": 0, "scriptPubKey": coinbase["vout"][0]["scriptPubKey"]["hex"], "amount": coinbase_value}],
        )
        assert signed["complete"]
        accepted = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(accepted["allowed"], True)
        txid = node.sendrawtransaction(signed["hex"])
        self.generate(node, 1, sync_fun=self.no_op)
        return txid, amount

    def _seal(self, tag, amount=None):
        seal = {"txid": f"{tag:064x}", "vout": 0}
        if amount is not None:
            seal["amount"] = amount
        return seal

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Testing decodergbcommitment...")
        
        # Test empty transaction (has no outputs, so no RGB commitments)
        tx = CTransaction()
        tx_hex = tx.serialize().hex()
        assert_equal(node.decodergbcommitment(tx_hex), [])

        state_hash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        raw_rgb = node.createrawtransaction([], [{"rgb_commitment": state_hash}])
        decoded_rgb = node.decoderawtransaction(raw_rgb)
        script_pub_key = decoded_rgb["vout"][0]["scriptPubKey"]
        assert_equal(script_pub_key["type"], "rgb_commitment")
        assert_equal(script_pub_key["rgb_state_hash"], state_hash)
        decoded_commitment = node.decodergbcommitment(script_pub_key["hex"])
        assert_equal(decoded_commitment["state_hash"], state_hash)

        self.log.info("Testing verifyrgbconsignment fixed-supply validation...")
        consignment = {
            "genesis": {
                "ticker": "QQT",
                "name": "Blackcoin Test Asset",
                "total_supply": 1000,
                "allocations": [self._seal(1, 1000)],
            },
            "transitions": [{
                "inputs": [self._seal(1)],
                "outputs": [self._seal(2, 400), self._seal(3, 600)],
            }],
        }
        rgb_validation = node.verifyrgbconsignment(consignment)
        assert_equal(rgb_validation["valid"], True)
        assert_equal(rgb_validation["current_supply"], 1000)
        assert_equal(rgb_validation["unspent_assignments"], 2)
        assert_equal(rgb_validation["errors"], [])
        assert_equal(len(rgb_validation["transition_ids"]), 1)

        raw_anchor = node.createrawtransaction([], [{"rgb_commitment": rgb_validation["anchor_commitment"]}])
        decoded_anchor = node.decoderawtransaction(raw_anchor)
        anchor_spk = decoded_anchor["vout"][0]["scriptPubKey"]
        assert_equal(anchor_spk["rgb_state_hash"], rgb_validation["anchor_commitment"])
        assert_equal(node.decodergbcommitment(anchor_spk["hex"])["state_hash"], rgb_validation["anchor_commitment"])

        self.log.info("Testing wallet funding preserves RGB commitment anchors...")
        self.generatetoaddress(node, 101, node.getnewaddress(), sync_fun=self.no_op)
        funded_anchor = node.fundrawtransaction(raw_anchor)
        funded_decoded = node.decoderawtransaction(funded_anchor["hex"])
        funded_rgb_outputs = [
            out for out in funded_decoded["vout"]
            if out["scriptPubKey"]["type"] == "rgb_commitment"
        ]
        assert_equal(len(funded_rgb_outputs), 1)
        assert_equal(funded_rgb_outputs[0]["scriptPubKey"]["rgb_state_hash"], rgb_validation["anchor_commitment"])
        signed_anchor = node.signrawtransactionwithwallet(funded_anchor["hex"])
        assert_equal(signed_anchor["complete"], True)
        assert_equal(node.testmempoolaccept([signed_anchor["hex"]])[0]["allowed"], True)

        self.log.info("Testing scoped RGB transfer-anchor commitments...")
        full_history = {
            "genesis": {
                "ticker": "RQS",
                "name": "Blackcoin Scoped Anchor",
                "total_supply": 300,
                "allocations": [self._seal(10, 100), self._seal(20, 200)],
            },
            "transitions": [
                {
                    "inputs": [self._seal(20)],
                    "outputs": [self._seal(40, 200)],
                },
                {
                    "inputs": [self._seal(10)],
                    "outputs": [self._seal(30, 100)],
                },
            ],
        }
        full_history_validation = node.verifyrgbconsignment(full_history)
        assert_equal(full_history_validation["valid"], True)
        assert_equal(len(full_history_validation["transition_ids"]), 2)
        assert_equal(full_history_validation["anchor_commitment"], full_history_validation["consignment_anchor_commitment"])
        scoped_transition_id = full_history_validation["transition_ids"][1]
        scoped_history_validation = node.verifyrgbconsignment(full_history, [scoped_transition_id])
        assert_equal(scoped_history_validation["valid"], True)
        assert_equal(scoped_history_validation["anchor_commitment"], full_history_validation["anchor_commitment"])
        assert_equal(scoped_history_validation["consignment_anchor_commitment"], full_history_validation["anchor_commitment"])
        assert_equal(scoped_history_validation["anchor_transition_ids"], [scoped_transition_id])
        assert scoped_history_validation["transfer_anchor_commitment"] != full_history_validation["anchor_commitment"]
        scoped_anchor = node.createrawtransaction([], [{"rgb_commitment": scoped_history_validation["transfer_anchor_commitment"]}])
        scoped_anchor_spk = node.decoderawtransaction(scoped_anchor)["vout"][0]["scriptPubKey"]
        assert_equal(scoped_anchor_spk["rgb_state_hash"], scoped_history_validation["transfer_anchor_commitment"])

        inflated = {
            "genesis": consignment["genesis"],
            "transitions": [{
                "inputs": [self._seal(1)],
                "outputs": [self._seal(2, 1001)],
            }],
        }
        inflated_validation = node.verifyrgbconsignment(inflated)
        assert_equal(inflated_validation["valid"], False)
        assert "transition input and output amounts do not balance" in inflated_validation["errors"]
        
        # Test malformed hex
        assert_raises_rpc_error(-22, "TX decode failed", node.decodergbcommitment, "zzz")

        self.log.info("Testing decodeeutxospend...")
        # Test empty transaction (has no inputs, so no EUTXO spends)
        assert_equal(node.decodeeutxospend(tx_hex), [])
        
        # Test malformed hex
        assert_raises_rpc_error(-22, "TX decode failed", node.decodeeutxospend, "zzz")

        self.log.info("Testing EUTXO commitment spend through mempool and block connection...")
        datum = "01"
        redeemer = "02"
        validator = "52885187"  # OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL
        eutxo_txid, eutxo_amount = self._funded_eutxo_commitment(node, datum, validator)
        spend_amount = eutxo_amount - Decimal("0.001")

        destination = node.getnewaddress()
        invalid = node.createeutxospend(
            {"txid": eutxo_txid, "vout": 0, "datum": datum, "validator": validator, "redeemer": "03"},
            [{destination: spend_amount}],
        )
        invalid_verification = node.verifyeutxospend(invalid["hex"])
        assert_equal(len(invalid_verification["spends"]), 1)
        assert_equal(invalid_verification["spends"][0]["commitment_ok"], True)
        assert_equal(invalid_verification["spends"][0]["script_valid"], False)
        assert_equal(invalid_verification["spends"][0]["script_error"], "Script failed an OP_EQUALVERIFY operation")
        assert_equal(invalid_verification["spends"][0]["transition_status"], "none")
        assert_equal(invalid_verification["spends"][0]["transition_valid"], True)
        invalid_accept = node.testmempoolaccept([invalid["hex"]])[0]
        assert_equal(invalid_accept["allowed"], False)

        valid = node.createeutxospend(
            {"txid": eutxo_txid, "vout": 0, "datum": datum, "validator": validator, "redeemer": redeemer},
            [{destination: spend_amount}],
        )
        verified = node.verifyeutxospend(valid["hex"])
        assert_equal(verified["validity"], "enforced")
        assert_equal(len(verified["spends"]), 1)
        assert_equal(verified["spends"][0]["commitment_ok"], True)
        assert_equal(verified["spends"][0]["script_valid"], True)
        assert_equal(verified["spends"][0]["transition_status"], "none")
        assert_equal(verified["spends"][0]["transition_valid"], True)
        accepted = node.testmempoolaccept([valid["hex"]])[0]
        assert_equal(accepted["allowed"], True)
        spend_txid = node.sendrawtransaction(valid["hex"])
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.gettxout(eutxo_txid, 0), None)
        assert node.gettxout(spend_txid, 0) is not None

        self.log.info("Testing structured EUTXO state transition enforcement...")
        transition_old_datum = "0a"
        transition_old_validator = "757551"  # OP_DROP OP_DROP OP_TRUE
        transition_txid, transition_amount = self._funded_eutxo_commitment(node, transition_old_datum, transition_old_validator)
        successor_amount = transition_amount - Decimal("0.001")
        transition = node.createeutxotransition(
            {"txid": transition_txid, "vout": 0, "datum": transition_old_datum, "validator": transition_old_validator},
            {"amount": successor_amount, "datum": "0b0c", "validator": "52885187"},
        )
        transition_verification = node.verifyeutxospend(transition["hex"])
        assert_equal(len(transition_verification["spends"]), 1)
        assert_equal(transition_verification["spends"][0]["commitment_ok"], True)
        assert_equal(transition_verification["spends"][0]["script_valid"], True)
        assert_equal(transition_verification["spends"][0]["transition_status"], "valid")
        assert_equal(transition_verification["spends"][0]["transition_valid"], True)
        assert_equal(transition_verification["spends"][0]["transition_error"], "")

        wrong_destination = node.getnewaddress()
        bad_transition = node.createeutxospend(
            {
                "txid": transition_txid,
                "vout": 0,
                "datum": transition_old_datum,
                "validator": transition_old_validator,
                "redeemer": transition["redeemer"],
            },
            [{wrong_destination: successor_amount}],
        )
        bad_transition_verification = node.verifyeutxospend(bad_transition["hex"])
        assert_equal(len(bad_transition_verification["spends"]), 1)
        assert_equal(bad_transition_verification["spends"][0]["commitment_ok"], True)
        assert_equal(bad_transition_verification["spends"][0]["script_valid"], True)
        assert_equal(bad_transition_verification["spends"][0]["transition_status"], "invalid")
        assert_equal(bad_transition_verification["spends"][0]["transition_valid"], False)
        assert_equal(bad_transition_verification["spends"][0]["transition_error"], "EUTXO transition successor commitment mismatch")
        bad_accept = node.testmempoolaccept([bad_transition["hex"]])[0]
        assert_equal(bad_accept["allowed"], False)
        assert "bad-eutxo-transition" in bad_accept["reject-reason"]

        transition_accept = node.testmempoolaccept([transition["hex"]])[0]
        assert_equal(transition_accept["allowed"], True)
        transition_spend_txid = node.sendrawtransaction(transition["hex"])
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.gettxout(transition_txid, 0), None)
        successor = node.gettxout(transition_spend_txid, 0)
        assert successor is not None
        assert_equal(successor["scriptPubKey"]["type"], "eutxo_commitment")
        assert_equal(successor["scriptPubKey"]["witness_program"], transition["successor_program"])

        self.log.info("Tests successful!")

if __name__ == '__main__':
    RGBRPCTest().main()
