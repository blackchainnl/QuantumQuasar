#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Run an accelerated demurrage soak with 50 local actors.

This is an extended, on-demand soak rather than a default-suite test. It compresses
the demurrage month to two blocks, then drives a three-year equivalent local run:
20 dormant direct-quantum actors decay to lock, 20 active direct-quantum actors
refresh by periodic quantum spends, and 10 cold-stake actors remain exempt while
the per-pool cap bootstrap pool-cap selection path is exercised.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 5_000
DIRECT_AMOUNT = Decimal("2")
COLD_BOOTSTRAP_AMOUNT = Decimal("100")
COLD_SMALL_AMOUNT = Decimal("1")
QUANTUM_SPEND_FEE = Decimal("0.01")
BLOCKS_PER_MONTH = 2
SOAK_BLOCKS = 36 * BLOCKS_PER_MONTH
ACTIVE_REFRESH_INTERVAL = 4 * BLOCKS_PER_MONTH


class QuantumDemurrageSoakTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-donatetodevfund=0",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
            "-qqdemurrageheight=1",
            f"-qqdemurrageblockspermonth={BLOCKS_PER_MONTH}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _generate(self, count, address):
        hashes = []
        for _ in range(count):
            hashes.extend(self.generatetoaddress(self.nodes[0], 1, address, sync_fun=self.no_op))
            self._bump_mocktime()
        return hashes

    def _mine_until_demurrage_active(self, address, max_blocks=24):
        node = self.nodes[0]
        for _ in range(max_blocks):
            supply = node.getcirculatingsupply()
            final_lockout = node.getquantumquasarinfo()["phase"] == "final_lockout"
            assert_equal(supply["demurrage_active"], final_lockout)
            if supply["demurrage_active"]:
                return supply
            self._generate(1, address)
        raise AssertionError("timed out waiting for demurrage/final-lockout atomic MTP activation")

    def _one_output(self, wallet, address):
        utxos = wallet.listunspent(0, 9999999, [address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def _wallet_output(self, wallet, address):
        matches = [output for output in wallet.getdemurragewalletinfo()["outputs"] if output["address"] == address]
        assert_equal(len(matches), 1)
        return matches[0]

    def _signed_quantum_spend(self, wallet, address, destination):
        node = self.nodes[0]
        utxo = self._one_output(wallet, address)
        amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: amount}],
        )
        key = wallet.dumpquantumkey(address)
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        assert_equal(signed["complete"], True)
        return node.sendrawtransaction(signed["hex"])

    def _new_cold_actor(self, owner, staker, label, amount):
        staker_key = staker.dumpquantumkey(staker.getnewquantumaddress()["address"])
        delegation = owner.getnewquantumcoldstakingaddress(staker_key["public_key"], label)
        owner_key = owner.dumpquantumkey(delegation["owner_quantum_address"])
        return {
            "address": delegation["address"],
            "staker_pubkey": staker_key["public_key"],
            "owner_pubkey": owner_key["public_key"],
            "amount": amount,
            "utxo": None,
        }

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        node.get_wallet_rpc(self.default_wallet_name).staking(False)

        self.log.info("Creating 50 actors and mature pre-deadline funding")
        for name in ("soak_funder", "soak_owner", "soak_staker_a", "soak_staker_b", "soak_staker_c"):
            node.createwallet(wallet_name=name)
        funder = node.get_wallet_rpc("soak_funder")
        owner = node.get_wallet_rpc("soak_owner")
        staker_a = node.get_wallet_rpc("soak_staker_a")
        staker_b = node.get_wallet_rpc("soak_staker_b")
        staker_c = node.get_wallet_rpc("soak_staker_c")
        for wallet in (funder, owner, staker_a, staker_b, staker_c):
            wallet.staking(False)

        funder_address = funder.getnewaddress("", "legacy")
        mining_address = node.createquantumkey()["address"]
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        self._generate(COINBASE_MATURITY + 2, funder_address)

        dormant_addresses = [funder.getnewquantumaddress()["address"] for _ in range(20)]
        active_addresses = [funder.getnewquantumaddress()["address"] for _ in range(20)]
        cold_actors = [self._new_cold_actor(owner, staker_a, "bootstrap-a", COLD_BOOTSTRAP_AMOUNT)]
        stakers = (staker_a, staker_b, staker_c)
        for i in range(1, 10):
            cold_actors.append(self._new_cold_actor(owner, stakers[i % len(stakers)], f"cold-{i}", COLD_SMALL_AMOUNT))

        outputs = {}
        for address in dormant_addresses + active_addresses:
            outputs[address] = DIRECT_AMOUNT
        for actor in cold_actors:
            outputs[actor["address"]] = actor["amount"]
        funding_txid = funder.sendmany("", outputs)
        assert_equal(funding_txid in node.getrawmempool(), True)
        self._generate(1, funder_address)
        for address in dormant_addresses + active_addresses:
            assert_equal(self._one_output(funder, address)["amount"], DIRECT_AMOUNT)
        for actor in cold_actors:
            actor["utxo"] = self._one_output(owner, actor["address"])
            assert_equal(actor["utxo"]["txid"], funding_txid)

        self.log.info("Exercising per-pool cap bootstrap pool-cap selection with cold-stake actors")
        first_cold = cold_actors[0]
        first_claim = node.submitquantumpoolclaim(first_cold["staker_pubkey"], [{
            "txid": first_cold["utxo"]["txid"],
            "vout": first_cold["utxo"]["vout"],
            "owner_pubkey": first_cold["owner_pubkey"],
        }])
        assert_equal(first_claim["accepted"], True)
        bootstrap = owner.getnewquantumcoldstakingaddress(
            first_cold["staker_pubkey"],
            "bootstrap-over-cap-ok",
            {"delegation_amount": Decimal("1")},
        )
        assert_equal(bootstrap["pool_cap_preflight"]["would_exceed_cap"], True)
        assert_equal(bootstrap["pool_cap_preflight"]["cap_filter_unlocked"], True)

        for actor in cold_actors[1:]:
            claim = node.submitquantumpoolclaim(actor["staker_pubkey"], [{
                "txid": actor["utxo"]["txid"],
                "vout": actor["utxo"]["vout"],
                "owner_pubkey": actor["owner_pubkey"],
            }])
            assert_equal(claim["accepted"], True)
        post_registry = owner.getnewquantumcoldstakingaddress(
            cold_actors[0]["staker_pubkey"],
            "post-bootstrap-over-cap-observed",
            {"delegation_amount": Decimal("1")},
        )
        assert_equal(post_registry["pool_cap_preflight"]["would_exceed_cap"], True)
        pool_info = node.getquantumpoolinfo(cold_actors[0]["staker_pubkey"], Decimal("1"))
        assert_equal(pool_info["operator_count"], 1)
        assert_equal(pool_info["operators"][0]["would_exceed_cap"], True)

        self.log.info("Crossing final lockout and running three compressed years")
        self._set_mocktime(MIGRATION_DEADLINE_TIME + 16)
        self._mine_until_demurrage_active(mining_address)

        for step in range(1, SOAK_BLOCKS + 1):
            if step % ACTIVE_REFRESH_INTERVAL == 0:
                refreshed = []
                for address in active_addresses:
                    destination = funder.getnewquantumaddress()["address"]
                    txid = self._signed_quantum_spend(funder, address, destination)
                    assert_equal(txid in node.getrawmempool(), True)
                    refreshed.append(destination)
                active_addresses = refreshed
            self._generate(1, mining_address)

        self.log.info("Checking dormant lock, active survival, cold-stake exemption, and supply decay")
        info = funder.getdemurragewalletinfo()
        assert_equal(info["demurrage_active"], True)
        for address in dormant_addresses:
            output = self._wallet_output(funder, address)
            assert_equal(output["locked"], True)
            assert_equal(output["remaining_ppm"], 0)
            assert_equal(output["effective_amount"], Decimal("0E-8"))

        for address in active_addresses:
            output = self._wallet_output(funder, address)
            assert_equal(output["locked"], False)
            assert_equal(output["burned_if_spent_amount"], Decimal("0E-8"))

        for actor in cold_actors:
            txout = node.gettxout(actor["utxo"]["txid"], actor["utxo"]["vout"], False)
            assert txout is not None
            assert_equal(Decimal(str(txout["value"])), actor["amount"])

        supply = node.getcirculatingsupply()
        assert_equal(supply["demurrage_active"], True)
        assert_greater_than(supply["locked_txouts"], 19)
        assert_greater_than(Decimal(supply["decayed_amount"]), Decimal("0"))


if __name__ == "__main__":
    QuantumDemurrageSoakTest().main()
