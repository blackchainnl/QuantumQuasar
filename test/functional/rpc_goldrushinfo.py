#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

QQSPROOF_HEX = "51515350524f4f46"

class GoldRushInfoTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-shadowwhitelistheight=1", "-shadowgoldrushblocks=500"],
            ["-shadowwhitelistheight=1", "-shadowgoldrushblocks=500"],
        ]

    def _sync_mocktime_to_tip(self):
        tip_time = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        )
        for node in self.nodes:
            node.setmocktime((tip_time & ~0xf) + 16)

    def _assert_builtin_pow_miner_lifecycle(self):
        node = self.nodes[0]
        wallet_name = "goldrush_pow_builtin"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        target = wallet.getnewaddress()

        self.generatetoaddress(node, 101, target, sync_fun=self.no_op)
        self.sync_blocks()
        self._sync_mocktime_to_tip()

        if not self.is_cli_compiled():
            self.log.info("Skipping built-in PoW miner CLI lifecycle test: CLI not compiled")
            return

        self.log.info("Starting the built-in PoW miner via CLI and checking worker telemetry")
        cli_wallet = node.cli(f"-rpcwallet={wallet_name}")
        legacy_payout = wallet.getnewquantumaddress("goldrush-pow")["address"]
        assert_equal(wallet.getaddressinfo(legacy_payout)["labels"], ["goldrush-pow"])
        # Use real clock time while the worker runs. The hashrate meter is wall-clock based,
        # while epoch activity is derived from the already-connected chain tip.
        node.setmocktime(0)
        payout = ""
        try:
            started = cli_wallet.setpowmining(True, 1, 100)
            assert_equal(started["enabled"], True)
            assert_equal(started["threads"], 1)
            assert_equal(started["cpu_percent"], 100)
            payout = started["payout_address"]
            assert_equal(payout, legacy_payout)
            assert "warning" not in started
            assert_equal(wallet.getaddressinfo(payout)["labels"], ["PoW - Quantum Claim Address"])
            assert_equal(node.validateaddress(payout)["isvalid"], True)
            assert_equal(wallet.getpowmininginfo()["payout_address"], payout)

            self.wait_until(lambda: wallet.getpowmininginfo()["hashrate"] > 0, timeout=60)
            info = cli_wallet.getpowmininginfo()
            assert_equal(info["enabled"], True)
            assert_equal(info["threads"], 1)
            assert_equal(info["cpu_percent"], 100)
            assert_equal(info["epoch_active"], True)
            assert_equal(info["payout_address"], payout)
            assert info["hashrate"] > 0
        finally:
            try:
                cli_wallet.setpowmining(False)
            finally:
                self._sync_mocktime_to_tip()

        stopped = wallet.getpowmininginfo()
        assert_equal(stopped["enabled"], False)
        assert_equal(stopped["hashrate"], 0)
        if payout:
            assert_equal(stopped["payout_address"], payout)

    def _assert_pow_claim_from_non_whitelisted_address(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping PoW claim wallet test: wallet not compiled")
            return

        node = self.nodes[0]
        self.log.info("Activating reachable Shadow Gold Rush window")
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self.sync_blocks()

        wallet_name = "goldrush_pow"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)

        rpc_target = wallet.getnewaddress()
        cli_target = wallet.getnewaddress()
        self.generatetoaddress(node, 101, rpc_target, sync_fun=self.no_op)
        self.generatetoaddress(node, 101, cli_target, sync_fun=self.no_op)
        self.sync_blocks()
        self._sync_mocktime_to_tip()

        self.log.info("Checking miner work RPC for a non-whitelisted PoW target")
        rpc_quantum = wallet.getnewquantumaddress()["address"]
        work = node.getshadowpowwork(rpc_target, rpc_quantum)
        assert_equal(work["active"], True)
        assert_equal(work["prefix"], "QQSPROOF")
        assert "target_whitelisted" not in work
        assert "target_script" in work
        assert_equal(work["quantum_address"], rpc_quantum)
        assert_equal(work["quantum_payout_script"], node.validateaddress(rpc_quantum)["scriptPubKey"])

        legacy_payout = wallet.getnewaddress("", "legacy")
        assert_raises_rpc_error(-5, "quantum_address must be a Blackcoin migration address", node.getshadowpowwork, rpc_target, legacy_payout)
        assert_raises_rpc_error(-5, "quantum_address must be a Blackcoin migration address", wallet.sendshadowpowclaim, rpc_target, legacy_payout, 1)

        help_text = node.help("getshadowpowwork")
        assert "not whitelist-gated" in help_text
        assert "target_whitelisted" not in help_text
        assert "quantum_payout_script" in help_text

        wallet_help = wallet.help("sendshadowpowclaim")
        assert "PoW claims are NOT whitelist-gated" in wallet_help
        assert "Quantum migration address" in wallet_help
        assert "proof" in wallet_help

        self.log.info("Rejecting invalid built-in PoW miner configuration")
        assert_raises_rpc_error(-4, "threads must be between 1 and 256", wallet.setpowmining, True, 0, 10)
        assert_raises_rpc_error(-4, "cpu_percent must be between 1 and 100", wallet.setpowmining, True, 1, 101)
        assert_equal(wallet.getpowmininginfo()["enabled"], False)

        self._assert_builtin_pow_miner_lifecycle()

        self.disconnect_nodes(0, 1)

        self.log.info("Broadcasting non-whitelisted PoW claim via RPC")
        stale_claim = wallet.sendshadowpowclaim(rpc_target, rpc_quantum, 200000)
        assert_equal(stale_claim["address"], rpc_target)
        assert_equal(stale_claim["quantum_address"], rpc_quantum)
        assert_equal(stale_claim["external_proof"], False)
        assert stale_claim["proof"].startswith(QQSPROOF_HEX)
        assert stale_claim["txid"] in node.getrawmempool()
        rpc_decoded = node.decoderawtransaction(stale_claim["hex"])
        assert any(QQSPROOF_HEX in vout["scriptPubKey"]["hex"] for vout in rpc_decoded["vout"])
        assert all(vout["scriptPubKey"].get("address") != rpc_quantum for vout in rpc_decoded["vout"] if "scriptPubKey" in vout)
        proof_mismatch_error = "proof does not match the current tip, target address, and quantum payout address"
        assert_raises_rpc_error(-8, proof_mismatch_error, wallet.sendshadowpowclaim, rpc_target, rpc_quantum, 1, None, QQSPROOF_HEX + "00")
        stolen_quantum = wallet.getnewquantumaddress()["address"]
        assert_raises_rpc_error(-8, proof_mismatch_error, wallet.sendshadowpowclaim, rpc_target, stolen_quantum, 1, None, stale_claim["proof"])
        assert_raises_rpc_error(-26, "shadow-proof-mempool-conflict", wallet.sendshadowpowclaim, rpc_target, rpc_quantum, 1, None, stale_claim["proof"])

        self.log.info("Expiring unmined next-block-only PoW claims when the tip advances")
        stale_parent = node.getbestblockhash()
        self.generatetoaddress(self.nodes[1], 3, self.nodes[1].get_deterministic_priv_key().address, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert node.getbestblockhash() != stale_parent
        self.wait_until(lambda: stale_claim["txid"] not in node.getrawmempool(), timeout=10)
        stale_accept = node.testmempoolaccept([stale_claim["hex"]])[0]
        assert_equal(stale_accept["allowed"], False)
        assert_equal(stale_accept["reject-reason"], "shadow-proof-invalid")

        if self.is_cli_compiled():
            self.log.info("Checking miner work and broadcasting non-whitelisted PoW claim via CLI")
            cli_quantum = wallet.getnewquantumaddress()["address"]
            cli_work = node.cli.getshadowpowwork(cli_target, cli_quantum)
            assert_equal(cli_work["prefix"], "QQSPROOF")
            assert "target_whitelisted" not in cli_work
            assert_equal(cli_work["quantum_address"], cli_quantum)
            assert_equal(cli_work["quantum_payout_script"], node.validateaddress(cli_quantum)["scriptPubKey"])

            cli_wallet = node.cli("-rpcwallet={}".format(wallet_name))
            cli_claim = cli_wallet.sendshadowpowclaim(cli_target, cli_quantum, 200000)
            assert_equal(cli_claim["address"], cli_target)
            assert_equal(cli_claim["quantum_address"], cli_quantum)
            assert_equal(cli_claim["external_proof"], False)
            assert cli_claim["proof"].startswith(QQSPROOF_HEX)
            assert cli_claim["txid"] in node.getrawmempool()

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Testing getgoldrushstate...")

        info = node.getgoldrushstate()
        assert "pow_amount" in info
        assert "pos_amount" in info
        assert "pow_count" in info
        assert "pos_count" in info
        assert "last_pow_height" in info
        assert "last_pos_height" in info
        assert "recent_count" in info
        assert "pow_target_bits" in info
        
        # Verify pow_target_bits is a valid positive integer
        assert isinstance(info["pow_target_bits"], int)
        assert info["pow_target_bits"] >= 0

        if self.is_wallet_compiled():
            self.log.info("Testing wallet getgoldrushinfo...")
            node.createwallet(wallet_name="goldrush")
            wallet_info = node.get_wallet_rpc("goldrush").getgoldrushinfo()
            assert "wallet_recent_solve_qualified" in wallet_info
            assert "wallet_scripts" in wallet_info
            assert "pow_amount" in wallet_info
            assert "pos_amount" in wallet_info

        self._assert_pow_claim_from_non_whitelisted_address()

        self.log.info("Tests successful!")

if __name__ == '__main__':
    GoldRushInfoTest().main()
