#!/usr/bin/env python3
# Copyright (c) 2017-2022 Blackcoin Core Developers
# Copyright (c) 2017-2022 Blackcoin More Developers
# Copyright (c) 2017-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test various command line arguments and configuration file parameters."""

import os
from pathlib import Path
import re
import sys
import tempfile
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework import util


class ConfArgsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False
        self.wallet_names = []
        self.disable_autoconnect = False

    def test_config_file_parser(self):
        self.log.info('Test config file parser')
        self.stop_node(0)

        # Check that startup fails if conf= is set in blackcoin.conf or in an included conf file
        bad_conf_file_path = self.nodes[0].datadir_path / "bitcoin_bad.conf"
        util.write_config(bad_conf_file_path, n=0, chain='', extra_config=f'conf=some.conf\n')
        conf_in_config_file_err = 'Error: Error reading configuration file: conf cannot be set in the configuration file; use includeconf= if you want to include additional config files'
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[f'-conf={bad_conf_file_path}'],
            expected_msg=conf_in_config_file_err,
        )
        inc_conf_file_path = self.nodes[0].datadir_path / 'include.conf'
        with open(self.nodes[0].datadir_path / 'blackcoin.conf', 'a', encoding='utf-8') as conf:
            conf.write(f'includeconf={inc_conf_file_path}\n')
        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('conf=some.conf\n')
        self.nodes[0].assert_start_raises_init_error(
            expected_msg=conf_in_config_file_err,
        )

        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Error parsing command line arguments: Invalid parameter -dash_cli=1',
            extra_args=['-dash_cli=1'],
        )
        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('dash_conf=1\n')

        with self.nodes[0].assert_debug_log(expected_msgs=['Ignoring unknown configuration value dash_conf']):
            self.start_node(0)
        self.stop_node(0)

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('reindex=1\n')

        with self.nodes[0].assert_debug_log(expected_msgs=['Warning: reindex=1 is set in the configuration file, which will significantly slow down startup. Consider removing or commenting out this option for better performance, unless there is currently a condition which makes rebuilding the indexes necessary']):
            self.start_node(0)
        self.stop_node(0)

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('-dash=1\n')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 1: -dash=1, options in configuration file must be specified without leading -')

        if self.is_wallet_compiled():
            with open(inc_conf_file_path, 'w', encoding='utf8') as conf:
                conf.write("wallet=foo\n")
            self.nodes[0].assert_start_raises_init_error(expected_msg=f'Error: Config setting for -wallet only applied on {self.chain} network when in [{self.chain}] section.')

        main_conf_file_path = self.nodes[0].datadir_path / "bitcoin_main.conf"
        util.write_config(main_conf_file_path, n=0, chain='', extra_config=f'includeconf={inc_conf_file_path}\n')
        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('acceptnonstdtxn=1\n')
        self.nodes[0].assert_start_raises_init_error(extra_args=[f"-conf={main_conf_file_path}", "-allowignoredconf"], expected_msg='Error: acceptnonstdtxn is not currently supported for main chain')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('nono\n')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 1: nono, if you intended to specify a negated option, use nono=1 instead')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\nrpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 3, using # in rpcpassword can be ambiguous and should be avoided')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\nmain.rpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 3, using # in rpcpassword can be ambiguous and should be avoided')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\n[main]\nrpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 4, using # in rpcpassword can be ambiguous and should be avoided')

        inc_conf_file2_path = self.nodes[0].datadir_path / 'include2.conf'
        with open(self.nodes[0].datadir_path / 'blackcoin.conf', 'a', encoding='utf-8') as conf:
            conf.write(f'includeconf={inc_conf_file2_path}\n')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('testnot.datadir=1\n')
        with open(inc_conf_file2_path, 'w', encoding='utf-8') as conf:
            conf.write('[testnet]\n')
        self.restart_node(0)
        self.nodes[0].stop_node(expected_stderr=f'Warning: {inc_conf_file_path}:1 Section [testnot] is not recognized.{os.linesep}{inc_conf_file2_path}:1 Section [testnet] is not recognized.')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('')  # clear
        with open(inc_conf_file2_path, 'w', encoding='utf-8') as conf:
            conf.write('')  # clear

    def test_config_file_log(self):
        # Disable this test for windows currently because trying to override
        # the default datadir through the environment does not seem to work.
        if sys.platform == "win32":
            return

        self.log.info('Test that correct configuration path is changed when configuration file changes the datadir')

        # Create a temporary directory that will be treated as the default data
        # directory by blackcoind.
        env, default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "test_config_file_log"))
        default_datadir.mkdir(parents=True)

        # Write a blackcoin.conf file in the default data directory containing a
        # datadir= line pointing at the node datadir.
        node = self.nodes[0]
        conf_text = node.bitcoinconf.read_text()
        conf_path = default_datadir / "blackcoin.conf"
        conf_path.write_text(f"datadir={node.datadir_path}\n{conf_text}")

        # Drop the node -datadir= argument during this test, because if it is
        # specified it would take precedence over the datadir setting in the
        # config file.
        node_args = node.args
        node.args = [arg for arg in node.args if not arg.startswith("-datadir=")]

        # Check that correct configuration file path is actually logged
        # (conf_path, not node.bitcoinconf)
        with self.nodes[0].assert_debug_log(expected_msgs=[f"Config file: {conf_path}"]):
            self.start_node(0, ["-allowignoredconf"], env=env)
            self.stop_node(0)

        # Restore node arguments after the test
        node.args = node_args

    def test_invalid_command_line_options(self):
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Error parsing command line arguments: Can not set -proxy with no value. Please specify value with -proxy=value.',
            extra_args=['-proxy'],
        )

    def test_log_buffer(self):
        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['Warning: parsed potentially confusing double-negative -connect=0\n']):
            self.start_node(0, extra_args=['-noconnect=0'])

    def test_args_log(self):
        self.stop_node(0)
        self.log.info('Test config args logging')
        with self.nodes[0].assert_debug_log(
                expected_msgs=[
                    'Command-line arg: addnode="some.node"',
                    'Command-line arg: rpcauth=****',
                    'Command-line arg: rpcpassword=****',
                    'Command-line arg: rpcuser=****',
                    'Command-line arg: torpassword=****',
                    f'Config file arg: {self.chain}="1"',
                    f'Config file arg: [{self.chain}] server="1"',
                ],
                unexpected_msgs=[
                    'alice:f7efda5c189b999524f151318c0c86$d5b51b3beffbc0',
                    'secret-rpcuser',
                    'secret-torpassword',
                    'Command-line arg: rpcbind=****',
                    'Command-line arg: rpcallowip=****',
                ]):
            self.start_node(0, extra_args=[
                '-addnode=some.node',
                '-rpcauth=alice:f7efda5c189b999524f151318c0c86$d5b51b3beffbc0',
                '-rpcbind=127.1.1.1',
                '-rpcbind=127.0.0.1',
                "-rpcallowip=127.0.0.1",
                '-rpcpassword=',
                '-rpcuser=secret-rpcuser',
                '-torpassword=secret-torpassword',
            ])

    def test_networkactive(self):
        self.log.info('Test -networkactive option')
        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0)

        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0, extra_args=['-networkactive'])

        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0, extra_args=['-networkactive=1'])

        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-networkactive=0'])

        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-nonetworkactive'])

        self.stop_node(0)
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-nonetworkactive=1'])

    def test_seed_peers(self):
        self.log.info('Test seed peers')
        default_data_dir = self.nodes[0].datadir_path
        peer_dat = default_data_dir / 'peers.dat'
        # Only regtest has no fixed seeds. To avoid connections to random
        # nodes, regtest is the only network where it is safe to enable
        # -fixedseeds in tests
        util.assert_equal(self.nodes[0].getblockchaininfo()['chain'],'regtest')
        self.stop_node(0)

        # No peers.dat exists and -dnsseed=1
        # We expect the node will use DNS Seeds, but Regtest mode does not have
        # any valid DNS seeds. So after 60 seconds, the node should fallback to
        # fixed seeds
        assert not peer_dat.exists()
        start = int(time.time())
        with self.nodes[0].assert_debug_log(
                expected_msgs=[
                    "Loaded 0 addresses from peers.dat",
                    "0 addresses found from DNS seeds",
                    "opencon thread start",  # Ensure ThreadOpenConnections::start time is properly set
                ],
                timeout=10,
        ):
            self.start_node(0, extra_args=['-dnsseed=1', '-fixedseeds=1', f'-mocktime={start}'])
        with self.nodes[0].assert_debug_log(expected_msgs=[
                "Adding fixed seeds as 60 seconds have passed and addrman is empty",
        ]):
            self.nodes[0].setmocktime(start + 65)
        self.nodes[0].setmocktime(0)
        self.stop_node(0)

        # No peers.dat exists and -dnsseed=0
        # We expect the node will fallback immediately to fixed seeds
        assert not peer_dat.exists()
        with self.nodes[0].assert_debug_log(expected_msgs=[
                "Loaded 0 addresses from peers.dat",
                "DNS seeding disabled",
                "Adding fixed seeds as -dnsseed=0 (or IPv4/IPv6 connections are disabled via -onlynet) and neither -addnode nor -seednode are provided",
        ]):
            self.start_node(0, extra_args=['-dnsseed=0', '-fixedseeds=1'])
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(['-dnsseed=1', '-onlynet=i2p', '-i2psam=127.0.0.1:7656'], "Error: Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")

        # No peers.dat exists and dns seeds are disabled.
        # We expect the node will not add fixed seeds when explicitly disabled.
        assert not peer_dat.exists()
        with self.nodes[0].assert_debug_log(expected_msgs=[
                "Loaded 0 addresses from peers.dat",
                "DNS seeding disabled",
                "Fixed seeds are disabled",
        ]):
            self.start_node(0, extra_args=['-dnsseed=0', '-fixedseeds=0'])
        self.stop_node(0)

        # No peers.dat exists and -dnsseed=0, but a -addnode is provided
        # We expect the node will allow 60 seconds prior to using fixed seeds
        assert not peer_dat.exists()
        start = int(time.time())
        with self.nodes[0].assert_debug_log(
                expected_msgs=[
                    "Loaded 0 addresses from peers.dat",
                    "DNS seeding disabled",
                    "opencon thread start",  # Ensure ThreadOpenConnections::start time is properly set
                ],
                timeout=10,
        ):
            self.start_node(0, extra_args=['-dnsseed=0', '-fixedseeds=1', '-addnode=fakenodeaddr', f'-mocktime={start}'])
        with self.nodes[0].assert_debug_log(expected_msgs=[
                "Adding fixed seeds as 60 seconds have passed and addrman is empty",
        ]):
            self.nodes[0].setmocktime(start + 65)
        self.nodes[0].setmocktime(0)

    def test_connect_with_seednode(self):
        self.log.info('Test -connect with -seednode')
        seednode_ignored = ['-seednode is ignored when -connect is used\n']
        dnsseed_ignored = ['-dnsseed is ignored when -connect is used and -proxy is specified\n']
        addcon_thread_started = ['addcon thread start\n']
        self.stop_node(0)

        # When -connect is supplied, expanding addrman via getaddr calls to ADDR_FETCH(-seednode)
        # nodes is irrelevant and -seednode is ignored.
        with self.nodes[0].assert_debug_log(expected_msgs=seednode_ignored):
            self.start_node(0, extra_args=['-connect=fakeaddress1', '-seednode=fakeaddress2'])

        # With -proxy, an ADDR_FETCH connection is made to a peer that the dns seed resolves to.
        # ADDR_FETCH connections are not used when -connect is used.
        with self.nodes[0].assert_debug_log(expected_msgs=dnsseed_ignored):
            self.restart_node(0, extra_args=['-connect=fakeaddress1', '-dnsseed=1', '-proxy=1.2.3.4'])

        # If the user did not disable -dnsseed, but it was soft-disabled because they provided -connect,
        # they shouldn't see a warning about -dnsseed being ignored.
        with self.nodes[0].assert_debug_log(expected_msgs=addcon_thread_started,
                unexpected_msgs=dnsseed_ignored):
            self.restart_node(0, extra_args=['-connect=fakeaddress1', '-proxy=1.2.3.4'])

        # We have to supply expected_msgs as it's a required argument
        # The expected_msg must be something we are confident will be logged after the unexpected_msg
        # These cases test for -connect being supplied but only to disable it
        for connect_arg in ['-connect=0', '-noconnect']:
            with self.nodes[0].assert_debug_log(expected_msgs=addcon_thread_started,
                    unexpected_msgs=seednode_ignored):
                self.restart_node(0, extra_args=[connect_arg, '-seednode=fakeaddress2'])

    def test_ignored_conf(self):
        self.log.info('Test error is triggered when the datadir in use contains a blackcoin.conf file that would be ignored '
                      'because a conflicting -conf file argument is passed.')
        node = self.nodes[0]
        with tempfile.NamedTemporaryFile(dir=self.options.tmpdir, mode="wt", delete=False) as temp_conf:
            temp_conf.write(f"datadir={node.datadir_path}\n")
        node.assert_start_raises_init_error([f"-conf={temp_conf.name}"], re.escape(
            f'Error: Data directory "{node.datadir_path}" contains a "blackcoin.conf" file which is ignored, because a '
            f'different configuration file "{temp_conf.name}" from command line argument "-conf={temp_conf.name}" '
            f'is being used instead.') + r"[\s\S]*", match=ErrorMatch.FULL_REGEX)

        # Test that passing a redundant -conf command line argument pointing to
        # the same blackcoin.conf that would be loaded anyway does not trigger an
        # error.
        self.start_node(0, [f'-conf={node.datadir_path}/blackcoin.conf'])
        self.stop_node(0)

    def test_ignored_default_conf(self):
        # Disable this test for windows currently because trying to override
        # the default datadir through the environment does not seem to work.
        if sys.platform == "win32":
            return

        self.log.info('Test error is triggered when blackcoin.conf in the default data directory sets another datadir '
                      'and it contains a different blackcoin.conf file that would be ignored')

        # Create a temporary directory that will be treated as the default data
        # directory by blackcoind.
        env, default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "home"))
        default_datadir.mkdir(parents=True)

        # Write a blackcoin.conf file in the default data directory containing a
        # datadir= line pointing at the node datadir. This will trigger a
        # startup error because the node datadir contains a different
        # blackcoin.conf that would be ignored.
        node = self.nodes[0]
        (default_datadir / "blackcoin.conf").write_text(f"datadir={node.datadir_path}\n")

        # Drop the node -datadir= argument during this test, because if it is
        # specified it would take precedence over the datadir setting in the
        # config file.
        node_args = node.args
        node.args = [arg for arg in node.args if not arg.startswith("-datadir=")]
        node.assert_start_raises_init_error([], re.escape(
            f'Error: Data directory "{node.datadir_path}" contains a "blackcoin.conf" file which is ignored, because a '
            f'different configuration file "{default_datadir}/blackcoin.conf" from data directory "{default_datadir}" '
            f'is being used instead.') + r"[\s\S]*", env=env, match=ErrorMatch.FULL_REGEX)
        node.args = node_args

    def _legacy_datadir_for_env(self, env):
        if sys.platform == "win32":
            return Path(env["APPDATA"]) / "Blackmore"
        return Path(env["HOME"]) / ".blackmore"

    def _write_legacy_datadir(self, legacy_datadir, *, conf_name="blackmore.conf", wallet_text="legacy wallet\n"):
        legacy_datadir.mkdir(parents=True)
        util.write_config(legacy_datadir / conf_name, n=0, chain=self.chain, disable_autoconnect=self.disable_autoconnect)
        (legacy_datadir / "wallet.dat").write_text(wallet_text, encoding="utf8")
        (legacy_datadir / "blocks").mkdir()

    def _migration_marker(self, datadir):
        return datadir / ".blackcoin-migration-done"

    def _migration_backup_root(self, datadir):
        return datadir.parent / f"{datadir.name}.backup"

    def _backup_dirs(self, datadir, prefix):
        backup_root = self._migration_backup_root(datadir)
        if not backup_root.exists():
            return []
        return sorted(backup_root.glob(f"{prefix}-*"))

    def _assert_backup_wallet(self, datadir, prefix, wallet_text):
        backups = self._backup_dirs(datadir, prefix)
        assert backups, f"missing {prefix} backup under {self._migration_backup_root(datadir)}"
        assert any((backup / "wallet.dat").exists() and (backup / "wallet.dat").read_text(encoding="utf8") == wallet_text for backup in backups)

    def _default_datadir_args(self, node):
        chain_arg = "-regtest" if self.chain == "regtest" else f"-chain={self.chain}"
        return [
            chain_arg,
            f"-port={util.p2p_port(node.index)}",
            f"-rpcport={util.rpc_port(node.index)}",
            "-server=1",
            "-connect=0",
            "-discover=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-listen=0",
            "-listenonion=0",
            "-natpmp=0",
            "-upnp=0",
            "-rpcdoccheck=1",
            "-rpcservertimeout=99000",
            "-keypool=1",
        ]

    def _stop_node_if_started(self, node):
        if not node.running:
            return
        if node.rpc_connected:
            self.stop_node(0)
            return
        if node.process is not None and node.process.poll() is None:
            node.process.kill()
            node.process.wait(timeout=node.rpc_timeout)
        node.running = False
        node.process = None

    def _run_default_datadir_node_once(self, node, env, default_datadir, extra_args=None):
        original_args = node.args
        original_datadir = node.datadir_path
        original_bitcoinconf = node.bitcoinconf
        try:
            node.args = [arg for arg in node.args if not arg.startswith("-datadir=")]
            node.datadir_path = default_datadir
            node.bitcoinconf = default_datadir / "blackcoin.conf"
            self.start_node(0, self._default_datadir_args(node) + (extra_args or []), env=env)
            self.stop_node(0)
        finally:
            self._stop_node_if_started(node)
            node.args = original_args
            node.datadir_path = original_datadir
            node.bitcoinconf = original_bitcoinconf

    def _assert_default_datadir_start_error(self, node, env, default_datadir, expected_msg, extra_args=None):
        original_args = node.args
        original_datadir = node.datadir_path
        original_bitcoinconf = node.bitcoinconf
        try:
            node.args = [arg for arg in node.args if not arg.startswith("-datadir=")]
            node.datadir_path = default_datadir
            node.bitcoinconf = default_datadir / "blackcoin.conf"
            node.assert_start_raises_init_error(
                extra_args=self._default_datadir_args(node) + (extra_args or []),
                expected_msg=expected_msg,
                match=ErrorMatch.PARTIAL_REGEX,
                env=env,
            )
        finally:
            self._stop_node_if_started(node)
            node.args = original_args
            node.datadir_path = original_datadir
            node.bitcoinconf = original_bitcoinconf

    def test_legacy_datadir_migration(self):
        # Disable this test for windows currently because trying to override
        # the default datadir through the environment does not seem to work.
        if sys.platform == "win32":
            return

        node = self.nodes[0]

        self.log.info("Test .blackmore-only first-run migration imports into .blackcoin and preserves a backup")
        env, default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_home"))
        legacy_datadir = self._legacy_datadir_for_env(env)
        self._write_legacy_datadir(legacy_datadir, wallet_text="blackmore wallet\n")

        original_args = node.args
        original_datadir = node.datadir_path
        original_bitcoinconf = node.bitcoinconf

        try:
            node.args = [arg for arg in node.args if not arg.startswith("-datadir=")]
            node.datadir_path = default_datadir
            node.bitcoinconf = default_datadir / "blackcoin.conf"
            self.start_node(0, env=env)
            self.stop_node(0)

            assert (default_datadir / "blackmore.conf").exists()
            assert (default_datadir / "blackcoin.conf").exists()
            assert_equal((default_datadir / "blackcoin.conf").read_text(encoding="utf8"), (legacy_datadir / "blackmore.conf").read_text(encoding="utf8"))
            assert_equal((default_datadir / "wallet.dat").read_text(encoding="utf8"), "blackmore wallet\n")
            assert (default_datadir / "blocks").is_dir()
            assert self._migration_marker(default_datadir).exists()
            self._assert_backup_wallet(default_datadir, "blackmore", "blackmore wallet\n")

            backup_count = len(self._backup_dirs(default_datadir, "blackmore"))
            self.start_node(0, env=env)
            self.stop_node(0)
            assert_equal(len(self._backup_dirs(default_datadir, "blackmore")), backup_count)
        finally:
            self._stop_node_if_started(node)
            node.args = original_args
            node.datadir_path = original_datadir
            node.bitcoinconf = original_bitcoinconf

        self.log.info("Test original .blackcoin-only first-run migration keeps the active wallet and preserves a backup")
        blackcoin_env, blackcoin_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_blackcoin_home"))
        self._write_legacy_datadir(blackcoin_default_datadir, conf_name="blackcoin.conf", wallet_text="original blackcoin wallet\n")
        self._run_default_datadir_node_once(node, blackcoin_env, blackcoin_default_datadir)
        assert_equal((blackcoin_default_datadir / "wallet.dat").read_text(encoding="utf8"), "original blackcoin wallet\n")
        assert self._migration_marker(blackcoin_default_datadir).exists()
        self._assert_backup_wallet(blackcoin_default_datadir, "original-blackcoin", "original blackcoin wallet\n")

        self.log.info("Test dual legacy datadirs with explicit .blackmore selection preserves both and activates .blackmore")
        dual_env, dual_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_dual_home"))
        dual_blackmore_datadir = self._legacy_datadir_for_env(dual_env)
        self._write_legacy_datadir(dual_default_datadir, conf_name="blackcoin.conf", wallet_text="dual original wallet\n")
        self._write_legacy_datadir(dual_blackmore_datadir, wallet_text="dual blackmore wallet\n")
        self._run_default_datadir_node_once(node, dual_env, dual_default_datadir, extra_args=["-migratewallet=blackmore"])
        assert_equal((dual_default_datadir / "wallet.dat").read_text(encoding="utf8"), "dual blackmore wallet\n")
        assert self._migration_marker(dual_default_datadir).exists()
        self._assert_backup_wallet(dual_default_datadir, "original-blackcoin", "dual original wallet\n")
        self._assert_backup_wallet(dual_default_datadir, "active-blackcoin", "dual original wallet\n")
        self._assert_backup_wallet(dual_default_datadir, "blackmore", "dual blackmore wallet\n")

        self.log.info("Test dual legacy datadirs with no flag keeps .blackcoin and preserves .blackmore")
        dual_auto_env, dual_auto_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_dual_auto_home"))
        dual_auto_blackmore_datadir = self._legacy_datadir_for_env(dual_auto_env)
        self._write_legacy_datadir(dual_auto_default_datadir, conf_name="blackcoin.conf", wallet_text="auto original wallet\n")
        self._write_legacy_datadir(dual_auto_blackmore_datadir, wallet_text="auto blackmore wallet\n")
        self._run_default_datadir_node_once(node, dual_auto_env, dual_auto_default_datadir)
        assert_equal((dual_auto_default_datadir / "wallet.dat").read_text(encoding="utf8"), "auto original wallet\n")
        assert self._migration_marker(dual_auto_default_datadir).exists()
        self._assert_backup_wallet(dual_auto_default_datadir, "original-blackcoin", "auto original wallet\n")
        self._assert_backup_wallet(dual_auto_default_datadir, "blackmore", "auto blackmore wallet\n")
        assert_equal(len(self._backup_dirs(dual_auto_default_datadir, "active-blackcoin")), 0)

        self.log.info("Test marker-absent rerun does not displace a populated live .blackcoin")
        self._migration_marker(dual_auto_default_datadir).unlink()
        self._run_default_datadir_node_once(node, dual_auto_env, dual_auto_default_datadir)
        assert_equal((dual_auto_default_datadir / "wallet.dat").read_text(encoding="utf8"), "auto original wallet\n")
        assert self._migration_marker(dual_auto_default_datadir).exists()
        assert_equal(len(self._backup_dirs(dual_auto_default_datadir, "active-blackcoin")), 0)

        self.log.info("Test dual legacy datadirs with explicit .blackcoin selection keeps the active .blackcoin wallet")
        dual_keep_env, dual_keep_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_dual_keep_home"))
        dual_keep_blackmore_datadir = self._legacy_datadir_for_env(dual_keep_env)
        self._write_legacy_datadir(dual_keep_default_datadir, conf_name="blackcoin.conf", wallet_text="keep original wallet\n")
        self._write_legacy_datadir(dual_keep_blackmore_datadir, wallet_text="keep blackmore wallet\n")
        self._run_default_datadir_node_once(node, dual_keep_env, dual_keep_default_datadir, extra_args=["-migratewallet=blackcoin"])
        assert_equal((dual_keep_default_datadir / "wallet.dat").read_text(encoding="utf8"), "keep original wallet\n")
        assert self._migration_marker(dual_keep_default_datadir).exists()
        self._assert_backup_wallet(dual_keep_default_datadir, "original-blackcoin", "keep original wallet\n")
        self._assert_backup_wallet(dual_keep_default_datadir, "blackmore", "keep blackmore wallet\n")

        self.log.info("Test interrupted .blackmore swap restores the original .blackcoin on next run")
        crash_env, crash_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_crash_home"))
        crash_blackmore_datadir = self._legacy_datadir_for_env(crash_env)
        self._write_legacy_datadir(crash_blackmore_datadir, wallet_text="crash blackmore wallet\n")
        crash_backup_root = self._migration_backup_root(crash_default_datadir)
        crash_active_backup = crash_backup_root / "active-blackcoin-999999999"
        self._write_legacy_datadir(crash_active_backup, conf_name="blackcoin.conf", wallet_text="crash original wallet\n")
        (crash_backup_root / ".blackcoin-migration-recovery").write_text(f"{crash_active_backup}\n", encoding="utf8")
        self._run_default_datadir_node_once(node, crash_env, crash_default_datadir)
        assert_equal((crash_default_datadir / "wallet.dat").read_text(encoding="utf8"), "crash original wallet\n")
        assert self._migration_marker(crash_default_datadir).exists()
        assert crash_active_backup.exists()
        assert_equal((crash_active_backup / "wallet.dat").read_text(encoding="utf8"), "crash original wallet\n")
        assert not (crash_backup_root / ".blackcoin-migration-recovery").exists()

        self.log.info("Test stale active backup without recovery record is not auto-restored")
        stale_env, stale_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_stale_active_home"))
        stale_backup_root = self._migration_backup_root(stale_default_datadir)
        stale_active_backup = stale_backup_root / "active-blackcoin-111111111"
        self._write_legacy_datadir(stale_active_backup, conf_name="blackcoin.conf", wallet_text="stale active backup wallet\n")
        self._run_default_datadir_node_once(node, stale_env, stale_default_datadir)
        assert not (stale_default_datadir / "wallet.dat").exists()
        assert not self._migration_marker(stale_default_datadir).exists()
        assert stale_active_backup.exists()
        assert_equal((stale_active_backup / "wallet.dat").read_text(encoding="utf8"), "stale active backup wallet\n")

        self.log.info("Test symlinked legacy source root resolves to the real datadir and migrates safely")
        symlink_env, symlink_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_symlink_home"))
        real_blackmore_datadir = Path(self.options.tmpdir, "legacy_migration_real_blackmore")
        symlink_blackmore_datadir = self._legacy_datadir_for_env(symlink_env)
        self._write_legacy_datadir(real_blackmore_datadir, wallet_text="symlink blackmore wallet\n")
        symlink_blackmore_datadir.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(real_blackmore_datadir, symlink_blackmore_datadir, target_is_directory=True)
        self._run_default_datadir_node_once(node, symlink_env, symlink_default_datadir)
        assert_equal((symlink_default_datadir / "wallet.dat").read_text(encoding="utf8"), "symlink blackmore wallet\n")
        assert self._migration_marker(symlink_default_datadir).exists()
        self._assert_backup_wallet(symlink_default_datadir, "blackmore", "symlink blackmore wallet\n")
        assert_equal((real_blackmore_datadir / "wallet.dat").read_text(encoding="utf8"), "symlink blackmore wallet\n")

        self.log.info("Test fresh first run does not create migration backup state")
        fresh_env, fresh_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_fresh_home"))
        self._run_default_datadir_node_once(node, fresh_env, fresh_default_datadir)
        assert fresh_default_datadir.exists()
        assert not self._migration_marker(fresh_default_datadir).exists()
        assert not self._migration_backup_root(fresh_default_datadir).exists()

        self.log.info("Test .blackmore import when the GUI already created an empty .blackcoin datadir")
        # The Qt data-directory chooser (Intro) creates the destination datadir
        # before first-run migration runs, so importing a Blackmore datadir must
        # succeed even though the destination directory already exists empty.
        empty_env, empty_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_empty_dest_home"))
        empty_blackmore_datadir = self._legacy_datadir_for_env(empty_env)
        # A minimal Blackmore datadir: wallet.dat and config only, no blocks.
        empty_blackmore_datadir.mkdir(parents=True)
        util.write_config(empty_blackmore_datadir / "blackmore.conf", n=0, chain=self.chain, disable_autoconnect=self.disable_autoconnect)
        (empty_blackmore_datadir / "wallet.dat").write_text("empty-dest blackmore wallet\n", encoding="utf8")
        empty_default_datadir.mkdir(parents=True)  # simulate the GUI Intro pre-creating the datadir
        self._run_default_datadir_node_once(node, empty_env, empty_default_datadir)
        assert_equal((empty_default_datadir / "wallet.dat").read_text(encoding="utf8"), "empty-dest blackmore wallet\n")
        assert (empty_default_datadir / "blackcoin.conf").exists()
        assert self._migration_marker(empty_default_datadir).exists()
        self._assert_backup_wallet(empty_default_datadir, "blackmore", "empty-dest blackmore wallet\n")

        self.log.info("Test .blackmore import when the pre-existing .blackcoin datadir holds only a stale lock file")
        lock_env, lock_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_lock_dest_home"))
        lock_blackmore_datadir = self._legacy_datadir_for_env(lock_env)
        lock_blackmore_datadir.mkdir(parents=True)
        util.write_config(lock_blackmore_datadir / "blackmore.conf", n=0, chain=self.chain, disable_autoconnect=self.disable_autoconnect)
        (lock_blackmore_datadir / "wallet.dat").write_text("lock-dest blackmore wallet\n", encoding="utf8")
        lock_default_datadir.mkdir(parents=True)
        (lock_default_datadir / ".lock").write_text("", encoding="utf8")  # a crashed prior run leaves this behind
        self._run_default_datadir_node_once(node, lock_env, lock_default_datadir)
        assert_equal((lock_default_datadir / "wallet.dat").read_text(encoding="utf8"), "lock-dest blackmore wallet\n")
        assert self._migration_marker(lock_default_datadir).exists()
        # The non-wallet contents were preserved in a backup rather than deleted.
        assert self._backup_dirs(lock_default_datadir, "preexisting-blackcoin")

        self.log.info("Test existing migration marker makes startup a no-op")
        marked_env, marked_default_datadir = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_marked_home"))
        marked_blackmore_datadir = self._legacy_datadir_for_env(marked_env)
        marked_default_datadir.mkdir(parents=True)
        self._migration_marker(marked_default_datadir).write_text("already migrated\n", encoding="utf8")
        self._write_legacy_datadir(marked_blackmore_datadir, wallet_text="ignored blackmore wallet\n")
        self._run_default_datadir_node_once(node, marked_env, marked_default_datadir)
        assert self._migration_marker(marked_default_datadir).exists()
        assert not (marked_default_datadir / "wallet.dat").exists()
        assert not self._migration_backup_root(marked_default_datadir).exists()

        self.log.info("Test explicit -datadir disables legacy datadir migration")
        skip_env, _ = util.get_temp_default_datadir(Path(self.options.tmpdir, "legacy_migration_skip_home"))
        skip_legacy_datadir = self._legacy_datadir_for_env(skip_env)
        self._write_legacy_datadir(skip_legacy_datadir)
        explicit_datadir = Path(self.options.tmpdir, "legacy_migration_explicit_datadir")
        explicit_datadir.mkdir()
        util.write_config(explicit_datadir / "blackcoin.conf", n=0, chain=self.chain, disable_autoconnect=self.disable_autoconnect)

        try:
            node.args = [
                f"-datadir={explicit_datadir}" if arg.startswith("-datadir=") else arg
                for arg in node.args
            ]
            node.datadir_path = explicit_datadir
            node.bitcoinconf = explicit_datadir / "blackcoin.conf"
            self.start_node(0, env=skip_env)
            self.stop_node(0)
            assert not (explicit_datadir / "blackmore.conf").exists()
            assert not (explicit_datadir / "wallet.dat").exists()
            assert not (explicit_datadir / "blocks").exists()
        finally:
            self._stop_node_if_started(node)
            node.args = original_args
            node.datadir_path = original_datadir
            node.bitcoinconf = original_bitcoinconf

    def test_acceptstalefeeestimates_arg_support(self):
        self.log.info("Test -acceptstalefeeestimates option support")
        self.nodes[0].assert_start_raises_init_error(
            extra_args=['-acceptstalefeeestimates=1'],
            expected_msg='Error: Error parsing command line arguments: Invalid parameter -acceptstalefeeestimates=1',
        )

    def test_powmining_arg_ranges(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping -powmining argument checks: wallet not compiled")
            return
        self.log.info("Test -powmining startup argument ranges")
        self.nodes[0].assert_start_raises_init_error(
            extra_args=['-powmining=1', '-powminingthreads=0'],
            expected_msg='Error: -powminingthreads must be between 1 and 256.',
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=['-powminingthreads=257'],
            expected_msg='Error: -powminingthreads must be between 1 and 256.',
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=['-powmining=1', '-powminingcpu=0'],
            expected_msg='Error: -powminingcpu must be between 1 and 100.',
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=['-powminingcpu=101'],
            expected_msg='Error: -powminingcpu must be between 1 and 100.',
        )

    def run_test(self):
        self.test_log_buffer()
        self.test_args_log()
        self.test_seed_peers()
        self.test_networkactive()
        self.test_connect_with_seednode()

        self.test_config_file_parser()
        self.test_config_file_log()
        self.test_invalid_command_line_options()
        self.test_ignored_conf()
        self.test_ignored_default_conf()
        self.test_legacy_datadir_migration()
        self.test_acceptstalefeeestimates_arg_support()
        self.test_powmining_arg_ranges()

        # Remove the -datadir argument so it doesn't override the config file
        self.nodes[0].args = [arg for arg in self.nodes[0].args if not arg.startswith("-datadir")]

        default_data_dir = self.nodes[0].datadir_path
        new_data_dir = default_data_dir / 'newdatadir'
        new_data_dir_2 = default_data_dir / 'newdatadir2'

        # Check that using -datadir argument on non-existent directory fails
        self.nodes[0].datadir_path = new_data_dir
        self.nodes[0].assert_start_raises_init_error([f'-datadir={new_data_dir}'], f'Error: Specified data directory "{new_data_dir}" does not exist.')

        # Check that using non-existent datadir in conf file fails
        conf_file = default_data_dir / "blackcoin.conf"

        # datadir needs to be set before [chain] section
        with open(conf_file, encoding='utf8') as f:
            conf_file_contents = f.read()
        with open(conf_file, 'w', encoding='utf8') as f:
            f.write(f"datadir={new_data_dir}\n")
            f.write(conf_file_contents)

        self.nodes[0].assert_start_raises_init_error([f'-conf={conf_file}'], f'Error: Error reading configuration file: specified data directory "{new_data_dir}" does not exist.')

        # Check that an explicitly specified config file that cannot be opened fails
        none_existent_conf_file = default_data_dir / "none_existent_blackcoin.conf"
        self.nodes[0].assert_start_raises_init_error(['-conf=' + f'{none_existent_conf_file}'], 'Error: Error reading configuration file: specified config file "' + f'{none_existent_conf_file}' + '" could not be opened.')

        # Create the directory and ensure the config file now works
        new_data_dir.mkdir()
        self.start_node(0, [f'-conf={conf_file}'])
        self.stop_node(0)
        assert (new_data_dir / self.chain / 'blocks').exists()

        # Ensure command line argument overrides datadir in conf
        new_data_dir_2.mkdir()
        self.nodes[0].datadir_path = new_data_dir_2
        self.start_node(0, [f'-datadir={new_data_dir_2}', f'-conf={conf_file}'])
        assert (new_data_dir_2 / self.chain / 'blocks').exists()


if __name__ == '__main__':
    ConfArgsTest().main()
