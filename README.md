# Blackcoin

This repository contains the Protocol V4 upgrade for Blackcoin. It keeps the
legacy chain history and migration path while adding the Quantum Quasar V4
feature set for the PoSV4.0 upgrade release.

## Current Upgrade Scope

- Gold Rush reward accounting through the legacy-compatible Shadow Network
  ledger.
- Quantum migration addresses backed by ML-DSA keys.
- Legacy-to-quantum wallet migration RPCs.
- EUTXO and RGB commitment primitives and raw transaction tooling.
- Blackcoin daemon, CLI, wallet, and Qt binary naming.
- Copy-only migration from legacy Blackcoin data directories used by prior
  nodes.

## Upgrade Overview

Read [doc/upgrade-v4.md](doc/upgrade-v4.md) for the public V4 transition
overview, including the Gold Rush timeline, quantum address migration, staking
changes, and first-run data-directory migration.

On first run without `-datadir` or `-conf`, `blackcoind` and `blackcoin-qt`
look for a legacy `~/.blackmore` data directory. If it is the only legacy data
directory, the node copies it to `~/.blackcoin`, converts `blackmore.conf` to
`blackcoin.conf`, leaves the original intact, and writes a migration marker. If
both `.blackcoin` and `.blackmore` exist, the GUI prompts the user and headless
startup safely keeps `.blackcoin` unless `-migratewallet=blackmore` is supplied.
Migration failures abort startup rather than creating or loading the wrong
wallet. Operators should make sure there is enough free disk space for a full
copy of the selected legacy directory and its backup.

The staking model includes quantum cold-stake principal preservation,
stake-reward splitting between delegator and operator, tiered staking weights,
autonomous redelegation, and a wallet/policy per-pool cap used to steer new
delegations without changing consensus.

Legacy Blackcoin operators should read [TRANSITION_GUIDE.md](TRANSITION_GUIDE.md)
before testing this fork.

## Build

Protocol V4 consensus requires liboqs 0.15.0 for ML-DSA quantum
signatures. Release builds must use the pinned dependency tree:

```bash
make -C depends
./autogen.sh
./configure --prefix="$PWD/depends/$(./depends/config.guess)"
make -j8
```

For local development only, an exact-version host liboqs can be used instead:

```bash
./autogen.sh
./configure --with-system-liboqs
make -j8
```

Useful targets:

```bash
make -j8 -C src test/test_blackcoin
./src/test/test_blackcoin
```

The primary binaries are:

- `src/blackcoind`
- `src/blackcoin-cli`
- `src/blackcoin-wallet`
- `src/qt/blackcoin-qt`

## Test

Run the focused Blackcoin checks:

```bash
./src/test/test_blackcoin --run_test=shadow_tests,blackcoin_tests --catch_system_errors=no
python3 test/functional/feature_blackcoin_phase.py
python3 test/functional/rpc_goldrushinfo.py
python3 test/functional/rpc_rgb.py
```

Run the full functional suite with:

```bash
python3 test/functional/test_runner.py
```

## Development Notes

This repository still contains legacy Blackcoin compatibility names in places
where they are protocol, URI, historical, migration, or test-framework
compatible. New user-facing Blackcoin code should use the Blackcoin
daemon, CLI, wallet, and configuration names.

## License

Blackcoin inherits the MIT-licensed Blackcoin codebase. See
[COPYING](COPYING) for details.
