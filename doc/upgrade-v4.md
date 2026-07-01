# Blackcoin V4 Upgrade Guide

Blackcoin V4 is the Quantum Quasar protocol upgrade line for Blackcoin. It keeps
the existing chain history and wallet continuity while adding quantum migration
addresses, Gold Rush reward participation, staking changes, RGB/EUTXO
commitment tooling, and first-run migration from older Blackcoin data
directories.

This document describes the intended transition model for testing and operator
review. It is not a public-network activation notice.

## Transition Timeline

The V4 transition is designed to run in phases.

1. Activation and bridge period.
   Upgraded nodes follow the legacy chain and accept legacy-compatible blocks.
   There is no day-one split from ordinary legacy ledger activity.

2. Gold Rush period, approximately six months.
   Upgraded wallets can participate in Gold Rush reward accounting while the
   base block flow remains legacy-compatible. Rewards are credited to quantum
   addresses on the upgraded ledger.

3. Quantum migration period, approximately eighteen months after Gold Rush.
   Users move spendable value to quantum migration addresses. Legacy chain
   activity remains tracked during this period so users can still upgrade and
   migrate later.

4. Final lockout.
   After the migration deadline, non-migrated legacy spends are disabled on the
   upgraded chain. Quantum outputs remain spendable under the new rules.

The full planned transition is approximately twenty-four months from the start
of Gold Rush through final lockout.

## Gold Rush Participation

Gold Rush rewards are split between staking-based participation and Proof of Work
claim participation.

For staking participation, eligible wallets signal from a whitelisted legacy
address and bind the signal to a quantum payout address. The signal is recorded
on-chain and remains active for the configured look-back window. Active,
qualified signalers share the staking-side Gold Rush allocation evenly while
they remain eligible.

For Proof of Work participation, a wallet computes an Argon2id proof against the
current work parameters and broadcasts a `QQSPROOF` transaction. The transaction
authenticates the claimant with a legacy spend and specifies a quantum payout
address. If a staker includes a valid claim, the upgraded rules credit the
claim's reward to that quantum address. Claim transactions pay ordinary network
fees.

The wallet exposes helper RPCs for both paths, including `getgoldrushstate`,
`getgoldrushinfo`, `sendshadowsignal`, `getshadowpowwork`,
`sendshadowpowclaim`, `setpowmining`, and `getpowmininginfo`.

## Quantum Addresses And Migration

Quantum migration addresses use ML-DSA keys and are distinct from legacy
addresses. Users should create quantum addresses with the wallet RPCs and move
funds before the migration deadline.

The primary wallet flow is:

1. Generate or select a wallet-backed quantum migration address.
2. Use `migratetoquantum` to build and send the migration transaction.
3. Confirm the migrated output is wallet-backed and spendable.
4. For Gold Rush rewards credited during the Gold Rush period, move those coins
   to a fresh quantum wallet during the migration period.

Wallets and UI surfaces should clearly separate legacy receiving addresses from
quantum migration addresses so users do not confuse pre-migration legacy sends
with post-migration quantum custody.

## Staking Changes

V4 includes quantum cold-staking and staking policy changes intended to preserve
principal safety while improving operator distribution.

- Cold-stake principal preservation keeps delegated principal in the owner's
  spend branch while allowing the selected staking key to produce coinstakes.
- Stake-reward splitting pays the delegator and operator according to the
  consensus split for eligible cold-stake coinstakes.
- Tiered staking weights use a deterministic fixed-point curve for eligible
  quantum staking commitments.
- Autonomous redelegation lets an unlocked owner wallet move a delegation when
  the current operator has not won for the configured interval and a better
  verified target is available.
- The per-pool cap is wallet and policy guidance. It steers new delegations away
  from oversized operators when alternatives exist, but it is not a consensus
  defense and does not prevent solo staking or operator sub-pools.
- Cold-stake outputs are exempt from demurrage while they remain in the
  cold-stake covenant.

## Demurrage And Liveness

Demurrage applies only after the migration deadline and only to post-migration
quantum outputs that are not exempt. It is inactive during Gold Rush and the
migration window. Wallet-backed liveness attestations can refresh inactive
quantum keys, and staking wallets can create periodic attestations while
staking.

Wallet RPCs include `getdemurragewalletinfo`, `senddemurrageattestation`,
`sweepdemurragedecay`, and `getcirculatingsupply`.

## First-Run Data Directory Migration

On first run, if no explicit `-datadir` or `-conf` is supplied, `blackcoind` and
`blackcoin-qt` inspect the default data-directory locations for older Blackcoin
data.

If a legacy `~/.blackmore` directory exists and `.blackcoin` does not, the node
copies `.blackmore` to `.blackcoin`, converts `blackmore.conf` to
`blackcoin.conf`, removes copied lock files, leaves the original `.blackmore`
directory intact, and writes a durable migration marker.

If both `.blackcoin` and `.blackmore` contain data, `blackcoin-qt` prompts the
user to keep `.blackcoin` or import `.blackmore`. Headless `blackcoind` safely
keeps `.blackcoin` by default and preserves `.blackmore` under
`.blackcoin.backup`. Operators can explicitly choose with
`-migratewallet=blackmore`, `-migratewallet=blackcoin`, or
`-migratewallet=none`.

Migration is copy-first and backup-preserving. If migration cannot complete
safely, startup aborts rather than creating or loading an empty or wrong wallet.
Operators should make sure the system has enough free disk space for the copied
data directory and backup material before first run.

## Build And Run

Build from the repository root:

```bash
./autogen.sh
./configure
make -j8
```

Useful binaries:

```bash
src/blackcoind
src/blackcoin-cli
src/blackcoin-wallet
src/qt/blackcoin-qt
```

For local testing, start with regtest or a private soak network. Do not use a
pre-release build as a public-network activation client until activation
parameters, release binaries, and operator instructions have been published.

Run core validation checks with:

```bash
make -C src -j8 check
python3 test/functional/test_runner.py
```

