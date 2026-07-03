# Blackcoin Transition Guide

## Legacy Blackcoin Operators

Blackcoin is the Protocol V4 upgrade path for the legacy Blackcoin
network. The current build is intended for testnet validation before a public
release.

## Current Schedule in Code

- V4 activation opens the Gold Rush phase.
- Gold Rush runs for the configured six-month epoch.
- Quantum witness spends activate after the Gold Rush reward-height window,
  during the migration phase.
- The quantum migration window follows for the configured eighteen-month epoch.
- After the migration deadline, final lockout rules disable remaining legacy
  spends according to the consensus schedule.

Use RPC to inspect the active schedule and wallet migration status:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli -rpcwallet=<wallet> getmigrationstatus
```

## Upgrade Test Flow

1. Stop the legacy Blackcoin node.
2. Build the Blackcoin branch.
3. Start `blackcoind`.
4. Back up the wallet before generating or funding quantum migration keys.
5. Use `getmigrationstatus` to inspect remaining legacy funds.
6. Use `migratetoquantum` during the migration window when ready to move legacy
   wallet coins into ML-DSA-backed quantum migration outputs.

## Gold Rush

Gold Rush rewards are tracked in the upgraded Shadow Network ledger while the
base Blackcoin ledger remains legacy-compatible. Upgraded wallets publish
fee-paying, legacy-valid OP_RETURN transactions for Gold Rush participation;
legacy nodes can still relay and mine the underlying transactions, while
upgraded nodes interpret the `QQSIGNAL` and `QQSPROOF` payloads as shadow-ledger
credits.

Gold Rush reward credits are not spendable on the base legacy rules. Upgraded
nodes keep those credits in the upgraded UTXO set and defer ML-DSA quantum
spends, EUTXO spends, and larger post-quantum script elements until the
post-Gold-Rush migration phase. This keeps the Gold Rush bridge
legacy-compatible; the hard-fork spend phase begins when migration spends are
enabled.

Whitelisted recent PoS solvers signal with `QQSIGNAL` to link a qualifying
legacy address to a quantum migration payout address. Argon2id PoW claim
transactions use the `QQSPROOF` OP_RETURN payload, are not whitelist-gated, and
credit the PoW-side jackpot only to a quantum migration address. Neither path
requires an extra coinstake payout output, and Gold Rush credits do not increase
the legacy block subsidy during the compatibility bridge.

Small-balance PoW miners use `getshadowpowwork` to inspect the current Argon2id
target and `sendshadowpowclaim` from a wallet to grind and broadcast a claim.
The built-in miner can also be controlled with `setpowmining` and inspected
with `getpowmininginfo`. In the Qt GUI, use the Staking/Mining page to configure
the built-in Gold Rush PoW miner and copy its quantum payout address.

## Validation Status

The V4 Gold Rush, quantum migration, cold-staking, autonomous redelegation,
tiered staking, stake-reward split, and demurrage paths are implemented for
testnet validation in this branch. Do not treat this branch as a final mainnet
release until the public activation parameters, packaging, and testnet sign-off
are announced.
