# Testnet Height-Based Quantum Quasar Schedule

The test schedule branch lets an isolated testnet (or regtest) run the full
Quantum Quasar lifecycle — Gold Rush → Migration → Final Lockout — at
configurable **block heights** instead of the fixed mainnet wall-clock
schedule. Mainnet structurally rejects every knob below at startup.

## Boundary knobs

| Boundary | Height-based (authoritative when set) | Time-based fallback |
|---|---|---|
| Gold Rush reward window start | `-shadowgoldrushstartheight=<h>` | n/a (always height-based) |
| Gold Rush reward window end (inclusive) | `-shadowgoldrushendheight=<h>` or `-shadowgoldrushblocks=<n>` | n/a (always height-based) |
| Gold Rush phase end (→ Migration) | `-qqgoldrushendheight=<h>` | `-qqgoldrushendtime=<unix>` |
| Migration end (→ Final Lockout) | `-qqmigrationendheight=<h>` | `-qqmigrationdeadlinetime=<unix>` |
| Whitelist snapshot | `-shadowwhitelistheight=<h>` | n/a |
| Protocol V4 start | n/a (already 0/instant on testnet) | `-qqv4time=<unix>` |

Semantics of the height boundaries: the block **at** the boundary height is
the last block of its phase; the next block starts the new phase. When a
height override is non-zero the paired time value is ignored for that
boundary. Consensus phase predicates evaluate `(median-time-past, height)`
pairs, so every node on the same chain flips phases at exactly the same
block.

Validation at startup:

* `-shadowgoldrushstartheight` must be greater than `-shadowwhitelistheight`.
* `-shadowgoldrushendheight` must be at least the Gold Rush start height and
  cannot be combined with `-shadowgoldrushblocks`.
* `-qqgoldrushendheight` must not be below the shadow reward end height
  (the reward window cannot outlive the Gold Rush phase).
* `-qqmigrationendheight` must be greater than `-qqgoldrushendheight`.

`getquantumquasarinfo` reports the effective schedule
(`shadow_reward_start_height`, `shadow_reward_end_height`,
`gold_rush_end_height`, `quantum_migration_end_height`) plus the live
`phase`, so operators can confirm every node agrees.

The demurrage minimum activation height on testnet now follows the
overridden reward schedule (`shadow reward end + 1`) instead of the
mainnet-scale height, so post-migration demurrage is reachable in test runs.

On this branch testnet is a mockable chain: `setmocktime` works, which lets
harnesses drive deterministic PoS kernels. This has no effect on peers and is
operator-only RPC.

## Example: 5-node private testnet lifecycle

```
blackcoind -testnet \
  -shadowwhitelistheight=1 \
  -shadowgoldrushstartheight=30 \
  -shadowgoldrushendheight=90 \
  -qqgoldrushendheight=90 \
  -qqmigrationendheight=140 \
  -minimumchainwork=0x00 -assumevalid=0 \
  -solostaking=1 \
  -connect=<peer> -listen=1
```

Give **identical schedule arguments to every node** — they are consensus
parameters for the run. `-minimumchainwork=0x00` is required on a private
testnet so freshly-started peers leave IBD on a low-work chain, and
`-solostaking=1` (testnet/regtest only) lets wallets stake on a private chain
— without it the staker waits for peers and for a sync-progress estimate that
is computed from **public** testnet transaction statistics and never completes
on an isolated schedule-override chain.

`test/functional/feature_goldrush_height_schedule_multinode.py` drives this
exact scenario end to end: single node bootstraps with PoW, produces PoS
blocks and QQSPROOF shadow-PoW claims during Gold Rush, four more nodes join
and sync before the Gold Rush end height, a second node stakes, and all five
nodes cross both boundaries at exactly the configured heights, ending in
Final Lockout with legacy spends refused.
