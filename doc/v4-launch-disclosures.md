# Blackcoin V4 Launch Disclosures

This document records design decisions and residual risks that should be visible to
reviewers before Blackcoin Core Protocol V4 (Quantum Quasar) is deployed.

## Gold Rush reward model

Gold Rush rewards are credited only to quantum migration addresses. A reward
credited to the address that mined or claimed it must be moved once to a fresh
quantum address before ordinary wallet funding, cold-stake delegation, or node
bonding uses it. Wallet workflows avoid selecting unmoved reward outputs by
default, and consensus rejects same-address remigration attempts.

PoS Gold Rush eligibility is based on the deterministic whitelist snapshot. The
snapshot aggregates spendable balance by canonical spend target at the snapshot
height. Targets at or above the 10,000 BLK threshold can qualify for PoS Gold
Rush rewards after they actively signal and solve within the required lookback
window. Targets below the threshold do not qualify retroactively because of later
receipts.

PoS Gold Rush participation is split by eligible active target, not by inferred
human owner. This is intentional and deterministic, but it means the protocol
does not try to prove that two eligible targets are controlled by different
people.

## PoW Gold Rush claims

PoW Gold Rush claims are not whitelist-gated. A valid claim transaction contains
the proof and a quantum payout address, and the reward is credited to that
quantum address when an upgraded node validates the block.

The PoW side uses a winner-take-claim pool model. A well-resourced miner can win
more of the PoW migration pool than a lightly provisioned miner. This is an
accepted launch tradeoff: the PoW path exists to give non-whitelisted and smaller
holders a direct quantum-entry path, while the PoS side remains snapshot-limited
and equalized across active eligible targets.

## Wallet protections and consensus backstops

Wallet code treats several outputs as protected by default:

- unmoved Gold Rush quantum rewards;
- bonded or still-unbonding tiered quantum staking outputs;
- fully locked demurrage outputs;
- RGB/EUTXO seal outputs.

These wallet exclusions are not the security boundary. Consensus rules also
reject invalid raw spends for the critical cases:

- bonded tiered principal cannot be redirected outside the allowed covenant;
- fully locked demurrage outputs cannot be spent;
- unmoved Gold Rush rewards cannot satisfy the required first move by paying
  back to the same quantum address.

The wallet also uses demurrage-adjusted effective input value for partially
decayed outputs during automatic and manual coin selection, so transaction
funding matches the value that consensus will recognize.

## Cold staking and pool share

The cold-staking pool cap is a wallet and policy coordination tool, not a
consensus-enforced security boundary. It helps wallets steer new delegations away
from already-large operators, but it does not prevent solo staking or multiple
operator identities. The consensus security model depends on the staking
covenant, the tiered stake weight rules, the reorganization limits, assumeutxo,
and weak-subjectivity checkpoints.

## Demurrage scope

Demurrage is post-migration and quantum-only. It does not decay legacy coins
during Gold Rush, and it does not activate before the migration deadline even if
a lower activation height is configured for a test network. Cold-stake contract
outputs and treasury outputs are exempt according to the consensus rules.

## Closeout findings addressed

The final red-team pass identified four items that were handled before export:

- shadow emission cap rejection is atomic on connect and symmetric on disconnect;
- wallet exclusions have consensus backstop tests for raw crafted spends;
- the PoW winner-take-claim model is explicitly disclosed as a launch tradeoff;
- partially decayed outputs use effective-value accounting in wallet funding.
