30.0 Release Notes
==================

Blackcoin version 30.0.0 is the major Blackcoin protocol upgrade release.
Release binaries will be made available from:

  <https://github.com/Blackcoin-Dev/Blackcoin/releases>

This release includes the Blackcoin V4 feature set, including the V4 upgrade
path, quantum-address migration support, Gold Rush staking and PoW claim logic,
wallet/RPC hardening, and the release/package rename from legacy daemon/config
binary names to Blackcoin.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/Blackcoin-Dev/Blackcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://github.com/Blackcoin-Dev/Blackcoin/releases>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Blackcoin` (on macOS)
or `blackcoind`/`blackcoin-qt` (on Linux).

Upgrading directly from a version of Blackcoin that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Blackcoin are generally supported.

Compatibility
==============

Blackcoin is supported and tested on operating systems
using the Linux kernel, macOS 11.0+, and Windows 7 and newer. Blackcoin
should also work on most other Unix-like systems but is not as
frequently tested on them. It is not recommended to use Blackcoin on
unsupported systems.

Notable changes
===============

### Version line

- Blackcoin moves the upgrade line from v26.2.x to v30.0.0 to reflect the
  scope of the protocol transition.

### Protocol transition

- V4 activation, Gold Rush, and quantum transition logic are included in the
  codebase so operators can review the full feature set before network activation.
- Gold Rush staking and PoW claim paths credit the upgraded shadow ledger to
  quantum addresses while preserving legacy-compatible base block rewards during
  the bridge period.
- Legacy data-directory migration remains in place so existing Blackcoin users
  can move to Blackcoin without manually relocating wallet or chain data.

### Wallet and RPC

- Quantum address, Gold Rush, PoW miner, cold-staking, RGB, and EUTXO RPC
  surfaces are present for testnet validation.
- Wallet code includes migration and safety checks for the quantum transition
  path.

### Packaging

- The legacy daemon/config names have been replaced by Blackcoin
  names.
- Blackcoin remains the coin and network name.
