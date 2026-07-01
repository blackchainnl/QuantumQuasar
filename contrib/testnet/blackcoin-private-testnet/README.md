# Blackcoin private soak network

This directory contains the launch notes and helper script for the private soak-test
network. It is intentionally private and uses no public seeds.

## Isolation choice

Use a **private regtest network with explicit peer wiring** for the accelerated
private soak.

Reasons:

- The phase-compression knobs needed for a days-long soak are currently
  regtest-only: `-qqgoldrushendtime`, `-qqmigrationdeadlinetime`,
  `-qqdemurrageheight`, `-qqdemurrageblockspermonth`,
  `-shadowwhitelistheight`, and `-shadowgoldrushblocks`.
- Changing the shared `-testnet` message start, ports, seeds, or consensus
  schedule would touch the frozen network/consensus surface and should be
  handled as a separate network-design change.
- `-connect` plus disabled DNS/fixed seeds gives an immediate no-code path that
  does not risk joining the public Blackcoin testnet.

Tradeoff:

- A distinct compiled network magic would provide stronger isolation.
- The no-code topology below is safe only if every node is launched with the
  supplied discovery-disabled options and the host firewall permits P2P inbound
  only from the chosen private peer IPs.

## Required host firewall

On each VPS, allow the P2P port only from the other private soak nodes. Do not
open it to the internet. Keep RPC bound to `127.0.0.1`.

Example Linux firewall shape:

```bash
sudo ufw default deny incoming
sudo ufw allow from <peer-1-ip> to any port 35714 proto tcp
sudo ufw allow from <peer-2-ip> to any port 35714 proto tcp
sudo ufw allow ssh
sudo ufw enable
```

Use the actual P2P port from each node's config if you customize the defaults.

## Accelerated schedule

The helper script uses:

- whitelist snapshot: height 1
- Gold Rush reward window: 40 blocks
- migration window: approximately 2 mock-time days after Gold Rush
- demurrage active after final lockout, with 1 month compressed to 4 blocks
- tiered staking and stake-reward split features active from height 1

That is intentionally short. For a fuller VPS soak, increase
`BLACKCOIN_SHADOW_GOLD_RUSH_BLOCKS` to 720 or 1440 and set the mock-time cadence to
the intended wall-clock duration.

The chain still uses normal node code paths:

- staking and block relay are real node behavior
- Gold Rush state is observed through `getgoldrushstate`
- phase state is observed through `getquantumquasarinfo`
- supply and demurrage are observed through `getcirculatingsupply`
- wallet migration status is observed through `getmigrationstatus`
- PoW Gold Rush claims use `getshadowpowwork` and `sendshadowpowclaim`

## Single-host smoke

From the repository root after building:

```bash
contrib/testnet/blackcoin-private-testnet/start-private-regtest.sh --nodes 4 --init
```

Useful checks:

```bash
ROOT=/tmp/blackcoin-private-regtest
CLI="./src/blackcoin-cli -datadir=$ROOT/node0 -regtest"

$CLI getnetworkinfo
$CLI getpeerinfo
$CLI getquantumquasarinfo
$CLI getgoldrushstate
$CLI getcirculatingsupply
```

Stop all nodes:

```bash
contrib/testnet/blackcoin-private-testnet/start-private-regtest.sh --stop
```

## Multi-VPS shape

Use one seed node and several workers. The seed node listens but makes no
automatic outbound connections:

```ini
regtest=1
server=1

[regtest]
listen=1
connect=0
dnsseed=0
fixedseeds=0
discover=0
listenonion=0
upnp=0
natpmp=0
i2pacceptincoming=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

Each worker connects only to the seed:

```ini
regtest=1
server=1

[regtest]
listen=1
connect=<seed-private-ip>:35714
dnsseed=0
fixedseeds=0
discover=0
listenonion=0
upnp=0
natpmp=0
i2pacceptincoming=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

All nodes should use the same accelerated phase arguments.

## Before public soak testing

Before exposing any long-running public testnet, choose one:

1. Keep using this private regtest topology for the official private soak. This is
   fastest and avoids code churn, but it is not a public discoverable network.
2. Authorize a separate isolated network profile with its own message start,
   ports, empty seeds, and compressed schedule. That is stronger isolation for a
   public testnet, but it is a code change.
