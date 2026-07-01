#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  start-private-regtest.sh [--nodes N] [--root DIR] [--init]
  start-private-regtest.sh --stop [--root DIR]

Starts an isolated multi-node Blackcoin regtest network for the private soak-test
network. Discovery is disabled and nodes are explicitly wired to node0.

Environment overrides:
  BLACKCOIND                         daemon path (default: ./src/blackcoind)
  BLACKCOINCLI                       cli path (default: ./src/blackcoin-cli)
  BLACKCOIN_BIND                     bind address (default: 127.0.0.1)
  BLACKCOIN_P2P_BASE                 first P2P port (default: 35714)
  BLACKCOIN_RPC_BASE                 first RPC port (default: 36715)
  BLACKCOIN_SHADOW_GOLD_RUSH_BLOCKS  compressed Gold Rush length (default: 40)
  BLACKCOIN_BLOCKS_PER_MONTH         demurrage month length in blocks (default: 4)
USAGE
}

NODES=4
ROOT="${BLACKCOIN_PRIVATE_TESTNET_ROOT:-/tmp/blackcoin-private-regtest}"
INIT=0
STOP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)
            NODES="$2"
            shift 2
            ;;
        --root)
            ROOT="$2"
            shift 2
            ;;
        --init)
            INIT=1
            shift
            ;;
        --stop)
            STOP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

BLACKCOIND="${BLACKCOIND:-./src/blackcoind}"
BLACKCOINCLI="${BLACKCOINCLI:-./src/blackcoin-cli}"
BLACKCOIN_BIND="${BLACKCOIN_BIND:-127.0.0.1}"
P2P_BASE="${BLACKCOIN_P2P_BASE:-35714}"
RPC_BASE="${BLACKCOIN_RPC_BASE:-36715}"
GOLD_RUSH_BLOCKS="${BLACKCOIN_SHADOW_GOLD_RUSH_BLOCKS:-40}"
BLOCKS_PER_MONTH="${BLACKCOIN_BLOCKS_PER_MONTH:-4}"

GOLD_RUSH_END_TIME="${BLACKCOIN_GOLD_RUSH_END_TIME:-1700003600}"
MIGRATION_DEADLINE_TIME="${BLACKCOIN_MIGRATION_DEADLINE_TIME:-1700176400}"

cli() {
    local idx="$1"
    shift
    "$BLACKCOINCLI" -datadir="$ROOT/node${idx}" -regtest "$@"
}

wait_for_rpc() {
    local idx="$1"
    local tries=120
    while (( tries > 0 )); do
        if cli "$idx" getblockchaininfo >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        tries=$((tries - 1))
    done
    echo "node${idx} RPC did not become ready" >&2
    return 1
}

if (( STOP )); then
    for dir in "$ROOT"/node*; do
        [[ -d "$dir" ]] || continue
        "$BLACKCOINCLI" -datadir="$dir" -regtest stop >/dev/null 2>&1 || true
    done
    exit 0
fi

mkdir -p "$ROOT"

for ((i = 0; i < NODES; ++i)); do
    datadir="$ROOT/node${i}"
    mkdir -p "$datadir"
    p2p_port=$((P2P_BASE + i))
    rpc_port=$((RPC_BASE + i))
    if (( i == 0 )); then
        connect_line="connect=0"
    else
        connect_line="connect=${BLACKCOIN_BIND}:${P2P_BASE}"
    fi
    cat > "$datadir/blackcoin.conf" <<CONF
regtest=1
server=1
daemon=1
fallbackfee=0.0005

[regtest]
listen=1
bind=${BLACKCOIN_BIND}
port=${p2p_port}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=${rpc_port}
txindex=1
coinstatsindex=1
dnsseed=0
fixedseeds=0
discover=0
listenonion=0
upnp=0
natpmp=0
i2pacceptincoming=0
${connect_line}
shadowwhitelistheight=1
shadowgoldrushblocks=${GOLD_RUSH_BLOCKS}
qqgoldrushendtime=${GOLD_RUSH_END_TIME}
qqmigrationdeadlinetime=${MIGRATION_DEADLINE_TIME}
qqstaketierheight=1
qqstakesplitheight=1
qqdemurrageheight=1
qqdemurrageblockspermonth=${BLOCKS_PER_MONTH}
CONF
done

for ((i = 0; i < NODES; ++i)); do
    "$BLACKCOIND" -datadir="$ROOT/node${i}"
done

for ((i = 0; i < NODES; ++i)); do
    wait_for_rpc "$i"
done

if (( INIT )); then
    for ((i = 0; i < NODES; ++i)); do
        cli "$i" createwallet "soak${i}" >/dev/null 2>&1 || true
    done
    addr="$(cli 0 -rpcwallet=soak0 getnewaddress "" legacy)"
    cli 0 setmocktime 1700000000
    cli 0 generatetoaddress 120 "$addr" >/dev/null
fi

echo "Private Blackcoin regtest network started at $ROOT"
echo "Node0 CLI: $BLACKCOINCLI -datadir=$ROOT/node0 -regtest"
echo "Check peers: $BLACKCOINCLI -datadir=$ROOT/node0 -regtest getpeerinfo"
