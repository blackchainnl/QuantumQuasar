// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits)
 *  NOTE: pre-V4 (legacy) value MUST match upstream Blackcoin to avoid an accidental
 *  pre-activation chain split. V4 blocks use V4_MAX_BLOCK_SERIALIZED_SIZE (gated by MTP). */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule).
 *  NOTE: pre-V4 (legacy) value MUST match upstream Blackcoin. V4 uses V4_MAX_BLOCK_WEIGHT. */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;

/** Quantum Quasar V4 limit values */
static const unsigned int V4_MAX_BLOCK_SERIALIZED_SIZE = 32000000;
static const unsigned int V4_MAX_BLOCK_WEIGHT = 32000000;
static const int64_t V4_MAX_BLOCK_SIGOPS_COST = 640000;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
