// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_QUANTUM_WITNESS_H
#define BITCOIN_CONSENSUS_QUANTUM_WITNESS_H

#include <uint256.h>

#include <cstdint>
#include <vector>

static constexpr unsigned int QUANTUM_MIGRATION_WITNESS_VERSION = 16;
static constexpr unsigned int QUANTUM_MIGRATION_PROGRAM_SIZE = 32;
static constexpr unsigned int QUANTUM_TIERED_PROGRAM_SIZE = 40;
static constexpr unsigned char QUANTUM_TIERED_PROGRAM_TAG = 0x01;
static constexpr unsigned char QUANTUM_TIERED_STATE_BONDED = 0x01;
static constexpr unsigned char QUANTUM_TIERED_STATE_UNBONDING = 0x02;
// Native witness versions are encoded by OP_0..OP_16. Keep cold staking on an
// unused valid version below the EUTXO v15 and migration v16 reservations.
static constexpr unsigned int QUANTUM_COLDSTAKE_WITNESS_VERSION = 14;
static constexpr unsigned int QUANTUM_COLDSTAKE_PROGRAM_SIZE = 32;

struct QuantumStakeTierProgram
{
    unsigned int witness_version{0};
    bool cold_stake{false};
    bool tiered{false};
    unsigned char state{QUANTUM_TIERED_STATE_BONDED};
    uint16_t unbonding_blocks{0};
    uint32_t unlock_height{0};
    uint256 commitment{};

    bool IsBonded() const { return tiered && state == QUANTUM_TIERED_STATE_BONDED; }
    bool IsUnbonding() const { return tiered && state == QUANTUM_TIERED_STATE_UNBONDING; }
    int EffectiveUnbondingBlocks(int candidate_height) const;
};

bool DecodeQuantumStakeTierProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program, QuantumStakeTierProgram& tier);
bool IsQuantumMigrationWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program);
std::vector<unsigned char> QuantumTieredProgramForCommitment(unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height, const uint256& commitment);
std::vector<unsigned char> QuantumTieredColdStakeProgramForKeyHashes(const uint256& staker_pubkey_hash, const uint256& owner_pubkey_hash, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height);
bool IsQuantumColdStakeWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program);

#endif // BITCOIN_CONSENSUS_QUANTUM_WITNESS_H
