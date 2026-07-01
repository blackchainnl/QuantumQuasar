// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/quantum_witness.h>

#include <crypto/common.h>
#include <hash.h>

#include <algorithm>
#include <string>

namespace {
std::vector<unsigned char> BuildTieredProgram(unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height, const uint256& commitment)
{
    std::vector<unsigned char> program;
    program.reserve(QUANTUM_TIERED_PROGRAM_SIZE);
    program.push_back(QUANTUM_TIERED_PROGRAM_TAG);
    program.push_back(state);
    program.push_back(static_cast<unsigned char>(unbonding_blocks & 0xff));
    program.push_back(static_cast<unsigned char>((unbonding_blocks >> 8) & 0xff));
    program.push_back(static_cast<unsigned char>(unlock_height & 0xff));
    program.push_back(static_cast<unsigned char>((unlock_height >> 8) & 0xff));
    program.push_back(static_cast<unsigned char>((unlock_height >> 16) & 0xff));
    program.push_back(static_cast<unsigned char>((unlock_height >> 24) & 0xff));
    program.insert(program.end(), commitment.begin(), commitment.end());
    return program;
}
} // namespace

int QuantumStakeTierProgram::EffectiveUnbondingBlocks(int candidate_height) const
{
    if (!tiered) return 0;
    if (IsBonded()) return unbonding_blocks;
    if (candidate_height < 0) return static_cast<int>(unbonding_blocks);
    if (unlock_height <= static_cast<uint32_t>(candidate_height)) return 0;
    return static_cast<int>(unlock_height - static_cast<uint32_t>(candidate_height));
}

bool DecodeQuantumStakeTierProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program, QuantumStakeTierProgram& tier)
{
    const bool is_migration = witness_version == QUANTUM_MIGRATION_WITNESS_VERSION;
    const bool is_cold_stake = witness_version == QUANTUM_COLDSTAKE_WITNESS_VERSION;
    if (!is_migration && !is_cold_stake) return false;

    tier = {};
    tier.witness_version = witness_version;
    tier.cold_stake = is_cold_stake;

    if (witness_program.size() == QUANTUM_MIGRATION_PROGRAM_SIZE) {
        tier.tiered = false;
        std::copy(witness_program.begin(), witness_program.end(), tier.commitment.begin());
        return true;
    }

    if (witness_program.size() != QUANTUM_TIERED_PROGRAM_SIZE) return false;
    if (witness_program[0] != QUANTUM_TIERED_PROGRAM_TAG) return false;

    const unsigned char state = witness_program[1];
    const uint16_t unbonding_blocks = ReadLE16(witness_program.data() + 2);
    const uint32_t unlock_height = ReadLE32(witness_program.data() + 4);
    if (state != QUANTUM_TIERED_STATE_BONDED && state != QUANTUM_TIERED_STATE_UNBONDING) return false;
    if (state == QUANTUM_TIERED_STATE_BONDED && unlock_height != 0) return false;
    if (state == QUANTUM_TIERED_STATE_UNBONDING && unlock_height == 0) return false;

    tier.tiered = true;
    tier.state = state;
    tier.unbonding_blocks = unbonding_blocks;
    tier.unlock_height = unlock_height;
    std::copy(witness_program.begin() + 8, witness_program.end(), tier.commitment.begin());
    return true;
}

bool IsQuantumMigrationWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program)
{
    QuantumStakeTierProgram tier;
    return witness_version == QUANTUM_MIGRATION_WITNESS_VERSION &&
           DecodeQuantumStakeTierProgram(witness_version, witness_program, tier);
}

std::vector<unsigned char> QuantumTieredProgramForCommitment(unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height, const uint256& commitment)
{
    return BuildTieredProgram(state, unbonding_blocks, unlock_height, commitment);
}

std::vector<unsigned char> QuantumTieredColdStakeProgramForKeyHashes(const uint256& staker_pubkey_hash, const uint256& owner_pubkey_hash, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height)
{
    HashWriter ss{};
    ss << std::string("Quantum Quasar Cold Stake v2");
    ss << state;
    ss << unbonding_blocks;
    ss << unlock_height;
    ss << staker_pubkey_hash;
    ss << owner_pubkey_hash;
    const uint256 program_hash = ss.GetHash();
    return BuildTieredProgram(state, unbonding_blocks, unlock_height, program_hash);
}

bool IsQuantumColdStakeWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program)
{
    QuantumStakeTierProgram tier;
    return witness_version == QUANTUM_COLDSTAKE_WITNESS_VERSION &&
           DecodeQuantumStakeTierProgram(witness_version, witness_program, tier);
}
