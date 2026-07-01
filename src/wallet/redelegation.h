// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_REDELEGATION_H
#define BITCOIN_WALLET_REDELEGATION_H

#include <consensus/amount.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace wallet {

struct QuantumRedelegationPolicy
{
    int64_t trigger_multiplier{6};
    int64_t max_patience_blocks{4050};
    int64_t min_trigger_blocks{300};
    int64_t rate_limit_blocks{1350};
    int64_t probation_blocks{1350};
    int64_t stampede_jitter_blocks{1350};
    int64_t liveness_improvement_blocks{300};
    int64_t top_liveness_candidates{4};
};

struct QuantumRedelegationStatus
{
    bool should_redelegate{false};
    bool rate_limited{false};
    bool probation{false};
    bool success_rate_limited{false};
    int64_t trigger_blocks{0};
    int64_t eligible_height{0};
    int64_t jitter_blocks{0};
};

struct QuantumRedelegationCandidate
{
    uint256 staker_pubkey_hash;
    std::vector<unsigned char> staker_pubkey;
    CAmount operator_value{0};
    CAmount total_coldstake{0};
    int last_win_height{0};
    bool operator_commitment_verified{false};
    bool current_operator{false};
};

struct QuantumRedelegationCandidateScore
{
    QuantumRedelegationCandidate candidate;
    int64_t share_bps{0};
    int last_win_height{0};
    bool would_exceed_cap{false};
    uint64_t tie_breaker{0};
};

int64_t QuantumRedelegationTriggerBlocks(int64_t expected_interval_blocks, const QuantumRedelegationPolicy& policy = {});
uint64_t QuantumRedelegationJitter(const uint256& delegation_id, const uint256& staker_pubkey_hash, const QuantumRedelegationPolicy& policy = {});
QuantumRedelegationStatus EvaluateQuantumRedelegation(int64_t zero_win_blocks, int64_t expected_interval_blocks, int64_t current_height, int64_t last_redelegation_height, int64_t last_successful_redelegation_height, int64_t target_activation_height, const uint256& delegation_id, const uint256& staker_pubkey_hash, const QuantumRedelegationPolicy& policy = {});
bool HasUnderCapQuantumRedelegationCandidate(const std::vector<QuantumRedelegationCandidate>& candidates, CAmount delegation_amount);
std::vector<QuantumRedelegationCandidateScore> RankQuantumRedelegationCandidates(const std::vector<QuantumRedelegationCandidate>& candidates, CAmount delegation_amount, const QuantumRedelegationPolicy& policy = {});
std::optional<QuantumRedelegationCandidateScore> SelectQuantumRedelegationTarget(const std::vector<QuantumRedelegationCandidateScore>& ranked, int source_last_win_height, const uint256& delegation_id, const QuantumRedelegationPolicy& policy = {});

} // namespace wallet

#endif // BITCOIN_WALLET_REDELEGATION_H
