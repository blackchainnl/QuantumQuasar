// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/redelegation.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <hash.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string>

namespace wallet {
namespace {

arith_uint256 AmountToArith(CAmount value)
{
    return arith_uint256{static_cast<uint64_t>(std::max<CAmount>(value, 0))};
}

int64_t ShareBps(CAmount value, CAmount total)
{
    if (value <= 0 || total <= 0) return 0;
    arith_uint256 scaled = AmountToArith(value) * static_cast<uint32_t>(10000);
    scaled /= AmountToArith(total);
    return static_cast<int64_t>(scaled.GetLow64());
}

bool WouldExceedCap(CAmount total, CAmount value, CAmount inflow)
{
    if (total < 0 || value < 0 || inflow < 0 || !MoneyRange(value + inflow)) {
        return true;
    }
    const CAmount post_total = total;
    const CAmount post_value = value + inflow;
    if (post_total <= 0 || post_value <= 0) return false;
    return AmountToArith(post_value) * static_cast<uint32_t>(10000) > AmountToArith(post_total) * static_cast<uint32_t>(2000);
}

int64_t SaturatingAddNonNegative(int64_t a, int64_t b)
{
    if (a < 0 || b < 0) return 0;
    if (a > std::numeric_limits<int64_t>::max() - b) return std::numeric_limits<int64_t>::max();
    return a + b;
}

bool IsEligibleCandidate(const QuantumRedelegationCandidate& candidate)
{
    return !candidate.current_operator &&
           candidate.operator_commitment_verified &&
           !candidate.staker_pubkey.empty();
}

QuantumRedelegationCandidateScore ScoreCandidate(const QuantumRedelegationCandidate& candidate, CAmount delegation_amount)
{
    QuantumRedelegationCandidateScore score;
    score.candidate = candidate;
    score.share_bps = ShareBps(candidate.operator_value, candidate.total_coldstake);
    score.last_win_height = std::max(candidate.last_win_height, 0);
    score.would_exceed_cap = WouldExceedCap(candidate.total_coldstake, candidate.operator_value, delegation_amount);

    HashWriter ss{};
    ss << std::string{"Blackcoin redelegation candidate tie"};
    ss << candidate.staker_pubkey_hash;
    const uint256 h = ss.GetHash();
    score.tie_breaker = ReadLE64(h.begin());
    return score;
}

uint64_t SelectionTieBreaker(const QuantumRedelegationCandidateScore& score, const uint256& delegation_id)
{
    HashWriter ss{};
    ss << std::string{"Blackcoin redelegation target selection"};
    ss << delegation_id;
    ss << score.candidate.staker_pubkey_hash;
    const uint256 h = ss.GetHash();
    return ReadLE64(h.begin());
}

bool MeaningfullyBetter(const QuantumRedelegationCandidateScore& score, int source_last_win_height, const QuantumRedelegationPolicy& policy)
{
    if (score.last_win_height <= 0) return false;
    if (source_last_win_height <= 0) return true;
    const int64_t required_delta = std::max<int64_t>(1, policy.liveness_improvement_blocks);
    return static_cast<int64_t>(score.last_win_height) >= static_cast<int64_t>(source_last_win_height) + required_delta;
}

} // namespace

int64_t QuantumRedelegationTriggerBlocks(int64_t expected_interval_blocks, const QuantumRedelegationPolicy& policy)
{
    const int64_t min_trigger = std::max<int64_t>(1, policy.min_trigger_blocks);
    const int64_t max_trigger = std::max<int64_t>(min_trigger, policy.max_patience_blocks);
    if (expected_interval_blocks <= 0) return max_trigger;
    const int64_t multiplied = expected_interval_blocks > max_trigger / std::max<int64_t>(policy.trigger_multiplier, 1)
        ? max_trigger
        : expected_interval_blocks * std::max<int64_t>(policy.trigger_multiplier, 1);
    return std::clamp<int64_t>(multiplied, min_trigger, max_trigger);
}

uint64_t QuantumRedelegationJitter(const uint256& delegation_id, const uint256& staker_pubkey_hash, const QuantumRedelegationPolicy& policy)
{
    if (policy.stampede_jitter_blocks <= 0) return 0;
    HashWriter ss{};
    ss << std::string{"Blackcoin redelegation jitter"};
    ss << delegation_id;
    ss << staker_pubkey_hash;
    const uint256 h = ss.GetHash();
    return ReadLE64(h.begin()) % (static_cast<uint64_t>(policy.stampede_jitter_blocks) + 1U);
}

QuantumRedelegationStatus EvaluateQuantumRedelegation(int64_t zero_win_blocks, int64_t expected_interval_blocks, int64_t current_height, int64_t last_redelegation_height, int64_t last_successful_redelegation_height, int64_t target_activation_height, const uint256& delegation_id, const uint256& staker_pubkey_hash, const QuantumRedelegationPolicy& policy)
{
    QuantumRedelegationStatus status;
    status.trigger_blocks = QuantumRedelegationTriggerBlocks(expected_interval_blocks, policy);
    status.jitter_blocks = static_cast<int64_t>(QuantumRedelegationJitter(delegation_id, staker_pubkey_hash, policy));

    const int64_t rate_limit_until = last_redelegation_height > 0 ? SaturatingAddNonNegative(last_redelegation_height, policy.rate_limit_blocks) : 0;
    const int64_t success_rate_limit_until = last_successful_redelegation_height > 0 ? SaturatingAddNonNegative(last_successful_redelegation_height, policy.rate_limit_blocks) : 0;
    const int64_t probation_until = target_activation_height > 0 ? SaturatingAddNonNegative(target_activation_height, policy.probation_blocks) : 0;
    const int64_t threshold_cross_height = zero_win_blocks >= status.trigger_blocks
        ? std::max<int64_t>(0, current_height - std::min<int64_t>(zero_win_blocks - status.trigger_blocks, current_height))
        : current_height;
    const int64_t jitter_until = SaturatingAddNonNegative(threshold_cross_height, status.jitter_blocks);
    status.eligible_height = std::max({rate_limit_until, success_rate_limit_until, probation_until, jitter_until});
    status.rate_limited = rate_limit_until > current_height;
    status.success_rate_limited = success_rate_limit_until > current_height;
    status.probation = probation_until > current_height;
    status.should_redelegate = zero_win_blocks >= status.trigger_blocks &&
                               current_height >= status.eligible_height &&
                               !status.rate_limited &&
                               !status.success_rate_limited &&
                               !status.probation;
    return status;
}

std::vector<QuantumRedelegationCandidateScore> RankQuantumRedelegationCandidates(const std::vector<QuantumRedelegationCandidate>& candidates, CAmount delegation_amount, const QuantumRedelegationPolicy& policy)
{
    (void)policy;
    std::vector<QuantumRedelegationCandidateScore> ranked;
    for (const QuantumRedelegationCandidate& candidate : candidates) {
        if (!IsEligibleCandidate(candidate)) continue;
        ranked.push_back(ScoreCandidate(candidate, delegation_amount));
    }

    const bool has_under_cap = std::any_of(ranked.begin(), ranked.end(), [](const auto& score) {
        return !score.would_exceed_cap;
    });
    if (has_under_cap) {
        ranked.erase(std::remove_if(ranked.begin(), ranked.end(), [](const auto& score) {
            return score.would_exceed_cap;
        }), ranked.end());
    }

    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
        if (a.last_win_height != b.last_win_height) return a.last_win_height > b.last_win_height;
        if (a.share_bps != b.share_bps) return a.share_bps < b.share_bps;
        return a.tie_breaker < b.tie_breaker;
    });
    return ranked;
}

std::optional<QuantumRedelegationCandidateScore> SelectQuantumRedelegationTarget(const std::vector<QuantumRedelegationCandidateScore>& ranked, int source_last_win_height, const uint256& delegation_id, const QuantumRedelegationPolicy& policy)
{
    std::vector<QuantumRedelegationCandidateScore> eligible;
    for (const QuantumRedelegationCandidateScore& score : ranked) {
        if (!MeaningfullyBetter(score, source_last_win_height, policy)) continue;
        eligible.push_back(score);
    }
    if (eligible.empty()) return std::nullopt;

    const size_t top_k = static_cast<size_t>(std::max<int64_t>(1, policy.top_liveness_candidates));
    if (eligible.size() > top_k) {
        eligible.resize(top_k);
    }

    auto selected = eligible.begin();
    uint64_t selected_tie = SelectionTieBreaker(*selected, delegation_id);
    for (auto it = std::next(eligible.begin()); it != eligible.end(); ++it) {
        const uint64_t tie = SelectionTieBreaker(*it, delegation_id);
        if (tie < selected_tie) {
            selected = it;
            selected_tie = tie;
        }
    }
    selected->tie_breaker = selected_tie;
    return *selected;
}

bool HasUnderCapQuantumRedelegationCandidate(const std::vector<QuantumRedelegationCandidate>& candidates, CAmount delegation_amount)
{
    return std::any_of(candidates.begin(), candidates.end(), [&](const QuantumRedelegationCandidate& candidate) {
        return IsEligibleCandidate(candidate) && !WouldExceedCap(candidate.total_coldstake, candidate.operator_value, delegation_amount);
    });
}

} // namespace wallet
