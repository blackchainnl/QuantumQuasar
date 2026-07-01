// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/mldsa.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/redelegation.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(quantum_redelegation_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> PubKey(unsigned char tag)
{
    return std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, tag);
}

wallet::QuantumRedelegationCandidate Candidate(uint64_t hash_tag, unsigned char pubkey_tag, CAmount operator_value, bool verified = true, bool current = false, int last_win_height = 0)
{
    wallet::QuantumRedelegationCandidate candidate;
    candidate.staker_pubkey_hash = uint256{static_cast<uint8_t>(hash_tag)};
    candidate.staker_pubkey = PubKey(pubkey_tag);
    candidate.operator_value = operator_value;
    candidate.total_coldstake = 1000 * COIN;
    candidate.last_win_height = last_win_height;
    candidate.operator_commitment_verified = verified;
    candidate.current_operator = current;
    return candidate;
}

} // namespace

BOOST_AUTO_TEST_CASE(trigger_math_clamps_to_policy_bounds)
{
    const wallet::QuantumRedelegationPolicy policy;
    BOOST_CHECK_EQUAL(wallet::QuantumRedelegationTriggerBlocks(100, policy), 600);
    BOOST_CHECK_EQUAL(wallet::QuantumRedelegationTriggerBlocks(1000, policy), 4050);
    BOOST_CHECK_EQUAL(wallet::QuantumRedelegationTriggerBlocks(0, policy), 4050);
    BOOST_CHECK_EQUAL(wallet::QuantumRedelegationTriggerBlocks(1, policy), 300);

    wallet::QuantumRedelegationPolicy drained_policy;
    drained_policy.max_patience_blocks = 10;
    BOOST_CHECK_EQUAL(wallet::QuantumRedelegationTriggerBlocks(1, drained_policy), 300);
}

BOOST_AUTO_TEST_CASE(evaluate_respects_rate_limit_probation_and_jitter)
{
    wallet::QuantumRedelegationPolicy policy;
    policy.stampede_jitter_blocks = 0;

    auto status = wallet::EvaluateQuantumRedelegation(
        /*zero_win_blocks=*/599,
        /*expected_interval_blocks=*/100,
        /*current_height=*/1000,
        /*last_redelegation_height=*/0,
        /*last_successful_redelegation_height=*/0,
        /*target_activation_height=*/0,
        uint256::ONE,
        uint256{2},
        policy);
    BOOST_CHECK(!status.should_redelegate);
    BOOST_CHECK_EQUAL(status.trigger_blocks, 600);

    status = wallet::EvaluateQuantumRedelegation(600, 100, 1000, 0, 0, 0, uint256::ONE, uint256{2}, policy);
    BOOST_CHECK(status.should_redelegate);

    status = wallet::EvaluateQuantumRedelegation(600, 100, 1000, 900, 0, 0, uint256::ONE, uint256{2}, policy);
    BOOST_CHECK(!status.should_redelegate);
    BOOST_CHECK(status.rate_limited);

    status = wallet::EvaluateQuantumRedelegation(600, 100, 1000, 0, 900, 0, uint256::ONE, uint256{2}, policy);
    BOOST_CHECK(!status.should_redelegate);
    BOOST_CHECK(status.success_rate_limited);

    status = wallet::EvaluateQuantumRedelegation(600, 100, 1000, 0, 0, 900, uint256::ONE, uint256{2}, policy);
    BOOST_CHECK(!status.should_redelegate);
    BOOST_CHECK(status.probation);

    policy.stampede_jitter_blocks = 10;
    status = wallet::EvaluateQuantumRedelegation(600, 100, 1000, 0, 0, 0, uint256::ONE, uint256{2}, policy);
    BOOST_CHECK_LE(status.jitter_blocks, 10);
    BOOST_CHECK_GE(status.eligible_height, 1000);
}

BOOST_AUTO_TEST_CASE(candidate_ranking_filters_unsafe_and_biases_smaller_pools)
{
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 100 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/900),
        Candidate(2, 0x12, 50 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/900),
        Candidate(3, 0x13, 10 * COIN, /*verified=*/false, /*current=*/false, /*last_win_height=*/1200),
        Candidate(4, 0x14, 10 * COIN, /*verified=*/true, /*current=*/true, /*last_win_height=*/1200),
        Candidate(5, 0x15, 250 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1300),
    };

    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 1 * COIN);
    BOOST_REQUIRE_EQUAL(ranked.size(), 2);
    BOOST_CHECK_EQUAL(ranked[0].candidate.operator_value, 50 * COIN);
    BOOST_CHECK_EQUAL(ranked[1].candidate.operator_value, 100 * COIN);
    BOOST_CHECK(!ranked[0].would_exceed_cap);
    BOOST_CHECK_LT(ranked[0].share_bps, ranked[1].share_bps);
}

BOOST_AUTO_TEST_CASE(candidate_ranking_prefers_liveness_before_tiny_pool_share)
{
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 1 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/0),
        Candidate(2, 0x12, 150 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1400),
        Candidate(3, 0x13, 120 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1500),
    };

    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 1 * COIN);
    BOOST_REQUIRE_EQUAL(ranked.size(), 3);
    BOOST_CHECK_EQUAL(ranked[0].candidate.staker_pubkey_hash, uint256{3});
    BOOST_CHECK_EQUAL(ranked[1].candidate.staker_pubkey_hash, uint256{2});
    BOOST_CHECK_EQUAL(ranked[2].candidate.staker_pubkey_hash, uint256{1});
}

BOOST_AUTO_TEST_CASE(selection_requires_meaningfully_better_live_target)
{
    wallet::QuantumRedelegationPolicy policy;
    policy.liveness_improvement_blocks = 300;
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 50 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1199),
        Candidate(2, 0x12, 70 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1300),
    };
    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 1 * COIN, policy);

    BOOST_CHECK(!wallet::SelectQuantumRedelegationTarget(ranked, /*source_last_win_height=*/1001, uint256::ONE, policy));
    auto selected = wallet::SelectQuantumRedelegationTarget(ranked, /*source_last_win_height=*/999, uint256::ONE, policy);
    BOOST_REQUIRE(selected);
    BOOST_CHECK_EQUAL(selected->candidate.staker_pubkey_hash, uint256{2});

    BOOST_CHECK(!wallet::SelectQuantumRedelegationTarget(ranked, /*source_last_win_height=*/1500, uint256::ONE, policy));
}

BOOST_AUTO_TEST_CASE(selection_spreads_many_delegations_across_top_live_candidates)
{
    wallet::QuantumRedelegationPolicy policy;
    policy.top_liveness_candidates = 4;
    policy.liveness_improvement_blocks = 1;
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 50 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/2000),
        Candidate(2, 0x12, 60 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1999),
        Candidate(3, 0x13, 70 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1998),
        Candidate(4, 0x14, 80 * COIN, /*verified=*/true, /*current=*/false, /*last_win_height=*/1997),
    };
    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 1 * COIN, policy);

    std::set<uint256> selected_hashes;
    for (uint8_t tag = 1; tag <= 16; ++tag) {
        const auto selected = wallet::SelectQuantumRedelegationTarget(ranked, /*source_last_win_height=*/1000, uint256{tag}, policy);
        BOOST_REQUIRE(selected);
        selected_hashes.insert(selected->candidate.staker_pubkey_hash);
    }
    BOOST_CHECK_GT(selected_hashes.size(), 1U);
}

BOOST_AUTO_TEST_CASE(candidate_ranking_uses_redelegation_denominator)
{
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 199 * COIN),
        Candidate(2, 0x12, 190 * COIN),
    };

    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 2 * COIN);
    BOOST_REQUIRE_EQUAL(ranked.size(), 1);
    BOOST_CHECK_EQUAL(ranked[0].candidate.operator_value, 190 * COIN);
}

BOOST_AUTO_TEST_CASE(candidate_ranking_unlocks_over_cap_when_no_under_cap_exists)
{
    std::vector<wallet::QuantumRedelegationCandidate> candidates{
        Candidate(1, 0x11, 250 * COIN),
        Candidate(2, 0x12, 300 * COIN),
    };

    const auto ranked = wallet::RankQuantumRedelegationCandidates(candidates, 1 * COIN);
    BOOST_REQUIRE_EQUAL(ranked.size(), 2);
    BOOST_CHECK(ranked[0].would_exceed_cap);
    BOOST_CHECK(ranked[1].would_exceed_cap);
    BOOST_CHECK(!wallet::HasUnderCapQuantumRedelegationCandidate(candidates, 1 * COIN));
}

BOOST_AUTO_TEST_CASE(evaluate_saturates_extreme_policy_values)
{
    wallet::QuantumRedelegationPolicy policy;
    policy.trigger_multiplier = std::numeric_limits<int64_t>::max();
    policy.max_patience_blocks = std::numeric_limits<int64_t>::max();
    policy.rate_limit_blocks = std::numeric_limits<int64_t>::max();
    policy.probation_blocks = std::numeric_limits<int64_t>::max();
    policy.stampede_jitter_blocks = std::numeric_limits<int64_t>::max();

    const auto status = wallet::EvaluateQuantumRedelegation(
        /*zero_win_blocks=*/std::numeric_limits<int64_t>::max(),
        /*expected_interval_blocks=*/std::numeric_limits<int64_t>::max(),
        /*current_height=*/std::numeric_limits<int64_t>::max() - 1,
        /*last_redelegation_height=*/std::numeric_limits<int64_t>::max() - 10,
        /*last_successful_redelegation_height=*/std::numeric_limits<int64_t>::max() - 10,
        /*target_activation_height=*/std::numeric_limits<int64_t>::max() - 10,
        uint256::ONE,
        uint256{2},
        policy);
    BOOST_CHECK_EQUAL(status.trigger_blocks, std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(status.eligible_height, std::numeric_limits<int64_t>::max());
    BOOST_CHECK(!status.should_redelegate);
}

BOOST_AUTO_TEST_SUITE_END()
