// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/consensus.h>
#include <script/script.h>
#include <uint256.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_CSV = std::numeric_limits<int16_t>::min(),
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_CSV; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_SEGWIT, // Deployment of SegWit (BIP141, BIP143, and BIP147)
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    DEPLOYMENT_QUANTUM_QUASAR, // Readiness signalling for the V4 hard-fork schedule
    DEPLOYMENT_QUANTUM_MIGRATION, // Readiness signalling for the post-quantum migration deadline
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

enum class QuantumQuasarPhase : uint8_t {
    LEGACY,
    GOLD_RUSH,
    MIGRATION,
    FINAL_LOCKOUT,
};

static constexpr int64_t QUANTUM_QUASAR_GOLD_RUSH_SECONDS = 180 * 24 * 60 * 60;
static constexpr int64_t QUANTUM_QUASAR_MIGRATION_SECONDS = 540 * 24 * 60 * 60;
static constexpr int64_t QUANTUM_QUASAR_MAINNET_V4_TIME = 1783835299; // Expected mainnet height 5,950,000 (2026-07-12 05:48:19 UTC)

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nMaxReorganizationDepth;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV activation. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nTargetTimespan / nTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 posLimit;
    uint256 posLimitV2;
    bool fPowAllowMinDifficultyBlocks;
    int64_t nTargetSpacingV1;
    bool fPowNoRetargeting;
    bool fPoSNoRetargeting;
    int64_t nTargetSpacing;
    int64_t nTargetTimespan;
    std::chrono::seconds TargetSpacing() const
    {
        return std::chrono::seconds{nTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nTargetTimespan / nTargetSpacing; }
    int64_t nProtocolV1RetargetingFixedTime;
    int64_t nProtocolV2Time;
    int64_t nProtocolV3Time;
    int64_t nProtocolV3_1Time;
    int64_t nProtocolV4Time;
    int64_t nGoldRushEndTime;
    int64_t nQuantumMigrationDeadlineTime;
    /** Optional height-based phase boundaries (testnet/regtest schedule overrides only;
     *  0 = disabled, phase boundaries stay time-based). When set, the block AT the
     *  boundary height is the last block of its phase, matching the inclusive
     *  SHADOW_REWARD_END_HEIGHT reward-window semantics. Mainnet never sets these. */
    int nGoldRushEndHeight{0};
    int nQuantumMigrationEndHeight{0};
    uint32_t nQuantumSighashChainId{0};
    int nStakeTierActivationHeight{std::numeric_limits<int>::max()};
    int nStakeRewardSplitActivationHeight{std::numeric_limits<int>::max()};
    int nDemurrageActivationHeight{std::numeric_limits<int>::max()};
    int nDemurrageMinActivationHeight{0};
    int nDemurrageBlocksPerMonth{40500};
    std::vector<CScript> m_demurrage_exempt_scripts{};
    bool IsProtocolV1RetargetingFixed(int64_t nTime) const { return nTime > nProtocolV1RetargetingFixedTime && nTime != 1395631999; }
    bool IsProtocolV2(int64_t nTime) const { return nTime > nProtocolV2Time && nTime != 1407053678; }
    bool IsProtocolV3(int64_t nTime) const { return nTime > nProtocolV3Time && nTime != 1444028400; }
    bool IsProtocolV3_1(int64_t nTime) const { return nTime > nProtocolV3_1Time && nTime != 1713938400; }
    bool IsProtocolV4(int64_t nTime) const { return nTime > nProtocolV4Time; }
    /** Phase boundary primitives. nTime is the median-time-past context the caller already
     *  uses for phase decisions; nHeight is the height of the block being evaluated (for
     *  next-block/mempool contexts: tip height + 1; for tip-status contexts: tip height).
     *  When a height override is set (testnet/regtest schedule branch) the height is
     *  authoritative and the paired time is ignored for that boundary. */
    bool IsGoldRushEndScheduled() const { return nGoldRushEndHeight > 0 || nGoldRushEndTime != 0; }
    bool IsMigrationEndScheduled() const { return nQuantumMigrationEndHeight > 0 || nQuantumMigrationDeadlineTime != 0; }
    bool GoldRushEndPassed(int64_t nTime, int nHeight) const
    {
        if (nGoldRushEndHeight > 0) return nHeight > nGoldRushEndHeight;
        return nGoldRushEndTime != 0 && nTime > nGoldRushEndTime;
    }
    bool MigrationDeadlinePassed(int64_t nTime, int nHeight) const
    {
        if (nQuantumMigrationEndHeight > 0) return nHeight > nQuantumMigrationEndHeight;
        return nQuantumMigrationDeadlineTime != 0 && nTime > nQuantumMigrationDeadlineTime;
    }
    bool IsQuantumFinalLockout(int64_t nTime, int nHeight) const { return IsProtocolV4(nTime) && IsMigrationEndScheduled() && MigrationDeadlinePassed(nTime, nHeight); }
    bool IsGoldRushEpoch(int64_t nTime, int nHeight) const { return IsProtocolV4(nTime) && !IsQuantumFinalLockout(nTime, nHeight) && !GoldRushEndPassed(nTime, nHeight); }
    bool IsQuantumMigrationWindow(int64_t nTime, int nHeight) const { return IsProtocolV4(nTime) && !IsGoldRushEpoch(nTime, nHeight) && !IsQuantumFinalLockout(nTime, nHeight) && IsGoldRushEndScheduled() && GoldRushEndPassed(nTime, nHeight) && !MigrationDeadlinePassed(nTime, nHeight); }
    bool IsQuantumSpendEnforcementActive(int64_t nTime, int nHeight) const { return IsQuantumMigrationWindow(nTime, nHeight) || IsQuantumFinalLockout(nTime, nHeight); }
    bool IsQuantumStakeRulesActive(int64_t nTime, int nHeight) const { return IsQuantumSpendEnforcementActive(nTime, nHeight); }
    bool IsNewNetworkStakeOnly(int64_t nTime, int nHeight) const { return IsQuantumFinalLockout(nTime, nHeight); }
    bool IsBaseNetworkStakeCompatible(int64_t nTime, int nHeight) const { return !IsNewNetworkStakeOnly(nTime, nHeight); }
    bool IsStakeTiersActive(int nHeight) const { return nHeight >= nStakeTierActivationHeight; }
    bool IsStakeRewardSplitActive(int nHeight) const { return nHeight >= nStakeRewardSplitActivationHeight; }
    int EffectiveDemurrageActivationHeight() const { return std::max(nDemurrageActivationHeight, nDemurrageMinActivationHeight); }
    int DemurrageBlocksPerMonth() const { return std::max(1, nDemurrageBlocksPerMonth); }
    int DemurrageGraceBlocks() const { return 6 * DemurrageBlocksPerMonth(); }
    int DemurrageZeroBlocks() const { return 24 * DemurrageBlocksPerMonth(); }
    int DemurrageDecayWindowBlocks() const { return DemurrageZeroBlocks() - DemurrageGraceBlocks(); }
    int DemurrageAutoAttestBlocks() const { return 3 * DemurrageBlocksPerMonth(); }
    bool IsDemurrageActive(int nHeight, int64_t nParentMedianTimePast) const
    {
        return IsMigrationEndScheduled() &&
               MigrationDeadlinePassed(nParentMedianTimePast, nHeight) &&
               nHeight >= EffectiveDemurrageActivationHeight();
    }
    QuantumQuasarPhase GetQuantumQuasarPhase(int64_t nTime, int nHeight) const
    {
        if (!IsProtocolV4(nTime)) return QuantumQuasarPhase::LEGACY;
        if (IsGoldRushEpoch(nTime, nHeight)) return QuantumQuasarPhase::GOLD_RUSH;
        if (IsQuantumMigrationWindow(nTime, nHeight)) return QuantumQuasarPhase::MIGRATION;
        return QuantumQuasarPhase::FINAL_LOCKOUT;
    }
    int nLastPOWBlock;
    int nStakeTimestampMask;
    int nCoinbaseMaturity;
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_CSV:
            return CSVHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
