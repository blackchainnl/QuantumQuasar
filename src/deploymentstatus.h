// Copyright (c) 2020-2022 Blackcoin Core Developers
// Copyright (c) 2020-2022 Blackcoin More Developers
// Copyright (c) 2020-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>

inline bool HasSegwitHeightOverride(const Consensus::Params& params)
{
    return params.SegwitHeight != std::numeric_limits<int>::max();
}

inline bool SegwitHeightActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= params.SegwitHeight;
}

inline bool SegwitHeightActiveAt(const CBlockIndex& index, const Consensus::Params& params)
{
    return index.nHeight >= params.SegwitHeight;
}

/** Determine if a deployment is active for the next block */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (dep == Consensus::DEPLOYMENT_SEGWIT && HasSegwitHeightOverride(params)) {
        return SegwitHeightActiveAfter(pindexPrev, params);
    }
    return ThresholdState::ACTIVE == versionbitscache.State(pindexPrev, params, dep);
}

/** Determine if a deployment is active for this block */
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (dep == Consensus::DEPLOYMENT_SEGWIT && HasSegwitHeightOverride(params)) {
        return SegwitHeightActiveAt(index, params);
    }
    return DeploymentActiveAfter(index.pprev, params, dep, versionbitscache);
}

/** Determine if a deployment is enabled (can ever be active) */
inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return params.DeploymentHeight(dep) != std::numeric_limits<int>::max();
}

inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    if (dep == Consensus::DEPLOYMENT_SEGWIT && HasSegwitHeightOverride(params)) return true;
    return params.vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
