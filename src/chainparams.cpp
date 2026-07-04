// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <base58.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <logging.h>
#include <key_io.h> // for DecodeDestination()
#include <shadow.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (args.IsArgSet("-signetseednode")) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (args.IsArgSet("-signetchallenge")) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
}

namespace {
//! Shared testnet/regtest parsing for -vbparams deployment overrides.
void ReadVersionBitsArgs(const ArgsManager& args, std::unordered_map<Consensus::DeploymentPos, CChainParams::VersionBitsParameters>& version_bits_parameters)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

//! Shared testnet/regtest parsing for the Gold Rush shadow schedule heights and
//! the height-based phase boundary overrides. `shadow_whitelist_height`,
//! `shadow_gold_rush_start_height` and `shadow_gold_rush_blocks` are stored via
//! the supplied optionals so both TestNetOptions and RegTestOptions reuse it.
void ReadShadowScheduleArgs(const ArgsManager& args,
                            std::optional<int>& shadow_whitelist_height,
                            std::optional<int>& shadow_gold_rush_start_height,
                            std::optional<int>& shadow_gold_rush_blocks,
                            std::optional<int>& shadow_halving_interval_blocks,
                            std::optional<int>& quantum_gold_rush_end_height,
                            std::optional<int>& quantum_migration_end_height,
                            int default_shadow_start_height)
{
    if (args.IsArgSet("-shadowwhitelistheight")) {
        const int64_t height = args.GetIntArg("-shadowwhitelistheight", 0);
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -shadowwhitelistheight.", height));
        }
        shadow_whitelist_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-shadowgoldrushstartheight")) {
        const int64_t height = args.GetIntArg("-shadowgoldrushstartheight", 0);
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -shadowgoldrushstartheight.", height));
        }
        shadow_gold_rush_start_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-shadowgoldrushblocks")) {
        const int64_t blocks = args.GetIntArg("-shadowgoldrushblocks", 0);
        if (blocks <= 0 || blocks >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid block count value (%d) for -shadowgoldrushblocks.", blocks));
        }
        shadow_gold_rush_blocks = static_cast<int>(blocks);
    }
    if (args.IsArgSet("-shadowgoldrushendheight")) {
        if (shadow_gold_rush_blocks) {
            throw std::runtime_error("-shadowgoldrushendheight cannot be combined with -shadowgoldrushblocks.");
        }
        const int64_t end_height = args.GetIntArg("-shadowgoldrushendheight", 0);
        const int64_t start_height = shadow_gold_rush_start_height
            ? *shadow_gold_rush_start_height
            : (shadow_whitelist_height ? *shadow_whitelist_height + 1 : default_shadow_start_height);
        if (end_height < start_height || end_height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -shadowgoldrushendheight; must be >= the Gold Rush start height (%d).", end_height, start_height));
        }
        shadow_gold_rush_blocks = static_cast<int>(end_height - start_height + 1);
        if (!shadow_gold_rush_start_height) shadow_gold_rush_start_height = static_cast<int>(start_height);
    }
    if (args.IsArgSet("-shadowhalvinginterval")) {
        const int64_t blocks = args.GetIntArg("-shadowhalvinginterval", 0);
        if (blocks <= 0 || blocks >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid block count value (%d) for -shadowhalvinginterval.", blocks));
        }
        shadow_halving_interval_blocks = static_cast<int>(blocks);
    }
    if (args.IsArgSet("-qqgoldrushendheight")) {
        const int64_t height = args.GetIntArg("-qqgoldrushendheight", 0);
        if (height <= 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -qqgoldrushendheight.", height));
        }
        quantum_gold_rush_end_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-qqmigrationendheight")) {
        const int64_t height = args.GetIntArg("-qqmigrationendheight", 0);
        if (height <= 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -qqmigrationendheight.", height));
        }
        quantum_migration_end_height = static_cast<int>(height);
    }
    if (quantum_gold_rush_end_height && quantum_migration_end_height &&
        *quantum_migration_end_height <= *quantum_gold_rush_end_height) {
        throw std::runtime_error("-qqmigrationendheight must be greater than -qqgoldrushendheight.");
    }
}
} // namespace

void ReadTestNetArgs(const ArgsManager& args, CChainParams::TestNetOptions& options)
{
    if (args.IsArgSet("-qqv4time")) {
        options.quantum_v4_time = args.GetIntArg("-qqv4time", 0);
    }
    if (args.IsArgSet("-qqgoldrushendtime")) {
        options.quantum_gold_rush_end_time = args.GetIntArg("-qqgoldrushendtime", 0);
    }
    if (args.IsArgSet("-qqmigrationdeadlinetime")) {
        options.quantum_migration_deadline_time = args.GetIntArg("-qqmigrationdeadlinetime", 0);
    }
    ReadShadowScheduleArgs(args,
                           options.shadow_whitelist_height,
                           options.shadow_gold_rush_start_height,
                           options.shadow_gold_rush_blocks,
                           options.shadow_halving_interval_blocks,
                           options.quantum_gold_rush_end_height,
                           options.quantum_migration_end_height,
                           SHADOW_REWARD_START_HEIGHT);
    if (options.shadow_gold_rush_start_height && *options.shadow_gold_rush_start_height <= options.shadow_whitelist_height.value_or(SHADOW_WHITELIST_HEIGHT)) {
        throw std::runtime_error("-shadowgoldrushstartheight must be greater than -shadowwhitelistheight.");
    }
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }
        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }
        const auto deployment_name{arg.substr(0, found)};
        if (deployment_name == "segwit") {
            options.segwit_activation_height = height;
        } else {
            throw std::runtime_error(strprintf("Only segwit supports -testactivationheight on testnet, not (%s).", deployment_name));
        }
    }
    ReadVersionBitsArgs(args, options.version_bits_parameters);
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (deployment_name == "segwit") {
            options.segwit_activation_height = height;
            continue;
        }
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& arg : args.GetArgs("-testcheckpoint")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testcheckpoint=height@hash.", arg));
        }

        const auto height_value{arg.substr(0, found)};
        int32_t height;
        if (!ParseInt32(height_value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testcheckpoint=height@hash.", arg));
        }

        const auto hash_value{arg.substr(found + 1)};
        if (hash_value.size() != 64 || !IsHex(hash_value)) {
            throw std::runtime_error(strprintf("Invalid hash value (%s) for -testcheckpoint=height@hash.", arg));
        }

        options.checkpoint_overrides[height] = uint256S(hash_value);
    }

    // Quantum Quasar phase-time overrides (regtest-only) for deterministic functional tests.
    if (args.IsArgSet("-qqv4time")) {
        options.quantum_v4_time = args.GetIntArg("-qqv4time", 0);
    }
    if (args.IsArgSet("-qqgoldrushendtime")) {
        options.quantum_gold_rush_end_time = args.GetIntArg("-qqgoldrushendtime", 0);
    }
    if (args.IsArgSet("-qqmigrationdeadlinetime")) {
        options.quantum_migration_deadline_time = args.GetIntArg("-qqmigrationdeadlinetime", 0);
    }
    if (args.IsArgSet("-qqstaketierheight")) {
        const int64_t height = args.GetIntArg("-qqstaketierheight", std::numeric_limits<int>::max());
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -qqstaketierheight.", height));
        }
        options.quantum_stake_tiers_activation_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-qqstakesplitheight")) {
        const int64_t height = args.GetIntArg("-qqstakesplitheight", std::numeric_limits<int>::max());
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -qqstakesplitheight.", height));
        }
        options.quantum_stake_reward_split_activation_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-qqdemurrageheight")) {
        const int64_t height = args.GetIntArg("-qqdemurrageheight", std::numeric_limits<int>::max());
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -qqdemurrageheight.", height));
        }
        options.quantum_demurrage_activation_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-qqdemurrageblockspermonth")) {
        const int64_t blocks = args.GetIntArg("-qqdemurrageblockspermonth", 40500);
        if (blocks <= 0 || blocks > 40500) {
            throw std::runtime_error(strprintf("Invalid block count value (%d) for -qqdemurrageblockspermonth.", blocks));
        }
        options.quantum_demurrage_blocks_per_month = static_cast<int>(blocks);
    }
    ReadShadowScheduleArgs(args,
                           options.shadow_whitelist_height,
                           options.shadow_gold_rush_start_height,
                           options.shadow_gold_rush_blocks,
                           options.shadow_halving_interval_blocks,
                           options.quantum_gold_rush_end_height,
                           options.quantum_migration_end_height,
                           options.shadow_whitelist_height.value_or(SHADOW_WHITELIST_HEIGHT) + 1);
    if (options.shadow_gold_rush_start_height && *options.shadow_gold_rush_start_height <= options.shadow_whitelist_height.value_or(SHADOW_WHITELIST_HEIGHT)) {
        throw std::runtime_error("-shadowgoldrushstartheight must be greater than -shadowwhitelistheight.");
    }

    ReadVersionBitsArgs(args, options.version_bits_parameters);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET: {
        auto opts = CChainParams::TestNetOptions{};
        ReadTestNetArgs(args, opts);
        return CChainParams::TestNet(opts);
    }
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}

// Blackcoin: Donations to dev fund 
std::string CChainParams::GetDevFundAddress() const
{
    return !vDevFundAddress.empty() ? vDevFundAddress[0] : "";
}

CScript CChainParams::GetDevRewardScript() const
{
    CTxDestination dest = DecodeDestination(GetDevFundAddress());
    CScript scriptPubKey = GetScriptForDestination(dest);
    return scriptPubKey;
}
