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
    if (args.IsArgSet("-shadowwhitelistheight")) {
        const int64_t height = args.GetIntArg("-shadowwhitelistheight", 0);
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -shadowwhitelistheight.", height));
        }
        options.shadow_whitelist_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-shadowgoldrushstartheight")) {
        const int64_t height = args.GetIntArg("-shadowgoldrushstartheight", 0);
        if (height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%d) for -shadowgoldrushstartheight.", height));
        }
        options.shadow_gold_rush_start_height = static_cast<int>(height);
    }
    if (args.IsArgSet("-shadowgoldrushblocks")) {
        const int64_t blocks = args.GetIntArg("-shadowgoldrushblocks", 0);
        if (blocks <= 0 || blocks >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid block count value (%d) for -shadowgoldrushblocks.", blocks));
        }
        options.shadow_gold_rush_blocks = static_cast<int>(blocks);
    }
    if (options.shadow_gold_rush_start_height && *options.shadow_gold_rush_start_height <= options.shadow_whitelist_height.value_or(SHADOW_WHITELIST_HEIGHT)) {
        throw std::runtime_error("-shadowgoldrushstartheight must be greater than -shadowwhitelistheight.");
    }

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
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
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
    case ChainType::TESTNET:
        return CChainParams::TestNet();
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
