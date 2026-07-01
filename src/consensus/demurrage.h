// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BLACKCOIN_CONSENSUS_DEMURRAGE_H
#define BLACKCOIN_CONSENSUS_DEMURRAGE_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class Coin;
class CCoinsViewCache;
class CScript;
class CTransaction;

namespace Consensus {
struct Params;

static constexpr int DEMURRAGE_BLOCKS_PER_MONTH = 40500;
static constexpr int DEMURRAGE_GRACE_BLOCKS = 6 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int DEMURRAGE_ZERO_BLOCKS = 24 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int DEMURRAGE_DECAY_WINDOW_BLOCKS = DEMURRAGE_ZERO_BLOCKS - DEMURRAGE_GRACE_BLOCKS;
static constexpr int DEMURRAGE_ATTEST_VALIDITY_BLOCKS = DEMURRAGE_GRACE_BLOCKS;
static constexpr int DEMURRAGE_AUTO_ATTEST_BLOCKS = 3 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int64_t DEMURRAGE_PPM = 1000000;

struct DemurrageEvaluation {
    bool active{false};
    bool exempt{false};
    bool locked{false};
    int inactive_blocks{0};
    int64_t remaining_ppm{DEMURRAGE_PPM};
    CAmount nominal_value{0};
    CAmount effective_value{0};
    CAmount burned_value{0};
    std::string exemption;
};

struct DemurrageAttestation {
    int height{0};
    uint32_t output_index{0};
    COutPoint replay_anchor;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> signature;
    uint256 pubkey_hash;
};

int64_t DemurrageRemainingPpm(int inactive_blocks);
int64_t DemurrageRemainingPpm(int inactive_blocks, const Params& params);
CAmount DemurrageEffectiveValue(CAmount nominal_value, int64_t remaining_ppm);
bool IsDemurrageTreasuryExemptScript(const CScript& script_pub_key, const Params& params);
uint256 DemurragePubKeyHash(const std::vector<unsigned char>& pubkey);
uint256 DemurrageAttestationMessageHash(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey);
std::vector<unsigned char> EncodeDemurrageAttestationPayload(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& signature);
CScript BuildDemurrageAttestationScript(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& signature);
bool IsDemurrageAttestationScript(const CScript& script_pub_key);
bool DecodeDemurrageAttestationPayload(const std::vector<unsigned char>& payload, DemurrageAttestation& attestation);
std::vector<DemurrageAttestation> ExtractDemurrageAttestations(const CTransaction& tx);
std::optional<uint256> DemurrageControllingKeyHashForScript(const CScript& script_pub_key);
std::optional<int> LatestDemurrageAttestationHeight(const CCoinsViewCache& view, const uint256& pubkey_hash);
std::optional<int> LatestDemurrageAttestationHeightForScript(const CCoinsViewCache& view, const CScript& script_pub_key);

bool ApplyDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params, std::string& reject_reason);
bool UndoDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params);
CAmount GetDemurrageAdjustedValueIn(const CTransaction& tx, const CCoinsViewCache& inputs, const Params& params, int spend_height, int64_t spend_time);

DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time,
    std::optional<int> latest_attestation_height = std::nullopt);

} // namespace Consensus

#endif // BLACKCOIN_CONSENSUS_DEMURRAGE_H
