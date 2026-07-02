// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/quantum_pool.h>

#include <addresstype.h>
#include <arith_uint256.h>
#include <coins.h>
#include <crypto/mldsa.h>
#include <sync.h>
#include <util/check.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <utility>

namespace node {
namespace {

struct QuantumPoolOperatorRecord
{
    std::vector<unsigned char> staker_pubkey;
    std::vector<QuantumPoolClaim> claims;
    bool operator_commitment_verified{false};
    COutPoint operator_commitment_outpoint;
};

GlobalMutex g_quantum_pool_mutex;
std::map<uint256, QuantumPoolOperatorRecord> g_quantum_pool_registry GUARDED_BY(g_quantum_pool_mutex);

uint256 Uint256FromBytes(const std::vector<unsigned char>& bytes)
{
    Assume(bytes.size() == uint256::size());
    uint256 value;
    std::copy(bytes.begin(), bytes.end(), value.begin());
    return value;
}

arith_uint256 AmountToArith(CAmount value)
{
    Assume(value >= 0);
    return arith_uint256{static_cast<uint64_t>(value)};
}

} // namespace

uint256 QuantumPoolHashPubKey(const std::vector<unsigned char>& pubkey)
{
    Assume(pubkey.size() == ML_DSA::PUBLICKEY_BYTES);
    return Uint256FromBytes(QuantumMigrationProgramForPubkey(pubkey));
}

CScript QuantumPoolScriptForClaim(const QuantumPoolClaim& claim)
{
    const std::vector<unsigned char> program = claim.tiered
        ? QuantumTieredColdStakeProgramForKeyHashes(
              claim.staker_pubkey_hash,
              claim.owner_pubkey_hash,
              claim.state,
              claim.unbonding_blocks,
              claim.unlock_height)
        : QuantumColdStakeProgramForKeyHashes(claim.staker_pubkey_hash, claim.owner_pubkey_hash);
    return GetScriptForDestination(WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, program});
}

CScript QuantumPoolOperatorCommitmentScript(const std::vector<unsigned char>& staker_pubkey)
{
    const std::vector<unsigned char> program = QuantumTieredMigrationProgramForPubkey(
        staker_pubkey, QUANTUM_TIERED_STATE_BONDED, /*unbonding_blocks=*/40500, /*unlock_height=*/0);
    return GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, program});
}

CAmount ComputeQuantumColdStakeTotal(const CCoinsView& view)
{
    CAmount total{0};
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    if (!cursor) return total;

    for (; cursor->Valid(); cursor->Next()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin) || coin.IsSpent()) continue;
        if (!IsQuantumColdStakeScript(coin.out.scriptPubKey)) continue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(total + coin.out.nValue)) continue;
        total += coin.out.nValue;
    }
    return total;
}

QuantumPoolClaimResult VerifyQuantumPoolClaim(const CCoinsView& view, const QuantumPoolClaim& claim)
{
    QuantumPoolClaimResult result;
    if (claim.outpoint.IsNull()) {
        result.reject_reason = "missing-outpoint";
        return result;
    }

    Coin coin;
    if (!view.GetCoin(claim.outpoint, coin) || coin.IsSpent()) {
        result.reject_reason = "missing-utxo";
        return result;
    }

    if (!MoneyRange(coin.out.nValue)) {
        result.reject_reason = "invalid-amount";
        return result;
    }

    const CScript expected = QuantumPoolScriptForClaim(claim);
    if (coin.out.scriptPubKey != expected) {
        result.reject_reason = "commitment-mismatch";
        return result;
    }

    result.valid = true;
    result.value = coin.out.nValue;
    return result;
}

bool VerifyQuantumPoolOperatorCommitment(const CCoinsView& view, const std::vector<unsigned char>& staker_pubkey, const COutPoint& outpoint)
{
    if (staker_pubkey.size() != ML_DSA::PUBLICKEY_BYTES || outpoint.IsNull()) return false;

    Coin coin;
    if (!view.GetCoin(outpoint, coin) || coin.IsSpent() || !MoneyRange(coin.out.nValue) || coin.out.nValue <= 0) {
        return false;
    }
    return coin.out.scriptPubKey == QuantumPoolOperatorCommitmentScript(staker_pubkey);
}

QuantumPoolShare ComputeQuantumPoolShare(const CCoinsView& view, const uint256& staker_pubkey_hash, const std::vector<QuantumPoolClaim>& claims)
{
    QuantumPoolShare share;
    share.total_coldstake = ComputeQuantumColdStakeTotal(view);
    share.operator_share.staker_pubkey_hash = staker_pubkey_hash;
    share.operator_share.staker_pubkey = GetQuantumPoolOperatorPubKey(staker_pubkey_hash);
    share.operator_share.operator_commitment_verified = IsQuantumPoolOperatorCommitmentVerified(staker_pubkey_hash);

    std::set<COutPoint> seen;
    for (const QuantumPoolClaim& claim : claims) {
        if (claim.staker_pubkey_hash != staker_pubkey_hash || !seen.insert(claim.outpoint).second) {
            ++share.operator_share.invalid_claims;
            continue;
        }
        const QuantumPoolClaimResult verified = VerifyQuantumPoolClaim(view, claim);
        if (!verified.valid) {
            ++share.operator_share.invalid_claims;
            continue;
        }
        if (MoneyRange(share.operator_share.verified_value + verified.value)) {
            share.operator_share.verified_value += verified.value;
            ++share.operator_share.verified_claims;
        } else {
            ++share.operator_share.invalid_claims;
        }
    }
    return share;
}

int64_t QuantumPoolShareBps(CAmount value, CAmount total)
{
    if (value <= 0 || total <= 0) return 0;
    arith_uint256 scaled = AmountToArith(value) * static_cast<uint32_t>(QUANTUM_POOL_BPS_DENOMINATOR);
    scaled /= AmountToArith(total);
    return static_cast<int64_t>(scaled.GetLow64());
}

bool WouldQuantumPoolExceedCap(CAmount total_coldstake, CAmount operator_value, CAmount inflow, int64_t cap_bps)
{
    if (cap_bps < 0 || cap_bps > QUANTUM_POOL_BPS_DENOMINATOR) return false;
    if (inflow < 0 || operator_value < 0 || total_coldstake < 0) return false;
    if (!MoneyRange(operator_value + inflow) || !MoneyRange(total_coldstake + inflow)) return true;

    const CAmount post_operator = operator_value + inflow;
    const CAmount post_total = total_coldstake + inflow;
    if (post_operator <= 0 || post_total <= 0) return false;

    const arith_uint256 left = AmountToArith(post_operator) * static_cast<uint32_t>(QUANTUM_POOL_BPS_DENOMINATOR);
    const arith_uint256 right = AmountToArith(post_total) * static_cast<uint32_t>(cap_bps);
    return left > right;
}

bool HasQuantumPoolUnderCapCandidate(const CCoinsView& view, CAmount inflow, const std::vector<uint256>& excluded_staker_hashes)
{
    for (const uint256& staker_hash : ListQuantumPoolOperators()) {
        if (std::find(excluded_staker_hashes.begin(), excluded_staker_hashes.end(), staker_hash) != excluded_staker_hashes.end()) {
            continue;
        }
        const QuantumPoolShare share = ComputeQuantumPoolShare(view, staker_hash, GetQuantumPoolClaims(staker_hash));
        if (!share.operator_share.operator_commitment_verified || share.operator_share.staker_pubkey.empty()) {
            continue;
        }
        if (!WouldQuantumPoolExceedCap(share.total_coldstake, share.operator_share.verified_value, inflow)) {
            return true;
        }
    }
    return false;
}

void ClearQuantumPoolRegistry()
{
    LOCK(g_quantum_pool_mutex);
    g_quantum_pool_registry.clear();
}

void UpsertQuantumPoolClaims(const uint256& staker_pubkey_hash, std::vector<QuantumPoolClaim> claims)
{
    UpsertQuantumPoolOperator(staker_pubkey_hash, {}, std::move(claims));
}

void UpsertQuantumPoolOperator(const uint256& staker_pubkey_hash, std::vector<unsigned char> staker_pubkey, std::vector<QuantumPoolClaim> claims, bool operator_commitment_verified, COutPoint operator_commitment_outpoint)
{
    LOCK(g_quantum_pool_mutex);
    const auto existing = g_quantum_pool_registry.find(staker_pubkey_hash);
    if (existing != g_quantum_pool_registry.end()) {
        if (staker_pubkey.empty()) {
            staker_pubkey = existing->second.staker_pubkey;
        }
        if (!operator_commitment_verified && existing->second.operator_commitment_verified) {
            operator_commitment_verified = true;
            operator_commitment_outpoint = existing->second.operator_commitment_outpoint;
        }
    }
    QuantumPoolOperatorRecord record;
    record.staker_pubkey = std::move(staker_pubkey);
    record.claims = std::move(claims);
    record.operator_commitment_verified = operator_commitment_verified;
    record.operator_commitment_outpoint = operator_commitment_outpoint;
    g_quantum_pool_registry[staker_pubkey_hash] = std::move(record);
}

std::vector<QuantumPoolClaim> GetQuantumPoolClaims(const uint256& staker_pubkey_hash)
{
    LOCK(g_quantum_pool_mutex);
    const auto it = g_quantum_pool_registry.find(staker_pubkey_hash);
    if (it == g_quantum_pool_registry.end()) return {};
    return it->second.claims;
}

std::vector<unsigned char> GetQuantumPoolOperatorPubKey(const uint256& staker_pubkey_hash)
{
    LOCK(g_quantum_pool_mutex);
    const auto it = g_quantum_pool_registry.find(staker_pubkey_hash);
    if (it == g_quantum_pool_registry.end()) return {};
    return it->second.staker_pubkey;
}

bool IsQuantumPoolOperatorCommitmentVerified(const uint256& staker_pubkey_hash)
{
    LOCK(g_quantum_pool_mutex);
    const auto it = g_quantum_pool_registry.find(staker_pubkey_hash);
    if (it == g_quantum_pool_registry.end()) return false;
    return it->second.operator_commitment_verified;
}

std::vector<uint256> ListQuantumPoolOperators()
{
    LOCK(g_quantum_pool_mutex);
    std::vector<uint256> operators;
    operators.reserve(g_quantum_pool_registry.size());
    for (const auto& [staker_pubkey_hash, claims] : g_quantum_pool_registry) {
        operators.push_back(staker_pubkey_hash);
    }
    return operators;
}

} // namespace node
