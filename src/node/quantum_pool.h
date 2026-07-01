// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_QUANTUM_POOL_H
#define BITCOIN_NODE_QUANTUM_POOL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CCoinsView;

namespace node {

static constexpr int64_t QUANTUM_POOL_CAP_BPS = 2000;
static constexpr int64_t QUANTUM_POOL_BPS_DENOMINATOR = 10000;

struct QuantumPoolClaim
{
    COutPoint outpoint;
    uint256 staker_pubkey_hash;
    uint256 owner_pubkey_hash;
    bool tiered{false};
    unsigned char state{0};
    uint16_t unbonding_blocks{0};
    uint32_t unlock_height{0};
};

struct QuantumPoolClaimResult
{
    bool valid{false};
    CAmount value{0};
    std::string reject_reason;
};

struct QuantumPoolOperatorShare
{
    uint256 staker_pubkey_hash;
    std::vector<unsigned char> staker_pubkey;
    CAmount verified_value{0};
    int verified_claims{0};
    int invalid_claims{0};
    bool operator_commitment_verified{false};
    COutPoint operator_commitment_outpoint;
};

struct QuantumPoolShare
{
    CAmount total_coldstake{0};
    QuantumPoolOperatorShare operator_share;
};

uint256 QuantumPoolHashPubKey(const std::vector<unsigned char>& pubkey);
CScript QuantumPoolScriptForClaim(const QuantumPoolClaim& claim);
CScript QuantumPoolOperatorCommitmentScript(const std::vector<unsigned char>& staker_pubkey);
CAmount ComputeQuantumColdStakeTotal(const CCoinsView& view);
QuantumPoolClaimResult VerifyQuantumPoolClaim(const CCoinsView& view, const QuantumPoolClaim& claim);
bool VerifyQuantumPoolOperatorCommitment(const CCoinsView& view, const std::vector<unsigned char>& staker_pubkey, const COutPoint& outpoint);
QuantumPoolShare ComputeQuantumPoolShare(const CCoinsView& view, const uint256& staker_pubkey_hash, const std::vector<QuantumPoolClaim>& claims);
int64_t QuantumPoolShareBps(CAmount value, CAmount total);
bool WouldQuantumPoolExceedCap(CAmount total_coldstake, CAmount operator_value, CAmount inflow, int64_t cap_bps = QUANTUM_POOL_CAP_BPS);
bool HasQuantumPoolUnderCapCandidate(const CCoinsView& view, CAmount inflow, const std::vector<uint256>& excluded_staker_hashes = {});

void ClearQuantumPoolRegistry();
void UpsertQuantumPoolClaims(const uint256& staker_pubkey_hash, std::vector<QuantumPoolClaim> claims);
void UpsertQuantumPoolOperator(const uint256& staker_pubkey_hash, std::vector<unsigned char> staker_pubkey, std::vector<QuantumPoolClaim> claims, bool operator_commitment_verified = false, COutPoint operator_commitment_outpoint = {});
std::vector<QuantumPoolClaim> GetQuantumPoolClaims(const uint256& staker_pubkey_hash);
std::vector<unsigned char> GetQuantumPoolOperatorPubKey(const uint256& staker_pubkey_hash);
bool IsQuantumPoolOperatorCommitmentVerified(const uint256& staker_pubkey_hash);
std::vector<uint256> ListQuantumPoolOperators();

} // namespace node

#endif // BITCOIN_NODE_QUANTUM_POOL_H
