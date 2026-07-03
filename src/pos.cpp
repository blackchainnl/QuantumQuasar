// Copyright (c) 2014-2018 The BlackCoin Developers
// Copyright (c) 2011-2013 The PPCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stake cache by Qtum
// Copyright (c) 2016-2018 The Qtum developers

#include <pos.h>
#include <addresstype.h>
#include <txdb.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <timedata.h>
#include <validation.h>
#include <arith_uint256.h>
#include <crypto/common.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <consensus/consensus.h>
#include <shadow.h>
#include <test/data/staking_mr_table.h>

#include <algorithm>
#include <array>
#include <optional>
#include <stdio.h>

using namespace std;

uint16_t StakeWeightMultiplierPpm10k(int remaining_unbonding_blocks)
{
    const int clamped = std::clamp(remaining_unbonding_blocks, 0, blackcoin_staking_canonical::kNvMaxBlocks);
    return blackcoin_staking_canonical::kStakingMrPpm10k[clamped];
}

arith_uint256 EffectiveStakeWeight(CAmount nValueIn, uint16_t m_ppm10k, uint16_t pool_ppm10k)
{
    if (nValueIn <= 0) return arith_uint256(0);

    const uint16_t m = std::min<uint16_t>(m_ppm10k, blackcoin_staking_canonical::kFullPpm10k);
    const uint16_t pool = std::min<uint16_t>(pool_ppm10k, blackcoin_staking_canonical::kFullPpm10k);

    arith_uint256 weight = arith_uint256(static_cast<uint64_t>(nValueIn));
    weight *= arith_uint256(m);
    weight /= arith_uint256(10000);
    weight *= arith_uint256(pool);
    weight /= arith_uint256(10000);
    return weight;
}

CAmount GetKernelStakeValue(const Coin& coin, const CCoinsViewCache& view, const Consensus::Params& consensus, int spend_height, int64_t spend_time)
{
    if (!consensus.IsDemurrageActive(spend_height, spend_time)) return coin.out.nValue;

    const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, coin.out.scriptPubKey);
    const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin, consensus, spend_height, spend_time, latest_attestation);
    return eval.effective_value;
}

namespace {
std::array<uint32_t, 8> Uint256ToWordsLE(const uint256& value)
{
    std::array<uint32_t, 8> words{};
    for (size_t i = 0; i < words.size(); ++i) {
        words[i] = ReadLE32(value.begin() + i * 4);
    }
    return words;
}

std::array<uint32_t, 16> Multiply512(const arith_uint256& a, const arith_uint256& b)
{
    const auto aw = Uint256ToWordsLE(ArithToUint256(a));
    const auto bw = Uint256ToWordsLE(ArithToUint256(b));
    std::array<uint32_t, 16> product{};

    for (size_t i = 0; i < aw.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < bw.size(); ++j) {
            const uint64_t n = static_cast<uint64_t>(product[i + j]) +
                               static_cast<uint64_t>(aw[i]) * bw[j] +
                               carry;
            product[i + j] = static_cast<uint32_t>(n);
            carry = n >> 32;
        }
        size_t k = i + bw.size();
        while (carry != 0 && k < product.size()) {
            const uint64_t n = static_cast<uint64_t>(product[k]) + carry;
            product[k] = static_cast<uint32_t>(n);
            carry = n >> 32;
            ++k;
        }
    }

    return product;
}
} // namespace

bool KernelProductLE(const arith_uint256& bnTarget, const arith_uint256& bnWeight, const uint256& hashProofOfStake)
{
    const auto product = Multiply512(bnTarget, bnWeight);
    const auto hash = Uint256ToWordsLE(hashProofOfStake);

    for (size_t i = 8; i < product.size(); ++i) {
        if (product[i] != 0) return true;
    }

    for (int i = 7; i >= 0; --i) {
        if (hash[i] < product[i]) return true;
        if (hash[i] > product[i]) return false;
    }
    return true;
}

StakeWeightContext GetStakeWeightContext(const CScript& scriptPubKey, const CTxIn* stake_input, int candidate_height, bool stake_tiers_active)
{
    (void)stake_input;
    StakeWeightContext context;
    if (!stake_tiers_active) return context;

    context.stake_tiers_active = true;
    context.multiplier_ppm10k = blackcoin_staking_canonical::kLiquidPpm10k;
    context.pool_ppm10k = IsQuantumColdStakeScript(scriptPubKey)
        ? blackcoin_staking_canonical::kPoolStakerPpm10k
        : blackcoin_staking_canonical::kPoolOwnerPpm10k;

    const std::optional<QuantumStakeTierProgram> tier = GetQuantumStakeTierProgram(scriptPubKey);
    if (tier && tier->tiered) {
        context.effective_unbonding_blocks = tier->EffectiveUnbondingBlocks(candidate_height);
        context.multiplier_ppm10k = StakeWeightMultiplierPpm10k(context.effective_unbonding_blocks);
    }
    return context;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
uint256 ComputeStakeModifier(const CBlockIndex* pindexPrev, const uint256& kernel)
{
    if (!pindexPrev)
        return uint256(); // genesis block's modifier is 0

    CHashWriter ss{};
    ss << kernel << pindexPrev->nStakeModifier;
    return ss.GetHash();
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    const Consensus::Params& params = Params().GetConsensus();
    if (params.IsProtocolV2(nTimeBlock))
        return (nTimeBlock == nTimeTx) && ((nTimeTx & params.nStakeTimestampMask) == 0);
    else
        return (nTimeBlock == nTimeTx);
}

// Simplified version of CheckCoinStakeTimestamp() to check header-only timestamp
bool CheckStakeBlockTimestamp(int64_t nTimeBlock)
{
   return CheckCoinStakeTimestamp(nTimeBlock, nTimeBlock);
}

static bool QuantumBlockSigningPubKeyMatchesStake(const std::vector<unsigned char>& pubkey, const CScript& stake_script, const CTxIn& stake_input)
{
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    if (!stake_script.IsWitnessProgram(witness_version, witness_program)) {
        return false;
    }

    uint256 pubkey_hash;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(pubkey_hash.begin());
    if (IsQuantumMigrationWitnessProgram(witness_version, witness_program)) {
        QuantumStakeTierProgram tier;
        return DecodeQuantumStakeTierProgram(witness_version, witness_program, tier) &&
               tier.commitment == pubkey_hash;
    }

    if (IsQuantumColdStakeWitnessProgram(witness_version, witness_program)) {
        const auto& stack = stake_input.scriptWitness.stack;
        if (stack.size() != 4) return false;
        if (stack[1] != pubkey) return false;
        if (!(stack[3].size() == 1 && stack[3][0] == 1)) return false;
        if (stack[2].size() != uint256::size()) return false;
        uint256 owner_pubkey_hash;
        std::copy(stack[2].begin(), stack[2].end(), owner_pubkey_hash.begin());
        QuantumStakeTierProgram tier;
        if (!DecodeQuantumStakeTierProgram(witness_version, witness_program, tier)) return false;
        const std::vector<unsigned char> expected_program = tier.tiered
            ? QuantumTieredColdStakeProgramForKeyHashes(pubkey_hash, owner_pubkey_hash, tier.state, tier.unbonding_blocks, tier.unlock_height)
            : QuantumColdStakeProgramForKeyHashes(pubkey_hash, owner_pubkey_hash);
        return expected_program == witness_program;
    }

    return false;
}

// BlackCoin kernel protocol v3
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.nTime + txPrev.vout.hash + txPrev.vout.n + nTime) < bnTarget * nWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coins one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                   future proof-of-stake
//   txPrev.nTime: slightly scrambles computation
//   txPrev.vout.hash: hash of txPrev, to reduce the chance of nodes
//                     generating coinstake at the same time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   nTime: current timestamp
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(const CBlockIndex* pindexPrev, unsigned int nBits, uint32_t blockFromTime, CAmount prevoutValue, const COutPoint& prevout, const CScript& scriptPubKey, unsigned int nTimeTx, bool fPrintProofOfStake)
{
    return CheckStakeKernelHash(pindexPrev, nBits, blockFromTime, prevoutValue, prevout, scriptPubKey, nTimeTx, StakeWeightContext{}, fPrintProofOfStake);
}

bool CheckStakeKernelHash(const CBlockIndex* pindexPrev, unsigned int nBits, uint32_t blockFromTime, CAmount prevoutValue, const COutPoint& prevout, const CScript& scriptPubKey, unsigned int nTimeTx, const StakeWeightContext& weight_context, bool fPrintProofOfStake)
{
    if (nTimeTx < blockFromTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");

    // Base target
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits);

    // Weighted target
    int64_t nValueIn = prevoutValue;
    if (nValueIn <= 0)
        return error("CheckStakeKernelHash() : nValueIn = 0");


    arith_uint256 bnWeight = EffectiveStakeWeight(nValueIn, weight_context.multiplier_ppm10k, weight_context.pool_ppm10k);

    uint256 nStakeModifier = pindexPrev->nStakeModifier;

    // Calculate hash
    CHashWriter ss{};
    ss << nStakeModifier;
    ss << blockFromTime << prevout.hash << prevout.n << nTimeTx;

    uint256 hashProofOfStake = ss.GetHash();

    if (fPrintProofOfStake)
    {
        LogPrintf("CheckStakeKernelHash() : nStakeModifier=%s, txPrev.nTime=%u, txPrev.vout.hash=%s, txPrev.vout.n=%u, nTimeTx=%u, hashProof=%s\n",
            nStakeModifier.GetHex().c_str(),
            blockFromTime, prevout.hash.ToString(), prevout.n, nTimeTx,
            hashProofOfStake.ToString());
        if (weight_context.stake_tiers_active) {
            LogPrintf("CheckStakeKernelHash() : stake-tier effective_unbonding_blocks=%d, multiplier_ppm10k=%u, pool_ppm10k=%u\n",
                weight_context.effective_unbonding_blocks,
                weight_context.multiplier_ppm10k,
                weight_context.pool_ppm10k);
        }
    }

    // Now check if proof-of-stake hash meets target protocol
    if (!KernelProductLE(bnTarget, bnWeight, hashProofOfStake))
        return false;

    if (LogInstance().WillLogCategory(BCLog::COINSTAKE) && !fPrintProofOfStake)
    {
        LogPrintf("CheckStakeKernelHash() : nStakeModifier=%s, txPrev.nTime=%u, txPrev.vout.hash=%s, txPrev.vout.n=%u, nTimeTx=%u, hashProof=%s\n",
            nStakeModifier.GetHex().c_str(),
            blockFromTime, prevout.hash.ToString(), prevout.n, nTimeTx,
            hashProofOfStake.ToString());
        if (weight_context.stake_tiers_active) {
            LogPrintf("CheckStakeKernelHash() : stake-tier effective_unbonding_blocks=%d, multiplier_ppm10k=%u, pool_ppm10k=%u\n",
                weight_context.effective_unbonding_blocks,
                weight_context.multiplier_ppm10k,
                weight_context.pool_ppm10k);
        }
    }

    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(CBlockIndex* pindexPrev, const CTransaction& tx, unsigned int nBits, BlockValidationState& state, CCoinsViewCache& view, unsigned int nTimeTx)
{
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    Coin coinPrev;

    if (!view.GetCoin(txin.prevout, coinPrev)) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "stake-prevout-not-exist", strprintf("CheckProofOfStake() : Stake prevout does not exist %s", txin.prevout.hash.ToString()));
    }

    // Min age requirement
    if (pindexPrev->nHeight + 1 - coinPrev.nHeight < Params().GetConsensus().nCoinbaseMaturity){
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "stake-prevout-not-mature", strprintf("CheckProofOfStake() : Stake prevout is not mature, expecting %i and only matured to %i", Params().GetConsensus().nCoinbaseMaturity, pindexPrev->nHeight + 1 - coinPrev.nHeight));
    }

    CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinPrev.nHeight);
    if (!blockFrom) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "stake-prevout-not-loaded", strprintf("CheckProofOfStake() : Block at height %i for prevout can not be loaded", coinPrev.nHeight));
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t stake_mtp = pindexPrev->GetMedianTimePast();
    const int stake_height = pindexPrev->nHeight + 1;
    const bool quantum_stake = IsQuantumMigrationScript(coinPrev.out.scriptPubKey) || IsQuantumColdStakeScript(coinPrev.out.scriptPubKey);
    const bool quantum_stake_rules_active = IsQuantumWitnessSpendActive(consensus, stake_mtp, stake_height);
    std::vector<unsigned char> quantum_block_pubkey;
    const bool quantum_block_signature = tx.vout.size() >= 2 && ExtractQuantumBlockSigningPubKey(tx.vout[1].scriptPubKey, quantum_block_pubkey);
    if (consensus.IsNewNetworkStakeOnly(stake_mtp) && !quantum_stake) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "legacy-stake-disabled", strprintf("CheckProofOfStake() : Legacy stake prevout is disabled after the Quantum Quasar migration deadline on coinstake %s", tx.GetHash().ToString()));
    }
    if (quantum_block_signature) {
        if (!quantum_stake_rules_active) {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "blackcoin-blocksig-premature", strprintf("CheckProofOfStake() : Quantum block signatures are not active on coinstake %s", tx.GetHash().ToString()));
        }
        if (!quantum_stake || !QuantumBlockSigningPubKeyMatchesStake(quantum_block_pubkey, coinPrev.out.scriptPubKey, txin)) {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "blackcoin-blocksig-stake-mismatch", strprintf("CheckProofOfStake() : Quantum block signing key does not match staked output on coinstake %s", tx.GetHash().ToString()));
        }
    } else if (quantum_stake && quantum_stake_rules_active) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "blackcoin-blocksig-missing", strprintf("CheckProofOfStake() : Quantum stake requires ML-DSA block signing key on coinstake %s", tx.GetHash().ToString()));
    }

    unsigned int script_verify_flags = SCRIPT_VERIFY_NONE;
    if (consensus.IsProtocolV4(stake_mtp)) {
        script_verify_flags |= SCRIPT_VERIFY_ISCOINSTAKE;
        script_verify_flags |= SCRIPT_VERIFY_STRICTENC;
    }
    if (consensus.IsNewNetworkStakeOnly(stake_mtp)) {
        script_verify_flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
    }
    if (IsQuantumWitnessSpendActive(consensus, stake_mtp, stake_height)) {
        script_verify_flags |= SCRIPT_VERIFY_P2SH;
        script_verify_flags |= SCRIPT_VERIFY_WITNESS;
        script_verify_flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
        script_verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
        script_verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
    }
    if (IsQuantumWitnessSpendActive(consensus, stake_mtp, stake_height)) {
        script_verify_flags |= SCRIPT_VERIFY_EUTXO;
    }
    if (consensus.IsStakeTiersActive(stake_height)) {
        script_verify_flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
    }
    if (consensus.IsQuantumFinalLockout(stake_mtp)) {
        script_verify_flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
    }

    // Verify signature
    if (!VerifySignature(coinPrev, txin.prevout.hash, tx, 0, script_verify_flags))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "stake-verify-signature-failed", strprintf("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString()));

    const StakeWeightContext stake_weight_context = GetStakeWeightContext(
        coinPrev.out.scriptPubKey,
        &txin,
        pindexPrev->nHeight + 1,
        consensus.IsStakeTiersActive(pindexPrev->nHeight + 1));
    const CAmount kernel_value = GetKernelStakeValue(coinPrev, view, consensus, pindexPrev->nHeight + 1, stake_mtp);
    if (!CheckStakeKernelHash(pindexPrev, nBits, (coinPrev.nTime ? coinPrev.nTime : blockFrom->nTime), kernel_value, txin.prevout, coinPrev.out.scriptPubKey, nTimeTx, stake_weight_context, LogInstance().WillLogCategory(BCLog::COINSTAKE)))
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_SYNC, "stake-check-kernel-failed", strprintf("CheckProofOfStake() : INFO: check kernel failed on coinstake %s", tx.GetHash().ToString())); // may occur during initial download or if behind on block chain sync

    return true;
}

bool CheckKernel(CBlockIndex* pindexPrev, unsigned int nBits, uint32_t nTime, const COutPoint& prevout, CCoinsViewCache& view){
    std::map<COutPoint, CStakeCache> tmp;
    return CheckKernel(pindexPrev, nBits, nTime, prevout, view, tmp);
}

bool CheckKernel(CBlockIndex* pindexPrev, unsigned int nBits, uint32_t nTime, const COutPoint& prevout, CCoinsViewCache& view, const std::map<COutPoint, CStakeCache>& cache)
{
    auto it = cache.find(prevout);

    if (it == cache.end()) {
        // not found in cache (shouldn't happen during staking, only during verification which does not use cache)
        Coin coinPrev;
        if (!view.GetCoin(prevout, coinPrev)) {
            return false;
        }

        if (pindexPrev->nHeight + 1 - coinPrev.nHeight < Params().GetConsensus().nCoinbaseMaturity) {
            return error("CheckKernel(): Coin is not mature");
        }

        CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinPrev.nHeight);
        if (!blockFrom) {
            return error("CheckKernel(): Could not find block");
        }

        if (coinPrev.IsSpent()) {
            return error("CheckKernel(): Coin is spent");
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        const StakeWeightContext stake_weight_context = GetStakeWeightContext(
            coinPrev.out.scriptPubKey,
            /*stake_input=*/nullptr,
            pindexPrev->nHeight + 1,
            consensus.IsStakeTiersActive(pindexPrev->nHeight + 1));
        const int64_t stake_mtp = pindexPrev->GetMedianTimePast();
        const CAmount kernel_value = GetKernelStakeValue(coinPrev, view, consensus, pindexPrev->nHeight + 1, stake_mtp);
        return CheckStakeKernelHash(pindexPrev, nBits, (coinPrev.nTime ? coinPrev.nTime : blockFrom->nTime), kernel_value, prevout, coinPrev.out.scriptPubKey, nTime, stake_weight_context, /*fPrintProofOfStake=*/false);
    } else {
        const int64_t stake_mtp = pindexPrev->GetMedianTimePast();
        if (Params().GetConsensus().IsDemurrageActive(pindexPrev->nHeight + 1, stake_mtp)) {
            return CheckKernel(pindexPrev, nBits, nTime, prevout, view);
        }

        // found in cache
        const CStakeCache& stake = it->second;
        const StakeWeightContext stake_weight_context = GetStakeWeightContext(
            stake.scriptPubKey,
            /*stake_input=*/nullptr,
            pindexPrev->nHeight + 1,
            Params().GetConsensus().IsStakeTiersActive(pindexPrev->nHeight + 1));
        if (CheckStakeKernelHash(pindexPrev, nBits, stake.blockFromTime, stake.amount, prevout, stake.scriptPubKey, nTime, stake_weight_context, /*fPrintProofOfStake=*/false)) {
            // Cache could potentially cause false positive stakes in the event of deep reorgs, so check without cache also return CheckKernel(pindexPrev, nBits, nTime, prevout, view); }
            return CheckKernel(pindexPrev, nBits, nTime, prevout, view);
        }
    }
    return false;
}

void CacheKernel(std::map<COutPoint, CStakeCache>& cache, const COutPoint& prevout, CBlockIndex* pindexPrev, CCoinsViewCache& view)
{
    if (cache.find(prevout) != cache.end()) {
        //already in cache
        return;
    }

    Coin coinPrev;
    if (!view.GetCoin(prevout, coinPrev)) {
        return;
    }

    if (pindexPrev->nHeight + 1 - coinPrev.nHeight < Params().GetConsensus().nCoinbaseMaturity) {
        return;
    }

    CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinPrev.nHeight);
    if (!blockFrom) {
        return;
    }

    CStakeCache c((coinPrev.nTime ? coinPrev.nTime : blockFrom->nTime), coinPrev.out.nValue, coinPrev.out.scriptPubKey);
    cache.insert({prevout, c});
}
