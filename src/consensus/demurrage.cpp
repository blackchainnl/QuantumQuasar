// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/demurrage.h>

#include <addresstype.h>
#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <compat/endian.h>
#include <consensus/params.h>
#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <algorithm>
#include <limits>

namespace Consensus {
namespace {

using valtype = std::vector<unsigned char>;

static constexpr unsigned char DEMURRAGE_ATTESTATION_VERSION = 1;
static constexpr uint32_t DEMURRAGE_NO_PREVIOUS_ATTESTATION = std::numeric_limits<uint32_t>::max();
static const valtype TAG_ATTEST{'Q', 'Q', 'A', 'T', 'T', 'E', 'S', 'T'};
static const valtype TAG_LATEST{'Q', 'Q', 'A', 'L', 'I', 'V', 'E'};
static const valtype TAG_UNDO{'Q', 'Q', 'A', 'U', 'N', 'D', 'O'};

CScript MarkerScript(const valtype& tag, const valtype& payload = {})
{
    return CScript() << OP_FALSE << OP_RETURN << tag << payload;
}

bool ParseMarkerScript(const CScript& script, const valtype& expected_tag, valtype* payload = nullptr)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_FALSE) return false;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, data) || data != expected_tag) return false;
    if (pc == script.end()) {
        if (payload) payload->clear();
        return true;
    }
    if (!script.GetOp(pc, opcode, data)) return false;
    if (pc != script.end()) return false;
    if (payload) *payload = data;
    return true;
}

bool ParseAttestationScript(const CScript& script, valtype& payload)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, data) || data != TAG_ATTEST) return false;
    if (!script.GetOp(pc, opcode, data)) return false;
    if (pc != script.end()) return false;
    payload = std::move(data);
    return true;
}

COutPoint LatestAttestationOutpoint(const uint256& pubkey_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Latest") << pubkey_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint UndoAttestationOutpoint(const CBlockIndex* pindex, const uint256& txid, uint32_t output_index, const uint256& pubkey_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Undo") << pindex->nHeight << pindex->GetBlockHash() << txid << output_index << pubkey_hash;
    return COutPoint{ss.GetHash(), 0};
}

valtype EncodeLatestPayload(const uint256& pubkey_hash)
{
    return {pubkey_hash.begin(), pubkey_hash.end()};
}

valtype EncodeUndoPayload(const uint256& pubkey_hash, std::optional<int> previous_height)
{
    valtype out(uint256::size() + sizeof(uint32_t));
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), out.begin());
    WriteLE32(out.data() + uint256::size(), previous_height ? static_cast<uint32_t>(*previous_height) : DEMURRAGE_NO_PREVIOUS_ATTESTATION);
    return out;
}

bool DecodeUndoPayload(const valtype& payload, uint256& pubkey_hash, std::optional<int>& previous_height)
{
    if (payload.size() != uint256::size() + sizeof(uint32_t)) return false;
    std::copy(payload.begin(), payload.begin() + uint256::size(), pubkey_hash.begin());
    const uint32_t raw_height = ReadLE32(payload.data() + uint256::size());
    previous_height = raw_height == DEMURRAGE_NO_PREVIOUS_ATTESTATION ? std::optional<int>{} : std::optional<int>{static_cast<int>(raw_height)};
    return true;
}

Coin MarkerCoin(CAmount value, const CScript& script, int height, int64_t time)
{
    Coin coin;
    coin.out.nValue = value;
    coin.out.scriptPubKey = script;
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = height;
    coin.nTime = time;
    return coin;
}

} // namespace

int64_t DemurrageRemainingPpm(int inactive_blocks)
{
    if (inactive_blocks <= DEMURRAGE_GRACE_BLOCKS) return DEMURRAGE_PPM;
    if (inactive_blocks >= DEMURRAGE_ZERO_BLOCKS) return 0;

    const int64_t elapsed = inactive_blocks - DEMURRAGE_GRACE_BLOCKS;
    const int64_t t_ppm = (elapsed * DEMURRAGE_PPM) / DEMURRAGE_DECAY_WINDOW_BLOCKS;
    return DEMURRAGE_PPM - ((t_ppm * t_ppm) / DEMURRAGE_PPM);
}

int64_t DemurrageRemainingPpm(int inactive_blocks, const Params& params)
{
    const int grace_blocks = params.DemurrageGraceBlocks();
    const int zero_blocks = params.DemurrageZeroBlocks();
    if (inactive_blocks <= grace_blocks) return DEMURRAGE_PPM;
    if (inactive_blocks >= zero_blocks) return 0;

    const int64_t elapsed = inactive_blocks - grace_blocks;
    const int64_t t_ppm = (elapsed * DEMURRAGE_PPM) / params.DemurrageDecayWindowBlocks();
    return DEMURRAGE_PPM - ((t_ppm * t_ppm) / DEMURRAGE_PPM);
}

CAmount DemurrageEffectiveValue(CAmount nominal_value, int64_t remaining_ppm)
{
    if (nominal_value <= 0 || remaining_ppm <= 0) return 0;
    if (remaining_ppm >= DEMURRAGE_PPM) return nominal_value;

    arith_uint256 value{static_cast<uint64_t>(nominal_value)};
    value *= static_cast<uint32_t>(remaining_ppm);
    value /= arith_uint256{static_cast<uint64_t>(DEMURRAGE_PPM)};
    if (value > arith_uint256{static_cast<uint64_t>(MAX_MONEY)}) return MAX_MONEY;
    return static_cast<CAmount>(value.GetLow64());
}

bool IsDemurrageTreasuryExemptScript(const CScript& script_pub_key, const Params& params)
{
    return std::find(params.m_demurrage_exempt_scripts.begin(), params.m_demurrage_exempt_scripts.end(), script_pub_key) !=
           params.m_demurrage_exempt_scripts.end();
}

uint256 DemurragePubKeyHash(const std::vector<unsigned char>& pubkey)
{
    uint256 out;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(out.begin());
    return out;
}

uint256 DemurrageAttestationMessageHash(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Attestation v1");
    ss << replay_anchor;
    ss << pubkey;
    return ss.GetHash();
}

std::vector<unsigned char> EncodeDemurrageAttestationPayload(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& signature)
{
    if (pubkey.size() != ML_DSA::PUBLICKEY_BYTES || signature.size() != ML_DSA::SIGNATURE_BYTES) return {};
    std::vector<unsigned char> payload(1 + uint256::size() + sizeof(uint32_t) + ML_DSA::PUBLICKEY_BYTES + ML_DSA::SIGNATURE_BYTES);
    payload[0] = DEMURRAGE_ATTESTATION_VERSION;
    auto cursor = payload.begin() + 1;
    cursor = std::copy(replay_anchor.hash.begin(), replay_anchor.hash.end(), cursor);
    WriteLE32(&*cursor, replay_anchor.n);
    cursor += sizeof(uint32_t);
    cursor = std::copy(pubkey.begin(), pubkey.end(), cursor);
    std::copy(signature.begin(), signature.end(), cursor);
    return payload;
}

CScript BuildDemurrageAttestationScript(const COutPoint& replay_anchor, const std::vector<unsigned char>& pubkey, const std::vector<unsigned char>& signature)
{
    return CScript() << OP_RETURN << TAG_ATTEST << EncodeDemurrageAttestationPayload(replay_anchor, pubkey, signature);
}

bool IsDemurrageAttestationScript(const CScript& script_pub_key)
{
    valtype payload;
    DemurrageAttestation attestation;
    return ParseAttestationScript(script_pub_key, payload) && DecodeDemurrageAttestationPayload(payload, attestation);
}

bool DecodeDemurrageAttestationPayload(const std::vector<unsigned char>& payload, DemurrageAttestation& attestation)
{
    static constexpr size_t EXPECTED_SIZE = 1 + uint256::size() + sizeof(uint32_t) + ML_DSA::PUBLICKEY_BYTES + ML_DSA::SIGNATURE_BYTES;
    if (payload.size() != EXPECTED_SIZE || payload[0] != DEMURRAGE_ATTESTATION_VERSION) return false;

    attestation = {};
    auto cursor = payload.begin() + 1;
    std::copy(cursor, cursor + uint256::size(), attestation.replay_anchor.hash.begin());
    cursor += uint256::size();
    attestation.replay_anchor.n = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    attestation.pubkey.assign(cursor, cursor + ML_DSA::PUBLICKEY_BYTES);
    cursor += ML_DSA::PUBLICKEY_BYTES;
    attestation.signature.assign(cursor, cursor + ML_DSA::SIGNATURE_BYTES);
    attestation.pubkey_hash = DemurragePubKeyHash(attestation.pubkey);
    return true;
}

std::vector<DemurrageAttestation> ExtractDemurrageAttestations(const CTransaction& tx)
{
    std::vector<DemurrageAttestation> attestations;
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        valtype payload;
        if (!ParseAttestationScript(tx.vout[i].scriptPubKey, payload)) continue;
        DemurrageAttestation attestation;
        if (!DecodeDemurrageAttestationPayload(payload, attestation) ||
            tx.IsCoinBase() ||
            tx.vin.empty() ||
            attestation.replay_anchor.IsNull() ||
            attestation.replay_anchor != tx.vin.front().prevout) {
            attestation.height = -1;
        }
        attestation.output_index = i;
        attestations.push_back(std::move(attestation));
    }
    return attestations;
}

std::optional<uint256> DemurrageControllingKeyHashForScript(const CScript& script_pub_key)
{
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return std::nullopt;
    QuantumStakeTierProgram tier;
    if (!DecodeQuantumStakeTierProgram(static_cast<unsigned int>(witness_version), witness_program, tier) || tier.cold_stake) {
        return std::nullopt;
    }
    return tier.commitment;
}

std::optional<int> LatestDemurrageAttestationHeight(const CCoinsViewCache& view, const uint256& pubkey_hash)
{
    Coin coin;
    if (!view.GetCoin(LatestAttestationOutpoint(pubkey_hash), coin)) return std::nullopt;
    valtype payload;
    if (!ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload)) return std::nullopt;
    if (payload != EncodeLatestPayload(pubkey_hash)) return std::nullopt;
    return static_cast<int>(coin.nHeight);
}

std::optional<int> LatestDemurrageAttestationHeightForScript(const CCoinsViewCache& view, const CScript& script_pub_key)
{
    const std::optional<uint256> key_hash = DemurrageControllingKeyHashForScript(script_pub_key);
    if (!key_hash) return std::nullopt;
    return LatestDemurrageAttestationHeight(view, *key_hash);
}

bool ApplyDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params, std::string& reject_reason)
{
    if (!pindex) return true;
    const int64_t block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
    if (!params.IsDemurrageActive(pindex->nHeight, block_mtp)) return true;

    for (const CTransactionRef& tx : block.vtx) {
        for (const DemurrageAttestation& attestation : ExtractDemurrageAttestations(*tx)) {
            if (attestation.height < 0) {
                reject_reason = "bad-demurrage-attestation";
                return false;
            }
            const uint256 msg_hash = DemurrageAttestationMessageHash(attestation.replay_anchor, attestation.pubkey);
            if (!ML_DSA::Verify(attestation.pubkey, msg_hash.begin(), uint256::size(), attestation.signature)) {
                reject_reason = "bad-demurrage-attestation-signature";
                return false;
            }

            const std::optional<int> previous_height = LatestDemurrageAttestationHeight(view, attestation.pubkey_hash);
            const COutPoint undo_outpoint = UndoAttestationOutpoint(pindex, tx->GetHash(), attestation.output_index, attestation.pubkey_hash);
            view.AddCoin(undo_outpoint,
                         MarkerCoin(0, MarkerScript(TAG_UNDO, EncodeUndoPayload(attestation.pubkey_hash, previous_height)), pindex->nHeight, pindex->GetBlockTime()),
                         /*possible_overwrite=*/true);
            view.AddCoin(LatestAttestationOutpoint(attestation.pubkey_hash),
                         MarkerCoin(0, MarkerScript(TAG_LATEST, EncodeLatestPayload(attestation.pubkey_hash)), pindex->nHeight, pindex->GetBlockTime()),
                         /*possible_overwrite=*/true);
        }
    }
    return true;
}

bool UndoDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params)
{
    if (!pindex) return true;
    const int64_t block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
    if (!params.IsDemurrageActive(pindex->nHeight, block_mtp)) return true;

    for (auto tx_it = block.vtx.rbegin(); tx_it != block.vtx.rend(); ++tx_it) {
        const CTransactionRef& tx = *tx_it;
        std::vector<DemurrageAttestation> attestations = ExtractDemurrageAttestations(*tx);
        for (auto att_it = attestations.rbegin(); att_it != attestations.rend(); ++att_it) {
            const DemurrageAttestation& attestation = *att_it;
            if (attestation.height < 0) continue;
            const COutPoint undo_outpoint = UndoAttestationOutpoint(pindex, tx->GetHash(), attestation.output_index, attestation.pubkey_hash);
            Coin undo_coin;
            if (!view.GetCoin(undo_outpoint, undo_coin)) return false;
            valtype payload;
            uint256 pubkey_hash;
            std::optional<int> previous_height;
            if (!ParseMarkerScript(undo_coin.out.scriptPubKey, TAG_UNDO, &payload) ||
                !DecodeUndoPayload(payload, pubkey_hash, previous_height) ||
                pubkey_hash != attestation.pubkey_hash) {
                return false;
            }

            const COutPoint latest_outpoint = LatestAttestationOutpoint(attestation.pubkey_hash);
            if (previous_height) {
                view.AddCoin(latest_outpoint,
                             MarkerCoin(0, MarkerScript(TAG_LATEST, EncodeLatestPayload(attestation.pubkey_hash)), *previous_height, pindex->GetBlockTime()),
                             /*possible_overwrite=*/true);
            } else if (view.HaveCoin(latest_outpoint)) {
                view.SpendCoin(latest_outpoint);
            }
            view.SpendCoin(undo_outpoint);
        }
    }
    return true;
}

CAmount GetDemurrageAdjustedValueIn(const CTransaction& tx, const CCoinsViewCache& inputs, const Params& params, int spend_height, int64_t spend_time)
{
    if (tx.IsCoinBase()) return 0;

    CAmount n_result = 0;
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = inputs.AccessCoin(txin.prevout);
        const std::optional<int> latest_attestation = LatestDemurrageAttestationHeightForScript(inputs, coin.out.scriptPubKey);
        const DemurrageEvaluation eval = EvaluateDemurrage(coin, params, spend_height, spend_time, latest_attestation);
        n_result += eval.effective_value;
    }
    return n_result;
}

DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time,
    std::optional<int> latest_attestation_height)
{
    DemurrageEvaluation eval;
    eval.nominal_value = coin.out.nValue;
    eval.effective_value = coin.out.nValue;

    if (!params.IsDemurrageActive(spend_height, spend_time)) {
        eval.exemption = "inactive";
        return eval;
    }
    eval.active = true;

    if (IsQuantumColdStakeScript(coin.out.scriptPubKey)) {
        eval.exempt = true;
        eval.exemption = "coldstake";
        return eval;
    }

    if (IsDemurrageTreasuryExemptScript(coin.out.scriptPubKey, params)) {
        eval.exempt = true;
        eval.exemption = "treasury";
        return eval;
    }

    if (!IsQuantumMigrationScript(coin.out.scriptPubKey)) {
        eval.exempt = true;
        eval.exemption = "non_quantum";
        return eval;
    }

    int effective_last_active = std::max<int>(coin.nHeight, params.EffectiveDemurrageActivationHeight());
    if (latest_attestation_height && *latest_attestation_height <= spend_height) {
        effective_last_active = std::max(effective_last_active, *latest_attestation_height);
    }
    eval.inactive_blocks = std::max(0, spend_height - effective_last_active);

    if (eval.inactive_blocks <= params.DemurrageGraceBlocks()) {
        eval.exempt = true;
        eval.exemption = latest_attestation_height && *latest_attestation_height >= effective_last_active ? "attested" : "young";
        return eval;
    }

    eval.remaining_ppm = DemurrageRemainingPpm(eval.inactive_blocks, params);
    eval.locked = eval.remaining_ppm == 0;
    eval.effective_value = DemurrageEffectiveValue(eval.nominal_value, eval.remaining_ppm);
    eval.burned_value = eval.nominal_value - eval.effective_value;
    return eval;
}

} // namespace Consensus
