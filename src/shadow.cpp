#include <shadow.h>

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <crypto/argon2/argon2.h>
#include <crypto/common.h>
#include <hash.h>
#include <logging.h>
#include <streams.h>
#include <undo.h>
#include <util/fs.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>
#include <set>

namespace {

using valtype = std::vector<unsigned char>;

static const valtype SHADOW_PREFIX{'Q', 'Q', 'S', 'P', 'R', 'O', 'O', 'F'};
static const valtype SIGNAL_PREFIX{'Q', 'Q', 'S', 'I', 'G', 'N', 'A', 'L'};
static const valtype MARKER_WHITELIST{'Q', 'Q', 'W', 'L'};
static const valtype MARKER_POOL{'Q', 'Q', 'P', 'O', 'O', 'L'};
static const valtype MARKER_DIRECT_CLAIM{'Q', 'Q', 'D', 'C', 'L', 'A', 'I', 'M'};
static const valtype MARKER_GOLD_RUSH_PAYOUT{'Q', 'Q', 'G', 'R', 'P', 'A', 'Y'};
static const valtype MARKER_SOLVER{'Q', 'Q', 'S', 'O', 'L', 'V', 'E'};
static const valtype MARKER_ACTIVE_SIGNAL{'Q', 'Q', 'A', 'S', 'I', 'G'};
static const valtype MARKER_CLAIM_PAYOUT_TX{'Q', 'Q', 'C', 'P', 'A', 'Y'};
static const valtype PROOF_MAGIC_V1{'Q', 'Q', 'P', '1'};
static const valtype PROOF_MAGIC_V2{'Q', 'Q', 'P', '2'};
static const valtype SIGNAL_MAGIC_V2{'Q', 'Q', 'S', '2'};
static const valtype CLAIM_MAGIC_V2{'Q', 'Q', 'C', '2'};
static constexpr size_t PROOF_SIZE = 13; // magic(4) | mode(1) | nonce(8)
static constexpr size_t SIGNAL_HEADER_SIZE = 40; // magic(4) | solve_height(4) | solve_hash(32)
static constexpr size_t POOL_LEGACY_SIZE = 16;
static constexpr size_t POOL_V1_SIZE = 41;
static constexpr size_t POOL_V2_SIZE = 49;
static constexpr unsigned int BASE_SHADOW_TARGET_BITS = 12;
static constexpr unsigned int MIN_SHADOW_TARGET_BITS = 10;
static constexpr unsigned int MAX_SHADOW_TARGET_BITS = 18;
static constexpr uint8_t SHADOW_RETARGET_WINDOW = 64;
static constexpr int SHADOW_POW_TARGET_SPACING_BLOCKS = 1;
static constexpr int SHADOW_POW_ASERT_HALF_LIFE_BLOCKS = 64;
static constexpr uint32_t MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK = (V4_MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) + 2;
// DoS bound: each QQSPROOF output triggers a memory-hard Argon2id (1 MiB) evaluation.
// An attacker could otherwise stuff a block with thousands of QQSPROOF outputs to force
// unbounded memory-hashing on every validating node. Honest blocks carry a single claim,
// so capping the number of proof evaluations per block at a generous constant bounds the
// worst-case validation cost (<= cap * 1 MiB) without affecting legitimate claims.
static constexpr unsigned int MAX_SHADOW_POW_EVALS_PER_BLOCK = 64;
static constexpr uint32_t SHADOW_ARGON2_TIME_COST = 1;
static constexpr uint32_t SHADOW_ARGON2_MEMORY_KIB = 1024;
static constexpr uint32_t SHADOW_ARGON2_LANES = 1;

bool IsDirectQuantumMigrationScript(const CScript& script)
{
    const auto tier = GetQuantumStakeTierProgram(script);
    return tier && !tier->tiered && !tier->cold_stake;
}

enum class ShadowProofMode : unsigned char {
    POW = 0,
    POS = 1,
};

struct ShadowPoolState {
    CAmount pow_amount{0};
    CAmount pos_amount{0};
    CAmount claimed_amount{0};
    uint32_t pow_count{0};
    uint32_t pos_count{0};
    uint32_t last_pow_height{0};
    uint32_t last_pos_height{0};
    uint8_t recent_count{0};
    uint64_t recent_modes{0};
};

struct ShadowClaim {
    CScript target;
    CAmount amount{0};
    ShadowProofMode mode{ShadowProofMode::POW};
    ShadowPoolState undo_pool;
    bool direct{false};
};

struct ShadowClaimResult {
    std::optional<ShadowClaim> claim;
    bool internal_error{false};
    bool proof_limit_exceeded{false};
    bool duplicate_claim{false};
    bool invalid_claim_location{false};
};

struct ShadowSignal {
    CScript target;
    CScript payout_script;
    uint32_t solve_height{0};
    uint256 solve_hash;
    bool quantum_linked{false};
};

struct ShadowActiveSignal {
    CScript target;
    CScript payout_script;
    uint32_t last_signal_height{0};
};

struct ShadowProof {
    ShadowProofMode mode{ShadowProofMode::POW};
    uint64_t nonce{0};
    CScript target;
    CScript payout_script;
    bool quantum_linked{false};
};

enum class ShadowProofValidation {
    INVALID,
    VALID,
    INTERNAL_ERROR,
};

CScript MarkerScript(const valtype& tag, const valtype& payload = {})
{
    // This is not pruned by AddCoin() because it does not start with OP_RETURN,
    // but any attempted spend reaches OP_RETURN and fails.
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

uint256 TaggedHash(const std::string& tag, const valtype& payload)
{
    CHashWriter ss;
    ss << tag << payload;
    return ss.GetHash();
}

CScript CanonicalLegacyStakeScript(const CScript& script)
{
    if ((script.size() == CPubKey::COMPRESSED_SIZE + 2 && script[0] == CPubKey::COMPRESSED_SIZE && script.back() == OP_CHECKSIG) ||
        (script.size() == CPubKey::SIZE + 2 && script[0] == CPubKey::SIZE && script.back() == OP_CHECKSIG)) {
        const valtype pubkey_bytes(script.begin() + 1, script.end() - 1);
        const CPubKey pubkey(pubkey_bytes);
        if (pubkey.IsValid()) {
            return GetScriptForDestination(PKHash(pubkey));
        }
    }
    return script;
}

COutPoint WhitelistOutpoint(const CScript& script)
{
    return COutPoint{TaggedHash("Quantum Quasar Legacy Whitelist", {script.begin(), script.end()}), 0};
}

COutPoint PoolOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Shadow Pool", {}), 0};
}

} // namespace

CScript CanonicalizeLegacyStakeScript(const CScript& scriptPubKey)
{
    return CanonicalLegacyStakeScript(scriptPubKey);
}

namespace {

COutPoint ClaimOutpoint(int height, const uint256& block_hash, uint32_t n)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Claim") << height << block_hash << n;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ClaimOutpoint(const CBlockIndex* pindex, uint32_t n)
{
    return ClaimOutpoint(pindex->nHeight, pindex->GetBlockHash(), n);
}

CTransactionRef BuildClaimPayoutTransaction(int height, const uint256& block_hash, int64_t block_time, uint32_t marker_index, const ShadowClaim& claim)
{
    valtype anchor;
    anchor.reserve(4 + uint256::size() + 4);
    anchor.resize(4);
    WriteLE32(anchor.data(), static_cast<uint32_t>(height));
    anchor.insert(anchor.end(), block_hash.begin(), block_hash.end());
    const size_t marker_offset = anchor.size();
    anchor.resize(anchor.size() + 4);
    WriteLE32(anchor.data() + marker_offset, marker_index);

    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.nTime = block_time;
    mtx.vin.emplace_back(COutPoint{}, CScript{} << MARKER_CLAIM_PAYOUT_TX << anchor);
    mtx.vout.emplace_back(claim.amount, claim.target);
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef BuildClaimPayoutTransaction(const CBlockIndex* pindex, uint32_t marker_index, const ShadowClaim& claim)
{
    return BuildClaimPayoutTransaction(pindex->nHeight, pindex->GetBlockHash(), pindex->GetBlockTime(), marker_index, claim);
}

COutPoint ClaimPayoutOutpoint(const CBlockIndex* pindex, uint32_t marker_index, const ShadowClaim& claim)
{
    return COutPoint{BuildClaimPayoutTransaction(pindex, marker_index, claim)->GetHash(), 0};
}

COutPoint SolverOutpoint(const CScript& script, uint32_t height, const uint256& block_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Recent Solver") << script << height << block_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalOutpoint(int height, const uint256& block_hash, uint32_t n)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal") << height << block_hash << n;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalOutpoint(const CBlockIndex* pindex, uint32_t n)
{
    return ActiveSignalOutpoint(pindex->nHeight, pindex->GetBlockHash(), n);
}

COutPoint GoldRushPayoutOutpoint(const COutPoint& payout_outpoint)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Direct Gold Rush Payout") << payout_outpoint;
    return COutPoint{ss.GetHash(), 0};
}

valtype EncodeAmount(CAmount amount)
{
    valtype out(8);
    WriteLE64(out.data(), static_cast<uint64_t>(amount));
    return out;
}

std::optional<CAmount> DecodeAmount(const valtype& data)
{
    if (data.size() < 8) return std::nullopt;
    const uint64_t raw = ReadLE64(data.data());
    if (raw > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    return static_cast<CAmount>(raw);
}

std::optional<CAmount> CheckedAddMoney(CAmount left, CAmount right)
{
    if (!MoneyRange(left) || !MoneyRange(right)) return std::nullopt;
    if (left > MAX_MONEY - right) return std::nullopt;
    return left + right;
}

valtype EncodeSignalPayloadV2(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash)
{
    valtype out(SIGNAL_HEADER_SIZE + 4 + target.size() + quantum_payout_script.size());
    std::copy(SIGNAL_MAGIC_V2.begin(), SIGNAL_MAGIC_V2.end(), out.begin());
    WriteLE32(out.data() + 4, solve_height);
    std::copy(solve_hash.begin(), solve_hash.end(), out.begin() + 8);
    WriteLE16(out.data() + SIGNAL_HEADER_SIZE, static_cast<uint16_t>(target.size()));
    auto cursor = out.begin() + SIGNAL_HEADER_SIZE + 2;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(quantum_payout_script.size()));
    cursor += 2;
    std::copy(quantum_payout_script.begin(), quantum_payout_script.end(), cursor);
    return out;
}

bool DecodeSignalPayload(const valtype& payload, ShadowSignal& signal)
{
    if (payload.size() < SIGNAL_HEADER_SIZE) return false;
    signal = {};
    signal.solve_height = ReadLE32(payload.data() + 4);
    std::copy(payload.begin() + 8, payload.begin() + 40, signal.solve_hash.begin());

    if (std::equal(SIGNAL_MAGIC_V2.begin(), SIGNAL_MAGIC_V2.end(), payload.begin())) {
        if (payload.size() < SIGNAL_HEADER_SIZE + 4) return false;
        const size_t target_size = ReadLE16(payload.data() + SIGNAL_HEADER_SIZE);
        size_t cursor = SIGNAL_HEADER_SIZE + 2;
        if (target_size == 0 || cursor + target_size + 2 > payload.size()) return false;
        signal.target = CScript(payload.begin() + cursor, payload.begin() + cursor + target_size);
        cursor += target_size;
        const size_t payout_size = ReadLE16(payload.data() + cursor);
        cursor += 2;
        if (payout_size == 0 || cursor + payout_size != payload.size()) return false;
        signal.payout_script = CScript(payload.begin() + cursor, payload.end());
        signal.quantum_linked = true;
        if (!IsDirectQuantumMigrationScript(signal.payout_script)) return false;
    } else {
        return false;
    }

    return !signal.target.empty() && !signal.target.IsUnspendable() &&
           !signal.payout_script.empty() && !signal.payout_script.IsUnspendable();
}

valtype EncodeActiveSignalMarker(const CScript& target, const CScript& payout_script, uint32_t last_signal_height)
{
    valtype out(8 + target.size() + payout_script.size());
    WriteLE32(out.data(), last_signal_height);
    WriteLE16(out.data() + 4, static_cast<uint16_t>(target.size()));
    auto cursor = out.begin() + 6;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(payout_script.size()));
    cursor += 2;
    std::copy(payout_script.begin(), payout_script.end(), cursor);
    return out;
}

bool DecodeActiveSignalMarker(const CScript& script, ShadowActiveSignal& signal)
{
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL, &payload)) return false;
    if (payload.size() < 8) return false;
    const uint32_t last_signal_height = ReadLE32(payload.data());
    const size_t target_size = ReadLE16(payload.data() + 4);
    size_t cursor = 6;
    if (target_size == 0 || cursor + target_size + 2 > payload.size()) return false;
    CScript target(payload.begin() + cursor, payload.begin() + cursor + target_size);
    cursor += target_size;
    const size_t payout_size = ReadLE16(payload.data() + cursor);
    cursor += 2;
    if (payout_size == 0 || cursor + payout_size != payload.size()) return false;
    CScript payout(payload.begin() + cursor, payload.end());
    if (target.empty() || target.IsUnspendable()) return false;
    if (!IsDirectQuantumMigrationScript(payout)) return false;
    signal = ShadowActiveSignal{target, payout, last_signal_height};
    return true;
}

valtype EncodePool(const ShadowPoolState& pool)
{
    valtype out(POOL_V2_SIZE);
    WriteLE64(out.data(), static_cast<uint64_t>(pool.pow_amount));
    WriteLE64(out.data() + 8, static_cast<uint64_t>(pool.pos_amount));
    WriteLE32(out.data() + 16, pool.pow_count);
    WriteLE32(out.data() + 20, pool.pos_count);
    WriteLE32(out.data() + 24, pool.last_pow_height);
    WriteLE32(out.data() + 28, pool.last_pos_height);
    out[32] = pool.recent_count;
    WriteLE64(out.data() + 33, pool.recent_modes);
    WriteLE64(out.data() + 41, static_cast<uint64_t>(pool.claimed_amount));
    return out;
}

ShadowPoolState ReadPool(const CCoinsViewCache& view)
{
    ShadowPoolState pool;
    Coin coin;
    if (!view.GetCoin(PoolOutpoint(), coin)) return pool;
    valtype payload;
    if (!ParseMarkerScript(coin.out.scriptPubKey, MARKER_POOL, &payload)) return pool;
    if (payload.size() != POOL_LEGACY_SIZE && payload.size() != POOL_V1_SIZE && payload.size() != POOL_V2_SIZE) return pool;
    if (payload.size() == POOL_LEGACY_SIZE) {
        const uint64_t amount = ReadLE64(payload.data());
        if (amount <= static_cast<uint64_t>(MAX_MONEY)) {
            pool.pow_amount = static_cast<CAmount>(amount / 2);
            pool.pos_amount = static_cast<CAmount>(amount - amount / 2);
        }
        pool.pow_count = ReadLE32(payload.data() + 8);
        pool.pos_count = ReadLE32(payload.data() + 12);
    } else {
        const uint64_t pow_amount = ReadLE64(payload.data());
        const uint64_t pos_amount = ReadLE64(payload.data() + 8);
        if (pow_amount <= static_cast<uint64_t>(MAX_MONEY)) pool.pow_amount = static_cast<CAmount>(pow_amount);
        if (pos_amount <= static_cast<uint64_t>(MAX_MONEY)) pool.pos_amount = static_cast<CAmount>(pos_amount);
        pool.pow_count = ReadLE32(payload.data() + 16);
        pool.pos_count = ReadLE32(payload.data() + 20);
        pool.last_pow_height = ReadLE32(payload.data() + 24);
        pool.last_pos_height = ReadLE32(payload.data() + 28);
        pool.recent_count = std::min<uint8_t>(payload[32], SHADOW_RETARGET_WINDOW);
        pool.recent_modes = ReadLE64(payload.data() + 33);
        if (pool.recent_count < SHADOW_RETARGET_WINDOW) {
            pool.recent_modes &= (uint64_t{1} << pool.recent_count) - 1;
        }
        if (payload.size() == POOL_V2_SIZE) {
            const uint64_t claimed_amount = ReadLE64(payload.data() + 41);
            if (claimed_amount <= static_cast<uint64_t>(MAX_MONEY)) pool.claimed_amount = static_cast<CAmount>(claimed_amount);
        }
    }
    return pool;
}

void WritePool(CCoinsViewCache& view, const CBlockIndex* pindex, const ShadowPoolState& pool)
{
    const COutPoint outpoint = PoolOutpoint();
    if (view.HaveCoin(outpoint)) view.SpendCoin(outpoint);
    if (pool.pow_amount == 0 && pool.pos_amount == 0 && pool.claimed_amount == 0 &&
        pool.pow_count == 0 && pool.pos_count == 0) return;

    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_POOL, EncodePool(pool));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(outpoint, std::move(coin), true);
}

bool ShadowObligationWithinCap(const ShadowPoolState& pool)
{
    const auto claimed_plus_pow = CheckedAddMoney(pool.claimed_amount, pool.pow_amount);
    if (!claimed_plus_pow) return false;
    const auto total = CheckedAddMoney(*claimed_plus_pow, pool.pos_amount);
    return total && *total <= SHADOW_MAX_EMISSION;
}

bool AddClaimedAmount(ShadowPoolState& pool, CAmount amount)
{
    if (amount <= 0 || !MoneyRange(amount)) return false;
    const auto next = CheckedAddMoney(pool.claimed_amount, amount);
    if (!next || *next > SHADOW_MAX_EMISSION) return false;
    pool.claimed_amount = *next;
    return true;
}


valtype EncodeClaim(const ShadowClaim& claim)
{
    const valtype undo_pool = EncodePool(claim.undo_pool);
    valtype out;
    out.reserve(CLAIM_MAGIC_V2.size() + 8 + 1 + undo_pool.size() + 2 + claim.target.size());
    out.insert(out.end(), CLAIM_MAGIC_V2.begin(), CLAIM_MAGIC_V2.end());
    const valtype amount = EncodeAmount(claim.amount);
    out.insert(out.end(), amount.begin(), amount.end());
    out.push_back(static_cast<unsigned char>(claim.mode));
    out.insert(out.end(), undo_pool.begin(), undo_pool.end());
    const uint16_t target_size = static_cast<uint16_t>(claim.target.size());
    out.push_back(static_cast<unsigned char>(target_size & 0xff));
    out.push_back(static_cast<unsigned char>(target_size >> 8));
    out.insert(out.end(), claim.target.begin(), claim.target.end());
    return out;
}

std::optional<ShadowClaim> DecodeClaimPayloadV1(const valtype& payload)
{
    if (payload.size() < 9 + POOL_V1_SIZE + 1) return std::nullopt;
    auto amount = DecodeAmount(payload);
    if (!amount) return std::nullopt;
    const auto mode = static_cast<ShadowProofMode>(payload[8]);
    if (mode != ShadowProofMode::POW && mode != ShadowProofMode::POS) return std::nullopt;
    ShadowPoolState undo_pool;
    const uint64_t undo_pow_amount = ReadLE64(payload.data() + 9);
    const uint64_t undo_pos_amount = ReadLE64(payload.data() + 17);
    if (undo_pow_amount > static_cast<uint64_t>(MAX_MONEY) || undo_pos_amount > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    undo_pool.pow_amount = static_cast<CAmount>(undo_pow_amount);
    undo_pool.pos_amount = static_cast<CAmount>(undo_pos_amount);
    undo_pool.pow_count = ReadLE32(payload.data() + 25);
    undo_pool.pos_count = ReadLE32(payload.data() + 29);
    undo_pool.last_pow_height = ReadLE32(payload.data() + 33);
    undo_pool.last_pos_height = ReadLE32(payload.data() + 37);
    undo_pool.recent_count = std::min<uint8_t>(payload[41], SHADOW_RETARGET_WINDOW);
    undo_pool.recent_modes = ReadLE64(payload.data() + 42);
    if (undo_pool.recent_count < SHADOW_RETARGET_WINDOW) {
        undo_pool.recent_modes &= (uint64_t{1} << undo_pool.recent_count) - 1;
    }
    CScript target(payload.begin() + 9 + POOL_V1_SIZE, payload.end());
    if (target.empty() || target.IsUnspendable()) return std::nullopt;
    return ShadowClaim{target, *amount, mode, undo_pool, true};
}

std::optional<ShadowClaim> DecodeClaimScript(const CScript& script)
{
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_DIRECT_CLAIM, &payload)) return std::nullopt;
    if (payload.size() < CLAIM_MAGIC_V2.size() ||
        !std::equal(CLAIM_MAGIC_V2.begin(), CLAIM_MAGIC_V2.end(), payload.begin())) {
        return DecodeClaimPayloadV1(payload);
    }

    size_t cursor = CLAIM_MAGIC_V2.size();
    if (payload.size() < cursor + 8 + 1 + POOL_V2_SIZE + 2 + 1) return std::nullopt;
    auto amount = DecodeAmount(valtype(payload.begin() + cursor, payload.begin() + cursor + 8));
    if (!amount) return std::nullopt;
    cursor += 8;
    const auto mode = static_cast<ShadowProofMode>(payload[cursor++]);
    if (mode != ShadowProofMode::POW && mode != ShadowProofMode::POS) return std::nullopt;
    ShadowPoolState undo_pool;
    const unsigned char* pool_data = payload.data() + cursor;
    const uint64_t undo_pow_amount = ReadLE64(pool_data);
    const uint64_t undo_pos_amount = ReadLE64(pool_data + 8);
    const uint64_t undo_claimed_amount = ReadLE64(pool_data + 41);
    if (undo_pow_amount > static_cast<uint64_t>(MAX_MONEY) ||
        undo_pos_amount > static_cast<uint64_t>(MAX_MONEY) ||
        undo_claimed_amount > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    undo_pool.pow_amount = static_cast<CAmount>(undo_pow_amount);
    undo_pool.pos_amount = static_cast<CAmount>(undo_pos_amount);
    undo_pool.claimed_amount = static_cast<CAmount>(undo_claimed_amount);
    undo_pool.pow_count = ReadLE32(pool_data + 16);
    undo_pool.pos_count = ReadLE32(pool_data + 20);
    undo_pool.last_pow_height = ReadLE32(pool_data + 24);
    undo_pool.last_pos_height = ReadLE32(pool_data + 28);
    undo_pool.recent_count = std::min<uint8_t>(pool_data[32], SHADOW_RETARGET_WINDOW);
    undo_pool.recent_modes = ReadLE64(pool_data + 33);
    if (undo_pool.recent_count < SHADOW_RETARGET_WINDOW) {
        undo_pool.recent_modes &= (uint64_t{1} << undo_pool.recent_count) - 1;
    }
    cursor += POOL_V2_SIZE;
    const size_t target_size = ReadLE16(payload.data() + cursor);
    cursor += 2;
    if (target_size == 0 || cursor + target_size != payload.size()) return std::nullopt;
    CScript target(payload.begin() + cursor, payload.end());
    if (target.empty() || target.IsUnspendable()) return std::nullopt;
    return ShadowClaim{target, *amount, mode, undo_pool, true};
}

CAmount ClaimablePoolAmount(const ShadowPoolState& pool, ShadowProofMode mode)
{
    return mode == ShadowProofMode::POW ? pool.pow_amount : pool.pos_amount;
}

unsigned int RetargetedBits(ShadowProofMode mode, const ShadowPoolState& pool, int height)
{
    if (mode != ShadowProofMode::POW || height <= SHADOW_REWARD_START_HEIGHT) {
        return BASE_SHADOW_TARGET_BITS;
    }

    // Shadow PoW can be claimed at most once per block. Use block height as the
    // 64-second ASERT clock and relax difficulty by one leading-zero bit for
    // each half-life of missed PoW claims.
    const int anchor_height = pool.last_pow_height != 0
        ? static_cast<int>(pool.last_pow_height)
        : SHADOW_REWARD_START_HEIGHT - SHADOW_POW_TARGET_SPACING_BLOCKS;
    const int actual_spacing = std::max(0, height - anchor_height);
    const int drift = actual_spacing - SHADOW_POW_TARGET_SPACING_BLOCKS;
    const int rounded_half_lives = std::max(0, (drift + SHADOW_POW_ASERT_HALF_LIFE_BLOCKS / 2) / SHADOW_POW_ASERT_HALF_LIFE_BLOCKS);
    const int bits = static_cast<int>(BASE_SHADOW_TARGET_BITS) - rounded_half_lives;
    return static_cast<unsigned int>(std::clamp(bits, static_cast<int>(MIN_SHADOW_TARGET_BITS), static_cast<int>(MAX_SHADOW_TARGET_BITS)));
}

bool HashMeetsLeadingZeroBits(const uint256& hash, unsigned int bits)
{
    const unsigned char* data = hash.data();
    while (bits >= 8) {
        if (*data++ != 0) return false;
        bits -= 8;
    }
    if (bits == 0) return true;
    const unsigned char mask = 0xff << (8 - bits);
    return (*data & mask) == 0;
}

bool DecodeProof(const valtype& proof, ShadowProof& decoded)
{
    if (proof.size() < PROOF_SIZE) return false;
    decoded = {};
    decoded.mode = static_cast<ShadowProofMode>(proof[4]);
    if (decoded.mode != ShadowProofMode::POW && decoded.mode != ShadowProofMode::POS) return false;
    decoded.nonce = ReadLE64(proof.data() + 5);

    if (std::equal(PROOF_MAGIC_V1.begin(), PROOF_MAGIC_V1.end(), proof.begin())) {
        decoded.target = CScript(proof.begin() + PROOF_SIZE, proof.end());
        decoded.payout_script = decoded.target;
        decoded.quantum_linked = false;
    } else if (std::equal(PROOF_MAGIC_V2.begin(), PROOF_MAGIC_V2.end(), proof.begin())) {
        if (proof.size() < PROOF_SIZE + 4) return false;
        const size_t target_size = ReadLE16(proof.data() + PROOF_SIZE);
        size_t cursor = PROOF_SIZE + 2;
        if (target_size == 0 || cursor + target_size + 2 > proof.size()) return false;
        decoded.target = CScript(proof.begin() + cursor, proof.begin() + cursor + target_size);
        cursor += target_size;
        const size_t payout_size = ReadLE16(proof.data() + cursor);
        cursor += 2;
        if (payout_size == 0 || cursor + payout_size != proof.size()) return false;
        decoded.payout_script = CScript(proof.begin() + cursor, proof.end());
        decoded.quantum_linked = true;
        if (!IsDirectQuantumMigrationScript(decoded.payout_script)) return false;
    } else {
        return false;
    }

    return !decoded.target.empty() && !decoded.target.IsUnspendable() &&
           !decoded.payout_script.empty() && !decoded.payout_script.IsUnspendable();
}

bool ComputeShadowProofHash(const CScript& target, const CScript& payout_script, int height, const uint256& prev_hash, ShadowProofMode mode, uint64_t nonce, uint256& result)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar QQPROOF POW Argon2id v1");
    ss << static_cast<unsigned char>(mode);
    ss << nonce;
    ss << height;
    ss << prev_hash;
    ss << target;
    ss << payout_script;
    const uint256 prehash = ss.GetHash();

    std::array<unsigned char, 80> input{};
    auto out = input.begin();
    out = std::copy(prehash.begin(), prehash.end(), out);
    out = std::copy(prev_hash.begin(), prev_hash.end(), out);
    WriteLE32(&*out, static_cast<uint32_t>(height));
    out += 4;
    WriteLE64(&*out, nonce);
    out += 8;
    *out++ = static_cast<unsigned char>(mode);
    *out++ = 'Q';
    *out++ = 'Q';
    *out++ = 'A';

    std::array<unsigned char, 16> salt{};
    std::copy(prev_hash.begin(), prev_hash.begin() + salt.size(), salt.begin());

    const int rc = argon2id_hash_raw(
        SHADOW_ARGON2_TIME_COST,
        SHADOW_ARGON2_MEMORY_KIB,
        SHADOW_ARGON2_LANES,
        input.data(),
        input.size(),
        salt.data(),
        salt.size(),
        result.begin(),
        result.size());
    if (rc != ARGON2_OK) {
        LogPrintf("ERROR: Quantum Quasar Argon2id shadow proof evaluation failed: %s\n", argon2_error_message(rc));
        result.SetNull();
        return false;
    }
    return true;
}

valtype EncodeProofPayloadV2(ShadowProofMode mode, uint64_t nonce, const CScript& target, const CScript& quantum_payout_script)
{
    valtype proof(PROOF_SIZE + 4 + target.size() + quantum_payout_script.size());
    std::copy(PROOF_MAGIC_V2.begin(), PROOF_MAGIC_V2.end(), proof.begin());
    proof[4] = static_cast<unsigned char>(mode);
    WriteLE64(proof.data() + 5, nonce);
    WriteLE16(proof.data() + PROOF_SIZE, static_cast<uint16_t>(target.size()));
    auto cursor = proof.begin() + PROOF_SIZE + 2;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(quantum_payout_script.size()));
    cursor += 2;
    std::copy(quantum_payout_script.begin(), quantum_payout_script.end(), cursor);
    return proof;
}

ShadowProofValidation ValidateQQProofAt(const valtype& proof, int height, const uint256& prev_hash, const ShadowPoolState& pool, ShadowProof& decoded_out, unsigned int& proof_evals, bool& proof_limit_exceeded)
{
    ShadowProof decoded;
    if (!DecodeProof(proof, decoded)) return ShadowProofValidation::INVALID;
    if (decoded.mode != ShadowProofMode::POW) return ShadowProofValidation::INVALID;
    if (!decoded.quantum_linked) return ShadowProofValidation::INVALID;
    if (decoded.target.empty() || decoded.target.IsUnspendable()) return ShadowProofValidation::INVALID;
    if (IsQuantumMigrationScript(decoded.target) || IsQuantumColdStakeScript(decoded.target) || IsEUTXOScript(decoded.target)) return ShadowProofValidation::INVALID;

    if (proof_evals >= MAX_SHADOW_POW_EVALS_PER_BLOCK) {
        proof_limit_exceeded = true;
        return ShadowProofValidation::INVALID;
    }
    ++proof_evals;

    uint256 proof_hash;
    if (!ComputeShadowProofHash(decoded.target, decoded.payout_script, height, prev_hash, decoded.mode, decoded.nonce, proof_hash)) {
        return ShadowProofValidation::INTERNAL_ERROR;
    }
    if (!HashMeetsLeadingZeroBits(proof_hash, RetargetedBits(decoded.mode, pool, height))) return ShadowProofValidation::INVALID;
    decoded_out = std::move(decoded);
    return ShadowProofValidation::VALID;
}

ShadowProofValidation ValidateQQProof(const valtype& proof, const CBlockIndex* pindex, const ShadowPoolState& pool, ShadowProof& decoded_out, unsigned int& proof_evals, bool& proof_limit_exceeded)
{
    if (!pindex) return ShadowProofValidation::INVALID;
    return ValidateQQProofAt(proof, pindex->nHeight, pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}, pool, decoded_out, proof_evals, proof_limit_exceeded);
}

void AddSolvedProof(ShadowPoolState& pool, ShadowProofMode mode, int height)
{
    if (mode == ShadowProofMode::POW) {
        ++pool.pow_count;
        pool.last_pow_height = height;
    } else {
        ++pool.pos_count;
        pool.last_pos_height = height;
    }
    pool.recent_modes = ((pool.recent_modes << 1) | (mode == ShadowProofMode::POS ? uint64_t{1} : uint64_t{0}));
    if (pool.recent_count < SHADOW_RETARGET_WINDOW) ++pool.recent_count;
}

std::optional<valtype> ExtractPrefixedOpReturnPayload(const CScript& script, const valtype& prefix)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return std::nullopt;
    if (!script.GetOp(pc, opcode, data) || pc != script.end()) return std::nullopt;
    if (data.size() < prefix.size()) return std::nullopt;
    if (!std::equal(prefix.begin(), prefix.end(), data.begin())) return std::nullopt;
    return valtype(data.begin() + prefix.size(), data.end());
}

std::optional<valtype> ExtractProofPayload(const CScript& script)
{
    return ExtractPrefixedOpReturnPayload(script, SHADOW_PREFIX);
}

std::optional<valtype> ExtractSignalPayload(const CScript& script)
{
    return ExtractPrefixedOpReturnPayload(script, SIGNAL_PREFIX);
}

const CScript* GetInputScript(const CBlockUndo* blockundo, size_t tx_index, size_t input_index)
{
    if (!blockundo || tx_index == 0 || blockundo->vtxundo.size() <= tx_index - 1) return nullptr;
    const CTxUndo& txundo = blockundo->vtxundo[tx_index - 1];
    if (txundo.vprevout.size() <= input_index || txundo.vprevout[input_index].IsSpent()) return nullptr;
    return &txundo.vprevout[input_index].out.scriptPubKey;
}

std::optional<CScript> GetCurrentSolverScript(const CCoinsViewCache& view, const CBlock& block, const CBlockUndo* blockundo)
{
    if (!block.IsProofOfStake() || block.vtx.size() < 2 || !block.vtx[1]->IsCoinStake()) return std::nullopt;
    const CScript* stake_input_script = GetInputScript(blockundo, 1, 0);
    if (stake_input_script && IsQuantumColdStakeScript(*stake_input_script)) return std::nullopt;
    if (!stake_input_script) return std::nullopt;
    const CScript solver_script = CanonicalLegacyStakeScript(*stake_input_script);
    if (!IsWhitelisted(view, solver_script)) return std::nullopt;
    return solver_script;
}

bool TxSpendsFromScript(const CTransaction& tx, size_t tx_index, const CBlockUndo* blockundo, const CScript& script)
{
    for (size_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
        const CScript* input_script = GetInputScript(blockundo, tx_index, input_index);
        if (input_script && CanonicalLegacyStakeScript(*input_script) == script) return true;
    }
    return false;
}

bool TxPaysToScript(const CTransaction& tx, const CScript& script)
{
    return std::any_of(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& txout) {
        return txout.nValue > 0 && txout.scriptPubKey == script;
    });
}

bool SignalReferencesRecentSolve(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash)
{
    if (!pindex || solve_height == 0 || solve_hash.IsNull()) return false;
    if (solve_height >= static_cast<uint32_t>(pindex->nHeight)) return false;
    if (pindex->nHeight - static_cast<int>(solve_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) return false;
    Coin solver_coin;
    if (!view.GetCoin(SolverOutpoint(target, solve_height, solve_hash), solver_coin)) return false;
    const int64_t block_time = pindex->GetBlockTime();
    const int64_t solver_time = static_cast<int64_t>(solver_coin.nTime);
    if (solver_time > block_time) return false;
    if (block_time - solver_time > SHADOW_SOLVER_ACTIVITY_SECONDS) return false;
    return true;
}

std::map<CScript, CScript> FindValidShadowSignalsInBlock(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo)
{
    std::map<CScript, CScript> signals;
    std::set<CScript> conflicted_targets;
    for (size_t tx_index = 1; tx_index < block.vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.vtx[tx_index];
        if (tx.IsCoinBase() || tx.IsCoinStake()) continue;
        for (const CTxOut& out : tx.vout) {
            const auto payload = ExtractSignalPayload(out.scriptPubKey);
            if (!payload) continue;
            ShadowSignal signal;
            if (!DecodeSignalPayload(*payload, signal)) continue;
            if (!signal.quantum_linked) continue;
            if (IsQuantumColdStakeScript(signal.target)) continue;
            if (!IsWhitelisted(view, signal.target)) continue;
            if (!TxSpendsFromScript(tx, tx_index, blockundo, signal.target)) continue;

            if (!TxPaysToScript(tx, signal.target)) continue;
            if (SignalReferencesRecentSolve(view, pindex, signal.target, signal.solve_height, signal.solve_hash)) {
                if (conflicted_targets.count(signal.target)) continue;
                const auto [it, inserted] = signals.emplace(signal.target, signal.payout_script);
                if (!inserted && it->second != signal.payout_script) {
                    signals.erase(it);
                    conflicted_targets.insert(signal.target);
                }
            }
        }
    }
    return signals;
}

void UpsertActiveSignals(std::map<CScript, ShadowActiveSignal>& active, const std::map<CScript, CScript>& signals, uint32_t height)
{
    for (const auto& [target, payout_script] : signals) {
        active[target] = ShadowActiveSignal{target, payout_script, height};
    }
}

std::map<CScript, ShadowActiveSignal> ReadActiveShadowSignals(const CCoinsViewCache& view, const CBlockIndex* pindex, int evaluation_height)
{
    std::map<CScript, ShadowActiveSignal> active;
    std::vector<const CBlockIndex*> window;
    for (const CBlockIndex* cursor = pindex;
         cursor && cursor->nHeight <= evaluation_height && evaluation_height - cursor->nHeight <= SHADOW_SOLVER_ACTIVITY_WINDOW;
         cursor = cursor->pprev) {
        window.push_back(cursor);
    }

    // the active set is enumerable without a UTXO-set scan. Each block stores a
    // contiguous list of validated signal markers keyed by height/block-hash/index; replaying
    // only the 14-day chain window and upserting later entries derives target -> latest signal.
    for (auto it = window.rbegin(); it != window.rend(); ++it) {
        const CBlockIndex* block_index = *it;
        for (uint32_t marker_index = 0; marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK; ++marker_index) {
            Coin coin;
            if (!view.GetCoin(ActiveSignalOutpoint(block_index, marker_index), coin)) break;
            ShadowActiveSignal signal;
            if (!DecodeActiveSignalMarker(coin.out.scriptPubKey, signal)) continue;
            if (signal.last_signal_height != static_cast<uint32_t>(block_index->nHeight)) continue;
            if (evaluation_height - static_cast<int>(signal.last_signal_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) continue;
            active[signal.target] = signal;
        }
    }
    return active;
}

std::map<CScript, CScript> ActiveSignalPayoutScripts(const std::map<CScript, ShadowActiveSignal>& active)
{
    std::map<CScript, CScript> payouts;
    for (const auto& [target, signal] : active) {
        payouts.emplace(target, signal.payout_script);
    }
    return payouts;
}

bool BuildPosPayouts(const ShadowPoolState& credited_pool, const std::optional<CScript>& current_solver, const std::map<CScript, CScript>& active_signals, bool require_quantum_payouts, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!current_solver || !active_signals.count(*current_solver) || credited_pool.pos_amount <= 0 || active_signals.empty()) return true;

    if (require_quantum_payouts) {
        for (const auto& [legacy_target, payout_script] : active_signals) {
            if (!IsDirectQuantumMigrationScript(payout_script)) return true;
        }
    }

    const CAmount share = credited_pool.pos_amount / active_signals.size();
    CAmount remainder = credited_pool.pos_amount - share * active_signals.size();
    for (const auto& [legacy_target, payout_script] : active_signals) {
        CAmount amount = share;
        if (remainder > 0) {
            ++amount;
            --remainder;
        }
        if (amount <= 0) continue;
        CAmount& current = payouts_out[payout_script];
        const auto next = CheckedAddMoney(current, amount);
        if (!next) return false;
        current = *next;
        const auto next_total = CheckedAddMoney(total_out, amount);
        if (!next_total) return false;
        total_out = *next_total;
    }
    return true;
}

ShadowClaimResult FindPowShadowClaim(const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, const ShadowPoolState& pool)
{
    if (!block.IsProofOfStake()) return {};
    unsigned int proof_evals = 0;
    bool proof_limit_exceeded = false;
    ShadowClaimResult result;
    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& ptx = block.vtx[tx_index];
        const CTransaction& tx = *ptx;
        if (tx.IsCoinBase() || tx.IsCoinStake()) {
            for (const CTxOut& out : tx.vout) {
                if (ExtractProofPayload(out.scriptPubKey)) result.invalid_claim_location = true;
            }
            continue;
        }
        for (const CTxOut& out : tx.vout) {
            const auto proof = ExtractProofPayload(out.scriptPubKey);
            if (!proof) continue;
            // DoS bound (H-2): stop after a fixed number of Argon2id evaluations per block.
            // During the 24-month legacy-compatible bridge, malformed or excess QQPROOF
            // notes do not make an otherwise legacy-valid block invalid; they simply receive
            // no shadow-ledger credit.
            ShadowProof decoded;
            const ShadowProofValidation status = ValidateQQProof(*proof, pindex, pool, decoded, proof_evals, proof_limit_exceeded);
            if (proof_limit_exceeded) return {std::nullopt, false, true};
            if (status == ShadowProofValidation::INTERNAL_ERROR) {
                return {std::nullopt, true};
            }
            if (status == ShadowProofValidation::VALID) {
                if (!TxSpendsFromScript(tx, tx_index, blockundo, decoded.target)) continue;
                const CAmount amount = ClaimablePoolAmount(pool, decoded.mode);
                if (amount <= 0) continue;
                if (result.claim) {
                    result.claim.reset();
                    result.duplicate_claim = true;
                    return result;
                }
                result.claim = ShadowClaim{decoded.payout_script, amount, decoded.mode, pool, true};
            }
        }
    }
    return result;
}

bool AddClaimMarker(CCoinsViewCache& view, const CBlockIndex* pindex, uint32_t marker_index, ShadowClaim claim)
{
    claim.direct = true;
    if (!pindex || claim.amount <= 0 || !MoneyRange(claim.amount) ||
        !IsDirectQuantumMigrationScript(claim.target) ||
        claim.target.size() > std::numeric_limits<uint16_t>::max()) {
        return false;
    }

    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_DIRECT_CLAIM, EncodeClaim(claim));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(ClaimOutpoint(pindex, marker_index), std::move(coin), true);

    const COutPoint payout_outpoint = ClaimPayoutOutpoint(pindex, marker_index, claim);

    Coin payout;
    payout.out = CTxOut{claim.amount, claim.target};
    payout.fCoinBase = true;
    payout.fCoinStake = false;
    payout.nHeight = pindex->nHeight;
    payout.nTime = pindex->GetBlockTime();
    view.AddCoin(payout_outpoint, std::move(payout), true);

    Coin payout_marker;
    payout_marker.out.nValue = 0;
    payout_marker.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_PAYOUT, {claim.target.begin(), claim.target.end()});
    payout_marker.fCoinBase = true;
    payout_marker.fCoinStake = false;
    payout_marker.nHeight = pindex->nHeight;
    payout_marker.nTime = pindex->GetBlockTime();
    view.AddCoin(GoldRushPayoutOutpoint(payout_outpoint), std::move(payout_marker), true);
    return true;
}

std::vector<COutPoint> FindDeterministicClaimMarkers(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    std::vector<COutPoint> outpoints;
    if (!pindex) return outpoints;
    for (uint32_t marker_index = 0; marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK; ++marker_index) {
        const COutPoint outpoint = ClaimOutpoint(pindex, marker_index);
        if (!view.HaveCoin(outpoint)) break;
        outpoints.push_back(outpoint);
    }
    return outpoints;
}

void AddSolverMarker(CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& solver)
{
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_SOLVER, {solver.begin(), solver.end()});
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(SolverOutpoint(solver, pindex->nHeight, pindex->GetBlockHash()), std::move(coin), true);
}

bool AddActiveSignalMarkers(CCoinsViewCache& view, const CBlockIndex* pindex, const std::map<CScript, CScript>& signals)
{
    if (!pindex) return false;
    uint32_t marker_index = 0;
    for (const auto& [target, payout_script] : signals) {
        if (marker_index >= MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK ||
            target.empty() || target.IsUnspendable() ||
            target.size() > std::numeric_limits<uint16_t>::max() ||
            !IsDirectQuantumMigrationScript(payout_script) ||
            payout_script.size() > std::numeric_limits<uint16_t>::max()) {
            return false;
        }
        Coin coin;
        coin.out.nValue = 0;
        coin.out.scriptPubKey = MarkerScript(MARKER_ACTIVE_SIGNAL, EncodeActiveSignalMarker(target, payout_script, pindex->nHeight));
        coin.fCoinBase = true;
        coin.fCoinStake = false;
        coin.nHeight = pindex->nHeight;
        coin.nTime = pindex->GetBlockTime();
        view.AddCoin(ActiveSignalOutpoint(pindex, marker_index++), std::move(coin), true);
    }
    return true;
}

void UndoActiveSignalMarkers(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return;
    for (uint32_t marker_index = 0; marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK; ++marker_index) {
        const COutPoint outpoint = ActiveSignalOutpoint(pindex, marker_index);
        if (!view.HaveCoin(outpoint)) break;
        view.SpendCoin(outpoint);
    }
}

std::vector<COutPoint> FindMarkerCoins(CCoinsViewCache& view, const valtype& tag, const CBlockIndex* pindex = nullptr)
{
    std::vector<COutPoint> outpoints;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            if ((!pindex || coin.nHeight == static_cast<uint32_t>(pindex->nHeight)) && ParseMarkerScript(coin.out.scriptPubKey, tag)) {
                outpoints.push_back(outpoint);
            }
        }
        cursor->Next();
    }
    return outpoints;
}



} // namespace

uint64_t GetActiveShadowSignalCount(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return 0;
    return ReadActiveShadowSignals(view, pindex, pindex->nHeight).size();
}

std::map<CScript, CScript> GetActiveShadowSignalPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return {};
    return ActiveSignalPayoutScripts(ReadActiveShadowSignals(view, pindex, pindex->nHeight));
}

CAmount ShadowBaseReward(int height)
{
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return 0;
    const int blocks_since_snapshot = height - SHADOW_REWARD_START_HEIGHT;
    if (height <= SHADOW_PHASE1_END_HEIGHT) {
        const int halvings = blocks_since_snapshot / 43200;
        return (580 * COIN) >> halvings;
    }
    return 463 * COIN;
}

const std::string& GetQuantumQuasarBlockNotice()
{
    static const std::string notice =
        "Quantum Quasar V30 Gold Rush is live. Upgrade to the new Quantum Resistant Blackcoin; all migrations must finish within 24 months. Source: [Blackcoin-Dev/Blackcoin](https://github.com/Blackcoin-Dev/Blackcoin)";
    return notice;
}

CScript BuildQuantumQuasarBlockNoticeScript()
{
    const std::string& notice = GetQuantumQuasarBlockNotice();
    return CScript{} << OP_RETURN << valtype{notice.begin(), notice.end()};
}

CAmount ShadowMaxBlockDirectTotal(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) {
        return 0;
    }
    // Carried pool as it stands BEFORE this block is applied, plus this block's scheduled
    // credit. This is the largest value the block could legally pay out.
    const ShadowPoolState pool = ReadPool(view);
    const auto carried = CheckedAddMoney(pool.pow_amount, pool.pos_amount);
    if (!carried) return 0;
    const auto bound = CheckedAddMoney(*carried, ShadowBaseReward(pindex->nHeight));
    if (!bound) return 0;
    return *bound;
}

ShadowGoldRushInfo GetShadowGoldRushInfo(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    const ShadowPoolState pool = ReadPool(view);
    ShadowGoldRushInfo info;
    info.pow_amount = pool.pow_amount;
    info.pos_amount = pool.pos_amount;
    info.claimed_amount = pool.claimed_amount;
    info.pow_count = pool.pow_count;
    info.pos_count = pool.pos_count;
    info.last_pow_height = pool.last_pow_height;
    info.last_pos_height = pool.last_pos_height;
    info.recent_count = pool.recent_count;
    info.recent_modes = pool.recent_modes;
    info.pow_target_bits = pindex ? RetargetedBits(ShadowProofMode::POW, pool, pindex->nHeight + 1) : RetargetedBits(ShadowProofMode::POW, pool, 0);
    return info;
}

std::map<CScript, ShadowSolverActivity> GetRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    std::map<CScript, ShadowSolverActivity> activity;
    if (!pindex) return activity;

    const int tip_height = pindex->nHeight;
    const int64_t tip_time = pindex->GetBlockTime();
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            valtype payload;
            if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_SOLVER, &payload)) {
                const int coin_height = static_cast<int>(coin.nHeight);
                const int64_t coin_time = static_cast<int64_t>(coin.nTime);
                if (coin_height <= tip_height &&
                    tip_height - coin_height <= SHADOW_SOLVER_ACTIVITY_WINDOW &&
                    coin_time <= tip_time &&
                    tip_time - coin_time <= SHADOW_SOLVER_ACTIVITY_SECONDS) {
                    CScript solver(payload.begin(), payload.end());
                    if (!solver.empty() && !solver.IsUnspendable()) {
                        ShadowSolverActivity& entry = activity[solver];
                        if (coin.nHeight > entry.height) {
                            entry.height = coin.nHeight;
                            entry.time = coin_time;
                        }
                    }
                }
            }
        }
        cursor->Next();
    }
    return activity;
}

std::optional<ShadowSolverActivity> GetRecentShadowSolverActivityForScript(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target)
{
    if (!pindex || target.empty() || target.IsUnspendable()) return std::nullopt;

    const int tip_height = pindex->nHeight;
    const int64_t tip_time = pindex->GetBlockTime();
    for (const CBlockIndex* cursor = pindex;
         cursor && cursor->nHeight <= tip_height && tip_height - cursor->nHeight <= SHADOW_SOLVER_ACTIVITY_WINDOW;
         cursor = cursor->pprev) {
        Coin coin;
        if (!view.GetCoin(SolverOutpoint(target, cursor->nHeight, cursor->GetBlockHash()), coin) || coin.IsSpent()) continue;

        valtype payload;
        if (!ParseMarkerScript(coin.out.scriptPubKey, MARKER_SOLVER, &payload)) continue;
        const CScript solver(payload.begin(), payload.end());
        if (solver != target) continue;

        const int coin_height = static_cast<int>(coin.nHeight);
        const int64_t coin_time = static_cast<int64_t>(coin.nTime);
        if (coin_height > tip_height || tip_height - coin_height > SHADOW_SOLVER_ACTIVITY_WINDOW) continue;
        if (coin_time > tip_time || tip_time - coin_time > SHADOW_SOLVER_ACTIVITY_SECONDS) continue;
        return ShadowSolverActivity{coin.nHeight, coin_time};
    }
    return std::nullopt;
}

bool HasRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash)
{
    return SignalReferencesRecentSolve(view, pindex, target, solve_height, solve_hash);
}

bool GetShadowPosDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    ShadowPoolState pool = ReadPool(view);
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pos_reward = reward - reward / 2;
    const auto next_pos_amount = CheckedAddMoney(pool.pos_amount, pos_reward);
    if (!next_pos_amount) return false;
    pool.pos_amount = *next_pos_amount;

    const std::optional<CScript> current_solver = GetCurrentSolverScript(view, block, blockundo);
    const std::map<CScript, CScript> current_signals = FindValidShadowSignalsInBlock(view, block, pindex, blockundo);
    std::map<CScript, ShadowActiveSignal> active_signal_state = ReadActiveShadowSignals(view, pindex->pprev, pindex->nHeight);
    UpsertActiveSignals(active_signal_state, current_signals, pindex->nHeight);
    const std::map<CScript, CScript> active_signals = ActiveSignalPayoutScripts(active_signal_state);
    return BuildPosPayouts(pool, current_solver, active_signals, /*require_quantum_payouts=*/true, payouts_out, total_out);
}

bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    ShadowPoolState pool = ReadPool(view);
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pow_reward = reward / 2;
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, pow_reward);
    if (!next_pow_amount) return false;
    pool.pow_amount = *next_pow_amount;

    ShadowClaimResult pow_claim = FindPowShadowClaim(block, pindex, blockundo, pool);
    if (pow_claim.internal_error) return false;
    if (pow_claim.proof_limit_exceeded || pow_claim.duplicate_claim) return true;
    if (!pow_claim.claim || !pow_claim.claim->direct) return true;
    if (!IsDirectQuantumMigrationScript(pow_claim.claim->target)) return false;
    payouts_out.emplace(pow_claim.claim->target, pow_claim.claim->amount);
    total_out = pow_claim.claim->amount;
    return MoneyRange(total_out);
}

bool CheckShadowDirectPayoutOutputs(const CTransaction& tx, const std::map<CScript, CAmount>& expected_payouts, std::string& reject_reason)
{
    if (expected_payouts.empty()) return true;

    std::set<CScript> paid;
    for (const CTxOut& txout : tx.vout) {
        const auto it = expected_payouts.find(txout.scriptPubKey);
        if (it == expected_payouts.end()) continue;
        if (!MoneyRange(txout.nValue) || txout.nValue != it->second || paid.count(txout.scriptPubKey)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
        paid.insert(txout.scriptPubKey);
    }

    for (const auto& [script, amount] : expected_payouts) {
        if (amount <= 0 || !MoneyRange(amount)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
        if (!paid.count(script)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
    }
    return true;
}

bool GetAppliedShadowDirectPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    for (const COutPoint& claim_outpoint : FindDeterministicClaimMarkers(view, pindex)) {
        Coin claim_coin;
        if (!view.GetCoin(claim_outpoint, claim_coin)) return false;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount)) return false;
        CAmount& current = payouts_out[claim->target];
        const auto next = CheckedAddMoney(current, claim->amount);
        if (!next) return false;
        current = *next;
        const auto next_total = CheckedAddMoney(total_out, claim->amount);
        if (!next_total) return false;
        total_out = *next_total;
    }
    return MoneyRange(total_out);
}

bool DecodeShadowClaimMarker(const CTxOut& txout, ShadowClaimMarkerInfo& info)
{
    info = {};
    const auto claim = DecodeClaimScript(txout.scriptPubKey);
    if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount) ||
        !IsDirectQuantumMigrationScript(claim->target)) {
        return false;
    }
    info.target = claim->target;
    info.amount = claim->amount;
    info.proof_of_work = claim->mode == ShadowProofMode::POW;
    return true;
}

bool IsShadowMarkerScript(const CScript& script)
{
    return ParseMarkerScript(script, MARKER_WHITELIST) ||
           ParseMarkerScript(script, MARKER_POOL) ||
           ParseMarkerScript(script, MARKER_DIRECT_CLAIM) ||
           ParseMarkerScript(script, MARKER_GOLD_RUSH_PAYOUT) ||
           ParseMarkerScript(script, MARKER_SOLVER) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL);
}

std::vector<ShadowSyntheticPayoutTransaction> GetAppliedShadowClaimPayoutTransactionRecords(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<ShadowSyntheticPayoutTransaction> payouts;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return payouts;

    for (uint32_t marker_index = 0; marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK; ++marker_index) {
        Coin claim_coin;
        if (!view.GetCoin(ClaimOutpoint(height, block_hash, marker_index), claim_coin)) break;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount) ||
            !IsDirectQuantumMigrationScript(claim->target)) {
            break;
        }
        payouts.push_back(ShadowSyntheticPayoutTransaction{
            BuildClaimPayoutTransaction(height, block_hash, block_time, marker_index, *claim),
            claim->target,
            claim->amount,
            claim->mode == ShadowProofMode::POW,
        });
    }
    return payouts;
}

std::vector<CTransactionRef> GetAppliedShadowClaimPayoutTransactions(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<CTransactionRef> payouts;
    for (const ShadowSyntheticPayoutTransaction& payout : GetAppliedShadowClaimPayoutTransactionRecords(view, height, block_hash, block_time)) {
        payouts.push_back(payout.tx);
    }
    return payouts;
}

std::vector<ShadowSyntheticPayoutCoin> GetAppliedShadowClaimPayoutCoins(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<ShadowSyntheticPayoutCoin> payouts;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return payouts;

    for (uint32_t marker_index = 0; marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK; ++marker_index) {
        Coin claim_coin;
        if (!view.GetCoin(ClaimOutpoint(height, block_hash, marker_index), claim_coin)) break;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount) ||
            !IsDirectQuantumMigrationScript(claim->target)) {
            break;
        }
        const CTransactionRef payout_tx = BuildClaimPayoutTransaction(height, block_hash, block_time, marker_index, *claim);
        payouts.push_back(ShadowSyntheticPayoutCoin{
            COutPoint{payout_tx->GetHash(), 0},
            CTxOut{claim->amount, claim->target},
            static_cast<uint32_t>(height),
            block_time,
        });
    }
    return payouts;
}

void MarkGoldRushDirectPayoutOutputs(CCoinsViewCache& view, const CTransaction& coinstake, const CBlockIndex* pindex, const std::map<CScript, CAmount>& payouts)
{
    if (!pindex || payouts.empty()) return;
    const uint256 txid = coinstake.GetHash();
    std::set<CScript> marked;
    for (uint32_t i = 0; i < coinstake.vout.size(); ++i) {
        const CTxOut& txout = coinstake.vout[i];
        const auto it = payouts.find(txout.scriptPubKey);
        if (it == payouts.end() || marked.count(txout.scriptPubKey) || txout.nValue != it->second) continue;

        Coin marker;
        marker.out.nValue = 0;
        marker.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_PAYOUT, {txout.scriptPubKey.begin(), txout.scriptPubKey.end()});
        marker.fCoinBase = true;
        marker.fCoinStake = false;
        marker.nHeight = pindex->nHeight;
        marker.nTime = pindex->GetBlockTime();
        view.AddCoin(GoldRushPayoutOutpoint(COutPoint{txid, i}), std::move(marker), true);
        marked.insert(txout.scriptPubKey);
    }
}

void UndoGoldRushDirectPayoutOutputMarkers(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return;
    for (const COutPoint& outpoint : FindMarkerCoins(view, MARKER_GOLD_RUSH_PAYOUT, pindex)) {
        view.SpendCoin(outpoint);
    }
}

bool IsGoldRushDirectPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint, CScript* payout_script)
{
    Coin marker;
    if (!view.GetCoin(GoldRushPayoutOutpoint(outpoint), marker)) return false;
    valtype payload;
    if (!ParseMarkerScript(marker.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT, &payload)) return false;
    if (payout_script) {
        *payout_script = CScript(payload.begin(), payload.end());
    }
    return true;
}

const std::vector<unsigned char>& GetShadowPrefix()
{
    return SHADOW_PREFIX;
}

bool TransactionHasShadowProof(const CTransaction& tx)
{
    for (const CTxOut& out : tx.vout) {
        if (ExtractProofPayload(out.scriptPubKey)) return true;
    }
    return false;
}

bool TransactionHasShadowSignal(const CTransaction& tx)
{
    for (const CTxOut& out : tx.vout) {
        if (ExtractSignalPayload(out.scriptPubKey)) return true;
    }
    return false;
}

bool CheckShadowPowClaimForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason)
{
    if (!TransactionHasShadowProof(tx)) return true;
    if (!gold_rush_active || !pindexPrev) {
        reject_reason = "shadow-proof-inactive";
        return false;
    }
    if (tx.IsCoinBase() || tx.IsCoinStake()) {
        reject_reason = "shadow-proof-invalid-location";
        return false;
    }

    const int height = pindexPrev->nHeight + 1;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) {
        reject_reason = "shadow-proof-height";
        return false;
    }

    ShadowPoolState pool = ReadPool(view);
    const CAmount reward = ShadowBaseReward(height);
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, reward / 2);
    if (!next_pow_amount) {
        reject_reason = "shadow-proof-pool-overflow";
        return false;
    }
    pool.pow_amount = *next_pow_amount;

    bool seen_proof = false;
    unsigned int proof_evals = 0;
    bool proof_limit_exceeded = false;
    for (const CTxOut& out : tx.vout) {
        const auto proof = ExtractProofPayload(out.scriptPubKey);
        if (!proof) continue;
        if (seen_proof) {
            reject_reason = "shadow-proof-duplicate";
            return false;
        }
        seen_proof = true;

        ShadowProof decoded;
        const ShadowProofValidation status = ValidateQQProofAt(*proof, height, pindexPrev->GetBlockHash(), pool, decoded, proof_evals, proof_limit_exceeded);
        if (proof_limit_exceeded) {
            reject_reason = "shadow-proof-limit";
            return false;
        }
        if (status != ShadowProofValidation::VALID) {
            reject_reason = status == ShadowProofValidation::INTERNAL_ERROR ? "shadow-proof-error" : "shadow-proof-invalid";
            return false;
        }

        bool spends_target = false;
        for (const CTxIn& txin : tx.vin) {
            Coin coin;
            if (view.GetCoin(txin.prevout, coin) && !coin.IsSpent() && coin.out.scriptPubKey == decoded.target) {
                spends_target = true;
                break;
            }
        }
        if (!spends_target) {
            reject_reason = "shadow-proof-input-mismatch";
            return false;
        }
    }

    return true;
}

std::set<CScript> BuildLegacyWhitelist(CCoinsView& view)
{
    std::set<CScript> whitelist;
    std::map<CScript, CAmount> balances;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            if (coin.out.nValue > 0 && !coin.out.scriptPubKey.IsUnspendable()) {
                const CScript script = CanonicalLegacyStakeScript(coin.out.scriptPubKey);
                CAmount& balance = balances[script];
                if (balance < SHADOW_WHITELIST_MIN_BALANCE) {
                    const CAmount needed = SHADOW_WHITELIST_MIN_BALANCE - balance;
                    balance = coin.out.nValue >= needed ? SHADOW_WHITELIST_MIN_BALANCE : balance + coin.out.nValue;
                    if (balance >= SHADOW_WHITELIST_MIN_BALANCE) {
                        whitelist.insert(script);
                    }
                }
            }
        }
        cursor->Next();
    }
    return whitelist;
}

void SaveLegacyWhitelist(const fs::path& path, const std::set<CScript>& whitelist)
{
    CAutoFile fileout{fsbridge::fopen(path, "wb")};
    if (fileout.IsNull()) {
        LogPrintf("Quantum Quasar: Error opening %s for writing\n", fs::PathToString(path));
        return;
    }
    try {
        fileout << whitelist;
        LogPrintf("Quantum Quasar: Saved diagnostic legacy whitelist to %s (%u entries)\n", fs::PathToString(path), whitelist.size());
    } catch (const std::exception& e) {
        LogPrintf("Quantum Quasar: Error saving whitelist to %s: %s\n", fs::PathToString(path), e.what());
    }
}

bool LoadLegacyWhitelist(const fs::path& path, std::set<CScript>& whitelist)
{
    CAutoFile filein{fsbridge::fopen(path, "rb")};
    if (filein.IsNull()) return false;
    try {
        filein >> whitelist;
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Quantum Quasar: Error loading whitelist from %s: %s\n", fs::PathToString(path), e.what());
        whitelist.clear();
        return false;
    }
}

void ApplyLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex, const fs::path* dump_path)
{
    if (!pindex || pindex->nHeight != SHADOW_WHITELIST_HEIGHT) return;
    const std::set<CScript> whitelist = BuildLegacyWhitelist(view);
    for (const CScript& script : whitelist) {
        Coin coin;
        coin.out.nValue = 0;
        coin.out.scriptPubKey = MarkerScript(MARKER_WHITELIST, {script.begin(), script.end()});
        coin.fCoinBase = true;
        coin.fCoinStake = false;
        coin.nHeight = pindex->nHeight;
        coin.nTime = pindex->GetBlockTime();
        view.AddCoin(WhitelistOutpoint(script), std::move(coin), true);
    }
    if (dump_path) SaveLegacyWhitelist(*dump_path, whitelist);
    LogPrintf("Quantum Quasar: Applied deterministic legacy whitelist snapshot with %u entries\n", whitelist.size());
}

void UndoLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight != SHADOW_WHITELIST_HEIGHT) return;
    uint32_t removed = 0;
    for (const COutPoint& outpoint : FindMarkerCoins(view, MARKER_WHITELIST, pindex)) {
        if (view.SpendCoin(outpoint)) ++removed;
    }
    LogPrintf("Quantum Quasar: Removed %u legacy whitelist snapshot markers during reorg\n", removed);
}

bool IsWhitelisted(const CCoinsViewCache& view, const CScript& scriptPubKey)
{
    return view.HaveCoin(WhitelistOutpoint(CanonicalLegacyStakeScript(scriptPubKey)));
}

bool BuildShadowSignalData(const CScript& target, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    (void)target;
    (void)solve_height;
    (void)solve_hash;
    return false;
}

bool BuildShadowSignalData(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    if (target.empty() || target.IsUnspendable()) return false;
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) return false;
    if (target.size() > std::numeric_limits<uint16_t>::max() || quantum_payout_script.size() > std::numeric_limits<uint16_t>::max()) return false;
    if ((solve_height == 0) != solve_hash.IsNull()) return false;
    const valtype payload = EncodeSignalPayloadV2(target, quantum_payout_script, solve_height, solve_hash);
    data_out = SIGNAL_PREFIX;
    data_out.insert(data_out.end(), payload.begin(), payload.end());
    return true;
}

bool MineShadowProofData(const CScript& target, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool proof_of_stake, uint64_t max_tries, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    (void)target;
    (void)pindexPrev;
    (void)view;
    (void)proof_of_stake;
    (void)max_tries;
    return false;
}

bool MineShadowProofData(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t max_tries, std::vector<unsigned char>& data_out)
{
    return MineShadowProofDataRange(target, quantum_payout_script, pindexPrev, view, 0, 1, max_tries, data_out);
}

ShadowPowWork PrepareShadowPowWork(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view)
{
    ShadowPowWork work;
    if (!pindexPrev) return work;
    const int height = pindexPrev->nHeight + 1;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return work;
    if (target.empty() || target.IsUnspendable()) return work;
    if (IsQuantumMigrationScript(target) || IsQuantumColdStakeScript(target) || IsEUTXOScript(target)) return work;
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) return work;
    if (target.size() > std::numeric_limits<uint16_t>::max() || quantum_payout_script.size() > std::numeric_limits<uint16_t>::max()) return work;

    // The ONLY coins-view read: snapshot the shadow pool and derive this tip's difficulty.
    ShadowPoolState pool = ReadPool(view);
    const CAmount reward = ShadowBaseReward(height);
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, reward / 2);
    if (!next_pow_amount) return work;
    pool.pow_amount = *next_pow_amount;

    work.bits = RetargetedBits(ShadowProofMode::POW, pool, height);
    work.target = target;
    work.quantum_payout_script = quantum_payout_script;
    work.height = height;
    work.prev_hash = pindexPrev->GetBlockHash();
    work.valid = true;
    return work;
}

bool GrindShadowPowWork(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done)
{
    // Pure Argon2id grind. Touches no chain state, so it must run WITHOUT cs_main held.
    data_out.clear();
    if (tries_done) *tries_done = 0;
    if (!work.valid || nonce_step == 0 || max_tries == 0) return false;
    uint64_t nonce = start_nonce;
    for (uint64_t tries = 0; tries < max_tries; ++tries) {
        if (tries_done) *tries_done = tries + 1;
        uint256 proof_hash;
        if (!ComputeShadowProofHash(work.target, work.quantum_payout_script, work.height, work.prev_hash, ShadowProofMode::POW, nonce, proof_hash)) return false;
        if (HashMeetsLeadingZeroBits(proof_hash, work.bits)) {
            const valtype payload = EncodeProofPayloadV2(ShadowProofMode::POW, nonce, work.target, work.quantum_payout_script);
            data_out = SHADOW_PREFIX;
            data_out.insert(data_out.end(), payload.begin(), payload.end());
            return true;
        }
        // `nonce_step` is normally 1 for contiguous atomic ranges. The overflow
        // guard keeps a long-running miner from wrapping into already-searched space.
        if (std::numeric_limits<uint64_t>::max() - nonce < nonce_step) break;
        nonce += nonce_step;
    }
    return false;
}

bool MineShadowProofDataRange(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done)
{
    // Convenience wrapper (used by the RPC path): prepare under the caller's lock, then grind.
    const ShadowPowWork work = PrepareShadowPowWork(target, quantum_payout_script, pindexPrev, view);
    return GrindShadowPowWork(work, start_nonce, nonce_step, max_tries, data_out, tries_done);
}

bool ApplyShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    if (!gold_rush_active) return true;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;
    const ShadowPoolState undo_pool = ReadPool(view);
    ShadowPoolState pool = undo_pool;
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pow_reward = reward / 2;
    const CAmount pos_reward = reward - pow_reward;
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, pow_reward);
    const auto next_pos_amount = CheckedAddMoney(pool.pos_amount, pos_reward);
    if (!next_pow_amount || !next_pos_amount) {
        LogPrintf("ERROR: Quantum Quasar shadow jackpot pool overflow at height %d\n", pindex->nHeight);
        return false;
    }
    pool.pow_amount = *next_pow_amount;
    pool.pos_amount = *next_pos_amount;
    if (!ShadowObligationWithinCap(pool)) {
        LogPrintf("ERROR: Quantum Quasar shadow emission cap exceeded at height %d\n", pindex->nHeight);
        return false;
    }

    const ShadowPoolState credited_pool = pool;
    uint32_t claim_marker_index = 0;

    const std::optional<CScript> current_solver = GetCurrentSolverScript(view, block, blockundo);
    if (current_solver) {
        AddSolverMarker(view, pindex, *current_solver);
    }
    const std::map<CScript, CScript> current_signals = FindValidShadowSignalsInBlock(view, block, pindex, blockundo);
    if (!AddActiveSignalMarkers(view, pindex, current_signals)) return false;
    std::map<CScript, ShadowActiveSignal> active_signal_state = ReadActiveShadowSignals(view, pindex, pindex->nHeight);
    const std::map<CScript, CScript> active_signals = ActiveSignalPayoutScripts(active_signal_state);
    ShadowClaimResult pow_claim = FindPowShadowClaim(block, pindex, blockundo, credited_pool);
    if (pow_claim.internal_error) return false;
    if (pow_claim.duplicate_claim) {
        LogPrintf("Quantum Quasar: ignored duplicate QQPROOF claims at height %d; block remains legacy-compatible\n",
            pindex->nHeight);
    }
    if (pow_claim.invalid_claim_location) {
        LogPrintf("Quantum Quasar: ignored QQPROOF in coinbase/coinstake at height %d; claims must be fee-paying transactions\n",
            pindex->nHeight);
    }
    if (pow_claim.proof_limit_exceeded) {
        LogPrintf("Quantum Quasar: ignored QQPROOF claims at height %d after the %u-proof validation limit; block remains legacy-compatible\n",
            pindex->nHeight, MAX_SHADOW_POW_EVALS_PER_BLOCK);
    }
    if (pow_claim.duplicate_claim || pow_claim.proof_limit_exceeded) {
        pow_claim.claim.reset();
    }

    std::map<CScript, CAmount> pos_payouts;
    CAmount pos_payout_total{0};
    if (!BuildPosPayouts(credited_pool, current_solver, active_signals, /*require_quantum_payouts=*/true, pos_payouts, pos_payout_total)) return false;

    if (pos_payout_total > 0) {
        if (!AddClaimedAmount(pool, pos_payout_total)) {
            LogPrintf("ERROR: Quantum Quasar POS shadow claim exceeds emission cap at height %d\n", pindex->nHeight);
            return false;
        }
        for (const auto& [payout_script, amount] : pos_payouts) {
            if (amount <= 0) continue;
            if (!AddClaimMarker(view, pindex, claim_marker_index++, ShadowClaim{payout_script, amount, ShadowProofMode::POS, undo_pool, true})) return false;
        }
        AddSolvedProof(pool, ShadowProofMode::POS, pindex->nHeight);
        pool.pos_amount = 0;
        LogPrintf("Quantum Quasar: Accepted quantum-linked POS shadow-ledger credit at height %d for %u active participants\n",
            pindex->nHeight,
            active_signals.size());
    }

    if (pow_claim.claim) {
        pow_claim.claim->undo_pool = undo_pool;
        if (!AddClaimedAmount(pool, pow_claim.claim->amount)) {
            LogPrintf("ERROR: Quantum Quasar POW shadow claim exceeds emission cap at height %d\n", pindex->nHeight);
            return false;
        }
        if (!AddClaimMarker(view, pindex, claim_marker_index++, *pow_claim.claim)) return false;
        AddSolvedProof(pool, ShadowProofMode::POW, pindex->nHeight);
        pool.pow_amount = 0;
        LogPrintf("Quantum Quasar: Accepted quantum-linked POW shadow-ledger credit at height %d for %d satoshis\n",
            pindex->nHeight,
            pow_claim.claim->amount);
    }
    if (!ShadowObligationWithinCap(pool)) {
        LogPrintf("ERROR: Quantum Quasar shadow obligation cap exceeded at height %d\n", pindex->nHeight);
        return false;
    }
    WritePool(view, pindex, pool);
    return true;
}

bool UndoShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    if (!gold_rush_active) return true;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;
    ShadowPoolState pool = ReadPool(view);
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    bool restored_from_claim = false;
    const std::vector<COutPoint> claim_outpoints = FindDeterministicClaimMarkers(view, pindex);
    for (uint32_t marker_index = 0; marker_index < claim_outpoints.size(); ++marker_index) {
        const COutPoint& claim_outpoint = claim_outpoints[marker_index];
        Coin claim_coin;
        if (!view.GetCoin(claim_outpoint, claim_coin)) continue;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (claim && !restored_from_claim) {
            pool = claim->undo_pool;
            restored_from_claim = true;
        }
        if (claim) {
            const COutPoint payout_outpoint = ClaimPayoutOutpoint(pindex, marker_index, *claim);
            const COutPoint payout_marker_outpoint = GoldRushPayoutOutpoint(payout_outpoint);
            if (view.HaveCoin(payout_marker_outpoint)) {
                view.SpendCoin(payout_marker_outpoint);
            }
            if (view.HaveCoin(payout_outpoint)) {
                view.SpendCoin(payout_outpoint);
            } else {
                LogPrintf("ERROR: Quantum Quasar missing shadow payout coin for claim at height %d\n", pindex->nHeight);
                return false;
            }
        }
        view.SpendCoin(claim_outpoint);
    }
    // Remove the (at most one) solver marker this block added. ApplyShadowBlock stores it at
    // the deterministic SolverOutpoint(solver, height, blockhash), so when block-undo data is
    // available we recompute the solver and spend that exact outpoint -- avoiding a full
    // UTXO-set cursor scan on every disconnected block (reorg-DoS, H-3). The cursor scan is
    // retained only as a fallback for callers without undo data (e.g. some unit tests).
    if (blockundo) {
        const std::optional<CScript> solver = GetCurrentSolverScript(view, block, blockundo);
        if (solver) {
            const COutPoint solver_outpoint = SolverOutpoint(*solver, pindex->nHeight, pindex->GetBlockHash());
            if (view.HaveCoin(solver_outpoint)) view.SpendCoin(solver_outpoint);
        }
    } else {
        for (const COutPoint& solver_outpoint : FindMarkerCoins(view, MARKER_SOLVER, pindex)) {
            view.SpendCoin(solver_outpoint);
        }
    }
    UndoActiveSignalMarkers(view, pindex);
    if (!restored_from_claim) {
        const CAmount pow_reward = reward / 2;
        const CAmount pos_reward = reward - pow_reward;
        pool.pow_amount = pool.pow_amount > pow_reward ? pool.pow_amount - pow_reward : 0;
        pool.pos_amount = pool.pos_amount > pos_reward ? pool.pos_amount - pos_reward : 0;
    }
    WritePool(view, pindex->pprev ? pindex->pprev : pindex, pool);
    return true;
}
