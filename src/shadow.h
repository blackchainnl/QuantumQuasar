#ifndef BLACKCOIN_SHADOW_H
#define BLACKCOIN_SHADOW_H

#include <consensus/amount.h>
#include <primitives/block.h>
#include <script/script.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

class CBlockIndex;
class CBlockUndo;
class CCoinsView;
class CCoinsViewCache;
namespace Consensus {
struct Params;
}

struct ShadowGoldRushInfo {
    CAmount pow_amount{0};
    CAmount pos_amount{0};
    CAmount claimed_amount{0};
    uint32_t pow_count{0};
    uint32_t pos_count{0};
    uint32_t last_pow_height{0};
    uint32_t last_pos_height{0};
    uint8_t recent_count{0};
    uint64_t recent_modes{0};
    unsigned int pow_target_bits{0};
};

struct ShadowSolverActivity {
    uint32_t height{0};
    int64_t time{0};
};

struct ShadowClaimMarkerInfo {
    CScript target;
    CAmount amount{0};
    bool proof_of_work{false};
};

struct ShadowSyntheticPayoutCoin {
    COutPoint outpoint;
    CTxOut txout;
    uint32_t height{0};
    int64_t time{0};
};

// Gold Rush schedule heights. Defaults are the mainnet values; on regtest they may be
// overridden via SetShadowRegtestSchedule() (driven by -shadowwhitelistheight /
// -shadowgoldrushblocks) so the reward window is reachable for end-to-end testing.
// They are set once during chainparams init (before any block validation) and read-only
// thereafter, so the runtime globals are race-free.
extern int SHADOW_WHITELIST_HEIGHT;
extern int SHADOW_REWARD_START_HEIGHT;
extern int SHADOW_GOLD_RUSH_BLOCKS;
extern int SHADOW_PHASE1_END_HEIGHT;
extern int SHADOW_REWARD_END_HEIGHT;

/** Regtest-only: shift the Gold Rush schedule to a small, reachable window. */
void SetShadowRegtestSchedule(int whitelist_height, int gold_rush_blocks);

/** Quantum witness spends activate when Gold Rush rewards can first materialize,
 * then stay active through the migration and final lockout phases. */
bool IsQuantumWitnessSpendActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight);
static constexpr unsigned int SHADOW_EQUAL_FOOTING_TIME = 1713938400;
static constexpr CAmount SHADOW_WHITELIST_MIN_BALANCE = 10000 * COIN;
static constexpr int SHADOW_SOLVER_ACTIVITY_SECONDS = 14 * 24 * 60 * 60;
static constexpr int SHADOW_SOLVER_ACTIVITY_WINDOW = SHADOW_SOLVER_ACTIVITY_SECONDS / 64;

/** Exact total value in the deterministic 180-day Gold Rush schedule.
 *  Direct payouts are bounded per block by ShadowBaseReward() and the coinstake
 *  reward cap; this invariant locks the total scheduled issuance against drift. */
static constexpr CAmount SHADOW_MAX_EMISSION = 51437700 * COIN;

/** Get the magic OP_RETURN prefix used for Quantum Quasar shadow proofs. */
const std::vector<unsigned char>& GetShadowPrefix();

/** Build the height-5,920,000 whitelist from aggregate balances in the currently connected UTXO view. */
std::set<CScript> BuildLegacyWhitelist(CCoinsView& view);

/** Optional diagnostic cache. Consensus must not trust this file. */
void SaveLegacyWhitelist(const fs::path& path, const std::set<CScript>& whitelist);
bool LoadLegacyWhitelist(const fs::path& path, std::set<CScript>& whitelist);

/** Apply/remove deterministic chainstate markers for the legacy whitelist snapshot. */
void ApplyLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex, const fs::path* dump_path = nullptr);
void UndoLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex);

/** Check if a script is in the deterministic height-5,920,000 whitelist. */
bool IsWhitelisted(const CCoinsViewCache& view, const CScript& scriptPubKey);

/** Deterministic per-block Gold Rush shadow reward schedule (exposed for tests/cap checks). */
CAmount ShadowBaseReward(int height);

/** Plain-English transition notice embedded by upgraded local block producers. */
const std::string& GetQuantumQuasarBlockNotice();
CScript BuildQuantumQuasarBlockNoticeScript();

/** Legacy direct-emission helper retained for stale marker tests and migration cleanup.
 *  ConnectBlock no longer uses this path during the 24-month compatibility bridge; Gold Rush
 *  note transactions update the upgraded shadow ledger without increasing base block rewards. */
CAmount ShadowMaxBlockDirectTotal(const CCoinsViewCache& view, const CBlockIndex* pindex);

/** Read-only Gold Rush pool and participant diagnostics for RPC/status reporting. */
ShadowGoldRushInfo GetShadowGoldRushInfo(const CCoinsViewCache& view, const CBlockIndex* pindex);
std::map<CScript, ShadowSolverActivity> GetRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex);
uint64_t GetActiveShadowSignalCount(const CCoinsViewCache& view, const CBlockIndex* pindex);
std::map<CScript, CScript> GetActiveShadowSignalPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex);
bool HasRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash);

/** Compute PoS Gold Rush shadow-ledger credits implied by a candidate block.
 *  Returns false only on malformed/overflow state; a true return with total_out=0 means no credit is recorded. */
bool GetShadowPosDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Build a quantum-linked QQSIGNAL OP_RETURN data push proving recent whitelisted solver activity.
 *  Live Gold Rush consensus only credits regular fee-paying transactions that reference a
 *  prior solver marker inside the 14-day window. The legacy overload is retained for source
 *  compatibility and always fails closed. */
bool BuildShadowSignalData(const CScript& target, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out);
bool BuildShadowSignalData(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out);

/** Build a mined OP_RETURN data push containing the QQSPROOF prefix and payload. */
bool MineShadowProofData(const CScript& target, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool proof_of_stake, uint64_t max_tries, std::vector<unsigned char>& data_out);
bool MineShadowProofData(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t max_tries, std::vector<unsigned char>& data_out);
bool MineShadowProofDataRange(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done = nullptr);

/** Immutable Gold Rush PoW work parameters snapshotted for one tip. Produced under the chain
 *  lock by PrepareShadowPowWork(); GrindShadowPowWork() then grinds Argon2id over a nonce range
 *  with NO lock held (the grind never reads the coins view). This keeps the in-process miner from
 *  holding cs_main across the memory-hard grind. */
struct ShadowPowWork {
    bool valid{false};
    CScript target;
    CScript quantum_payout_script;
    int height{0};
    uint256 prev_hash;
    unsigned int bits{0};
};
/** Snapshot PoW work for the block after pindexPrev. Reads the shadow pool from `view`, so the
 *  caller must hold the chain state stable (cs_main). Cheap; does no Argon2id work. */
ShadowPowWork PrepareShadowPowWork(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view);
/** Pure Argon2id grind over a nonce range. No chain/view access; safe to call with NO lock held. */
bool GrindShadowPowWork(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done = nullptr);

/** Compute PoW Gold Rush shadow-ledger credits implied by a candidate block. */
bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Mempool policy helpers for next-block-only QQSPROOF claims. */
bool TransactionHasShadowProof(const CTransaction& tx);
bool CheckShadowPowClaimForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason);

/** Obsolete direct-emission helper retained for stale test-build marker cleanup. */
bool CheckShadowDirectPayoutOutputs(const CTransaction& tx, const std::map<CScript, CAmount>& expected_payouts, std::string& reject_reason);

/** Read quantum Gold Rush shadow-ledger credits already recorded by ApplyShadowBlock. */
bool GetAppliedShadowDirectPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Decode a spendable Gold Rush shadow-ledger claim marker. */
bool DecodeShadowClaimMarker(const CTxOut& txout, ShadowClaimMarkerInfo& info);

/** Return true for Quantum Quasar's zero-value internal chainstate marker records. */
bool IsShadowMarkerScript(const CScript& script);

/** Build wallet-indexable synthetic payout transactions for applied claim markers in one block. */
std::vector<CTransactionRef> GetAppliedShadowClaimPayoutTransactions(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time);

/** Build indexable synthetic payout coins for applied claim markers in one block. */
std::vector<ShadowSyntheticPayoutCoin> GetAppliedShadowClaimPayoutCoins(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time);

/** Mark/check obsolete direct Gold Rush emission outputs from earlier test builds.
 *  Current Gold Rush blocks no longer create these base-chain payout outputs. */
void MarkGoldRushDirectPayoutOutputs(CCoinsViewCache& view, const CTransaction& coinstake, const CBlockIndex* pindex, const std::map<CScript, CAmount>& payouts);
void UndoGoldRushDirectPayoutOutputMarkers(CCoinsViewCache& view, const CBlockIndex* pindex);
bool IsGoldRushDirectPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint, CScript* payout_script = nullptr);

/** Apply/remove deterministic shadow claim state for one shadow-epoch block. */
bool ApplyShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);
bool UndoShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);



#endif // BLACKCOIN_SHADOW_H
