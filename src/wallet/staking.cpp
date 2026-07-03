// Copyright (c) 2014-2023 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Staking start/stop algos by Qtum
// Copyright (c) 2016-2023 The Qtum developers

#include <index/txindex.h>
#include <addresstype.h>
#include <chain.h>
#include <common/args.h>
#include <consensus/demurrage.h>
#include <crypto/mldsa.h>
#include <key_io.h>
#include <node/quantum_pool.h>
#include <policy/policy.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/redelegation.h>
#include <wallet/staking.h>
#include <hash.h>
#include <node/miner.h>
#include <script/signingprovider.h>
#include <shadow.h>
#include <support/cleanse.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>
#include <undo.h>
#include <validation.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <map>
#include <set>

namespace wallet {

static int64_t GetStakeCombineThreshold() { return 500 * COIN; }
static int64_t GetStakeSplitThreshold() { return 2 * GetStakeCombineThreshold(); }

static bool IsKnownColdStakeOutput(CWallet& wallet, const CTxOut& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    (void)wallet;
    return IsQuantumColdStakeScript(output.scriptPubKey);
}

static bool CoinStakeSpendsKnownColdStake(CWallet& wallet, const CMutableTransaction& txNew, const std::vector<CTransactionRef>& prev_txs) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (txNew.vin.size() != prev_txs.size()) {
        return false;
    }

    for (size_t i = 0; i < txNew.vin.size(); ++i) {
        const CTxIn& txin = txNew.vin[i];
        const CTransactionRef& prev_tx = prev_txs[i];
        if (!prev_tx || prev_tx->GetHash() != txin.prevout.hash || txin.prevout.n >= prev_tx->vout.size()) {
            return false;
        }
        if (IsKnownColdStakeOutput(wallet, prev_tx->vout[txin.prevout.n])) {
            return true;
        }
    }
    return false;
}

namespace {

struct AutoDemurrageAttestCandidate
{
    std::vector<unsigned char> witness_program;
    uint256 key_hash;
    int inactive_blocks{0};
    COutPoint outpoint;
};

struct AutoRedelegationSource
{
    CTxDestination source_dest;
    std::vector<unsigned char> witness_program;
    uint256 staker_pubkey_hash;
    CAmount amount{0};
    int activation_height{0};
    int last_win_height{0};
};

bool IsGoldRushStakeHeight(const CBlockIndex* tip)
{
    if (!tip) return false;
    const int next_height = tip->nHeight + 1;
    return next_height >= SHADOW_REWARD_START_HEIGHT && next_height <= SHADOW_REWARD_END_HEIGHT;
}

std::set<CScript> WhitelistedGoldRushStakeScripts(
    const CCoinsViewCache& view,
    const std::set<std::pair<const CWalletTx*, unsigned int>>& coins)
{
    std::set<CScript> scripts;
    for (const auto& coin : coins) {
        if (!coin.first || !coin.first->tx || coin.second >= coin.first->tx->vout.size()) continue;
        const CScript script = CanonicalizeLegacyStakeScript(coin.first->tx->vout[coin.second].scriptPubKey);
        if (IsWhitelisted(view, script)) {
            scripts.insert(script);
        }
    }
    return scripts;
}

void RestrictToGoldRushStakeScripts(
    const std::set<CScript>& allowed_scripts,
    std::set<std::pair<const CWalletTx*, unsigned int>>& coins,
    CAmount& value_in)
{
    if (allowed_scripts.empty()) return;

    value_in = 0;
    for (auto it = coins.begin(); it != coins.end();) {
        const CWalletTx* wtx = it->first;
        const unsigned int n = it->second;
        if (!wtx || !wtx->tx || n >= wtx->tx->vout.size()) {
            it = coins.erase(it);
            continue;
        }
        const CTxOut& txout = wtx->tx->vout[n];
        const CScript script = CanonicalizeLegacyStakeScript(txout.scriptPubKey);
        if (!allowed_scripts.count(script)) {
            it = coins.erase(it);
            continue;
        }
        value_in += txout.nValue;
        ++it;
    }
}

bool HasUnderCapRedelegationAlternative(const CCoinsViewCache& view, const uint256& source_staker_hash, const uint256& target_staker_hash, CAmount delegation_amount)
{
    std::vector<QuantumRedelegationCandidate> candidates;
    for (const uint256& staker_hash : node::ListQuantumPoolOperators()) {
        if (staker_hash == source_staker_hash || staker_hash == target_staker_hash) continue;
        const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));
        QuantumRedelegationCandidate candidate;
        candidate.staker_pubkey_hash = staker_hash;
        candidate.staker_pubkey = share.operator_share.staker_pubkey;
        candidate.operator_value = share.operator_share.verified_value;
        candidate.total_coldstake = share.total_coldstake;
        candidate.operator_commitment_verified = share.operator_share.operator_commitment_verified;
        candidate.current_operator = false;
        candidates.push_back(std::move(candidate));
    }
    return HasUnderCapQuantumRedelegationCandidate(candidates, delegation_amount);
}

struct AutoShadowSignalCandidate
{
    CScript target;
    uint32_t solve_height{0};
    uint256 solve_hash;
};

static constexpr const char* SHADOW_SIGNAL_COMMENT{"PoS Claim"};
static constexpr const char* OLD_SHADOW_SIGNAL_COMMENT{"Quantum PoS Claim"};
static constexpr const char* SHADOW_SIGNAL_PAYOUT_LABEL{"PoS - Quantum Stake Address"};
static constexpr const char* OLD_SHADOW_SIGNAL_PAYOUT_LABEL{"Quantum PoS Reward Address"};
static constexpr const char* LEGACY_SHADOW_SIGNAL_PAYOUT_LABEL{"goldrush-pos"};

bool HasPendingShadowSignal(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        const auto comment = wtx.mapValue.find("comment");
        if (comment == wtx.mapValue.end() || (comment->second != SHADOW_SIGNAL_COMMENT && comment->second != OLD_SHADOW_SIGNAL_COMMENT)) continue;
        if (wtx.isAbandoned() || wtx.isConflicted()) continue;
        if (wallet.GetTxDepthInMainChain(wtx) == 0) return true;
    }
    return false;
}

bool EnsureShadowSignalPayout(CWallet& wallet, CScript& payout_script, std::string& payout_address, bilingual_str& error)
{
    std::optional<CTxDestination> reused_dest;
    bool relabel_reused_dest{false};
    {
        LOCK(wallet.cs_wallet);
        for (const auto& [dest, entry] : wallet.m_address_book) {
            const std::string label = entry.GetLabel();
            if (entry.IsChange() || (label != SHADOW_SIGNAL_PAYOUT_LABEL && label != OLD_SHADOW_SIGNAL_PAYOUT_LABEL && label != LEGACY_SHADOW_SIGNAL_PAYOUT_LABEL)) continue;
            if (!IsValidDestination(dest) || !IsQuantumMigrationDestination(dest)) continue;
            if (wallet.IsMine(dest) == ISMINE_NO) continue;
            payout_address = EncodeDestination(dest);
            payout_script = GetScriptForDestination(dest);
            reused_dest = dest;
            relabel_reused_dest = label != SHADOW_SIGNAL_PAYOUT_LABEL;
            break;
        }
    }
    if (reused_dest) {
        if (relabel_reused_dest && !wallet.SetAddressBook(*reused_dest, SHADOW_SIGNAL_PAYOUT_LABEL, AddressPurpose::RECEIVE)) {
            error = _("Failed to update Gold Rush PoS payout address label.");
            return false;
        }
        return true;
    }

    auto dest = wallet.GetNewQuantumDestination(SHADOW_SIGNAL_PAYOUT_LABEL);
    if (!dest) {
        error = util::ErrorString(dest);
        return false;
    }
    payout_address = EncodeDestination(*dest);
    payout_script = GetScriptForDestination(*dest);
    wallet.WalletLogPrintf("Gold Rush PoS signaler created payout address %s. Back up the wallet.\n", payout_address);
    return true;
}

bool FindAutoShadowSignalCandidate(CWallet& wallet, AutoShadowSignalCandidate& candidate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, wallet.cs_wallet)
{
    const CBlockIndex* tip = wallet.chain().getTip();
    if (!tip) return false;
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!consensus.IsGoldRushEpoch(tip->GetMedianTimePast()) ||
        tip->nHeight < SHADOW_REWARD_START_HEIGHT ||
        tip->nHeight > SHADOW_REWARD_END_HEIGHT) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: inactive at height=%d\n", tip->nHeight);
        return false;
    }
    if (wallet.m_shadow_signal_last_auto_scan_height >= tip->nHeight) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: already scanned height=%d\n", tip->nHeight);
        return false;
    }
    wallet.m_shadow_signal_last_auto_scan_height = tip->nHeight;
    if (HasPendingShadowSignal(wallet)) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: pending signal already exists\n");
        return false;
    }

    const CCoinsViewCache& view = wallet.chain().getCoinsTip();
    const std::map<CScript, CScript> active_signals = GetActiveShadowSignalPayouts(view, tip);
    const std::map<CScript, ShadowSolverActivity> recent_solvers = GetRecentShadowSolverActivity(view, tip);
    if (recent_solvers.empty()) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: no recent solver markers\n");
        return false;
    }

    CCoinControl coin_control;
    coin_control.m_avoid_address_reuse = false;
    std::vector<COutput> outputs = AvailableCoins(wallet, &coin_control).All();
    std::sort(outputs.begin(), outputs.end(), [](const COutput& a, const COutput& b) {
        if (a.txout.nValue != b.txout.nValue) return a.txout.nValue < b.txout.nValue;
        return a.outpoint < b.outpoint;
    });

    const CChain& active_chain = wallet.chain().chainman().ActiveChain();
    unsigned int whitelisted_outputs{0};
    unsigned int recent_outputs{0};
    unsigned int already_active_outputs{0};
    for (const COutput& output : outputs) {
        if (output.txout.nValue <= 0) continue;
        const CScript target = CanonicalizeLegacyStakeScript(output.txout.scriptPubKey);
        if (target.empty() || target.IsUnspendable()) continue;
        if (!IsWhitelisted(view, target)) continue;
        ++whitelisted_outputs;
        const auto solver_it = recent_solvers.find(target);
        if (solver_it == recent_solvers.end()) continue;
        ++recent_outputs;
        if (active_signals.count(target)) {
            ++already_active_outputs;
            continue;
        }
        const CBlockIndex* solved = active_chain[solver_it->second.height];
        if (!solved) continue;

        candidate.target = target;
        candidate.solve_height = solver_it->second.height;
        candidate.solve_hash = solved->GetBlockHash();
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: candidate found solve_height=%u\n", candidate.solve_height);
        return true;
    }
    if (already_active_outputs > 0) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: wallet signal already active (wallet_active=%u recent_outputs=%u active_network=%u)\n",
                 already_active_outputs, recent_outputs, active_signals.size());
    } else {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: no eligible output needing a signal (wallet_whitelisted=%u wallet_recent=%u recent_network=%u active_network=%u)\n",
                 whitelisted_outputs, recent_outputs, recent_solvers.size(), active_signals.size());
    }
    return false;
}

bool BuildAutoShadowSignalTransaction(CWallet& wallet, const AutoShadowSignalCandidate& candidate, const CScript& payout_script, CMutableTransaction& signal_tx, std::map<COutPoint, Coin>& coins, CAmount& fee, bilingual_str& error)
{
    std::vector<unsigned char> signal;
    if (!BuildShadowSignalData(candidate.target, payout_script, candidate.solve_height, candidate.solve_hash, signal)) {
        error = _("Failed to build Gold Rush PoS signal payload.");
        return false;
    }

    CTxDestination target_dest;
    if (!ExtractDestination(candidate.target, target_dest) || !IsValidDestination(target_dest)) {
        error = _("Gold Rush PoS signal target does not resolve to a wallet address.");
        return false;
    }

    CCoinControl coin_control;
    coin_control.destChange = target_dest;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_address_reuse = false;
    signal_tx = CMutableTransaction();
    fee = 0;
    coins.clear();

    LOCK2(::cs_main, wallet.cs_wallet);
    const CBlockIndex* tip = wallet.chain().getTip();
    if (!tip) return false;
    const CCoinsViewCache& view = wallet.chain().getCoinsTip();
    if (GetActiveShadowSignalPayouts(view, tip).count(candidate.target)) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: candidate became active before build\n");
        return false;
    }
    bool has_solver_activity = HasRecentShadowSolverActivity(view, tip, candidate.target, candidate.solve_height, candidate.solve_hash);
    if (!has_solver_activity && candidate.solve_height == static_cast<uint32_t>(tip->nHeight)) {
        const auto recent_solvers = GetRecentShadowSolverActivity(view, tip);
        const auto it = recent_solvers.find(candidate.target);
        has_solver_activity = it != recent_solvers.end() && it->second.height == candidate.solve_height;
    }
    if (!has_solver_activity) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: candidate solve marker missing before build\n");
        return false;
    }
    if (HasPendingShadowSignal(wallet)) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: pending signal appeared before build\n");
        return false;
    }

    const int64_t current_time = GetAdjustedTimeSeconds();
    const CFeeRate fee_rate = GetMinimumFeeRate(wallet, coin_control, current_time);
    std::vector<COutput> outputs = AvailableCoins(wallet, &coin_control).All();
    std::sort(outputs.begin(), outputs.end(), [](const COutput& a, const COutput& b) {
        if (a.txout.nValue != b.txout.nValue) return a.txout.nValue < b.txout.nValue;
        return a.outpoint < b.outpoint;
    });

    for (const COutput& output : outputs) {
        if (CanonicalizeLegacyStakeScript(output.txout.scriptPubKey) != candidate.target) continue;

        CMutableTransaction tx;
        tx.nVersion = CTransaction::CURRENT_VERSION;
        tx.nTime = current_time;
        static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
        tx.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
        tx.vout.emplace_back(output.txout.nValue, candidate.target);
        tx.vout.emplace_back(0, CScript() << OP_RETURN << signal);

        const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(tx), &wallet, &coin_control);
        if (tx_size.vsize <= 0) continue;
        const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
        const CAmount candidate_change = output.txout.nValue - candidate_fee;
        CTxOut change_out(candidate_change, candidate.target);
        if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, wallet.chain().relayDustFee())) continue;
        if (candidate_fee > wallet.m_default_max_tx_fee) {
            error = strprintf(_("Gold Rush PoS signal fee exceeds wallet max transaction fee (%s)."), FormatMoney(wallet.m_default_max_tx_fee));
            return false;
        }

        const auto tx_it = wallet.mapWallet.find(output.outpoint.hash);
        if (tx_it == wallet.mapWallet.end() || output.outpoint.n >= tx_it->second.tx->vout.size()) continue;
        const CWalletTx& wtx = tx_it->second;
        const int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
        coins.emplace(output.outpoint, Coin(output.txout, prev_height, wtx.IsCoinBase(), wtx.IsCoinStake(), wtx.nTimeSmart));

        tx.vout[0].nValue = candidate_change;
        signal_tx = std::move(tx);
        fee = candidate_fee;
        return true;
    }

    error = _("No spendable non-dust UTXO found for the Gold Rush PoS signal address.");
    return false;
}

QuantumRedelegationPolicy AutoRedelegationPolicyFromArgs()
{
    QuantumRedelegationPolicy policy;
    policy.trigger_multiplier = gArgs.GetIntArg("-qqredelegationtriggermultiplier", policy.trigger_multiplier);
    policy.max_patience_blocks = gArgs.GetIntArg("-qqredelegationmaxpatienceblocks", policy.max_patience_blocks);
    policy.min_trigger_blocks = gArgs.GetIntArg("-qqredelegationmintriggerblocks", policy.min_trigger_blocks);
    policy.rate_limit_blocks = gArgs.GetIntArg("-qqredelegationratelimitblocks", policy.rate_limit_blocks);
    policy.probation_blocks = gArgs.GetIntArg("-qqredelegationprobationblocks", policy.probation_blocks);
    policy.stampede_jitter_blocks = gArgs.GetIntArg("-qqredelegationjitterblocks", policy.stampede_jitter_blocks);
    policy.liveness_improvement_blocks = gArgs.GetIntArg("-qqredelegationlivenessimprovementblocks", policy.liveness_improvement_blocks);
    policy.top_liveness_candidates = gArgs.GetIntArg("-qqredelegationtopcandidates", policy.top_liveness_candidates);
    if (policy.trigger_multiplier <= 0) policy.trigger_multiplier = 1;
    if (policy.max_patience_blocks <= 0) policy.max_patience_blocks = 1;
    if (policy.min_trigger_blocks <= 0) policy.min_trigger_blocks = 1;
    if (policy.rate_limit_blocks < 0) policy.rate_limit_blocks = 0;
    if (policy.probation_blocks < 0) policy.probation_blocks = 0;
    if (policy.stampede_jitter_blocks < 0) policy.stampede_jitter_blocks = 0;
    if (policy.liveness_improvement_blocks <= 0) policy.liveness_improvement_blocks = 1;
    if (policy.top_liveness_candidates <= 0) policy.top_liveness_candidates = 1;
    return policy;
}

int WalletTxHeight(const CWallet& wallet, const CWalletTx& wtx, int current_height) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const int depth = wallet.GetTxDepthInMainChain(wtx);
    if (depth <= 0 || current_height <= 0 || depth > current_height + 1) return 0;
    return current_height - depth + 1;
}

int64_t AutoRedelegationExpectedIntervalBlocks(CAmount delegation_amount, CAmount total_coldstake)
{
    if (delegation_amount <= 0 || total_coldstake <= 0) return 0;
    return std::max<int64_t>(1, (total_coldstake + delegation_amount - 1) / delegation_amount);
}

bool IsSafeDemurrageAttestationFeeOutput(const COutput& out, const Coin& coin, const Consensus::Params& consensus, int evaluation_height, int64_t evaluation_time, const CCoinsViewCache& view)
{
    if (!out.spendable || !out.safe || out.input_bytes < 0) return false;
    if (IsQuantumColdStakeScript(out.txout.scriptPubKey) || IsEUTXOScript(out.txout.scriptPubKey)) return false;
    if (!IsQuantumMigrationScript(out.txout.scriptPubKey)) {
        return !consensus.IsDemurrageActive(evaluation_height, evaluation_time);
    }

    const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, out.txout.scriptPubKey);
    const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin, consensus, evaluation_height, evaluation_time, latest_attestation);
    return !eval.locked && eval.burned_value == 0;
}

bool GetCoinStakeInputPrincipal(const CCoinsViewCache& view, const COutPoint& outpoint, const Consensus::Params& consensus, int spend_height, int64_t spend_time, CAmount& principal)
{
    Coin coin;
    if (!view.GetCoin(outpoint, coin) || coin.IsSpent()) return false;
    if (!consensus.IsDemurrageActive(spend_height, spend_time)) {
        principal = coin.out.nValue;
        return principal > 0 && MoneyRange(principal);
    }

    const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, coin.out.scriptPubKey);
    const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin, consensus, spend_height, spend_time, latest_attestation);
    if (eval.locked) return false;
    principal = eval.effective_value;
    return principal > 0 && MoneyRange(principal);
}

std::vector<COutPoint> SafeDemurrageAttestationFeeOutpoints(CWallet& wallet, const Consensus::Params& consensus, int evaluation_height, int64_t evaluation_time)
{
    std::vector<COutPoint> fee_outpoints;
    LOCK2(cs_main, wallet.cs_wallet);
    CoinFilterParams fee_filter;
    fee_filter.only_spendable = true;
    fee_filter.skip_locked = true;
    fee_filter.include_immature_coinbase = false;
    CCoinControl fee_scan_control;
    CoinsResult fee_outputs = AvailableCoins(wallet, &fee_scan_control, std::nullopt, fee_filter);
    std::vector<COutput> sorted_fee_outputs = fee_outputs.All();
    std::sort(sorted_fee_outputs.begin(), sorted_fee_outputs.end(), [](const COutput& a, const COutput& b) {
        if (a.txout.nValue != b.txout.nValue) return a.txout.nValue < b.txout.nValue;
        return a.outpoint < b.outpoint;
    });

    std::map<COutPoint, Coin> chain_coins;
    for (const COutput& out : sorted_fee_outputs) {
        chain_coins.emplace(out.outpoint, Coin{});
    }
    wallet.chain().findCoins(chain_coins);

    const CCoinsViewCache& view = wallet.chain().getCoinsTip();
    for (const COutput& out : sorted_fee_outputs) {
        const auto coin_it = chain_coins.find(out.outpoint);
        if (coin_it == chain_coins.end() || coin_it->second.IsSpent()) continue;
        if (!IsSafeDemurrageAttestationFeeOutput(out, coin_it->second, consensus, evaluation_height, evaluation_time, view)) continue;
        fee_outpoints.push_back(out.outpoint);
    }
    return fee_outpoints;
}

bool ValidateSelectedDemurrageAttestationFeeOutpoints(CWallet& wallet,
                                                      const CCoinControl& coin_control,
                                                      const Consensus::Params& consensus,
                                                      int evaluation_height,
                                                      int64_t evaluation_time,
                                                      bilingual_str& error)
{
    const std::vector<COutPoint> selected = coin_control.ListSelected();
    if (selected.empty()) {
        error = _("Unable to select a fee input for demurrage attestation");
        return false;
    }

    LOCK2(cs_main, wallet.cs_wallet);
    CoinFilterParams fee_filter;
    fee_filter.only_spendable = true;
    fee_filter.skip_locked = true;
    fee_filter.include_immature_coinbase = false;
    CCoinControl fee_scan_control;
    CoinsResult fee_outputs = AvailableCoins(wallet, &fee_scan_control, std::nullopt, fee_filter);

    std::set<COutPoint> selected_set(selected.begin(), selected.end());
    std::map<COutPoint, COutput> available_by_outpoint;
    for (const COutput& out : fee_outputs.All()) {
        if (selected_set.count(out.outpoint)) {
            available_by_outpoint.emplace(out.outpoint, out);
        }
    }

    std::map<COutPoint, Coin> chain_coins;
    for (const COutPoint& outpoint : selected) {
        chain_coins.emplace(outpoint, Coin{});
    }
    wallet.chain().findCoins(chain_coins);

    const CCoinsViewCache& view = wallet.chain().getCoinsTip();
    for (const COutPoint& outpoint : selected) {
        if (coin_control.IsExternalSelected(outpoint)) {
            error = _("External inputs cannot be used to fund a demurrage attestation");
            return false;
        }
        const auto output_it = available_by_outpoint.find(outpoint);
        const auto coin_it = chain_coins.find(outpoint);
        if (output_it == available_by_outpoint.end() || coin_it == chain_coins.end() || coin_it->second.IsSpent()) {
            error = _("Selected demurrage attestation fee input is unavailable, locked, or unsafe");
            return false;
        }
        if (!IsSafeDemurrageAttestationFeeOutput(output_it->second, coin_it->second, consensus, evaluation_height, evaluation_time, view)) {
            error = _("Selected demurrage attestation fee input would decay or is not safe");
            return false;
        }
    }
    return true;
}

} // namespace

bool CreateDemurrageAttestationTransaction(
    CWallet& wallet,
    const std::vector<unsigned char>& witness_program,
    const CCoinControl& coin_control,
    bool sign,
    DemurrageAttestationTxResult& result,
    bilingual_str& error)
{
    result = {};
    result.witness_program = witness_program;

    std::vector<unsigned char> public_key;
    CKeyingMaterial private_key;
    {
        LOCK(wallet.cs_wallet);
        if (wallet.IsLocked()) {
            error = _("Wallet is locked");
            return false;
        }
        if (sign && wallet.m_wallet_unlock_staking_only) {
            error = _("Wallet is unlocked for staking only");
            return false;
        }
        bilingual_str key_error;
        if (!wallet.GetQuantumKey(witness_program, public_key, private_key, key_error)) {
            error = key_error;
            return false;
        }
    }

    std::vector<unsigned char> private_key_bytes(private_key.begin(), private_key.end());
    if (!private_key.empty()) memory_cleanse(private_key.data(), private_key.size());
    auto cleanse_private_key_bytes = [&]() {
        if (!private_key_bytes.empty()) memory_cleanse(private_key_bytes.data(), private_key_bytes.size());
    };

    const std::vector<unsigned char> dummy_signature(ML_DSA::SIGNATURE_BYTES, 0);
    const COutPoint placeholder_anchor{};
    const CScript placeholder_script = Consensus::BuildDemurrageAttestationScript(placeholder_anchor, public_key, dummy_signature);

    constexpr int RANDOM_CHANGE_POSITION = -1;
    std::vector<CRecipient> placeholder_recipients;
    placeholder_recipients.push_back({placeholder_script, 0, /*subtract_fee=*/false});

    const Consensus::Params& consensus = Params().GetConsensus();
    int evaluation_height{-1};
    int64_t evaluation_time{0};
    {
        LOCK(cs_main);
        const CBlockIndex* tip = wallet.chain().getTip();
        if (tip) {
            evaluation_height = tip->nHeight + 1;
            evaluation_time = tip->GetMedianTimePast();
        }
    }

    std::vector<CCoinControl> attempts;
    const bool demurrage_active = consensus.IsDemurrageActive(evaluation_height, evaluation_time);
    if (demurrage_active) {
        if (coin_control.HasSelected()) {
            bilingual_str selected_error;
            if (!ValidateSelectedDemurrageAttestationFeeOutpoints(wallet, coin_control, consensus, evaluation_height, evaluation_time, selected_error)) {
                cleanse_private_key_bytes();
                error = selected_error;
                return false;
            }
            CCoinControl selected_attempt = coin_control;
            selected_attempt.m_allow_other_inputs = false;
            attempts.push_back(std::move(selected_attempt));
        } else {
            const std::vector<COutPoint> safe_outpoints = SafeDemurrageAttestationFeeOutpoints(wallet, consensus, evaluation_height, evaluation_time);
            if (safe_outpoints.empty()) {
                cleanse_private_key_bytes();
                error = _("Unable to select a safe non-decaying fee input for demurrage attestation");
                return false;
            }
            for (const COutPoint& outpoint : safe_outpoints) {
                CCoinControl attempt = coin_control;
                attempt.m_allow_other_inputs = false;
                attempt.Select(outpoint);
                attempts.push_back(std::move(attempt));
            }
        }
    } else {
        attempts.push_back(coin_control);
    }

    bilingual_str last_error;
    for (const CCoinControl& attempt_control : attempts) {
        auto planned = CreateTransaction(wallet, placeholder_recipients, RANDOM_CHANGE_POSITION, attempt_control, /*sign=*/false);
        if (!planned) {
            last_error = util::ErrorString(planned);
            continue;
        }
        if (planned->tx->vin.empty()) {
            last_error = _("Unable to select a fee input for demurrage attestation");
            continue;
        }

        const COutPoint replay_anchor = planned->tx->vin.front().prevout;
        const uint256 msg_hash = Consensus::DemurrageAttestationMessageHash(replay_anchor, public_key);
        std::vector<unsigned char> signature;
        if (!ML_DSA::Sign(private_key_bytes, msg_hash.begin(), uint256::size(), signature)) {
            cleanse_private_key_bytes();
            error = _("Failed to sign demurrage attestation");
            return false;
        }

        const CScript attestation_script = Consensus::BuildDemurrageAttestationScript(replay_anchor, public_key, signature);
        CCoinControl anchored_control = attempt_control;
        anchored_control.m_allow_other_inputs = false;
        for (const CTxIn& txin : planned->tx->vin) {
            anchored_control.Select(txin.prevout);
        }
        std::vector<CRecipient> recipients;
        recipients.push_back({attestation_script, 0, /*subtract_fee=*/false});
        auto res = CreateTransaction(wallet, recipients, RANDOM_CHANGE_POSITION, anchored_control, /*sign=*/sign);
        if (!res) {
            last_error = util::ErrorString(res);
            continue;
        }
        const CTransactionRef& tx = res->tx;
        if (tx->vin.empty() || tx->vin.front().prevout != replay_anchor) {
            last_error = _("Unable to preserve demurrage attestation replay anchor");
            continue;
        }
        const auto attestation_out = std::find_if(tx->vout.begin(), tx->vout.end(), [&](const CTxOut& txout) {
            return txout.nValue == 0 && txout.scriptPubKey == attestation_script;
        });
        if (attestation_out == tx->vout.end()) {
            last_error = _("Demurrage attestation transaction did not preserve attestation output");
            continue;
        }

        cleanse_private_key_bytes();
        result.tx = tx;
        result.public_key = std::move(public_key);
        result.replay_anchor = replay_anchor;
        result.attestation_vout = static_cast<int>(std::distance(tx->vout.begin(), attestation_out));
        result.fee = res->fee;
        return true;
    }

    cleanse_private_key_bytes();
    error = last_error.empty() ? _("Unable to select a fee input for demurrage attestation") : last_error;
    return false;
}

bool CreateQuantumColdStakeRedelegationTransaction(
    CWallet& wallet,
    const CTxDestination& source_dest,
    const std::vector<unsigned char>& target_staking_pubkey,
    const QuantumColdStakeRedelegationOptions& options,
    QuantumColdStakeRedelegationResult& result,
    bilingual_str& error)
{
    result = {};
    result.dry_run = options.dry_run;
    result.source_dest = source_dest;
    result.cap_enforced = options.enforce_pool_cap;

    if (!IsValidDestination(source_dest) || !IsQuantumColdStakeDestination(source_dest)) {
        error = _("source_coldstake_address is not a Quantum Cold-Stake address");
        return false;
    }
    if (target_staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        error = strprintf(_("target_staking_pubkey must be exactly %u bytes"), ML_DSA::PUBLICKEY_BYTES);
        return false;
    }

    wallet.BlockUntilSyncedToCurrentChain();

    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = false;
    coin_control.destChange = source_dest;
    if (options.fee_rate) {
        coin_control.m_feerate = options.fee_rate;
        coin_control.fOverrideFeeRate = true;
    }

    CAmount input_amount{0};
    unsigned int selected_inputs{0};
    uint256 source_staker_hash;
    uint256 source_owner_hash;
    {
        LOCK(wallet.cs_wallet);
        if (wallet.IsLocked()) {
            error = _("Wallet is locked");
            return false;
        }
        if (wallet.m_wallet_unlock_staking_only) {
            error = _("Wallet unlocked for staking only, unable to redelegate");
            return false;
        }

        const auto source_info = wallet.GetQuantumColdStakeDelegationInfo(source_dest);
        if (!source_info || !source_info->has_owner_key) {
            error = _("Wallet does not have the owner key for source_coldstake_address");
            return false;
        }
        const int spend_height = wallet.GetLastBlockHeight() + 1;
        if (source_info->tiered && source_info->unlock_height == 0) {
            error = _("Bonded cold-stake funds must be unbonded before redelegating");
            return false;
        }
        if (source_info->tiered && source_info->unlock_height > static_cast<uint32_t>(std::max(0, spend_height))) {
            error = strprintf(_("Cold-stake funds are unbonding and cannot be redelegated until block %u"), source_info->unlock_height);
            return false;
        }
        source_staker_hash = source_info->staker_pubkey_hash;
        source_owner_hash = source_info->owner_pubkey_hash;

        CoinFilterParams filter;
        filter.only_spendable = true;
        filter.skip_locked = true;
        for (const COutput& out : AvailableCoins(wallet, &coin_control, std::nullopt, filter).All()) {
            CTxDestination dest;
            if (!ExtractDestination(out.txout.scriptPubKey, dest) || !(dest == source_dest) || !out.spendable) continue;
            coin_control.Select(out.outpoint);
            if (!MoneyRange(input_amount + out.txout.nValue)) {
                error = _("Unable to select source_coldstake_address amount");
                return false;
            }
            input_amount += out.txout.nValue;
            ++selected_inputs;
        }
    }
    if (selected_inputs == 0 || input_amount <= 0) {
        error = _("No spendable owner-controlled UTXOs found for source_coldstake_address");
        return false;
    }

    const uint256 target_staker_hash = node::QuantumPoolHashPubKey(target_staking_pubkey);
    {
        LOCK(cs_main);
        const CCoinsViewCache& view = wallet.chain().getCoinsTip();
        const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, target_staker_hash, node::GetQuantumPoolClaims(target_staker_hash));
        if (options.require_verified_operator && !share.operator_share.operator_commitment_verified) {
            error = _("Target Quantum cold-stake operator commitment is not verified in the local registry");
            return false;
        }

        CAmount projected_operator_value = share.operator_share.verified_value;
        if (source_staker_hash == target_staker_hash && projected_operator_value >= input_amount) {
            projected_operator_value -= input_amount;
        }
        if (!MoneyRange(projected_operator_value + input_amount)) {
            error = _("Unable to project redelegation pool totals");
            return false;
        }
        projected_operator_value += input_amount;
        const bool would_exceed_cap = node::WouldQuantumPoolExceedCap(share.total_coldstake, projected_operator_value, 0);
        const bool has_under_cap_alternative = would_exceed_cap && HasUnderCapRedelegationAlternative(view, source_staker_hash, target_staker_hash, input_amount);
        if (options.enforce_pool_cap && would_exceed_cap && has_under_cap_alternative) {
            error = _("Target Quantum cold-stake pool cap would be exceeded by this redelegation");
            return false;
        }
    }

    const std::string label = options.label.empty() ? "redelegated-coldstake" : options.label;
    CTxDestination target_dest;
    bool target_wallet_backed{false};
    if (options.dry_run) {
        target_dest = WitnessUnknown{
            QUANTUM_COLDSTAKE_WITNESS_VERSION,
            QuantumColdStakeProgramForKeyHashes(target_staker_hash, source_owner_hash)};
    } else {
        const std::string owner_label = label + " owner";
        auto owner_dest = wallet.GetNewQuantumDestination(owner_label);
        if (!owner_dest) {
            error = util::ErrorString(owner_dest);
            return false;
        }
        std::vector<unsigned char> owner_pubkey;
        {
            LOCK(wallet.cs_wallet);
            const auto owner_info = wallet.GetQuantumKeyInfo(*owner_dest);
            CHECK_NONFATAL(owner_info.has_value());
            owner_pubkey = owner_info->public_key;
        }
        auto target_dest_result = wallet.AddQuantumColdStakeDelegation(target_staking_pubkey, owner_pubkey, label, GetTime());
        if (!target_dest_result) {
            error = util::ErrorString(target_dest_result);
            return false;
        }
        target_dest = *target_dest_result;
        target_wallet_backed = true;
    }

    std::vector<CRecipient> recipients;
    recipients.push_back({target_dest, input_amount, /*fSubtractFeeFromAmount=*/true});

    constexpr int RANDOM_CHANGE_POSITION = -1;
    auto res = CreateTransaction(wallet, recipients, RANDOM_CHANGE_POSITION, coin_control, /*sign=*/!options.dry_run);
    if (!res) {
        error = util::ErrorString(res);
        return false;
    }
    const CTransactionRef& tx = res->tx;
    if (tx->vout.empty() || IsDust(tx->vout[0], wallet.chain().relayDustFee())) {
        error = _("Redelegation output would be dust after fees");
        return false;
    }
    if (tx->vout.size() != 1 || tx->vout[0].scriptPubKey != GetScriptForDestination(target_dest)) {
        error = _("Redelegation transaction unexpectedly produced change or a non-target output");
        return false;
    }

    const CAmount output_amount = tx->vout[0].nValue;
    {
        LOCK(cs_main);
        const CCoinsViewCache& view = wallet.chain().getCoinsTip();
        const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, target_staker_hash, node::GetQuantumPoolClaims(target_staker_hash));
        if (options.require_verified_operator && !share.operator_share.operator_commitment_verified) {
            error = _("Target Quantum cold-stake operator commitment is not verified in the local registry");
            return false;
        }
        if (share.total_coldstake < input_amount || !MoneyRange(share.total_coldstake - input_amount + output_amount)) {
            error = _("Unable to project post-redelegation pool totals");
            return false;
        }
        CAmount post_operator_value = share.operator_share.verified_value;
        if (source_staker_hash == target_staker_hash && post_operator_value >= input_amount) {
            post_operator_value -= input_amount;
        }
        if (!MoneyRange(post_operator_value + output_amount)) {
            error = _("Unable to project post-redelegation operator total");
            return false;
        }
        post_operator_value += output_amount;
        const CAmount post_total_coldstake = share.total_coldstake - input_amount + output_amount;
        const bool would_exceed_cap = node::WouldQuantumPoolExceedCap(post_total_coldstake, post_operator_value, 0);
        const bool cap_filter_unlocked = would_exceed_cap && !HasUnderCapRedelegationAlternative(view, source_staker_hash, target_staker_hash, output_amount);
        if (would_exceed_cap && options.enforce_pool_cap && !cap_filter_unlocked) {
            error = _("Target Quantum cold-stake pool cap would be exceeded by this redelegation");
            return false;
        }

        result.operator_commitment_verified = share.operator_share.operator_commitment_verified;
        result.post_total_coldstake = post_total_coldstake;
        result.post_operator_value = post_operator_value;
        result.post_share_bps = node::QuantumPoolShareBps(post_operator_value, post_total_coldstake);
        result.would_exceed_cap = would_exceed_cap;
        result.cap_filter_unlocked = cap_filter_unlocked;
    }

    result.target_dest = target_dest;
    result.target_wallet_backed = target_wallet_backed;
    result.input_amount = input_amount;
    result.output_amount = output_amount;
    result.fee = res->fee;
    result.vsize = static_cast<int>(GetVirtualTransactionSize(*tx, 0, 0));
    result.tx = tx;

    if (!options.dry_run) {
        mapValue_t map_value;
        map_value["comment"] = "Quantum Quasar cold-stake redelegation";
        std::string broadcast_error;
        if (!wallet.CommitTransaction(tx, std::move(map_value), {}, &broadcast_error)) {
            if (!wallet.AbandonTransaction(tx->GetHash())) {
                wallet.WalletLogPrintf("Cold-stake redelegation could not be abandoned after broadcast failure: txid=%s\n", tx->GetHash().ToString());
            }
            error = strprintf(_("Broadcasting cold-stake redelegation failed: %s"), broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error);
            return false;
        }
    }
    return true;
}

int MaybeAutoDemurrageAttest(CWallet& wallet)
{
    {
        LOCK(wallet.cs_wallet);
        if (!wallet.m_enabled_staking.load() ||
            wallet.IsLocked() ||
            wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) ||
            wallet.m_wallet_unlock_staking_only) {
            return 0;
        }
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    int evaluation_height{-1};
    int64_t evaluation_time{0};
    {
        LOCK(cs_main);
        const CBlockIndex* tip = wallet.chain().getTip();
        if (!tip) return 0;
        evaluation_height = tip->nHeight + 1;
        evaluation_time = tip->GetMedianTimePast();
    }
    if (!consensus.IsDemurrageActive(evaluation_height, evaluation_time)) {
        return 0;
    }

    {
        LOCK(wallet.cs_wallet);
        if (wallet.m_demurrage_last_auto_attest_scan_height >= evaluation_height) {
            return 0;
        }
        wallet.m_demurrage_last_auto_attest_scan_height = evaluation_height;
    }

    std::vector<AutoDemurrageAttestCandidate> candidates;
    std::vector<COutPoint> fee_outpoints;
    {
        LOCK2(cs_main, wallet.cs_wallet);
        CoinsResult available_list = AvailableCoinsListUnspent(wallet);
        std::map<COutPoint, Coin> chain_coins;
        for (const COutput& out : available_list.All()) {
            chain_coins.emplace(out.outpoint, Coin{});
        }
        wallet.chain().findCoins(chain_coins);

        const CCoinsViewCache& view = wallet.chain().getCoinsTip();
        std::map<uint256, AutoDemurrageAttestCandidate> by_key;
        for (const COutput& out : available_list.All()) {
            if (!IsQuantumMigrationScript(out.txout.scriptPubKey)) continue;
            CTxDestination dest;
            if (!ExtractDestination(out.txout.scriptPubKey, dest)) continue;
            const auto key_info = wallet.GetQuantumKeyInfo(dest);
            if (!key_info) continue;

            const auto key_hash = Consensus::DemurrageControllingKeyHashForScript(out.txout.scriptPubKey);
            if (!key_hash) continue;

            const auto coin_it = chain_coins.find(out.outpoint);
            if (coin_it == chain_coins.end() || coin_it->second.IsSpent()) continue;

            const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, out.txout.scriptPubKey);
            const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin_it->second, consensus, evaluation_height, evaluation_time, latest_attestation);
            if (eval.locked || eval.inactive_blocks < consensus.DemurrageAutoAttestBlocks()) continue;

            const int retry_blocks = std::max(1, consensus.DemurrageBlocksPerMonth() / 30);
            const auto last_attempt = wallet.m_demurrage_last_auto_attest_attempt_height.find(*key_hash);
            if (last_attempt != wallet.m_demurrage_last_auto_attest_attempt_height.end() &&
                evaluation_height - last_attempt->second < retry_blocks) {
                continue;
            }

            AutoDemurrageAttestCandidate candidate;
            candidate.witness_program = key_info->witness_program;
            candidate.key_hash = *key_hash;
            candidate.inactive_blocks = eval.inactive_blocks;
            candidate.outpoint = out.outpoint;

            auto [it, inserted] = by_key.emplace(*key_hash, candidate);
            if (!inserted && candidate.inactive_blocks > it->second.inactive_blocks) {
                it->second = std::move(candidate);
            }
        }

        CoinFilterParams fee_filter;
        fee_filter.only_spendable = true;
        fee_filter.skip_locked = true;
        fee_filter.include_immature_coinbase = false;
        CCoinControl fee_scan_control;
        CoinsResult fee_outputs = AvailableCoins(wallet, &fee_scan_control, std::nullopt, fee_filter);
        std::vector<COutput> sorted_fee_outputs = fee_outputs.All();
        std::sort(sorted_fee_outputs.begin(), sorted_fee_outputs.end(), [](const COutput& a, const COutput& b) {
            if (a.txout.nValue != b.txout.nValue) return a.txout.nValue < b.txout.nValue;
            return a.outpoint < b.outpoint;
        });
        for (const COutput& out : sorted_fee_outputs) {
            const auto coin_it = chain_coins.find(out.outpoint);
            if (coin_it == chain_coins.end() || coin_it->second.IsSpent()) continue;
            if (!IsSafeDemurrageAttestationFeeOutput(out, coin_it->second, consensus, evaluation_height, evaluation_time, view)) continue;
            fee_outpoints.push_back(out.outpoint);
        }

        for (auto& [key_hash, candidate] : by_key) {
            candidates.push_back(std::move(candidate));
        }
    }

    int submitted{0};
    bool logged_no_fee{false};
    std::set<COutPoint> used_fee_outpoints;
    for (const AutoDemurrageAttestCandidate& candidate : candidates) {
        {
            LOCK(wallet.cs_wallet);
            wallet.m_demurrage_last_auto_attest_attempt_height[candidate.key_hash] = evaluation_height;
        }

        bool committed{false};
        bilingual_str last_error;
        for (const COutPoint& fee_outpoint : fee_outpoints) {
            if (used_fee_outpoints.count(fee_outpoint)) continue;

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = false;
            coin_control.m_avoid_address_reuse = false;
            coin_control.Select(fee_outpoint);

            DemurrageAttestationTxResult tx_result;
            bilingual_str error;
            if (!CreateDemurrageAttestationTransaction(wallet, candidate.witness_program, coin_control, /*sign=*/true, tx_result, error)) {
                last_error = error;
                continue;
            }

            mapValue_t map_value;
            map_value["comment"] = "Quantum Quasar demurrage auto-attestation";
            std::string broadcast_error;
            if (!wallet.CommitTransaction(tx_result.tx, std::move(map_value), {}, &broadcast_error)) {
                if (!wallet.AbandonTransaction(tx_result.tx->GetHash())) {
                    wallet.WalletLogPrintf("Demurrage auto-attestation could not be abandoned after broadcast failure: txid=%s\n", tx_result.tx->GetHash().ToString());
                }
                last_error = Untranslated(strprintf("broadcast failed: %s", broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error));
                continue;
            }
            used_fee_outpoints.insert(fee_outpoint);
            wallet.WalletLogPrintf("Demurrage auto-attested demurrage key %s at height %d with tx %s (inactive %d blocks, fee %d)\n",
                                   candidate.key_hash.ToString(), evaluation_height, tx_result.tx->GetHash().ToString(), candidate.inactive_blocks, tx_result.fee);
            ++submitted;
            committed = true;
            break;
        }

        if (!committed) {
            if (fee_outpoints.empty() && !logged_no_fee) {
                wallet.WalletLogPrintf("Demurrage auto-attest skipped: no safe spendable fee input is available\n");
                logged_no_fee = true;
            } else if (!last_error.empty()) {
                wallet.WalletLogPrintf("Demurrage auto-attest skipped for key %s: %s\n", candidate.key_hash.ToString(), last_error.original);
            }
        }
    }
    return submitted;
}

int MaybeAutoShadowSignal(CWallet& wallet)
{
    if (!gArgs.GetBoolArg("-qqautoshadowsignal", true)) return 0;
    if (!wallet.m_enabled_staking.load() || wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return 0;
    }
    if (wallet.IsLocked() || wallet.m_wallet_unlock_staking_only) {
        LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: normal wallet unlock required (locked=%d staking_only=%d)\n",
                 wallet.IsLocked(), wallet.m_wallet_unlock_staking_only);
        return 0;
    }

    AutoShadowSignalCandidate candidate;
    {
        TRY_LOCK(::cs_main, main_lock);
        if (!main_lock) {
            LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: skipped because chain lock is busy\n");
            return 0;
        }
        TRY_LOCK(wallet.cs_wallet, wallet_lock);
        if (!wallet_lock) {
            LogPrint(BCLog::COINSTAKE, "Gold Rush PoS auto-signal: skipped because wallet lock is busy\n");
            return 0;
        }
        if (!FindAutoShadowSignalCandidate(wallet, candidate)) return 0;
    }

    CScript payout_script;
    std::string payout_address;
    bilingual_str error;
    if (!EnsureShadowSignalPayout(wallet, payout_script, payout_address, error)) {
        wallet.WalletLogPrintf("Gold Rush PoS signal skipped: %s\n", error.original);
        return 0;
    }

    CMutableTransaction signal_tx;
    std::map<COutPoint, Coin> coins;
    CAmount fee{0};
    if (!BuildAutoShadowSignalTransaction(wallet, candidate, payout_script, signal_tx, coins, fee, error)) {
        if (!error.empty()) {
            wallet.WalletLogPrintf("Gold Rush PoS signal skipped: %s\n", error.original);
        }
        return 0;
    }

    std::map<int, bilingual_str> input_errors;
    if (!wallet.SignTransaction(signal_tx, coins, SIGHASH_DEFAULT, input_errors)) {
        if (!input_errors.empty()) {
            error = strprintf(_("Signing Gold Rush PoS signal failed: %s"), input_errors.begin()->second.original);
        } else {
            error = _("Signing Gold Rush PoS signal failed.");
        }
        wallet.WalletLogPrintf("%s\n", error.original);
        return 0;
    }

    CTransactionRef tx = MakeTransactionRef(std::move(signal_tx));
    {
        ChainstateManager& chainman = wallet.chain().chainman();
        LOCK(::cs_main);
        const MempoolAcceptResult accept = chainman.ProcessTransaction(tx, /*test_accept=*/true);
        if (accept.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            wallet.WalletLogPrintf("Gold Rush PoS signal rejected: %s\n", accept.m_state.ToString());
            return 0;
        }
    }

    mapValue_t map_value;
    map_value["comment"] = SHADOW_SIGNAL_COMMENT;
    try {
        std::string broadcast_error;
        if (!wallet.CommitTransaction(tx, std::move(map_value), {}, &broadcast_error)) {
            wallet.WalletLogPrintf("Broadcasting Gold Rush PoS signal failed: %s\n", broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error);
            if (!wallet.AbandonTransaction(tx->GetHash())) {
                wallet.WalletLogPrintf("Gold Rush PoS signal could not be abandoned after broadcast failure: txid=%s\n", tx->GetHash().ToString());
            }
            return 0;
        }
    } catch (const std::exception& e) {
        wallet.WalletLogPrintf("Broadcasting Gold Rush PoS signal failed: %s\n", e.what());
        return 0;
    }

    CTxDestination signal_dest;
    std::string signal_address;
    if (ExtractDestination(candidate.target, signal_dest) && IsValidDestination(signal_dest)) {
        signal_address = EncodeDestination(signal_dest);
    } else {
        signal_address = HexStr(candidate.target);
    }
    wallet.WalletLogPrintf("Gold Rush PoS signal submitted: txid=%s address=%s solve_height=%u payout=%s fee=%s\n",
                           tx->GetHash().ToString(), signal_address, candidate.solve_height, payout_address, FormatMoney(fee));
    return 1;
}

int MaybeAutoRedelegateQuantumColdStake(CWallet& wallet)
{
    if (!gArgs.GetBoolArg("-qqautoredelegate", true)) return 0;
    if (wallet.IsLocked() || wallet.m_wallet_unlock_staking_only || wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return 0;
    }

    int current_height{0};
    {
        LOCK(cs_main);
        const CBlockIndex* tip = wallet.chain().getTip();
        if (!tip) return 0;
        current_height = tip->nHeight;
    }

    {
        LOCK(wallet.cs_wallet);
        if (wallet.m_redelegation_last_auto_scan_height >= current_height) {
            return 0;
        }
        wallet.m_redelegation_last_auto_scan_height = current_height;
        WalletBatch batch(wallet.GetDatabase());
        batch.WriteQuantumRedelegationAutoScanHeight(current_height);
    }

    std::vector<AutoRedelegationSource> sources;
    {
        LOCK2(cs_main, wallet.cs_wallet);
        CoinFilterParams filter;
        filter.only_spendable = true;
        filter.skip_locked = true;
        filter.include_immature_coinbase = false;
        CCoinControl coin_control;
        const CoinsResult available = AvailableCoins(wallet, &coin_control, std::nullopt, filter);
        std::map<std::vector<unsigned char>, AutoRedelegationSource> grouped;
        for (const COutput& out : available.All()) {
            if (!IsQuantumColdStakeScript(out.txout.scriptPubKey) || !out.spendable || !out.safe || out.input_bytes < 0) continue;
            CTxDestination dest;
            if (!ExtractDestination(out.txout.scriptPubKey, dest)) continue;
            const auto info = wallet.GetQuantumColdStakeDelegationInfo(dest);
            if (!info || !info->has_owner_key) continue;
            const CWalletTx* wtx = wallet.GetWalletTx(out.outpoint.hash);
            if (!wtx) continue;
            const int height = WalletTxHeight(wallet, *wtx, current_height);
            if (height <= 0) continue;

            AutoRedelegationSource& source = grouped[info->witness_program];
            if (source.witness_program.empty()) {
                source.source_dest = dest;
                source.witness_program = info->witness_program;
                source.staker_pubkey_hash = info->staker_pubkey_hash;
                source.activation_height = height;
            } else {
                source.activation_height = std::max(source.activation_height, height);
            }
            if (!MoneyRange(source.amount + out.txout.nValue)) continue;
            source.amount += out.txout.nValue;
        }
        for (auto& [_, source] : grouped) {
            if (source.amount > 0 && source.activation_height > 0) {
                const auto win = wallet.m_redelegation_last_win_height.find(source.witness_program);
                if (win != wallet.m_redelegation_last_win_height.end()) {
                    source.last_win_height = win->second;
                }
                sources.push_back(std::move(source));
            }
        }
    }

    const QuantumRedelegationPolicy policy = AutoRedelegationPolicyFromArgs();
    std::map<uint256, int> operator_last_win_height;
    {
        LOCK(wallet.cs_wallet);
        for (const QuantumColdStakeDelegationInfo& info : wallet.ListQuantumColdStakeDelegationInfos()) {
            const auto win = wallet.m_redelegation_last_win_height.find(info.witness_program);
            if (win == wallet.m_redelegation_last_win_height.end()) continue;
            auto& height = operator_last_win_height[info.staker_pubkey_hash];
            height = std::max(height, win->second);
        }
    }

    for (const AutoRedelegationSource& source : sources) {
        int last_attempt_height{0};
        int last_success_height{0};
        {
            LOCK(wallet.cs_wallet);
            const auto it = wallet.m_redelegation_last_auto_attempt_height.find(source.witness_program);
            if (it != wallet.m_redelegation_last_auto_attempt_height.end()) {
                last_attempt_height = it->second;
            }
            const auto success_it = wallet.m_redelegation_last_auto_success_height.find(source.witness_program);
            if (success_it != wallet.m_redelegation_last_auto_success_height.end()) {
                last_success_height = success_it->second;
            }
        }

        std::vector<QuantumRedelegationCandidate> candidates;
        CAmount total_coldstake{0};
        {
            LOCK(cs_main);
            const CCoinsViewCache& view = wallet.chain().getCoinsTip();
            const node::QuantumPoolShare current_share = node::ComputeQuantumPoolShare(view, source.staker_pubkey_hash, node::GetQuantumPoolClaims(source.staker_pubkey_hash));
            total_coldstake = current_share.total_coldstake;
            for (const uint256& staker_hash : node::ListQuantumPoolOperators()) {
                const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));
                QuantumRedelegationCandidate candidate;
                candidate.staker_pubkey_hash = staker_hash;
                candidate.staker_pubkey = share.operator_share.staker_pubkey;
                candidate.operator_value = share.operator_share.verified_value;
                candidate.total_coldstake = share.total_coldstake;
                const auto win = operator_last_win_height.find(staker_hash);
                candidate.last_win_height = win == operator_last_win_height.end() ? 0 : win->second;
                candidate.operator_commitment_verified = share.operator_share.operator_commitment_verified;
                candidate.current_operator = staker_hash == source.staker_pubkey_hash;
                candidates.push_back(std::move(candidate));
            }
        }
        const int64_t expected_interval_blocks = AutoRedelegationExpectedIntervalBlocks(source.amount, total_coldstake);
        if (expected_interval_blocks <= 0) continue;

        HashWriter delegation_id_writer{};
        delegation_id_writer << std::string{"Blackcoin auto delegation id"};
        delegation_id_writer << source.witness_program;
        const uint256 delegation_id = delegation_id_writer.GetHash();

        const int last_win_height = source.last_win_height > 0 ? source.last_win_height : source.activation_height;
        const int64_t zero_win_blocks = std::max<int64_t>(0, current_height - last_win_height);
        const QuantumRedelegationStatus status = EvaluateQuantumRedelegation(
            zero_win_blocks,
            expected_interval_blocks,
            current_height,
            last_attempt_height,
            last_success_height,
            source.activation_height,
            delegation_id,
            source.staker_pubkey_hash,
            policy);
        if (!status.should_redelegate) continue;

        const auto ranked = RankQuantumRedelegationCandidates(candidates, source.amount, policy);
        const auto selected = SelectQuantumRedelegationTarget(ranked, source.last_win_height, delegation_id, policy);
        if (!selected) continue;

        {
            LOCK(wallet.cs_wallet);
            wallet.m_redelegation_last_auto_attempt_height[source.witness_program] = current_height;
            WalletBatch batch(wallet.GetDatabase());
            batch.WriteQuantumRedelegationLastAttemptHeight(source.witness_program, current_height);
        }

        QuantumColdStakeRedelegationOptions options;
        options.dry_run = false;
        options.enforce_pool_cap = true;
        options.require_verified_operator = true;
        options.label = "auto-redelegated-coldstake";

        QuantumColdStakeRedelegationResult redelegation;
        bilingual_str error;
        if (!CreateQuantumColdStakeRedelegationTransaction(wallet, source.source_dest, selected->candidate.staker_pubkey, options, redelegation, error)) {
            wallet.WalletLogPrintf("Auto-redelegation skipped for %s at height %d: %s\n",
                                   EncodeDestination(source.source_dest), current_height, error.original);
            continue;
        }
        {
            LOCK(wallet.cs_wallet);
            wallet.m_redelegation_last_auto_success_height[source.witness_program] = current_height;
            WalletBatch batch(wallet.GetDatabase());
            batch.WriteQuantumRedelegationLastSuccessHeight(source.witness_program, current_height);
        }

        wallet.WalletLogPrintf("Auto-redelegated %s to %s at height %d with tx %s after %d zero-win blocks\n",
                               EncodeDestination(source.source_dest),
                               EncodeDestination(redelegation.target_dest),
                               current_height,
                               redelegation.tx->GetHash().ToString(),
                               zero_win_blocks);
        return 1;
    }
    return 0;
}

void StakeCoins(CWallet& wallet, bool fStake) {
    node::StakeCoins(fStake, &wallet, wallet.threadStakeMinerGroup);
}

void StartStake(CWallet& wallet) {
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        wallet.WalletLogPrintf("Wallet can't contain any private keys - staking disabled\n");
        wallet.m_enabled_staking = false;
    }
    else if (wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
        wallet.WalletLogPrintf("Wallet is blank - staking disabled\n");
        wallet.m_enabled_staking = false;
    }
    else if (!WITH_LOCK(wallet.cs_wallet, return wallet.GetKeyPoolSize() || !wallet.ListQuantumKeyInfos().empty())) {
        wallet.WalletLogPrintf("Error: Keypool is empty and no quantum staking keys are available, please add keys or call keypoolrefill and restart the staking thread\n");
        wallet.m_enabled_staking = false;
    }
    else {
        wallet.m_enabled_staking = true;
    }
    StakeCoins(wallet, wallet.m_enabled_staking);
}

void StopStake(CWallet& wallet) {
    if (!wallet.threadStakeMinerGroup) {
        if (wallet.m_enabled_staking)
            wallet.m_enabled_staking = false;
    }
    else {
        wallet.m_stop_staking_thread = true;
        wallet.m_enabled_staking = false;
        StakeCoins(wallet, false);
        wallet.threadStakeMinerGroup = 0;
        wallet.m_stop_staking_thread = false;
    }
}

uint64_t GetStakeWeight(const CWallet& wallet)
{
    // Choose coins to use
    const auto bal = GetBalance(wallet);
    CAmount nBalance = bal.m_mine_trusted;
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS))
        nBalance += bal.m_watchonly_trusted;

    if (nBalance <= wallet.m_reserve_balance)
        return 0;

    std::set<std::pair<const CWalletTx*, unsigned int> > setCoins;
    CAmount nValueIn = 0;

    CAmount nTargetValue = nBalance - wallet.m_reserve_balance;
    if (!SelectCoinsForStaking(wallet, nTargetValue, setCoins, nValueIn))
        return 0;

    if (setCoins.empty())
        return 0;

    uint64_t nWeight = 0;

    for (std::pair<const CWalletTx*,unsigned int> pcoin : setCoins)
    {
        if (wallet.GetTxDepthInMainChain(*pcoin.first) >= Params().GetConsensus().nCoinbaseMaturity)
        {
            nWeight += pcoin.first->tx->vout[pcoin.second].nValue;
        }
    }

    return nWeight;
}

void AvailableCoinsForStaking(const CWallet& wallet,
                           std::vector<std::pair<const CWalletTx*, unsigned int> >& vCoins,
                           const CCoinControl* coinControl,
                           const CoinFilterParams& params)
{
    AssertLockHeld(wallet.cs_wallet);

    vCoins.clear();
    CAmount nTotal = 0;
    // Either the WALLET_FLAG_AVOID_REUSE flag is not set (in which case we always allow), or we default to avoiding, and only in the case where
    // a coin control object is provided, and has the avoid address reuse flag set to false, do we allow already used addresses
    bool allow_used_addresses = !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    const int min_depth = std::max(DEFAULT_MIN_DEPTH, Params().GetConsensus().nCoinbaseMaturity);
    const int max_depth = DEFAULT_MAX_DEPTH;
    const bool only_safe = true;

    // Never stake UTXOs carrying live RGB single-use-seal or EUTXO state.
    const std::set<COutPoint> protected_rgb_seals = wallet.GetProtectedRGBSeals();

    std::set<uint256> trusted_parents;
    for (const auto& entry : wallet.mapWallet)
    {
        const uint256& wtxid = entry.first;
        const CWalletTx& wtx = entry.second;

        if (wallet.IsTxImmature(wtx))
            continue;

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < 0)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !wtx.InMempool())
            continue;

        bool safeTx = CachedTxIsTrusted(wallet, wtx, trusted_parents);

        if (only_safe && !safeTx) {
            continue;
        }

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            const CTxOut& output = wtx.tx->vout[i];
            const COutPoint outpoint(wtxid, i);

            if (output.nValue < wallet.m_min_staking_amount)
                continue;

            if (output.nValue < params.min_amount || output.nValue > params.max_amount)
                continue;

            if (wallet.IsLockedCoin(outpoint) && params.skip_locked)
                continue;

            if (wallet.IsSpent(outpoint))
                continue;

            // Never stake an RGB seal / EUTXO-state UTXO; spending it would burn the asset.
            if (protected_rgb_seals.count(outpoint))
                continue;

            isminetype mine = wallet.IsMine(output);

            if (mine == ISMINE_NO) {
                continue;
            }

            if (!allow_used_addresses && wallet.IsSpentKey(output.scriptPubKey)) {
                continue;
            }

            std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(output.scriptPubKey);

            bool solvable = IsQuantumMigrationScript(output.scriptPubKey) || IsQuantumColdStakeScript(output.scriptPubKey);
            if (!solvable && provider) {
                if (auto desc = InferDescriptor(output.scriptPubKey, *provider)) {
                    solvable = desc->IsSolvable();
                }
            }
            bool spendable = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (((mine & ISMINE_WATCH_ONLY) != ISMINE_NO) && (coinControl && coinControl->fAllowWatchOnly && solvable));

            // Filter by spendable outputs only
            if (!spendable && params.only_spendable) continue;

            // If the Output is P2SH and spendable, we want to know if it is
            // a P2SH (legacy) or one of P2SH-P2WPKH, P2SH-P2WSH (P2SH-Segwit). We can determine
            // this from the redeemScript. If the Output is not spendable, it will be classified
            // as a P2SH (legacy), since we have no way of knowing otherwise without the redeemScript
            CScript script;
            if (output.scriptPubKey.IsPayToScriptHash() && solvable) {
                CTxDestination destination;
                if (!ExtractDestination(output.scriptPubKey, destination))
                    continue;
                const CScriptID& hash = ToScriptID(std::get<ScriptHash>(destination));
                if (!provider->GetCScript(hash, script))
                    continue;
            } else {
                script = output.scriptPubKey;
            }

            if (spendable)
                vCoins.push_back(std::make_pair(&wtx, i));

            // Cache total amount as we go
            nTotal += output.nValue;
            // Checks the sum amount of all UTXO's.
            if (params.min_sum_amount != MAX_MONEY) {
                if (nTotal >= params.min_sum_amount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (params.max_count > 0 && vCoins.size() >= params.max_count) {
                return;
            }
        }
    }
}

// Select some coins without random shuffle or best subset approximation
bool SelectCoinsForStaking(const CWallet& wallet, CAmount& nTargetValue, std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet, CAmount& nValueRet)
{
    std::vector<std::pair<const CWalletTx*, unsigned int> > vCoins;
    CCoinControl coincontrol;
    AvailableCoinsForStaking(wallet, vCoins, &coincontrol);

    setCoinsRet.clear();
    nValueRet = 0;

    for (const std::pair<const CWalletTx*, unsigned int> &output : vCoins)
    {

        const CWalletTx *pcoin = output.first;
        int i = output.second;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        int64_t n = pcoin->tx->vout[i].nValue;

        std::pair<int64_t,std::pair<const CWalletTx*,unsigned int> > coin = std::make_pair(n,std::make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            // it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        }
        else if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
}

// peercoin: create coin stake transaction
typedef std::vector<unsigned char> valtype;
bool CreateCoinStake(CWallet& wallet, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, CAmount& nFees, CTxDestination destination, const std::vector<CTransactionRef>& selected_txs)
{
    bool fAllowWatchOnly = wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    CBlockIndex* pindexPrev = wallet.chain().getTip();
    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    LOCK2(cs_main, wallet.cs_wallet);
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    const auto bal = GetBalance(wallet);
    CAmount nBalance = bal.m_mine_trusted;
    if (fAllowWatchOnly)
        nBalance += bal.m_watchonly_trusted;

    if (nBalance <= wallet.m_reserve_balance)
        return false;

    std::set<std::pair<const CWalletTx*, unsigned int> > setCoins;
    std::vector<CTransactionRef> vwtxPrev;
    CAmount nValueIn = 0;
    CAmount nAllowedBalance = nBalance - wallet.m_reserve_balance;
    const int64_t stake_mtp = pindexPrev->GetMedianTimePast();
    const Consensus::Params& consensus = Params().GetConsensus();
    const bool quantum_stake_rules_active = consensus.IsQuantumStakeRulesActive(stake_mtp);
    const bool new_network_stake_only = consensus.IsNewNetworkStakeOnly(stake_mtp);
    const bool final_quantum_lockout = consensus.IsQuantumFinalLockout(stake_mtp);
    const bool stake_reward_split_active = consensus.IsStakeRewardSplitActive(pindexPrev->nHeight + 1);

    // Select coins with suitable depth
    if (!SelectCoinsForStaking(wallet, nAllowedBalance, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    if (IsGoldRushStakeHeight(pindexPrev) && !final_quantum_lockout) {
        const std::set<CScript> whitelisted_scripts = WhitelistedGoldRushStakeScripts(wallet.chain().getCoinsTip(), setCoins);
        if (!whitelisted_scripts.empty()) {
            const size_t original_size = setCoins.size();
            RestrictToGoldRushStakeScripts(whitelisted_scripts, setCoins, nValueIn);
            if (setCoins.empty()) {
                return false;
            }
            if (setCoins.size() != original_size) {
                LogPrint(BCLog::COINSTAKE,
                         "CreateCoinStake : restricted Gold Rush staking to %u whitelisted scripts (%u/%u UTXOs eligible)\n",
                         whitelisted_scripts.size(), setCoins.size(), original_size);
            }
        }
    }

    std::set<COutPoint> selected_tx_inputs;
    for (const CTransactionRef& tx : selected_txs) {
        if (!tx) continue;
        for (const CTxIn& txin : tx->vin) {
            if (!txin.prevout.IsNull()) selected_tx_inputs.insert(txin.prevout);
        }
    }

    CAmount nCredit = 0;
    bool fKernelFound = false;
    CScript scriptPubKeyKernel, scriptPubKeyOut;
    bool bMinterKey = false;
    bool fQuantumKernel = false;
    bool fQuantumColdStakeKernel = false;
    CScript operatorRewardScript;

    for (const std::pair<const CWalletTx*, unsigned int> &pcoin : setCoins)
    {
        if (selected_tx_inputs.count(COutPoint(pcoin.first->GetHash(), pcoin.second))) continue;
        if (final_quantum_lockout &&
            !IsQuantumMigrationScript(pcoin.first->tx->vout[pcoin.second].scriptPubKey) &&
            !IsQuantumColdStakeScript(pcoin.first->tx->vout[pcoin.second].scriptPubKey)) {
            continue;
        }

        CTransactionRef tx = pcoin.first->tx;
        if (!tx) {
            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : wallet transaction unavailable for %s\n", pcoin.first->GetHash().ToString());
            continue;
        }

        static int nMaxStakeSearchInterval = 60;
        for (unsigned int n=0; n<std::min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound; n++)
        {
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
            const uint32_t kernel_time = txNew.nTime - n;
            if (CheckKernel(pindexPrev, nBits, kernel_time, prevoutStake, wallet.chain().getCoinsTip()))
            {
                CAmount kernel_principal{0};
                if (!GetCoinStakeInputPrincipal(wallet.chain().getCoinsTip(), prevoutStake, consensus, pindexPrev->nHeight + 1, stake_mtp, kernel_principal)) {
                    LogPrint(BCLog::COINSTAKE, "CreateCoinStake : skipping kernel with no demurrage-effective principal\n");
                    break;
                }
                // Found a kernel
                LogPrint(BCLog::COINSTAKE, "CreateCoinStake : kernel found\n");
                std::vector<valtype> vSolutions;
                scriptPubKeyKernel = pcoin.first->tx->vout[pcoin.second].scriptPubKey;
                TxoutType whichType = Solver(scriptPubKeyKernel, vSolutions);
                const bool quantum_migration_kernel = IsQuantumMigrationScript(scriptPubKeyKernel);
                const bool quantum_coldstake_kernel = IsQuantumColdStakeScript(scriptPubKeyKernel);
                const bool quantum_kernel = quantum_migration_kernel || quantum_coldstake_kernel;
                if (quantum_kernel && !quantum_stake_rules_active)
                {
                    LogPrint(BCLog::COINSTAKE, "CreateCoinStake : skipping quantum kernel before new-network staking is active\n");
                    break;
                }

                if (!quantum_kernel && whichType != TxoutType::PUBKEY && whichType != TxoutType::PUBKEYHASH && whichType != TxoutType::WITNESS_V0_KEYHASH && whichType != TxoutType::WITNESS_V1_TAPROOT)
                {
                    LogPrint(BCLog::COINSTAKE, "CreateCoinStake : no support for kernel type=%s\n", GetTxnOutputType(whichType));
                    break;  // only support pay to public key and pay to address and pay to witness keyhash
                }
                if (quantum_kernel)
                {
                    int witness_version{0};
                    std::vector<unsigned char> witness_program;
                    const bool parsed_quantum = scriptPubKeyKernel.IsWitnessProgram(witness_version, witness_program) &&
                                                (IsQuantumMigrationWitnessProgram(witness_version, witness_program) ||
                                                 IsQuantumColdStakeWitnessProgram(witness_version, witness_program));
                    CHECK_NONFATAL(parsed_quantum);
                    std::vector<unsigned char> quantum_pubkey;
                    CKeyingMaterial quantum_private_key;
                    bilingual_str error;
                    std::vector<unsigned char> signing_program = witness_program;
                    if (quantum_coldstake_kernel) {
                        const auto delegation = wallet.GetQuantumColdStakeDelegationInfo(witness_program);
                        if (!delegation || !delegation->has_staker_key) {
                            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : skipping quantum cold-stake kernel without loaded staker delegation metadata\n");
                            break;
                        }
                        signing_program.assign(delegation->staker_pubkey_hash.begin(), delegation->staker_pubkey_hash.end());
                    }
                    if (!wallet.GetQuantumKey(signing_program, quantum_pubkey, quantum_private_key, error)) {
                        LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get quantum key for output %s: %s\n", pcoin.first->tx->vout[pcoin.second].ToString(), error.original);
                        break;
                    }
                    if (quantum_coldstake_kernel) {
                        operatorRewardScript = GetScriptForDestination(WitnessUnknown{
                            QUANTUM_MIGRATION_WITNESS_VERSION,
                            QuantumMigrationProgramForPubkey(quantum_pubkey)});
                    }
                    scriptPubKeyOut << OP_RETURN << quantum_pubkey;
                    bMinterKey = true;
                }
                else if (whichType == TxoutType::PUBKEYHASH) // pay to address
                {
                    // convert to pay to public key type
                    CKey key;
                    if (wallet.IsLegacy()) {
                        auto scriptPubKeyMan = wallet.GetLegacyScriptPubKeyMan();
                        if (!scriptPubKeyMan) {
                            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get scriptpubkeyman for kernel type=%s\n", GetTxnOutputType(whichType));
                            break;  // unable to find corresponding public key
                        }
                        if (!scriptPubKeyMan->GetKey(CKeyID(uint160(vSolutions[0])), key))
                        {
                            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get key for kernel type=%s\n", GetTxnOutputType(whichType));
                            break;  // unable to find corresponding public key
                        }
                        scriptPubKeyOut << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
                    }
                    else {
                        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(scriptPubKeyKernel);
                        if (!provider) {
                            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get signing provider for output %s\n", pcoin.first->tx->vout[pcoin.second].ToString());
                            break;
                        }
                        CKeyID ckey = CKeyID(uint160(vSolutions[0]));
                        CPubKey pkey;
                        if (!provider.get()->GetPubKey(ckey, pkey)) {
                            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get key for output %s\n", pcoin.first->tx->vout[pcoin.second].ToString());
                            break;
                        }
                        scriptPubKeyOut << ToByteVector(pkey) << OP_CHECKSIG;
                    }
                }
                else if (whichType == TxoutType::PUBKEY)
                    scriptPubKeyOut = scriptPubKeyKernel;
                else if (whichType == TxoutType::WITNESS_V0_KEYHASH || whichType == TxoutType::WITNESS_V1_TAPROOT) // pay to witness keyhash
                {
                    std::vector<valtype> vSolutionsTmp;
                    CScript scriptPubKeyTmp = GetScriptForDestination(destination);
                    Solver(scriptPubKeyTmp, vSolutionsTmp);
                    std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(scriptPubKeyTmp);
                    if (!provider) {
                        LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get signing provider for output %s\n", pcoin.first->tx->vout[pcoin.second].ToString());
                        break;
                    }
                    CKeyID ckey = CKeyID(uint160(vSolutionsTmp[0]));
                    CPubKey pkey;
                    if (!provider.get()->GetPubKey(ckey, pkey)) {
                        LogPrint(BCLog::COINSTAKE, "CreateCoinStake : failed to get key for output %s\n", pcoin.first->tx->vout[pcoin.second].ToString());
                        break;
                    }
                    scriptPubKeyOut << ToByteVector(pkey) << OP_CHECKSIG;
                    bMinterKey = true;
                }

                txNew.nTime = kernel_time;
                txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
                nCredit += kernel_principal;
                vwtxPrev.push_back(tx);
                fQuantumKernel = quantum_kernel;
                fQuantumColdStakeKernel = quantum_coldstake_kernel;

                if (bMinterKey) {
                    // extra output for minter key
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                    // redefine scriptPubKeyOut to send output to input address
                    scriptPubKeyOut = scriptPubKeyKernel;
                }
    
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                LogPrint(BCLog::COINSTAKE, "CreateCoinStake : added kernel type=%d\n", (int)whichType);
                fKernelFound = true;
                break;
            }
        }
        if (fKernelFound)
            break; // if kernel is found stop searching
    }
    if (!fKernelFound)
        return false;
    if (nCredit == 0 || nCredit > nAllowedBalance)
        return false;

    for (const std::pair<const CWalletTx*, unsigned int> &pcoin : setCoins)
    {
        if (selected_tx_inputs.count(COutPoint(pcoin.first->GetHash(), pcoin.second))) continue;
        CTransactionRef tx = pcoin.first->tx;
        if (!tx) {
            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : wallet transaction unavailable for %s\n", pcoin.first->GetHash().ToString());
            continue;
        }

        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 && ((pcoin.first->tx->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->tx->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.first->GetHash() != txNew.vin[0].prevout.hash)
        {
            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 10)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit >= GetStakeCombineThreshold())
                break;
            const COutPoint candidate_outpoint(pcoin.first->GetHash(), pcoin.second);
            CAmount candidate_principal{0};
            if (!GetCoinStakeInputPrincipal(wallet.chain().getCoinsTip(), candidate_outpoint, consensus, pindexPrev->nHeight + 1, stake_mtp, candidate_principal))
                continue;
            // Stop adding inputs if reached reserve limit
            if (nCredit + candidate_principal > nBalance - wallet.m_reserve_balance)
                break;
            // Do not add additional significant input
            if (candidate_principal >= GetStakeCombineThreshold())
                continue;

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += candidate_principal;
            vwtxPrev.push_back(tx);
        }
    }

    // Calculate reward. Before the stake-reward split activates, V4 cold-stake
    // delegation is deliberately less profitable than self-staking.
    const bool fColdStakeReward = consensus.IsProtocolV4(stake_mtp) && CoinStakeSpendsKnownColdStake(wallet, txNew, vwtxPrev);
    CAmount nReward = 0;
    CAmount nOperatorCredit = 0;
    if (stake_reward_split_active) {
        const CAmount base_reward = GetProofOfStakeSubsidy();
        if (fColdStakeReward) {
            if (!fQuantumColdStakeKernel || operatorRewardScript.empty()) {
                return error("CreateCoinStake : missing operator reward script for cold-stake reward split");
            }
            const CAmount operator_floor = (base_reward * 5) / 100;
            nOperatorCredit = std::max(operator_floor, nFees);
            const CAmount operator_shortfall = nOperatorCredit > nFees ? nOperatorCredit - nFees : 0;
            if (operator_shortfall > base_reward) {
                return error("CreateCoinStake : invalid operator reward split");
            }
            nReward = base_reward - operator_shortfall;
            LogPrint(BCLog::COINSTAKE, "CreateCoinStake : cold-stake split applied delegator_reward=%d operator_comp=%d fees=%d\n", nReward, nOperatorCredit, nFees);
        } else {
            nReward = nFees + base_reward;
        }
    } else {
        nReward = nFees + GetProofOfStakeSubsidyForCoinstake(fColdStakeReward);
    }
    if (nReward < 0)
        return false;
    if (fColdStakeReward && !stake_reward_split_active) {
        LogPrint(BCLog::COINSTAKE, "CreateCoinStake : cold-stake subsidy discount applied\n");
    }

    bool isDevFundEnabled = (wallet.m_donation_percentage > 0 && !Params().GetDevFundAddress().empty()) ? true : false;
    int treasuryPercentage = wallet.m_donation_percentage;

    // Treasury contribution is WALLET-LEVEL and opt-in/opt-out (set -donatetodevfund).
    // It is not consensus-enforced: consensus does not require any treasury output, so
    // a staker who opts out still produces a fully valid block. The GUI keeps the
    // default off until the wallet migration is complete, but a manual nonzero choice
    // is honored whenever the coinstake format can safely include the extra output.
    if (stake_reward_split_active) {
        isDevFundEnabled = false; // The stake-reward split enforces exact participant/operator split; no wallet-level extra value outputs.
    }
    if (isDevFundEnabled && final_quantum_lockout) {
        const CScript dev_reward_script = Params().GetDevRewardScript();
        if (!IsQuantumMigrationScript(dev_reward_script) && !IsQuantumColdStakeScript(dev_reward_script) && !IsEUTXOScript(dev_reward_script)) {
            wallet.WalletLogPrintf("Dev fund contribution disabled after Quantum lockout because the configured dev reward script is legacy\n");
            isDevFundEnabled = false;
        }
    }

    CAmount nDevCredit = 0;
    CAmount nMinerCredit = 0;

    if (isDevFundEnabled)
    {
        nDevCredit = (nReward * treasuryPercentage) / 100;
        nMinerCredit = nReward - nDevCredit;
        nCredit += nMinerCredit;
    }
    else
    {
        nCredit += nReward;
    }

    // Split stake
    if (nCredit >= GetStakeSplitThreshold())
        txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));

    if (isDevFundEnabled)
        txNew.vout.push_back(CTxOut(0, Params().GetDevRewardScript()));

    // Set output amount
    if (txNew.vout.size() == (isDevFundEnabled ? 4u : 3u) + bMinterKey) {
        txNew.vout[1 + bMinterKey].nValue = (nCredit / 2 / CENT) * CENT;
        txNew.vout[2 + bMinterKey].nValue = nCredit - txNew.vout[1 + bMinterKey].nValue;
        if (isDevFundEnabled)
            txNew.vout[3 + bMinterKey].nValue = nDevCredit;
    }
    else
    {
        txNew.vout[1 + bMinterKey].nValue = nCredit;
        if (isDevFundEnabled)
            txNew.vout[2 + bMinterKey].nValue = nDevCredit;
    }

    if (stake_reward_split_active && nOperatorCredit > 0) {
        txNew.vout.push_back(CTxOut(nOperatorCredit, operatorRewardScript));
    }

    if (pindexPrev->nHeight + 1 >= SHADOW_REWARD_START_HEIGHT &&
        consensus.IsProtocolV4(stake_mtp) &&
        !final_quantum_lockout) {
        txNew.vout.push_back(CTxOut(0, BuildQuantumQuasarBlockNoticeScript()));
    }

    // Sign
    int nIn = 0;
    const int nStakeHashType = SIGHASH_ALL | (new_network_stake_only ? SIGHASH_FORKID : 0);

    if (wallet.IsLegacy() && !fQuantumKernel) {
        for (const auto &pcoin : vwtxPrev) {
            SignatureData empty;
            if (!SignSignature(*wallet.GetLegacyScriptPubKeyMan(), *pcoin, txNew, nIn++, nStakeHashType, empty))
                return error("CreateCoinStake : failed to sign coinstake");
        }
    }
    else
    {
        // Fetch previous transactions (inputs):
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : txNew.vin) {
            coins[txin.prevout]; // Create empty map entry keyed by prevout.
        }
        wallet.chain().findCoins(coins);
        // Script verification errors
        std::map<int, bilingual_str> input_errors;
        int nTime = txNew.nTime;
        if (!wallet.SignTransaction(txNew, coins, nStakeHashType, input_errors)) {
            for (const auto& [input_index, error] : input_errors) {
                LogPrintf("CreateCoinStake : failed to sign input %d: %s\n", input_index, error.original);
            }
            return error("CreateCoinStake : failed to sign coinstake");
        }
        txNew.nTime = nTime;
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(TX_WITH_WITNESS(txNew));
    if (nBytes >= 1000000/5)
        return error("CreateCoinStake : exceeded coinstake size limit");

    // Successfully generated coinstake
    return true;
}
} // namespace wallet
