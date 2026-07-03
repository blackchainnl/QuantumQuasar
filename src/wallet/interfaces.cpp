// Copyright (c) 2018-2022 Blackcoin Core Developers
// Copyright (c) 2018-2022 Blackcoin More Developers
// Copyright (c) 2018-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/demurrage.h>
#include <consensus/quantum_witness.h>
#include <crypto/mldsa.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <kernel/cs_main.h>
#include <key_io.h>
#include <node/quantum_pool.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/solver.h>
#include <shadow.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/types.h>
#include <wallet/load.h>
#include <wallet/quantum_stake_ops.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/spend.h>
#include <wallet/staking.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeSignalHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletLoader;
using interfaces::WalletMigrationResult;
using interfaces::WalletMigrationStatus;
using interfaces::WalletPowMiningInfo;
using interfaces::WalletDemurrageInfo;
using interfaces::WalletDemurrageOutputInfo;
using interfaces::WalletEUTXOStateInfo;
using interfaces::WalletRGBAssetInfo;
using interfaces::WalletRGBAssignmentInfo;
using interfaces::WalletQuantumAddressInfo;
using interfaces::WalletQuantumColdStakeBalanceInfo;
using interfaces::WalletQuantumActionTx;
using interfaces::WalletQuantumColdStakeInfo;
using interfaces::WalletQuantumOperatorBondInfo;
using interfaces::WalletQuantumOperatorBondTx;
using interfaces::WalletQuantumPoolInfo;
using interfaces::WalletQuantumPoolOperatorInfo;
using interfaces::WalletQuantumStakeOutputInfo;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;

namespace wallet {
// All members of the classes in this namespace are intentionally public, as the
// classes themselves are private.
namespace {
std::string QuantumQuasarPhaseName(Consensus::QuantumQuasarPhase phase)
{
    switch (phase) {
    case Consensus::QuantumQuasarPhase::LEGACY: return "legacy";
    case Consensus::QuantumQuasarPhase::GOLD_RUSH: return "gold_rush";
    case Consensus::QuantumQuasarPhase::MIGRATION: return "migration";
    case Consensus::QuantumQuasarPhase::FINAL_LOCKOUT: return "final_lockout";
    }
    return "unknown";
}

bool IsDirectQuantumMigrationScript(const CScript& script_pub_key)
{
    const auto tier = GetQuantumStakeTierProgram(script_pub_key);
    return tier && !tier->tiered && !tier->cold_stake;
}

util::Result<void> CommitWalletTransactionOrError(CWallet& wallet, const CTransactionRef& tx, mapValue_t map_value, const std::string& action)
{
    try {
        std::string broadcast_error;
        if (!wallet.CommitTransaction(tx, std::move(map_value), {}, &broadcast_error)) {
            const std::string reason = broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error;
            if (!wallet.AbandonTransaction(tx->GetHash())) {
                wallet.WalletLogPrintf("%s transaction could not be abandoned after broadcast failure: txid=%s\n", action, tx->GetHash().ToString());
            }
            return util::Error{Untranslated(strprintf("Error: %s transaction was created but could not be broadcast: %s", action, reason))};
        }
    } catch (const std::exception& e) {
        return util::Error{Untranslated(strprintf("Error: %s transaction could not be committed: %s", action, e.what()))};
    }
    return {};
}

WalletQuantumAddressInfo MakeWalletQuantumAddressInfo(const CWallet& wallet, const QuantumKeyInfo& info)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletQuantumAddressInfo result;
    result.address = EncodeDestination(info.destination);
    if (const auto* entry = wallet.FindAddressBookEntry(info.destination)) {
        result.label = entry->GetLabel();
    }
    result.public_key = HexStr(info.public_key);
    result.creation_time = info.creation_time;
    result.encrypted = info.encrypted;
    QuantumStakeTierProgram tier;
    if (DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, info.witness_program, tier) && tier.tiered) {
        result.tiered = true;
        result.unbonding_blocks = tier.unbonding_blocks;
        result.unlock_height = tier.unlock_height;
    }
    return result;
}

WalletQuantumColdStakeInfo MakeWalletQuantumColdStakeInfo(const CWallet& wallet, const QuantumColdStakeDelegationInfo& info)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletQuantumColdStakeInfo result;
    result.address = EncodeDestination(info.destination);
    if (const auto* entry = wallet.FindAddressBookEntry(info.destination)) {
        result.label = entry->GetLabel();
    }
    result.staking_pubkey_hash = info.staker_pubkey_hash.GetHex();
    result.owner_pubkey_hash = info.owner_pubkey_hash.GetHex();
    result.creation_time = info.creation_time;
    result.has_staker_key = info.has_staker_key;
    result.has_owner_key = info.has_owner_key;
    result.tiered = info.tiered;
    result.unbonding_blocks = info.unbonding_blocks;
    result.unlock_height = info.unlock_height;
    return result;
}

} // namespace

struct ColdStakeDelegationOutputs
{
    CAmount amount{0};
    int outputs{0};
    CAmount confirmed_amount{0};
    int confirmed_outputs{0};
    CAmount unconfirmed_amount{0};
    int unconfirmed_outputs{0};
    CAmount spendable_amount{0};
    int spendable_outputs{0};
    std::vector<COutPoint> spendable_outpoints;
};

struct ColdStakeFundingInputs
{
    CAmount eligible_amount{0};
    unsigned int eligible_inputs{0};
    CAmount goldrush_reward_amount{0};
    unsigned int goldrush_reward_inputs{0};
};

static constexpr uint16_t OPERATOR_COMMITMENT_BLOCKS = 40500;
static constexpr int RANDOM_CHANGE_POSITION = -1;

util::Result<QuantumColdStakeDelegationInfo> DecodeWalletColdStakeDelegationAddress(
    const CWallet& wallet,
    const std::string& address,
    CTxDestination& dest) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string error_msg;
    dest = DecodeDestination(address, error_msg);
    if (!IsValidDestination(dest)) {
        return util::Error{Untranslated(error_msg.empty() ? "Error: Invalid quantum cold-stake address" : error_msg)};
    }

    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumColdStakeWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        return util::Error{_("Error: Address must be a Quantum Cold-Stake delegation address")};
    }

    const auto info = wallet.GetQuantumColdStakeDelegationInfo(dest);
    if (!info) {
        return util::Error{_("Error: Cold-stake delegation address is not backed by this wallet")};
    }
    return *info;
}

ColdStakeDelegationOutputs ScanColdStakeDelegationOutputs(
    const CWallet& wallet,
    const CScript& delegation_script,
    bool spendable_only) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    ColdStakeDelegationOutputs outputs;

    CoinFilterParams filter;
    filter.only_spendable = spendable_only;
    filter.skip_locked = spendable_only;
    filter.include_immature_coinbase = false;

    const std::vector<COutput> coins = spendable_only
        ? AvailableCoins(wallet, nullptr, std::nullopt, filter).All()
        : AvailableCoinsListUnspent(wallet, nullptr, filter).All();

    for (const COutput& out : coins) {
        if (out.txout.nValue <= 0 || out.txout.scriptPubKey != delegation_script) continue;
        outputs.amount += out.txout.nValue;
        ++outputs.outputs;
        if (out.depth > 0) {
            outputs.confirmed_amount += out.txout.nValue;
            ++outputs.confirmed_outputs;
        } else {
            outputs.unconfirmed_amount += out.txout.nValue;
            ++outputs.unconfirmed_outputs;
        }
        if (out.spendable) {
            outputs.spendable_amount += out.txout.nValue;
            ++outputs.spendable_outputs;
            if (spendable_only) outputs.spendable_outpoints.push_back(out.outpoint);
        }
    }
    return outputs;
}

WalletQuantumColdStakeBalanceInfo MakeWalletColdStakeBalanceInfo(const CWallet& wallet, const std::string& address)
{
    WalletQuantumColdStakeBalanceInfo result;
    CTxDestination dest;
    TRY_LOCK(wallet.cs_wallet, wallet_lock);
    if (!wallet_lock) {
        result.available = false;
        return result;
    }
    const auto delegation = DecodeWalletColdStakeDelegationAddress(wallet, address, dest);
    if (!delegation) return result;

    result.valid_delegation_address = true;
    result.current_height = wallet.GetLastBlockHeight();
    const ColdStakeDelegationOutputs outputs = ScanColdStakeDelegationOutputs(
        wallet,
        GetScriptForDestination(dest),
        /*spendable_only=*/false);
    result.amount = outputs.amount;
    result.outputs = outputs.outputs;
    result.confirmed_amount = outputs.confirmed_amount;
    result.confirmed_outputs = outputs.confirmed_outputs;
    result.unconfirmed_amount = outputs.unconfirmed_amount;
    result.unconfirmed_outputs = outputs.unconfirmed_outputs;
    result.spendable_amount = outputs.spendable_amount;
    result.spendable_outputs = outputs.spendable_outputs;
    return result;
}

util::Result<QuantumStakeTierProgram> DecodeTieredStakeAddress(const std::string& address, CTxDestination& dest, bool require_operator_lock)
{
    std::string error_msg;
    dest = DecodeDestination(address, error_msg);
    if (!IsValidDestination(dest)) {
        return util::Error{Untranslated(error_msg.empty() ? "Error: Invalid quantum staking address" : error_msg)};
    }

    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness) {
        return util::Error{_("Error: Address must be a bonded quantum staking address")};
    }

    QuantumStakeTierProgram tier;
    if (!DecodeQuantumStakeTierProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram(), tier) ||
        tier.cold_stake || !tier.IsBonded()) {
        return util::Error{_("Error: Address must be a wallet-backed bonded quantum staking address")};
    }
    if (require_operator_lock && tier.unbonding_blocks != OPERATOR_COMMITMENT_BLOCKS) {
        return util::Error{_("Error: Operator address must be a wallet-backed fixed 30-day bonded quantum staking address")};
    }
    return tier;
}

bool CanCreateSignedSpend(const CWallet& wallet, bilingual_str& error)
{
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = _("Error: Private keys are disabled for this wallet");
        return false;
    }
    if (wallet.IsLocked()) {
        error = _("Error: Wallet is locked");
        return false;
    }
    if (wallet.m_wallet_unlock_staking_only) {
        error = _("Error: Wallet is unlocked for staking only");
        return false;
    }
    return true;
}

ColdStakeFundingInputs ScanColdStakeFundingInputs(
    const CWallet& wallet,
    const CCoinsViewCache& view) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, wallet.cs_wallet)
{
    ColdStakeFundingInputs summary;

    CCoinControl scan_control;
    scan_control.m_input_family = CCoinControl::InputFamily::QUANTUM_MIGRATION;

    CoinFilterParams filter;
    filter.only_spendable = true;
    filter.skip_locked = true;
    filter.include_immature_coinbase = false;

    for (const COutput& out : AvailableCoins(wallet, &scan_control, std::nullopt, filter).All()) {
        if (out.txout.nValue <= 0 || !IsDirectQuantumMigrationScript(out.txout.scriptPubKey)) continue;

        CScript marker_script;
        if (IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) && marker_script == out.txout.scriptPubKey) {
            summary.goldrush_reward_amount += out.txout.nValue;
            ++summary.goldrush_reward_inputs;
            continue;
        }

        summary.eligible_amount += out.txout.nValue;
        ++summary.eligible_inputs;
    }

    return summary;
}

struct SafeFeeInputSummary {
    CAmount amount{0};
    unsigned int inputs{0};
};

SafeFeeInputSummary SelectSafeUnbondingFeeInputs(
    CWallet& wallet,
    const CCoinsViewCache& view,
    CCoinControl& coin_control,
    CAmount target_amount,
    bool allow_legacy) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, wallet.cs_wallet)
{
    SafeFeeInputSummary summary;

    CoinFilterParams filter;
    filter.only_spendable = true;
    filter.skip_locked = true;
    filter.include_immature_coinbase = false;

    CCoinControl scan_control;
    scan_control.m_exclude_generated_quantum_inputs = true;

    std::vector<COutput> outputs = AvailableCoins(wallet, &scan_control, std::nullopt, filter).All();
    std::sort(outputs.begin(), outputs.end(), [](const COutput& a, const COutput& b) {
        if (a.txout.nValue != b.txout.nValue) return a.txout.nValue < b.txout.nValue;
        return a.outpoint < b.outpoint;
    });

    for (const COutput& out : outputs) {
        if (coin_control.IsSelected(out.outpoint) || out.txout.nValue <= 0) continue;

        const CScript& spk = out.txout.scriptPubKey;
        CScript marker_script;
        if (IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) && marker_script == spk) continue;

        const bool direct_quantum = IsDirectQuantumMigrationScript(spk);
        const bool legacy = allow_legacy && !IsQuantumMigrationScript(spk) && !IsQuantumColdStakeScript(spk) && !IsEUTXOScript(spk);
        if (!direct_quantum && !legacy) continue;

        if (!MoneyRange(out.txout.nValue) || summary.amount > MAX_MONEY - out.txout.nValue) break;
        coin_control.Select(out.outpoint);
        summary.amount += out.txout.nValue;
        ++summary.inputs;
        if (summary.amount >= target_amount) break;
    }

    return summary;
}

struct OperatorBondOutputs
{
    struct Record
    {
        COutPoint outpoint;
        CAmount amount{0};
        int depth{0};
        bool spendable{false};
        std::string state;
        uint32_t unlock_height{0};
    };

    CAmount bonded_amount{0};
    int bonded_outputs{0};
    std::vector<COutPoint> bonded_outpoints;
    CAmount unbonding_amount{0};
    int unbonding_outputs{0};
    CAmount withdrawable_amount{0};
    int withdrawable_outputs{0};
    std::vector<COutPoint> withdrawable_outpoints;
    uint32_t next_unlock_height{0};
    std::vector<Record> records;
};

struct LocalOperatorBondCandidate
{
    std::vector<unsigned char> staking_pubkey;
    COutPoint outpoint;
};

util::Result<WalletQuantumActionTx> CreateGoldRushColdStakeMigration(CWallet& wallet);

OperatorBondOutputs ScanOperatorBondOutputs(
    const CWallet& wallet,
    const CScript& bonded_script,
    const uint256& operator_commitment,
    int spend_height,
    bool spendable_only) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    OperatorBondOutputs outputs;

    CoinFilterParams filter;
    filter.only_spendable = spendable_only;
    filter.skip_locked = spendable_only;
    filter.include_immature_coinbase = false;

    const std::vector<COutput> coins = spendable_only
        ? AvailableCoins(wallet, nullptr, std::nullopt, filter).All()
        : AvailableCoinsListUnspent(wallet, nullptr, filter).All();

    for (const COutput& out : coins) {
        if (out.txout.nValue <= 0) continue;
        if (out.txout.scriptPubKey == bonded_script) {
            outputs.bonded_amount += out.txout.nValue;
            ++outputs.bonded_outputs;
            if (spendable_only) outputs.bonded_outpoints.push_back(out.outpoint);
            outputs.records.push_back({out.outpoint, out.txout.nValue, out.depth, out.spendable, "bonded", 0});
            continue;
        }

        const auto tier = GetQuantumStakeTierProgram(out.txout.scriptPubKey);
        if (!tier || !tier->IsUnbonding() || tier->cold_stake || tier->commitment != operator_commitment) continue;

        outputs.unbonding_amount += out.txout.nValue;
        ++outputs.unbonding_outputs;
        if (tier->unlock_height <= static_cast<uint32_t>(std::max(0, spend_height))) {
            outputs.withdrawable_amount += out.txout.nValue;
            ++outputs.withdrawable_outputs;
            if (spendable_only) outputs.withdrawable_outpoints.push_back(out.outpoint);
            outputs.records.push_back({out.outpoint, out.txout.nValue, out.depth, out.spendable, "withdrawable", tier->unlock_height});
        } else if (outputs.next_unlock_height == 0 || tier->unlock_height < outputs.next_unlock_height) {
            outputs.next_unlock_height = tier->unlock_height;
            outputs.records.push_back({out.outpoint, out.txout.nValue, out.depth, out.spendable, "unbonding", tier->unlock_height});
        } else {
            outputs.records.push_back({out.outpoint, out.txout.nValue, out.depth, out.spendable, "unbonding", tier->unlock_height});
        }
    }
    return outputs;
}

std::vector<WalletQuantumStakeOutputInfo> ListTieredStakeOutputs(
    const CWallet& wallet,
    const std::string& address,
    bool require_operator_lock)
{
    std::vector<WalletQuantumStakeOutputInfo> result;
    CTxDestination dest;
    const auto tier = DecodeTieredStakeAddress(address, dest, require_operator_lock);
    if (!tier) return result;

    TRY_LOCK(wallet.cs_wallet, wallet_lock);
    if (!wallet_lock) return result;
    const auto key_info = wallet.GetQuantumKeyInfo(dest);
    if (!key_info) return result;

    const int current_height = wallet.GetLastBlockHeight();
    const int spend_height = current_height + 1;
    const OperatorBondOutputs outputs = ScanOperatorBondOutputs(
        wallet,
        GetScriptForDestination(dest),
        tier->commitment,
        spend_height,
        /*spendable_only=*/false);

    result.reserve(outputs.records.size());
    for (const OperatorBondOutputs::Record& record : outputs.records) {
        WalletQuantumStakeOutputInfo info;
        info.txid = record.outpoint.hash.GetHex();
        info.vout = record.outpoint.n;
        info.address = address;
        info.amount = record.amount;
        info.depth = record.depth;
        info.state = record.state;
        info.unlock_height = record.unlock_height;
        info.spendable = record.spendable;
        result.push_back(std::move(info));
    }
    return result;
}

std::vector<LocalOperatorBondCandidate> FindWalletOperatorBondCandidates(const CWallet& wallet)
{
    struct OperatorAddress
    {
        std::string address;
        std::vector<unsigned char> staking_pubkey;
    };

    std::vector<OperatorAddress> operator_addresses;
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        const auto infos = wallet.ListQuantumKeyInfos();
        operator_addresses.reserve(infos.size());
        for (const QuantumKeyInfo& info : infos) {
            const WalletQuantumAddressInfo address_info = MakeWalletQuantumAddressInfo(wallet, info);
            if (!address_info.tiered ||
                address_info.unbonding_blocks != OPERATOR_COMMITMENT_BLOCKS ||
                info.public_key.size() != ML_DSA::PUBLICKEY_BYTES) {
                continue;
            }
            operator_addresses.push_back({address_info.address, info.public_key});
        }
    }

    std::vector<LocalOperatorBondCandidate> candidates;
    for (const OperatorAddress& operator_address : operator_addresses) {
        const std::vector<WalletQuantumStakeOutputInfo> outputs =
            ListTieredStakeOutputs(wallet, operator_address.address, /*require_operator_lock=*/true);
        for (const WalletQuantumStakeOutputInfo& output : outputs) {
            if (output.state != "bonded" || output.amount <= 0) continue;
            candidates.push_back({
                operator_address.staking_pubkey,
                COutPoint{uint256S(output.txid), output.vout}});
        }
    }
    return candidates;
}

std::map<uint256, std::vector<node::QuantumPoolClaim>> FindWalletQuantumPoolClaims(const CWallet& wallet)
{
    std::map<uint256, std::vector<node::QuantumPoolClaim>> claims_by_operator;

    LOCK(wallet.cs_wallet);
    CoinFilterParams filter;
    filter.only_spendable = false;
    filter.skip_locked = false;
    filter.include_immature_coinbase = false;
    const std::vector<COutput> coins = AvailableCoinsListUnspent(wallet, nullptr, filter).All();

    for (const COutput& out : coins) {
        if (out.txout.nValue <= 0) continue;

        int witness_version{0};
        std::vector<unsigned char> witness_program;
        if (!out.txout.scriptPubKey.IsWitnessProgram(witness_version, witness_program) ||
            !IsQuantumColdStakeWitnessProgram(witness_version, witness_program)) {
            continue;
        }

        const auto info = wallet.GetQuantumColdStakeDelegationInfo(witness_program);
        if (!info) continue;

        node::QuantumPoolClaim claim;
        claim.outpoint = out.outpoint;
        claim.staker_pubkey_hash = info->staker_pubkey_hash;
        claim.owner_pubkey_hash = info->owner_pubkey_hash;

        if (const auto tier = GetQuantumStakeTierProgram(out.txout.scriptPubKey); tier && tier->tiered && tier->cold_stake) {
            claim.tiered = true;
            claim.state = tier->state;
            claim.unbonding_blocks = tier->unbonding_blocks;
            claim.unlock_height = tier->unlock_height;
        }

        claims_by_operator[claim.staker_pubkey_hash].push_back(std::move(claim));
    }

    return claims_by_operator;
}

bool FindTieredStakeRecord(const OperatorBondOutputs& outputs, const COutPoint& outpoint, OperatorBondOutputs::Record& record)
{
    const auto it = std::find_if(outputs.records.begin(), outputs.records.end(), [&](const OperatorBondOutputs::Record& candidate) {
        return candidate.outpoint == outpoint;
    });
    if (it == outputs.records.end()) return false;
    record = *it;
    return true;
}

void KeepOnlySelectedTieredStakeOutput(OperatorBondOutputs& outputs, const OperatorBondOutputs::Record& selected)
{
    outputs.bonded_amount = 0;
    outputs.bonded_outputs = 0;
    outputs.bonded_outpoints.clear();
    outputs.unbonding_amount = 0;
    outputs.unbonding_outputs = 0;
    outputs.withdrawable_amount = 0;
    outputs.withdrawable_outputs = 0;
    outputs.withdrawable_outpoints.clear();
    outputs.next_unlock_height = 0;

    if (selected.state == "bonded") {
        outputs.bonded_amount = selected.amount;
        outputs.bonded_outputs = 1;
        outputs.bonded_outpoints.push_back(selected.outpoint);
    } else if (selected.state == "withdrawable") {
        outputs.unbonding_amount = selected.amount;
        outputs.unbonding_outputs = 1;
        outputs.withdrawable_amount = selected.amount;
        outputs.withdrawable_outputs = 1;
        outputs.withdrawable_outpoints.push_back(selected.outpoint);
    } else if (selected.state == "unbonding") {
        outputs.unbonding_amount = selected.amount;
        outputs.unbonding_outputs = 1;
        outputs.next_unlock_height = selected.unlock_height;
    }
}

WalletQuantumOperatorBondInfo MakeWalletTieredStakeBondInfo(const CWallet& wallet, const std::string& address, bool require_operator_lock)
{
    WalletQuantumOperatorBondInfo result;
    CTxDestination dest;
    const auto tier = DecodeTieredStakeAddress(address, dest, require_operator_lock);
    if (!tier) return result;

    TRY_LOCK(wallet.cs_wallet, wallet_lock);
    if (!wallet_lock) {
        result.available = false;
        return result;
    }
    const auto key_info = wallet.GetQuantumKeyInfo(dest);
    if (!key_info) return result;

    const int current_height = wallet.GetLastBlockHeight();
    const int spend_height = current_height + 1;
    const OperatorBondOutputs outputs = ScanOperatorBondOutputs(
        wallet,
        GetScriptForDestination(dest),
        tier->commitment,
        spend_height,
        /*spendable_only=*/false);

    result.valid_operator_address = true;
    result.current_height = current_height;
    result.bonded_amount = outputs.bonded_amount;
    result.bonded_outputs = outputs.bonded_outputs;
    result.unbonding_amount = outputs.unbonding_amount;
    result.unbonding_outputs = outputs.unbonding_outputs;
    result.withdrawable_amount = outputs.withdrawable_amount;
    result.withdrawable_outputs = outputs.withdrawable_outputs;
    result.next_unlock_height = outputs.next_unlock_height;
    return result;
}

WalletQuantumOperatorBondInfo MakeWalletOperatorBondInfo(const CWallet& wallet, const std::string& operator_address)
{
    return MakeWalletTieredStakeBondInfo(wallet, operator_address, /*require_operator_lock=*/true);
}

util::Result<WalletQuantumOperatorBondTx> FundTieredStakeAddress(
    CWallet& wallet,
    const std::string& address,
    CAmount amount,
    bool require_operator_lock,
    std::string comment)
{
    if (!MoneyRange(amount) || amount <= 0) {
        return util::Error{_("Error: Funding amount must be positive")};
    }

    CTxDestination dest;
    const auto tier = DecodeTieredStakeAddress(address, dest, require_operator_lock);
    if (!tier) return util::Error{util::ErrorString(tier)};

    CTransactionRef tx;
    CAmount fee{0};
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};
        if (!wallet.GetQuantumKeyInfo(dest)) {
            return util::Error{_("Error: Staking address is not backed by this wallet")};
        }

        std::vector<CRecipient> recipients{{dest, amount, /*fSubtractFeeFromAmount=*/false}};
        CCoinControl coin_control;
        coin_control.m_input_family = CCoinControl::InputFamily::LEGACY;
        coin_control.m_allow_other_inputs = true;
        auto change_dest = wallet.GetNewQuantumChangeDestination();
        if (!change_dest) return util::Error{util::ErrorString(change_dest)};
        coin_control.destChange = *change_dest;
        int change_pos = RANDOM_CHANGE_POSITION;
        auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
        if (!res) return util::Error{util::ErrorString(res)};
        tx = res->tx;
        fee = res->fee;
    }

    mapValue_t map_value;
    map_value["comment"] = std::move(comment);
    if (auto committed = CommitWalletTransactionOrError(wallet, tx, std::move(map_value), "staking address funding"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumOperatorBondTx result;
    result.txid = tx->GetHash().GetHex();
    result.address = address;
    result.amount = amount;
    result.fee = fee;
    return result;
}

util::Result<WalletQuantumOperatorBondTx> WithdrawTieredStakeAddress(
    CWallet& wallet,
    const std::string& address,
    bool require_operator_lock,
    const std::string& unbonding_label,
    const std::string& withdrawal_label,
    std::string unbonding_comment,
    std::string withdrawal_comment,
    std::optional<COutPoint> selected_outpoint)
{
    CTxDestination dest;
    const auto tier = DecodeTieredStakeAddress(address, dest, require_operator_lock);
    if (!tier) return util::Error{util::ErrorString(tier)};

    CTransactionRef tx;
    CAmount amount{0};
    CAmount fee{0};
    uint32_t unlock_height{0};
    std::string destination_address;
    std::string comment;
    bool started_unbonding{false};
    bool completed_withdrawal{false};
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};

        const auto stake_key = wallet.GetQuantumKeyInfo(dest);
        if (!stake_key) {
            return util::Error{_("Error: Staking address is not backed by this wallet")};
        }

        const int current_height = wallet.GetLastBlockHeight();
        const int spend_height = current_height + 1;
        OperatorBondOutputs outputs = ScanOperatorBondOutputs(
            wallet,
            GetScriptForDestination(dest),
            tier->commitment,
            spend_height,
            /*spendable_only=*/true);

        if (selected_outpoint) {
            OperatorBondOutputs::Record selected_record;
            if (!FindTieredStakeRecord(outputs, *selected_outpoint, selected_record)) {
                const OperatorBondOutputs all_outputs = ScanOperatorBondOutputs(
                    wallet,
                    GetScriptForDestination(dest),
                    tier->commitment,
                    spend_height,
                    /*spendable_only=*/false);
                if (FindTieredStakeRecord(all_outputs, *selected_outpoint, selected_record)) {
                    return util::Error{_("Error: Selected staking output is not currently spendable")};
                }
                return util::Error{_("Error: Selected staking output was not found for this address")};
            }
            KeepOnlySelectedTieredStakeOutput(outputs, selected_record);
        }

        CCoinControl coin_control;
        int change_pos = RANDOM_CHANGE_POSITION;
        std::vector<CRecipient> recipients;

        if (!outputs.bonded_outpoints.empty()) {
            for (const COutPoint& outpoint : outputs.bonded_outpoints) {
                coin_control.Select(outpoint);
            }
            coin_control.m_allow_other_inputs = false;
            coin_control.m_exclude_generated_quantum_inputs = true;
            const CCoinsViewCache& view = wallet.chain().chainman().ActiveChainstate().CoinsTip();
            const SafeFeeInputSummary fee_inputs = SelectSafeUnbondingFeeInputs(
                wallet,
                view,
                coin_control,
                wallet.m_default_max_tx_fee,
                /*allow_legacy=*/true);
            if (fee_inputs.inputs == 0) {
                return util::Error{_("Error: No safe fee input is available to start unbonding. Add a small ordinary legacy or direct quantum UTXO, then try again.")};
            }

            auto change_dest = wallet.GetNewQuantumChangeDestination();
            if (!change_dest) return util::Error{util::ErrorString(change_dest)};
            coin_control.destChange = *change_dest;

            unlock_height = static_cast<uint32_t>(std::max(0, spend_height + int{tier->unbonding_blocks}));
            const std::vector<unsigned char> unbonding_program = QuantumTieredMigrationProgramForPubkey(
                stake_key->public_key,
                QUANTUM_TIERED_STATE_UNBONDING,
                tier->unbonding_blocks,
                unlock_height);
            const CTxDestination unbonding_dest = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, unbonding_program};
            wallet.SetAddressBook(unbonding_dest, unbonding_label, AddressPurpose::RECEIVE);

            amount = outputs.bonded_amount;
            destination_address = EncodeDestination(unbonding_dest);
            recipients.push_back({unbonding_dest, amount, /*fSubtractFeeFromAmount=*/false});
            comment = std::move(unbonding_comment);
            started_unbonding = true;
        } else if (!outputs.withdrawable_outpoints.empty()) {
            for (const COutPoint& outpoint : outputs.withdrawable_outpoints) {
                coin_control.Select(outpoint);
            }
            coin_control.m_allow_other_inputs = false;
            coin_control.m_input_family = CCoinControl::InputFamily::QUANTUM;

            auto withdraw_dest = wallet.GetNewQuantumDestination(withdrawal_label);
            if (!withdraw_dest) return util::Error{util::ErrorString(withdraw_dest)};

            amount = outputs.withdrawable_amount;
            destination_address = EncodeDestination(*withdraw_dest);
            recipients.push_back({*withdraw_dest, amount, /*fSubtractFeeFromAmount=*/true});
            comment = std::move(withdrawal_comment);
            completed_withdrawal = true;
        } else if (outputs.unbonding_outputs > 0 && outputs.next_unlock_height > 0) {
            return util::Error{strprintf(_("Error: Staking funds are unbonding and cannot be withdrawn until block %u"), outputs.next_unlock_height)};
        } else {
            return util::Error{_("Error: No spendable bonded or matured unbonding staking funds found for this address")};
        }

        auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
        if (!res) return util::Error{util::ErrorString(res)};
        tx = res->tx;
        fee = res->fee;
    }

    mapValue_t map_value;
    map_value["comment"] = std::move(comment);
    if (auto committed = CommitWalletTransactionOrError(wallet, tx, std::move(map_value), "staking address withdrawal"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumOperatorBondTx result;
    result.txid = tx->GetHash().GetHex();
    result.address = destination_address;
    result.amount = amount;
    result.fee = fee;
    result.unlock_height = unlock_height;
    result.started_unbonding = started_unbonding;
    result.completed_withdrawal = completed_withdrawal;
    return result;
}

util::Result<WalletQuantumOperatorBondTx> FundColdStakeDelegationAddress(
    CWallet& wallet,
    const std::string& address,
    CAmount amount,
    bool allow_goldrush_migration)
{
    if (!MoneyRange(amount) || amount <= 0) {
        return util::Error{_("Error: Delegation funding amount must be positive")};
    }

    CTransactionRef tx;
    CAmount fee{0};
    bool use_goldrush_migration{false};
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};

        CTxDestination dest;
        const auto delegation = DecodeWalletColdStakeDelegationAddress(wallet, address, dest);
        if (!delegation) return util::Error{util::ErrorString(delegation)};
        if (!delegation->has_owner_key) {
            return util::Error{_("Error: Wallet must hold the owner key before funding a cold-stake delegation")};
        }

        CCoinControl coin_control;
        coin_control.m_input_family = CCoinControl::InputFamily::QUANTUM_MIGRATION;
        coin_control.m_exclude_generated_quantum_inputs = true;
        coin_control.m_allow_other_inputs = true;

        const CCoinsViewCache& view = wallet.chain().chainman().ActiveChainstate().CoinsTip();
        const ColdStakeFundingInputs funding = ScanColdStakeFundingInputs(wallet, view);
        if (funding.eligible_inputs == 0) {
            if (funding.goldrush_reward_inputs > 0) {
                use_goldrush_migration = true;
            } else {
                return util::Error{_("Error: No spendable direct quantum outputs are available to fund this cold-stake delegation.")};
            }
        }
        if (!use_goldrush_migration && funding.eligible_amount <= amount) {
            if (funding.goldrush_reward_inputs > 0) {
                use_goldrush_migration = true;
            } else {
                bilingual_str error = strprintf(
                    _("Error: Insufficient direct quantum balance to fund this delegation and its fee. Available direct quantum balance: %s."),
                    FormatMoney(funding.eligible_amount));
                return util::Error{error};
            }
        }
        if (!use_goldrush_migration) {
            auto change_dest = wallet.GetNewQuantumChangeDestination();
            if (!change_dest) return util::Error{util::ErrorString(change_dest)};

            std::vector<CRecipient> recipients{{dest, amount, /*fSubtractFeeFromAmount=*/false}};
            coin_control.destChange = *change_dest;
            int change_pos = RANDOM_CHANGE_POSITION;
            auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
            if (!res) {
                bilingual_str error = strprintf(
                    _("Error: Unable to fund cold-stake delegation from direct quantum outputs. %s"),
                    util::ErrorString(res).original);
                return util::Error{error};
            }
            tx = res->tx;
            fee = res->fee;
        }
    }

    if (use_goldrush_migration) {
        if (!allow_goldrush_migration) {
            return util::Error{_("Error: Funding this cold-stake delegation requires first moving wallet-owned Gold Rush reward outputs to a fresh quantum address. Re-run with allow_goldrush_migration=true, or run migrategoldrushrewards first.")};
        }
        auto migration = CreateGoldRushColdStakeMigration(wallet);
        if (!migration) return util::Error{util::ErrorString(migration)};

        auto delegation = FundColdStakeDelegationAddress(wallet, address, amount, allow_goldrush_migration);
        if (!delegation) {
            return util::Error{strprintf(
                _("Gold Rush rewards were moved to fresh quantum address %s in transaction %s, but the cold-stake delegation was not broadcast yet: %s"),
                migration->address,
                migration->txid,
                util::ErrorString(delegation).original)};
        }
        delegation->created_migration = true;
        delegation->migration_txid = migration->txid;
        delegation->migration_address = migration->address;
        delegation->migration_amount = migration->amount;
        delegation->migration_fee = migration->fee;
        return delegation;
    }

    mapValue_t map_value;
    map_value["comment"] = "Blackcoin quantum cold-stake delegation funding";
    if (auto committed = CommitWalletTransactionOrError(wallet, tx, std::move(map_value), "cold-stake delegation funding"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumOperatorBondTx result;
    result.txid = tx->GetHash().GetHex();
    result.address = address;
    result.amount = amount;
    result.fee = fee;
    return result;
}

util::Result<WalletQuantumOperatorBondTx> WithdrawColdStakeDelegationAddress(
    CWallet& wallet,
    const std::string& address)
{
    CTransactionRef tx;
    CAmount amount{0};
    CAmount fee{0};
    uint32_t unlock_height{0};
    std::string destination_address;
    bool started_unbonding{false};
    bool completed_withdrawal{false};
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};

        CTxDestination dest;
        const auto delegation = DecodeWalletColdStakeDelegationAddress(wallet, address, dest);
        if (!delegation) return util::Error{util::ErrorString(delegation)};
        if (!delegation->has_owner_key) {
            return util::Error{_("Error: Wallet does not hold the owner key for this cold-stake delegation")};
        }

        const ColdStakeDelegationOutputs outputs = ScanColdStakeDelegationOutputs(
            wallet,
            GetScriptForDestination(dest),
            /*spendable_only=*/true);
        if (outputs.spendable_outpoints.empty()) {
            return util::Error{_("Error: No spendable cold-stake delegation funds found for this address")};
        }

        CCoinControl coin_control;
        for (const COutPoint& outpoint : outputs.spendable_outpoints) {
            coin_control.Select(outpoint);
        }
        int change_pos = RANDOM_CHANGE_POSITION;

        amount = outputs.spendable_amount;
        std::vector<CRecipient> recipients;
        const int current_height = wallet.GetLastBlockHeight();
        const int spend_height = current_height + 1;

        if (delegation->tiered && delegation->unlock_height == 0) {
            coin_control.m_allow_other_inputs = false;
            coin_control.m_exclude_generated_quantum_inputs = true;
            const CCoinsViewCache& view = wallet.chain().chainman().ActiveChainstate().CoinsTip();
            const SafeFeeInputSummary fee_inputs = SelectSafeUnbondingFeeInputs(
                wallet,
                view,
                coin_control,
                wallet.m_default_max_tx_fee,
                /*allow_legacy=*/true);
            if (fee_inputs.inputs == 0) {
                return util::Error{_("Error: No safe fee input is available to start cold-stake unbonding. Add a small ordinary legacy or direct quantum UTXO, then try again.")};
            }
            auto change_dest = wallet.GetNewQuantumChangeDestination();
            if (!change_dest) return util::Error{util::ErrorString(change_dest)};
            coin_control.destChange = *change_dest;

            unlock_height = static_cast<uint32_t>(std::max(0, spend_height + int{delegation->unbonding_blocks}));
            auto unbonding_dest = wallet.AddQuantumColdStakeDelegationForKeyHashes(
                delegation->staker_pubkey_hash,
                delegation->owner_pubkey_hash,
                "coldstake-delegation-unbonding",
                GetTime(),
                delegation->unbonding_blocks,
                unlock_height,
                QUANTUM_TIERED_STATE_UNBONDING);
            if (!unbonding_dest) return util::Error{util::ErrorString(unbonding_dest)};

            destination_address = EncodeDestination(*unbonding_dest);
            recipients.push_back({*unbonding_dest, amount, /*fSubtractFeeFromAmount=*/false});
            started_unbonding = true;
        } else {
            if (delegation->tiered && delegation->unlock_height > static_cast<uint32_t>(std::max(0, spend_height))) {
                return util::Error{strprintf(_("Error: Cold-stake delegation funds are unbonding and cannot be withdrawn until block %u"), delegation->unlock_height)};
            }
            coin_control.m_allow_other_inputs = false;
            coin_control.m_input_family = CCoinControl::InputFamily::QUANTUM;

            auto withdraw_dest = wallet.GetNewQuantumDestination("coldstake-delegation-withdrawal");
            if (!withdraw_dest) return util::Error{util::ErrorString(withdraw_dest)};

            destination_address = EncodeDestination(*withdraw_dest);
            recipients.push_back({*withdraw_dest, amount, /*fSubtractFeeFromAmount=*/true});
            completed_withdrawal = true;
        }
        auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
        if (!res) return util::Error{util::ErrorString(res)};
        tx = res->tx;
        fee = res->fee;
    }

    mapValue_t map_value;
    map_value["comment"] = "Blackcoin quantum cold-stake delegation withdrawal";
    if (auto committed = CommitWalletTransactionOrError(wallet, tx, std::move(map_value), "cold-stake delegation withdrawal"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumOperatorBondTx result;
    result.txid = tx->GetHash().GetHex();
    result.address = destination_address;
    result.amount = amount;
    result.fee = fee;
    result.unlock_height = unlock_height;
    result.started_unbonding = started_unbonding;
    result.completed_withdrawal = completed_withdrawal;
    return result;
}

namespace {

std::vector<WalletRGBAssetInfo> ListWalletRGBAssets(CWallet& wallet, bool include_spent)
{
    std::vector<WalletRGBAssetInfo> result;
    TRY_LOCK(wallet.cs_wallet, wallet_lock);
    if (!wallet_lock) return result;

    const auto contracts = wallet.ListRGBContracts();
    const auto assignments = wallet.ListRGBAssignments();
    const auto transitions = wallet.ListRGBTransitions();
    const auto transition_proofs = wallet.ListRGBTransitionProofs();

    result.reserve(contracts.size());
    for (const auto& [contract_id, contract] : contracts) {
        WalletRGBAssetInfo asset;
        asset.contract_id = contract_id.GetHex();
        asset.ticker = contract.ticker;
        asset.name = contract.name;
        asset.total_supply = contract.total_supply;
        asset.creation_time = contract.creation_time;
        asset.proof_available = wallet.GetRGBGenesisProof(contract_id).has_value();

        for (const auto& [key, assignment] : assignments) {
            if (key.first != contract_id) continue;
            if (!assignment.spent) {
                if (assignment.amount > std::numeric_limits<uint64_t>::max() - asset.balance) {
                    asset.balance = std::numeric_limits<uint64_t>::max();
                } else {
                    asset.balance += assignment.amount;
                }
            }
            if (include_spent || !assignment.spent) {
                WalletRGBAssignmentInfo entry;
                entry.txid = key.second.hash.GetHex();
                entry.vout = key.second.n;
                entry.amount = assignment.amount;
                entry.spent = assignment.spent;
                entry.creation_time = assignment.creation_time;
                asset.assignments.push_back(std::move(entry));
            }
        }
        for (const auto& [key, transition] : transitions) {
            if (key.first == contract_id) ++asset.transition_count;
        }
        for (const auto& [key, proof] : transition_proofs) {
            if (key.first == contract_id) ++asset.proof_transition_count;
        }
        result.push_back(std::move(asset));
    }
    return result;
}

std::vector<WalletEUTXOStateInfo> ListWalletEUTXOStates(CWallet& wallet, bool include_spent)
{
    std::vector<std::pair<COutPoint, EUTXOStateRecord>> states;
    {
        TRY_LOCK(wallet.cs_wallet, wallet_lock);
        if (!wallet_lock) return {};
        states = wallet.ListEUTXOStates();
    }

    std::map<COutPoint, Coin> coins;
    for (const auto& [outpoint, record] : states) {
        coins.emplace(outpoint, Coin{});
    }
    TRY_LOCK(::cs_main, main_lock);
    if (!main_lock) return {};
    wallet.chain().findCoins(coins);

    std::vector<WalletEUTXOStateInfo> result;
    for (const auto& [outpoint, record] : states) {
        const auto coin_it = coins.find(outpoint);
        const bool spent = coin_it == coins.end() || coin_it->second.IsSpent();
        if (spent && !include_spent) continue;

        WalletEUTXOStateInfo state;
        state.txid = outpoint.hash.GetHex();
        state.vout = outpoint.n;
        state.amount = record.amount;
        state.datum_hex = HexStr(record.datum);
        state.validator_hex = HexStr(record.validator_script);
        state.address = EncodeDestination(WitnessUnknown{EUTXO_WITNESS_VERSION, EUTXOProgramForDatumAndValidator(record.datum, record.validator_script)});
        state.creation_time = record.creation_time;
        state.spent = spent;
        result.push_back(std::move(state));
    }
    return result;
}

WalletDemurrageInfo GetWalletDemurrageInfo(CWallet& wallet)
{
    WalletDemurrageInfo info;
    if (!wallet.HaveChain()) {
        info.available = false;
        return info;
    }

    TRY_LOCK(::cs_main, main_lock);
    if (!main_lock) {
        info.available = false;
        return info;
    }
    TRY_LOCK(wallet.cs_wallet, wallet_lock);
    if (!wallet_lock) {
        info.available = false;
        return info;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const CBlockIndex* tip = wallet.chain().getTip();
    info.tip_height = tip ? tip->nHeight : -1;
    info.evaluation_height = info.tip_height >= 0 ? info.tip_height + 1 : 0;
    info.evaluation_time = tip ? tip->GetMedianTimePast() : 0;
    info.demurrage_active = consensus.IsDemurrageActive(info.evaluation_height, info.evaluation_time);
    info.demurrage_activation_height = consensus.nDemurrageActivationHeight;
    info.demurrage_effective_activation_height = consensus.EffectiveDemurrageActivationHeight();
    info.demurrage_height_guard_satisfied = info.evaluation_height >= consensus.EffectiveDemurrageActivationHeight();
    info.demurrage_post_migration_guard_satisfied =
        consensus.nQuantumMigrationDeadlineTime != 0 && info.evaluation_time > consensus.nQuantumMigrationDeadlineTime;
    info.wallet_staking_enabled = wallet.m_enabled_staking.load();

    CoinsResult available = AvailableCoinsListUnspent(wallet);
    std::map<COutPoint, Coin> chain_coins;
    std::vector<COutput> quantum_outputs;
    for (const COutput& out : available.All()) {
        if (!IsQuantumMigrationScript(out.txout.scriptPubKey)) continue;
        CTxDestination dest;
        if (!ExtractDestination(out.txout.scriptPubKey, dest) || !wallet.GetQuantumKeyInfo(dest).has_value()) continue;
        chain_coins.emplace(out.outpoint, Coin{});
        quantum_outputs.push_back(out);
    }
    wallet.chain().findCoins(chain_coins);

    const CCoinsViewCache& view = wallet.chain().getCoinsTip();
    info.quantum_outputs = static_cast<int>(quantum_outputs.size());
    info.outputs.reserve(quantum_outputs.size());

    for (const COutput& out : quantum_outputs) {
        CTxDestination dest;
        if (!ExtractDestination(out.txout.scriptPubKey, dest)) continue;

        const auto coin_it = chain_coins.find(out.outpoint);
        const bool chainstate_backed = coin_it != chain_coins.end() && !coin_it->second.IsSpent();
        Coin coin = chainstate_backed
            ? coin_it->second
            : Coin{out.txout, out.depth > 0 ? info.tip_height - out.depth + 1 : info.evaluation_height, false, false, static_cast<int>(out.time)};
        const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, out.txout.scriptPubKey);
        const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(
            coin, consensus, info.evaluation_height, info.evaluation_time, latest_attestation);
        const bool attestation_due = info.demurrage_active &&
                                     !eval.locked &&
                                     eval.inactive_blocks >= consensus.DemurrageAutoAttestBlocks();

        WalletDemurrageOutputInfo output;
        output.txid = out.outpoint.hash.GetHex();
        output.vout = out.outpoint.n;
        output.address = EncodeDestination(dest);
        output.depth = out.depth;
        output.coin_height = coin.nHeight;
        output.latest_attestation_height = latest_attestation;
        output.inactive_blocks = eval.inactive_blocks;
        output.remaining_ppm = eval.remaining_ppm;
        output.nominal_amount = eval.nominal_value;
        output.effective_amount = eval.effective_value;
        output.burned_if_spent_amount = eval.burned_value;
        output.locked = eval.locked;
        output.attestation_due = attestation_due;
        output.blocks_until_decay = std::max(0, consensus.DemurrageGraceBlocks() - eval.inactive_blocks);
        output.blocks_until_lock = std::max(0, consensus.DemurrageZeroBlocks() - eval.inactive_blocks);
        if (!info.demurrage_active) {
            output.action = "none: demurrage is inactive";
        } else if (eval.locked) {
            output.action = "locked: this output can no longer be spent";
        } else if (attestation_due && info.wallet_staking_enabled) {
            output.action = "auto-attest eligible while staking";
        } else if (attestation_due) {
            output.action = "manual attestation recommended";
        } else if (eval.burned_value > 0) {
            output.action = "full-sweep spend recommended";
        } else {
            output.action = "none";
        }

        info.nominal_amount += eval.nominal_value;
        info.effective_amount += eval.effective_value;
        info.burned_if_spent_amount += eval.burned_value;
        if (eval.burned_value > 0) ++info.decaying_outputs;
        if (eval.locked) ++info.locked_outputs;
        if (attestation_due) ++info.attestation_due_outputs;
        info.outputs.push_back(std::move(output));
    }

    return info;
}

} // namespace

util::Result<WalletQuantumActionTx> CreateQuantumMigrationSweep(
    CWallet& wallet,
    bool goldrush_rewards_only,
    bool allow_goldrush_epoch,
    const std::string& destination_label,
    const std::string& comment_override)
{
    const std::string label = !destination_label.empty()
        ? destination_label
        : (goldrush_rewards_only ? "goldrush-remigration-gui" : "migration-gui");
    auto destination_result = wallet.GetNewQuantumDestination(label);
    if (!destination_result) return util::Error{util::ErrorString(destination_result)};
    const CTxDestination destination = *destination_result;
    const CScript destination_script = GetScriptForDestination(destination);
    const std::string destination_address = EncodeDestination(destination);

    CTransactionRef tx;
    CAmount eligible_amount{0};
    CAmount fee{0};
    unsigned int eligible_inputs{0};
    std::string comment;
    {
        LOCK2(::cs_main, wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            return util::Error{_("Error: Private keys are disabled for this wallet")};
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        const CBlockIndex* tip = wallet.chain().getTip();
        const int64_t mtp = tip ? tip->GetMedianTimePast() : 0;
        const int next_height = tip ? tip->nHeight + 1 : 0;
        if (goldrush_rewards_only) {
            const bool can_move_reward_outputs = consensus.IsQuantumMigrationWindow(mtp) ||
                (allow_goldrush_epoch && !consensus.IsQuantumFinalLockout(mtp) &&
                 IsQuantumWitnessSpendActive(consensus, mtp, next_height));
            if (!can_move_reward_outputs) {
                return util::Error{allow_goldrush_epoch
                    ? _("Gold Rush reward migration is only allowed once quantum reward spends are active and before the final quantum lockout deadline.")
                    : _("Gold Rush reward migration is only allowed during the migration window and before the final quantum lockout deadline.")};
            }
        } else if (consensus.IsQuantumFinalLockout(mtp)) {
                return util::Error{_("The migration deadline has passed; legacy coins are no longer spendable and cannot be migrated.")};
        }

        if (!wallet.GetQuantumKeyInfo(destination).has_value()) {
            return util::Error{_("Refusing to migrate: destination ML-DSA key is not confirmed stored in the wallet.")};
        }

        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = false;
        coin_control.m_include_unsafe_inputs = false;
        coin_control.destChange = CNoDestination{};

        CoinFilterParams filter;
        filter.only_spendable = true;
        filter.skip_locked = true;
        filter.include_immature_coinbase = false;

        const CCoinsViewCache& view = wallet.chain().chainman().ActiveChainstate().CoinsTip();
        for (const COutput& out : AvailableCoins(wallet, &coin_control, std::nullopt, filter).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (goldrush_rewards_only) {
                if (!IsQuantumMigrationScript(spk) || spk == destination_script) continue;
                CScript marker_script;
                if (!IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) || marker_script != spk) continue;
            } else {
                if (IsQuantumMigrationScript(spk) || IsQuantumColdStakeScript(spk) || IsEUTXOScript(spk)) continue;
                if (!out.spendable) continue;
            }
            coin_control.Select(out.outpoint);
            eligible_amount += out.txout.nValue;
            ++eligible_inputs;
        }
        if (eligible_inputs == 0) {
            return util::Error{goldrush_rewards_only
                ? _("No wallet-owned Gold Rush reward outputs need migration.")
                : _("No spendable legacy coins to migrate.")};
        }

        std::vector<CRecipient> recipients{{destination, eligible_amount, /*fSubtractFeeFromAmount=*/true}};
        int change_pos = RANDOM_CHANGE_POSITION;
        auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
        if (!res) return util::Error{util::ErrorString(res)};
        tx = res->tx;
        fee = res->fee;
        if (tx->vout.size() != 1 || IsDust(tx->vout[0], wallet.chain().relayDustFee())) {
            return util::Error{goldrush_rewards_only
                ? _("Gold Rush reward migration would strand funds: selected value is below the dust threshold after fees.")
                : _("Migration would strand funds: swept value is below the dust threshold after fees.")};
        }
        comment = !comment_override.empty()
            ? comment_override
            : goldrush_rewards_only
            ? "Blackcoin Gold Rush reward remigration"
            : "Blackcoin quantum migration";
    }

    mapValue_t map_value;
    map_value["comment"] = std::move(comment);
    if (auto committed = CommitWalletTransactionOrError(wallet, tx, std::move(map_value), goldrush_rewards_only ? "Gold Rush reward migration" : "quantum migration"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumActionTx result;
    result.txid = tx->GetHash().GetHex();
    result.address = destination_address;
    result.amount = tx->vout.empty() ? 0 : tx->vout[0].nValue;
    result.fee = fee;
    result.vsize = static_cast<int>(GetVirtualTransactionSize(*tx, 0, 0));
    result.selected_inputs = eligible_inputs;
    result.selected_amount = eligible_amount;
    result.warning = "A new ML-DSA quantum address was created. Back up this wallet before relying on the moved funds.";
    return result;
}

util::Result<WalletQuantumActionTx> CreateGoldRushColdStakeMigration(CWallet& wallet)
{
    return CreateQuantumMigrationSweep(
        wallet,
        /*goldrush_rewards_only=*/true,
        /*allow_goldrush_epoch=*/true,
        "goldrush-coldstake-migration-gui",
        "Blackcoin Gold Rush reward migration before cold-stake delegation");
}

namespace {

util::Result<WalletQuantumActionTx> CreateWalletDemurrageAttestation(CWallet& wallet, const std::string& address)
{
    std::string error_msg;
    const CTxDestination dest = DecodeDestination(address, error_msg);
    if (!IsValidDestination(dest)) {
        return util::Error{Untranslated(error_msg.empty() ? "Invalid address" : error_msg)};
    }
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        return util::Error{_("Address is not a Blackcoin migration address")};
    }

    {
        LOCK(wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};
    }

    CCoinControl coin_control;
    DemurrageAttestationTxResult tx_result;
    bilingual_str error;
    if (!CreateDemurrageAttestationTransaction(wallet, witness->GetWitnessProgram(), coin_control, /*sign=*/true, tx_result, error)) {
        return util::Error{error};
    }

    mapValue_t map_value;
    map_value["comment"] = "Blackcoin demurrage attestation";
    if (auto committed = CommitWalletTransactionOrError(wallet, tx_result.tx, std::move(map_value), "demurrage attestation"); !committed) {
        return util::Error{util::ErrorString(committed)};
    }

    WalletQuantumActionTx result;
    result.txid = tx_result.tx->GetHash().GetHex();
    result.address = EncodeDestination(dest);
    result.fee = tx_result.fee;
    result.vsize = static_cast<int>(GetVirtualTransactionSize(*tx_result.tx, 0, 0));
    return result;
}

//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(InputIsMine(wallet, txin));
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        CTxDestination address;
        ExtractDestination(txout.scriptPubKey, address);
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_is_change.push_back(OutputIsChange(wallet, txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      ISMINE_NO);
    }
    result.credit = CachedTxGetCredit(wallet, wtx, ISMINE_ALL);
    result.debit = CachedTxGetDebit(wallet, wtx, ISMINE_ALL);
    result.change = CachedTxGetChange(wallet, wtx);
    result.time = wtx.GetTxTime();
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    result.is_coinstake = wtx.IsCoinStake();
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height =
        wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height :
        wtx.state<TxStateConflicted>() ? wtx.state<TxStateConflicted>()->conflicting_block_height :
        std::numeric_limits<int>::max();
    result.blocks_to_maturity = wallet.GetTxBlocksToMaturity(wtx);
    result.depth_in_main_chain = wallet.GetTxDepthInMainChain(wtx);
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_trusted = CachedTxIsTrusted(wallet, wtx);
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_coinstake = wtx.IsCoinStake();
    result.is_in_main_chain = wallet.IsTxInMainChain(wtx);
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(COutPoint(wtx.GetHash(), n));
    return result;
}

WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const COutput& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = output.txout;
    result.time = output.time;
    result.depth_in_main_chain = output.depth;
    result.is_spent = wallet.IsSpent(output.outpoint);
    return result;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(WalletContext& context, const std::shared_ptr<CWallet>& wallet) : m_context(context), m_wallet(wallet) {}

    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool hasPrivateKeys() override { return m_wallet->HasPrivateKeys(); }
    bool isCrypted() override { return m_wallet->IsCrypted(); }
    bool lock() override { return m_wallet->Lock(); }
    bool unlock(const SecureString& wallet_passphrase) override { return m_wallet->Unlock(wallet_passphrase); }
    bool isLocked() override { return m_wallet->IsLocked(); }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    std::string getWalletName() override { return m_wallet->GetName(); }
    util::Result<CTxDestination> getNewDestination(const OutputType type, const std::string& label) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewDestination(type, label);
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest) & ISMINE_SPENDABLE;
    }
    bool haveWatchOnly() override
    {
        auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            return spk_man->HaveWatchOnly();
        }
        return false;
    };
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<AddressPurpose>& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        isminetype* is_mine,
        AddressPurpose* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        const auto& entry = m_wallet->FindAddressBookEntry(dest, /*allow_change=*/false);
        if (!entry) return false; // addr not found
        if (name) {
            *name = entry->GetLabel();
        }
        std::optional<isminetype> dest_is_mine;
        if (is_mine || purpose) {
            dest_is_mine = m_wallet->IsMine(dest);
        }
        if (is_mine) {
            *is_mine = *dest_is_mine;
        }
        if (purpose) {
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            *purpose = entry->purpose.value_or(*dest_is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND);
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() const override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        m_wallet->ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet) {
            if (is_change) return;
            isminetype is_mine = m_wallet->IsMine(dest);
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            result.emplace_back(dest, is_mine, purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND), label);
        });
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        // Note: The setAddressReceiveRequest interface used by the GUI to store
        // receive requests is a little awkward and could be improved in the
        // future:
        //
        // - The same method is used to save requests and erase them, but
        //   having separate methods could be clearer and prevent bugs.
        //
        // - Request ids are passed as strings even though they are generated as
        //   integers.
        //
        // - Multiple requests can be stored for the same address, but it might
        //   be better to only allow one request or only keep the current one.
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return value.empty() ? m_wallet->EraseAddressReceiveRequest(batch, dest, id)
                             : m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    bool displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    bool lockCoin(const COutPoint& output, const bool write_to_db) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = write_to_db ? std::make_unique<WalletBatch>(m_wallet->GetDatabase()) : nullptr;
        return m_wallet->LockCoin(output, batch.get());
    }
    bool unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(m_wallet->GetDatabase());
        return m_wallet->UnlockCoin(output, batch.get());
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output);
    }
    void listLockedCoins(std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins(outputs);
    }
    util::Result<CTransactionRef> createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee) override
    {
        LOCK(m_wallet->cs_wallet);
        auto res = CreateTransaction(*m_wallet, recipients, change_pos,
                                     coin_control, sign);
        if (!res) return util::Error{util::ErrorString(res)};
        const auto& txr = *res;
        fee = txr.fee;
        change_pos = txr.change_pos;

        return txr.tx;
    }
    void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const uint256& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool abandonTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    CTransactionRef getTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::set<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::set<WalletTx> result;
        for (const auto& entry : m_wallet->mapWallet) {
            result.emplace(MakeWalletTx(*m_wallet, entry.second));
        }
        return result;
    }
    bool tryGetTxStatus(const uint256& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end()) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed);
    }
    bool finalizePSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& mtx) override
    {
        return m_wallet->FinalizeAndExtractPSBT(psbtx, mtx);
    }
    WalletBalances getBalances() override
    {
        LOCK(m_wallet->cs_wallet);
        const auto bal = GetBalance(*m_wallet);
        WalletBalances result;
        result.balance = bal.m_mine_trusted;
        CCoinControl legacy_control;
        legacy_control.m_input_family = CCoinControl::InputFamily::LEGACY;
        result.legacy_balance = AvailableCoinsListUnspent(*m_wallet, &legacy_control).GetTotalAmount();
        CCoinControl quantum_control;
        quantum_control.m_input_family = CCoinControl::InputFamily::QUANTUM;
        result.quantum_balance = AvailableCoinsListUnspent(*m_wallet, &quantum_control).GetTotalAmount();
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        result.stake = bal.m_mine_stake;
        result.have_watch_only = haveWatchOnly();
        if (result.have_watch_only) {
            result.watch_only_balance = bal.m_watchonly_trusted;
            result.unconfirmed_watch_only_balance = bal.m_watchonly_untrusted_pending;
            result.immature_watch_only_balance = bal.m_watchonly_immature;
            result.watch_only_stake = bal.m_watchonly_stake;
        }
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return GetBalance(*m_wallet).m_mine_trusted; }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        LOCK(m_wallet->cs_wallet);
        CAmount total_amount = 0;
        // Fetch selected coins total amount
        if (coin_control.HasSelected()) {
            FastRandomContext rng{};
            CoinSelectionParams params(rng);
            // Note: for now, swallow any error.
            if (auto res = FetchSelectedInputs(*m_wallet, coin_control, params)) {
                total_amount += res->total_amount;
            }
        }

        // And fetch the wallet available coins
        if (coin_control.m_allow_other_inputs) {
            total_amount += AvailableCoins(*m_wallet, &coin_control).GetTotalAmount();
        }

        return total_amount;
    }
    isminetype txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return InputIsMine(*m_wallet, txin);
    }
    isminetype txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin, filter);
    }
    CAmount getCredit(const CTxOut& txout, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return OutputGetCredit(*m_wallet, txout, filter);
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : ListCoins(*m_wallet)) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(coin.outpoint,
                    MakeWalletTxOut(*m_wallet, coin));
            }
        }
        return result;
    }
    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = m_wallet->GetTxDepthInMainChain(it->second);
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int64_t current_time) override
    {
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, current_time);
        return result;
    }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    bool taprootEnabled() override {
        if (m_wallet->IsLegacy()) return false;
        auto spk_man = m_wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false);
        return spk_man != nullptr;
    }
    OutputType getDefaultAddressType() override { return m_wallet->m_default_address_type; }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_context, m_wallet, /*load_on_start=*/false);
    }
    unsigned int getDonationPercentage() override { return m_wallet->m_donation_percentage; }
    void setDonationPercentage(unsigned int percentage) override
    {
        m_wallet->m_donation_percentage = std::min<unsigned int>(percentage, MAX_DONATION_PERCENTAGE);
    }
    bool tryGetStakeWeight(uint64_t& nWeight) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }

        nWeight = m_wallet->GetStakeWeight();
        return true;
    }
    uint64_t getStakeWeight() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetStakeWeight();
    }
    int64_t getLastCoinStakeSearchInterval() override
    {
        return m_wallet->m_last_coin_stake_search_interval;
    }
    bool getWalletUnlockStakingOnly() override
    {
        return m_wallet->m_wallet_unlock_staking_only;
    }
    void setWalletUnlockStakingOnly(bool unlock) override
    {
        m_wallet->m_wallet_unlock_staking_only = unlock;
    }
    void setEnabledStaking(bool enabled) override
    {
        m_wallet->m_enabled_staking = enabled;
    }
    bool getEnabledStaking() override
    {
        return m_wallet->m_enabled_staking;
    }
    bool setPowMining(bool enabled, int threads, int cpu_percent, std::string& error) override
    {
        bilingual_str werror;
        const bool ok = m_wallet->SetPowMining(enabled, threads, cpu_percent, werror);
        if (!ok) {
            error = werror.original;
            m_wallet->WalletLogPrintf("Gold Rush PoW miner configuration failed: %s\n", werror.original);
        }
        return ok;
    }
    WalletPowMiningInfo getPowMiningInfo() override
    {
        WalletPowMiningInfo info;
        info.enabled = m_wallet->m_pow_mining_enabled;
        info.threads = m_wallet->m_pow_threads;
        info.cpu_percent = m_wallet->m_pow_cpu_percent;
        info.hashrate = m_wallet->m_pow_hashrate;
        info.claims_submitted = m_wallet->m_pow_claims_submitted;
        info.shadow_whitelist_height = SHADOW_WHITELIST_HEIGHT;
        info.shadow_reward_start_height = SHADOW_REWARD_START_HEIGHT;
        info.shadow_reward_end_height = SHADOW_REWARD_END_HEIGHT;
        std::set<CScript> wallet_scripts;
        {
            TRY_LOCK(m_wallet->cs_wallet, wallet_lock);
            if (wallet_lock) {
                info.payout_address = m_wallet->m_pow_payout_quantum;
                CCoinControl coin_control;
                coin_control.m_avoid_address_reuse = false;
                for (const COutput& output : AvailableCoins(*m_wallet, &coin_control).All()) {
                    if (output.txout.nValue > 0 && !output.txout.scriptPubKey.empty() && !output.txout.scriptPubKey.IsUnspendable()) {
                        wallet_scripts.insert(output.txout.scriptPubKey);
                    }
                }
            } else {
                info.payout_address_available = false;
                info.wallet_goldrush_status_available = false;
            }
        }
        if (m_wallet->HaveChain()) {
            ChainstateManager& chainman = m_wallet->chain().chainman();
            TRY_LOCK(::cs_main, main_lock);
            if (!main_lock) return info;
            Chainstate& active = chainman.ActiveChainstate();
            const CBlockIndex* tip = active.m_chain.Tip();
            if (tip) {
                const Consensus::Params& consensus = Params().GetConsensus();
                const int next_height = tip->nHeight + 1;
                info.epoch_active = consensus.IsGoldRushEpoch(tip->GetMedianTimePast()) &&
                                    next_height >= SHADOW_REWARD_START_HEIGHT &&
                                    next_height <= SHADOW_REWARD_END_HEIGHT;
                info.blocks_remaining = info.epoch_active ? std::max(0, SHADOW_REWARD_END_HEIGHT - next_height + 1) : 0;
                const ShadowGoldRushInfo shadow_info = GetShadowGoldRushInfo(active.CoinsTip(), tip);
                info.accrued_jackpot = shadow_info.pow_amount;
                info.next_claim_payout = info.epoch_active ? shadow_info.pow_amount + ShadowBaseReward(next_height) / 2 : shadow_info.pow_amount;
                info.pos_accrued_jackpot = shadow_info.pos_amount;
                const CAmount next_reward = info.epoch_active ? ShadowBaseReward(next_height) : 0;
                const CAmount next_pos_reward = next_reward - next_reward / 2;
                info.pos_next_payout_pool = shadow_info.pos_amount + next_pos_reward;
                const std::map<CScript, CScript> active_signals = GetActiveShadowSignalPayouts(active.CoinsTip(), tip);
                info.pos_active_signalers = static_cast<int>(active_signals.size());
                info.pos_estimated_payout_per_signaler = info.pos_active_signalers > 0
                    ? info.pos_next_payout_pool / info.pos_active_signalers
                    : 0;
                info.pos_claim_count = static_cast<int>(shadow_info.pos_count);
                info.pos_last_payout_height = static_cast<int>(shadow_info.last_pos_height);
                for (const CScript& script : wallet_scripts) {
                    const bool whitelisted = IsWhitelisted(active.CoinsTip(), script);
                    if (!whitelisted) continue;
                    ++info.wallet_whitelisted_scripts;
                    if (active_signals.count(script)) {
                        info.wallet_active_signal = true;
                    }
                    const std::optional<ShadowSolverActivity> activity = GetRecentShadowSolverActivityForScript(active.CoinsTip(), tip, script);
                    if (activity) {
                        info.wallet_recent_solve_qualified = true;
                        info.wallet_blocks_until_solver_expiry = std::max(
                            info.wallet_blocks_until_solver_expiry,
                            std::max(0, SHADOW_SOLVER_ACTIVITY_WINDOW - (tip->nHeight - static_cast<int>(activity->height))));
                    }
                }
            }
        }
        return info;
    }
    util::Result<WalletQuantumAddressInfo> createQuantumAddress(const std::string& label) override
    {
        auto dest = m_wallet->GetNewQuantumDestination(label);
        if (!dest) return util::Error{util::ErrorString(dest)};
        LOCK(m_wallet->cs_wallet);
        const auto info = m_wallet->GetQuantumKeyInfo(*dest);
        if (!info) return util::Error{_("Error: Created quantum address is not wallet-backed")};
        return MakeWalletQuantumAddressInfo(*m_wallet, *info);
    }
    util::Result<WalletQuantumAddressInfo> createQuantumStakeAddress(const std::string& label, uint16_t unbonding_blocks) override
    {
        auto dest = m_wallet->GetNewTieredQuantumDestination(label, unbonding_blocks);
        if (!dest) return util::Error{util::ErrorString(dest)};
        LOCK(m_wallet->cs_wallet);
        const auto info = m_wallet->GetQuantumKeyInfo(*dest);
        if (!info) return util::Error{_("Error: Created quantum staking address is not wallet-backed")};
        return MakeWalletQuantumAddressInfo(*m_wallet, *info);
    }
    std::vector<WalletQuantumAddressInfo> listQuantumAddresses() override
    {
        std::vector<WalletQuantumAddressInfo> result;
        TRY_LOCK(m_wallet->cs_wallet, wallet_lock);
        if (!wallet_lock) return result;
        const auto infos = m_wallet->ListQuantumKeyInfos();
        result.reserve(infos.size());
        for (const QuantumKeyInfo& info : infos) {
            result.push_back(MakeWalletQuantumAddressInfo(*m_wallet, info));
        }
        return result;
    }
    std::vector<WalletQuantumColdStakeInfo> listQuantumColdStakeDelegations() override
    {
        std::vector<WalletQuantumColdStakeInfo> result;
        TRY_LOCK(m_wallet->cs_wallet, wallet_lock);
        if (!wallet_lock) return result;
        const auto infos = m_wallet->ListQuantumColdStakeDelegationInfos();
        result.reserve(infos.size());
        for (const QuantumColdStakeDelegationInfo& info : infos) {
            result.push_back(MakeWalletQuantumColdStakeInfo(*m_wallet, info));
        }
        return result;
    }
    WalletQuantumPoolInfo getQuantumPoolInfo() override
    {
        WalletQuantumPoolInfo result;
        if (!m_wallet->HaveChain()) {
            result.available = false;
            return result;
        }

        const std::vector<LocalOperatorBondCandidate> local_operator_bonds =
            FindWalletOperatorBondCandidates(*m_wallet);
        const std::map<uint256, std::vector<node::QuantumPoolClaim>> local_claims =
            FindWalletQuantumPoolClaims(*m_wallet);

        TRY_LOCK(::cs_main, main_lock);
        if (!main_lock) {
            result.available = false;
            return result;
        }

        ChainstateManager& chainman = m_wallet->chain().chainman();
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        result.total_coldstake = node::ComputeQuantumColdStakeTotal(view);
        result.cap_bps = node::QUANTUM_POOL_CAP_BPS;

        for (const auto& [staker_hash, claims] : local_claims) {
            node::UpsertQuantumPoolClaims(staker_hash, claims);
        }

        for (const LocalOperatorBondCandidate& candidate : local_operator_bonds) {
            if (!node::VerifyQuantumPoolOperatorCommitment(view, candidate.staking_pubkey, candidate.outpoint)) {
                continue;
            }
            const uint256 staker_hash = node::QuantumPoolHashPubKey(candidate.staking_pubkey);
            node::UpsertQuantumPoolOperator(
                staker_hash,
                candidate.staking_pubkey,
                node::GetQuantumPoolClaims(staker_hash),
                /*operator_commitment_verified=*/true,
                candidate.outpoint);
        }

        const std::vector<uint256> operators = node::ListQuantumPoolOperators();
        result.operators.reserve(operators.size());
        for (const uint256& staker_hash : operators) {
            const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));

            WalletQuantumPoolOperatorInfo entry;
            entry.staking_pubkey_hash = share.operator_share.staker_pubkey_hash.GetHex();
            if (!share.operator_share.staker_pubkey.empty()) {
                entry.staking_pubkey = HexStr(share.operator_share.staker_pubkey);
            }
            entry.verified_value = share.operator_share.verified_value;
            entry.share_bps = node::QuantumPoolShareBps(share.operator_share.verified_value, share.total_coldstake);
            entry.verified_claims = share.operator_share.verified_claims;
            entry.invalid_claims = share.operator_share.invalid_claims;
            entry.operator_commitment_verified = share.operator_share.operator_commitment_verified;
            entry.over_cap = node::WouldQuantumPoolExceedCap(share.total_coldstake, share.operator_share.verified_value, 0);
            result.operators.push_back(std::move(entry));
        }
        return result;
    }
    WalletQuantumOperatorBondInfo getQuantumOperatorBondInfo(const std::string& operator_address) override
    {
        return MakeWalletOperatorBondInfo(*m_wallet, operator_address);
    }
    util::Result<WalletQuantumOperatorBondTx> fundQuantumOperatorBond(const std::string& operator_address, CAmount amount) override
    {
        return FundTieredStakeAddress(
            *m_wallet,
            operator_address,
            amount,
            /*require_operator_lock=*/true,
            "Blackcoin cold-stake operator bond");
    }
    util::Result<WalletQuantumOperatorBondTx> withdrawQuantumOperatorBond(const std::string& operator_address) override
    {
        return WithdrawTieredStakeAddress(
            *m_wallet,
            operator_address,
            /*require_operator_lock=*/true,
            "coldstake-operator-unbonding",
            "coldstake-operator-withdrawal",
            "Blackcoin cold-stake operator unbond",
            "Blackcoin cold-stake operator withdrawal");
    }
    WalletQuantumOperatorBondInfo getQuantumStakeAddressBondInfo(const std::string& stake_address) override
    {
        return MakeWalletTieredStakeBondInfo(*m_wallet, stake_address, /*require_operator_lock=*/false);
    }
    std::vector<WalletQuantumStakeOutputInfo> listQuantumStakeOutputs(const std::string& stake_address) override
    {
        return ListTieredStakeOutputs(*m_wallet, stake_address, /*require_operator_lock=*/false);
    }
    util::Result<WalletQuantumOperatorBondTx> fundQuantumStakeAddress(const std::string& stake_address, CAmount amount) override
    {
        return FundTieredStakeAddress(
            *m_wallet,
            stake_address,
            amount,
            /*require_operator_lock=*/false,
            "Blackcoin quantum staking address funding");
    }
    util::Result<WalletQuantumOperatorBondTx> withdrawQuantumStakeAddress(const std::string& stake_address) override
    {
        return WithdrawTieredStakeAddress(
            *m_wallet,
            stake_address,
            /*require_operator_lock=*/false,
            "quantum-stake-unbonding",
            "quantum-stake-withdrawal",
            "Blackcoin quantum staking address unbond",
            "Blackcoin quantum staking address withdrawal");
    }
    util::Result<WalletQuantumOperatorBondTx> withdrawQuantumStakeOutput(const std::string& stake_address, const COutPoint& outpoint) override
    {
        return WithdrawTieredStakeAddress(
            *m_wallet,
            stake_address,
            /*require_operator_lock=*/false,
            "quantum-stake-unbonding",
            "quantum-stake-withdrawal",
            "Blackcoin quantum staking output unbond",
            "Blackcoin quantum staking output withdrawal",
            outpoint);
    }
    util::Result<WalletQuantumColdStakeInfo> createQuantumColdStakeAddress(const std::string& staking_pubkey_hex, const std::string& label, uint16_t unbonding_blocks) override
    {
        if (!IsHex(staking_pubkey_hex)) {
            return util::Error{_("Error: staking public key must be hex")};
        }
        const std::vector<unsigned char> staking_pubkey = ParseHex(staking_pubkey_hex);
        if (staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
            return util::Error{_("Error: staking public key must be exactly 1312 bytes")};
        }

        const std::string owner_label = label.empty() ? "coldstake-owner" : label + " owner";
        auto owner_dest = m_wallet->GetNewQuantumDestination(owner_label);
        if (!owner_dest) return util::Error{util::ErrorString(owner_dest)};

        LOCK(m_wallet->cs_wallet);
        const auto owner_info = m_wallet->GetQuantumKeyInfo(*owner_dest);
        if (!owner_info) return util::Error{_("Error: Created quantum owner address is not wallet-backed")};

        auto qcs_dest = m_wallet->AddQuantumColdStakeDelegation(staking_pubkey, owner_info->public_key, label, GetTime(), /*record_as_receive=*/true, unbonding_blocks, /*tiered=*/unbonding_blocks > 0);
        if (!qcs_dest) return util::Error{util::ErrorString(qcs_dest)};

        const auto qcs_info = m_wallet->GetQuantumColdStakeDelegationInfo(*qcs_dest);
        if (!qcs_info) return util::Error{_("Error: Created quantum cold-stake address is not wallet-backed")};
        return MakeWalletQuantumColdStakeInfo(*m_wallet, *qcs_info);
    }
    WalletQuantumColdStakeBalanceInfo getQuantumColdStakeBalanceInfo(const std::string& coldstake_address) override
    {
        return MakeWalletColdStakeBalanceInfo(*m_wallet, coldstake_address);
    }
    util::Result<WalletQuantumOperatorBondTx> fundQuantumColdStakeAddress(const std::string& coldstake_address, CAmount amount) override
    {
        return FundColdStakeDelegationAddress(*m_wallet, coldstake_address, amount, /*allow_goldrush_migration=*/true);
    }
    util::Result<WalletQuantumOperatorBondTx> withdrawQuantumColdStakeAddress(const std::string& coldstake_address) override
    {
        return WithdrawColdStakeDelegationAddress(*m_wallet, coldstake_address);
    }
    WalletMigrationStatus getMigrationStatus() override
    {
        WalletMigrationStatus status;
        if (!m_wallet->HaveChain()) return status;

        TRY_LOCK(::cs_main, main_lock);
        if (!main_lock) {
            status.available = false;
            return status;
        }
        TRY_LOCK(m_wallet->cs_wallet, wallet_lock);
        if (!wallet_lock) {
            status.available = false;
            return status;
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        ChainstateManager& chainman = m_wallet->chain().chainman();
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        const int64_t mtp = tip ? tip->GetMedianTimePast() : 0;
        const int next_height = tip ? tip->nHeight + 1 : 0;
        const bool scheduled = consensus.nQuantumMigrationDeadlineTime != 0;
        const bool passed = consensus.IsQuantumFinalLockout(mtp);
        const int64_t secs = (scheduled && consensus.nQuantumMigrationDeadlineTime > mtp)
                                 ? consensus.nQuantumMigrationDeadlineTime - mtp : 0;
        const bool quantum_active = IsQuantumWitnessSpendActive(consensus, mtp, next_height);

        status.phase = QuantumQuasarPhaseName(consensus.GetQuantumQuasarPhase(mtp));
        status.median_time = mtp;
        status.deadline_mtp = consensus.nQuantumMigrationDeadlineTime;
        status.deadline_scheduled = scheduled;
        status.seconds_until_deadline = secs;
        status.blocks_until_deadline_est = secs / std::max<int64_t>(1, consensus.nTargetSpacing);
        status.deadline_passed = passed;
        status.goldrush_remigration_active = !passed && quantum_active;
        status.quantum_spends_active = quantum_active;

        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        for (const COutput& out : AvailableCoinsListUnspent(*m_wallet).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (IsQuantumMigrationScript(spk)) {
                CTxDestination dest;
                const bool wallet_owned = ExtractDestination(spk, dest) && m_wallet->GetQuantumKeyInfo(dest).has_value();
                if (wallet_owned) {
                    status.migrated_quantum_amount += out.txout.nValue;
                    ++status.migrated_quantum_outputs;
                }
                CScript marker_script;
                if (IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) && marker_script == spk) {
                    status.goldrush_reward_amount_needing_move += out.txout.nValue;
                    ++status.goldrush_reward_outputs_needing_move;
                } else if (wallet_owned && IsDirectQuantumMigrationScript(spk)) {
                    status.direct_quantum_amount += out.txout.nValue;
                    ++status.direct_quantum_outputs;
                } else if (wallet_owned) {
                    status.staked_quantum_amount += out.txout.nValue;
                    ++status.staked_quantum_outputs;
                }
            } else if (IsQuantumColdStakeScript(spk)) {
                continue;
            } else if (!IsEUTXOScript(spk) && out.spendable) {
                status.eligible_legacy_amount += out.txout.nValue;
                ++status.eligible_legacy_inputs;
            }
        }

        if (passed && status.goldrush_reward_outputs_needing_move > 0) {
            status.advice = "Deadline passed. Remaining Gold Rush reward outputs are permanently unspendable.";
        } else if (passed) {
            status.advice = "Deadline passed. Remaining legacy coins are permanently unspendable.";
        } else if (status.goldrush_reward_outputs_needing_move > 0 && status.goldrush_remigration_active) {
            status.advice = "Move Gold Rush reward outputs to a fresh quantum address before staking, delegation, or final lockout.";
        } else if (status.goldrush_reward_outputs_needing_move > 0) {
            status.advice = "Gold Rush reward outputs become ordinary quantum funds after they are moved to a fresh quantum address.";
        } else if (status.eligible_legacy_inputs == 0) {
            status.advice = "No legacy coins remain to migrate.";
        } else if (!scheduled) {
            status.advice = "No deadline is scheduled yet, but this wallet can create quantum addresses now.";
        } else {
            status.advice = "Move legacy coins into a quantum address before the deadline.";
        }
        return status;
    }
    util::Result<WalletQuantumActionTx> migrateLegacyToQuantum() override
    {
        return CreateQuantumMigrationSweep(*m_wallet, /*goldrush_rewards_only=*/false);
    }
    util::Result<WalletQuantumActionTx> migrateGoldRushRewards() override
    {
        return CreateQuantumMigrationSweep(*m_wallet, /*goldrush_rewards_only=*/true, /*allow_goldrush_epoch=*/true);
    }
    std::vector<WalletRGBAssetInfo> listRGBAssets(bool include_spent = false) override
    {
        return ListWalletRGBAssets(*m_wallet, include_spent);
    }
    std::vector<WalletEUTXOStateInfo> listEUTXOStates(bool include_spent = false) override
    {
        return ListWalletEUTXOStates(*m_wallet, include_spent);
    }
    WalletDemurrageInfo getDemurrageInfo() override
    {
        return GetWalletDemurrageInfo(*m_wallet);
    }
    util::Result<WalletQuantumActionTx> sendDemurrageAttestation(const std::string& address) override
    {
        return CreateWalletDemurrageAttestation(*m_wallet, address);
    }
    bool isLegacy() override { return m_wallet->IsLegacy(); }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeSignalHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 AddressPurpose purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const uint256& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyWatchonlyChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    CWallet* wallet() override { return m_wallet.get(); }

    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
};

class WalletLoaderImpl : public WalletLoader
{
public:
    WalletLoaderImpl(Chain& chain, ArgsManager& args)
    {
        m_context.chain = &chain;
        m_context.args = &args;
    }
    ~WalletLoaderImpl() override { UnloadWallets(m_context); }

    //! ChainClient methods
    void registerRpcs() override
    {
        std::vector<Span<const CRPCCommand>> commands;
        commands.push_back(GetWalletRPCCommands());
        commands.push_back(m_context.chain->getStakingRPCCommands());
        for(size_t i = 0; i < commands.size(); i++) {
            for (const CRPCCommand& command : commands[i]) {
                m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                    JSONRPCRequest& wallet_request = (JSONRPCRequest&)request;
                    wallet_request.context = &m_context;
                    return command.actor(wallet_request, result, last_handler);
                }, command.argNames, command.unique_id);
                m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
            }
        }
    }
    bool verify() override { return VerifyWallets(m_context); }
    bool load() override { return LoadWallets(m_context); }
    void start(CScheduler& scheduler) override { return StartWallets(m_context, scheduler); }
    void flush() override { return FlushWallets(m_context); }
    void stop() override { return StopWallets(m_context); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }

    //! WalletLoader methods
    util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = passphrase;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, CreateWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_existing = true;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, LoadWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseStatus status;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, RestoreWallet(m_context, backup_file, wallet_name, /*load_on_start=*/true, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase) override
    {
        auto res = wallet::MigrateLegacyToDescriptor(name, passphrase, m_context);
        if (!res) return util::Error{util::ErrorString(res)};
        WalletMigrationResult out{
            .wallet = MakeWallet(m_context, res->wallet),
            .watchonly_wallet_name = res->watchonly_wallet ? std::make_optional(res->watchonly_wallet->GetName()) : std::nullopt,
            .solvables_wallet_name = res->solvables_wallet ? std::make_optional(res->solvables_wallet->GetName()) : std::nullopt,
            .backup_path = res->backup_path,
        };
        return {std::move(out)}; // std::move to work around clang bug
    }
    std::string getWalletDir() override
    {
        return fs::PathToString(GetWalletDir());
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListDatabases(GetWalletDir())) {
            paths.push_back(fs::PathToString(path));
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets(m_context)) {
            wallets.emplace_back(MakeWallet(m_context, wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(m_context, std::move(fn));
    }
    WalletContext* context() override  { return &m_context; }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(context, wallet) : nullptr; }

std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args)
{
    return std::make_unique<wallet::WalletLoaderImpl>(chain, args);
}
} // namespace interfaces
