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
#include <consensus/quantum_witness.h>
#include <crypto/mldsa.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <kernel/cs_main.h>
#include <key_io.h>
#include <node/quantum_pool.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/solver.h>
#include <shadow.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/types.h>
#include <wallet/load.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <memory>
#include <optional>
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
using interfaces::WalletQuantumAddressInfo;
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
    result.creation_time = info.creation_time;
    result.has_staker_key = info.has_staker_key;
    result.has_owner_key = info.has_owner_key;
    result.tiered = info.tiered;
    result.unbonding_blocks = info.unbonding_blocks;
    result.unlock_height = info.unlock_height;
    return result;
}

static constexpr uint16_t OPERATOR_COMMITMENT_BLOCKS = 40500;
static constexpr int RANDOM_CHANGE_POSITION = -1;

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

    LOCK(wallet.cs_wallet);
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

    LOCK(wallet.cs_wallet);
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
        LOCK(wallet.cs_wallet);
        bilingual_str spend_error;
        if (!CanCreateSignedSpend(wallet, spend_error)) return util::Error{spend_error};
        if (!wallet.GetQuantumKeyInfo(dest)) {
            return util::Error{_("Error: Staking address is not backed by this wallet")};
        }

        std::vector<CRecipient> recipients{{dest, amount, /*fSubtractFeeFromAmount=*/false}};
        CCoinControl coin_control;
        coin_control.m_input_family = CCoinControl::InputFamily::LEGACY;
        coin_control.m_allow_other_inputs = true;
        int change_pos = RANDOM_CHANGE_POSITION;
        auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/true);
        if (!res) return util::Error{util::ErrorString(res)};
        tx = res->tx;
        fee = res->fee;
    }

    mapValue_t map_value;
    map_value["comment"] = std::move(comment);
    wallet.CommitTransaction(tx, std::move(map_value), {});

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
    std::optional<COutPoint> selected_outpoint = std::nullopt)
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
        LOCK(wallet.cs_wallet);
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
            coin_control.m_allow_other_inputs = true;

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
    wallet.CommitTransaction(tx, std::move(map_value), {});

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
        {
            TRY_LOCK(m_wallet->cs_wallet, wallet_lock);
            if (wallet_lock) {
                info.payout_address = m_wallet->m_pow_payout_quantum;
            } else {
                info.payout_address_available = false;
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
                info.pos_active_signalers = static_cast<int>(GetActiveShadowSignalCount(active.CoinsTip(), tip));
                info.pos_estimated_payout_per_signaler = info.pos_active_signalers > 0
                    ? info.pos_next_payout_pool / info.pos_active_signalers
                    : 0;
                info.pos_claim_count = static_cast<int>(shadow_info.pos_count);
                info.pos_last_payout_height = static_cast<int>(shadow_info.last_pos_height);
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

        TRY_LOCK(::cs_main, main_lock);
        if (!main_lock) {
            result.available = false;
            return result;
        }

        ChainstateManager& chainman = m_wallet->chain().chainman();
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        result.total_coldstake = node::ComputeQuantumColdStakeTotal(view);
        result.cap_bps = node::QUANTUM_POOL_CAP_BPS;

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
        status.goldrush_remigration_active = consensus.IsQuantumMigrationWindow(mtp);
        status.quantum_spends_active = quantum_active;

        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        for (const COutput& out : AvailableCoinsListUnspent(*m_wallet).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (IsQuantumMigrationScript(spk)) {
                CTxDestination dest;
                if (ExtractDestination(spk, dest) && m_wallet->GetQuantumKeyInfo(dest).has_value()) {
                    status.migrated_quantum_amount += out.txout.nValue;
                    ++status.migrated_quantum_outputs;
                }
                CScript marker_script;
                if (IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) && marker_script == spk) {
                    status.goldrush_reward_amount_needing_move += out.txout.nValue;
                    ++status.goldrush_reward_outputs_needing_move;
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
        } else if (status.goldrush_reward_outputs_needing_move > 0 && consensus.IsQuantumMigrationWindow(mtp)) {
            status.advice = "Move Gold Rush reward outputs to a fresh quantum address before the deadline.";
        } else if (status.goldrush_reward_outputs_needing_move > 0) {
            status.advice = "Gold Rush reward outputs can be moved after Gold Rush ends and before the deadline.";
        } else if (status.eligible_legacy_inputs == 0) {
            status.advice = "No legacy coins remain to migrate.";
        } else if (!scheduled) {
            status.advice = "No deadline is scheduled yet, but this wallet can create quantum addresses now.";
        } else {
            status.advice = "Move legacy coins into a quantum address before the deadline.";
        }
        return status;
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
