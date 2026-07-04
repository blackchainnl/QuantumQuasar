// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif
#include <addresstype.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <common/settings.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <external_signer.h>
#include <hash.h>
#include <index/disktxpos.h>
#include <index/txindex.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <kernel/chain.h>
#include <kernel/mempool_removal_reason.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <random.h>
#include <rgb/engine.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <shadow.h>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/allocators/zeroafterfree.h>
#include <support/cleanse.h>
#include <sync.h>
#include <timedata.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/error.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/message.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/fees.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/staking.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <variant>

struct KeyOriginInfo;

using interfaces::FoundBlock;

namespace wallet {

static std::vector<unsigned char> QuantumWalletProgramForPubkey(const std::vector<unsigned char>& public_key)
{
    std::vector<unsigned char> program(QUANTUM_MIGRATION_PROGRAM_SIZE);
    CSHA256().Write(public_key.data(), public_key.size()).Finalize(program.data());
    return program;
}

static std::vector<unsigned char> VectorForUint256(const uint256& value)
{
    return {value.begin(), value.end()};
}

static uint256 Uint256FromVector(const std::vector<unsigned char>& value)
{
    uint256 out;
    if (value.size() == uint256::size()) {
        std::copy(value.begin(), value.end(), out.begin());
    }
    return out;
}

static bool IsQuantumProtectedScript(const CScript& script_pubkey)
{
    return IsQuantumMigrationScript(script_pubkey) || IsQuantumColdStakeScript(script_pubkey);
}

static bool IsValidRGBProofAssignment(const RGBProofAssignment& assignment)
{
    return !assignment.outpoint.IsNull() && assignment.amount > 0;
}

static bool IsValidRGBContractRecord(const RGBContractRecord& record)
{
    return !record.ticker.empty() &&
           record.ticker.size() <= MAX_RGB_WALLET_TICKER_CHARS &&
           record.name.size() <= MAX_RGB_WALLET_NAME_CHARS &&
           record.total_supply > 0;
}

static bool IsBoundedRGBProofAssignments(const std::vector<RGBProofAssignment>& assignments)
{
    return !assignments.empty() &&
           assignments.size() <= MAX_RGB_WALLET_RECORD_VECTOR_ENTRIES &&
           std::all_of(assignments.begin(), assignments.end(), IsValidRGBProofAssignment);
}

static bool IsBoundedRGBOutPoints(const std::vector<COutPoint>& outpoints)
{
    return !outpoints.empty() &&
           outpoints.size() <= MAX_RGB_WALLET_RECORD_VECTOR_ENTRIES &&
           std::all_of(outpoints.begin(), outpoints.end(), [](const COutPoint& outpoint) {
               return !outpoint.IsNull();
           });
}

static bool IsValidRGBGenesisProofRecord(const RGBGenesisProofRecord& record)
{
    return IsBoundedRGBProofAssignments(record.allocations);
}

static bool IsValidRGBTransitionRecord(const RGBTransitionRecord& record)
{
    return !record.anchor_commitment.IsNull() &&
           IsBoundedRGBOutPoints(record.inputs) &&
           IsBoundedRGBOutPoints(record.outputs);
}

static bool IsValidRGBTransitionProofRecord(const RGBTransitionProofRecord& record)
{
    return IsBoundedRGBOutPoints(record.inputs) &&
           IsBoundedRGBProofAssignments(record.outputs);
}

static bool IsRGBAnchorProvenInChainOrMempool(interfaces::Chain& chain, const uint256& txid)
{
    if (txid.IsNull()) return false;
    if (chain.isInMempool(txid)) return true;

    node::NodeContext* node = chain.context();
    if (!node || !node->chainman) return false;

    uint256 block_hash;
    const CTransactionRef tx = node::GetTransaction(/*block_index=*/nullptr, /*mempool=*/nullptr, txid, block_hash, node->chainman->m_blockman);
    if (!tx || block_hash.IsNull()) return false;

    bool active{false};
    return chain.findBlock(block_hash, FoundBlock().inActiveChain(active)) && active;
}

static bool IsQuantumProtectedSpendAllowedOutput(const CTransaction& tx, unsigned int output_index)
{
    const CTxOut& txout = tx.vout[output_index];
    if (tx.IsCoinStake() && output_index == 0 && txout.IsEmpty()) return true;
    if (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == OP_RETURN) return true;
    return IsQuantumProtectedScript(txout.scriptPubKey) || IsEUTXOScript(txout.scriptPubKey);
}

static std::vector<ShadowSyntheticPayoutTransaction> GetWalletShadowPayoutTransactions(CWallet& wallet, const interfaces::BlockInfo& block)
{
    AssertLockNotHeld(wallet.cs_wallet);
    if (!block.data) return {};
    LOCK(cs_main);
    return GetAppliedShadowClaimPayoutTransactionRecords(
        wallet.chain().getCoinsTip(),
        block.height,
        block.hash,
        block.data->GetBlockTime());
}

static void AnnotateWalletShadowPayout(CWallet& wallet, const ShadowSyntheticPayoutTransaction& payout, WalletBatch& batch)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!payout.tx) return;

    const uint256 txid = payout.tx->GetHash();
    auto it = wallet.mapWallet.find(txid);
    if (it == wallet.mapWallet.end()) return;

    CWalletTx& wtx = it->second;
    CTxDestination dest;
    const std::string address = ExtractDestination(payout.target, dest) ? EncodeDestination(dest) : "";
    const std::string comment = payout.proof_of_work ? "PoW - Quantum Claim" : "PoS - Quantum Stake";

    bool changed{false};
    auto set_value = [&](const std::string& key, const std::string& value) {
        auto current = wtx.mapValue.find(key);
        if (current == wtx.mapValue.end() || current->second != value) {
            wtx.mapValue[key] = value;
            changed = true;
        }
    };

    set_value("comment", comment);
    if (!address.empty()) set_value("to", address);

    if (changed) {
        batch.WriteTx(wtx);
        wtx.MarkDirty();
        wallet.NotifyTransactionChanged(txid, CT_UPDATED);
    }
}

static bool IsValidQuantumColdStakeSelector(const std::vector<unsigned char>& selector)
{
    return selector.empty() || (selector.size() == 1 && selector[0] == 1);
}

static bool IsQuantumColdStakeStakerBranch(const std::vector<unsigned char>& selector)
{
    return selector.size() == 1 && selector[0] == 1;
}

static uint256 QuantumWalletKeyIV(const std::vector<unsigned char>& witness_program)
{
    uint256 iv;
    if (witness_program.size() == uint256::size()) {
        std::copy(witness_program.begin(), witness_program.end(), iv.begin());
    }
    return iv;
}

static std::vector<unsigned char> QuantumWalletKeyLookupProgram(const std::vector<unsigned char>& witness_program)
{
    QuantumStakeTierProgram tier;
    if (DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, witness_program, tier) && tier.tiered) {
        return {tier.commitment.begin(), tier.commitment.end()};
    }
    return witness_program;
}

template <typename Byte>
static void CleanseVector(std::vector<Byte>& bytes)
{
    if (!bytes.empty()) {
        memory_cleanse(bytes.data(), bytes.size() * sizeof(Byte));
        bytes.clear();
    }
}

static bool VerifyFinalizedPSBTInput(const PartiallySignedTransaction& psbtx, unsigned int input_index, const PrecomputedTransactionData& txdata, unsigned int verify_flags, ScriptError* serror)
{
    if (input_index >= psbtx.inputs.size() || input_index >= psbtx.tx->vin.size()) return false;

    CTxOut utxo;
    if (!psbtx.GetInputUTXO(utxo, input_index)) return false;

    const PSBTInput& input = psbtx.inputs[input_index];
    return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, verify_flags,
                        MutableTransactionSignatureChecker(&(*psbtx.tx), input_index, utxo.nValue, txdata, MissingDataBehavior::FAIL), serror);
}

static bool QuantumWalletPrivateKeyMatches(const std::vector<unsigned char>& public_key, const CKeyingMaterial& private_key)
{
    if (public_key.size() != ML_DSA::PUBLICKEY_BYTES || private_key.size() != ML_DSA::SECRETKEY_BYTES) {
        return false;
    }

    HashWriter challenge_writer{};
    challenge_writer << std::string("Quantum Quasar wallet ML-DSA key check v1");
    challenge_writer << public_key;
    const uint256 challenge = challenge_writer.GetHash();

    std::vector<uint8_t> private_key_bytes(private_key.begin(), private_key.end());
    std::vector<uint8_t> signature;
    if (!ML_DSA::Sign(private_key_bytes, challenge.begin(), uint256::size(), signature)) {
        CleanseVector(private_key_bytes);
        return false;
    }
    CleanseVector(private_key_bytes);
    std::vector<uint8_t> public_key_bytes(public_key.begin(), public_key.end());
    return ML_DSA::Verify(public_key_bytes, challenge.begin(), uint256::size(), signature);
}

bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    common::SettingsValue setting_value = chain.getRwSetting("wallet");
    if (!setting_value.isArray()) setting_value.setArray();
    for (const common::SettingsValue& value : setting_value.getValues()) {
        if (value.isStr() && value.get_str() == wallet_name) return true;
    }
    setting_value.push_back(wallet_name);
    return chain.updateRwSetting("wallet", setting_value);
}

bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    common::SettingsValue setting_value = chain.getRwSetting("wallet");
    if (!setting_value.isArray()) return true;
    common::SettingsValue new_value(common::SettingsValue::VARR);
    for (const common::SettingsValue& value : setting_value.getValues()) {
        if (!value.isStr() || value.get_str() != wallet_name) new_value.push_back(value);
    }
    if (new_value.size() == setting_value.size()) return true;
    return chain.updateRwSetting("wallet", new_value);
}

static void UpdateWalletSetting(interfaces::Chain& chain,
                                const std::string& wallet_name,
                                std::optional<bool> load_on_startup,
                                std::vector<bilingual_str>& warnings)
{
    if (!load_on_startup) return;
    if (load_on_startup.value() && !AddWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
    } else if (!load_on_startup.value() && !RemoveWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
    }
}

/**
 * Refresh mempool status so the wallet is in an internally consistent state and
 * immediately knows the transaction's status: Whether it can be considered
 * trusted and is eligible to be abandoned ...
 */
static void RefreshMempoolStatus(CWalletTx& tx, interfaces::Chain& chain)
{
    if (chain.isInMempool(tx.GetHash())) {
        tx.m_state = TxStateInMempool();
    } else if (tx.state<TxStateInMempool>()) {
        tx.m_state = TxStateInactive();
    }
}

bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::const_iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i != context.wallets.end()) return false;
    context.wallets.push_back(wallet);
    wallet->ConnectScriptPubKeyManNotifiers();
    wallet->NotifyCanGetAddressesChanged();
    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start, std::vector<bilingual_str>& warnings)
{
    assert(wallet);

    interfaces::Chain& chain = wallet->chain();
    std::string name = wallet->GetName();

    // Unregister with the validation interface which also drops shared pointers.
    wallet->m_chain_notifications_handler.reset();
    LOCK(context.wallets_mutex);
    std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i == context.wallets.end()) return false;
    context.wallets.erase(i);

    // Write the wallet setting
    UpdateWalletSetting(chain, name, load_on_start, warnings);

    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start)
{
    std::vector<bilingual_str> warnings;
    return RemoveWallet(context, wallet, load_on_start, warnings);
}

std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context)
{
    LOCK(context.wallets_mutex);
    return context.wallets;
}

std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count)
{
    LOCK(context.wallets_mutex);
    count = context.wallets.size();
    return count == 1 ? context.wallets[0] : nullptr;
}

std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name)
{
    LOCK(context.wallets_mutex);
    for (const std::shared_ptr<CWallet>& wallet : context.wallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

std::unique_ptr<interfaces::Handler> HandleLoadWallet(WalletContext& context, LoadWalletFn load_wallet)
{
    LOCK(context.wallets_mutex);
    auto it = context.wallet_load_fns.emplace(context.wallet_load_fns.end(), std::move(load_wallet));
    return interfaces::MakeCleanupHandler([&context, it] { LOCK(context.wallets_mutex); context.wallet_load_fns.erase(it); });
}

void NotifyWalletLoaded(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    for (auto& load_wallet : context.wallet_load_fns) {
        load_wallet(interfaces::MakeWallet(context, wallet));
    }
}

static GlobalMutex g_loading_wallet_mutex;
static GlobalMutex g_wallet_release_mutex;
static std::condition_variable g_wallet_release_cv;
static std::set<std::string> g_loading_wallet_set GUARDED_BY(g_loading_wallet_mutex);
static std::set<std::string> g_unloading_wallet_set GUARDED_BY(g_wallet_release_mutex);

// Custom deleter for shared_ptr<CWallet>.
static void ReleaseWallet(CWallet* wallet)
{
    const std::string name = wallet->GetName();
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Flush();
    delete wallet;
    // Wallet is now released, notify UnloadWallet, if any.
    {
        LOCK(g_wallet_release_mutex);
        if (g_unloading_wallet_set.erase(name) == 0) {
            // UnloadWallet was not called for this wallet, all done.
            return;
        }
    }
    g_wallet_release_cv.notify_all();
}

void UnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Mark wallet for unloading.
    const std::string name = wallet->GetName();
    {
        LOCK(g_wallet_release_mutex);
        auto it = g_unloading_wallet_set.insert(name);
        assert(it.second);
    }
    // The wallet can be in use so it's not possible to explicitly unload here.
    // Notify the unload intent so that all remaining shared pointers are
    // released.
    wallet->NotifyUnload();

    // Time to ditch our shared_ptr and wait for ReleaseWallet call.
    wallet.reset();
    {
        WAIT_LOCK(g_wallet_release_mutex, lock);
        while (g_unloading_wallet_set.count(name) == 1) {
            g_wallet_release_cv.wait(lock);
        }
    }
}

namespace {
std::shared_ptr<CWallet> LoadWalletInternal(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    try {
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
        if (!database) {
            error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
            return nullptr;
        }

        context.chain->initMessage(_("Loading wallet…").translated);
        std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), options.create_flags, error, warnings);
        if (!wallet) {
            error = Untranslated("Wallet loading failed.") + Untranslated(" ") + error;
            status = DatabaseStatus::FAILED_LOAD;
            return nullptr;
        }

        // Legacy wallets are being deprecated, warn if the loaded wallet is legacy
        if (!wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            warnings.push_back(_("Wallet loaded successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future. Legacy wallets can be migrated to a descriptor wallet with migratewallet."));
        }

        NotifyWalletLoaded(context, wallet);
        AddWallet(context, wallet);
        wallet->postInitProcess();

        // Write the wallet setting
        UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

        return wallet;
    } catch (const std::runtime_error& e) {
        error = Untranslated(e.what());
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
}

class FastWalletRescanFilter
{
public:
    FastWalletRescanFilter(const CWallet& wallet) : m_wallet(wallet)
    {
        // fast rescanning via block filters is only supported by descriptor wallets right now
        assert(!m_wallet.IsLegacy());

        // create initial filter with scripts from all ScriptPubKeyMans
        for (auto spkm : m_wallet.GetAllScriptPubKeyMans()) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
            assert(desc_spkm != nullptr);
            AddScriptPubKeys(desc_spkm);
            // save each range descriptor's end for possible future filter updates
            if (desc_spkm->IsHDEnabled()) {
                m_last_range_ends.emplace(desc_spkm->GetID(), desc_spkm->GetEndRange());
            }
        }
    }

    void UpdateIfNeeded()
    {
        // repopulate filter with new scripts if top-up has happened since last iteration
        for (const auto& [desc_spkm_id, last_range_end] : m_last_range_ends) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(desc_spkm_id))};
            assert(desc_spkm != nullptr);
            int32_t current_range_end{desc_spkm->GetEndRange()};
            if (current_range_end > last_range_end) {
                AddScriptPubKeys(desc_spkm, last_range_end);
                m_last_range_ends.at(desc_spkm->GetID()) = current_range_end;
            }
        }
    }

    std::optional<bool> MatchesBlock(const uint256& block_hash) const
    {
        return m_wallet.chain().blockFilterMatchesAny(BlockFilterType::BASIC, block_hash, m_filter_set);
    }

private:
    const CWallet& m_wallet;
    /** Map for keeping track of each range descriptor's last seen end range.
      * This information is used to detect whether new addresses were derived
      * (that is, if the current end range is larger than the saved end range)
      * after processing a block and hence a filter set update is needed to
      * take possible keypool top-ups into account.
      */
    std::map<uint256, int32_t> m_last_range_ends;
    GCSFilter::ElementSet m_filter_set;

    void AddScriptPubKeys(const DescriptorScriptPubKeyMan* desc_spkm, int32_t last_range_end = 0)
    {
        for (const auto& script_pub_key : desc_spkm->GetScriptPubKeys(last_range_end)) {
            m_filter_set.emplace(script_pub_key.begin(), script_pub_key.end());
        }
    }
};
} // namespace

std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    auto result = WITH_LOCK(g_loading_wallet_mutex, return g_loading_wallet_set.insert(name));
    if (!result.second) {
        error = Untranslated("Wallet already loading.");
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
    auto wallet = LoadWalletInternal(context, name, load_on_start, options, status, error, warnings);
    WITH_LOCK(g_loading_wallet_mutex, g_loading_wallet_set.erase(result.first));
    return wallet;
}

std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    uint64_t wallet_creation_flags = options.create_flags;
    const SecureString& passphrase = options.create_passphrase;

    if (wallet_creation_flags & WALLET_FLAG_DESCRIPTORS) options.require_format = DatabaseFormat::SQLITE;

    // Indicate that the wallet is actually supposed to be blank and not just blank to make it encrypted
    bool create_blank = (wallet_creation_flags & WALLET_FLAG_BLANK_WALLET);

    // Born encrypted wallets need to be created blank first.
    if (!passphrase.empty()) {
        wallet_creation_flags |= WALLET_FLAG_BLANK_WALLET;
    }

    // Private keys must be disabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Private keys must be disabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Descriptor support must be enabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        error = Untranslated("Descriptor support must be enabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Do not allow a passphrase when private keys are disabled
    if (!passphrase.empty() && (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Wallet::Verify will check if we're trying to create a wallet with a duplicate name.
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
    if (!database) {
        error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_VERIFY;
        return nullptr;
    }

    // Make the wallet
    context.chain->initMessage(_("Loading wallet…").translated);
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), wallet_creation_flags, error, warnings);
    if (!wallet) {
        error = Untranslated("Wallet creation failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Encrypt the wallet
    if (!passphrase.empty() && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        if (!wallet->EncryptWallet(passphrase)) {
            error = Untranslated("Error: Wallet created but failed to encrypt.");
            status = DatabaseStatus::FAILED_ENCRYPT;
            return nullptr;
        }
        if (!create_blank) {
            // Unlock the wallet
            if (!wallet->Unlock(passphrase)) {
                error = Untranslated("Error: Wallet was encrypted but could not be unlocked");
                status = DatabaseStatus::FAILED_ENCRYPT;
                return nullptr;
            }

            // Set a seed for the wallet
            {
                LOCK(wallet->cs_wallet);
                if (wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                    wallet->SetupDescriptorScriptPubKeyMans();
                } else {
                    for (auto spk_man : wallet->GetActiveScriptPubKeyMans()) {
                        if (!spk_man->SetupGeneration()) {
                            error = Untranslated("Unable to generate initial keys");
                            status = DatabaseStatus::FAILED_CREATE;
                            return nullptr;
                        }
                    }
                }
            }

            // Relock the wallet
            wallet->Lock();
        }
    }

    NotifyWalletLoaded(context, wallet);
    AddWallet(context, wallet);
    wallet->postInitProcess();

    // Write the wallet settings
    UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

    // Legacy wallets are being deprecated, warn if a newly created wallet is legacy
    if (!(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        warnings.push_back(_("Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."));
    }

    status = DatabaseStatus::SUCCESS;
    return wallet;
}

std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    DatabaseOptions options;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;

    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::u8path(wallet_name));
    auto wallet_file = wallet_path / "wallet.dat";
    std::shared_ptr<CWallet> wallet;
    bool wallet_file_copied = false;
    bool created_parent_dir = false;

    try {
        if (!fs::exists(backup_file)) {
            error = Untranslated("Backup file does not exist");
            status = DatabaseStatus::FAILED_INVALID_BACKUP_FILE;
            return nullptr;
        }

        // Wallet directories are allowed to exist, but must not contain a .dat file.
        // Any existing wallet database is treated as a hard failure to prevent overwriting.
        if (fs::exists(wallet_path)) {
            // If this is a file, it is the db and we don't want to overwrite it.
            if (!fs::is_directory(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }

            // Check we are not going to overwrite an existing db file
            if (fs::exists(wallet_file)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists in '%s'.", fs::PathToString(wallet_file)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
        } else {
            // The directory doesn't exist, create it
            if (!TryCreateDirectories(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore database path '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
            created_parent_dir = true;
        }

        fs::copy_file(backup_file, wallet_file, fs::copy_options::none);
        wallet_file_copied = true;

        wallet = LoadWallet(context, wallet_name, load_on_start, options, status, error, warnings);
    } catch (const std::exception& e) {
        assert(!wallet);
        if (!error.empty()) error += Untranslated("\n");
        error += strprintf(Untranslated("Unexpected exception: %s"), e.what());
    }
    if (!wallet) {
        if (wallet_file_copied) fs::remove(wallet_file);
        // Clean up the parent directory if we created it during restoration.
        // As we have created it, it must be empty after deleting the wallet file.
        if (created_parent_dir) {
            Assume(fs::is_empty(wallet_path));
            fs::remove(wallet_path);
        }
    }

    return wallet;
}

/** @defgroup mapWallet
 *
 * @{
 */

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    AssertLockHeld(cs_wallet);
    const auto it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

void CWallet::UpgradeKeyMetadata()
{
    if (IsLocked() || IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
        return;
    }

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return;
    }

    spk_man->UpgradeKeyMetadata();
    SetWalletFlag(WALLET_FLAG_KEY_ORIGIN_METADATA);
}

void CWallet::UpgradeDescriptorCache()
{
    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) || IsLocked() || IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    for (ScriptPubKeyMan* spkm : GetAllScriptPubKeyMans()) {
        DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        desc_spkm->UpgradeDescriptorCache();
    }
    SetWalletFlag(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase, bool accept_no_keys)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (Unlock(_vMasterKey, accept_no_keys)) {
                // Now that we've unlocked, upgrade the key metadata
                UpgradeKeyMetadata();
                // Now that we've unlocked, upgrade the descriptor cache
                UpgradeDescriptorCache();
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK2(m_relock_mutex, cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (Unlock(_vMasterKey))
            {
                constexpr MillisecondsDouble target{100};
                auto start{SteadyClock::now()};
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * target / (SteadyClock::now() - start));

                start = SteadyClock::now();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * target / (SteadyClock::now() - start))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                WalletLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                WalletBatch(GetDatabase()).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::chainStateFlushed(ChainstateRole role, const CBlockLocator& loc)
{
    // Don't update the best block until the chain is attached so that in case of a shutdown,
    // the rescan will be restarted at next startup.
    if (m_attaching_chain || role == ChainstateRole::BACKGROUND) {
        return;
    }
    WalletBatch batch(GetDatabase());
    batch.WriteBestBlock(loc);
}

void CWallet::SetMinVersion(enum WalletFeature nVersion, WalletBatch* batch_in)
{
    LOCK(cs_wallet);
    if (nWalletVersion >= nVersion)
        return;
    WalletLogPrintf("Setting minversion to %d\n", nVersion);
    nWalletVersion = nVersion;

    {
        WalletBatch* batch = batch_in ? batch_in : new WalletBatch(GetDatabase());
        if (nWalletVersion > 40000)
            batch->WriteMinVersion(nWalletVersion);
        if (!batch_in)
            delete batch;
    }
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    const auto it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const CTransactionRef& tx) const
{
    AssertLockHeld(cs_wallet);
    const uint256& txid = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); ++i) {
        if (IsSpent(COutPoint(txid, i))) {
            return true;
        }
    }
    return false;
}

void CWallet::Flush()
{
    GetDatabase().Flush();
}

void CWallet::Close()
{
    GetDatabase().Close();
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet.at(it->second);
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;
            copyFrom = wtx;
        }
    }

    if (!copyFrom) {
        return;
    }

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet.at(hash);
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const COutPoint& outpoint) const
{
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256& wtxid = it->second;
        const auto mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = GetTxDepthInMainChain(mit->second);
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid, WalletBatch* batch)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    if (batch) {
        UnlockCoin(outpoint, batch);
    } else {
        WalletBatch temp_batch(GetDatabase());
        UnlockCoin(outpoint, &temp_batch);
    }

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}

void CWallet::AddToSpends(const CWalletTx& wtx, WalletBatch* batch)
{
    if (wtx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : wtx.tx->vin)
        AddToSpends(txin.prevout, wtx.GetHash(), batch);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(_vMasterKey);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(kMasterKey.vchSalt);

    CCrypter crypter;
    constexpr MillisecondsDouble target{100};
    auto start{SteadyClock::now()};
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = static_cast<unsigned int>(25000 * target / (SteadyClock::now() - start));

    start = SteadyClock::now();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + static_cast<unsigned int>(kMasterKey.nDeriveIterations * target / (SteadyClock::now() - start))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    WalletLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        WalletBatch* encrypted_batch = new WalletBatch(GetDatabase());
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        for (const auto& spk_man_pair : m_spk_managers) {
            auto spk_man = spk_man_pair.second.get();
            if (!spk_man->Encrypt(_vMasterKey, encrypted_batch)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                // We now probably have half of our keys encrypted in memory, and half not...
                // die and let the user reload the unencrypted wallet.
                assert(false);
            }
        }

        if (!EncryptQuantumKeys(_vMasterKey, *encrypted_batch)) {
            encrypted_batch->TxnAbort();
            delete encrypted_batch;
            encrypted_batch = nullptr;
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, encrypted_batch);

        if (!encrypted_batch->TxnCommit()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete encrypted_batch;
        encrypted_batch = nullptr;

        Lock();
        Unlock(strWalletPassphrase);

        // If we are using descriptors, make new descriptors with a new seed
        if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) && !IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
            SetupDescriptorScriptPubKeyMans();
        } else if (auto spk_man = GetLegacyScriptPubKeyMan()) {
            // if we are using HD, replace the HD seed with a new one
            if (spk_man->IsHDEnabled()) {
                if (!spk_man->SetupGeneration(true)) {
                    return false;
                }
            }
        }
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        GetDatabase().Rewrite();

        // BDB seems to have a bad habit of writing old data into
        // slack space in .dat files; that is bad if the old data is
        // unencrypted private keys. So:
        GetDatabase().ReloadDbEnv();

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx into a sorted-by-time multimap.
    typedef std::multimap<int64_t, CWalletTx*> TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, wtx));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second;
        int64_t& nOrderPos = pwtx->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
    }
    batch.WriteOrderPosNext(nOrderPosNext);

    return DBErrors::LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    int64_t nRet = nOrderPosNext++;
    if (batch) {
        batch->WriteOrderPosNext(nOrderPosNext);
    } else {
        WalletBatch(GetDatabase()).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx>& item : mapWallet)
            item.second.MarkDirty();
    }
}

void CWallet::SetSpentKeyState(WalletBatch& batch, const uint256& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    AssertLockHeld(cs_wallet);
    const CWalletTx* srctx = GetWalletTx(hash);
    if (!srctx) return;

    CTxDestination dst;
    if (ExtractDestination(srctx->tx->vout[n].scriptPubKey, dst)) {
        if (IsMine(dst)) {
            if (used != IsAddressPreviouslySpent(dst)) {
                if (used) {
                    tx_destinations.insert(dst);
                }
                SetAddressPreviouslySpent(batch, dst, used);
            }
        }
    }
}

bool CWallet::IsSpentKey(const CScript& scriptPubKey) const
{
    AssertLockHeld(cs_wallet);
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest)) {
        return false;
    }
    if (IsAddressPreviouslySpent(dest)) {
        return true;
    }
    if (IsLegacy()) {
        LegacyScriptPubKeyMan* spk_man = GetLegacyScriptPubKeyMan();
        assert(spk_man != nullptr);
        for (const auto& keyid : GetAffectedKeys(scriptPubKey, *spk_man)) {
            WitnessV0KeyHash wpkh_dest(keyid);
            if (IsAddressPreviouslySpent(wpkh_dest)) {
                return true;
            }
            ScriptHash sh_wpkh_dest(GetScriptForDestination(wpkh_dest));
            if (IsAddressPreviouslySpent(sh_wpkh_dest)) {
                return true;
            }
            PKHash pkh_dest(keyid);
            if (IsAddressPreviouslySpent(pkh_dest)) {
                return true;
            }
        }
    }
    return false;
}

CWalletTx* CWallet::AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx, bool fFlushOnClose, bool rescanning_old_block)
{
    LOCK(cs_wallet);

    WalletBatch batch(GetDatabase(), fFlushOnClose);

    uint256 hash = tx->GetHash();

    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        // Mark used destinations
        std::set<CTxDestination> tx_destinations;

        for (const CTxIn& txin : tx->vin) {
            const COutPoint& op = txin.prevout;
            SetSpentKeyState(batch, op.hash, op.n, true, tx_destinations);
        }

        MarkDestinationsDirty(tx_destinations);
    }

    // Inserts only if not already there, returns tx inserted or tx found
    auto ret = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(tx, state));
    CWalletTx& wtx = (*ret.first).second;
    bool fInsertedNew = ret.second;
    bool fUpdated = update_wtx && update_wtx(wtx, fInsertedNew);
    if (fInsertedNew) {
        wtx.nTimeReceived = GetTime();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        wtx.nTimeSmart = ComputeTimeSmart(wtx, rescanning_old_block);
        AddToSpends(wtx, &batch);

        // Update birth time when tx time is older than it.
        MaybeUpdateBirthTime(wtx.GetTxTime());
    }

    if (!fInsertedNew)
    {
        if (state.index() != wtx.m_state.index()) {
            wtx.m_state = state;
            fUpdated = true;
        } else {
            assert(TxStateSerializedIndex(wtx.m_state) == TxStateSerializedIndex(state));
            assert(TxStateSerializedBlockHash(wtx.m_state) == TxStateSerializedBlockHash(state));
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(tx);
            fUpdated = true;
        }
    }

    // Mark inactive coinbase and coinstake transactions and their descendants as abandoned
    if ((wtx.IsCoinBase() || wtx.IsCoinStake()) && wtx.isInactive()) {
        std::vector<CWalletTx*> txs{&wtx};

        TxStateInactive inactive_state = TxStateInactive{/*abandoned=*/true};

        while (!txs.empty()) {
            CWalletTx* desc_tx = txs.back();
            txs.pop_back();
            desc_tx->m_state = inactive_state;
            // Break caches since we have changed the state
            desc_tx->MarkDirty();
            batch.WriteTx(*desc_tx);
            MarkInputsDirty(desc_tx->tx);
            for (unsigned int i = 0; i < desc_tx->tx->vout.size(); ++i) {
                COutPoint outpoint(desc_tx->GetHash(), i);
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(outpoint);
                for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
                    const auto wit = mapWallet.find(it->second);
                    if (wit != mapWallet.end()) {
                        txs.push_back(&wit->second);
                    }
                }
            }
        }
    }

    //// debug print
    WalletLogPrintf("AddToWallet %s  %s%s %s\n", hash.ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""), TxStateString(state));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!batch.WriteTx(wtx))
            return nullptr;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(hash, fInsertedNew ? CT_NEW : CT_UPDATED);

#if HAVE_SYSTEM
    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = m_notify_tx_changed_script;

    if (!strCmd.empty())
    {
        ReplaceAll(strCmd, "%s", hash.GetHex());
        if (auto* conf = wtx.state<TxStateConfirmed>())
        {
            ReplaceAll(strCmd, "%b", conf->confirmed_block_hash.GetHex());
            ReplaceAll(strCmd, "%h", ToString(conf->confirmed_block_height));
        } else {
            ReplaceAll(strCmd, "%b", "unconfirmed");
            ReplaceAll(strCmd, "%h", "-1");
        }
#ifndef WIN32
        // Substituting the wallet name isn't currently supported on windows
        // because windows shell escaping has not been implemented yet:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-537384875
        // A few ways it could be implemented in the future are described in:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-461288094
        ReplaceAll(strCmd, "%w", ShellEscape(GetName()));
#endif
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }
#endif

    return &wtx;
}

bool CWallet::LoadToWallet(const uint256& hash, const UpdateWalletTxFn& fill_wtx)
{
    const auto& ins = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(nullptr, TxStateInactive{}));
    CWalletTx& wtx = ins.first->second;
    if (!fill_wtx(wtx, ins.second)) {
        return false;
    }
    // If wallet doesn't have a chain (e.g. when using the wallet tool),
    // don't bother to update txn.
    if (HaveChain()) {
        bool active;
        auto lookup_block = [&](const uint256& hash, int& height, TxState& state) {
            // If tx block (or conflicting block) was reorged out of chain
            // while the wallet was shutdown, change tx status to UNCONFIRMED
            // and reset block height, hash, and index. ABANDONED tx don't have
            // associated blocks and don't need to be updated. The case where a
            // transaction was reorged out while online and then reconfirmed
            // while offline is covered by the rescan logic.
            if (!chain().findBlock(hash, FoundBlock().inActiveChain(active).height(height)) || !active) {
                state = TxStateInactive{};
            }
        };
        if (auto* conf = wtx.state<TxStateConfirmed>()) {
            lookup_block(conf->confirmed_block_hash, conf->confirmed_block_height, wtx.m_state);
        } else if (auto* conf = wtx.state<TxStateConflicted>()) {
            lookup_block(conf->conflicting_block_hash, conf->conflicting_block_height, wtx.m_state);
        }
    }
    if (/* insertion took place */ ins.second) {
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
    }
    AddToSpends(wtx);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (auto* prev = prevtx.state<TxStateConflicted>()) {
                MarkConflicted(prev->conflicting_block_hash, prev->conflicting_block_height, wtx.GetHash());
            }
        }
    }

    // Update birth time when tx time is older than it.
    MaybeUpdateBirthTime(wtx.GetTxTime());

    return true;
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const SyncTxState& state, bool fUpdate, bool rescanning_old_block)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (auto* conf = std::get_if<TxStateConfirmed>(&state)) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), conf->confirmed_block_hash.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(conf->confirmed_block_hash, conf->confirmed_block_height, range.first->second);
                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                for (const auto& spk_man : GetScriptPubKeyMans(txout.scriptPubKey)) {
                    for (auto &dest : spk_man->MarkUnusedAddresses(txout.scriptPubKey)) {
                        // If internal flag is not defined try to infer it from the ScriptPubKeyMan
                        if (!dest.internal.has_value()) {
                            dest.internal = IsInternalScriptPubKeyMan(spk_man);
                        }

                        // skip if can't determine whether it's a receiving address or not
                        if (!dest.internal.has_value()) continue;

                        // If this is a receiving address and it's not in the address book yet
                        // (e.g. it wasn't generated on this node or we're restoring from backup)
                        // add it to the address book for proper transaction accounting
                        if (!*dest.internal && !FindAddressBookEntry(dest.dest, /* allow_change= */ false)) {
                            SetAddressBook(dest.dest, "", AddressPurpose::RECEIVE);
                        }
                    }
                }
            }

            // Block disconnection override an abandoned tx as unconfirmed
            // which means user may have to call abandontransaction again
            TxState tx_state = std::visit([](auto&& s) -> TxState { return s; }, state);
            CWalletTx* wtx = AddToWallet(MakeTransactionRef(tx), tx_state, /*update_wtx=*/nullptr, /*fFlushOnClose=*/false, rescanning_old_block);
            if (!wtx) {
                // Can only be nullptr if there was a db write error (missing db, read-only db or a db engine internal writing error).
                // As we only store arriving transaction in this process, and we don't want an inconsistent state, let's throw an error.
                throw std::runtime_error("DB error adding transaction to wallet, write failed");
            }
            return true;
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && GetTxDepthInMainChain(*wtx) == 0 && !wtx->InMempool();
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    for (const CTxIn& txin : tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK(cs_wallet);

    // Can't mark abandoned if confirmed or in mempool
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    const CWalletTx& origtx = it->second;
    if (GetTxDepthInMainChain(origtx) != 0 || origtx.InMempool()) {
        return false;
    }

    auto try_updating_state = [](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // If the orig tx was not in block/mempool, none of its spends can be.
        assert(!wtx.isConfirmed());
        assert(!wtx.InMempool());
        // If already conflicted or abandoned, no need to set abandoned
        if (!wtx.isConflicted() && !wtx.isAbandoned()) {
            wtx.m_state = TxStateInactive{/*abandoned=*/true};
            return TxUpdate::NOTIFY_CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too.
    // States are not permanent, so these transactions can become unabandoned if they are re-added to the
    // mempool, or confirmed in a block, or conflicted.
    // Note: If the reorged coinbase is re-added to the main chain, the descendants that have not had their
    // states change will remain abandoned and will require manual broadcast if the user wants them.

    RecursiveUpdateTxState(hashTx, try_updating_state);

    ReconcileRGBAssignments(); // Re-sync the RGB ledger after abandoning a transfer.
    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, int conflicting_height, const uint256& hashTx)
{
    LOCK(cs_wallet);

    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (m_last_block_processed_height < 0 || conflicting_height < 0) {
        return;
    }
    int conflictconfirms = (m_last_block_processed_height - conflicting_height + 1) * -1;
    if (conflictconfirms >= 0)
        return;

    auto try_updating_state = [&](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        if (conflictconfirms < GetTxDepthInMainChain(wtx)) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.m_state = TxStateConflicted{hashBlock, conflicting_height};
            return TxUpdate::CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too.
    RecursiveUpdateTxState(hashTx, try_updating_state);

}

void CWallet::RecursiveUpdateTxState(const uint256& tx_hash, const TryUpdatingStateFn& try_updating_state) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
    // Do not flush the wallet here for performance reasons
    WalletBatch batch(GetDatabase(), false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(tx_hash);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;

        TxUpdate update_state = try_updating_state(wtx);
        if (update_state != TxUpdate::UNCHANGED) {
            wtx.MarkDirty();
            batch.WriteTx(wtx);
            // Iterate over all its outputs, and update those tx states as well (if applicable)
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(COutPoint(now, i));
                for (TxSpends::const_iterator iter = range.first; iter != range.second; ++iter) {
                    if (!done.count(iter->second)) {
                        todo.insert(iter->second);
                    }
                }
            }

            if (update_state == TxUpdate::NOTIFY_CHANGED) {
                NotifyTransactionChanged(wtx.GetHash(), CT_UPDATED);
            }

            // If a transaction changes its tx state, that usually changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.tx);
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const SyncTxState& state, bool update_tx, bool rescanning_old_block)
{
    if (!AddToWalletIfInvolvingMe(ptx, state, update_tx, rescanning_old_block))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    MarkInputsDirty(ptx);
}

void CWallet::transactionAddedToMempool(const CTransactionRef& tx) {
    LOCK(cs_wallet);
    SyncTransaction(tx, TxStateInMempool{});

    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }
}

void CWallet::transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }
    // Handle transactions that were removed from the mempool because they
    // conflict with transactions in a newly connected block.
    if (reason == MemPoolRemovalReason::CONFLICT) {
        // Trigger external -walletnotify notifications for these transactions.
        // Set Status::UNCONFIRMED instead of Status::CONFLICTED for a few reasons:
        //
        // 1. The transactionRemovedFromMempool callback does not currently
        //    provide the conflicting block's hash and height, and for backwards
        //    compatibility reasons it may not be not safe to store conflicted
        //    wallet transactions with a null block hash. See
        //    https://github.com/bitcoin/bitcoin/pull/18600#discussion_r420195993.
        // 2. For most of these transactions, the wallet's internal conflict
        //    detection in the blockConnected handler will subsequently call
        //    MarkConflicted and update them with CONFLICTED status anyway. This
        //    applies to any wallet transaction that has inputs spent in the
        //    block, or that has ancestors in the wallet with inputs spent by
        //    the block.
        // 3. Longstanding behavior since the sync implementation in
        //    https://github.com/bitcoin/bitcoin/pull/9371 and the prior sync
        //    implementation before that was to mark these transactions
        //    unconfirmed rather than conflicted.
        //
        // Nothing described above should be seen as an unchangeable requirement
        // when improving this code in the future. The wallet's heuristics for
        // distinguishing between conflicted and unconfirmed transactions are
        // imperfect, and could be improved in general, see
        // https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Wallet-Transaction-Conflict-Tracking
        SyncTransaction(tx, TxStateInactive{});
    }
}

void CWallet::blockConnected(ChainstateRole role, const interfaces::BlockInfo& block)
{
    if (role == ChainstateRole::BACKGROUND) {
        return;
    }
    assert(block.data);
    const std::vector<ShadowSyntheticPayoutTransaction> shadow_payout_txs = GetWalletShadowPayoutTransactions(*this, block);
    LOCK(cs_wallet);

    m_last_block_processed_height = block.height;
    m_last_block_processed = block.hash;

    // No need to scan block if it was created before the wallet birthday.
    // Uses chain max time and twice the grace period to adjust time for block time variability.
    if (block.chain_time_max < m_birth_time.load() - (TIMESTAMP_WINDOW * 2)) return;

    // Scan block
    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        SyncTransaction(block.data->vtx[index], TxStateConfirmed{block.hash, block.height, static_cast<int>(index)});
        transactionRemovedFromMempool(block.data->vtx[index], MemPoolRemovalReason::BLOCK);
    }
    for (size_t index = 0; index < shadow_payout_txs.size(); ++index) {
        SyncTransaction(shadow_payout_txs[index].tx, TxStateConfirmed{block.hash, block.height, static_cast<int>(block.data->vtx.size() + index)});
    }
    WalletBatch batch(GetDatabase());
    for (const ShadowSyntheticPayoutTransaction& payout : shadow_payout_txs) {
        AnnotateWalletShadowPayout(*this, payout, batch);
    }
    for (const CTransactionRef& ptx : block.data->vtx) {
        RecordQuantumRedelegationWins(*ptx, block.height, batch);
    }
    ReconcileRGBAssignments(); // Re-sync the RGB ledger after a block connects.
}

void CWallet::blockDisconnected(const interfaces::BlockInfo& block)
{
    assert(block.data);
    LOCK(cs_wallet);

    // At block disconnection, this will change an abandoned transaction to
    // be unconfirmed, whether or not the transaction is added back to the mempool.
    // User may have to call abandontransaction again. It may be addressed in the
    // future with a stickier abandoned state or even removing abandontransaction call.
    m_last_block_processed_height = block.height - 1;
    m_last_block_processed = *Assert(block.prev_hash);

    int disconnect_height = block.height;
    std::set<uint256> disconnected_block_txids;
    for (const CTransactionRef& ptx : Assert(block.data)->vtx) {
        disconnected_block_txids.insert(ptx->GetHash());
    }

    for (const CTransactionRef& ptx : Assert(block.data)->vtx) {
        SyncTransaction(ptx, TxStateInactive{});

        for (const CTxIn& tx_in : ptx->vin) {
            // No other wallet transactions conflicted with this transaction
            if (mapTxSpends.count(tx_in.prevout) < 1) continue;

            std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(tx_in.prevout);

            // For all of the spends that conflict with this transaction
            for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it) {
                CWalletTx& wtx = mapWallet.find(_it->second)->second;

                if (!wtx.isConflicted()) continue;

                auto try_updating_state = [&](CWalletTx& tx) {
                    if (!tx.isConflicted()) return TxUpdate::UNCHANGED;
                    if (tx.state<TxStateConflicted>()->conflicting_block_height >= disconnect_height) {
                        tx.m_state = TxStateInactive{};
                        return TxUpdate::CHANGED;
                    }
                    return TxUpdate::UNCHANGED;
                };

                RecursiveUpdateTxState(wtx.tx->GetHash(), try_updating_state);
            }
        }
    }
    std::vector<CTransactionRef> synthetic_confirmed_txs;
    for (const auto& [hash, wtx] : mapWallet) {
        const auto* confirmed = wtx.state<TxStateConfirmed>();
        if (!confirmed || confirmed->confirmed_block_hash != block.hash) continue;
        if (disconnected_block_txids.count(hash)) continue;
        synthetic_confirmed_txs.push_back(wtx.tx);
    }
    for (const CTransactionRef& tx : synthetic_confirmed_txs) {
        SyncTransaction(tx, TxStateInactive{});
    }

    // Blackcoin - Call to abandon orphaned coinstakes after handling disconnections
    AbandonOrphanedCoinstakes();

    WalletBatch batch(GetDatabase());
    RecomputeQuantumRedelegationWinHistory(batch);

    ReconcileRGBAssignments(); // Re-sync the RGB ledger after a reorg disconnects a block.
}

void CWallet::updatedBlockTip()
{
    m_best_block_time = GetTime();
}

void CWallet::BlockUntilSyncedToCurrentChain() const {
    AssertLockNotHeld(cs_wallet);
    // Skip the queue-draining stuff if we know we're caught up with
    // chain().Tip(), otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    uint256 last_block_hash = WITH_LOCK(cs_wallet, return m_last_block_processed);
    chain().waitForNotificationsIfTipChanged(last_block_hash);
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    AssertLockHeld(cs_wallet);
    isminetype result = IsMine(txout.scriptPubKey);
    if (result == ISMINE_NO) // try pubkeyhash version of the address
    {
        CTxDestination address;
        ExtractDestination(txout.scriptPubKey, address);
        result = IsMine(address);
    }
    return result;
}

isminetype CWallet::IsMine(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(GetScriptForDestination(dest));
}

isminetype CWallet::IsMine(const CScript& script) const
{
    AssertLockHeld(cs_wallet);
    isminetype result = ISMINE_NO;
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    if (script.IsWitnessProgram(witness_version, witness_program) &&
        IsQuantumMigrationWitnessProgram(witness_version, witness_program) &&
        HaveQuantumKeyForProgram(witness_program)) {
        result = ISMINE_SPENDABLE;
    }
    if (script.IsWitnessProgram(witness_version, witness_program) &&
        IsQuantumColdStakeWitnessProgram(witness_version, witness_program)) {
        const auto coldstake = GetQuantumColdStakeDelegationInfo(witness_program);
        if (coldstake && (coldstake->has_owner_key || coldstake->has_staker_key)) {
            result = ISMINE_SPENDABLE;
        }
    }
    for (const auto& spk_man_pair : m_spk_managers) {
        result = std::max(result, spk_man_pair.second->IsMine(script));
    }
    return result;
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    AssertLockHeld(cs_wallet);
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

isminetype CWallet::IsMine(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    auto wtx = GetWalletTx(outpoint.hash);
    if (!wtx) {
        return ISMINE_NO;
    }
    if (outpoint.n >= wtx->tx->vout.size()) {
        return ISMINE_NO;
    }
    return IsMine(wtx->tx->vout[outpoint.n]);
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsHDEnabled() const
{
    // All Active ScriptPubKeyMans must be HD for this to be true
    bool result = false;
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->IsHDEnabled()) return false;
        result = true;
    }
    return result;
}

bool CWallet::CanGetAddresses(bool internal) const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) return false;
    for (OutputType t : OUTPUT_TYPES) {
        auto spk_man = GetScriptPubKeyMan(t, internal);
        if (spk_man && spk_man->CanGetAddresses(internal)) {
            return true;
        }
    }
    return false;
}

void CWallet::SetWalletFlag(uint64_t flags)
{
    LOCK(cs_wallet);
    m_wallet_flags |= flags;
    if (!WalletBatch(GetDatabase()).WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    WalletBatch batch(GetDatabase());
    UnsetWalletFlagWithDB(batch, flag);
}

void CWallet::UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag)
{
    LOCK(cs_wallet);
    m_wallet_flags &= ~flag;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetBlankWalletFlag(WalletBatch& batch)
{
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
}

bool CWallet::IsWalletFlagSet(uint64_t flag) const
{
    return (m_wallet_flags & flag);
}

bool CWallet::LoadWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);
    if (((flags & KNOWN_WALLET_FLAGS) >> 32) ^ (flags >> 32)) {
        // contains unknown non-tolerable wallet flags
        return false;
    }
    m_wallet_flags = flags;

    return true;
}

void CWallet::InitWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);

    // We should never be writing unknown non-tolerable wallet flags
    assert(((flags & KNOWN_WALLET_FLAGS) >> 32) == (flags >> 32));
    // This should only be used once, when creating a new wallet - so current flags are expected to be blank
    assert(m_wallet_flags == 0);

    if (!WalletBatch(GetDatabase()).WriteWalletFlags(flags)) {
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }

    if (!LoadWalletFlags(flags)) assert(false);
}

bool CWallet::ImportScripts(const std::set<CScript> scripts, int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportScripts(scripts, timestamp);
}

bool CWallet::ImportPrivKeys(const std::map<CKeyID, CKey>& privkey_map, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportPrivKeys(privkey_map, timestamp);
}

bool CWallet::ImportPubKeys(const std::vector<CKeyID>& ordered_pubkeys, const std::map<CKeyID, CPubKey>& pubkey_map, const std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& key_origins, const bool add_keypool, const bool internal, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    return spk_man->ImportPubKeys(ordered_pubkeys, pubkey_map, key_origins, add_keypool, internal, timestamp);
}

bool CWallet::ImportScriptPubKeys(const std::string& label, const std::set<CScript>& script_pub_keys, const bool have_solving_data, const bool apply_label, const int64_t timestamp)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return false;
    }
    LOCK(spk_man->cs_KeyStore);
    if (!spk_man->ImportScriptPubKeys(script_pub_keys, have_solving_data, timestamp)) {
        return false;
    }
    if (apply_label) {
        WalletBatch batch(GetDatabase());
        for (const CScript& script : script_pub_keys) {
            CTxDestination dest;
            ExtractDestination(script, dest);
            if (IsValidDestination(dest)) {
                SetAddressBookWithDB(batch, dest, label, AddressPurpose::RECEIVE);
            }
        }
    }
    return true;
}

void CWallet::MaybeUpdateBirthTime(int64_t time)
{
    int64_t birthtime = m_birth_time.load();
    if (time < birthtime) {
        m_birth_time = time;
    }
}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    int start_height = 0;
    uint256 start_block;
    bool start = chain().findFirstBlockWithTimeAndHeight(startTime - TIMESTAMP_WINDOW, 0, FoundBlock().hash(start_block).height(start_height));
    WalletLogPrintf("%s: Rescanning last %i blocks\n", __func__, start ? WITH_LOCK(cs_wallet, return GetLastBlockHeight()) - start_height + 1 : 0);

    if (start) {
        // TODO: this should take into account failure by ScanResult::USER_ABORT
        ScanResult result = ScanForWalletTransactions(start_block, start_height, /*max_height=*/{}, reserver, /*fUpdate=*/update, /*save_progress=*/false);
        if (result.status == ScanResult::FAILURE) {
            int64_t time_max;
            CHECK_NONFATAL(chain().findBlock(result.last_failed_block, FoundBlock().maxTime(time_max)));
            return time_max + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in start_block) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated. If max_height is not set, the
 * mempool will be scanned as well.
 *
 * @param[in] start_block Scan starting block. If block is not on the active
 *                        chain, the scan will return SUCCESS immediately.
 * @param[in] start_height Height of start_block
 * @param[in] max_height  Optional max scanning height. If unset there is
 *                        no maximum and scanning can continue to the tip
 *
 * @return ScanResult returning scan information and indicating success or
 *         failure. Return status will be set to SUCCESS if scan was
 *         successful. FAILURE if a complete rescan was not possible (due to
 *         pruning or corruption). USER_ABORT if the rescan was aborted before
 *         it could complete.
 *
 * @pre Caller needs to make sure start_block (and the optional stop_block) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool fUpdate, const bool save_progress)
{
    constexpr auto INTERVAL_TIME{60s};
    auto current_time{reserver.now()};
    auto start_time{reserver.now()};

    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    std::unique_ptr<FastWalletRescanFilter> fast_rescan_filter;
    if (!IsLegacy() && chain().hasBlockFilterIndex(BlockFilterType::BASIC)) fast_rescan_filter = std::make_unique<FastWalletRescanFilter>(*this);

    WalletLogPrintf("Rescan started from block %s... (%s)\n", start_block.ToString(),
                    fast_rescan_filter ? "fast variant using block filters" : "slow variant inspecting all blocks");

    fAbortRescan = false;
    ShowProgress(strprintf("%s " + _("Rescanning…").translated, GetDisplayName()), 0); // show rescan progress in GUI as dialog or on splashscreen, if rescan required on startup (e.g. due to corruption)
    uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = tip_hash;
    if (max_height) chain().findAncestorByHeight(tip_hash, *max_height, FoundBlock().hash(end_hash));
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    int block_height = start_height;
    while (!fAbortRescan && !chain().shutdownRequested()) {
        if (progress_end - progress_begin > 0.0) {
            m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        } else { // avoid divide-by-zero for single block scan range (i.e. start and stop hashes are equal)
            m_scanning_progress = 0;
        }
        if (block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
            ShowProgress(strprintf("%s " + _("Rescanning…").translated, GetDisplayName()), std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
        }

        bool next_interval = reserver.now() >= current_time + INTERVAL_TIME;
        if (next_interval) {
            current_time = reserver.now();
            WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", block_height, progress_current);
        }

        bool fetch_block{true};
        if (fast_rescan_filter) {
            fast_rescan_filter->UpdateIfNeeded();
            auto matches_block{fast_rescan_filter->MatchesBlock(block_hash)};
            if (matches_block.has_value()) {
                if (*matches_block) {
                    LogPrint(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (filter matched)\n", block_height, block_hash.ToString());
                } else {
                    result.last_scanned_block = block_hash;
                    result.last_scanned_height = block_height;
                    fetch_block = false;
                }
            } else {
                LogPrint(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (WARNING: block filter not found!)\n", block_height, block_hash.ToString());
            }
        }
        if (!fetch_block && block_height >= SHADOW_REWARD_START_HEIGHT && block_height <= SHADOW_REWARD_END_HEIGHT) {
            fetch_block = true;
            LogPrint(BCLog::SCAN, "Fast rescan: inspect Gold Rush block %d [%s] for Quantum Quasar shadow payouts\n", block_height, block_hash.ToString());
        }

        // Find next block separately from reading data above, because reading
        // is slow and there might be a reorg while it is read.
        bool block_still_active = false;
        bool next_block = false;
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));

        if (fetch_block) {
            // Read block data
            CBlock block;
            chain().findBlock(block_hash, FoundBlock().data(block));

            if (!block.IsNull()) {
                std::vector<ShadowSyntheticPayoutTransaction> shadow_payout_txs;
                {
                    LOCK(cs_main);
                    shadow_payout_txs = GetAppliedShadowClaimPayoutTransactionRecords(chain().getCoinsTip(), block_height, block_hash, block.GetBlockTime());
                }
                LOCK(cs_wallet);
                if (!block_still_active) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{block_hash, block_height, static_cast<int>(posInBlock)}, fUpdate, /*rescanning_old_block=*/true);
                }
                for (size_t pos = 0; pos < shadow_payout_txs.size(); ++pos) {
                    SyncTransaction(shadow_payout_txs[pos].tx, TxStateConfirmed{block_hash, block_height, static_cast<int>(block.vtx.size() + pos)}, fUpdate, /*rescanning_old_block=*/true);
                }
                if (!shadow_payout_txs.empty() || fUpdate) {
                    WalletBatch batch(GetDatabase());
                    for (const ShadowSyntheticPayoutTransaction& payout : shadow_payout_txs) {
                        AnnotateWalletShadowPayout(*this, payout, batch);
                    }
                    if (fUpdate) {
                        for (const CTransactionRef& ptx : block.vtx) {
                            RecordQuantumRedelegationWins(*ptx, block_height, batch);
                        }
                    }
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = block_height;

                if (save_progress && next_interval) {
                    CBlockLocator loc = m_chain->getActiveChainLocator(block_hash);

                    if (!loc.IsNull()) {
                        WalletLogPrintf("Saving scan progress %d.\n", block_height);
                        WalletBatch batch(GetDatabase());
                        batch.WriteBestBlock(loc);
                    }
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
        }
        if (max_height && block_height >= *max_height) {
            break;
        }
        {
            if (!next_block) {
                // break successfully when rescan has reached the tip, or
                // previous block is no longer on the chain due to a reorg
                break;
            }

            // increment block and verification progress
            block_hash = next_block_hash;
            ++block_height;
            progress_current = chain().guessVerificationProgress(block_hash);

            // handle updated tip hash
            const uint256 prev_tip_hash = tip_hash;
            tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
            if (!max_height && prev_tip_hash != tip_hash) {
                // in case the tip has changed, update progress max
                progress_end = chain().guessVerificationProgress(tip_hash);
            }
        }
    }
    if (!max_height) {
        WalletLogPrintf("Scanning current mempool transactions.\n");
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    }
    ShowProgress(strprintf("%s " + _("Rescanning…").translated, GetDisplayName()), 100); // hide progress dialog in GUI
    if (block_height && fAbortRescan) {
        WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else if (block_height && chain().shutdownRequested()) {
        WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else {
        WalletLogPrintf("Rescan completed in %15dms\n", Ticks<std::chrono::milliseconds>(reserver.now() - start_time));
    }
    if (fUpdate && result.status == ScanResult::SUCCESS) {
        LOCK(cs_wallet);
        ReconcileRGBAssignments(); // Re-sync RGB seals discovered or updated by a rescan.
    }
    return result;
}

void CWallet::AbandonOrphanedCoinstakes()
{
	LOCK(cs_wallet);

    // Blackcoin: m_last_block_processed_height can be < 0
    // when loading the wallet during a reindex. Do nothing in that
    // case.
    if (m_last_block_processed_height < 0) {
        return;
    }

    for (std::pair<const uint256, CWalletTx>& item : mapWallet) {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);
        if (GetTxDepthInMainChain(wtx) == 0 && !wtx.isAbandoned() && wtx.IsCoinStake()) {
            LogPrint(BCLog::COINSTAKE, "Abandoning coinstake wtx %s\n", wtx.GetHash().ToString());
            if (!AbandonTransaction(wtxid)) {
                LogPrint(BCLog::COINSTAKE, "Failed to abandon coinstake tx %s\n", wtx.GetHash().ToString());
            }
        }
    }
}

bool CWallet::SubmitTxMemoryPoolAndRelay(CWalletTx& wtx, std::string& err_string, bool relay) const
{
    AssertLockHeld(cs_wallet);

    // Can't relay if wallet is not broadcasting
    if (!GetBroadcastTransactions()) return false;
    // Don't relay abandoned transactions
    if (wtx.isAbandoned()) return false;
    // Don't try to submit coinbase transactions. These would fail anyway but would
    // cause log spam.
    if (wtx.IsCoinBase() || wtx.IsCoinStake()) return false;
    // Don't try to submit conflicted or confirmed transactions.
    if (GetTxDepthInMainChain(wtx) != 0) return false;

    // Submit transaction to mempool for relay
    WalletLogPrintf("Submitting wtx %s to mempool for relay\n", wtx.GetHash().ToString());
    // We must set TxStateInMempool here. Even though it will also be set later by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that this newly generated transaction's change is
    // unavailable as we're not yet aware that it is in the mempool.
    //
    // If broadcast fails for any reason, trying to set wtx.m_state here would be incorrect.
    // If transaction was previously in the mempool, it should be updated when
    // TransactionRemovedFromMempool fires.
    bool ret = chain().broadcastTransaction(wtx.tx, m_default_max_tx_fee, relay, err_string);
    if (ret) wtx.m_state = TxStateInMempool{};
    return ret;
}

std::set<uint256> CWallet::GetTxConflicts(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    const uint256 myHash{wtx.GetHash()};
    std::set<uint256> result{GetConflicts(myHash)};
    result.erase(myHash);
    return result;
}

bool CWallet::ShouldResend() const
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast
    if (!fBroadcastTransactions) return false;

    // During reindex, importing and IBD, old wallet transactions become
    // unconfirmed. Don't resend them as that would spam other nodes.
    // We only allow forcing mempool submission when not relaying to avoid this spam.
    if (!chain().isReadyToBroadcast()) return false;

    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (NodeClock::now() < m_next_resend) return false;

    return true;
}

NodeClock::time_point CWallet::GetDefaultNextResend() { return FastRandomContext{}.rand_uniform_delay(NodeClock::now() + 12h, 24h); }

// Resubmit transactions from the wallet to the mempool, optionally asking the
// mempool to relay them. On startup, we will do this for all unconfirmed
// transactions but will not ask the mempool to relay them. We do this on startup
// to ensure that our own mempool is aware of our transactions. There
// is a privacy side effect here as not broadcasting on startup also means that we won't
// inform the world of our wallet's state, particularly if the wallet (or node) is not
// yet synced.
//
// Otherwise this function is called periodically in order to relay our unconfirmed txs.
// We do this on a random timer to slightly obfuscate which transactions
// come from our wallet.
//
// TODO: Ideally, we'd only resend transactions that we think should have been
// mined in the most recent block. Any transaction that wasn't in the top
// blockweight of transactions in the mempool shouldn't have been mined,
// and so is probably just sitting in the mempool waiting to be confirmed.
// Rebroadcasting does nothing to speed up confirmation and only damages
// privacy.
//
// The `force` option results in all unconfirmed transactions being submitted to
// the mempool. This does not necessarily result in those transactions being relayed,
// that depends on the `relay` option. Periodic rebroadcast uses the pattern
// relay=true force=false, while loading into the mempool
// (on start, or after import) uses relay=false force=true.
void CWallet::ResubmitWalletTransactions(bool relay, bool force)
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast,
    // even if forcing.
    if (!fBroadcastTransactions) return;

    int submitted_tx_count = 0;

    { // cs_wallet scope
        LOCK(cs_wallet);

        // First filter for the transactions we want to rebroadcast.
        // We use a set with WalletTxOrderComparator so that rebroadcasting occurs in insertion order
        std::set<CWalletTx*, WalletTxOrderComparator> to_submit;
        for (auto& [txid, wtx] : mapWallet) {
            // Only rebroadcast unconfirmed txs
            if (!wtx.isUnconfirmed()) continue;

            // Attempt to rebroadcast all txes more than 5 minutes older than
            // the last block, or all txs if forcing.
            if (!force && wtx.nTimeReceived > m_best_block_time - 5 * 60) continue;
            to_submit.insert(&wtx);
        }
        // Now try submitting the transactions to the memory pool and (optionally) relay them.
        for (auto wtx : to_submit) {
            std::string unused_err_string;
            if (SubmitTxMemoryPoolAndRelay(*wtx, unused_err_string, relay)) ++submitted_tx_count;
        }
    } // cs_wallet

    if (submitted_tx_count > 0) {
        WalletLogPrintf("%s: resubmit %u unconfirmed transactions\n", __func__, submitted_tx_count);
    }
}

/** @} */ // end of mapWallet

void MaybeResendWalletTxs(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        MaybeAutoDemurrageAttest(*pwallet);
        MaybeAutoShadowSignal(*pwallet);
        MaybeAutoRedelegateQuantumColdStake(*pwallet);
        if (!pwallet->ShouldResend()) continue;
        pwallet->ResubmitWalletTransactions(/*relay=*/true, /*force=*/false);
        pwallet->SetNextResend();
    }
}


/** @defgroup Actions
 *
 * @{
 */

bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, input_errors);
}

bool CWallet::SignTransaction(CMutableTransaction& tx, std::map<int, bilingual_str>& input_errors) const
{
    AssertLockHeld(cs_wallet);

    // Build coins map
    std::map<COutPoint, Coin> coins;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const auto& input = tx.vin[i];
        const auto mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CWalletTx& wtx = mi->second;
        int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
        coins[input.prevout] = Coin(wtx.tx->vout[input.prevout.n], prev_height, wtx.IsCoinBase(), wtx.IsCoinStake(), wtx.nTimeSmart);
    }
    if (!input_errors.empty()) return false;
    return SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
}

bool CWallet::SignQuantumTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, unsigned int verify_flags, bool quantum_spend_active, std::map<int, bilingual_str>& input_errors) const
{
    AssertLockHeld(cs_wallet);

    const uint32_t quantum_chain_id = Params().GetConsensus().nQuantumSighashChainId;
    std::set<unsigned int> quantum_inputs;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const auto coin_it = coins.find(tx.vin[i].prevout);
        if (coin_it == coins.end() || coin_it->second.IsSpent()) {
            if (!input_errors.count(i)) {
                input_errors[i] = _("Input not found or already spent");
            }
            continue;
        }

        int witness_version{0};
        std::vector<unsigned char> witness_program;
        if (coin_it->second.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
            (IsQuantumMigrationWitnessProgram(witness_version, witness_program) ||
             IsQuantumColdStakeWitnessProgram(witness_version, witness_program))) {
            tx.vin[i].scriptSig.clear();
            quantum_inputs.insert(i);
        } else if (verify_flags & SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT) {
            input_errors[i] = _("Legacy spends are disabled after the Quantum Quasar migration deadline");
        }
    }

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(tx.vin.size());
    for (const CTxIn& txin : tx.vin) {
        const auto coin_it = coins.find(txin.prevout);
        spent_outputs.push_back(coin_it == coins.end() || coin_it->second.IsSpent() ? CTxOut{} : coin_it->second.out);
    }

    if (!quantum_inputs.empty() && input_errors.empty()) {
        for (unsigned int i = 0; i < tx.vout.size(); ++i) {
            if (IsQuantumProtectedSpendAllowedOutput(CTransaction{tx}, i)) {
                continue;
            }
            input_errors[0] = strprintf(_("Quantum-protected spends may only create quantum outputs (output %u)"), i);
            return false;
        }
    }

    for (const unsigned int i : quantum_inputs) {
        if (!quantum_spend_active || !(verify_flags & SCRIPT_VERIFY_QUANTUM_ML_DSA)) {
            input_errors[i] = _("Quantum migration spends are not active until the post-Gold-Rush migration window");
            continue;
        }

        const Coin& coin = coins.at(tx.vin[i].prevout);
        if (coin.out.nValue == MAX_MONEY) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        int witness_version{0};
        std::vector<unsigned char> witness_program;
        const bool is_quantum_migration = coin.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                                          IsQuantumMigrationWitnessProgram(witness_version, witness_program);
        const bool is_quantum_coldstake = coin.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                                          IsQuantumColdStakeWitnessProgram(witness_version, witness_program);
        CHECK_NONFATAL(is_quantum_migration || is_quantum_coldstake);

        std::vector<unsigned char> public_key;
        CKeyingMaterial private_key;
        if (is_quantum_migration) {
            bilingual_str error;
            if (!GetQuantumKey(witness_program, public_key, private_key, error)) {
                input_errors[i] = error;
                continue;
            }
        } else {
            if (!(verify_flags & SCRIPT_VERIFY_QUANTUM_COLDSTAKE)) {
                input_errors[i] = _("Quantum cold-stake spends are not active at the current chain tip");
                continue;
            }

            auto fill_from_delegation = [&]() -> bool {
                const auto info = GetQuantumColdStakeDelegationInfo(witness_program);
                if (!info) {
                    input_errors[i] = _("No wallet metadata matches this quantum cold-stake witness program");
                    return false;
                }

                const bool coinstake = tx.IsCoinStake();
                std::vector<unsigned char> key_program;
                uint256 other_pubkey_hash;
                std::vector<unsigned char> selector;
                if (coinstake && info->has_staker_key) {
                    key_program = VectorForUint256(info->staker_pubkey_hash);
                    other_pubkey_hash = info->owner_pubkey_hash;
                    selector = {1};
                } else if (info->has_owner_key) {
                    key_program = VectorForUint256(info->owner_pubkey_hash);
                    other_pubkey_hash = info->staker_pubkey_hash;
                    selector = {};
                } else if (coinstake) {
                    input_errors[i] = _("Wallet has no staker ML-DSA key for this quantum cold-stake delegation");
                    return false;
                } else {
                    input_errors[i] = _("Wallet has no owner ML-DSA key for this quantum cold-stake delegation");
                    return false;
                }

                bilingual_str error;
                if (!GetQuantumKey(key_program, public_key, private_key, error)) {
                    input_errors[i] = error;
                    return false;
                }

                CScriptWitness witness;
                witness.stack.emplace_back();
                witness.stack.emplace_back();
                witness.stack.emplace_back(other_pubkey_hash.begin(), other_pubkey_hash.end());
                witness.stack.emplace_back(std::move(selector));
                tx.vin[i].scriptWitness = std::move(witness);
                return true;
            };

            const auto& stack = tx.vin[i].scriptWitness.stack;
            if (stack.size() != 4 || stack[2].size() != uint256::size() || !IsValidQuantumColdStakeSelector(stack[3])) {
                if (!fill_from_delegation()) {
                    continue;
                }
            } else {
                uint256 other_pubkey_hash;
                std::copy(stack[2].begin(), stack[2].end(), other_pubkey_hash.begin());
                const bool staker_branch = IsQuantumColdStakeStakerBranch(stack[3]);
                bool matched_key{false};
                for (const auto& [key_program, record] : m_quantum_keys) {
                    if (key_program.size() != uint256::size()) continue;
                    uint256 revealed_pubkey_hash;
                    std::copy(key_program.begin(), key_program.end(), revealed_pubkey_hash.begin());
                    const std::vector<unsigned char> expected_program = staker_branch
                        ? QuantumColdStakeProgramForKeyHashes(revealed_pubkey_hash, other_pubkey_hash)
                        : QuantumColdStakeProgramForKeyHashes(other_pubkey_hash, revealed_pubkey_hash);
                    if (expected_program != witness_program) continue;

                    bilingual_str error;
                    if (!GetQuantumKey(key_program, public_key, private_key, error)) {
                        input_errors[i] = error;
                        matched_key = true;
                        break;
                    }
                    matched_key = true;
                    break;
                }
                if (!matched_key) {
                    if (!fill_from_delegation()) {
                        continue;
                    }
                }
            }
            if (input_errors.count(i)) continue;
        }

        const CTransaction tx_to{tx};
        const uint256 sighash = QuantumSignatureHash(tx_to, i, spent_outputs, quantum_chain_id);
        std::vector<uint8_t> private_key_bytes(private_key.begin(), private_key.end());
        std::vector<uint8_t> signature;
        if (!ML_DSA::Sign(private_key_bytes, sighash.begin(), uint256::size(), signature)) {
            CleanseVector(private_key_bytes);
            input_errors[i] = _("ML-DSA signing failed");
            continue;
        }
        CleanseVector(private_key_bytes);

        if (is_quantum_migration) {
            CScriptWitness witness;
            witness.stack.emplace_back(signature.begin(), signature.end());
            witness.stack.emplace_back(public_key.begin(), public_key.end());
            tx.vin[i].scriptWitness = std::move(witness);
        } else {
            CScriptWitness witness = tx.vin[i].scriptWitness;
            witness.stack[0].assign(signature.begin(), signature.end());
            witness.stack[1].assign(public_key.begin(), public_key.end());
            tx.vin[i].scriptWitness = std::move(witness);
        }
        input_errors.erase(i);
    }

    const CTransaction tx_const{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, std::move(spent_outputs), true);
    txdata.m_quantum_sighash_chain_id = quantum_chain_id;

    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        if (input_errors.count(i)) {
            continue;
        }

        const auto coin_it = coins.find(tx.vin[i].prevout);
        if (coin_it == coins.end() || coin_it->second.IsSpent()) {
            if (!input_errors.count(i)) {
                input_errors[i] = _("Input not found or already spent");
            }
            continue;
        }

        const CScript& prev_script = coin_it->second.out.scriptPubKey;
        const CAmount amount = coin_it->second.out.nValue;
        if (amount == MAX_MONEY && !tx.vin[i].scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(tx.vin[i].scriptSig, prev_script, &tx.vin[i].scriptWitness, verify_flags,
                          TransactionSignatureChecker(&tx_const, i, amount, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            input_errors.erase(i);
        }
    }

    if ((verify_flags & SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT) && input_errors.empty()) {
        for (unsigned int i = 0; i < tx.vout.size(); ++i) {
            const CTxOut& txout = tx.vout[i];
            if (txout.IsEmpty() || (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == OP_RETURN) ||
                IsQuantumProtectedScript(txout.scriptPubKey) || IsEUTXOScript(txout.scriptPubKey)) {
                continue;
            }
            input_errors[0] = strprintf(_("Legacy outputs are disabled after the Quantum Quasar migration deadline (output %u)"), i);
            break;
        }
    }

    return input_errors.empty();
}

bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    int active_sighash = sighash;
    unsigned int verify_flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    bool quantum_spend_active = !HaveChain();
    bool eutxo_spend_active = !HaveChain();
    if (HaveChain()) {
        if (const CBlockIndex* tip = chain().getTip()) {
            const int64_t tip_mtp = tip->GetMedianTimePast();
            const auto& consensus = Params().GetConsensus();
            if (consensus.IsProtocolV4(tip_mtp)) {
                verify_flags |= SCRIPT_VERIFY_ISCOINSTAKE;
                verify_flags |= SCRIPT_VERIFY_STRICTENC;
            }
            if (consensus.IsNewNetworkStakeOnly(tip_mtp, tip->nHeight + 1)) {
                active_sighash = (active_sighash == SIGHASH_DEFAULT ? SIGHASH_ALL : active_sighash) | SIGHASH_FORKID;
                verify_flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
            }
            quantum_spend_active = IsQuantumWitnessSpendActive(consensus, tip_mtp, tip->nHeight + 1);
            eutxo_spend_active = quantum_spend_active;
            if (quantum_spend_active) {
                verify_flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
                verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
                verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
            }
            if (eutxo_spend_active) {
                verify_flags |= SCRIPT_VERIFY_EUTXO;
            }
            if (consensus.IsStakeTiersActive(tip->nHeight + 1)) {
                verify_flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
            }
            if (consensus.IsQuantumFinalLockout(tip_mtp, tip->nHeight + 1)) {
                verify_flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
            }
        }
    } else {
        verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
        verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
    }

    FlatSigningProvider descriptor_keys;
    bool have_descriptor_keys{false};
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) {
            spk_man->SignTransaction(tx, coins, active_sighash, input_errors);
            continue;
        }

        for (const auto& coin_pair : coins) {
            auto coin_keys = desc_spk_man->GetSigningProviderForScript(coin_pair.second.out.scriptPubKey);
            if (!coin_keys) {
                continue;
            }
            have_descriptor_keys = true;
            descriptor_keys.Merge(std::move(*coin_keys));
        }
    }
    if (have_descriptor_keys) {
        ::SignTransaction(tx, &descriptor_keys, coins, active_sighash, input_errors);
    }

    LOCK(cs_wallet);
    return SignQuantumTransaction(tx, coins, verify_flags, quantum_spend_active, input_errors);
}

unsigned int CWallet::GetActiveScriptVerifyFlags() const
{
    unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    bool quantum_spend_active = !HaveChain();
    bool eutxo_spend_active = !HaveChain();
    bool final_lockout_active = false;

    if (HaveChain()) {
        if (const CBlockIndex* tip = chain().getTip()) {
            const int64_t tip_mtp = tip->GetMedianTimePast();
            const auto& consensus = Params().GetConsensus();
            if (consensus.IsProtocolV4(tip_mtp)) {
                flags |= SCRIPT_VERIFY_ISCOINSTAKE;
                flags |= SCRIPT_VERIFY_STRICTENC;
            }
            if (consensus.IsNewNetworkStakeOnly(tip_mtp, tip->nHeight + 1)) {
                flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
            }
            quantum_spend_active = IsQuantumWitnessSpendActive(consensus, tip_mtp, tip->nHeight + 1);
            eutxo_spend_active = quantum_spend_active;
            final_lockout_active = consensus.IsQuantumFinalLockout(tip_mtp, tip->nHeight + 1);
            if (consensus.IsStakeTiersActive(tip->nHeight + 1)) {
                flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
            }
        }
    }
    if (quantum_spend_active) {
        flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
        flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
        flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
    }
    if (eutxo_spend_active) {
        flags |= SCRIPT_VERIFY_EUTXO;
    }
    if (final_lockout_active) {
        flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
    }
    return flags;
}

bool CWallet::FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result) const
{
    return ::FinalizeAndExtractPSBT(psbtx, result, GetActiveScriptVerifyFlags());
}

TransactionError CWallet::FillPSBT(PartiallySignedTransaction& psbtx, bool& complete, int sighash_type, bool sign, bool bip32derivs, size_t * n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    LOCK(cs_wallet);
    int active_sighash = sighash_type;
    bool quantum_spend_active = !HaveChain();
    bool eutxo_spend_active = !HaveChain();
    bool final_lockout_active = false;
    unsigned int psbt_verify_flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (HaveChain()) {
        if (const CBlockIndex* tip = chain().getTip()) {
            const int64_t tip_mtp = tip->GetMedianTimePast();
            const auto& consensus = Params().GetConsensus();
            if (consensus.IsProtocolV4(tip_mtp)) {
                psbt_verify_flags |= SCRIPT_VERIFY_ISCOINSTAKE;
                psbt_verify_flags |= SCRIPT_VERIFY_STRICTENC;
            }
            if (consensus.IsNewNetworkStakeOnly(tip_mtp, tip->nHeight + 1)) {
                active_sighash = (active_sighash == SIGHASH_DEFAULT ? SIGHASH_ALL : active_sighash) | SIGHASH_FORKID;
                psbt_verify_flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
            }
            quantum_spend_active = IsQuantumWitnessSpendActive(consensus, tip_mtp, tip->nHeight + 1);
            eutxo_spend_active = quantum_spend_active;
            final_lockout_active = consensus.IsQuantumFinalLockout(tip_mtp, tip->nHeight + 1);
            if (consensus.IsStakeTiersActive(tip->nHeight + 1)) {
                psbt_verify_flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
            }
        }
    }
    if (quantum_spend_active) {
        psbt_verify_flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
        psbt_verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
        psbt_verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
    }
    if (eutxo_spend_active) {
        psbt_verify_flags |= SCRIPT_VERIFY_EUTXO;
    }
    if (final_lockout_active) {
        psbt_verify_flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
    }
    // Get all of the previous transactions
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const CTxIn& txin = psbtx.tx->vin[i];
        PSBTInput& input = psbtx.inputs.at(i);

        // If we have no utxo, grab it from the wallet.
        if (!input.non_witness_utxo) {
            const uint256& txhash = txin.prevout.hash;
            const auto it = mapWallet.find(txhash);
            if (it != mapWallet.end()) {
                const CWalletTx& wtx = it->second;
                // We only need the non_witness_utxo, which is a superset of the witness_utxo.
                //   The signing code will switch to the smaller witness_utxo if this is ok.
                input.non_witness_utxo = wtx.tx;
            }
        }
    }

    PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    txdata.m_quantum_sighash_chain_id = Params().GetConsensus().nQuantumSighashChainId;

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const PSBTInput& input = psbtx.inputs.at(i);
        if (!PSBTInputSigned(input)) {
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyFinalizedPSBTInput(psbtx, i, txdata, psbt_verify_flags, &serror)) {
            return TransactionError::INVALID_PSBT;
        }
    }

    // Fill in information from ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        int n_signed_this_spkm = 0;
        TransactionError res = spk_man->FillPSBT(psbtx, txdata, active_sighash, sign, bip32derivs, &n_signed_this_spkm, finalize);
        if (res != TransactionError::OK) {
            return res;
        }

        if (n_signed) {
            (*n_signed) += n_signed_this_spkm;
        }
    }

    bool psbt_spends_quantum_migration_output = false;
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        CTxOut utxo;
        if (psbtx.GetInputUTXO(utxo, i) && IsQuantumProtectedScript(utxo.scriptPubKey)) {
            psbt_spends_quantum_migration_output = true;
            break;
        }
    }

    if (psbt_spends_quantum_migration_output) {
        const CTransaction tx_const{*psbtx.tx};
        for (unsigned int i = 0; i < tx_const.vout.size(); ++i) {
            if (IsQuantumProtectedSpendAllowedOutput(tx_const, i)) {
                continue;
            }
            return TransactionError::INVALID_PSBT;
        }
    }

    if (sign) {
        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs.at(i);
            if (PSBTInputSigned(input)) {
                continue;
            }

            CTxOut utxo;
            if (!psbtx.GetInputUTXO(utxo, i) || !IsQuantumMigrationScript(utxo.scriptPubKey)) {
                continue;
            }
            if (!quantum_spend_active) {
                return TransactionError::INVALID_PSBT;
            }
            if (!finalize) {
                return TransactionError::INVALID_PSBT;
            }
            if (utxo.nValue == MAX_MONEY) {
                return TransactionError::MISSING_INPUTS;
            }
            if (!txdata.m_spent_outputs_ready || txdata.m_spent_outputs.size() != psbtx.tx->vin.size()) {
                return TransactionError::MISSING_INPUTS;
            }

            int witness_version{0};
            std::vector<unsigned char> witness_program;
            const bool is_quantum = utxo.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                                    IsQuantumMigrationWitnessProgram(witness_version, witness_program);
            CHECK_NONFATAL(is_quantum);

            std::vector<unsigned char> public_key;
            CKeyingMaterial private_key;
            bilingual_str error;
            if (!GetQuantumKey(witness_program, public_key, private_key, error)) {
                continue;
            }

            const CTransaction tx_to{*psbtx.tx};
            const uint256 sighash = QuantumSignatureHash(tx_to, i, txdata.m_spent_outputs, txdata.m_quantum_sighash_chain_id);
            std::vector<uint8_t> private_key_bytes(private_key.begin(), private_key.end());
            std::vector<uint8_t> signature;
            if (!ML_DSA::Sign(private_key_bytes, sighash.begin(), uint256::size(), signature)) {
                CleanseVector(private_key_bytes);
                return TransactionError::INVALID_PSBT;
            }
            CleanseVector(private_key_bytes);

            CScriptWitness witness;
            witness.stack.emplace_back(signature.begin(), signature.end());
            witness.stack.emplace_back(public_key.begin(), public_key.end());

            ScriptError serror = SCRIPT_ERR_OK;
            if (!VerifyScript(CScript(), utxo.scriptPubKey, &witness, psbt_verify_flags,
                              MutableTransactionSignatureChecker(&(*psbtx.tx), i, utxo.nValue, txdata, MissingDataBehavior::FAIL), &serror)) {
                return TransactionError::INVALID_PSBT;
            }

            input.final_script_sig.clear();
            input.final_script_witness = std::move(witness);
            input.witness_utxo = utxo;
            if (n_signed) {
                ++(*n_signed);
            }
        }
    }

    if (final_lockout_active) {
        const CTransaction tx_const{*psbtx.tx};
        for (const CTxOut& txout : tx_const.vout) {
            if (txout.IsEmpty() || (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == OP_RETURN) ||
                IsQuantumProtectedScript(txout.scriptPubKey) || IsEUTXOScript(txout.scriptPubKey)) {
                continue;
            }
            return TransactionError::INVALID_PSBT;
        }
    }

    RemoveUnnecessaryTransactions(psbtx, active_sighash);

    // Complete if every input is now signed
    complete = true;
    for (const auto& input : psbtx.inputs) {
        complete &= PSBTInputSigned(input);
    }

    return TransactionError::OK;
}

SigningResult CWallet::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    SignatureData sigdata;
    CScript script_pub_key = GetScriptForDestination(pkhash);
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script_pub_key, sigdata)) {
            LOCK(cs_wallet);  // DescriptorScriptPubKeyMan calls IsLocked which can lock cs_wallet in a deadlocking order
            return spk_man_pair.second->SignMessage(message, pkhash, str_sig);
        }
    }
    return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
}

SigningResult CWallet::SignBlockHash(const uint256 &hash, const PKHash& pkhash, std::vector<unsigned char>& vchSig) const
{
    SignatureData sigdata;
    CScript script_pub_key = GetScriptForDestination(pkhash);
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script_pub_key, sigdata)) {
            LOCK(cs_wallet);  // DescriptorScriptPubKeyMan calls IsLocked which can lock cs_wallet in a deadlocking order
            return spk_man_pair.second->SignBlockHash(hash, pkhash, vchSig);
        }
    }
    return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
}

OutputType CWallet::TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& vecSend) const
{
    // If -changetype is specified, always use that change type.
    if (change_type) {
        return *change_type;
    }

    // if m_default_address_type is legacy, use legacy address as change.
    if (m_default_address_type == OutputType::LEGACY) {
        return OutputType::LEGACY;
    }

    bool any_tr{false};
    bool any_wpkh{false};
    bool any_sh{false};
    bool any_pkh{false};

    for (const auto& recipient : vecSend) {
        if (std::get_if<WitnessV1Taproot>(&recipient.dest)) {
            any_tr = true;
        } else if (std::get_if<WitnessV0KeyHash>(&recipient.dest)) {
            any_wpkh = true;
        } else if (std::get_if<ScriptHash>(&recipient.dest)) {
            any_sh = true;
        } else if (std::get_if<PKHash>(&recipient.dest)) {
            any_pkh = true;
        }
    }

    const bool has_bech32m_spkman(GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
    if (has_bech32m_spkman && any_tr) {
        // Currently tr is the only type supported by the BECH32M spkman
        return OutputType::BECH32M;
    }
    const bool has_bech32_spkman(GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
    if (has_bech32_spkman && any_wpkh) {
        // Currently wpkh is the only type supported by the BECH32 spkman
        return OutputType::BECH32;
    }
    const bool has_p2sh_segwit_spkman(GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
    if (has_p2sh_segwit_spkman && any_sh) {
        // Currently sh_wpkh is the only type supported by the P2SH_SEGWIT spkman
        // As of 2021 about 80% of all SH are wrapping WPKH, so use that
        return OutputType::P2SH_SEGWIT;
    }
    const bool has_legacy_spkman(GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
    if (has_legacy_spkman && any_pkh) {
        // Currently pkh is the only type supported by the LEGACY spkman
        return OutputType::LEGACY;
    }

    if (has_bech32m_spkman) {
        return OutputType::BECH32M;
    }
    if (has_bech32_spkman) {
        return OutputType::BECH32;
    }
    // else use m_default_address_type for change
    return m_default_address_type;
}

bool CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm, std::string* broadcast_error)
{
    LOCK(cs_wallet);
    WalletLogPrintf("CommitTransaction:\n%s", tx->ToString()); // NOLINT(bitcoin-unterminated-logprintf)

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    CWalletTx* wtx = AddToWallet(tx, TxStateInactive{}, [&](CWalletTx& wtx, bool new_tx) {
        CHECK_NONFATAL(wtx.mapValue.empty());
        CHECK_NONFATAL(wtx.vOrderForm.empty());
        wtx.mapValue = std::move(mapValue);
        wtx.vOrderForm = std::move(orderForm);
        wtx.fTimeReceivedIsTxTime = true;
        wtx.fFromMe = true;
        return true;
    });

    // wtx can only be null if the db write failed.
    if (!wtx) {
        throw std::runtime_error(std::string(__func__) + ": Wallet db error, transaction commit failed");
    }

    // Notify that old coins are spent
    for (const CTxIn& txin : tx->vin) {
        CWalletTx &coin = mapWallet.at(txin.prevout.hash);
        coin.MarkDirty();
        NotifyTransactionChanged(coin.GetHash(), CT_UPDATED);
    }

    if (!fBroadcastTransactions) {
        // Don't submit tx to the mempool
        return true;
    }

    std::string err_string;
    if (!SubmitTxMemoryPoolAndRelay(*wtx, err_string, true)) {
        WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
        if (broadcast_error) *broadcast_error = err_string;
        // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
        return false;
    }
    if (broadcast_error) broadcast_error->clear();
    return true;
}

bool CWallet::CommitRGBTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm, const RGBTxCommitData& rgb_data, std::string& error)
{
    LOCK(cs_wallet);

    auto fail = [&](std::string message) {
        error = std::move(message);
        return false;
    };

    const uint256 hash = tx->GetHash();
    if (mapWallet.count(hash)) return fail("RGB anchor transaction is already in the wallet");
    if (rgb_data.contract_id.IsNull() || rgb_data.transition_id.IsNull()) return fail("RGB transition id is invalid");
    if (m_rgb_contracts.count(rgb_data.contract_id) == 0) return fail("RGB contract not found");
    if (!IsValidRGBTransitionRecord(rgb_data.transition_record)) return fail("RGB transition metadata is invalid");
    if (!IsValidRGBTransitionProofRecord(rgb_data.transition_proof)) return fail("RGB transition proof is invalid");

    rgb::Transition anchored_transition;
    anchored_transition.contract_id = rgb_data.contract_id;
    anchored_transition.inputs.reserve(rgb_data.transition_proof.inputs.size());
    for (const COutPoint& outpoint : rgb_data.transition_proof.inputs) {
        anchored_transition.inputs.push_back(rgb::Seal{outpoint});
    }
    anchored_transition.outputs.reserve(rgb_data.transition_proof.outputs.size());
    std::vector<COutPoint> proof_output_outpoints;
    proof_output_outpoints.reserve(rgb_data.transition_proof.outputs.size());
    for (const RGBProofAssignment& output : rgb_data.transition_proof.outputs) {
        anchored_transition.outputs.push_back(rgb::Assignment{rgb::Seal{output.outpoint}, output.amount});
        proof_output_outpoints.push_back(output.outpoint);
    }
    if (rgb::TransitionId(anchored_transition) != rgb_data.transition_id) return fail("RGB transition proof id mismatch");
    if (rgb_data.transition_record.inputs != rgb_data.transition_proof.inputs) return fail("RGB transition metadata/proof input mismatch");
    if (rgb_data.transition_record.outputs != proof_output_outpoints) return fail("RGB transition metadata/proof output mismatch");
    const uint256 expected_anchor_commitment = rgb::AnchorCommitment(std::vector<uint256>{rgb_data.transition_id});
    if (rgb_data.transition_record.anchor_commitment != expected_anchor_commitment) return fail("RGB transition anchor commitment mismatch");
    if (!rgb_data.transition_record.anchor_checked) return fail("RGB transition anchor was not checked");
    if (rgb_data.transition_record.anchor_txid != hash) return fail("RGB transition anchor txid mismatch");
    std::string anchor_error;
    if (!rgb::ValidateRGBAnchor(*tx, expected_anchor_commitment, std::vector<rgb::Transition>{anchored_transition}, anchor_error)) {
        return fail("RGB anchor transaction is invalid: " + anchor_error);
    }
    const auto first_anchor = rgb::FirstRGBCommitment(*tx);
    if (!first_anchor || first_anchor->first != rgb_data.transition_record.anchor_vout) {
        return fail("RGB transition anchor vout mismatch");
    }

    const auto transition_key = std::make_pair(rgb_data.contract_id, rgb_data.transition_id);
    if (m_rgb_transitions.count(transition_key) != 0) return fail("RGB transition metadata already exists");
    if (m_rgb_transition_proofs.count(transition_key) != 0) return fail("RGB transition proof already exists");
    for (const auto& [existing_key, existing_record] : m_rgb_transition_proofs) {
        if (existing_key.first == rgb_data.contract_id && existing_record.order == rgb_data.transition_proof.order) {
            return fail("RGB transition proof order already exists");
        }
    }

    const std::set<COutPoint> transition_inputs{rgb_data.transition_record.inputs.begin(), rgb_data.transition_record.inputs.end()};
    const std::set<COutPoint> transition_outputs{rgb_data.transition_record.outputs.begin(), rgb_data.transition_record.outputs.end()};
    if (transition_inputs.size() != rgb_data.transition_record.inputs.size()) return fail("RGB transition inputs contain duplicates");
    if (transition_outputs.size() != rgb_data.transition_record.outputs.size()) return fail("RGB transition outputs contain duplicates");

    std::set<COutPoint> spent_assignments_seen;
    for (const COutPoint& outpoint : rgb_data.spent_assignments) {
        if (!spent_assignments_seen.insert(outpoint).second) return fail("RGB spent assignment list contains duplicates");
        if (!transition_inputs.count(outpoint)) return fail("RGB spent assignment is not a transition input");
        const auto assignment_it = m_rgb_assignments.find(std::make_pair(rgb_data.contract_id, outpoint));
        if (assignment_it == m_rgb_assignments.end()) return fail("RGB spent assignment is not in the wallet");
        if (assignment_it->second.spent) return fail("RGB spent assignment is already marked spent");
    }
    if (spent_assignments_seen != transition_inputs) return fail("RGB spent assignments do not match transition inputs");

    std::set<COutPoint> output_assignments_seen;
    for (const auto& [outpoint, record] : rgb_data.output_assignments) {
        if (!output_assignments_seen.insert(outpoint).second) return fail("RGB output assignment list contains duplicates");
        if (!transition_outputs.count(outpoint)) return fail("RGB output assignment is not a transition output");
        if (record.amount == 0) return fail("RGB output assignment amount is zero");
        const auto assignment_it = m_rgb_assignments.find(std::make_pair(rgb_data.contract_id, outpoint));
        if (assignment_it != m_rgb_assignments.end() &&
            (assignment_it->second.amount != record.amount || assignment_it->second.spent != record.spent)) {
            return fail("RGB output assignment conflicts with existing wallet metadata");
        }
    }

    WalletLogPrintf("CommitRGBTransaction:\n%s", tx->ToString()); // NOLINT(bitcoin-unterminated-logprintf)

    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) return fail("Failed to begin wallet database transaction");

    const int64_t old_order_pos_next = nOrderPosNext;

    std::set<CTxDestination> tx_destinations;
    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        for (const CTxIn& txin : tx->vin) {
            SetSpentKeyState(batch, txin.prevout.hash, txin.prevout.n, true, tx_destinations);
        }
    }

    CWalletTx wtx(tx, TxStateInactive{});
    wtx.mapValue = std::move(mapValue);
    wtx.vOrderForm = std::move(orderForm);
    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    wtx.nTimeReceived = GetTime();
    wtx.nOrderPos = nOrderPosNext++;
    if (!batch.WriteOrderPosNext(nOrderPosNext)) {
        nOrderPosNext = old_order_pos_next;
        batch.TxnAbort();
        return fail("Failed to persist wallet order position");
    }
    wtx.nTimeSmart = ComputeTimeSmart(wtx, /*rescanning_old_block=*/false);

    if (!batch.WriteTx(wtx)) {
        nOrderPosNext = old_order_pos_next;
        batch.TxnAbort();
        return fail("Failed to persist RGB anchor transaction");
    }
    if (!batch.WriteRGBTransition(rgb_data.contract_id, rgb_data.transition_id, rgb_data.transition_record)) {
        nOrderPosNext = old_order_pos_next;
        batch.TxnAbort();
        return fail("Failed to persist RGB transition metadata");
    }
    if (!batch.WriteRGBTransitionProof(rgb_data.contract_id, rgb_data.transition_id, rgb_data.transition_proof)) {
        nOrderPosNext = old_order_pos_next;
        batch.TxnAbort();
        return fail("Failed to persist RGB transition proof");
    }
    for (const COutPoint& outpoint : rgb_data.spent_assignments) {
        RGBOwnedAssignmentRecord updated = m_rgb_assignments.at(std::make_pair(rgb_data.contract_id, outpoint));
        updated.spent = true;
        if (!batch.WriteRGBAssignment(rgb_data.contract_id, outpoint, updated)) {
            nOrderPosNext = old_order_pos_next;
            batch.TxnAbort();
            return fail("Failed to persist RGB spent assignment");
        }
    }
    for (const auto& [outpoint, record] : rgb_data.output_assignments) {
        if (!batch.WriteRGBAssignment(rgb_data.contract_id, outpoint, record)) {
            nOrderPosNext = old_order_pos_next;
            batch.TxnAbort();
            return fail("Failed to persist RGB output assignment");
        }
    }

    if (!batch.TxnCommit()) {
        nOrderPosNext = old_order_pos_next;
        batch.TxnAbort();
        return fail("Failed to commit wallet database transaction");
    }

    const auto [wallet_it, inserted] = mapWallet.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(hash),
        std::forward_as_tuple(tx, TxStateInactive{}));
    assert(inserted);
    CWalletTx& committed_wtx = wallet_it->second;
    committed_wtx.CopyFrom(wtx);
    committed_wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(committed_wtx.nOrderPos, &committed_wtx));
    AddToSpends(committed_wtx);
    MaybeUpdateBirthTime(committed_wtx.GetTxTime());
    MarkDestinationsDirty(tx_destinations);
    committed_wtx.MarkDirty();
    NotifyTransactionChanged(hash, CT_NEW);

    for (const CTxIn& txin : tx->vin) {
        const auto coin_it = mapWallet.find(txin.prevout.hash);
        if (coin_it == mapWallet.end()) continue;
        CWalletTx& coin = coin_it->second;
        coin.MarkDirty();
        NotifyTransactionChanged(coin.GetHash(), CT_UPDATED);
    }

    m_rgb_transitions[transition_key] = rgb_data.transition_record;
    m_rgb_transition_proofs[transition_key] = rgb_data.transition_proof;
    MaybeUpdateBirthTime(rgb_data.transition_record.creation_time > 0 ? rgb_data.transition_record.creation_time : 1);
    for (const COutPoint& outpoint : rgb_data.spent_assignments) {
        m_rgb_assignments[std::make_pair(rgb_data.contract_id, outpoint)].spent = true;
    }
    for (const auto& [outpoint, record] : rgb_data.output_assignments) {
        m_rgb_assignments[std::make_pair(rgb_data.contract_id, outpoint)] = record;
        MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    }

    if (!fBroadcastTransactions) return true;

    std::string err_string;
    if (!SubmitTxMemoryPoolAndRelay(committed_wtx, err_string, true)) {
        WalletLogPrintf("CommitRGBTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
    }
    error.clear();
    return true;
}

DBErrors CWallet::LoadWallet()
{
    LOCK(cs_wallet);

    DBErrors nLoadWalletRet = WalletBatch(GetDatabase()).LoadWallet(this);
    if (nLoadWalletRet == DBErrors::NEED_REWRITE)
    {
        if (GetDatabase().Rewrite("\x04pool"))
        {
            for (const auto& spk_man_pair : m_spk_managers) {
                spk_man_pair.second->RewriteDB();
            }
        }
    }

    if (m_spk_managers.empty()) {
        assert(m_external_spk_managers.empty());
        assert(m_internal_spk_managers.empty());
    }

    return nLoadWalletRet;
}

DBErrors CWallet::ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut)
{
    AssertLockHeld(cs_wallet);
    DBErrors nZapSelectTxRet = WalletBatch(GetDatabase()).ZapSelectTx(vHashIn, vHashOut);
    for (const uint256& hash : vHashOut) {
        const auto& it = mapWallet.find(hash);
        wtxOrdered.erase(it->second.m_it_wtxOrdered);
        for (const auto& txin : it->second.tx->vin)
            mapTxSpends.erase(txin.prevout);
        mapWallet.erase(it);
        NotifyTransactionChanged(hash, CT_DELETED);
    }

    if (nZapSelectTxRet == DBErrors::NEED_REWRITE)
    {
        if (GetDatabase().Rewrite("\x04pool"))
        {
            for (const auto& spk_man_pair : m_spk_managers) {
                spk_man_pair.second->RewriteDB();
            }
        }
    }

    if (nZapSelectTxRet != DBErrors::LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DBErrors::LOAD_OK;
}

bool CWallet::SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& new_purpose)
{
    bool fUpdated = false;
    bool is_mine;
    std::optional<AddressPurpose> purpose;
    {
        LOCK(cs_wallet);
        std::map<CTxDestination, CAddressBookData>::iterator mi = m_address_book.find(address);
        fUpdated = (mi != m_address_book.end() && !mi->second.IsChange());
        m_address_book[address].SetLabel(strName);
        is_mine = IsMine(address) != ISMINE_NO;
        if (new_purpose) { /* update purpose only if requested */
            purpose = m_address_book[address].purpose = new_purpose;
        } else {
            purpose = m_address_book[address].purpose;
        }
    }
    // In very old wallets, address purpose may not be recorded so we derive it from IsMine
    NotifyAddressBookChanged(address, strName, is_mine,
                             purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND),
                             (fUpdated ? CT_UPDATED : CT_NEW));
    if (new_purpose && !batch.WritePurpose(EncodeDestination(address), PurposeToString(*new_purpose)))
        return false;
    return batch.WriteName(EncodeDestination(address), strName);
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose)
{
    WalletBatch batch(GetDatabase());
    return SetAddressBookWithDB(batch, address, strName, purpose);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    WalletBatch batch(GetDatabase());
    {
        LOCK(cs_wallet);
        // If we want to delete receiving addresses, we should avoid calling EraseAddressData because it will delete the previously_spent value. Could instead just erase the label so it becomes a change address, and keep the data.
        // NOTE: This isn't a problem for sending addresses because they don't have any data that needs to be kept.
        // When adding new address data, it should be considered here whether to retain or delete it.
        if (IsMine(address)) {
            WalletLogPrintf("%s called with IsMine address, NOT SUPPORTED. Please report this bug! %s\n", __func__, PACKAGE_BUGREPORT);
            return false;
        }
        // Delete data rows associated with this address
        batch.EraseAddressData(address);
        m_address_book.erase(address);
    }

    NotifyAddressBookChanged(address, "", /*is_mine=*/false, AddressPurpose::SEND, CT_DELETED);

    batch.ErasePurpose(EncodeDestination(address));
    return batch.EraseName(EncodeDestination(address));
}

uint64_t CWallet::GetStakeWeight() const
{
    if (HaveChain()) {
        return chain().getStakeWeight(*this);
    }
    return 0;
}

size_t CWallet::KeypoolCountExternalKeys() const
{
    AssertLockHeld(cs_wallet);

    auto legacy_spk_man = GetLegacyScriptPubKeyMan();
    if (legacy_spk_man) {
        return legacy_spk_man->KeypoolCountExternalKeys();
    }

    unsigned int count = 0;
    for (auto spk_man : m_external_spk_managers) {
        count += spk_man.second->GetKeyPoolSize();
    }

    return count;
}

unsigned int CWallet::GetKeyPoolSize() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        count += spk_man->GetKeyPoolSize();
    }
    return count;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    LOCK(cs_wallet);
    bool res = true;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        res &= spk_man->TopUp(kpSize);
    }
    return res;
}

util::Result<CTxDestination> CWallet::GetNewDestination(const OutputType type, const std::string label)
{
    LOCK(cs_wallet);
    auto spk_man = GetScriptPubKeyMan(type, /*internal=*/false);
    if (!spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    auto op_dest = spk_man->GetNewDestination(type);
    if (op_dest) {
        SetAddressBook(*op_dest, label, AddressPurpose::RECEIVE);
    }

    return op_dest;
}

util::Result<CTxDestination> CWallet::GetNewChangeDestination(const OutputType type)
{
    LOCK(cs_wallet);

    ReserveDestination reservedest(this, type);
    auto op_dest = reservedest.GetReservedDestination(true);
    if (op_dest) reservedest.KeepDestination();

    return op_dest;
}

bool CWallet::LoadQuantumKey(const std::vector<unsigned char>& public_key, const CKeyingMaterial& private_key, int64_t creation_time)
{
    AssertLockHeld(cs_wallet);
    if (!QuantumWalletPrivateKeyMatches(public_key, private_key)) {
        return false;
    }

    const std::vector<unsigned char> witness_program = QuantumWalletProgramForPubkey(public_key);
    const auto existing = m_quantum_keys.find(witness_program);
    if (existing != m_quantum_keys.end()) {
        // If wallet encryption completed after writing cquantumkey but an older
        // build left the plaintext quantumkey behind, keep the encrypted record
        // and ignore this duplicate plaintext copy.
        if (existing->second.IsCrypted() && existing->second.public_key == public_key) {
            return true;
        }
        return false;
    }

    QuantumKeyRecord record;
    record.public_key = public_key;
    record.private_key = private_key;
    record.creation_time = creation_time;
    m_quantum_keys.emplace(witness_program, std::move(record));
    MaybeUpdateBirthTime(creation_time > 0 ? creation_time : 1);
    return true;
}

bool CWallet::LoadCryptedQuantumKey(const std::vector<unsigned char>& public_key, const std::vector<unsigned char>& crypted_private_key, int64_t creation_time)
{
    AssertLockHeld(cs_wallet);
    if (public_key.size() != ML_DSA::PUBLICKEY_BYTES || crypted_private_key.empty()) {
        return false;
    }

    const std::vector<unsigned char> witness_program = QuantumWalletProgramForPubkey(public_key);
    const auto existing = m_quantum_keys.find(witness_program);
    if (existing != m_quantum_keys.end()) {
        if (existing->second.public_key != public_key) {
            return false;
        }
        if (existing->second.IsCrypted()) {
            return false;
        }
        if (!existing->second.private_key.empty()) {
            memory_cleanse(existing->second.private_key.data(), existing->second.private_key.size());
            existing->second.private_key.clear();
        }
        existing->second.crypted_private_key = crypted_private_key;
        existing->second.creation_time = creation_time;
        MaybeUpdateBirthTime(creation_time > 0 ? creation_time : 1);
        return true;
    }

    if (m_quantum_keys.count(witness_program) > 0) {
        return false;
    }

    QuantumKeyRecord record;
    record.public_key = public_key;
    record.crypted_private_key = crypted_private_key;
    record.creation_time = creation_time;
    m_quantum_keys.emplace(witness_program, std::move(record));
    MaybeUpdateBirthTime(creation_time > 0 ? creation_time : 1);
    return true;
}

bool CWallet::LoadQuantumColdStakeDelegation(const std::vector<unsigned char>& witness_program, const QuantumColdStakeDelegationRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (!IsQuantumColdStakeWitnessProgram(QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program)) {
        return false;
    }
    const std::vector<unsigned char> expected = QuantumColdStakeProgramForKeyHashes(record.staker_pubkey_hash, record.owner_pubkey_hash);
    bool matches_record = expected == witness_program;
    if (!matches_record) {
        QuantumStakeTierProgram tier;
        if (DecodeQuantumStakeTierProgram(QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program, tier) &&
            tier.cold_stake) {
            const std::vector<unsigned char> expected_tiered = QuantumTieredColdStakeProgramForKeyHashes(
                record.staker_pubkey_hash,
                record.owner_pubkey_hash,
                tier.state,
                tier.unbonding_blocks,
                tier.unlock_height);
            matches_record = expected_tiered == witness_program;
        }
    }
    if (!matches_record) {
        return false;
    }
    const auto existing = m_quantum_coldstake_delegations.find(witness_program);
    if (existing != m_quantum_coldstake_delegations.end()) {
        return existing->second.staker_pubkey_hash == record.staker_pubkey_hash &&
               existing->second.owner_pubkey_hash == record.owner_pubkey_hash;
    }
    m_quantum_coldstake_delegations.emplace(witness_program, record);
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::HaveQuantumKeyForProgram(const std::vector<unsigned char>& witness_program) const
{
    AssertLockHeld(cs_wallet);
    return m_quantum_keys.count(QuantumWalletKeyLookupProgram(witness_program)) > 0;
}

bool CWallet::GetQuantumKey(const std::vector<unsigned char>& witness_program, std::vector<unsigned char>& public_key, CKeyingMaterial& private_key, bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);
    const std::vector<unsigned char> lookup_program = QuantumWalletKeyLookupProgram(witness_program);
    const auto it = m_quantum_keys.find(lookup_program);
    if (it == m_quantum_keys.end()) {
        error = _("No wallet ML-DSA key matches this quantum witness program");
        return false;
    }

    public_key = it->second.public_key;
    if (it->second.IsCrypted()) {
        if (vMasterKey.empty()) {
            error = _("Wallet is locked");
            return false;
        }
        if (!DecryptSecret(vMasterKey, it->second.crypted_private_key, QuantumWalletKeyIV(lookup_program), private_key)) {
            error = _("Failed to decrypt wallet ML-DSA key");
            return false;
        }
    } else {
        private_key = it->second.private_key;
    }

    if (!QuantumWalletPrivateKeyMatches(public_key, private_key)) {
        error = _("Wallet ML-DSA key failed integrity check");
        return false;
    }
    return true;
}

std::optional<QuantumKeyInfo> CWallet::GetQuantumKeyInfo(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        return std::nullopt;
    }

    const auto it = m_quantum_keys.find(QuantumWalletKeyLookupProgram(witness->GetWitnessProgram()));
    if (it == m_quantum_keys.end()) {
        return std::nullopt;
    }

    QuantumKeyInfo info;
    info.destination = dest;
    info.witness_program = witness->GetWitnessProgram();
    info.public_key = it->second.public_key;
    info.creation_time = it->second.creation_time;
    info.encrypted = it->second.IsCrypted();
    return info;
}

std::vector<QuantumKeyInfo> CWallet::ListQuantumKeyInfos() const
{
    AssertLockHeld(cs_wallet);
    std::vector<QuantumKeyInfo> infos;
    infos.reserve(m_quantum_keys.size() + m_address_book.size());
    std::set<std::vector<unsigned char>> seen_programs;

    // Include wallet-backed quantum address-book aliases first. Tiered staking
    // addresses store the private key under the base quantum program, while
    // the user-visible bonded address lives only in the address book.
    for (const auto& [dest, address_book] : m_address_book) {
        const auto* witness = std::get_if<WitnessUnknown>(&dest);
        if (!witness || !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) continue;

        const auto info = GetQuantumKeyInfo(dest);
        if (!info || !seen_programs.insert(info->witness_program).second) continue;
        infos.push_back(*info);
    }

    // Also return raw stored keys so wallet dumps and diagnostics still include
    // change/private quantum keys that do not have receive-book aliases.
    for (const auto& [witness_program, record] : m_quantum_keys) {
        if (!seen_programs.insert(witness_program).second) continue;
        QuantumKeyInfo info;
        info.destination = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, witness_program};
        info.witness_program = witness_program;
        info.public_key = record.public_key;
        info.creation_time = record.creation_time;
        info.encrypted = record.IsCrypted();
        infos.push_back(std::move(info));
    }
    return infos;
}

std::optional<QuantumColdStakeDelegationInfo> CWallet::GetQuantumColdStakeDelegationInfo(const std::vector<unsigned char>& witness_program) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_quantum_coldstake_delegations.find(witness_program);
    if (it == m_quantum_coldstake_delegations.end()) {
        return std::nullopt;
    }

    QuantumColdStakeDelegationInfo info;
    info.destination = WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program};
    info.witness_program = witness_program;
    info.staker_pubkey_hash = it->second.staker_pubkey_hash;
    info.owner_pubkey_hash = it->second.owner_pubkey_hash;
    info.creation_time = it->second.creation_time;
    info.has_staker_key = HaveQuantumKeyForProgram(VectorForUint256(info.staker_pubkey_hash));
    info.has_owner_key = HaveQuantumKeyForProgram(VectorForUint256(info.owner_pubkey_hash));
    QuantumStakeTierProgram tier;
    if (DecodeQuantumStakeTierProgram(QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program, tier) && tier.tiered) {
        info.tiered = true;
        info.unbonding_blocks = tier.unbonding_blocks;
        info.unlock_height = tier.unlock_height;
    }
    return info;
}

std::optional<QuantumColdStakeDelegationInfo> CWallet::GetQuantumColdStakeDelegationInfo(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumColdStakeWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        return std::nullopt;
    }
    return GetQuantumColdStakeDelegationInfo(witness->GetWitnessProgram());
}

std::vector<QuantumColdStakeDelegationInfo> CWallet::ListQuantumColdStakeDelegationInfos() const
{
    AssertLockHeld(cs_wallet);
    std::vector<QuantumColdStakeDelegationInfo> infos;
    infos.reserve(m_quantum_coldstake_delegations.size());
    for (const auto& [witness_program, record] : m_quantum_coldstake_delegations) {
        auto info = GetQuantumColdStakeDelegationInfo(witness_program);
        if (info) infos.push_back(*info);
    }
    return infos;
}

void CWallet::RecordQuantumRedelegationWins(const CTransaction& tx, int height, WalletBatch& batch)
{
    AssertLockHeld(cs_wallet);
    if (!tx.IsCoinStake() || height <= 0) return;

    for (const CTxOut& txout : tx.vout) {
        CTxDestination dest;
        if (!ExtractDestination(txout.scriptPubKey, dest)) continue;
        const auto info = GetQuantumColdStakeDelegationInfo(dest);
        if (!info || !info->has_owner_key) continue;

        const auto it = m_redelegation_last_win_height.find(info->witness_program);
        if (it != m_redelegation_last_win_height.end() && it->second >= height) continue;
        m_redelegation_last_win_height[info->witness_program] = height;
        batch.WriteQuantumRedelegationLastWinHeight(info->witness_program, height);
    }
}

void CWallet::RecomputeQuantumRedelegationWinHistory(WalletBatch& batch)
{
    AssertLockHeld(cs_wallet);
    std::map<std::vector<unsigned char>, int> rebuilt;

    for (const auto& [_, wtx] : mapWallet) {
        if (!wtx.IsCoinStake()) continue;
        const auto* confirmed = wtx.state<TxStateConfirmed>();
        if (!confirmed || confirmed->confirmed_block_height <= 0) continue;

        for (const CTxOut& txout : wtx.tx->vout) {
            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest)) continue;
            const auto info = GetQuantumColdStakeDelegationInfo(dest);
            if (!info || !info->has_owner_key) continue;
            auto& height = rebuilt[info->witness_program];
            height = std::max(height, confirmed->confirmed_block_height);
        }
    }

    for (const auto& [witness_program, height] : rebuilt) {
        const auto old = m_redelegation_last_win_height.find(witness_program);
        if (old == m_redelegation_last_win_height.end() || old->second != height) {
            batch.WriteQuantumRedelegationLastWinHeight(witness_program, height);
        }
    }
    for (const auto& [witness_program, height] : m_redelegation_last_win_height) {
        if (rebuilt.count(witness_program) == 0) {
            batch.EraseQuantumRedelegationLastWinHeight(witness_program);
        }
    }
    m_redelegation_last_win_height = std::move(rebuilt);
}

bool CWallet::LoadRGBContract(const uint256& contract_id, const RGBContractRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (contract_id.IsNull() || !IsValidRGBContractRecord(record)) {
        return false;
    }
    const auto [it, inserted] = m_rgb_contracts.emplace(contract_id, record);
    if (!inserted) {
        return it->second.ticker == record.ticker &&
               it->second.name == record.name &&
               it->second.total_supply == record.total_supply;
    }
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::LoadRGBAssignment(const uint256& contract_id, const COutPoint& outpoint, const RGBOwnedAssignmentRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (contract_id.IsNull() || m_rgb_contracts.count(contract_id) == 0 || outpoint.IsNull() || record.amount == 0) {
        return false;
    }
    m_rgb_assignments[std::make_pair(contract_id, outpoint)] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::LoadRGBGenesisProof(const uint256& contract_id, const RGBGenesisProofRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (contract_id.IsNull() || m_rgb_contracts.count(contract_id) == 0 || !IsValidRGBGenesisProofRecord(record)) {
        return false;
    }
    const auto [it, inserted] = m_rgb_genesis_proofs.emplace(contract_id, record);
    if (!inserted) return it->second == record;
    return true;
}

bool CWallet::LoadRGBTransition(const uint256& contract_id, const uint256& transition_id, const RGBTransitionRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (contract_id.IsNull() || transition_id.IsNull() || m_rgb_contracts.count(contract_id) == 0 ||
        !IsValidRGBTransitionRecord(record)) {
        return false;
    }
    m_rgb_transitions[std::make_pair(contract_id, transition_id)] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::LoadRGBTransitionProof(const uint256& contract_id, const uint256& transition_id, const RGBTransitionProofRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (contract_id.IsNull() || transition_id.IsNull() || m_rgb_contracts.count(contract_id) == 0 ||
        !IsValidRGBTransitionProofRecord(record)) {
        return false;
    }
    const auto key = std::make_pair(contract_id, transition_id);
    const auto it = m_rgb_transition_proofs.find(key);
    if (it != m_rgb_transition_proofs.end()) return it->second == record;
    for (const auto& [existing_key, existing_record] : m_rgb_transition_proofs) {
        if (existing_key.first == contract_id && existing_record.order == record.order) return false;
    }
    m_rgb_transition_proofs.emplace(key, record);
    return true;
}

bool CWallet::LoadEUTXOState(const COutPoint& outpoint, const EUTXOStateRecord& record)
{
    AssertLockHeld(cs_wallet);
    if (outpoint.IsNull() || record.amount <= 0 || !MoneyRange(record.amount) ||
        record.datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        record.validator_script.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        return false;
    }
    m_eutxo_states[outpoint] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::AddRGBContract(const uint256& contract_id, const RGBContractRecord& record)
{
    LOCK(cs_wallet);
    if (contract_id.IsNull() || !IsValidRGBContractRecord(record)) {
        return false;
    }
    const auto it = m_rgb_contracts.find(contract_id);
    if (it != m_rgb_contracts.end() &&
        (it->second.ticker != record.ticker ||
         it->second.name != record.name ||
         it->second.total_supply != record.total_supply)) {
        return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBContract(contract_id, record)) {
        return false;
    }
    m_rgb_contracts[contract_id] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::AddRGBAssignment(const uint256& contract_id, const COutPoint& outpoint, const RGBOwnedAssignmentRecord& record)
{
    LOCK(cs_wallet);
    if (m_rgb_contracts.count(contract_id) == 0 || contract_id.IsNull() || outpoint.IsNull() || record.amount == 0) {
        return false;
    }
    const auto key = std::make_pair(contract_id, outpoint);
    const auto it = m_rgb_assignments.find(key);
    if (it != m_rgb_assignments.end() &&
        (it->second.amount != record.amount || it->second.spent != record.spent)) {
        return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBAssignment(contract_id, outpoint, record)) {
        return false;
    }
    m_rgb_assignments[key] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::AddRGBGenesisProof(const uint256& contract_id, const RGBGenesisProofRecord& record)
{
    LOCK(cs_wallet);
    if (m_rgb_contracts.count(contract_id) == 0 || contract_id.IsNull() || !IsValidRGBGenesisProofRecord(record)) {
        return false;
    }
    const auto it = m_rgb_genesis_proofs.find(contract_id);
    if (it != m_rgb_genesis_proofs.end() && !(it->second == record)) {
        return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBGenesisProof(contract_id, record)) {
        return false;
    }
    m_rgb_genesis_proofs[contract_id] = record;
    return true;
}

bool CWallet::AddRGBTransition(const uint256& contract_id, const uint256& transition_id, const RGBTransitionRecord& record)
{
    LOCK(cs_wallet);
    if (m_rgb_contracts.count(contract_id) == 0 || contract_id.IsNull() || transition_id.IsNull() ||
        !IsValidRGBTransitionRecord(record)) {
        return false;
    }
    const auto key = std::make_pair(contract_id, transition_id);
    const auto it = m_rgb_transitions.find(key);
    if (it != m_rgb_transitions.end()) {
        if (it->second == record) return true;

        const bool same_state = it->second.inputs == record.inputs && it->second.outputs == record.outputs;
        if (!same_state) return false;

        const bool same_anchor = it->second.anchor_commitment == record.anchor_commitment &&
                                 it->second.anchor_txid == record.anchor_txid &&
                                 it->second.anchor_vout == record.anchor_vout &&
                                 it->second.anchor_checked == record.anchor_checked;
        if (same_anchor || !record.anchor_checked) return true;
        if (it->second.anchor_checked) return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBTransition(contract_id, transition_id, record)) {
        return false;
    }
    m_rgb_transitions[key] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

bool CWallet::AddRGBTransitionProof(const uint256& contract_id, const uint256& transition_id, const RGBTransitionProofRecord& record)
{
    LOCK(cs_wallet);
    if (m_rgb_contracts.count(contract_id) == 0 || contract_id.IsNull() || transition_id.IsNull() ||
        !IsValidRGBTransitionProofRecord(record)) {
        return false;
    }
    const auto key = std::make_pair(contract_id, transition_id);
    const auto it = m_rgb_transition_proofs.find(key);
    if (it != m_rgb_transition_proofs.end()) {
        if (it->second == record) return true;
        return false;
    }
    for (const auto& [existing_key, existing_record] : m_rgb_transition_proofs) {
        if (existing_key.first == contract_id && existing_record.order == record.order) return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBTransitionProof(contract_id, transition_id, record)) {
        return false;
    }
    m_rgb_transition_proofs[key] = record;
    return true;
}

bool CWallet::SetRGBAssignmentSpent(const uint256& contract_id, const COutPoint& outpoint, bool spent, bool& changed)
{
    LOCK(cs_wallet);
    changed = false;
    if (contract_id.IsNull() || m_rgb_contracts.count(contract_id) == 0 || outpoint.IsNull()) return false;

    const auto key = std::make_pair(contract_id, outpoint);
    const auto it = m_rgb_assignments.find(key);
    if (it == m_rgb_assignments.end()) return false;
    if (it->second.spent == spent) return true;

    RGBOwnedAssignmentRecord updated = it->second;
    updated.spent = spent;
    WalletBatch batch(GetDatabase());
    if (!batch.WriteRGBAssignment(contract_id, outpoint, updated)) {
        return false;
    }
    it->second = updated;
    changed = true;
    return true;
}

bool CWallet::AddEUTXOState(const COutPoint& outpoint, const EUTXOStateRecord& record)
{
    LOCK(cs_wallet);
    if (outpoint.IsNull() || record.amount <= 0 || !MoneyRange(record.amount) ||
        record.datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        record.validator_script.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        return false;
    }
    const auto it = m_eutxo_states.find(outpoint);
    if (it != m_eutxo_states.end() &&
        (it->second.amount != record.amount ||
         it->second.datum != record.datum ||
         it->second.validator_script != record.validator_script)) {
        return false;
    }
    WalletBatch batch(GetDatabase());
    if (!batch.WriteEUTXOState(outpoint, record)) {
        return false;
    }
    m_eutxo_states[outpoint] = record;
    MaybeUpdateBirthTime(record.creation_time > 0 ? record.creation_time : 1);
    return true;
}

std::optional<RGBContractRecord> CWallet::GetRGBContract(const uint256& contract_id) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_rgb_contracts.find(contract_id);
    if (it == m_rgb_contracts.end()) return std::nullopt;
    return it->second;
}

std::vector<std::pair<uint256, RGBContractRecord>> CWallet::ListRGBContracts() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::pair<uint256, RGBContractRecord>> records;
    records.reserve(m_rgb_contracts.size());
    for (const auto& entry : m_rgb_contracts) {
        records.push_back(entry);
    }
    return records;
}

std::vector<std::pair<std::pair<uint256, COutPoint>, RGBOwnedAssignmentRecord>> CWallet::ListRGBAssignments() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::pair<std::pair<uint256, COutPoint>, RGBOwnedAssignmentRecord>> records;
    records.reserve(m_rgb_assignments.size());
    for (const auto& entry : m_rgb_assignments) {
        records.push_back(entry);
    }
    return records;
}

std::optional<RGBGenesisProofRecord> CWallet::GetRGBGenesisProof(const uint256& contract_id) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_rgb_genesis_proofs.find(contract_id);
    if (it == m_rgb_genesis_proofs.end()) return std::nullopt;
    return it->second;
}

std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionRecord>> CWallet::ListRGBTransitions() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionRecord>> records;
    records.reserve(m_rgb_transitions.size());
    for (const auto& entry : m_rgb_transitions) {
        records.push_back(entry);
    }
    return records;
}

std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionProofRecord>> CWallet::ListRGBTransitionProofs() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionProofRecord>> records;
    records.reserve(m_rgb_transition_proofs.size());
    for (const auto& entry : m_rgb_transition_proofs) {
        records.push_back(entry);
    }
    return records;
}

std::vector<std::pair<COutPoint, EUTXOStateRecord>> CWallet::ListEUTXOStates() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::pair<COutPoint, EUTXOStateRecord>> records;
    records.reserve(m_eutxo_states.size());
    for (const auto& entry : m_eutxo_states) {
        records.push_back(entry);
    }
    return records;
}

std::set<COutPoint> CWallet::GetProtectedRGBSeals() const
{
    AssertLockHeld(cs_wallet);
    // Outpoints that carry live RGB single-use-seal state (an unspent owned assignment) or EUTXO
    // state. Spending such a UTXO as ordinary coin consumes the single-use seal with no RGB/EUTXO
    // transition and permanently burns the asset, so coin selection and staking must never
    // auto-select them.
    std::set<COutPoint> seals;
    for (const auto& [key, record] : m_rgb_assignments) {
        if (!record.spent) seals.insert(key.second);
    }
    for (const auto& [outpoint, record] : m_eutxo_states) {
        seals.insert(outpoint);
    }
    return seals;
}

void CWallet::ReconcileRGBAssignments()
{
    AssertLockHeld(cs_wallet);
    // Keep each owned RGB assignment's spent flag in sync with the chain. A single-use
    // seal's asset is live iff the seal outpoint is still unspent by a non-abandoned, non-conflicted
    // wallet transaction -- exactly what IsSpent() reports. Without this, a reorged-out, abandoned, or
    // conflicted RGB transfer leaves the input assignment stuck "spent" (or revives a stale one),
    // permanently desyncing the RGB ledger from the chain. Run after every block connect/disconnect
    // and abandon, so the RGB ledger self-heals from the wallet's authoritative tx-state view.
    std::vector<std::pair<uint256, uint256>> stale_transition_keys;
    std::set<std::pair<uint256, COutPoint>> stale_output_assignment_keys;
    for (const auto& [key, record] : m_rgb_transitions) {
        if (!record.anchor_checked || record.anchor_txid.IsNull()) continue;
        const auto wtx_it = mapWallet.find(record.anchor_txid);
        if (wtx_it != mapWallet.end() && !wtx_it->second.isAbandoned() && !wtx_it->second.isConflicted()) continue;
        if (wtx_it == mapWallet.end() && IsRGBAnchorProvenInChainOrMempool(chain(), record.anchor_txid)) continue;
        stale_transition_keys.push_back(key);
        for (const COutPoint& output : record.outputs) {
            stale_output_assignment_keys.emplace(key.first, output);
        }
    }

    std::vector<std::pair<std::pair<uint256, COutPoint>, bool>> updates;
    for (const auto& [key, record] : m_rgb_assignments) {
        if (stale_output_assignment_keys.count(key)) continue;
        const bool chain_spent = IsSpent(key.second);
        if (record.spent != chain_spent) updates.emplace_back(key, chain_spent);
    }
    if (stale_transition_keys.empty() && stale_output_assignment_keys.empty() && updates.empty()) return;

    WalletBatch batch(GetDatabase());
    if (!batch.TxnBegin()) return;

    bool batch_ok{true};
    for (const auto& key : stale_transition_keys) {
        batch_ok &= batch.EraseRGBTransition(key.first, key.second);
        batch_ok &= batch.EraseRGBTransitionProof(key.first, key.second);
    }
    for (const auto& key : stale_output_assignment_keys) {
        if (m_rgb_assignments.count(key)) {
            batch_ok &= batch.EraseRGBAssignment(key.first, key.second);
        }
    }

    std::vector<std::pair<std::pair<uint256, COutPoint>, RGBOwnedAssignmentRecord>> updated_assignments;
    for (const auto& [key, chain_spent] : updates) {
        const auto it = m_rgb_assignments.find(key);
        if (it == m_rgb_assignments.end()) continue;
        RGBOwnedAssignmentRecord updated = it->second;
        updated.spent = chain_spent;
        batch_ok &= batch.WriteRGBAssignment(key.first, key.second, updated);
        updated_assignments.emplace_back(key, updated);
    }
    if (!batch_ok) {
        batch.TxnAbort();
        return;
    }
    if (!batch.TxnCommit()) {
        batch.TxnAbort();
        return;
    }

    for (const auto& key : stale_transition_keys) {
        m_rgb_transitions.erase(key);
        m_rgb_transition_proofs.erase(key);
    }
    for (const auto& key : stale_output_assignment_keys) {
        m_rgb_assignments.erase(key);
    }
    for (const auto& [key, updated] : updated_assignments) {
        const auto it = m_rgb_assignments.find(key);
        if (it != m_rgb_assignments.end()) {
            it->second = updated;
        }
    }
}

bool CWallet::HasPlaintextQuantumKeys() const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [witness_program, record] : m_quantum_keys) {
        if (!record.IsCrypted()) {
            return true;
        }
    }
    return false;
}

bool CWallet::HasCryptedQuantumKeys() const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [witness_program, record] : m_quantum_keys) {
        if (record.IsCrypted()) {
            return true;
        }
    }
    return false;
}

bool CWallet::EncryptQuantumKeys(const CKeyingMaterial& master_key, WalletBatch& batch)
{
    AssertLockHeld(cs_wallet);
    for (auto& [witness_program, record] : m_quantum_keys) {
        if (record.IsCrypted()) {
            continue;
        }
        if (!QuantumWalletPrivateKeyMatches(record.public_key, record.private_key)) {
            return false;
        }

        std::vector<unsigned char> crypted_private_key;
        if (!EncryptSecret(master_key, record.private_key, QuantumWalletKeyIV(witness_program), crypted_private_key)) {
            return false;
        }

        if (!batch.WriteCryptedQuantumKey(record.public_key, crypted_private_key, CKeyMetadata(record.creation_time))) {
            return false;
        }
        if (!record.private_key.empty()) {
            memory_cleanse(record.private_key.data(), record.private_key.size());
            record.private_key.clear();
        }
        record.crypted_private_key = std::move(crypted_private_key);
    }
    return true;
}

bool CWallet::CheckQuantumDecryptionKey(const CKeyingMaterial& master_key) const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [witness_program, record] : m_quantum_keys) {
        if (record.IsCrypted()) {
            CKeyingMaterial private_key;
            if (!DecryptSecret(master_key, record.crypted_private_key, QuantumWalletKeyIV(witness_program), private_key)) {
                return false;
            }
            if (!QuantumWalletPrivateKeyMatches(record.public_key, private_key)) {
                return false;
            }
        } else if (!QuantumWalletPrivateKeyMatches(record.public_key, record.private_key)) {
            return false;
        }
    }
    return true;
}

util::Result<CTxDestination> CWallet::GetNewQuantumDestination(const std::string label)
{
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> generated_private_key;
    if (!ML_DSA::KeyGen(public_key, generated_private_key)) {
        return util::Error{_("Error: ML-DSA key generation failed")};
    }
    CKeyingMaterial private_key(generated_private_key.begin(), generated_private_key.end());
    CleanseVector(generated_private_key);
    auto result = AddQuantumKey(std::vector<unsigned char>(public_key.begin(), public_key.end()), private_key, label, GetTime());
    if (!result) {
        return result;
    }
    return result;
}

util::Result<CTxDestination> CWallet::GetNewTieredQuantumDestination(const std::string label, uint16_t unbonding_blocks)
{
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> generated_private_key;
    if (!ML_DSA::KeyGen(public_key, generated_private_key)) {
        return util::Error{_("Error: ML-DSA key generation failed")};
    }
    CKeyingMaterial private_key(generated_private_key.begin(), generated_private_key.end());
    CleanseVector(generated_private_key);

    auto base_result = AddQuantumKey(std::vector<unsigned char>(public_key.begin(), public_key.end()), private_key, "", GetTime(), /*record_as_receive=*/false);
    if (!base_result) {
        return base_result;
    }

    const std::vector<unsigned char> tiered_program = QuantumTieredMigrationProgramForPubkey(
        public_key, QUANTUM_TIERED_STATE_BONDED, unbonding_blocks, /*unlock_height=*/0);
    const CTxDestination tiered_dest = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, tiered_program};
    {
        LOCK(cs_wallet);
        if (!SetAddressBook(tiered_dest, label, AddressPurpose::RECEIVE)) {
            return util::Error{_("Error: Failed to write address book entry")};
        }
    }
    return tiered_dest;
}

util::Result<CTxDestination> CWallet::GetNewQuantumChangeDestination()
{
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> generated_private_key;
    if (!ML_DSA::KeyGen(public_key, generated_private_key)) {
        return util::Error{_("Error: ML-DSA key generation failed")};
    }
    CKeyingMaterial private_key(generated_private_key.begin(), generated_private_key.end());
    CleanseVector(generated_private_key);
    return AddQuantumKey(std::vector<unsigned char>(public_key.begin(), public_key.end()), private_key, "", GetTime(), /*record_as_receive=*/false);
}

util::Result<CTxDestination> CWallet::AddQuantumKey(const std::vector<unsigned char>& public_key, const CKeyingMaterial& private_key, const std::string& label, int64_t creation_time, bool record_as_receive)
{
    CTxDestination dest;
    bool updated = false;
    bool notify_address_book = false;
    int64_t key_time = creation_time > 0 ? creation_time : GetTime();

    {
        LOCK(cs_wallet);
        if (!HasPrivateKeys() || IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            return util::Error{_("Error: Private keys are disabled for this wallet")};
        }
        if (IsCrypted() && vMasterKey.empty()) {
            return util::Error{_("Error: Please enter the wallet passphrase with walletpassphrase first.")};
        }
        if (m_wallet_unlock_staking_only) {
            return util::Error{_("Error: Wallet is unlocked for staking only.")};
        }
        if (!QuantumWalletPrivateKeyMatches(public_key, private_key)) {
            return util::Error{_("Error: ML-DSA key failed integrity check")};
        }

        const std::vector<unsigned char> witness_program = QuantumWalletProgramForPubkey(public_key);
        dest = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, witness_program};
        const auto existing = m_quantum_keys.find(witness_program);
        if (existing != m_quantum_keys.end()) {
            if (existing->second.public_key != public_key) {
                return util::Error{_("Error: Quantum witness program collision")};
            }
            if (!record_as_receive) {
                return dest;
            }
            if (!SetAddressBook(dest, label, AddressPurpose::RECEIVE)) {
                return util::Error{_("Error: Failed to write address book entry")};
            }
            return dest;
        }

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) {
            return util::Error{_("Error: Failed to begin wallet database transaction")};
        }

        CKeyMetadata key_meta(key_time);
        QuantumKeyRecord record;
        record.public_key = public_key;
        record.creation_time = key_time;

        if (IsCrypted()) {
            if (!EncryptSecret(vMasterKey, private_key, QuantumWalletKeyIV(witness_program), record.crypted_private_key)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to encrypt ML-DSA wallet key")};
            }
            if (!batch.WriteCryptedQuantumKey(record.public_key, record.crypted_private_key, key_meta)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write encrypted ML-DSA wallet key")};
            }
        } else {
            record.private_key = private_key;
            if (!batch.WriteQuantumKey(record.public_key, record.private_key, key_meta)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write ML-DSA wallet key")};
            }
        }

        const uint64_t new_flags = (m_wallet_flags | WALLET_FLAG_QUANTUM_KEYS) & ~WALLET_FLAG_BLANK_WALLET;
        if (!batch.WriteWalletFlags(new_flags)) {
            batch.TxnAbort();
            return util::Error{_("Error: Failed to write wallet flags")};
        }
        const std::string encoded_dest = EncodeDestination(dest);
        if (record_as_receive) {
            if (!batch.WritePurpose(encoded_dest, PurposeToString(AddressPurpose::RECEIVE))) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address purpose")};
            }
            if (!batch.WriteName(encoded_dest, label)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address book entry")};
            }
        }

        if (!batch.TxnCommit()) {
            return util::Error{_("Error: Failed to commit wallet database transaction")};
        }

        m_wallet_flags = new_flags;
        m_quantum_keys.emplace(witness_program, std::move(record));
        MaybeUpdateBirthTime(key_time);

        if (record_as_receive) {
            auto entry = m_address_book.find(dest);
            updated = entry != m_address_book.end() && !entry->second.IsChange();
            CAddressBookData& address_book = m_address_book[dest];
            address_book.SetLabel(label);
            address_book.purpose = AddressPurpose::RECEIVE;
            notify_address_book = true;
        }
    }

    if (notify_address_book) {
        NotifyAddressBookChanged(dest, label, true, AddressPurpose::RECEIVE, updated ? CT_UPDATED : CT_NEW);
    }

    return dest;
}

util::Result<CTxDestination> CWallet::AddQuantumColdStakeDelegation(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey, const std::string& label, int64_t creation_time, bool record_as_receive, uint16_t unbonding_blocks, bool tiered)
{
    if (staker_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        return util::Error{strprintf(_("Error: staking public key must be %u bytes"), ML_DSA::PUBLICKEY_BYTES)};
    }
    if (owner_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        return util::Error{strprintf(_("Error: owner public key must be %u bytes"), ML_DSA::PUBLICKEY_BYTES)};
    }

    const uint256 staker_hash = Uint256FromVector(QuantumMigrationProgramForPubkey(staker_pubkey));
    const uint256 owner_hash = Uint256FromVector(QuantumMigrationProgramForPubkey(owner_pubkey));
    const std::vector<unsigned char> witness_program = tiered
        ? QuantumTieredColdStakeProgramForKeyHashes(staker_hash, owner_hash, QUANTUM_TIERED_STATE_BONDED, unbonding_blocks, /*unlock_height=*/0)
        : QuantumColdStakeProgramForPubkeys(staker_pubkey, owner_pubkey);
    const CTxDestination dest = WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program};
    const int64_t key_time = creation_time > 0 ? creation_time : GetTime();

    bool updated = false;
    bool notify_address_book = false;
    {
        LOCK(cs_wallet);
        const bool has_staker_key = HaveQuantumKeyForProgram(VectorForUint256(staker_hash));
        const bool has_owner_key = HaveQuantumKeyForProgram(VectorForUint256(owner_hash));
        if (!has_staker_key && !has_owner_key) {
            return util::Error{_("Error: This wallet has neither the staking nor owner ML-DSA key for this delegation")};
        }

        QuantumColdStakeDelegationRecord record;
        record.staker_pubkey_hash = staker_hash;
        record.owner_pubkey_hash = owner_hash;
        record.creation_time = key_time;

        const auto existing = m_quantum_coldstake_delegations.find(witness_program);
        if (existing != m_quantum_coldstake_delegations.end()) {
            if (existing->second.staker_pubkey_hash != staker_hash || existing->second.owner_pubkey_hash != owner_hash) {
                return util::Error{_("Error: Quantum cold-stake witness program collision")};
            }
            if (!record_as_receive) {
                return dest;
            }
            if (!SetAddressBook(dest, label, AddressPurpose::RECEIVE)) {
                return util::Error{_("Error: Failed to write address book entry")};
            }
            return dest;
        }

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) {
            return util::Error{_("Error: Failed to begin wallet database transaction")};
        }
        if (!batch.WriteQuantumColdStakeDelegation(witness_program, record)) {
            batch.TxnAbort();
            return util::Error{_("Error: Failed to write quantum cold-stake delegation")};
        }
        const std::string encoded_dest = EncodeDestination(dest);
        if (record_as_receive) {
            if (!batch.WritePurpose(encoded_dest, PurposeToString(AddressPurpose::RECEIVE))) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address purpose")};
            }
            if (!batch.WriteName(encoded_dest, label)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address book entry")};
            }
        }
        if (!batch.TxnCommit()) {
            return util::Error{_("Error: Failed to commit wallet database transaction")};
        }

        m_quantum_coldstake_delegations.emplace(witness_program, record);
        MaybeUpdateBirthTime(key_time);

        if (record_as_receive) {
            auto entry = m_address_book.find(dest);
            updated = entry != m_address_book.end() && !entry->second.IsChange();
            CAddressBookData& address_book = m_address_book[dest];
            address_book.SetLabel(label);
            address_book.purpose = AddressPurpose::RECEIVE;
            notify_address_book = true;
        }
    }

    if (notify_address_book) {
        NotifyAddressBookChanged(dest, label, true, AddressPurpose::RECEIVE, updated ? CT_UPDATED : CT_NEW);
    }
    return dest;
}

util::Result<CTxDestination> CWallet::AddQuantumColdStakeDelegationForKeyHashes(const uint256& staker_pubkey_hash, const uint256& owner_pubkey_hash, const std::string& label, int64_t creation_time, uint16_t unbonding_blocks, uint32_t unlock_height, unsigned char state, bool record_as_receive)
{
    if (state != QUANTUM_TIERED_STATE_BONDED && state != QUANTUM_TIERED_STATE_UNBONDING) {
        return util::Error{_("Error: Invalid cold-stake tier state")};
    }
    if (state == QUANTUM_TIERED_STATE_BONDED && unlock_height != 0) {
        return util::Error{_("Error: Bonded cold-stake records cannot have an unlock height")};
    }
    if (state == QUANTUM_TIERED_STATE_UNBONDING && unlock_height == 0) {
        return util::Error{_("Error: Unbonding cold-stake records require an unlock height")};
    }

    const std::vector<unsigned char> witness_program = QuantumTieredColdStakeProgramForKeyHashes(
        staker_pubkey_hash,
        owner_pubkey_hash,
        state,
        unbonding_blocks,
        unlock_height);
    const CTxDestination dest = WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, witness_program};
    const int64_t key_time = creation_time > 0 ? creation_time : GetTime();

    bool updated = false;
    bool notify_address_book = false;
    {
        LOCK(cs_wallet);
        const bool has_staker_key = HaveQuantumKeyForProgram(VectorForUint256(staker_pubkey_hash));
        const bool has_owner_key = HaveQuantumKeyForProgram(VectorForUint256(owner_pubkey_hash));
        if (!has_staker_key && !has_owner_key) {
            return util::Error{_("Error: This wallet has neither the staking nor owner ML-DSA key for this delegation")};
        }

        QuantumColdStakeDelegationRecord record;
        record.staker_pubkey_hash = staker_pubkey_hash;
        record.owner_pubkey_hash = owner_pubkey_hash;
        record.creation_time = key_time;

        const auto existing = m_quantum_coldstake_delegations.find(witness_program);
        if (existing != m_quantum_coldstake_delegations.end()) {
            if (existing->second.staker_pubkey_hash != staker_pubkey_hash || existing->second.owner_pubkey_hash != owner_pubkey_hash) {
                return util::Error{_("Error: Quantum cold-stake witness program collision")};
            }
            if (!record_as_receive) {
                return dest;
            }
            if (!SetAddressBook(dest, label, AddressPurpose::RECEIVE)) {
                return util::Error{_("Error: Failed to write address book entry")};
            }
            return dest;
        }

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) {
            return util::Error{_("Error: Failed to begin wallet database transaction")};
        }
        if (!batch.WriteQuantumColdStakeDelegation(witness_program, record)) {
            batch.TxnAbort();
            return util::Error{_("Error: Failed to write quantum cold-stake delegation")};
        }
        const std::string encoded_dest = EncodeDestination(dest);
        if (record_as_receive) {
            if (!batch.WritePurpose(encoded_dest, PurposeToString(AddressPurpose::RECEIVE))) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address purpose")};
            }
            if (!batch.WriteName(encoded_dest, label)) {
                batch.TxnAbort();
                return util::Error{_("Error: Failed to write address book entry")};
            }
        }
        if (!batch.TxnCommit()) {
            return util::Error{_("Error: Failed to commit wallet database transaction")};
        }

        m_quantum_coldstake_delegations.emplace(witness_program, record);
        MaybeUpdateBirthTime(key_time);

        if (record_as_receive) {
            auto entry = m_address_book.find(dest);
            updated = entry != m_address_book.end() && !entry->second.IsChange();
            CAddressBookData& address_book = m_address_book[dest];
            address_book.SetLabel(label);
            address_book.purpose = AddressPurpose::RECEIVE;
            notify_address_book = true;
        }
    }

    if (notify_address_book) {
        NotifyAddressBookChanged(dest, label, true, AddressPurpose::RECEIVE, updated ? CT_UPDATED : CT_NEW);
    }
    return dest;
}

std::optional<int64_t> CWallet::GetOldestKeyPoolTime() const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) {
        return std::nullopt;
    }

    std::optional<int64_t> oldest_key{std::numeric_limits<int64_t>::max()};
    for (const auto& spk_man_pair : m_spk_managers) {
        oldest_key = std::min(oldest_key, spk_man_pair.second->GetOldestKeyPoolTime());
    }
    return oldest_key;
}

void CWallet::MarkDestinationsDirty(const std::set<CTxDestination>& destinations) {
    for (auto& entry : mapWallet) {
        CWalletTx& wtx = entry.second;
        if (wtx.m_is_cache_empty) continue;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            CTxDestination dst;
            if (ExtractDestination(wtx.tx->vout[i].scriptPubKey, dst) && destinations.count(dst)) {
                wtx.MarkDirty();
                break;
            }
        }
    }
}

void CWallet::ForEachAddrBookEntry(const ListAddrBookFunc& func) const
{
    AssertLockHeld(cs_wallet);
    for (const std::pair<const CTxDestination, CAddressBookData>& item : m_address_book) {
        const auto& entry = item.second;
        func(item.first, entry.GetLabel(), entry.IsChange(), entry.purpose);
    }
}

std::vector<CTxDestination> CWallet::ListAddrBookAddresses(const std::optional<AddrBookFilter>& _filter) const
{
    AssertLockHeld(cs_wallet);
    std::vector<CTxDestination> result;
    AddrBookFilter filter = _filter ? *_filter : AddrBookFilter();
    ForEachAddrBookEntry([&result, &filter](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        // Filter by change
        if (filter.ignore_change && is_change) return;
        // Filter by label
        if (filter.m_op_label && *filter.m_op_label != label) return;
        // All good
        result.emplace_back(dest);
    });
    return result;
}

std::set<std::string> CWallet::ListAddrBookLabels(const std::optional<AddressPurpose> purpose) const
{
    AssertLockHeld(cs_wallet);
    std::set<std::string> label_set;
    ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label,
                             bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (!purpose || purpose == _purpose) {
            label_set.insert(_label);
        }
    });
    return label_set;
}

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    m_spk_man = pwallet->GetScriptPubKeyMan(type, internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        CKeyPool keypool;
        int64_t index;
        auto op_address = m_spk_man->GetReservedDestination(type, internal, index, keypool);
        if (!op_address) return op_address;
        nIndex = index;
        address = *op_address;
        fInternal = keypool.fInternal;
    }
    return address;
}

void ReserveDestination::KeepDestination()
{
    if (nIndex != -1) {
        m_spk_man->KeepDestination(nIndex, type);
    }
    nIndex = -1;
    address = CNoDestination();
}

void ReserveDestination::ReturnDestination()
{
    if (nIndex != -1) {
        m_spk_man->ReturnDestination(nIndex, fInternal, address);
    }
    nIndex = -1;
    address = CNoDestination();
}

bool CWallet::DisplayAddress(const CTxDestination& dest)
{
    CScript scriptPubKey = GetScriptForDestination(dest);
    for (const auto& spk_man : GetScriptPubKeyMans(scriptPubKey)) {
        auto signer_spk_man = dynamic_cast<ExternalSignerScriptPubKeyMan *>(spk_man);
        if (signer_spk_man == nullptr) {
            continue;
        }
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();
        return signer_spk_man->DisplayAddress(scriptPubKey, signer);
    }
    return false;
}

bool CWallet::LockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    setLockedCoins.insert(output);
    if (batch) {
        return batch->WriteLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    bool was_locked = setLockedCoins.erase(output);
    if (batch && was_locked) {
        return batch->EraseLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet);
    bool success = true;
    WalletBatch batch(GetDatabase());
    for (auto it = setLockedCoins.begin(); it != setLockedCoins.end(); ++it) {
        success &= batch.EraseLockedUTXO(*it);
    }
    setLockedCoins.clear();
    return success;
}

bool CWallet::IsLockedCoin(const COutPoint& output) const
{
    AssertLockHeld(cs_wallet);
    return setLockedCoins.count(output) > 0;
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet);
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const {
    AssertLockHeld(cs_wallet);
    mapKeyBirth.clear();

    // map in which we'll infer heights of other keys
    std::map<CKeyID, const TxStateConfirmed*> mapKeyFirstBlock;
    TxStateConfirmed max_confirm{uint256{}, /*height=*/-1, /*index=*/-1};
    max_confirm.confirmed_block_height = GetLastBlockHeight() > 144 ? GetLastBlockHeight() - 144 : 0; // the tip can be reorganized; use a 144-block safety margin
    CHECK_NONFATAL(chain().findAncestorByHeight(GetLastBlockHash(), max_confirm.confirmed_block_height, FoundBlock().hash(max_confirm.confirmed_block_hash)));

    {
        LegacyScriptPubKeyMan* spk_man = GetLegacyScriptPubKeyMan();
        assert(spk_man != nullptr);
        LOCK(spk_man->cs_KeyStore);

        // get birth times for keys with metadata
        for (const auto& entry : spk_man->mapKeyMetadata) {
            if (entry.second.nCreateTime) {
                mapKeyBirth[entry.first] = entry.second.nCreateTime;
            }
        }

        // Prepare to infer birth heights for keys without metadata
        for (const CKeyID &keyid : spk_man->GetKeys()) {
            if (mapKeyBirth.count(keyid) == 0)
                mapKeyFirstBlock[keyid] = &max_confirm;
        }

        // if there are no such keys, we're done
        if (mapKeyFirstBlock.empty())
            return;

        // find first block that affects those keys, if there are any left
        for (const auto& entry : mapWallet) {
            // iterate over all wallet transactions...
            const CWalletTx &wtx = entry.second;
            if (auto* conf = wtx.state<TxStateConfirmed>()) {
                // ... which are already in a block
                for (const CTxOut &txout : wtx.tx->vout) {
                    // iterate over all their outputs
                    for (const auto &keyid : GetAffectedKeys(txout.scriptPubKey, *spk_man)) {
                        // ... and all their affected keys
                        auto rit = mapKeyFirstBlock.find(keyid);
                        if (rit != mapKeyFirstBlock.end() && conf->confirmed_block_height < rit->second->confirmed_block_height) {
                            rit->second = conf;
                        }
                    }
                }
            }
        }
    }

    // Extract block timestamps for those keys
    for (const auto& entry : mapKeyFirstBlock) {
        int64_t block_time;
        CHECK_NONFATAL(chain().findBlock(entry.second->confirmed_block_hash, FoundBlock().time(block_time)));
        mapKeyBirth[entry.first] = block_time - TIMESTAMP_WINDOW; // block times can be 2h off
    }
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a transaction during a rescanning process, assign all its
 *   (not already known) transactions' timestamps to the block time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const
{
    std::optional<uint256> block_hash;
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        block_hash = conf->confirmed_block_hash;
    } else if (auto* conf = wtx.state<TxStateConflicted>()) {
        block_hash = conf->conflicting_block_hash;
    }

    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (block_hash) {
        int64_t blocktime;
        int64_t block_max_time;
        if (chain().findBlock(*block_hash, FoundBlock().time(blocktime).maxTime(block_max_time))) {
            if (rescanning_old_block) {
                nTimeSmart = block_max_time;
            } else {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;

                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300;
                const TxItems& txOrdered = wtxOrdered;
                for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                    CWalletTx* const pwtx = it->second;
                    if (pwtx == &wtx) {
                        continue;
                    }
                    int64_t nSmartTime;
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow) {
                            latestNow = nSmartTime;
                        }
                        break;
                    }
                }

                nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), block_hash->ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used)
{
    if (std::get_if<CNoDestination>(&dest))
        return false;

    if (!used) {
        if (auto* data{common::FindKey(m_address_book, dest)}) data->previously_spent = false;
        return batch.WriteAddressPreviouslySpent(dest, false);
    }

    LoadAddressPreviouslySpent(dest);
    return batch.WriteAddressPreviouslySpent(dest, true);
}

void CWallet::LoadAddressPreviouslySpent(const CTxDestination& dest)
{
    m_address_book[dest].previously_spent = true;
}

void CWallet::LoadAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& request)
{
    m_address_book[dest].receive_requests[id] = request;
}

bool CWallet::IsAddressPreviouslySpent(const CTxDestination& dest) const
{
    if (auto* data{common::FindKey(m_address_book, dest)}) return data->previously_spent;
    return false;
}

std::vector<std::string> CWallet::GetAddressReceiveRequests() const
{
    std::vector<std::string> values;
    for (const auto& [dest, entry] : m_address_book) {
        for (const auto& [id, request] : entry.receive_requests) {
            values.emplace_back(request);
        }
    }
    return values;
}

bool CWallet::SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value)
{
    if (!batch.WriteAddressReceiveRequest(dest, id, value)) return false;
    m_address_book[dest].receive_requests[id] = value;
    return true;
}

bool CWallet::EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id)
{
    if (!batch.EraseAddressReceiveRequest(dest, id)) return false;
    m_address_book[dest].receive_requests.erase(id);
    return true;
}

std::unique_ptr<WalletDatabase> MakeWalletDatabase(const std::string& name, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error_string)
{
    // Do some checking on wallet path. It should be either a:
    //
    // 1. Path where a directory can be created.
    // 2. Path to an existing directory.
    // 3. Path to a symlink to a directory.
    // 4. For backwards compatibility, the name of a data file in -walletdir.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(name));
    fs::file_type path_type = fs::symlink_status(wallet_path).type();
    if (!(path_type == fs::file_type::not_found || path_type == fs::file_type::directory ||
          (path_type == fs::file_type::symlink && fs::is_directory(wallet_path)) ||
          (path_type == fs::file_type::regular && fs::PathFromString(name).filename() == fs::PathFromString(name)))) {
        error_string = Untranslated(strprintf(
              "Invalid -wallet path '%s'. -wallet path should point to a directory where wallet.dat and "
              "database/log.?????????? files can be stored, a location where such a directory could be created, "
              "or (for backwards compatibility) the name of an existing data file in -walletdir (%s)",
              name, fs::quoted(fs::PathToString(GetWalletDir()))));
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    return MakeDatabase(wallet_path, options, status, error_string);
}

std::shared_ptr<CWallet> CWallet::Create(WalletContext& context, const std::string& name, std::unique_ptr<WalletDatabase> database, uint64_t wallet_creation_flags, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    ArgsManager& args = *Assert(context.args);
    const std::string& walletFile = database->Filename();

    const auto start{SteadyClock::now()};
    // TODO: Can't use std::make_shared because we need a custom deleter but
    // should be possible to use std::allocate_shared.
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, name, std::move(database)), ReleaseWallet);
    walletInstance->m_keypool_size = std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{1});
    walletInstance->m_notify_tx_changed_script = args.GetArg("-walletnotify", "");

    // Load wallet
    bool rescan_required = false;
    DBErrors nLoadWalletRet = walletInstance->LoadWallet();
    if (nLoadWalletRet != DBErrors::LOAD_OK) {
        if (nLoadWalletRet == DBErrors::CORRUPT) {
            error = strprintf(_("Error loading %s: Wallet corrupted"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NONCRITICAL_ERROR)
        {
            warnings.push_back(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                           " or address metadata may be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DBErrors::TOO_NEW) {
            error = strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, PACKAGE_NAME);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED) {
            error = strprintf(_("Error loading %s: External signer wallet being loaded without external signer support compiled"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NEED_REWRITE)
        {
            error = strprintf(_("Wallet needed to be rewritten: restart %s to complete"), PACKAGE_NAME);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::NEED_RESCAN) {
            warnings.push_back(strprintf(_("Error reading %s! Transaction data may be missing or incorrect."
                                           " Rescanning wallet."), walletFile));
            rescan_required = true;
        } else if (nLoadWalletRet == DBErrors::UNKNOWN_DESCRIPTOR) {
            error = strprintf(_("Unrecognized descriptor found. Loading wallet %s\n\n"
                                "The wallet might had been created on a newer version.\n"
                                "Please try running the latest software version.\n"), walletFile);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::UNEXPECTED_LEGACY_ENTRY) {
            error = strprintf(_("Unexpected legacy entry in descriptor wallet found. Loading wallet %s\n\n"
                                "The wallet might have been tampered with or created with malicious intent.\n"), walletFile);
            return nullptr;
        } else {
            error = strprintf(_("Error loading %s"), walletFile);
            return nullptr;
        }
    }

    // This wallet is in its first run if there are no ScriptPubKeyMans and it isn't blank or no privkeys
    const bool fFirstRun = walletInstance->m_spk_managers.empty() &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        walletInstance->SetMinVersion(FEATURE_LATEST);

        walletInstance->InitWalletFlags(wallet_creation_flags);

        // Only create LegacyScriptPubKeyMan when not descriptor wallet
        if (!walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            walletInstance->SetupLegacyScriptPubKeyMan();
        }

        if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) || !(wallet_creation_flags & (WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET))) {
            LOCK(walletInstance->cs_wallet);
            if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                walletInstance->SetupDescriptorScriptPubKeyMans();
                // SetupDescriptorScriptPubKeyMans already calls SetupGeneration for us so we don't need to call SetupGeneration separately
            } else {
                // Legacy wallets need SetupGeneration here.
                for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
                    if (!spk_man->SetupGeneration()) {
                        error = _("Unable to generate initial keys");
                        return nullptr;
                    }
                }
            }
        }

        if (chain) {
            walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain->getTipLocator());
        }
    } else if (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
        // Make it impossible to disable private keys after creation
        error = strprintf(_("Error loading %s: Private keys can only be disabled during creation"), walletFile);
        return nullptr;
    } else if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
            if (spk_man->HavePrivateKeys()) {
                warnings.push_back(strprintf(_("Warning: Private keys detected in wallet {%s} with disabled private keys"), walletFile));
                break;
            }
        }
    }

    if (!args.GetArg("-addresstype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-addresstype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown address type '%s'"), args.GetArg("-addresstype", ""));
            return nullptr;
        }
        walletInstance->m_default_address_type = parsed.value();
    }

    if (!args.GetArg("-changetype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-changetype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown change type '%s'"), args.GetArg("-changetype", ""));
            return nullptr;
        }
        walletInstance->m_default_change_type = parsed.value();
    }

    if (args.IsArgSet("-maxapsfee")) {
        const std::string max_aps_fee{args.GetArg("-maxapsfee", "")};
        if (max_aps_fee == "-1") {
            walletInstance->m_max_aps_fee = -1;
        } else if (std::optional<CAmount> max_fee = ParseMoney(max_aps_fee)) {
            if (max_fee.value() > HIGH_APS_FEE) {
                warnings.push_back(AmountHighWarn("-maxapsfee") + Untranslated(" ") +
                                  _("This is the maximum transaction fee you pay (in addition to the normal fee) to prioritize partial spend avoidance over regular coin selection."));
            }
            walletInstance->m_max_aps_fee = max_fee.value();
        } else {
            error = AmountErrMsg("maxapsfee", max_aps_fee);
            return nullptr;
        }
    }

    if (args.IsArgSet("-discardfee")) {
        std::optional<CAmount> discard_fee = ParseMoney(args.GetArg("-discardfee", ""));
        if (!discard_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-discardfee", args.GetArg("-discardfee", ""));
            return nullptr;
        } else if (discard_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-discardfee") + Untranslated(" ") +
                               _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        walletInstance->m_discard_rate = CFeeRate{discard_fee.value()};
    }

    if (args.IsArgSet("-paytxfee")) {
        std::optional<CAmount> pay_tx_fee = ParseMoney(args.GetArg("-paytxfee", ""));
        if (!pay_tx_fee) {
            error = AmountErrMsg("paytxfee", args.GetArg("-paytxfee", ""));
            return nullptr;
        } else if (pay_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
                               _("This is the transaction fee you will pay if you send a transaction.");
        }

        walletInstance->m_pay_tx_fee = CFeeRate{pay_tx_fee.value(), 1000};

        if (chain && walletInstance->m_pay_tx_fee < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least %s)"),
                "-paytxfee", args.GetArg("-paytxfee", ""), chain->relayMinFee().ToString());
            return nullptr;
        }
    }

    if (args.IsArgSet("-maxtxfee")) {
        std::optional<CAmount> max_fee = ParseMoney(args.GetArg("-maxtxfee", ""));
        if (!max_fee) {
            error = AmountErrMsg("maxtxfee", args.GetArg("-maxtxfee", ""));
            return nullptr;
        } else if (max_fee.value() > HIGH_MAX_TX_FEE) {
            warnings.push_back(strprintf(_("%s is set very high! Fees this large could be paid on a single transaction."), "-maxtxfee"));
        }

        if (chain && CFeeRate{max_fee.value(), 1000} < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                "-maxtxfee", args.GetArg("-maxtxfee", ""), chain->relayMinFee().ToString());
            return nullptr;
        }

        walletInstance->m_default_max_tx_fee = max_fee.value();
    }

    if (args.IsArgSet("-consolidatefeerate")) {
        if (std::optional<CAmount> consolidate_feerate = ParseMoney(args.GetArg("-consolidatefeerate", ""))) {
            walletInstance->m_consolidate_feerate = CFeeRate(*consolidate_feerate);
        } else {
            error = AmountErrMsg("consolidatefeerate", args.GetArg("-consolidatefeerate", ""));
            return nullptr;
        }
    }

    if (chain && chain->relayMinFee().GetFeePerK() > HIGH_TX_FEE_PER_KB) {
        warnings.push_back(AmountHighWarn("-minrelaytxfee") + Untranslated(" ") +
                           _("The wallet will avoid paying less than the minimum relay fee."));
    }

    walletInstance->m_spend_zero_conf_change = args.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);

    std::optional<CAmount> min_staking_amount = ParseMoney(gArgs.GetArg("-minstakingamount", FormatMoney(DEFAULT_MIN_STAKING_AMOUNT)));
    walletInstance->m_min_staking_amount = min_staking_amount.value_or(DEFAULT_MIN_STAKING_AMOUNT);

    std::optional<CAmount> reserve_balance = ParseMoney(gArgs.GetArg("-reservebalance", FormatMoney(DEFAULT_RESERVE_BALANCE)));
    walletInstance->m_reserve_balance = reserve_balance.value_or(DEFAULT_RESERVE_BALANCE);

    const int64_t donation_arg = args.GetIntArg("-donatetodevfund", DEFAULT_DONATION_PERCENTAGE);
    const unsigned int donation_percentage = donation_arg <= 0
                                                 ? MIN_DONATION_PERCENTAGE
                                                 : static_cast<unsigned int>(std::min<int64_t>(donation_arg, MAX_DONATION_PERCENTAGE));
    walletInstance->m_donation_percentage = donation_percentage;

    walletInstance->WalletLogPrintf("Wallet completed loading in %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    // Cache the first key time
    std::optional<int64_t> time_first_key;
    for (auto spk_man : walletInstance->GetAllScriptPubKeyMans()) {
        int64_t time = spk_man->GetTimeFirstKey();
        if (!time_first_key || time < *time_first_key) time_first_key = time;
    }
    if (time_first_key) walletInstance->MaybeUpdateBirthTime(*time_first_key);

    if (chain && !AttachChain(walletInstance, *chain, rescan_required, error, warnings)) {
        return nullptr;
    }

    {
        LOCK(walletInstance->cs_wallet);
        walletInstance->SetBroadcastTransactions(args.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));
        walletInstance->WalletLogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        walletInstance->WalletLogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        walletInstance->WalletLogPrintf("m_address_book.size() = %u\n",  walletInstance->m_address_book.size());
    }

    return walletInstance;
}

bool CWallet::AttachChain(const std::shared_ptr<CWallet>& walletInstance, interfaces::Chain& chain, const bool rescan_required, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    LOCK(walletInstance->cs_wallet);
    // allow setting the chain if it hasn't been set already but prevent changing it
    assert(!walletInstance->m_chain || walletInstance->m_chain == &chain);
    walletInstance->m_chain = &chain;

    // Unless allowed, ensure wallet files are not reused across chains:
    if (!gArgs.GetBoolArg("-walletcrosschain", DEFAULT_WALLETCROSSCHAIN)) {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator) && locator.vHave.size() > 0 && chain.getHeight()) {
            // Wallet is assumed to be from another chain, if genesis block in the active
            // chain differs from the genesis block known to the wallet.
            if (chain.getBlockHash(0) != locator.vHave.back()) {
                error = Untranslated("Wallet files should not be reused across chains. Restart blackcoind with -walletcrosschain to override.");
                return false;
            }
        }
    }

    // Register wallet with validationinterface. It's done before rescan to avoid
    // missing block connections between end of rescan and validation subscribing.
    // Because of wallet lock being hold, block connection notifications are going to
    // be pending on the validation-side until lock release. It's likely to have
    // block processing duplicata (if rescan block range overlaps with notification one)
    // but we guarantee at least than wallet state is correct after notifications delivery.
    // However, chainStateFlushed notifications are ignored until the rescan is finished
    // so that in case of a shutdown event, the rescan will be repeated at the next start.
    // This is temporary until rescan and notifications delivery are unified under same
    // interface.
    walletInstance->m_attaching_chain = true; //ignores chainStateFlushed notifications
    walletInstance->m_chain_notifications_handler = walletInstance->chain().handleNotifications(walletInstance);

    // If rescan_required = true, rescan_height remains equal to 0
    int rescan_height = 0;
    if (!rescan_required)
    {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator)) {
            if (const std::optional<int> fork_height = chain.findLocatorFork(locator)) {
                rescan_height = *fork_height;
            }
        }
    }

    const std::optional<int> tip_height = chain.getHeight();
    if (tip_height) {
        walletInstance->m_last_block_processed = chain.getBlockHash(*tip_height);
        walletInstance->m_last_block_processed_height = *tip_height;
    } else {
        walletInstance->m_last_block_processed.SetNull();
        walletInstance->m_last_block_processed_height = -1;
    }

    if (tip_height && *tip_height != rescan_height)
    {
        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        std::optional<int64_t> time_first_key = walletInstance->m_birth_time.load();
        if (time_first_key) {
            FoundBlock found = FoundBlock().height(rescan_height);
            chain.findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height, found);
            if (!found.found) {
                // We were unable to find a block that had a time more recent than our earliest timestamp
                // or a height higher than the wallet was synced to, indicating that the wallet is newer than the
                // current chain tip. Skip rescanning in this case.
                rescan_height = *tip_height;
            }
        }

        /*
        // Technically we could execute the code below in any case, but performing the
        // `while` loop below can make startup very slow, so only check blocks on disk
        // if necessary.
        if (chain.havePruned() || chain.hasAssumedValidChain()) {
            int block_height = *tip_height;
            while (block_height > 0 && chain.haveBlockOnDisk(block_height - 1) && rescan_height != block_height) {
                --block_height;
            }

            if (rescan_height != block_height) {
                // We can't rescan beyond blocks we don't have data for, stop and throw an error.
                // This might happen if a user uses an old wallet within a pruned node
                // or if they ran -disablewallet for a longer time, then decided to re-enable
                // Exit early and print an error.
                // It also may happen if an assumed-valid chain is in use and therefore not
                // all block data is available.
                // If a block is pruned after this check, we will load the wallet,
                // but fail the rescan with a generic error.

                error = chain.havePruned() ?
                     _("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)") :
                     strprintf(_(
                        "Error loading wallet. Wallet requires blocks to be downloaded, "
                        "and software does not currently support loading wallets while "
                        "blocks are being downloaded out of order when using assumeutxo "
                        "snapshots. Wallet should be able to load successfully after "
                        "node sync reaches height %s"), block_height);
                return false;
            }
        }
        */

        chain.initMessage(_("Rescanning…").translated);
        walletInstance->WalletLogPrintf("Rescanning last %i blocks (from block %i)...\n", *tip_height - rescan_height, rescan_height);

        {
            WalletRescanReserver reserver(*walletInstance);
            if (!reserver.reserve() || (ScanResult::SUCCESS != walletInstance->ScanForWalletTransactions(chain.getBlockHash(rescan_height), rescan_height, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/true).status)) {
                error = _("Failed to rescan the wallet during initialization");
                return false;
            }
        }
        walletInstance->m_attaching_chain = false;
        walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain.getTipLocator());
        walletInstance->GetDatabase().IncrementUpdateCounter();
    }
    walletInstance->m_attaching_chain = false;

    return true;
}

const CAddressBookData* CWallet::FindAddressBookEntry(const CTxDestination& dest, bool allow_change) const
{
    const auto& address_book_it = m_address_book.find(dest);
    if (address_book_it == m_address_book.end()) return nullptr;
    if ((!allow_change) && address_book_it->second.IsChange()) {
        return nullptr;
    }
    return &address_book_it->second;
}

bool CWallet::UpgradeWallet(int version, bilingual_str& error)
{
    int prev_version = GetVersion();
    if (version == 0) {
        WalletLogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
        version = FEATURE_LATEST;
    } else {
        WalletLogPrintf("Allowing wallet upgrade up to %i\n", version);
    }
    if (version < prev_version) {
        error = strprintf(_("Cannot downgrade wallet from version %i to version %i. Wallet version unchanged."), prev_version, version);
        return false;
    }

    LOCK(cs_wallet);

    // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
    if (!CanSupportFeature(FEATURE_HD_SPLIT) && version >= FEATURE_HD_SPLIT && version < FEATURE_PRE_SPLIT_KEYPOOL) {
        error = strprintf(_("Cannot upgrade a non HD split wallet from version %i to version %i without upgrading to support pre-split keypool. Please use version %i or no version specified."), prev_version, version, FEATURE_PRE_SPLIT_KEYPOOL);
        return false;
    }

    // Permanently upgrade to the version
    SetMinVersion(GetClosestWalletFeature(version));

    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->Upgrade(prev_version, version, error)) {
            return false;
        }
    }
    return true;
}

void CWallet::postInitProcess()
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

    // Update wallet transactions with current mempool transactions.
    WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));

    // Start mining proof-of-stake blocks in the background unless the caller
    // wants explicit staking control.
    if (gArgs.GetBoolArg("-autostartstaking", true)) {
        StartStake();
    }
}

bool CWallet::BackupWallet(const std::string& strDest) const
{
    return GetDatabase().Backup(strDest);
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
    fInternal = false;
    m_pre_split = false;
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
    fInternal = internalIn;
    m_pre_split = false;
}

int CWallet::GetTxDepthInMainChain(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        return GetLastBlockHeight() - conf->confirmed_block_height + 1;
    } else if (auto* conf = wtx.state<TxStateConflicted>()) {
        return -1 * (GetLastBlockHeight() - conf->conflicting_block_height + 1);
    } else {
        return 0;
    }
}

int CWallet::GetTxBlocksToMaturity(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    if (!(wtx.IsCoinBase() || wtx.IsCoinStake())) {
        return 0;
    }
    int chain_depth = GetTxDepthInMainChain(wtx);
    if (!wtx.IsCoinStake())
        assert(chain_depth >= 0); // coinbase tx should not be conflicted
    return std::max(0, (Params().GetConsensus().nCoinbaseMaturity+1) - chain_depth);
}

bool CWallet::IsTxImmature(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    // note GetBlocksToMaturity is 0 for non-coinbase tx
    return GetTxBlocksToMaturity(wtx) > 0;
}

bool CWallet::IsTxImmatureCoinBase(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    return wtx.IsCoinBase() && IsTxImmature(wtx);
}

bool CWallet::IsTxImmatureCoinStake(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    return wtx.IsCoinStake() && IsTxImmature(wtx);
}

bool CWallet::HasPrivateKeys() const
{
    return !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
}

bool CWallet::IsCrypted() const
{
    return HasEncryptionKeys();
}

bool CWallet::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_wallet);
    return vMasterKey.empty();
}

bool CWallet::Lock()
{
    if (!IsCrypted())
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size() * sizeof(decltype(vMasterKey)::value_type));
            vMasterKey.clear();
        }
    }

    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    {
        LOCK(cs_wallet);
        for (const auto& spk_man_pair : m_spk_managers) {
            if (!spk_man_pair.second->CheckDecryptionKey(vMasterKeyIn, accept_no_keys)) {
                return false;
            }
        }
        if (!CheckQuantumDecryptionKey(vMasterKeyIn)) {
            return false;
        }
        vMasterKey = vMasterKeyIn;
    }
    NotifyStatusChanged(this);
    return true;
}

std::set<ScriptPubKeyMan*> CWallet::GetActiveScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            auto spk_man = GetScriptPubKeyMan(t, internal);
            if (spk_man) {
                spk_mans.insert(spk_man);
            }
        }
    }
    return spk_mans;
}

std::set<ScriptPubKeyMan*> CWallet::GetAllScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (const auto& spk_man_pair : m_spk_managers) {
        spk_mans.insert(spk_man_pair.second.get());
    }
    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const OutputType& type, bool internal) const
{
    const std::map<OutputType, ScriptPubKeyMan*>& spk_managers = internal ? m_internal_spk_managers : m_external_spk_managers;
    std::map<OutputType, ScriptPubKeyMan*>::const_iterator it = spk_managers.find(type);
    if (it == spk_managers.end()) {
        return nullptr;
    }
    return it->second;
}

std::set<ScriptPubKeyMan*> CWallet::GetScriptPubKeyMans(const CScript& script) const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    SignatureData sigdata;
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script, sigdata)) {
            spk_mans.insert(spk_man_pair.second.get());
        }
    }
    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const uint256& id) const
{
    if (m_spk_managers.count(id) > 0) {
        return m_spk_managers.at(id).get();
    }
    return nullptr;
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script) const
{
    SignatureData sigdata;
    return GetSolvingProvider(script, sigdata);
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script, SignatureData& sigdata) const
{
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script, sigdata)) {
            return spk_man_pair.second->GetSolvingProvider(script);
        }
    }
    return nullptr;
}

std::vector<WalletDescriptor> CWallet::GetWalletDescriptors(const CScript& script) const
{
    std::vector<WalletDescriptor> descs;
    for (const auto spk_man: GetScriptPubKeyMans(script)) {
        if (const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
            LOCK(desc_spk_man->cs_desc_man);
            descs.push_back(desc_spk_man->GetWalletDescriptor());
        }
    }
    return descs;
}

LegacyScriptPubKeyMan* CWallet::GetLegacyScriptPubKeyMan() const
{
    if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return nullptr;
    }
    // Legacy wallets only have one ScriptPubKeyMan which is a LegacyScriptPubKeyMan.
    // Everything in m_internal_spk_managers and m_external_spk_managers point to the same legacyScriptPubKeyMan.
    auto it = m_internal_spk_managers.find(OutputType::LEGACY);
    if (it == m_internal_spk_managers.end()) return nullptr;
    return dynamic_cast<LegacyScriptPubKeyMan*>(it->second);
}

LegacyScriptPubKeyMan* CWallet::GetOrCreateLegacyScriptPubKeyMan()
{
    SetupLegacyScriptPubKeyMan();
    return GetLegacyScriptPubKeyMan();
}

void CWallet::AddScriptPubKeyMan(const uint256& id, std::unique_ptr<ScriptPubKeyMan> spkm_man)
{
    // Add spkm_man to m_spk_managers before calling any method
    // that might access it.
    const auto& spkm = m_spk_managers[id] = std::move(spkm_man);

    // Update birth time if needed
    MaybeUpdateBirthTime(spkm->GetTimeFirstKey());
}

void CWallet::SetupLegacyScriptPubKeyMan()
{
    if (!m_internal_spk_managers.empty() || !m_external_spk_managers.empty() || !m_spk_managers.empty() || IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return;
    }

    auto spk_manager = std::unique_ptr<ScriptPubKeyMan>(new LegacyScriptPubKeyMan(*this, m_keypool_size));
    for (const auto& type : LEGACY_OUTPUT_TYPES) {
        m_internal_spk_managers[type] = spk_manager.get();
        m_external_spk_managers[type] = spk_manager.get();
    }
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
}

const CKeyingMaterial& CWallet::GetEncryptionKey() const
{
    return vMasterKey;
}

bool CWallet::HasEncryptionKeys() const
{
    return !mapMasterKeys.empty();
}

void CWallet::ConnectScriptPubKeyManNotifiers()
{
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        spk_man->NotifyWatchonlyChanged.connect(NotifyWatchonlyChanged);
        spk_man->NotifyCanGetAddressesChanged.connect(NotifyCanGetAddressesChanged);
        spk_man->NotifyFirstKeyTimeChanged.connect(std::bind(&CWallet::MaybeUpdateBirthTime, this, std::placeholders::_2));
    }
}

void CWallet::LoadDescriptorScriptPubKeyMan(uint256 id, WalletDescriptor& desc)
{
    if (IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        auto spk_manager = std::unique_ptr<ScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(*this, desc, m_keypool_size));
        AddScriptPubKeyMan(id, std::move(spk_manager));
    } else {
        auto spk_manager = std::unique_ptr<ScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size));
        AddScriptPubKeyMan(id, std::move(spk_manager));
    }
}

void CWallet::SetupDescriptorScriptPubKeyMans(const CExtKey& master_key)
{
    AssertLockHeld(cs_wallet);

    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            auto spk_manager = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, m_keypool_size));
            if (IsCrypted()) {
                if (IsLocked()) {
                    throw std::runtime_error(std::string(__func__) + ": Wallet is locked, cannot setup new descriptors");
                }
                if (!spk_manager->CheckDecryptionKey(vMasterKey) && !spk_manager->Encrypt(vMasterKey, nullptr)) {
                    throw std::runtime_error(std::string(__func__) + ": Could not encrypt new descriptors");
                }
            }
            spk_manager->SetupDescriptorGeneration(master_key, t, internal);
            uint256 id = spk_manager->GetID();
            AddScriptPubKeyMan(id, std::move(spk_manager));
            AddActiveScriptPubKeyMan(id, t, internal);
        }
    }
}

void CWallet::SetupDescriptorScriptPubKeyMans()
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        // Make a seed
        CKey seed_key;
        seed_key.MakeNewKey(true);
        CPubKey seed = seed_key.GetPubKey();
        assert(seed_key.VerifyPubKey(seed));

        // Get the extended key
        CExtKey master_key;
        master_key.SetSeed(seed_key);

        SetupDescriptorScriptPubKeyMans(master_key);
    } else {
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();

        // TODO: add account parameter
        int account = 0;
        UniValue signer_res = signer.GetDescriptors(account);

        if (!signer_res.isObject()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");
        for (bool internal : {false, true}) {
            const UniValue& descriptor_vals = signer_res.find_value(internal ? "internal" : "receive");
            if (!descriptor_vals.isArray()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");
            for (const UniValue& desc_val : descriptor_vals.get_array().getValues()) {
                const std::string& desc_str = desc_val.getValStr();
                FlatSigningProvider keys;
                std::string desc_error;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, desc_error, false);
                if (desc == nullptr) {
                    throw std::runtime_error(std::string(__func__) + ": Invalid descriptor \"" + desc_str + "\" (" + desc_error + ")");
                }
                if (!desc->GetOutputType()) {
                    continue;
                }
                OutputType t =  *desc->GetOutputType();
                auto spk_manager = std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(*this, m_keypool_size));
                spk_manager->SetupDescriptor(std::move(desc));
                uint256 id = spk_manager->GetID();
                AddScriptPubKeyMan(id, std::move(spk_manager));
                AddActiveScriptPubKeyMan(id, t, internal);
            }
        }
    }
}

void CWallet::AddActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    WalletBatch batch(GetDatabase());
    if (!batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(type), id, internal)) {
        throw std::runtime_error(std::string(__func__) + ": writing active ScriptPubKeyMan id failed");
    }
    LoadActiveScriptPubKeyMan(id, type, internal);
}

void CWallet::LoadActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    // Activating ScriptPubKeyManager for a given output and change type is incompatible with legacy wallets.
    // Legacy wallets have only one ScriptPubKeyManager and it's active for all output and change types.
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    WalletLogPrintf("Setting spkMan to active: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
    auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
    auto& spk_mans_other = internal ? m_external_spk_managers : m_internal_spk_managers;
    auto spk_man = m_spk_managers.at(id).get();
    spk_mans[type] = spk_man;

    const auto it = spk_mans_other.find(type);
    if (it != spk_mans_other.end() && it->second == spk_man) {
        spk_mans_other.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

void CWallet::DeactivateScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    auto spk_man = GetScriptPubKeyMan(type, internal);
    if (spk_man != nullptr && spk_man->GetID() == id) {
        WalletLogPrintf("Deactivate spkMan: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
        WalletBatch batch(GetDatabase());
        if (!batch.EraseActiveScriptPubKeyMan(static_cast<uint8_t>(type), internal)) {
            throw std::runtime_error(std::string(__func__) + ": erasing active ScriptPubKeyMan id failed");
        }

        auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
        spk_mans.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

bool CWallet::IsLegacy() const
{
    if (m_internal_spk_managers.count(OutputType::LEGACY) == 0) {
        return false;
    }
    auto spk_man = dynamic_cast<LegacyScriptPubKeyMan*>(m_internal_spk_managers.at(OutputType::LEGACY));
    return spk_man != nullptr;
}

DescriptorScriptPubKeyMan* CWallet::GetDescriptorScriptPubKeyMan(const WalletDescriptor& desc) const
{
    for (auto& spk_man_pair : m_spk_managers) {
        // Try to downcast to DescriptorScriptPubKeyMan then check if the descriptors match
        DescriptorScriptPubKeyMan* spk_manager = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man_pair.second.get());
        if (spk_manager != nullptr && spk_manager->HasWalletDescriptor(desc)) {
            return spk_manager;
        }
    }

    return nullptr;
}

std::optional<bool> CWallet::IsInternalScriptPubKeyMan(ScriptPubKeyMan* spk_man) const
{
    // Legacy script pubkey man can't be either external or internal
    if (IsLegacy()) {
        return std::nullopt;
    }

    // only active ScriptPubKeyMan can be internal
    if (!GetActiveScriptPubKeyMans().count(spk_man)) {
        return std::nullopt;
    }

    const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (!desc_spk_man) {
        throw std::runtime_error(std::string(__func__) + ": unexpected ScriptPubKeyMan type.");
    }

    LOCK(desc_spk_man->cs_desc_man);
    const auto& type = desc_spk_man->GetWalletDescriptor().descriptor->GetOutputType();
    assert(type.has_value());

    return GetScriptPubKeyMan(*type, /* internal= */ true) == desc_spk_man;
}

ScriptPubKeyMan* CWallet::AddWalletDescriptor(WalletDescriptor& desc, const FlatSigningProvider& signing_provider, const std::string& label, bool internal)
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        WalletLogPrintf("Cannot add WalletDescriptor to a non-descriptor wallet\n");
        return nullptr;
    }

    auto spk_man = GetDescriptorScriptPubKeyMan(desc);
    if (spk_man) {
        WalletLogPrintf("Update existing descriptor: %s\n", desc.descriptor->ToString());
        spk_man->UpdateWalletDescriptor(desc);
    } else {
        auto new_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size));
        spk_man = new_spk_man.get();

        // Save the descriptor to memory
        uint256 id = new_spk_man->GetID();
        AddScriptPubKeyMan(id, std::move(new_spk_man));
    }

    // Add the private keys to the descriptor
    for (const auto& entry : signing_provider.keys) {
        const CKey& key = entry.second;
        spk_man->AddDescriptorKey(key, key.GetPubKey());
    }

    // Top up key pool, the manager will generate new scriptPubKeys internally
    if (!spk_man->TopUp()) {
        WalletLogPrintf("Could not top up scriptPubKeys\n");
        return nullptr;
    }

    // Apply the label if necessary
    // Note: we disable labels for ranged descriptors
    if (!desc.descriptor->IsRange()) {
        auto script_pub_keys = spk_man->GetScriptPubKeys();
        if (script_pub_keys.empty()) {
            WalletLogPrintf("Could not generate scriptPubKeys (cache is empty)\n");
            return nullptr;
        }

        if (!internal) {
            for (const auto& script : script_pub_keys) {
                CTxDestination dest;
                if (ExtractDestination(script, dest)) {
                    SetAddressBook(dest, label, AddressPurpose::RECEIVE);
                }
            }
        }
    }

    // Save the descriptor to DB
    spk_man->WriteDescriptor();

    return spk_man;
}

bool CWallet::MigrateToSQLite(bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    WalletLogPrintf("Migrating wallet storage database from BerkeleyDB to SQLite.\n");

    if (m_database->Format() == "sqlite") {
        error = _("Error: This wallet already uses SQLite");
        return false;
    }

    // Get all of the records for DB type migration
    std::unique_ptr<DatabaseBatch> batch = m_database->MakeBatch();
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    std::vector<std::pair<SerializeData, SerializeData>> records;
    if (!cursor) {
        error = _("Error: Unable to begin reading all records in the database");
        return false;
    }
    DatabaseCursor::Status status = DatabaseCursor::Status::FAIL;
    while (true) {
        DataStream ss_key{};
        DataStream ss_value{};
        status = cursor->Next(ss_key, ss_value);
        if (status != DatabaseCursor::Status::MORE) {
            break;
        }
        SerializeData key(ss_key.begin(), ss_key.end());
        SerializeData value(ss_value.begin(), ss_value.end());
        records.emplace_back(key, value);
    }
    cursor.reset();
    batch.reset();
    if (status != DatabaseCursor::Status::DONE) {
        error = _("Error: Unable to read all records in the database");
        return false;
    }

    // Close this database and delete the file
    fs::path db_path = fs::PathFromString(m_database->Filename());
    m_database->Close();
    fs::remove(db_path);

    // Generate the path for the location of the migrated wallet
    // Wallets that are plain files rather than wallet directories will be migrated to be wallet directories.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(m_name));

    // Make new DB
    DatabaseOptions opts;
    opts.require_create = true;
    opts.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus db_status;
    std::unique_ptr<WalletDatabase> new_db = MakeDatabase(wallet_path, opts, db_status, error);
    assert(new_db); // This is to prevent doing anything further with this wallet. The original file was deleted, but a backup exists.
    m_database.reset();
    m_database = std::move(new_db);

    // Write existing records into the new DB
    batch = m_database->MakeBatch();
    bool began = batch->TxnBegin();
    assert(began); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    for (const auto& [key, value] : records) {
        if (!batch->Write(Span{key}, Span{value})) {
            batch->TxnAbort();
            m_database->Close();
            fs::remove(m_database->Filename());
            assert(false); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
        }
    }
    bool committed = batch->TxnCommit();
    assert(committed); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    return true;
}

std::optional<MigrationData> CWallet::GetDescriptorsForLegacy(bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    assert(legacy_spkm);

    std::optional<MigrationData> res = legacy_spkm->MigrateToDescriptor();
    if (res == std::nullopt) {
        error = _("Error: Unable to produce descriptors for this legacy wallet. Make sure to provide the wallet's passphrase if it is encrypted.");
        return std::nullopt;
    }
    return res;
}

bool CWallet::ApplyMigrationData(MigrationData& data, bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    if (!legacy_spkm) {
        error = _("Error: This wallet is already a descriptor wallet");
        return false;
    }

    // Get all invalid or non-watched scripts that will not be migrated
    std::set<CTxDestination> not_migrated_dests;
    for (const auto& script : legacy_spkm->GetNotMineScriptPubKeys()) {
        CTxDestination dest;
        if (ExtractDestination(script, dest)) not_migrated_dests.emplace(dest);
    }

    for (auto& desc_spkm : data.desc_spkms) {
        if (m_spk_managers.count(desc_spkm->GetID()) > 0) {
            error = _("Error: Duplicate descriptors created during migration. Your wallet may be corrupted.");
            return false;
        }
        uint256 id = desc_spkm->GetID();
        AddScriptPubKeyMan(id, std::move(desc_spkm));
    }

    // Remove the LegacyScriptPubKeyMan from disk
    if (!legacy_spkm->DeleteRecords()) {
        return false;
    }

    // Remove the LegacyScriptPubKeyMan from memory
    m_spk_managers.erase(legacy_spkm->GetID());
    m_external_spk_managers.clear();
    m_internal_spk_managers.clear();

    // Setup new descriptors
    SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    if (!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Use the existing master key if we have it
        if (data.master_key.key.IsValid()) {
            SetupDescriptorScriptPubKeyMans(data.master_key);
        } else {
            // Setup with a new seed if we don't.
            SetupDescriptorScriptPubKeyMans();
        }
    }

    // Check if the transactions in the wallet are still ours. Either they belong here, or they belong in the watchonly wallet.
    // We need to go through these in the tx insertion order so that lookups to spends works.
    std::vector<uint256> txids_to_delete;
    std::unique_ptr<WalletBatch> watchonly_batch;
    if (data.watchonly_wallet) {
        watchonly_batch = std::make_unique<WalletBatch>(data.watchonly_wallet->GetDatabase());
        // Copy the next tx order pos to the watchonly wallet
        LOCK(data.watchonly_wallet->cs_wallet);
        data.watchonly_wallet->nOrderPosNext = nOrderPosNext;
        watchonly_batch->WriteOrderPosNext(data.watchonly_wallet->nOrderPosNext);
    }
    for (const auto& [_pos, wtx] : wtxOrdered) {
        if (!IsMine(*wtx->tx) && !IsFromMe(*wtx->tx)) {
            // Check it is the watchonly wallet's
            // solvable_wallet doesn't need to be checked because transactions for those scripts weren't being watched for
            if (data.watchonly_wallet) {
                LOCK(data.watchonly_wallet->cs_wallet);
                if (data.watchonly_wallet->IsMine(*wtx->tx) || data.watchonly_wallet->IsFromMe(*wtx->tx)) {
                    // Add to watchonly wallet
                    const uint256& hash = wtx->GetHash();
                    const CWalletTx& to_copy_wtx = *wtx;
                    if (!data.watchonly_wallet->LoadToWallet(hash, [&](CWalletTx& ins_wtx, bool new_tx) EXCLUSIVE_LOCKS_REQUIRED(data.watchonly_wallet->cs_wallet) {
                        if (!new_tx) return false;
                        ins_wtx.SetTx(to_copy_wtx.tx);
                        ins_wtx.CopyFrom(to_copy_wtx);
                        return true;
                    })) {
                        error = strprintf(_("Error: Could not add watchonly tx %s to watchonly wallet"), wtx->GetHash().GetHex());
                        return false;
                    }
                    watchonly_batch->WriteTx(data.watchonly_wallet->mapWallet.at(hash));
                    // Mark as to remove from this wallet
                    txids_to_delete.push_back(hash);
                    continue;
                }
            }
            // Both not ours and not in the watchonly wallet
            error = strprintf(_("Error: Transaction %s in wallet cannot be identified to belong to migrated wallets"), wtx->GetHash().GetHex());
            return false;
        }
    }
    watchonly_batch.reset(); // Flush
    // Do the removes
    if (txids_to_delete.size() > 0) {
        std::vector<uint256> deleted_txids;
        if (ZapSelectTx(txids_to_delete, deleted_txids) != DBErrors::LOAD_OK) {
            error = _("Error: Could not delete watchonly transactions");
            return false;
        }
        if (deleted_txids != txids_to_delete) {
            error = _("Error: Not all watchonly txs could be deleted");
            return false;
        }
        // Tell the GUI of each tx
        for (const uint256& txid : deleted_txids) {
            NotifyTransactionChanged(txid, CT_UPDATED);
        }
    }

    // Check the address book data in the same way we did for transactions
    std::vector<CTxDestination> dests_to_delete;
    for (const auto& addr_pair : m_address_book) {
        // Labels applied to receiving addresses should go based on IsMine
        if (addr_pair.second.purpose == AddressPurpose::RECEIVE) {
            if (!IsMine(addr_pair.first)) {
                // Check the address book data is the watchonly wallet's
                if (data.watchonly_wallet) {
                    LOCK(data.watchonly_wallet->cs_wallet);
                    if (data.watchonly_wallet->IsMine(addr_pair.first)) {
                        // Add to the watchonly. Preserve the labels, purpose, and change-ness
                        std::string label = addr_pair.second.GetLabel();
                        data.watchonly_wallet->m_address_book[addr_pair.first].purpose = addr_pair.second.purpose;
                        if (!addr_pair.second.IsChange()) {
                            data.watchonly_wallet->m_address_book[addr_pair.first].SetLabel(label);
                        }
                        dests_to_delete.push_back(addr_pair.first);
                        continue;
                    }
                }
                if (data.solvable_wallet) {
                    LOCK(data.solvable_wallet->cs_wallet);
                    if (data.solvable_wallet->IsMine(addr_pair.first)) {
                        // Add to the solvable. Preserve the labels, purpose, and change-ness
                        std::string label = addr_pair.second.GetLabel();
                        data.solvable_wallet->m_address_book[addr_pair.first].purpose = addr_pair.second.purpose;
                        if (!addr_pair.second.IsChange()) {
                            data.solvable_wallet->m_address_book[addr_pair.first].SetLabel(label);
                        }
                        dests_to_delete.push_back(addr_pair.first);
                        continue;
                    }
                }

                // Skip invalid/non-watched scripts that will not be migrated
                if (not_migrated_dests.count(addr_pair.first) > 0) {
                    dests_to_delete.push_back(addr_pair.first);
                    continue;
                }

                // Not ours, not in watchonly wallet, and not in solvable
                error = _("Error: Address book data in wallet cannot be identified to belong to migrated wallets");
                return false;
            }
        } else {
            // Labels for everything else ("send") should be cloned to all
            if (data.watchonly_wallet) {
                LOCK(data.watchonly_wallet->cs_wallet);
                // Add to the watchonly. Preserve the labels, purpose, and change-ness
                std::string label = addr_pair.second.GetLabel();
                data.watchonly_wallet->m_address_book[addr_pair.first].purpose = addr_pair.second.purpose;
                if (!addr_pair.second.IsChange()) {
                    data.watchonly_wallet->m_address_book[addr_pair.first].SetLabel(label);
                }
            }
            if (data.solvable_wallet) {
                LOCK(data.solvable_wallet->cs_wallet);
                // Add to the solvable. Preserve the labels, purpose, and change-ness
                std::string label = addr_pair.second.GetLabel();
                data.solvable_wallet->m_address_book[addr_pair.first].purpose = addr_pair.second.purpose;
                if (!addr_pair.second.IsChange()) {
                    data.solvable_wallet->m_address_book[addr_pair.first].SetLabel(label);
                }
            }
        }
    }

    // Persist added address book entries (labels, purpose) for watchonly and solvable wallets
    auto persist_address_book = [](const CWallet& wallet) {
        LOCK(wallet.cs_wallet);
        WalletBatch batch{wallet.GetDatabase()};
        for (const auto& [destination, addr_book_data] : wallet.m_address_book) {
            auto address{EncodeDestination(destination)};
            std::optional<std::string> label = addr_book_data.IsChange() ? std::nullopt : std::make_optional(addr_book_data.GetLabel());
            // don't bother writing default values (unknown purpose)
            if (addr_book_data.purpose) batch.WritePurpose(address, PurposeToString(*addr_book_data.purpose));
            if (label) batch.WriteName(address, *label);
        }
    };
    if (data.watchonly_wallet) persist_address_book(*data.watchonly_wallet);
    if (data.solvable_wallet) persist_address_book(*data.solvable_wallet);

    // Remove the things to delete
    if (dests_to_delete.size() > 0) {
        for (const auto& dest : dests_to_delete) {
            if (!DelAddressBook(dest)) {
                error = _("Error: Unable to remove watchonly address book data");
                return false;
            }
        }
    }

    // Connect the SPKM signals
    ConnectScriptPubKeyManNotifiers();
    NotifyCanGetAddressesChanged();

    WalletLogPrintf("Wallet migration complete.\n");

    return true;
}

bool CWallet::CanGrindR() const
{
    return !IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER);
}

// Returns wallet prefix for migration.
// Used to name the backup file and newly created wallets.
// E.g. a watch-only wallet is named "<prefix>_watchonly".
static std::string MigrationPrefixName(CWallet& wallet)
{
    const std::string& name{wallet.GetName()};
    return name.empty() ? "default_wallet" : name;
}

bool DoMigration(CWallet& wallet, WalletContext& context, bilingual_str& error, MigrationResult& res) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // Get all of the descriptors from the legacy wallet
    std::optional<MigrationData> data = wallet.GetDescriptorsForLegacy(error);
    if (data == std::nullopt) return false;

    // Create the watchonly and solvable wallets if necessary
    if (data->watch_descs.size() > 0 || data->solvable_descs.size() > 0) {
        DatabaseOptions options;
        options.require_existing = false;
        options.require_create = true;
        options.require_format = DatabaseFormat::SQLITE;

        WalletContext empty_context;
        empty_context.args = context.args;

        // Make the wallets
        options.create_flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET | WALLET_FLAG_DESCRIPTORS;
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            options.create_flags |= WALLET_FLAG_AVOID_REUSE;
        }
        if (wallet.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
            options.create_flags |= WALLET_FLAG_KEY_ORIGIN_METADATA;
        }
        if (data->watch_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the watched scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = MigrationPrefixName(wallet) + "_watchonly";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->watchonly_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
            if (!data->watchonly_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.watchonly_wallet = data->watchonly_wallet;
            LOCK(data->watchonly_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->watch_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->watchonly_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
        if (data->solvable_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the unwatched solvable scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = MigrationPrefixName(wallet) + "_solvables";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->solvable_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
            if (!data->solvable_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.solvables_wallet = data->solvable_wallet;
            LOCK(data->solvable_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->solvable_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->solvable_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
    }

    // Add the descriptors to wallet, remove LegacyScriptPubKeyMan, and cleanup txs and address book data
    if (!wallet.ApplyMigrationData(*data, error)) {
        return false;
    }
    return true;
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(const std::string& wallet_name, const SecureString& passphrase, WalletContext& context)
{
    MigrationResult res;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // If the wallet is still loaded, unload it so that nothing else tries to use it while we're changing it
    if (auto wallet = GetWallet(context, wallet_name)) {
        if (!RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt, warnings)) {
            return util::Error{_("Unable to unload the wallet before migrating")};
        }
        UnloadWallet(std::move(wallet));
    }

    // Load the wallet but only in the context of this function.
    // No signals should be connected nor should anything else be aware of this wallet
    WalletContext empty_context;
    empty_context.args = context.args;
    DatabaseOptions options;
    options.require_existing = true;
    DatabaseStatus status;
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
    if (!database) {
        return util::Error{Untranslated("Wallet file verification failed.") + Untranslated(" ") + error};
    }

    // Make the local wallet
    std::shared_ptr<CWallet> local_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
    if (!local_wallet) {
        return util::Error{Untranslated("Wallet loading failed.") + Untranslated(" ") + error};
    }

    // Before anything else, check if there is something to migrate.
    if (!local_wallet->GetLegacyScriptPubKeyMan()) {
        return util::Error{_("Error: This wallet is already a descriptor wallet")};
    }

    // Make a backup of the DB in the wallet's directory with a unique filename
    // using the wallet name and current timestamp. The backup filename is based
    // on the name of the parent directory containing the wallet data in most
    // cases, but in the case where the wallet name is a path to a data file,
    // the name of the data file is used, and in the case where the wallet name
    // is blank, "default_wallet" is used.
    const std::string backup_prefix = wallet_name.empty() ? MigrationPrefixName(*local_wallet) : [&] {
        // fs::weakly_canonical resolves relative specifiers and remove trailing slashes.
        const auto legacy_wallet_path = fs::weakly_canonical(GetWalletDir() / fs::PathFromString(wallet_name));
        return fs::PathToString(legacy_wallet_path.filename());
    }();

    fs::path backup_filename = fs::PathFromString(strprintf("%s_%d.legacy.bak", backup_prefix, GetTime()));
    fs::path backup_path = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
    if (!local_wallet->BackupWallet(fs::PathToString(backup_path))) {
        return util::Error{_("Error: Unable to make a backup of your wallet")};
    }
    res.backup_path = backup_path;

    bool success = false;
    {
        LOCK(local_wallet->cs_wallet);

        // Unlock the wallet if needed
        if (local_wallet->IsLocked() && !local_wallet->Unlock(passphrase)) {
            if (passphrase.find('\0') == std::string::npos) {
                return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase was not provided or was incorrect.")};
            } else {
                return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase entered was incorrect. "
                                                "The passphrase contains a null character (ie - a zero byte). "
                                                "If this passphrase was set with a version of this software prior to 25.0, "
                                                "please try again with only the characters up to — but not including — "
                                                "the first null character.")};
            }
        }

        // First change to using SQLite
        if (!local_wallet->MigrateToSQLite(error)) return util::Error{error};

        // Do the migration, and cleanup if it fails
        success = DoMigration(*local_wallet, context, error, res);
    }

    // In case of loading failure, we need to remember the wallet files we have created to remove.
    // A `set` is used as it may be populated with the same wallet directory paths multiple times,
    // both before and after loading. This ensures the set is complete even if one of the wallets
    // fails to load.
    std::set<fs::path> wallet_files_to_remove;
    std::set<fs::path> wallet_empty_dirs_to_remove;

    // Helper to track wallet files and directories for cleanup on failure.
    // Only directories of wallets created during migration (not the main wallet) are tracked.
    auto track_for_cleanup = [&](const CWallet& wallet) {
        const auto files = wallet.GetDatabase().Files();
        wallet_files_to_remove.insert(files.begin(), files.end());
        if (wallet.GetName() != wallet_name) {
            // If this isn't the main wallet, mark its directory for removal.
            // This applies to the watch-only and solvable wallets.
            // Wallets stored directly as files in the top-level directory
            // (e.g. default unnamed wallets) don't have a removable parent directory.
            wallet_empty_dirs_to_remove.insert(fs::PathFromString(wallet.GetDatabase().Filename()).parent_path());
        }
    };

    if (success) {
        // Migration successful, unload all wallets locally, then reload them.
        const auto& reload_wallet = [&](std::shared_ptr<CWallet>& to_reload) {
            assert(to_reload.use_count() == 1);
            track_for_cleanup(*to_reload);
            std::string name = to_reload->GetName();
            to_reload.reset();
            to_reload = LoadWallet(context, name, /*load_on_start=*/std::nullopt, options, status, error, warnings);
            return to_reload != nullptr;
        };
        // Reload the main wallet
        success = reload_wallet(local_wallet);
        res.wallet = local_wallet;
        res.wallet_name = wallet_name;
        if (success && res.watchonly_wallet) {
            // Reload watchonly
            success = reload_wallet(res.watchonly_wallet);
        }
        if (success && res.solvables_wallet) {
            // Reload solvables
            success = reload_wallet(res.solvables_wallet);
        }
    }
    if (!success) {
        // Migration failed, cleanup
        // Copy the backup to the actual wallet dir
        fs::path temp_backup_location = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
        fs::copy_file(backup_path, temp_backup_location, fs::copy_options::none);

        // Make list of wallets to cleanup
        std::vector<std::shared_ptr<CWallet>> created_wallets;
        if (local_wallet) created_wallets.push_back(std::move(local_wallet));
        if (res.watchonly_wallet) created_wallets.push_back(std::move(res.watchonly_wallet));
        if (res.solvables_wallet) created_wallets.push_back(std::move(res.solvables_wallet));

        // Get the directories to remove after unloading
        for (std::shared_ptr<CWallet>& wallet : created_wallets) {
            track_for_cleanup(*wallet);
        }

        // Unload the wallets
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            if (w->HaveChain()) {
                // Unloading for wallets that were loaded for normal use
                if (!RemoveWallet(context, w, /*load_on_start=*/false)) {
                    error += _("\nUnable to cleanup failed migration");
                    return util::Error{error};
                }
                UnloadWallet(std::move(w));
            } else {
                // Unloading for wallets in local context
                assert(w.use_count() == 1);
                w.reset();
            }
        }

        // First, delete the db files we have created throughout this process and nothing else
        for (const fs::path& file : wallet_files_to_remove) {
            fs::remove(file);
        }

        // Second, delete the created wallet directories and nothing else. They must be empty at this point.
        for (const fs::path& dir : wallet_empty_dirs_to_remove) {
            Assume(fs::is_empty(dir));
            fs::remove(dir);
        }

        // Restore the backup
        DatabaseStatus status;
        std::vector<bilingual_str> warnings;
        if (!RestoreWallet(context, temp_backup_location, wallet_name, /*load_on_start=*/std::nullopt, status, error, warnings)) {
            error += _("\nUnable to restore backup of wallet.");
            return util::Error{error};
        }

        // Move the backup to the wallet dir
        fs::copy_file(temp_backup_location, backup_path, fs::copy_options::none);
        fs::remove(temp_backup_location);

        return util::Error{error};
    }
    return res;
}

void CWallet::StartStake() {
    if (HaveChain()) {
        chain().startStake(*this);
    }
}

void CWallet::StopStake() {
    if (HaveChain()) {
        chain().stopStake(*this);
    }
}

bool CWallet::IsStakeClosing() {
    return chain().shutdownRequested() || m_stop_staking_thread;
}

namespace {
static constexpr uint64_t POW_MINER_BATCH_TRIES = 128;

bool SleepPowMiner(CWallet& wallet, std::chrono::milliseconds duration)
{
    const auto step = std::chrono::milliseconds{100};
    auto slept = std::chrono::milliseconds{0};
    while (slept < duration) {
        if (wallet.IsPowMiningClosing() || !wallet.m_pow_mining_enabled.load()) return false;
        const auto pause = std::min(step, duration - slept);
        std::this_thread::sleep_for(pause);
        slept += pause;
    }
    return true;
}

bool IsShadowPowMiningTarget(const CScript& script)
{
    return !script.empty() && !script.IsUnspendable() &&
           !IsQuantumMigrationScript(script) &&
           !IsQuantumColdStakeScript(script) &&
           !IsEUTXOScript(script);
}

bool IsShadowPowClaimConflict(const bilingual_str& error)
{
    return error.original.find("shadow-proof-mempool-conflict") != std::string::npos;
}

bool SelectShadowPowMiningTarget(CWallet& wallet, const CScript& quantum_payout_script, CScript& target, CTxDestination& dest, bilingual_str& error)
{
    AssertLockHeld(wallet.cs_wallet);
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_address_reuse = false;
    const int64_t current_time = GetAdjustedTimeSeconds();
    const CFeeRate fee_rate = GetMinimumFeeRate(wallet, coin_control, current_time);
    std::vector<unsigned char> dummy_proof(GetShadowPrefix().size() + 17 + quantum_payout_script.size(), 0);
    std::copy(GetShadowPrefix().begin(), GetShadowPrefix().end(), dummy_proof.begin());
    for (const COutput& output : AvailableCoins(wallet, &coin_control).All()) {
        if (output.txout.nValue <= 0) continue;
        if (!IsShadowPowMiningTarget(output.txout.scriptPubKey)) continue;
        CTxDestination candidate_dest;
        if (!ExtractDestination(output.txout.scriptPubKey, candidate_dest) || !IsValidDestination(candidate_dest)) continue;
        const CScript canonical_target = CanonicalizeLegacyStakeScript(output.txout.scriptPubKey);

        dummy_proof.resize(GetShadowPrefix().size() + 17 + canonical_target.size() + quantum_payout_script.size(), 0);
        std::copy(GetShadowPrefix().begin(), GetShadowPrefix().end(), dummy_proof.begin());
        CMutableTransaction candidate;
        candidate.nVersion = CTransaction::CURRENT_VERSION;
        candidate.nTime = current_time;
        static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
        candidate.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
        candidate.vout.emplace_back(output.txout.nValue, canonical_target);
        candidate.vout.emplace_back(0, CScript() << OP_RETURN << dummy_proof);
        const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(candidate), &wallet, &coin_control);
        if (tx_size.vsize <= 0) continue;
        const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
        const CAmount candidate_change = output.txout.nValue - candidate_fee;
        CTxOut change_out(candidate_change, canonical_target);
        if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, wallet.chain().relayDustFee())) continue;
        if (candidate_fee > wallet.m_default_max_tx_fee) continue;

        target = canonical_target;
        dest = candidate_dest;
        return true;
    }
    error = _("No spendable legacy UTXO is available for Gold Rush PoW claim authentication.");
    return false;
}
} // namespace

bool CWallet::SetPowMining(bool enabled, int threads, int cpu_percent, bilingual_str& error, bool* created_payout)
{
    if (created_payout) *created_payout = false;
    if (enabled) {
        if (threads < 1 || threads > 256) {
            error = _("Gold Rush PoW mining threads must be between 1 and 256.");
            return false;
        }
        if (cpu_percent < 1 || cpu_percent > 100) {
            error = _("Gold Rush PoW mining cpu_percent must be between 1 and 100.");
            return false;
        }
    }

    StopPowMining();
    if (!enabled) {
        m_pow_threads = 1;
        m_pow_cpu_percent = 1;
        return true;
    }

    {
        LOCK(cs_wallet);
        if (!HasPrivateKeys() || IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            error = _("Gold Rush PoW mining requires a wallet with private keys.");
            return false;
        }
        if (IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            error = _("Gold Rush PoW mining is not available for external-signer wallets.");
            return false;
        }
        if (IsLocked()) {
            error = _("Gold Rush PoW mining requires an unlocked wallet.");
            return false;
        }
        if (m_wallet_unlock_staking_only) {
            error = _("Gold Rush PoW mining requires a normal wallet unlock, not staking-only unlock.");
            return false;
        }
    }

    if (!EnsurePowPayoutAddress(error, created_payout)) return false;

    m_pow_threads = threads;
    m_pow_cpu_percent = cpu_percent;
    m_pow_hashrate = 0.0;
    m_pow_total_tries = 0;
    m_pow_hashrate_start_ms = GetTime<std::chrono::milliseconds>().count();
    m_pow_next_nonce = 0;
    m_pow_claims_submitted = 0;
    m_stop_pow_mining_thread = false;
    {
        LOCK(m_pow_miner_mutex);
        m_pow_tip_hash.SetNull();
        m_pow_claim_inflight = false;
    }

    auto group = std::make_unique<std::vector<std::thread>>();
    group->reserve(threads);
    m_pow_mining_enabled = true;
    for (int i = 0; i < threads; ++i) {
        group->emplace_back(&CWallet::ThreadShadowPoWMiner, this, i);
    }
    {
        LOCK(m_pow_miner_mutex);
        threadPowMinerGroup = std::move(group);
    }
    WalletLogPrintf("Gold Rush PoW miner started with %d worker(s) at %d%% CPU target\n", threads, cpu_percent);
    return true;
}

void CWallet::StopPowMining()
{
    m_pow_mining_enabled = false;
    m_stop_pow_mining_thread = true;

    std::unique_ptr<std::vector<std::thread>> group;
    {
        LOCK(m_pow_miner_mutex);
        group = std::move(threadPowMinerGroup);
        m_pow_claim_inflight = false;
    }
    if (group) {
        for (std::thread& thread : *group) {
            if (thread.joinable()) thread.join();
        }
        group->clear();
    }
    m_pow_hashrate = 0.0;
    m_stop_pow_mining_thread = false;
}

bool CWallet::IsPowMiningClosing() const
{
    return (HaveChain() && chain().shutdownRequested()) || m_stop_pow_mining_thread.load();
}

bool CWallet::EnsurePowPayoutAddress(bilingual_str& error, bool* created)
{
    if (created) *created = false;
    static constexpr const char* POW_PAYOUT_LABEL{"PoW - Quantum Claim Address"};
    static constexpr const char* OLD_POW_PAYOUT_LABEL{"Quantum PoW Reward Address"};
    static constexpr const char* LEGACY_POW_PAYOUT_LABEL{"goldrush-pow"};
    std::string restored_payout;
    std::optional<CTxDestination> relabel_dest;
    {
        LOCK(cs_wallet);
        if (!m_pow_payout_quantum.empty()) {
            const CTxDestination existing = DecodeDestination(m_pow_payout_quantum);
            if (IsValidDestination(existing) && IsQuantumMigrationDestination(existing)) return true;
            error = _("Stored Gold Rush PoW payout address is not a valid quantum migration address.");
            return false;
        }

        for (const auto& [dest, entry] : m_address_book) {
            const std::string label = entry.GetLabel();
            if (entry.IsChange() || (label != POW_PAYOUT_LABEL && label != OLD_POW_PAYOUT_LABEL && label != LEGACY_POW_PAYOUT_LABEL)) continue;
            if (!IsValidDestination(dest) || !IsQuantumMigrationDestination(dest)) continue;
            if (IsMine(dest) == ISMINE_NO) continue;
            restored_payout = EncodeDestination(dest);
            m_pow_payout_quantum = restored_payout;
            if (label != POW_PAYOUT_LABEL) {
                relabel_dest = dest;
            }
            break;
        }
    }

    if (!restored_payout.empty()) {
        if (relabel_dest && !SetAddressBook(*relabel_dest, POW_PAYOUT_LABEL, AddressPurpose::RECEIVE)) {
            error = _("Failed to update Gold Rush PoW payout address label.");
            return false;
        }
        WalletLogPrintf("Gold Rush PoW miner restored payout address %s.\n", restored_payout);
        return true;
    }

    auto dest = GetNewQuantumDestination(POW_PAYOUT_LABEL);
    if (!dest) {
        error = util::ErrorString(dest);
        return false;
    }
    const std::string encoded = EncodeDestination(*dest);
    {
        LOCK(cs_wallet);
        if (m_pow_payout_quantum.empty()) {
            m_pow_payout_quantum = encoded;
        }
    }
    WalletLogPrintf("Gold Rush PoW miner created payout address %s. Back up the wallet.\n", encoded);
    if (created) *created = true;
    return true;
}

bool CWallet::SubmitShadowPowClaim(const CScript& target, const CTxDestination& dest, const std::vector<unsigned char>& proof, bilingual_str& error)
{
    CCoinControl coin_control;
    coin_control.destChange = dest;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_address_reuse = false;

    CMutableTransaction claim_tx;
    CAmount fee{0};
    std::map<COutPoint, Coin> coins;
    {
        LOCK(cs_wallet);
        if (IsLocked()) {
            error = _("Wallet locked before the Gold Rush PoW claim could be signed.");
            return false;
        }
        if (m_wallet_unlock_staking_only) {
            error = _("Wallet switched to staking-only unlock before the Gold Rush PoW claim could be signed.");
            return false;
        }

        const int64_t current_time = GetAdjustedTimeSeconds();
        const CFeeRate fee_rate = GetMinimumFeeRate(*this, coin_control, current_time);
        for (const COutput& output : AvailableCoins(*this, &coin_control).All()) {
            if (CanonicalizeLegacyStakeScript(output.txout.scriptPubKey) != target) continue;

            CMutableTransaction candidate;
            candidate.nVersion = CTransaction::CURRENT_VERSION;
            candidate.nTime = current_time;
            static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
            candidate.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
            candidate.vout.emplace_back(output.txout.nValue, target);
            candidate.vout.emplace_back(0, CScript() << OP_RETURN << proof);

            const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(candidate), this, &coin_control);
            if (tx_size.vsize <= 0) continue;
            const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
            const CAmount candidate_change = output.txout.nValue - candidate_fee;
            CTxOut change_out(candidate_change, target);
            if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, chain().relayDustFee())) continue;
            if (candidate_fee > m_default_max_tx_fee) {
                error = strprintf(_("Gold Rush PoW claim fee exceeds wallet max transaction fee (%s)."), FormatMoney(m_default_max_tx_fee));
                return false;
            }

            candidate.vout[0].nValue = candidate_change;
            const auto tx_it = mapWallet.find(output.outpoint.hash);
            if (tx_it == mapWallet.end() || output.outpoint.n >= tx_it->second.tx->vout.size()) continue;
            const CWalletTx& wtx = tx_it->second;
            const int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
            coins.emplace(output.outpoint, Coin(output.txout, prev_height, wtx.IsCoinBase(), wtx.IsCoinStake(), wtx.nTimeSmart));

            claim_tx = std::move(candidate);
            fee = candidate_fee;
            break;
        }
    }

    if (claim_tx.vin.empty()) {
        error = _("No spendable non-dust UTXO found for the Gold Rush PoW claim address.");
        return false;
    }

    std::map<int, bilingual_str> input_errors;
    if (!SignTransaction(claim_tx, coins, SIGHASH_DEFAULT, input_errors)) {
        if (!input_errors.empty()) {
            error = strprintf(_("Signing Gold Rush PoW claim failed: %s"), input_errors.begin()->second.original);
        } else {
            error = _("Signing Gold Rush PoW claim failed.");
        }
        return false;
    }

    CTransactionRef tx = MakeTransactionRef(std::move(claim_tx));
    {
        ChainstateManager& chainman = chain().chainman();
        LOCK(cs_main);
        const MempoolAcceptResult accept = chainman.ProcessTransaction(tx, /*test_accept=*/true);
        if (accept.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            error = strprintf(_("Gold Rush PoW claim rejected: %s"), accept.m_state.ToString());
            return false;
        }
    }

    mapValue_t map_value;
    map_value["comment"] = "PoW Claim";
    try {
        std::string broadcast_error;
        if (!CommitTransaction(tx, std::move(map_value), {}, &broadcast_error)) {
            error = strprintf(_("Broadcasting Gold Rush PoW claim failed: %s"), broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error);
            if (!AbandonTransaction(tx->GetHash())) {
                WalletLogPrintf("Gold Rush PoW stale claim could not be abandoned: txid=%s\n", tx->GetHash().ToString());
            }
            return false;
        }
    } catch (const std::exception& e) {
        error = strprintf(_("Broadcasting Gold Rush PoW claim failed: %s"), e.what());
        return false;
    }
    WalletLogPrintf("Gold Rush PoW claim submitted: txid=%s fee=%s\n", tx->GetHash().ToString(), FormatMoney(fee));
    return true;
}

void CWallet::ThreadShadowPoWMiner(int worker_id)
{
    WalletLogPrintf("Gold Rush PoW worker %d started\n", worker_id);
    while (!IsPowMiningClosing() && m_pow_mining_enabled.load()) {
        bilingual_str error;
        if (!HaveChain()) {
            SleepPowMiner(*this, std::chrono::seconds{1});
            continue;
        }
        // If the wallet is locked (or staking-only) we cannot sign claims; pause instead of
        // grinding pointlessly and spamming claim-failure logs until it is unlocked again.
        bool cannot_claim{false};
        {
            LOCK(cs_wallet);
            cannot_claim = IsLocked() || m_wallet_unlock_staking_only;
        }
        if (cannot_claim) {
            m_pow_hashrate = 0.0;
            SleepPowMiner(*this, std::chrono::seconds{2});
            continue;
        }
        if (!EnsurePowPayoutAddress(error)) {
            WalletLogPrintf("Gold Rush PoW worker %d stopped: %s\n", worker_id, error.original);
            m_pow_mining_enabled = false;
            break;
        }

        std::string quantum_address;
        {
            LOCK(cs_wallet);
            quantum_address = m_pow_payout_quantum;
        }
        const CTxDestination quantum_dest = DecodeDestination(quantum_address);
        if (!IsValidDestination(quantum_dest) || !IsQuantumMigrationDestination(quantum_dest)) {
            WalletLogPrintf("Gold Rush PoW worker %d stopped: invalid payout address\n", worker_id);
            m_pow_mining_enabled = false;
            break;
        }
        const CScript quantum_payout_script = GetScriptForDestination(quantum_dest);

        CScript target;
        CTxDestination target_dest;
        bool have_target{false};
        {
            LOCK(cs_wallet);
            have_target = SelectShadowPowMiningTarget(*this, quantum_payout_script, target, target_dest, error);
        }
        if (!have_target) {
            m_pow_hashrate = 0.0;
            SleepPowMiner(*this, std::chrono::seconds{5});
            continue;
        }

        std::vector<unsigned char> proof;
        uint64_t tries_done{0};
        bool proof_found{false};
        uint256 tip_hash;
        auto batch_elapsed = std::chrono::milliseconds{0};
        auto loop_sleep = std::chrono::milliseconds{0};
        ShadowPowWork work;
        uint64_t nonce_start{0};
        bool should_grind{false};
        {
            ChainstateManager& chainman = chain().chainman();
            LOCK(cs_main);
            const CBlockIndex* tip = chainman.ActiveChain().Tip();
            if (!tip) {
                loop_sleep = std::chrono::seconds{1};
            } else {
                const Consensus::Params& consensus = Params().GetConsensus();
                const int next_height = tip->nHeight + 1;
                const bool active = IsShadowGoldRushRewardActive(consensus, tip->GetMedianTimePast(), next_height);
                if (!active) {
                    m_pow_hashrate = 0.0;
                    loop_sleep = std::chrono::seconds{2};
                } else {
                    tip_hash = tip->GetBlockHash();
                    bool claim_inflight{false};
                    {
                        LOCK(m_pow_miner_mutex);
                        if (m_pow_tip_hash != tip_hash) {
                            m_pow_tip_hash = tip_hash;
                            m_pow_next_nonce = 0;
                            m_pow_claim_inflight = false;
                        }
                        claim_inflight = m_pow_claim_inflight;
                    }
                    if (claim_inflight) {
                        loop_sleep = std::chrono::seconds{1};
                    } else {
                        // Snapshot the PoW work (the only coins-view read) under cs_main, then grind
                        // Argon2id WITHOUT the lock below so the memory-hard work never stalls block
                        // validation, RPC, or the GUI.
                        nonce_start = m_pow_next_nonce.fetch_add(POW_MINER_BATCH_TRIES);
                        work = PrepareShadowPowWork(target, quantum_payout_script, tip, chainman.ActiveChainstate().CoinsTip());
                        should_grind = work.valid;
                        if (!should_grind) loop_sleep = std::chrono::seconds{2};
                    }
                }
            }
        }
        if (loop_sleep.count() > 0) {
            SleepPowMiner(*this, loop_sleep);
            continue;
        }
        if (should_grind) {
            const auto batch_start = std::chrono::steady_clock::now();
            proof_found = GrindShadowPowWork(work, nonce_start, 1, POW_MINER_BATCH_TRIES, proof, &tries_done);
            batch_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - batch_start);
        }

        if (tries_done > 0) {
            const uint64_t total_tries = m_pow_total_tries.fetch_add(tries_done) + tries_done;
            const int64_t now_ms = GetTime<std::chrono::milliseconds>().count();
            const int64_t start_ms = m_pow_hashrate_start_ms.load();
            if (start_ms > 0 && now_ms > start_ms) {
                m_pow_hashrate = (static_cast<double>(total_tries) * 1000.0) / static_cast<double>(now_ms - start_ms);
            }
        }

        if (proof_found) {
            // The grind ran without cs_main, so the tip may have advanced. Only claim if we mined
            // against the current tip; a stale proof would never pay out and would waste a fee.
            bool tip_still_current{false};
            {
                LOCK(cs_main);
                const CBlockIndex* tip = chain().chainman().ActiveChain().Tip();
                tip_still_current = tip && tip->GetBlockHash() == tip_hash;
            }
            if (!tip_still_current) continue;
            {
                LOCK(m_pow_miner_mutex);
                if (m_pow_claim_inflight) continue;
                m_pow_claim_inflight = true;
            }
            if (SubmitShadowPowClaim(target, target_dest, proof, error)) {
                ++m_pow_claims_submitted;
                while (!IsPowMiningClosing() && m_pow_mining_enabled.load()) {
                    bool tip_changed = false;
                    {
                        ChainstateManager& chainman = chain().chainman();
                        LOCK(cs_main);
                        const CBlockIndex* tip = chainman.ActiveChain().Tip();
                        tip_changed = tip && tip->GetBlockHash() != tip_hash;
                    }
                    if (tip_changed) break;
                    if (!SleepPowMiner(*this, std::chrono::seconds{1})) break;
                }
            } else {
                const bool conflict = IsShadowPowClaimConflict(error);
                WalletLogPrintf("Gold Rush PoW worker %d could not submit claim: %s\n", worker_id, error.original);
                if (conflict) {
                    while (!IsPowMiningClosing() && m_pow_mining_enabled.load()) {
                        bool tip_changed = false;
                        {
                            ChainstateManager& chainman = chain().chainman();
                            LOCK(cs_main);
                            const CBlockIndex* tip = chainman.ActiveChain().Tip();
                            tip_changed = tip && tip->GetBlockHash() != tip_hash;
                        }
                        if (tip_changed) break;
                        if (!SleepPowMiner(*this, std::chrono::seconds{1})) break;
                    }
                } else {
                    {
                        LOCK(m_pow_miner_mutex);
                        m_pow_claim_inflight = false;
                    }
                    SleepPowMiner(*this, std::chrono::seconds{2});
                }
            }
        }

        const int cpu_percent = std::clamp(m_pow_cpu_percent.load(), 1, 100);
        if (cpu_percent < 100 && tries_done > 0 && batch_elapsed.count() > 0) {
            const auto throttle = std::chrono::milliseconds{std::max<int64_t>(1, batch_elapsed.count() * (100 - cpu_percent) / cpu_percent)};
            SleepPowMiner(*this, throttle);
        }
    }
    WalletLogPrintf("Gold Rush PoW worker %d stopped\n", worker_id);
}

} // namespace wallet
