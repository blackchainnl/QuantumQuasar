// Copyright (c) 2018-2022 Blackcoin Core Developers
// Copyright (c) 2018-2022 Blackcoin More Developers
// Copyright (c) 2018-2022 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_WALLET_H
#define BITCOIN_INTERFACES_WALLET_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <pubkey.h>
#include <script/script.h>
#include <support/allocators/secure.h>
#include <util/fs.h>
#include <util/message.h>
#include <util/result.h>
#include <util/ui_change_type.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

class CFeeRate;
class CKey;
enum class FeeReason;
enum class OutputType;
enum class TransactionError;
struct PartiallySignedTransaction;
struct bilingual_str;
namespace wallet {
class CCoinControl;
class CWallet;
enum class AddressPurpose;
enum isminetype : unsigned int;
struct CRecipient;
struct WalletContext;
using isminefilter = std::underlying_type<isminetype>::type;
} // namespace wallet

namespace interfaces {

class Handler;
struct WalletAddress;
struct WalletBalances;
struct WalletTx;
struct WalletTxOut;
struct WalletTxStatus;
struct WalletMigrationResult;
struct WalletPowMiningInfo;
struct WalletQuantumAddressInfo;
struct WalletQuantumColdStakeBalanceInfo;
struct WalletQuantumColdStakeInfo;
struct WalletQuantumOperatorBondInfo;
struct WalletQuantumOperatorBondTx;
struct WalletQuantumStakeOutputInfo;
struct WalletQuantumPoolInfo;
struct WalletQuantumPoolOperatorInfo;
struct WalletMigrationStatus;
struct WalletRGBAssignmentInfo;
struct WalletRGBAssetInfo;
struct WalletEUTXOStateInfo;
struct WalletDemurrageOutputInfo;
struct WalletDemurrageInfo;
struct WalletQuantumActionTx;

using WalletOrderForm = std::vector<std::pair<std::string, std::string>>;
using WalletValueMap = std::map<std::string, std::string>;

//! Interface for accessing a wallet.
class Wallet
{
public:
    virtual ~Wallet() {}

    //! Encrypt wallet.
    virtual bool encryptWallet(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet has private keys.
    virtual bool hasPrivateKeys() = 0;

    //! Return whether wallet is encrypted.
    virtual bool isCrypted() = 0;

    //! Lock wallet.
    virtual bool lock() = 0;

    //! Unlock wallet.
    virtual bool unlock(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet is locked.
    virtual bool isLocked() = 0;

    //! Change wallet passphrase.
    virtual bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) = 0;

    //! Abort a rescan.
    virtual void abortRescan() = 0;

    //! Back up wallet.
    virtual bool backupWallet(const std::string& filename) = 0;

    //! Get wallet name.
    virtual std::string getWalletName() = 0;

    // Get a new address.
    virtual util::Result<CTxDestination> getNewDestination(const OutputType type, const std::string& label) = 0;

    //! Get public key.
    virtual bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) = 0;

    //! Sign message
    virtual SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) = 0;

    //! Return whether wallet has private key.
    virtual bool isSpendable(const CTxDestination& dest) = 0;

    //! Return whether wallet has watch only keys.
    virtual bool haveWatchOnly() = 0;

    //! Add or update address.
    virtual bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<wallet::AddressPurpose>& purpose) = 0;

    // Remove address.
    virtual bool delAddressBook(const CTxDestination& dest) = 0;

    //! Look up address in wallet, return whether exists.
    virtual bool getAddress(const CTxDestination& dest,
        std::string* name,
        wallet::isminetype* is_mine,
        wallet::AddressPurpose* purpose) = 0;

    //! Get wallet address list.
    virtual std::vector<WalletAddress> getAddresses() const = 0;

    //! Get receive requests.
    virtual std::vector<std::string> getAddressReceiveRequests() = 0;

    //! Save or remove receive request.
    virtual bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) = 0;

    //! Display address on external signer
    virtual bool displayAddress(const CTxDestination& dest) = 0;

    //! Lock coin.
    virtual bool lockCoin(const COutPoint& output, const bool write_to_db) = 0;

    //! Unlock coin.
    virtual bool unlockCoin(const COutPoint& output) = 0;

    //! Return whether coin is locked.
    virtual bool isLockedCoin(const COutPoint& output) = 0;

    //! List locked coins.
    virtual void listLockedCoins(std::vector<COutPoint>& outputs) = 0;

    //! Create transaction.
    virtual util::Result<CTransactionRef> createTransaction(const std::vector<wallet::CRecipient>& recipients,
        const wallet::CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee) = 0;

    //! Commit transaction.
    virtual void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) = 0;

    //! Return whether transaction can be abandoned.
    virtual bool transactionCanBeAbandoned(const uint256& txid) = 0;

    //! Abandon transaction.
    virtual bool abandonTransaction(const uint256& txid) = 0;

    //! Get a transaction.
    virtual CTransactionRef getTx(const uint256& txid) = 0;

    //! Get transaction information.
    virtual WalletTx getWalletTx(const uint256& txid) = 0;

    //! Get list of all wallet transactions.
    virtual std::set<WalletTx> getWalletTxs() = 0;

    //! Try to get updated status for a particular transaction, if possible without blocking.
    virtual bool tryGetTxStatus(const uint256& txid,
        WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) = 0;

    //! Get transaction details.
    virtual WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) = 0;

    //! Fill PSBT.
    virtual TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) = 0;

    //! Finalize and extract PSBT with wallet/chain-aware script verification flags.
    virtual bool finalizePSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& mtx) = 0;

    //! Get balances.
    virtual WalletBalances getBalances() = 0;

    //! Get balances if possible without blocking.
    virtual bool tryGetBalances(WalletBalances& balances, uint256& block_hash) = 0;

    //! Get balance.
    virtual CAmount getBalance() = 0;

    //! Get available balance.
    virtual CAmount getAvailableBalance(const wallet::CCoinControl& coin_control) = 0;

    //! Return whether transaction input belongs to wallet.
    virtual wallet::isminetype txinIsMine(const CTxIn& txin) = 0;

    //! Return whether transaction output belongs to wallet.
    virtual wallet::isminetype txoutIsMine(const CTxOut& txout) = 0;

    //! Return debit amount if transaction input belongs to wallet.
    virtual CAmount getDebit(const CTxIn& txin, wallet::isminefilter filter) = 0;

    //! Return credit amount if transaction input belongs to wallet.
    virtual CAmount getCredit(const CTxOut& txout, wallet::isminefilter filter) = 0;

    //! Return AvailableCoins + LockedCoins grouped by wallet address.
    //! (put change in one group with wallet address)
    using CoinsList = std::map<CTxDestination, std::vector<std::tuple<COutPoint, WalletTxOut>>>;
    virtual CoinsList listCoins() = 0;

    //! Return wallet transaction output information.
    virtual std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) = 0;

    //! Get minimum fee.
    virtual CAmount getMinimumFee(unsigned int tx_bytes,
        const wallet::CCoinControl& coin_control,
        int64_t current_time) = 0;

    // Return whether HD enabled.
    virtual bool hdEnabled() = 0;

    // Return whether the wallet is blank.
    virtual bool canGetAddresses() = 0;

    // Return whether private keys enabled.
    virtual bool privateKeysDisabled() = 0;

    // Return whether the wallet contains a Taproot scriptPubKeyMan
    virtual bool taprootEnabled() = 0;

    // Return whether wallet uses an external signer.
    virtual bool hasExternalSigner() = 0;

    // Get default address type.
    virtual OutputType getDefaultAddressType() = 0;

    //! Get max tx fee.
    virtual CAmount getDefaultMaxTxFee() = 0;

    // Remove wallet.
    virtual void remove() = 0;

    //! Get donation percentage
    virtual unsigned int getDonationPercentage() = 0;

    //! Set donation percentage for this wallet instance
    virtual void setDonationPercentage(unsigned int percentage) = 0;

    //! Try get the stake weight
    virtual bool tryGetStakeWeight(uint64_t& nWeight) = 0;

    //! Get the stake weight
    virtual uint64_t getStakeWeight() = 0;

    //! Get last coin stake search interval
    virtual int64_t getLastCoinStakeSearchInterval() = 0;

    //! Get wallet unlock for staking only
    virtual bool getWalletUnlockStakingOnly() = 0;

    //! Set wallet unlock for staking only
    virtual void setWalletUnlockStakingOnly(bool unlock) = 0;

    //! Set wallet enabled for staking
    virtual void setEnabledStaking(bool enabled) = 0;

    //! Get wallet enabled for staking
    virtual bool getEnabledStaking() = 0;

    //! Configure the built-in (in-process) Gold Rush PoW miner. No external miner is used.
    //! @param enabled  start/stop in-process PoW mining
    //! @param threads  worker threads / CPU cores (>=1)
    //! @param cpu_percent  per-core CPU duty-cycle target, 1..100
    //! Returns false (and fills `error`) if PoW mining cannot be configured (e.g. wallet locked).
    virtual bool setPowMining(bool enabled, int threads, int cpu_percent, std::string& error) = 0;

    //! Read the built-in Gold Rush PoW miner status (config, hashrate, epoch, payout).
    virtual WalletPowMiningInfo getPowMiningInfo() = 0;

    //! Create a wallet-backed Blackcoin ML-DSA migration address.
    virtual util::Result<WalletQuantumAddressInfo> createQuantumAddress(const std::string& label) = 0;

    //! Create a wallet-backed tiered Blackcoin ML-DSA staking address.
    virtual util::Result<WalletQuantumAddressInfo> createQuantumStakeAddress(const std::string& label, uint16_t unbonding_blocks) = 0;

    //! List wallet-backed Blackcoin ML-DSA migration addresses.
    virtual std::vector<WalletQuantumAddressInfo> listQuantumAddresses() = 0;

    //! List wallet-known Quantum Cold-Stake delegations.
    virtual std::vector<WalletQuantumColdStakeInfo> listQuantumColdStakeDelegations() = 0;

    //! Return verified local Quantum Cold-Stake operator registry state.
    virtual WalletQuantumPoolInfo getQuantumPoolInfo() = 0;

    //! Return wallet-owned operator bond status for a 30-day operator address.
    virtual WalletQuantumOperatorBondInfo getQuantumOperatorBondInfo(const std::string& operator_address) = 0;

    //! Fund this wallet's 30-day operator bond address from spendable wallet funds.
    virtual util::Result<WalletQuantumOperatorBondTx> fundQuantumOperatorBond(const std::string& operator_address, CAmount amount) = 0;

    //! Stop operating: start unbonding if bonded, or complete withdrawal if already mature.
    virtual util::Result<WalletQuantumOperatorBondTx> withdrawQuantumOperatorBond(const std::string& operator_address) = 0;

    //! Return wallet-owned tiered self-staking address status.
    virtual WalletQuantumOperatorBondInfo getQuantumStakeAddressBondInfo(const std::string& stake_address) = 0;

    //! List wallet-owned staking UTXOs for a tiered self-staking address.
    virtual std::vector<WalletQuantumStakeOutputInfo> listQuantumStakeOutputs(const std::string& stake_address) = 0;

    //! Fund this wallet's tiered self-staking address from spendable wallet funds.
    virtual util::Result<WalletQuantumOperatorBondTx> fundQuantumStakeAddress(const std::string& stake_address, CAmount amount) = 0;

    //! Stop self-staking: start unbonding if bonded, or complete withdrawal if already mature.
    virtual util::Result<WalletQuantumOperatorBondTx> withdrawQuantumStakeAddress(const std::string& stake_address) = 0;

    //! Stop or withdraw one selected self-staking UTXO.
    virtual util::Result<WalletQuantumOperatorBondTx> withdrawQuantumStakeOutput(const std::string& stake_address, const COutPoint& outpoint) = 0;

    //! Create a Quantum Cold-Stake deposit address using a hex ML-DSA staking public key.
    virtual util::Result<WalletQuantumColdStakeInfo> createQuantumColdStakeAddress(const std::string& staking_pubkey_hex, const std::string& label, uint16_t unbonding_blocks) = 0;

    //! Return wallet-owned Quantum Cold-Stake delegation funding status.
    virtual WalletQuantumColdStakeBalanceInfo getQuantumColdStakeBalanceInfo(const std::string& coldstake_address) = 0;

    //! Fund this wallet's Quantum Cold-Stake delegation address from spendable quantum funds.
    virtual util::Result<WalletQuantumOperatorBondTx> fundQuantumColdStakeAddress(const std::string& coldstake_address, CAmount amount) = 0;

    //! Withdraw this wallet's Quantum Cold-Stake delegation funds to a fresh quantum address.
    virtual util::Result<WalletQuantumOperatorBondTx> withdrawQuantumColdStakeAddress(const std::string& coldstake_address) = 0;

    //! Read wallet migration progress and deadline state.
    virtual WalletMigrationStatus getMigrationStatus() = 0;

    //! Sweep spendable legacy coins into a wallet-backed quantum address.
    virtual util::Result<WalletQuantumActionTx> migrateLegacyToQuantum() = 0;

    //! Move wallet-owned Gold Rush reward outputs to a fresh quantum address during the migration window.
    virtual util::Result<WalletQuantumActionTx> migrateGoldRushRewards() = 0;

    //! List wallet-owned RGB assets and assignments.
    virtual std::vector<WalletRGBAssetInfo> listRGBAssets(bool include_spent = false) = 0;

    //! List wallet-persisted EUTXO states.
    virtual std::vector<WalletEUTXOStateInfo> listEUTXOStates(bool include_spent = false) = 0;

    //! Read wallet demurrage exposure for direct quantum outputs.
    virtual WalletDemurrageInfo getDemurrageInfo() = 0;

    //! Create and broadcast a demurrage liveness attestation for a wallet-backed quantum address.
    virtual util::Result<WalletQuantumActionTx> sendDemurrageAttestation(const std::string& address) = 0;

    //! Return whether is a legacy wallet
    virtual bool isLegacy() = 0;

    //! Register handler for unload message.
    using UnloadFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleUnload(UnloadFn fn) = 0;

    //! Register handler for show progress messages.
    using ShowProgressFn = std::function<void(const std::string& title, int progress)>;
    virtual std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) = 0;

    //! Register handler for status changed messages.
    using StatusChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) = 0;

    //! Register handler for address book changed messages.
    using AddressBookChangedFn = std::function<void(const CTxDestination& address,
        const std::string& label,
        bool is_mine,
        wallet::AddressPurpose purpose,
        ChangeType status)>;
    virtual std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) = 0;

    //! Register handler for transaction changed messages.
    using TransactionChangedFn = std::function<void(const uint256& txid, ChangeType status)>;
    virtual std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) = 0;

    //! Register handler for watchonly changed messages.
    using WatchOnlyChangedFn = std::function<void(bool have_watch_only)>;
    virtual std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) = 0;

    //! Register handler for keypool changed messages.
    using CanGetAddressesChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) = 0;

    //! Return pointer to internal wallet class, useful for testing.
    virtual wallet::CWallet* wallet() { return nullptr; }
};

//! Wallet chain client that in addition to having chain client methods for
//! starting up, shutting down, and registering RPCs, also has additional
//! methods (called by the GUI) to load and create wallets.
class WalletLoader : public ChainClient
{
public:
    //! Create new wallet.
    virtual util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) = 0;

    //! Load existing wallet.
    virtual util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) = 0;

    //! Return default wallet directory.
    virtual std::string getWalletDir() = 0;

    //! Restore backup wallet
    virtual util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings) = 0;

    //! Migrate a wallet
    virtual util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase) = 0;

    //! Return available wallets in wallet directory.
    virtual std::vector<std::string> listWalletDir() = 0;

    //! Return interfaces for accessing wallets (if any).
    virtual std::vector<std::unique_ptr<Wallet>> getWallets() = 0;

    //! Register handler for load wallet messages. This callback is triggered by
    //! createWallet and loadWallet above, and also triggered when wallets are
    //! loaded at startup or by RPC.
    using LoadWalletFn = std::function<void(std::unique_ptr<Wallet> wallet)>;
    virtual std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) = 0;

    //! Return pointer to internal context, useful for testing.
    virtual wallet::WalletContext* context() { return nullptr; }
};

//! Information about one wallet address.
struct WalletAddress
{
    CTxDestination dest;
    wallet::isminetype is_mine;
    wallet::AddressPurpose purpose;
    std::string name;

    WalletAddress(CTxDestination dest, wallet::isminetype is_mine, wallet::AddressPurpose purpose, std::string name)
        : dest(std::move(dest)), is_mine(is_mine), purpose(std::move(purpose)), name(std::move(name))
    {
    }
};

//! Collection of wallet balances.
struct WalletBalances
{
    CAmount balance = 0;
    CAmount legacy_balance = 0;
    CAmount quantum_balance = 0;
    CAmount unconfirmed_balance = 0;
    CAmount immature_balance = 0;
    CAmount stake = 0;
    bool have_watch_only = false;
    CAmount watch_only_balance = 0;
    CAmount unconfirmed_watch_only_balance = 0;
    CAmount immature_watch_only_balance = 0;
    CAmount watch_only_stake = 0;

    bool balanceChanged(const WalletBalances& prev) const
    {
        return balance != prev.balance || legacy_balance != prev.legacy_balance || quantum_balance != prev.quantum_balance ||
               unconfirmed_balance != prev.unconfirmed_balance ||
               immature_balance != prev.immature_balance || stake != prev.stake || watch_only_balance != prev.watch_only_balance ||
               unconfirmed_watch_only_balance != prev.unconfirmed_watch_only_balance ||
               immature_watch_only_balance != prev.immature_watch_only_balance || watch_only_stake != prev.watch_only_stake;
    }
};

// Wallet transaction information.
struct WalletTx
{
    CTransactionRef tx;
    std::vector<wallet::isminetype> txin_is_mine;
    std::vector<wallet::isminetype> txout_is_mine;
    std::vector<bool> txout_is_change;
    std::vector<CTxDestination> txout_address;
    std::vector<wallet::isminetype> txout_address_is_mine;
    CAmount credit;
    CAmount debit;
    CAmount change;
    int64_t time;
    std::map<std::string, std::string> value_map;
    bool is_coinbase;
    bool is_coinstake;
    bool is_in_main_chain;

    bool operator<(const WalletTx& a) const { return tx->GetHash() < a.tx->GetHash(); }
};

//! Updated transaction status.
struct WalletTxStatus
{
    int block_height;
    int blocks_to_maturity;
    int depth_in_main_chain;
    unsigned int time_received;
    uint32_t lock_time;
    bool is_trusted;
    bool is_abandoned;
    bool is_coinbase;
    bool is_coinstake;
    bool is_in_main_chain;
};

//! Wallet transaction output.
struct WalletTxOut
{
    CTxOut txout;
    int64_t time;
    int depth_in_main_chain = -1;
    bool is_spent = false;
};

//! Migrated wallet info
struct WalletMigrationResult
{
    std::unique_ptr<Wallet> wallet;
    std::optional<std::string> watchonly_wallet_name;
    std::optional<std::string> solvables_wallet_name;
    fs::path backup_path;
};

//! Status of the in-process (built-in) Gold Rush Proof-of-Work miner. No external miner exists.
struct WalletPowMiningInfo
{
    bool enabled{false};            //!< whether in-process PoW mining is currently requested
    int threads{0};                 //!< worker threads (CPU cores) configured
    int cpu_percent{0};             //!< per-core CPU duty-cycle target, 1..100
    double hashrate{0.0};           //!< Argon2id tries per second (aggregate)
    bool epoch_active{false};       //!< whether the Gold Rush reward window is currently open
    int blocks_remaining{0};        //!< blocks left in the Gold Rush window (0 if inactive)
    std::string payout_address;     //!< auto-created quantum (ML-DSA) payout address (empty until created)
    CAmount accrued_jackpot{0};     //!< PoW jackpot currently accrued in the pool
    CAmount next_claim_payout{0};   //!< estimated payout for a valid PoW claim in the next block
    int64_t claims_submitted{0};    //!< number of PoW claims this miner has submitted
    CAmount pos_accrued_jackpot{0}; //!< PoS jackpot currently accrued in the pool
    CAmount pos_next_payout_pool{0}; //!< estimated PoS pool paid by the next qualified solver/signaler block
    CAmount pos_estimated_payout_per_signaler{0}; //!< estimated PoS share per active signaler
    int pos_active_signalers{0};     //!< active signal-once participants still inside the 14-day window
    int pos_claim_count{0};          //!< number of accepted PoS Gold Rush payouts
    int pos_last_payout_height{0};   //!< last accepted PoS Gold Rush payout height, or 0 if none
    int shadow_whitelist_height{0};   //!< deterministic Gold Rush whitelist snapshot height
    int shadow_reward_start_height{0};//!< Gold Rush reward start height
    int shadow_reward_end_height{0};  //!< Gold Rush reward end height
    bool wallet_goldrush_status_available{true}; //!< false when wallet status could not be read without blocking
    int wallet_whitelisted_scripts{0}; //!< wallet-owned spendable scripts in the deterministic whitelist
    bool wallet_recent_solve_qualified{false}; //!< wallet has a whitelisted script with a recent solver marker
    bool wallet_active_signal{false}; //!< wallet has an active QQSIGNAL entry
    int wallet_blocks_until_solver_expiry{0}; //!< max recent-solver expiry across wallet-owned whitelisted scripts
    bool payout_address_available{true}; //!< false when the wallet lock is busy and the cached address was not read
};

//! Wallet-backed Blackcoin ML-DSA migration address metadata.
struct WalletQuantumAddressInfo
{
    std::string address;
    std::string label;
    std::string public_key;
    int64_t creation_time{0};
    bool encrypted{false};
    bool tiered{false};
    uint16_t unbonding_blocks{0};
    uint32_t unlock_height{0};
};

//! Wallet-known Quantum Cold-Stake delegation metadata.
struct WalletQuantumColdStakeInfo
{
    std::string address;
    std::string label;
    int64_t creation_time{0};
    bool has_staker_key{false};
    bool has_owner_key{false};
    bool tiered{false};
    uint16_t unbonding_blocks{0};
    uint32_t unlock_height{0};
};

//! Wallet-owned Quantum Cold-Stake delegation balance.
struct WalletQuantumColdStakeBalanceInfo
{
    bool available{true};
    bool valid_delegation_address{false};
    CAmount amount{0};
    int outputs{0};
    CAmount spendable_amount{0};
    int spendable_outputs{0};
    int current_height{0};
};

//! Verified local Quantum Cold-Stake operator registry entry.
struct WalletQuantumPoolOperatorInfo
{
    std::string staking_pubkey_hash;
    std::string staking_pubkey;
    CAmount verified_value{0};
    int64_t share_bps{0};
    int verified_claims{0};
    int invalid_claims{0};
    bool operator_commitment_verified{false};
    bool over_cap{false};
};

//! Verified local Quantum Cold-Stake operator registry state.
struct WalletQuantumPoolInfo
{
    bool available{true};
    CAmount total_coldstake{0};
    int64_t cap_bps{0};
    std::vector<WalletQuantumPoolOperatorInfo> operators;
};

//! Wallet-owned Quantum Cold-Stake operator bond state.
struct WalletQuantumOperatorBondInfo
{
    bool available{true};
    bool valid_operator_address{false};
    CAmount bonded_amount{0};
    int bonded_outputs{0};
    CAmount unbonding_amount{0};
    int unbonding_outputs{0};
    CAmount withdrawable_amount{0};
    int withdrawable_outputs{0};
    uint32_t next_unlock_height{0};
    int current_height{0};
};

//! Wallet-owned tiered quantum staking UTXO.
struct WalletQuantumStakeOutputInfo
{
    std::string txid;
    uint32_t vout{0};
    std::string address;
    CAmount amount{0};
    int depth{0};
    std::string state; //!< bonded, unbonding, or withdrawable
    uint32_t unlock_height{0};
    bool spendable{false};
};

//! Result from a wallet-created operator bond transaction.
struct WalletQuantumOperatorBondTx
{
    std::string txid;
    std::string address;
    CAmount amount{0};
    CAmount fee{0};
    uint32_t unlock_height{0};
    bool started_unbonding{false};
    bool completed_withdrawal{false};
};

//! Wallet migration progress and deadline state.
struct WalletMigrationStatus
{
    bool available{true};
    std::string phase{"unknown"};
    int64_t median_time{0};
    int64_t deadline_mtp{0};
    bool deadline_scheduled{false};
    int64_t seconds_until_deadline{0};
    int64_t blocks_until_deadline_est{0};
    bool deadline_passed{false};
    unsigned int eligible_legacy_inputs{0};
    CAmount eligible_legacy_amount{0};
    unsigned int migrated_quantum_outputs{0};
    CAmount migrated_quantum_amount{0};
    unsigned int direct_quantum_outputs{0};
    CAmount direct_quantum_amount{0};
    unsigned int staked_quantum_outputs{0};
    CAmount staked_quantum_amount{0};
    unsigned int goldrush_reward_outputs_needing_move{0};
    CAmount goldrush_reward_amount_needing_move{0};
    bool goldrush_remigration_active{false};
    bool quantum_spends_active{false};
    std::string advice;
};

//! Generic wallet-created maintenance transaction result.
struct WalletQuantumActionTx
{
    std::string txid;
    std::string address;
    CAmount amount{0};
    CAmount fee{0};
    int vsize{0};
    unsigned int selected_inputs{0};
    CAmount selected_amount{0};
    std::string warning;
};

//! Wallet-owned RGB assignment metadata.
struct WalletRGBAssignmentInfo
{
    std::string txid;
    uint32_t vout{0};
    uint64_t amount{0};
    bool spent{false};
    int64_t creation_time{0};
};

//! Wallet-owned RGB asset summary.
struct WalletRGBAssetInfo
{
    std::string contract_id;
    std::string ticker;
    std::string name;
    uint64_t total_supply{0};
    uint64_t balance{0};
    int64_t creation_time{0};
    bool proof_available{false};
    int proof_transition_count{0};
    int transition_count{0};
    std::vector<WalletRGBAssignmentInfo> assignments;
};

//! Wallet-persisted EUTXO state summary.
struct WalletEUTXOStateInfo
{
    std::string txid;
    uint32_t vout{0};
    CAmount amount{0};
    std::string datum_hex;
    std::string validator_hex;
    std::string address;
    int64_t creation_time{0};
    bool spent{false};
};

//! Per-output demurrage state.
struct WalletDemurrageOutputInfo
{
    std::string txid;
    uint32_t vout{0};
    std::string address;
    int depth{0};
    int coin_height{0};
    std::optional<int> latest_attestation_height;
    int inactive_blocks{0};
    int64_t remaining_ppm{0};
    CAmount nominal_amount{0};
    CAmount effective_amount{0};
    CAmount burned_if_spent_amount{0};
    bool locked{false};
    bool attestation_due{false};
    int blocks_until_decay{0};
    int blocks_until_lock{0};
    std::string action;
};

//! Wallet demurrage exposure summary.
struct WalletDemurrageInfo
{
    bool available{true};
    bool demurrage_active{false};
    int tip_height{-1};
    int evaluation_height{0};
    int64_t evaluation_time{0};
    int demurrage_activation_height{0};
    int demurrage_effective_activation_height{0};
    bool demurrage_height_guard_satisfied{false};
    bool demurrage_post_migration_guard_satisfied{false};
    bool wallet_staking_enabled{false};
    int quantum_outputs{0};
    int decaying_outputs{0};
    int locked_outputs{0};
    int attestation_due_outputs{0};
    CAmount nominal_amount{0};
    CAmount effective_amount{0};
    CAmount burned_if_spent_amount{0};
    std::vector<WalletDemurrageOutputInfo> outputs;
};

//! Return implementation of Wallet interface. This function is defined in
//! dummywallet.cpp and throws if the wallet component is not compiled.
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet);

//! Return implementation of ChainClient interface for a wallet loader. This
//! function will be undefined in builds where ENABLE_WALLET is false.
std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_WALLET_H
