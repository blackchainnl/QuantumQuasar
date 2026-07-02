// Copyright (c) 2014-2023 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Staking start/stop algos by Qtum
// Copyright (c) 2016-2023 The Qtum developers

#ifndef BLACKCOIN_WALLET_STAKE_H
#define BLACKCOIN_WALLET_STAKE_H

#include <wallet/spend.h>
#include <wallet/wallet.h>

namespace wallet {
/* Start staking */
void StartStake(CWallet& wallet);

/* Stop staking */
void StopStake(CWallet& wallet);

uint64_t GetStakeWeight(const CWallet& wallet);
void AvailableCoinsForStaking(const CWallet& wallet,
                           std::vector<std::pair<const CWalletTx*, unsigned int> >& vCoins,
                           const CCoinControl* coinControl = nullptr,
                           const CoinFilterParams& params = {}) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
bool SelectCoinsForStaking(const CWallet& wallet, CAmount& nTargetValue, std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet, CAmount& nValueRet);
bool CreateCoinStake(CWallet& wallet, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& tx, CAmount& nFees, CTxDestination destination, const std::vector<CTransactionRef>& selected_txs = {});

struct DemurrageAttestationTxResult
{
    CTransactionRef tx;
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> witness_program;
    COutPoint replay_anchor;
    int attestation_vout{-1};
    CAmount fee{0};
};

struct QuantumColdStakeRedelegationOptions
{
    bool dry_run{true};
    bool enforce_pool_cap{true};
    bool require_verified_operator{true};
    std::optional<CFeeRate> fee_rate;
    std::string label{"redelegated-coldstake"};
};

struct QuantumColdStakeRedelegationResult
{
    bool dry_run{true};
    CTxDestination source_dest;
    CTxDestination target_dest;
    bool target_wallet_backed{false};
    CAmount input_amount{0};
    CAmount output_amount{0};
    CAmount fee{0};
    int vsize{0};
    bool operator_commitment_verified{false};
    CAmount post_total_coldstake{0};
    CAmount post_operator_value{0};
    int64_t post_share_bps{0};
    bool would_exceed_cap{false};
    bool cap_enforced{true};
    bool cap_filter_unlocked{false};
    CTransactionRef tx;
};

bool CreateDemurrageAttestationTransaction(
    CWallet& wallet,
    const std::vector<unsigned char>& witness_program,
    const CCoinControl& coin_control,
    bool sign,
    DemurrageAttestationTxResult& result,
    bilingual_str& error);

bool CreateQuantumColdStakeRedelegationTransaction(
    CWallet& wallet,
    const CTxDestination& source_dest,
    const std::vector<unsigned char>& target_staking_pubkey,
    const QuantumColdStakeRedelegationOptions& options,
    QuantumColdStakeRedelegationResult& result,
    bilingual_str& error);

int MaybeAutoDemurrageAttest(CWallet& wallet);
int MaybeAutoShadowSignal(CWallet& wallet);
int MaybeAutoRedelegateQuantumColdStake(CWallet& wallet);

} // namespace wallet

#endif // BLACKCOIN_WALLET_STAKE_H
