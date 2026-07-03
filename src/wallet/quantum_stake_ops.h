// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_QUANTUM_STAKE_OPS_H
#define BITCOIN_WALLET_QUANTUM_STAKE_OPS_H

#include <consensus/amount.h>
#include <interfaces/wallet.h>
#include <primitives/transaction.h>
#include <util/result.h>

#include <optional>
#include <string>
#include <vector>

namespace wallet {

class CWallet;

interfaces::WalletQuantumColdStakeBalanceInfo MakeWalletColdStakeBalanceInfo(const CWallet& wallet, const std::string& address);

interfaces::WalletQuantumOperatorBondInfo MakeWalletOperatorBondInfo(const CWallet& wallet, const std::string& operator_address);
interfaces::WalletQuantumOperatorBondInfo MakeWalletTieredStakeBondInfo(const CWallet& wallet, const std::string& address, bool require_operator_lock);
std::vector<interfaces::WalletQuantumStakeOutputInfo> ListTieredStakeOutputs(const CWallet& wallet, const std::string& address, bool require_operator_lock);

util::Result<interfaces::WalletQuantumOperatorBondTx> FundTieredStakeAddress(
    CWallet& wallet,
    const std::string& address,
    CAmount amount,
    bool require_operator_lock,
    std::string comment);

util::Result<interfaces::WalletQuantumOperatorBondTx> WithdrawTieredStakeAddress(
    CWallet& wallet,
    const std::string& address,
    bool require_operator_lock,
    const std::string& unbonding_label,
    const std::string& withdrawal_label,
    std::string unbonding_comment,
    std::string withdrawal_comment,
    std::optional<COutPoint> selected_outpoint = std::nullopt,
    bool allow_all_outputs = true);

util::Result<interfaces::WalletQuantumOperatorBondTx> FundColdStakeDelegationAddress(CWallet& wallet, const std::string& address, CAmount amount, bool allow_goldrush_migration);
util::Result<interfaces::WalletQuantumOperatorBondTx> WithdrawColdStakeDelegationAddress(
    CWallet& wallet,
    const std::string& address,
    std::optional<COutPoint> selected_outpoint = std::nullopt,
    bool allow_all_outputs = true);

util::Result<interfaces::WalletQuantumActionTx> CreateQuantumMigrationSweep(
    CWallet& wallet,
    bool goldrush_rewards_only,
    bool allow_goldrush_epoch = false,
    const std::string& destination_label = "",
    const std::string& comment_override = "");

} // namespace wallet

#endif // BITCOIN_WALLET_QUANTUM_STAKE_OPS_H
