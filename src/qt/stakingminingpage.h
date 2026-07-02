// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_STAKINGMININGPAGE_H
#define BITCOIN_QT_STAKINGMININGPAGE_H

#include <QPointer>
#include <QSize>
#include <QString>
#include <QWidget>

class ClientModel;
class WalletModel;
class PlatformStyle;
class BitcoinAmountField;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * "Staking & Mining" tab.
 *
 * Top section  - Staking: one master toggle that enables legacy PoS staking and, automatically,
 *                Gold Rush PoS signalling/claims when the wallet is whitelisted during the epoch.
 *                Wired to the existing interfaces::Wallet staking enable.
 * Bottom section - Gold Rush Proof-of-Work: a separate opt-in for the in-process (fully integrated,
 *                no external miner) Argon2id solver, with CPU-core and CPU-% throttle controls,
 *                an auto-created quantum payout address, live status, and the 18-month
 *                lock-or-forfeit warning. Wired to interfaces::Wallet PoW-mining methods.
 */
class StakingMiningPage : public QWidget
{
    Q_OBJECT

public:
    explicit StakingMiningPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~StakingMiningPage();

    QSize minimumSizeHint() const override;

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);

private Q_SLOTS:
    void onStakingToggled(bool enabled);
    void onUnlockStakingOnlyToggled(bool enabled);
    void onUnlockQuantumLegacyStakingToggled(bool enabled);
    void onDonationToggled(bool enabled);
    void onDonationPercentChanged(int percentage);
    void onPowEnableToggled(bool enabled);
    void onPowUnlockWalletToggled(bool enabled);
    void onPowSettingsChanged(int);
    void onApplyPow();
    void onCopyPayoutAddress();
    void onCreateQuantumAddress();
    void onCopyQuantumAddress();
    void onCopyQuantumPubkey();
    void onMigrateLegacyToQuantum();
    void onMigrateGoldRushRewards();
    void onSendDemurrageAttestation();
    void onCopySelectedRGBContract();
    void onCreateSelfStakeAddress();
    void onCopySelfStakeAddress();
    void onFundSelfStakeAddress();
    void onWithdrawSelfStakeAddress();
    void onCreateOperatorKey();
    void onCopyOperatorKey();
    void onUseOperatorKeyForDelegation();
    void onFundOperatorBond();
    void onWithdrawOperatorBond();
    void onRefreshOperatorRegistry();
    void onUseRegistryOperatorForDelegation();
    void onCreateColdStakeAddress();
    void onCopyColdStakeAddress();
    void updateStatus();

private:
    const PlatformStyle* m_platform_style{nullptr};
    ClientModel* m_client_model{nullptr};
    QPointer<WalletModel> m_wallet_model;
    QTimer* m_timer{nullptr};
    bool m_updating{false}; // guard against re-entrant control->slot->control loops
    bool m_pow_apply_pending{false};
    bool m_pow_pending_enabled{false};
    bool m_pow_settings_dirty{false};
    bool m_operator_registry_loaded{false};
    int m_operator_registry_refresh_seconds{0};
    QString m_selfstake_last_action_status;
    QString m_operator_last_action_status;

    // Staking section
    QCheckBox* m_staking_enable{nullptr};
    QCheckBox* m_unlock_staking_only{nullptr};
    QCheckBox* m_unlock_quantum_legacy_staking{nullptr};
    QLabel* m_quantum_legacy_unlock_note{nullptr};
    QLabel* m_staking_status{nullptr};
    QLabel* m_stake_weight{nullptr};
    QLabel* m_goldrush_badge{nullptr};
    QLabel* m_pos_goldrush_status{nullptr};
    QCheckBox* m_donation_enable{nullptr};
    QSpinBox* m_donation_percent{nullptr};
    QLabel* m_donation_status{nullptr};

    // Proof-of-Work section
    QCheckBox* m_pow_enable{nullptr};
    QCheckBox* m_pow_unlock_wallet{nullptr};
    QSpinBox* m_pow_cores{nullptr};
    QSpinBox* m_pow_percent{nullptr};
    QLineEdit* m_pow_payout{nullptr};
    QPushButton* m_pow_copy{nullptr};
    QPushButton* m_pow_apply{nullptr};
    QLabel* m_pow_status{nullptr};
    QLabel* m_pow_warning{nullptr};

    // Quantum migration section
    QLabel* m_migration_phase{nullptr};
    QLabel* m_migration_deadline{nullptr};
    QLabel* m_migration_legacy_amount{nullptr};
    QLabel* m_migration_quantum_amount{nullptr};
    QLabel* m_migration_goldrush_amount{nullptr};
    QLabel* m_migration_advice{nullptr};
    QLabel* m_quantum_address_count{nullptr};
    QLabel* m_coldstake_count{nullptr};
    QLineEdit* m_quantum_address{nullptr};
    QLineEdit* m_quantum_pubkey{nullptr};
    QPushButton* m_quantum_new{nullptr};
    QPushButton* m_quantum_copy{nullptr};
    QPushButton* m_quantum_pubkey_copy{nullptr};
    QPushButton* m_migration_legacy_sweep{nullptr};
    QPushButton* m_migration_goldrush_sweep{nullptr};
    QLabel* m_migration_action_status{nullptr};
    QLabel* m_demurrage_status{nullptr};
    QLabel* m_demurrage_amounts{nullptr};
    QLabel* m_demurrage_guards{nullptr};
    QPushButton* m_demurrage_attest{nullptr};
    QTableWidget* m_rgb_assets{nullptr};
    QPushButton* m_rgb_copy_contract{nullptr};
    QLabel* m_rgb_status{nullptr};
    QTableWidget* m_eutxo_states{nullptr};
    QLabel* m_eutxo_status{nullptr};
    QComboBox* m_selfstake_lock_period{nullptr};
    QComboBox* m_selfstake_selector{nullptr};
    QLineEdit* m_selfstake_address{nullptr};
    QPushButton* m_selfstake_new{nullptr};
    QPushButton* m_selfstake_copy{nullptr};
    QComboBox* m_selfstake_output_selector{nullptr};
    BitcoinAmountField* m_selfstake_fund_amount{nullptr};
    QPushButton* m_selfstake_fund{nullptr};
    QPushButton* m_selfstake_withdraw{nullptr};
    QLabel* m_selfstake_status{nullptr};
    QLineEdit* m_operator_address{nullptr};
    QComboBox* m_operator_selector{nullptr};
    QLineEdit* m_operator_pubkey{nullptr};
    QPushButton* m_operator_new{nullptr};
    QPushButton* m_operator_copy{nullptr};
    QPushButton* m_operator_use_for_delegation{nullptr};
    BitcoinAmountField* m_operator_bond_amount{nullptr};
    QPushButton* m_operator_fund{nullptr};
    QPushButton* m_operator_withdraw{nullptr};
    QLabel* m_operator_status{nullptr};
    QTableWidget* m_operator_registry{nullptr};
    QPushButton* m_operator_registry_refresh{nullptr};
    QPushButton* m_operator_registry_use{nullptr};
    QLabel* m_operator_registry_status{nullptr};
    QLabel* m_coldstake_quantum_available{nullptr};
    QComboBox* m_coldstake_lock_period{nullptr};
    QComboBox* m_coldstake_operator_selector{nullptr};
    QComboBox* m_coldstake_existing_selector{nullptr};
    QLineEdit* m_coldstake_address{nullptr};
    QPushButton* m_coldstake_new{nullptr};
    QPushButton* m_coldstake_copy{nullptr};
    QLabel* m_coldstake_status{nullptr};

    void setupUi();
    void refreshControlsEnabled();
    void refreshOperatorRegistry();
    void resetStatusForNoWallet();
    void applyDonationPercentage(unsigned int percentage);
    bool requestStakingOnlyUnlock();
    bool requestNormalUnlock();
    QString selectedColdStakeOperatorPubKey() const;
    void setColdStakeOperatorSelection(const QString& pubkey, const QString& label);
};

#endif // BITCOIN_QT_STAKINGMININGPAGE_H
