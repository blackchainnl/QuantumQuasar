// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/stakingminingpage.h>

#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <interfaces/wallet.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <thread>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

namespace {
QString formatBLK(CAmount amount)
{
    // Light-touch formatter (8 decimals); the page is informational, not a money entry surface.
    const double v = static_cast<double>(amount) / 100000000.0;
    return QString::number(v, 'f', 8) + QStringLiteral(" BLK");
}
} // namespace

StakingMiningPage::StakingMiningPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent), m_platform_style(platformStyle)
{
    setupUi();

    m_timer = new QTimer(this);
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &StakingMiningPage::updateStatus);

    connect(m_staking_enable, &QCheckBox::clicked, this, &StakingMiningPage::onStakingToggled);
    connect(m_unlock_staking_only, &QCheckBox::clicked, this, &StakingMiningPage::onUnlockStakingOnlyToggled);
    connect(m_unlock_quantum_legacy_staking, &QCheckBox::clicked, this, &StakingMiningPage::onUnlockQuantumLegacyStakingToggled);
    connect(m_donation_enable, &QCheckBox::clicked, this, &StakingMiningPage::onDonationToggled);
    connect(m_donation_percent, qOverload<int>(&QSpinBox::valueChanged), this, &StakingMiningPage::onDonationPercentChanged);
    connect(m_pow_enable, &QCheckBox::clicked, this, &StakingMiningPage::onPowEnableToggled);
    connect(m_pow_unlock_wallet, &QCheckBox::clicked, this, &StakingMiningPage::onPowUnlockWalletToggled);
    connect(m_pow_apply, &QPushButton::clicked, this, &StakingMiningPage::onApplyPow);
    connect(m_pow_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyPayoutAddress);
    connect(m_quantum_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateQuantumAddress);
    connect(m_quantum_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyQuantumAddress);
    connect(m_quantum_pubkey_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyQuantumPubkey);
    connect(m_coldstake_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateColdStakeAddress);
    connect(m_coldstake_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyColdStakeAddress);
    connect(m_coldstake_staker_pubkey, &QLineEdit::textChanged, this, [this]() { refreshControlsEnabled(); });
}

StakingMiningPage::~StakingMiningPage() = default;

void StakingMiningPage::setupUi()
{
    auto* outer = new QVBoxLayout(this);

    // ---- Staking section ----
    auto* stakingBox = new QGroupBox(tr("Staking"), this);
    auto* sgrid = new QGridLayout(stakingBox);
    m_staking_enable = new QCheckBox(tr("Enable staking (Proof-of-Stake + Gold Rush)"), stakingBox);
    m_staking_enable->setObjectName(QStringLiteral("stakingEnable"));
    m_staking_enable->setToolTip(tr("Starts legacy PoS staking. If this wallet is whitelisted, Gold Rush "
                                    "signalling and payouts are added to your coinstakes automatically during the epoch."));
    m_unlock_staking_only = new QCheckBox(tr("Unlock wallet for LEGACY staking only"), stakingBox);
    m_unlock_staking_only->setObjectName(QStringLiteral("unlockStakingOnly"));
    m_unlock_staking_only->setToolTip(tr("Unlocks an encrypted wallet only for legacy staking. Spending, Gold Rush signals, "
                                         "PoW claims, and quantum staking operations still require a normal wallet unlock."));
    m_unlock_quantum_legacy_staking = new QCheckBox(tr("Unlock wallet for Quantum and Legacy Staking"), stakingBox);
    m_unlock_quantum_legacy_staking->setObjectName(QStringLiteral("unlockQuantumLegacyStaking"));
    m_unlock_quantum_legacy_staking->setToolTip(tr("Uses a normal wallet unlock so the wallet can legacy stake and create "
                                                   "Gold Rush quantum signal transactions when qualified."));
    m_quantum_legacy_unlock_note = new QLabel(tr("NOTE: 10,000 BLK required at block height 5,920,000"), stakingBox);
    m_quantum_legacy_unlock_note->setObjectName(QStringLiteral("quantumLegacyUnlockNote"));
    m_quantum_legacy_unlock_note->setWordWrap(true);
    m_quantum_legacy_unlock_note->setStyleSheet(QStringLiteral("QLabel { color: #6b5d00; }"));
    m_staking_status = new QLabel(tr("Staking is off"), stakingBox);
    m_staking_status->setObjectName(QStringLiteral("stakingStatus"));
    m_stake_weight = new QLabel(QStringLiteral("-"), stakingBox);
    m_stake_weight->setObjectName(QStringLiteral("stakeWeight"));
    m_goldrush_badge = new QLabel(tr("Gold Rush: unknown"), stakingBox);
    m_goldrush_badge->setObjectName(QStringLiteral("goldrushBadge"));
    m_pos_goldrush_status = new QLabel(tr("PoS Gold Rush jackpot: unknown"), stakingBox);
    m_pos_goldrush_status->setObjectName(QStringLiteral("posGoldrushStatus"));
    m_pos_goldrush_status->setWordWrap(true);

    m_donation_enable = new QCheckBox(tr("Donate a share of staking rewards"), stakingBox);
    m_donation_enable->setObjectName(QStringLiteral("stakingDonationEnable"));
    m_donation_enable->setToolTip(tr("When enabled, this wallet contributes the selected percentage of each staking reward to the configured project treasury. Set it to off to opt out."));

    m_donation_percent = new QSpinBox(stakingBox);
    m_donation_percent->setObjectName(QStringLiteral("stakingDonationPercent"));
    m_donation_percent->setRange(std::max<unsigned int>(1, wallet::MIN_DONATION_PERCENTAGE), wallet::MAX_DONATION_PERCENTAGE);
    m_donation_percent->setSuffix(QStringLiteral(" %"));
    m_donation_percent->setToolTip(tr("Percentage of staking rewards donated when the donation toggle is on."));
    QSettings settings;
    const int saved_donation = settings.value(QStringLiteral("StakingMiningDonationPercent"), int{wallet::DEFAULT_DONATION_PERCENTAGE}).toInt();
    m_donation_percent->setValue(std::clamp(saved_donation, m_donation_percent->minimum(), m_donation_percent->maximum()));

    m_donation_status = new QLabel(tr("Donations are off"), stakingBox);
    m_donation_status->setObjectName(QStringLiteral("stakingDonationStatus"));
    m_donation_status->setWordWrap(true);

    sgrid->addWidget(m_staking_enable, 0, 0, 1, 2);
    sgrid->addWidget(m_unlock_staking_only, 1, 0, 1, 2);
    sgrid->addWidget(m_unlock_quantum_legacy_staking, 2, 0, 1, 2);
    sgrid->addWidget(m_quantum_legacy_unlock_note, 3, 0, 1, 2);
    sgrid->addWidget(new QLabel(tr("Status:"), stakingBox), 4, 0);
    sgrid->addWidget(m_staking_status, 4, 1);
    sgrid->addWidget(new QLabel(tr("Stake weight:"), stakingBox), 5, 0);
    sgrid->addWidget(m_stake_weight, 5, 1);
    sgrid->addWidget(m_goldrush_badge, 6, 0, 1, 2);
    sgrid->addWidget(m_pos_goldrush_status, 7, 0, 1, 2);
    sgrid->addWidget(m_donation_enable, 8, 0, 1, 2);
    sgrid->addWidget(new QLabel(tr("Donation:"), stakingBox), 9, 0);
    sgrid->addWidget(m_donation_percent, 9, 1);
    sgrid->addWidget(m_donation_status, 10, 0, 1, 2);
    outer->addWidget(stakingBox);

    // ---- Gold Rush Proof-of-Work section ----
    auto* powBox = new QGroupBox(tr("Gold Rush Proof-of-Work mining"), this);
    auto* pgrid = new QGridLayout(powBox);

    m_pow_enable = new QCheckBox(tr("Enable Gold Rush PoW mining (built-in, no external miner)"), powBox);
    m_pow_enable->setObjectName(QStringLiteral("powEnable"));
    m_pow_enable->setToolTip(tr("Runs the Argon2id Gold Rush solver inside this wallet. No separate mining "
                                "program is required. Active only during the Gold Rush epoch."));

    m_pow_unlock_wallet = new QCheckBox(tr("Unlock wallet for Gold Rush mining"), powBox);
    m_pow_unlock_wallet->setObjectName(QStringLiteral("powUnlockWallet"));
    m_pow_unlock_wallet->setToolTip(tr("Unlocks an encrypted wallet normally so Gold Rush PoW mining can create "
                                       "and submit claim transactions. This is not staking-only unlock."));

    m_pow_cores = new QSpinBox(powBox);
    m_pow_cores->setObjectName(QStringLiteral("powCores"));
    const int max_cores = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
    m_pow_cores->setRange(1, max_cores);
    m_pow_cores->setValue(1); // default 1 core
    m_pow_cores->setToolTip(tr("Number of CPU cores (worker threads) to use, 1..%1.").arg(max_cores));

    m_pow_percent = new QSpinBox(powBox);
    m_pow_percent->setObjectName(QStringLiteral("powPercent"));
    m_pow_percent->setRange(1, 100);
    m_pow_percent->setValue(10); // default 10%
    m_pow_percent->setSuffix(QStringLiteral(" %"));
    m_pow_percent->setToolTip(tr("CPU utilization target per core, 1..100%. Each worker runs an Argon2id try, "
                                 "then sleeps to hold this duty cycle."));

    m_pow_payout = new QLineEdit(powBox);
    m_pow_payout->setObjectName(QStringLiteral("powPayout"));
    m_pow_payout->setReadOnly(true);
    m_pow_payout->setToolTip(tr("The quantum (ML-DSA) address that receives your Gold Rush PoW shadow-ledger credits. "
                                "Created automatically when PoW mining is first enabled."));
    m_pow_copy = new QPushButton(tr("Copy"), powBox);
    m_pow_copy->setObjectName(QStringLiteral("powCopy"));
    m_pow_apply = new QPushButton(tr("Apply"), powBox);
    m_pow_apply->setObjectName(QStringLiteral("powApply"));

    m_pow_status = new QLabel(QStringLiteral("-"), powBox);
    m_pow_status->setObjectName(QStringLiteral("powStatus"));
    m_pow_status->setWordWrap(true);

    m_pow_warning = new QLabel(powBox);
    m_pow_warning->setObjectName(QStringLiteral("powWarning"));
    m_pow_warning->setWordWrap(true);
    m_pow_warning->setTextFormat(Qt::RichText);
    m_pow_warning->setText(tr("<b>Important:</b> Gold Rush PoW rewards are paid to the quantum address above. "
                              "Back up this wallet after the address is created, then move Gold Rush rewards "
                              "to a fresh quantum address during the migration window before final lockout."));
    m_pow_warning->setStyleSheet(QStringLiteral("QLabel { color: #8a6d00; background: #fff6d6; padding: 6px; border-radius: 4px; }"));

    int r = 0;
    pgrid->addWidget(m_pow_enable, r++, 0, 1, 3);
    pgrid->addWidget(m_pow_unlock_wallet, r++, 0, 1, 3);
    pgrid->addWidget(new QLabel(tr("CPU cores:"), powBox), r, 0);
    pgrid->addWidget(m_pow_cores, r++, 1);
    pgrid->addWidget(new QLabel(tr("CPU usage:"), powBox), r, 0);
    pgrid->addWidget(m_pow_percent, r++, 1);
    pgrid->addWidget(new QLabel(tr("Payout address:"), powBox), r, 0);
    pgrid->addWidget(m_pow_payout, r, 1);
    pgrid->addWidget(m_pow_copy, r++, 2);
    pgrid->addWidget(new QLabel(tr("Status:"), powBox), r, 0);
    pgrid->addWidget(m_pow_status, r++, 1, 1, 2);
    pgrid->addWidget(m_pow_apply, r++, 1);
    pgrid->addWidget(m_pow_warning, r++, 0, 1, 3);
    outer->addWidget(powBox);

    // ---- Quantum migration section ----
    auto* migrationBox = new QGroupBox(tr("Quantum migration"), this);
    auto* mgrid = new QGridLayout(migrationBox);

    m_migration_phase = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_phase->setObjectName(QStringLiteral("migrationPhase"));
    m_migration_deadline = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_deadline->setObjectName(QStringLiteral("migrationDeadline"));
    m_migration_legacy_amount = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_legacy_amount->setObjectName(QStringLiteral("migrationLegacyAmount"));
    m_migration_quantum_amount = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_quantum_amount->setObjectName(QStringLiteral("migrationQuantumAmount"));
    m_migration_goldrush_amount = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_goldrush_amount->setObjectName(QStringLiteral("migrationGoldrushAmount"));
    m_migration_advice = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_advice->setObjectName(QStringLiteral("migrationAdvice"));
    m_migration_advice->setWordWrap(true);

    m_quantum_address_count = new QLabel(QStringLiteral("0"), migrationBox);
    m_quantum_address_count->setObjectName(QStringLiteral("quantumAddressCount"));
    m_coldstake_count = new QLabel(QStringLiteral("0"), migrationBox);
    m_coldstake_count->setObjectName(QStringLiteral("quantumColdstakeCount"));
    m_quantum_address = new QLineEdit(migrationBox);
    m_quantum_address->setObjectName(QStringLiteral("quantumAddress"));
    m_quantum_address->setReadOnly(true);
    m_quantum_address->setToolTip(tr("Last wallet-backed quantum migration address created or found by this wallet."));
    m_quantum_pubkey = new QLineEdit(migrationBox);
    m_quantum_pubkey->setObjectName(QStringLiteral("quantumPubkey"));
    m_quantum_pubkey->setReadOnly(true);
    m_quantum_pubkey->setToolTip(tr("ML-DSA public key for the quantum address above. Share this public key with a cold wallet that will delegate staking to this wallet."));
    m_quantum_new = new QPushButton(tr("New quantum address"), migrationBox);
    m_quantum_new->setObjectName(QStringLiteral("newQuantumAddress"));
    m_quantum_new->setToolTip(tr("Create a wallet-backed ML-DSA quantum migration address."));
    m_quantum_copy = new QPushButton(tr("Copy"), migrationBox);
    m_quantum_copy->setObjectName(QStringLiteral("quantumCopy"));
    m_quantum_pubkey_copy = new QPushButton(tr("Copy key"), migrationBox);
    m_quantum_pubkey_copy->setObjectName(QStringLiteral("quantumPubkeyCopy"));

    m_coldstake_staker_pubkey = new QLineEdit(migrationBox);
    m_coldstake_staker_pubkey->setObjectName(QStringLiteral("coldstakeStakerPubkey"));
    m_coldstake_staker_pubkey->setPlaceholderText(tr("Staking public key"));
    m_coldstake_staker_pubkey->setToolTip(tr("Paste the hot-wallet ML-DSA staking public key that may stake this cold deposit."));
    m_coldstake_address = new QLineEdit(migrationBox);
    m_coldstake_address->setObjectName(QStringLiteral("coldstakeAddress"));
    m_coldstake_address->setReadOnly(true);
    m_coldstake_address->setToolTip(tr("Last wallet-backed Quantum Cold-Stake deposit address created or found by this wallet."));
    m_coldstake_new = new QPushButton(tr("Create cold-stake address"), migrationBox);
    m_coldstake_new->setObjectName(QStringLiteral("newColdstakeAddress"));
    m_coldstake_copy = new QPushButton(tr("Copy"), migrationBox);
    m_coldstake_copy->setObjectName(QStringLiteral("coldstakeCopy"));
    m_coldstake_status = new QLabel(QStringLiteral("-"), migrationBox);
    m_coldstake_status->setObjectName(QStringLiteral("coldstakeStatus"));
    m_coldstake_status->setWordWrap(true);

    r = 0;
    mgrid->addWidget(new QLabel(tr("Phase:"), migrationBox), r, 0);
    mgrid->addWidget(m_migration_phase, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Deadline:"), migrationBox), r, 0);
    mgrid->addWidget(m_migration_deadline, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Legacy left:"), migrationBox), r, 0);
    mgrid->addWidget(m_migration_legacy_amount, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Quantum held:"), migrationBox), r, 0);
    mgrid->addWidget(m_migration_quantum_amount, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Gold Rush to move:"), migrationBox), r, 0);
    mgrid->addWidget(m_migration_goldrush_amount, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Quantum addresses:"), migrationBox), r, 0);
    mgrid->addWidget(m_quantum_address_count, r, 1);
    mgrid->addWidget(new QLabel(tr("Cold-stake delegations:"), migrationBox), r++, 2);
    mgrid->addWidget(m_coldstake_count, r - 1, 3);
    mgrid->addWidget(new QLabel(tr("Address:"), migrationBox), r, 0);
    mgrid->addWidget(m_quantum_address, r, 1, 1, 2);
    mgrid->addWidget(m_quantum_copy, r++, 3);
    mgrid->addWidget(new QLabel(tr("Public key:"), migrationBox), r, 0);
    mgrid->addWidget(m_quantum_pubkey, r, 1, 1, 2);
    mgrid->addWidget(m_quantum_pubkey_copy, r++, 3);
    mgrid->addWidget(m_quantum_new, r++, 1, 1, 2);
    mgrid->addWidget(new QLabel(tr("Staking key:"), migrationBox), r, 0);
    mgrid->addWidget(m_coldstake_staker_pubkey, r++, 1, 1, 3);
    mgrid->addWidget(new QLabel(tr("Cold-stake address:"), migrationBox), r, 0);
    mgrid->addWidget(m_coldstake_address, r, 1, 1, 2);
    mgrid->addWidget(m_coldstake_copy, r++, 3);
    mgrid->addWidget(m_coldstake_new, r++, 1, 1, 2);
    mgrid->addWidget(m_coldstake_status, r++, 0, 1, 4);
    mgrid->addWidget(m_migration_advice, r++, 0, 1, 4);
    outer->addWidget(migrationBox);

    outer->addStretch();
}

void StakingMiningPage::setClientModel(ClientModel* clientModel)
{
    m_client_model = clientModel;
}

void StakingMiningPage::setWalletModel(WalletModel* walletModel)
{
    if (m_timer) m_timer->stop();
    if (m_wallet_model) {
        disconnect(m_wallet_model, nullptr, this, nullptr);
    }

    m_wallet_model = walletModel;
    m_updating = false;
    m_pow_apply_pending = false;

    if (m_wallet_model) {
        connect(m_wallet_model, &QObject::destroyed, this, [this] {
            m_wallet_model = nullptr;
            if (m_timer) m_timer->stop();
            m_updating = false;
            m_pow_apply_pending = false;
            resetStatusForNoWallet();
        });
        updateStatus();
        m_timer->start();
    } else {
        resetStatusForNoWallet();
    }
}

void StakingMiningPage::onStakingToggled(bool enabled)
{
    if (m_updating || !m_wallet_model) return;
    if (enabled && m_unlock_staking_only->isChecked() && !requestStakingOnlyUnlock()) {
        m_wallet_model->wallet().setEnabledStaking(false);
        updateStatus();
        return;
    }
    m_wallet_model->wallet().setEnabledStaking(enabled);
    updateStatus();
}

void StakingMiningPage::onUnlockStakingOnlyToggled(bool enabled)
{
    if (m_updating || !m_wallet_model) return;

    if (enabled) {
        if (!requestStakingOnlyUnlock()) {
            updateStatus();
            return;
        }
    } else if (m_wallet_model->getWalletUnlockStakingOnly()) {
        m_wallet_model->setWalletUnlockStakingOnly(false);
        if (m_wallet_model->getEncryptionStatus() == WalletModel::Unlocked) {
            m_wallet_model->setWalletLocked(true);
        }
        m_wallet_model->updateStatus();
    }

    updateStatus();
}

void StakingMiningPage::onUnlockQuantumLegacyStakingToggled(bool enabled)
{
    if (m_updating || !m_wallet_model) return;

    if (enabled) {
        if (!requestNormalUnlock()) {
            updateStatus();
            return;
        }
    } else {
        if (m_wallet_model->getEncryptionStatus() == WalletModel::Unlocked &&
            !m_wallet_model->getWalletUnlockStakingOnly()) {
            m_wallet_model->setWalletLocked(true);
            m_wallet_model->updateStatus();
        }
    }

    updateStatus();
}

void StakingMiningPage::onDonationToggled(bool enabled)
{
    if (m_updating || !m_wallet_model) return;
    applyDonationPercentage(enabled ? static_cast<unsigned int>(m_donation_percent->value()) : 0);
    updateStatus();
}

void StakingMiningPage::onDonationPercentChanged(int percentage)
{
    QSettings settings;
    settings.setValue(QStringLiteral("StakingMiningDonationPercent"), percentage);
    if (m_updating || !m_wallet_model || !m_donation_enable->isChecked()) return;
    applyDonationPercentage(static_cast<unsigned int>(percentage));
    updateStatus();
}

void StakingMiningPage::applyDonationPercentage(unsigned int percentage)
{
    if (!m_wallet_model) return;
    percentage = std::min<unsigned int>(percentage, wallet::MAX_DONATION_PERCENTAGE);
    m_wallet_model->wallet().setDonationPercentage(percentage);
    if (OptionsModel* options_model = m_wallet_model->getOptionsModel()) {
        options_model->setOption(OptionsModel::DonationPercentage, qlonglong{percentage});
    }
    Q_EMIT m_wallet_model->donationPercentageChanged(percentage);
}

void StakingMiningPage::onPowEnableToggled(bool /*enabled*/)
{
    if (m_updating) return;
    onApplyPow(); // applying immediately keeps the backend and the controls in sync
}

void StakingMiningPage::onPowUnlockWalletToggled(bool enabled)
{
    if (m_updating || !m_wallet_model) return;

    if (enabled) {
        if (!requestNormalUnlock()) {
            updateStatus();
            return;
        }
    } else {
        if (m_wallet_model->wallet().getPowMiningInfo().enabled) {
            std::string ignored_error;
            m_wallet_model->wallet().setPowMining(false, m_pow_cores->value(), m_pow_percent->value(), ignored_error);
        }
        m_wallet_model->setWalletUnlockStakingOnly(false);
        if (m_wallet_model->getEncryptionStatus() == WalletModel::Unlocked) {
            m_wallet_model->setWalletLocked(true);
        }
        m_wallet_model->updateStatus();
    }

    updateStatus();
}

void StakingMiningPage::onApplyPow()
{
    if (m_updating || !m_wallet_model || m_pow_apply_pending) return;
    const bool enabled = m_pow_enable->isChecked();
    const int cores = m_pow_cores->value();
    const int percent = m_pow_percent->value();

    if (enabled && !requestNormalUnlock()) {
        m_pow_enable->setChecked(false);
        m_pow_status->setText(tr("Gold Rush PoW mining requires a normal wallet unlock."));
        updateStatus();
        return;
    }

    m_pow_apply_pending = true;
    m_pow_pending_enabled = enabled;
    m_pow_status->setText(enabled ? tr("Starting Gold Rush PoW mining...") : tr("Stopping Gold Rush PoW mining..."));
    refreshControlsEnabled();

    std::string error;
    const bool ok = m_wallet_model->wallet().setPowMining(enabled, cores, percent, error);
    m_pow_apply_pending = false;
    if (!ok) {
        m_pow_enable->setChecked(false);
        const QString msg = error.empty()
            ? tr("Unable to start Gold Rush PoW mining. Unlock the wallet and check debug.log for details.")
            : QString::fromStdString(error);
        m_pow_status->setText(msg);
        if (enabled) QMessageBox::warning(this, tr("Gold Rush PoW mining"), msg);
        refreshControlsEnabled();
        return;
    }
    updateStatus();
}

void StakingMiningPage::onCopyPayoutAddress()
{
    if (m_pow_payout && !m_pow_payout->text().isEmpty()) {
        QApplication::clipboard()->setText(m_pow_payout->text());
    }
}

void StakingMiningPage::onCreateQuantumAddress()
{
    if (!m_wallet_model) return;
    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().createQuantumAddress("migration-gui");
    if (!result) {
        QMessageBox::warning(this, tr("Quantum address"), QString::fromStdString(util::ErrorString(result).original));
        return;
    }
    m_quantum_address->setText(QString::fromStdString(result->address));
    m_quantum_pubkey->setText(QString::fromStdString(result->public_key));
    QApplication::clipboard()->setText(m_quantum_address->text());
    updateStatus();
}

void StakingMiningPage::onCopyQuantumAddress()
{
    if (m_quantum_address && !m_quantum_address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_quantum_address->text());
    }
}

void StakingMiningPage::onCopyQuantumPubkey()
{
    if (m_quantum_pubkey && !m_quantum_pubkey->text().isEmpty()) {
        QApplication::clipboard()->setText(m_quantum_pubkey->text());
    }
}

void StakingMiningPage::onCreateColdStakeAddress()
{
    if (!m_wallet_model) return;
    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    const QString staking_pubkey = m_coldstake_staker_pubkey->text().trimmed();
    auto result = m_wallet_model->wallet().createQuantumColdStakeAddress(staking_pubkey.toStdString(), "coldstake-gui");
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_coldstake_status->setText(msg);
        QMessageBox::warning(this, tr("Quantum cold staking"), msg);
        return;
    }
    m_coldstake_address->setText(QString::fromStdString(result->address));
    m_coldstake_status->setText(result->has_staker_key
        ? tr("Cold-stake address created. This wallet can stake and owner-spend this delegation.")
        : tr("Cold-stake address created. This wallet holds the owner key."));
    QApplication::clipboard()->setText(m_coldstake_address->text());
    updateStatus();
}

void StakingMiningPage::onCopyColdStakeAddress()
{
    if (m_coldstake_address && !m_coldstake_address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_coldstake_address->text());
    }
}

void StakingMiningPage::updateStatus()
{
    if (!m_wallet_model) {
        resetStatusForNoWallet();
        return;
    }
    m_updating = true;

    interfaces::Wallet& w = m_wallet_model->wallet();

    // Staking
    const bool staking = w.getEnabledStaking();
    const bool normal_unlocked = m_wallet_model->getEncryptionStatus() == WalletModel::Unlocked &&
                                 !w.getWalletUnlockStakingOnly();
    m_staking_enable->setChecked(staking);
    m_unlock_staking_only->setChecked(w.getWalletUnlockStakingOnly());
    m_unlock_quantum_legacy_staking->setChecked(normal_unlocked);
    m_staking_status->setText(staking ? tr("Staking is active") : tr("Staking is off"));
    m_stake_weight->setText(QString::number(static_cast<qulonglong>(w.getStakeWeight())));

    const unsigned int donation_percentage = w.getDonationPercentage();
    m_donation_enable->setChecked(donation_percentage > 0);
    if (donation_percentage > 0 && !m_donation_percent->hasFocus()) {
        QSignalBlocker blocker(m_donation_percent);
        m_donation_percent->setValue(static_cast<int>(donation_percentage));
    }
    m_donation_status->setText(donation_percentage > 0
        ? tr("Donating %1% of staking rewards.").arg(donation_percentage)
        : tr("Staking reward donations are off."));

    // PoW
    const interfaces::WalletPowMiningInfo info = w.getPowMiningInfo();
    if (!m_pow_apply_pending) {
        m_pow_enable->setChecked(info.enabled);
        m_pow_unlock_wallet->setChecked(normal_unlocked);
        if (!m_pow_cores->hasFocus() && info.threads > 0) m_pow_cores->setValue(info.threads);
        if (!m_pow_percent->hasFocus() && info.cpu_percent > 0) m_pow_percent->setValue(info.cpu_percent);
    }
    m_pow_payout->setText(QString::fromStdString(info.payout_address));

    m_goldrush_badge->setText(info.epoch_active
        ? tr("Gold Rush: ACTIVE (%1 blocks remaining)").arg(info.blocks_remaining)
        : tr("Gold Rush: not active"));
    const QString last_pos_payout = info.pos_last_payout_height > 0
        ? QString::number(info.pos_last_payout_height)
        : tr("none yet");
    m_pos_goldrush_status->setText(info.epoch_active
        ? tr("PoS Gold Rush jackpot: %1 next qualified payout pool (%2 accrued)   |   Active signalers: %3   |   Estimated split: %4   |   Last PoS payout: %5")
              .arg(formatBLK(info.pos_next_payout_pool))
              .arg(formatBLK(info.pos_accrued_jackpot))
              .arg(QString::number(info.pos_active_signalers))
              .arg(formatBLK(info.pos_estimated_payout_per_signaler))
              .arg(last_pos_payout)
        : tr("PoS Gold Rush jackpot: %1 accrued; Gold Rush is not active.")
              .arg(formatBLK(info.pos_accrued_jackpot)));

    if (m_pow_apply_pending) {
        m_pow_status->setText(m_pow_pending_enabled ? tr("Starting Gold Rush PoW mining...") : tr("Stopping Gold Rush PoW mining..."));
    } else if (info.epoch_active) {
        m_pow_status->setText(tr("Hashrate: %1 tries/s   |   Next claim payout: %2   |   Claims submitted: %3")
            .arg(QString::number(info.hashrate, 'f', 1))
            .arg(formatBLK(info.next_claim_payout))
            .arg(QString::number(static_cast<qlonglong>(info.claims_submitted))));
    } else if (info.enabled) {
        m_pow_status->setText(tr("PoW mining is enabled and idle until the Gold Rush epoch is active."));
    } else {
        m_pow_status->setText(tr("PoW mining is off; Gold Rush epoch is not active."));
    }

    // Quantum migration
    const interfaces::WalletMigrationStatus migration = w.getMigrationStatus();
    m_migration_phase->setText(QString::fromStdString(migration.phase));
    m_migration_deadline->setText(migration.deadline_scheduled
        ? tr("%1 blocks estimated").arg(QString::number(migration.blocks_until_deadline_est))
        : tr("Not scheduled"));
    m_migration_legacy_amount->setText(tr("%1 across %2 inputs")
        .arg(formatBLK(migration.eligible_legacy_amount))
        .arg(QString::number(migration.eligible_legacy_inputs)));
    m_migration_quantum_amount->setText(tr("%1 across %2 outputs")
        .arg(formatBLK(migration.migrated_quantum_amount))
        .arg(QString::number(migration.migrated_quantum_outputs)));
    m_migration_goldrush_amount->setText(tr("%1 across %2 outputs")
        .arg(formatBLK(migration.goldrush_reward_amount_needing_move))
        .arg(QString::number(migration.goldrush_reward_outputs_needing_move)));
    m_migration_advice->setText(QString::fromStdString(migration.advice));

    const std::vector<interfaces::WalletQuantumAddressInfo> quantum_addresses = w.listQuantumAddresses();
    const std::vector<interfaces::WalletQuantumColdStakeInfo> coldstake_delegations = w.listQuantumColdStakeDelegations();
    m_quantum_address_count->setText(QString::number(static_cast<int>(quantum_addresses.size())));
    m_coldstake_count->setText(QString::number(static_cast<int>(coldstake_delegations.size())));
    if (m_quantum_address->text().isEmpty() && !quantum_addresses.empty()) {
        m_quantum_address->setText(QString::fromStdString(quantum_addresses.back().address));
        m_quantum_pubkey->setText(QString::fromStdString(quantum_addresses.back().public_key));
    }
    if (m_coldstake_address->text().isEmpty() && !coldstake_delegations.empty()) {
        m_coldstake_address->setText(QString::fromStdString(coldstake_delegations.back().address));
    }

    refreshControlsEnabled();
    m_updating = false;
}

void StakingMiningPage::resetStatusForNoWallet()
{
    QSignalBlocker staking_blocker(m_staking_enable);
    QSignalBlocker unlock_staking_blocker(m_unlock_staking_only);
    QSignalBlocker unlock_quantum_legacy_blocker(m_unlock_quantum_legacy_staking);
    QSignalBlocker donation_blocker(m_donation_enable);
    QSignalBlocker pow_blocker(m_pow_enable);
    QSignalBlocker pow_unlock_blocker(m_pow_unlock_wallet);

    m_staking_enable->setChecked(false);
    m_unlock_staking_only->setChecked(false);
    m_unlock_quantum_legacy_staking->setChecked(false);
    m_staking_status->setText(tr("No wallet loaded"));
    m_stake_weight->setText(QStringLiteral("-"));
    m_goldrush_badge->setText(tr("Gold Rush: no wallet loaded"));
    m_pos_goldrush_status->setText(tr("PoS Gold Rush jackpot: no wallet loaded"));

    m_donation_enable->setChecked(false);
    m_donation_status->setText(tr("Load a wallet to configure staking reward donations."));

    m_pow_enable->setChecked(false);
    m_pow_unlock_wallet->setChecked(false);
    m_pow_payout->clear();
    m_pow_status->setText(tr("Load a wallet to use Gold Rush PoW mining."));

    m_migration_phase->setText(QStringLiteral("-"));
    m_migration_deadline->setText(QStringLiteral("-"));
    m_migration_legacy_amount->setText(QStringLiteral("-"));
    m_migration_quantum_amount->setText(QStringLiteral("-"));
    m_migration_goldrush_amount->setText(QStringLiteral("-"));
    m_migration_advice->setText(tr("Load a wallet to view migration status."));
    m_quantum_address_count->setText(QStringLiteral("0"));
    m_coldstake_count->setText(QStringLiteral("0"));
    m_quantum_address->clear();
    m_quantum_pubkey->clear();
    m_coldstake_address->clear();
    m_coldstake_status->setText(QStringLiteral("-"));

    refreshControlsEnabled();
}

void StakingMiningPage::refreshControlsEnabled()
{
    // Config is always editable; the backend only mines during the Gold Rush epoch.
    const bool has_wallet = m_wallet_model != nullptr;
    const WalletModel::EncryptionStatus encryption_status = has_wallet
        ? m_wallet_model->getEncryptionStatus()
        : WalletModel::NoKeys;
    const bool tune = has_wallet && m_pow_enable->isChecked();
    m_staking_enable->setEnabled(has_wallet);
    m_unlock_staking_only->setEnabled(has_wallet &&
                                      encryption_status != WalletModel::NoKeys &&
                                      encryption_status != WalletModel::Unencrypted);
    m_unlock_quantum_legacy_staking->setEnabled(has_wallet &&
                                                encryption_status != WalletModel::NoKeys &&
                                                encryption_status != WalletModel::Unencrypted);
    m_pow_enable->setEnabled(has_wallet && !m_pow_apply_pending);
    m_pow_unlock_wallet->setEnabled(has_wallet &&
                                    encryption_status != WalletModel::NoKeys &&
                                    encryption_status != WalletModel::Unencrypted &&
                                    !m_pow_apply_pending);
    m_pow_cores->setEnabled(tune && !m_pow_apply_pending);
    m_pow_percent->setEnabled(tune && !m_pow_apply_pending);
    m_pow_apply->setEnabled(has_wallet && tune && !m_pow_apply_pending);
    m_pow_copy->setEnabled(m_pow_payout && !m_pow_payout->text().isEmpty());
    const bool can_create_quantum = has_wallet && !m_wallet_model->wallet().privateKeysDisabled();
    m_quantum_new->setEnabled(can_create_quantum);
    m_quantum_copy->setEnabled(m_quantum_address && !m_quantum_address->text().isEmpty());
    m_quantum_pubkey_copy->setEnabled(m_quantum_pubkey && !m_quantum_pubkey->text().isEmpty());
    m_coldstake_new->setEnabled(can_create_quantum && m_coldstake_staker_pubkey && !m_coldstake_staker_pubkey->text().trimmed().isEmpty());
    m_coldstake_copy->setEnabled(m_coldstake_address && !m_coldstake_address->text().isEmpty());
    m_donation_enable->setEnabled(has_wallet);
    m_donation_percent->setEnabled(has_wallet);
}

bool StakingMiningPage::requestStakingOnlyUnlock()
{
    if (!m_wallet_model) return false;

    const WalletModel::EncryptionStatus encryption_status = m_wallet_model->getEncryptionStatus();
    if (encryption_status == WalletModel::NoKeys || encryption_status == WalletModel::Unencrypted) {
        return false;
    }

    if (encryption_status == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::UnlockStaking, this);
        dlg.setModel(m_wallet_model);
        if (dlg.exec() != QDialog::Accepted) {
            return false;
        }
        if (!m_wallet_model->getWalletUnlockStakingOnly()) {
            m_wallet_model->setWalletLocked(true);
            m_wallet_model->updateStatus();
            return false;
        }
        return true;
    }

    m_wallet_model->setWalletUnlockStakingOnly(true);
    m_wallet_model->updateStatus();
    return true;
}

bool StakingMiningPage::requestNormalUnlock()
{
    if (!m_wallet_model) return false;

    const WalletModel::EncryptionStatus encryption_status = m_wallet_model->getEncryptionStatus();
    if (encryption_status == WalletModel::NoKeys) {
        return false;
    }
    if (encryption_status == WalletModel::Unencrypted) {
        return true;
    }

    if (m_wallet_model->getWalletUnlockStakingOnly()) {
        m_wallet_model->setWalletUnlockStakingOnly(false);
        if (encryption_status == WalletModel::Unlocked) {
            m_wallet_model->setWalletLocked(true);
        }
        m_wallet_model->updateStatus();
    }

    if (m_wallet_model->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(m_wallet_model);
        if (dlg.exec() != QDialog::Accepted) {
            return false;
        }
    }

    if (m_wallet_model->getEncryptionStatus() != WalletModel::Unlocked) {
        return false;
    }

    if (m_wallet_model->getWalletUnlockStakingOnly()) {
        m_wallet_model->setWalletUnlockStakingOnly(false);
        m_wallet_model->updateStatus();
    }
    return true;
}
