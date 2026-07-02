// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/stakingminingpage.h>

#include <qt/askpassphrasedialog.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <thread>

#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QSize>
#include <QSizePolicy>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>

namespace {
constexpr uint16_t OPERATOR_COMMITMENT_BLOCKS = 40500;

struct StakeLockPreset
{
    const char* label;
    uint16_t blocks;
};

constexpr std::array<StakeLockPreset, 6> STAKE_LOCK_PRESETS{{
    {"Liquid - no lock (0.25x)", 0},
    {"1 day (0.5335x)", 1350},
    {"2 days (0.6509x)", 2700},
    {"3.5 days (0.7803x)", 4725},
    {"5 days (0.8839x)", 6750},
    {"7 days full weight (1.00x)", 9450},
}};

void populateStakeLockCombo(QComboBox* combo)
{
    for (const StakeLockPreset& preset : STAKE_LOCK_PRESETS) {
        combo->addItem(QObject::tr(preset.label), QVariant::fromValue(static_cast<int>(preset.blocks)));
    }
}

uint16_t selectedStakeLockBlocks(const QComboBox* combo)
{
    if (!combo) return 0;
    const int blocks = combo->currentData().toInt();
    return static_cast<uint16_t>(std::clamp(blocks, 0, int{std::numeric_limits<uint16_t>::max()}));
}

QString formatBLK(CAmount amount)
{
    // Light-touch formatter (8 decimals); the page is informational, not a money entry surface.
    const double v = static_cast<double>(amount) / 100000000.0;
    return QString::number(v, 'f', 8) + QStringLiteral(" BLK");
}

QString shortenHex(const std::string& value)
{
    const QString text = QString::fromStdString(value);
    if (text.size() <= 24) return text;
    return text.left(12) + QStringLiteral("...") + text.right(12);
}

QString formatBps(int64_t bps)
{
    return QString::number(static_cast<double>(bps) / 100.0, 'f', 2) + QStringLiteral("%");
}

QString formatAssetAmount(uint64_t amount)
{
    return QString::number(static_cast<qulonglong>(amount));
}

QTableWidgetItem* readOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}

QString addressSelectorLabel(const std::string& label, const std::string& address, uint16_t lock_blocks)
{
    QString text = label.empty() ? QObject::tr("Unlabeled") : QString::fromStdString(label);
    text += QStringLiteral("  |  ") + shortenHex(address);
    if (lock_blocks > 0) {
        text += QObject::tr("  |  %1 blocks").arg(lock_blocks);
    }
    return text;
}

QString outputSelectorKey(const std::string& txid, uint32_t vout)
{
    return QString::fromStdString(txid) + QStringLiteral(":") + QString::number(vout);
}

QString outputSelectorLabel(const interfaces::WalletQuantumStakeOutputInfo& output)
{
    QString state = QString::fromStdString(output.state);
    if (!state.isEmpty()) state[0] = state[0].toUpper();

    QString text = QObject::tr("%1  |  %2  |  %3")
        .arg(state.isEmpty() ? QObject::tr("Unknown") : state)
        .arg(formatBLK(output.amount))
        .arg(shortenHex(output.txid + ":" + std::to_string(output.vout)));
    if (output.unlock_height > 0) {
        text += QObject::tr("  |  unlock %1").arg(output.unlock_height);
    }
    if (output.depth <= 0) {
        text += QObject::tr("  |  unconfirmed");
    }
    return text;
}

std::optional<COutPoint> outpointFromSelectorData(const QVariant& data)
{
    const QString key = data.toString();
    if (key.isEmpty()) return std::nullopt;

    const QStringList parts = key.split(QStringLiteral(":"));
    if (parts.size() != 2 || parts[0].isEmpty()) return std::nullopt;

    bool ok{false};
    const uint vout = parts[1].toUInt(&ok);
    if (!ok) return std::nullopt;
    return COutPoint(uint256S(parts[0].toStdString()), vout);
}

bool stakingAddressTier(const QString& address, QuantumStakeTierProgram& tier)
{
    const CTxDestination dest = DecodeDestination(address.toStdString());
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness) return false;
    if (!DecodeQuantumStakeTierProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram(), tier) || !tier.tiered || tier.cold_stake) {
        return false;
    }
    return true;
}

uint16_t stakingAddressLockBlocks(const QString& address)
{
    QuantumStakeTierProgram tier;
    if (!stakingAddressTier(address, tier)) return 0;
    return tier.unbonding_blocks;
}

bool isBondedTieredStakingAddress(const QString& address)
{
    QuantumStakeTierProgram tier;
    return stakingAddressTier(address, tier) && tier.IsBonded();
}

} // namespace

StakingMiningPage::StakingMiningPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent), m_platform_style(platformStyle)
{
    setupUi();

    m_timer = new QTimer(this);
    m_timer->setInterval(5000);
    connect(m_timer, &QTimer::timeout, this, &StakingMiningPage::updateStatus);

    connect(m_staking_enable, &QCheckBox::clicked, this, &StakingMiningPage::onStakingToggled);
    connect(m_unlock_staking_only, &QCheckBox::clicked, this, &StakingMiningPage::onUnlockStakingOnlyToggled);
    connect(m_unlock_quantum_legacy_staking, &QCheckBox::clicked, this, &StakingMiningPage::onUnlockQuantumLegacyStakingToggled);
    connect(m_donation_enable, &QCheckBox::clicked, this, &StakingMiningPage::onDonationToggled);
    connect(m_donation_percent, qOverload<int>(&QSpinBox::valueChanged), this, &StakingMiningPage::onDonationPercentChanged);
    connect(m_pow_enable, &QCheckBox::clicked, this, &StakingMiningPage::onPowEnableToggled);
    connect(m_pow_unlock_wallet, &QCheckBox::clicked, this, &StakingMiningPage::onPowUnlockWalletToggled);
    connect(m_pow_cores, qOverload<int>(&QSpinBox::valueChanged), this, &StakingMiningPage::onPowSettingsChanged);
    connect(m_pow_percent, qOverload<int>(&QSpinBox::valueChanged), this, &StakingMiningPage::onPowSettingsChanged);
    connect(m_pow_apply, &QPushButton::clicked, this, &StakingMiningPage::onApplyPow);
    connect(m_pow_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyPayoutAddress);
    connect(m_quantum_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateQuantumAddress);
    connect(m_quantum_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyQuantumAddress);
    connect(m_quantum_pubkey_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyQuantumPubkey);
    connect(m_migration_legacy_sweep, &QPushButton::clicked, this, &StakingMiningPage::onMigrateLegacyToQuantum);
    connect(m_migration_goldrush_sweep, &QPushButton::clicked, this, &StakingMiningPage::onMigrateGoldRushRewards);
    connect(m_demurrage_attest, &QPushButton::clicked, this, &StakingMiningPage::onSendDemurrageAttestation);
    connect(m_rgb_copy_contract, &QPushButton::clicked, this, &StakingMiningPage::onCopySelectedRGBContract);
    connect(m_rgb_assets, &QTableWidget::itemSelectionChanged, this, [this]() { refreshControlsEnabled(); });
    connect(m_selfstake_selector, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (m_updating || !m_selfstake_selector) return;
        const QString address = m_selfstake_selector->itemData(index).toString();
        if (address.isEmpty()) return;
        m_selfstake_address->setText(address);
        m_selfstake_last_action_status.clear();
        updateStatus();
    });
    connect(m_selfstake_output_selector, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) {
        if (m_updating || !m_selfstake_output_selector) return;
        m_selfstake_last_action_status.clear();
        updateStatus();
    });
    connect(m_selfstake_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateSelfStakeAddress);
    connect(m_selfstake_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopySelfStakeAddress);
    connect(m_selfstake_fund, &QPushButton::clicked, this, &StakingMiningPage::onFundSelfStakeAddress);
    connect(m_selfstake_withdraw, &QPushButton::clicked, this, &StakingMiningPage::onWithdrawSelfStakeAddress);
    connect(m_operator_selector, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (m_updating || !m_operator_selector) return;
        const QString address = m_operator_selector->itemData(index).toString();
        if (address.isEmpty()) return;
        m_operator_address->setText(address);
        m_operator_pubkey->setText(m_operator_selector->itemData(index, Qt::UserRole + 1).toString());
        m_operator_last_action_status.clear();
        updateStatus();
    });
    connect(m_operator_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateOperatorKey);
    connect(m_operator_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyOperatorKey);
    connect(m_operator_use_for_delegation, &QPushButton::clicked, this, &StakingMiningPage::onUseOperatorKeyForDelegation);
    connect(m_operator_fund, &QPushButton::clicked, this, &StakingMiningPage::onFundOperatorBond);
    connect(m_operator_withdraw, &QPushButton::clicked, this, &StakingMiningPage::onWithdrawOperatorBond);
    connect(m_operator_registry_refresh, &QPushButton::clicked, this, &StakingMiningPage::onRefreshOperatorRegistry);
    connect(m_operator_registry_use, &QPushButton::clicked, this, &StakingMiningPage::onUseRegistryOperatorForDelegation);
    connect(m_operator_registry, &QTableWidget::itemSelectionChanged, this, [this]() { refreshControlsEnabled(); });
    connect(m_operator_registry, &QTableWidget::cellDoubleClicked, this, [this](int, int) { onUseRegistryOperatorForDelegation(); });
    connect(m_coldstake_existing_selector, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (m_updating || !m_coldstake_existing_selector) return;
        const QString address = m_coldstake_existing_selector->itemData(index).toString();
        if (address.isEmpty()) return;
        m_coldstake_last_action_status.clear();
        m_coldstake_address->setText(address);
        updateStatus();
    });
    connect(m_coldstake_new, &QPushButton::clicked, this, &StakingMiningPage::onCreateColdStakeAddress);
    connect(m_coldstake_copy, &QPushButton::clicked, this, &StakingMiningPage::onCopyColdStakeAddress);
    connect(m_coldstake_fund, &QPushButton::clicked, this, &StakingMiningPage::onFundColdStakeAddress);
    connect(m_coldstake_withdraw, &QPushButton::clicked, this, &StakingMiningPage::onWithdrawColdStakeAddress);
    connect(m_coldstake_operator_selector, qOverload<int>(&QComboBox::currentIndexChanged), this, [this]() { refreshControlsEnabled(); });
}

StakingMiningPage::~StakingMiningPage() = default;

QSize StakingMiningPage::minimumSizeHint() const
{
    return QSize(0, 0);
}

void StakingMiningPage::setupUi()
{
    auto* outer = new QVBoxLayout(this);
    auto configureLineEdit = [](QLineEdit* edit) {
        edit->setMinimumWidth(0);
        edit->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    };

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
    m_quantum_legacy_unlock_note = new QLabel(tr("Gold Rush whitelist status will appear after the wallet is loaded."), stakingBox);
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
    m_pow_cores->setValue(1);
    m_pow_cores->setToolTip(tr("Number of CPU cores (worker threads) to use, 1..%1.").arg(max_cores));

    m_pow_percent = new QSpinBox(powBox);
    m_pow_percent->setObjectName(QStringLiteral("powPercent"));
    m_pow_percent->setRange(1, 100);
    m_pow_percent->setValue(1);
    m_pow_percent->setSuffix(QStringLiteral(" %"));
    m_pow_percent->setToolTip(tr("CPU utilization target per core, 1..100%. Each worker runs an Argon2id try, "
                                 "then sleeps to hold this duty cycle."));

    m_pow_payout = new QLineEdit(powBox);
    m_pow_payout->setObjectName(QStringLiteral("powPayout"));
    configureLineEdit(m_pow_payout);
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
                              "to a fresh quantum address before final lockout."));
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

    // ---- Quantum cold-staking section ----
    auto* coldstakeBox = new QGroupBox(tr("Quantum staking and cold staking"), this);
    auto* coldstakeOuter = new QVBoxLayout(coldstakeBox);
    auto* coldstakeTabs = new QTabWidget(coldstakeBox);
    auto* selfStakeTab = new QWidget(coldstakeTabs);
    auto* selfStakeGrid = new QGridLayout(selfStakeTab);
    auto* operatorTab = new QWidget(coldstakeTabs);
    auto* operatorGrid = new QGridLayout(operatorTab);
    auto* delegateTab = new QWidget(coldstakeTabs);
    auto* delegateGrid = new QGridLayout(delegateTab);
    coldstakeTabs->addTab(selfStakeTab, tr("Stake my coins"));
    coldstakeTabs->addTab(operatorTab, tr("Operate"));
    coldstakeTabs->addTab(delegateTab, tr("Delegate"));
    coldstakeOuter->addWidget(coldstakeTabs);

    auto* selfStakeHeading = new QLabel(tr("<b>Stake your own quantum coins</b>"), coldstakeBox);
    selfStakeHeading->setTextFormat(Qt::RichText);
    m_selfstake_lock_period = new QComboBox(coldstakeBox);
    m_selfstake_lock_period->setObjectName(QStringLiteral("selfStakeLockPeriod"));
    populateStakeLockCombo(m_selfstake_lock_period);
    m_selfstake_lock_period->setToolTip(tr("Creates a tiered quantum staking address. Longer lock periods increase staking weight and must unbond before ordinary spending."));
    m_selfstake_selector = new QComboBox(coldstakeBox);
    m_selfstake_selector->setObjectName(QStringLiteral("selfStakeAddressSelector"));
    m_selfstake_selector->setEditable(false);
    m_selfstake_selector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_selfstake_selector->setToolTip(tr("Select a previously-created wallet-backed quantum staking address."));
    m_selfstake_selector->addItem(tr("No saved staking addresses"), QString());
    m_selfstake_address = new QLineEdit(coldstakeBox);
    m_selfstake_address->setObjectName(QStringLiteral("selfStakeAddress"));
    configureLineEdit(m_selfstake_address);
    m_selfstake_address->setReadOnly(true);
    m_selfstake_address->setToolTip(tr("Last wallet-backed tiered quantum staking address created by this wallet."));
    m_selfstake_new = new QPushButton(tr("Create staking address"), coldstakeBox);
    m_selfstake_new->setObjectName(QStringLiteral("newSelfStakeAddress"));
    m_selfstake_copy = new QPushButton(tr("Copy"), coldstakeBox);
    m_selfstake_copy->setObjectName(QStringLiteral("selfStakeCopy"));
    m_selfstake_output_selector = new QComboBox(coldstakeBox);
    m_selfstake_output_selector->setObjectName(QStringLiteral("selfStakeOutputSelector"));
    m_selfstake_output_selector->setEditable(false);
    m_selfstake_output_selector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_selfstake_output_selector->setToolTip(tr("Select a specific previously-funded staking output to unbond or withdraw. Leave on All to act on every eligible output for this staking address."));
    m_selfstake_output_selector->addItem(tr("No staking outputs"), QString());
    m_selfstake_fund_amount = new BitcoinAmountField(coldstakeBox);
    m_selfstake_fund_amount->setObjectName(QStringLiteral("selfStakeFundAmount"));
    m_selfstake_fund_amount->SetMinValue(CENT);
    m_selfstake_fund_amount->setValue(COIN);
    m_selfstake_fund_amount->setToolTip(tr("Amount to send to this wallet-backed quantum staking address."));
    m_selfstake_fund = new QPushButton(tr("Activate staking"), coldstakeBox);
    m_selfstake_fund->setObjectName(QStringLiteral("selfStakeFund"));
    m_selfstake_fund->setToolTip(tr("Create, sign, and broadcast a wallet transaction funding this quantum staking address."));
    m_selfstake_withdraw = new QPushButton(tr("Stop staking"), coldstakeBox);
    m_selfstake_withdraw->setObjectName(QStringLiteral("selfStakeWithdraw"));
    m_selfstake_withdraw->setToolTip(tr("If bonded, starts unbonding for the selected lock period. If already unbonded and mature, withdraws to a fresh quantum address."));
    m_selfstake_status = new QLabel(QStringLiteral("-"), coldstakeBox);
    m_selfstake_status->setObjectName(QStringLiteral("selfStakeStatus"));
    m_selfstake_status->setWordWrap(true);

    auto* operatorHeading = new QLabel(tr("<b>Operate a cold-staking node</b>"), coldstakeBox);
    operatorHeading->setTextFormat(Qt::RichText);
    m_operator_address = new QLineEdit(coldstakeBox);
    m_operator_address->setObjectName(QStringLiteral("coldstakeOperatorAddress"));
    configureLineEdit(m_operator_address);
    m_operator_address->setReadOnly(true);
    m_operator_address->setToolTip(tr("Wallet-backed quantum address for this operator key."));
    m_operator_selector = new QComboBox(coldstakeBox);
    m_operator_selector->setObjectName(QStringLiteral("coldstakeOperatorAddressSelector"));
    m_operator_selector->setEditable(false);
    m_operator_selector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_operator_selector->setToolTip(tr("Select a previously-created 30-day cold-stake operator bond key."));
    m_operator_selector->addItem(tr("No saved operator keys"), QString());
    m_operator_pubkey = new QLineEdit(coldstakeBox);
    m_operator_pubkey->setObjectName(QStringLiteral("coldstakeOperatorPubkey"));
    configureLineEdit(m_operator_pubkey);
    m_operator_pubkey->setReadOnly(true);
    m_operator_pubkey->setToolTip(tr("Public ML-DSA staking key to give delegators. Keep the wallet online to stake for delegated cold deposits."));
    m_operator_new = new QPushButton(tr("Create 30-day operator bond key"), coldstakeBox);
    m_operator_new->setObjectName(QStringLiteral("newColdstakeOperatorKey"));
    m_operator_copy = new QPushButton(tr("Copy operator key"), coldstakeBox);
    m_operator_copy->setObjectName(QStringLiteral("coldstakeOperatorCopy"));
    m_operator_use_for_delegation = new QPushButton(tr("Use for delegation"), coldstakeBox);
    m_operator_use_for_delegation->setObjectName(QStringLiteral("coldstakeOperatorUseForDelegation"));
    m_operator_bond_amount = new BitcoinAmountField(coldstakeBox);
    m_operator_bond_amount->setObjectName(QStringLiteral("coldstakeOperatorBondAmount"));
    m_operator_bond_amount->SetMinValue(CENT);
    m_operator_bond_amount->setValue(COIN);
    m_operator_bond_amount->setToolTip(tr("Amount to send to this wallet-backed 30-day operator bond address. The protocol only requires a nonzero live bond output."));
    m_operator_fund = new QPushButton(tr("Activate operator"), coldstakeBox);
    m_operator_fund->setObjectName(QStringLiteral("coldstakeOperatorFund"));
    m_operator_fund->setToolTip(tr("Create, sign, and broadcast a wallet transaction funding this operator bond address."));
    m_operator_withdraw = new QPushButton(tr("Stop operator"), coldstakeBox);
    m_operator_withdraw->setObjectName(QStringLiteral("coldstakeOperatorWithdraw"));
    m_operator_withdraw->setToolTip(tr("If bonded, starts the 30-day unbonding spend. If already unbonded and mature, withdraws to a fresh quantum address."));
    m_operator_status = new QLabel(tr("No operator key selected. Fund a 30-day commitment bond; once the bond has normal confirmations, the operator is available for delegation."), coldstakeBox);
    m_operator_status->setObjectName(QStringLiteral("coldstakeOperatorStatus"));
    m_operator_status->setWordWrap(true);

    m_operator_registry = new QTableWidget(coldstakeBox);
    m_operator_registry->setObjectName(QStringLiteral("coldstakeOperatorRegistry"));
    m_operator_registry->setColumnCount(5);
    m_operator_registry->setHorizontalHeaderLabels(QStringList{tr("Operator"), tr("Delegated"), tr("Share"), tr("Status"), tr("Cap")});
    m_operator_registry->horizontalHeader()->setStretchLastSection(true);
    m_operator_registry->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_operator_registry->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_operator_registry->setSelectionMode(QAbstractItemView::SingleSelection);
    m_operator_registry->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_operator_registry->setAlternatingRowColors(true);
    m_operator_registry->setMinimumHeight(96);
    m_operator_registry->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    m_operator_registry_refresh = new QPushButton(tr("Refresh operators"), coldstakeBox);
    m_operator_registry_refresh->setObjectName(QStringLiteral("coldstakeOperatorRefresh"));
    m_operator_registry_use = new QPushButton(tr("Select operator"), coldstakeBox);
    m_operator_registry_use->setObjectName(QStringLiteral("coldstakeOperatorSelect"));
    m_operator_registry_status = new QLabel(tr("Operator registry not loaded."), coldstakeBox);
    m_operator_registry_status->setObjectName(QStringLiteral("coldstakeOperatorRegistryStatus"));
    m_operator_registry_status->setWordWrap(true);

    auto* delegateHeading = new QLabel(tr("<b>Delegate coins to an operator</b>"), coldstakeBox);
    delegateHeading->setTextFormat(Qt::RichText);
    m_coldstake_quantum_available = new QLabel(QStringLiteral("-"), coldstakeBox);
    m_coldstake_quantum_available->setObjectName(QStringLiteral("coldstakeQuantumAvailable"));
    m_coldstake_quantum_available->setWordWrap(true);
    m_coldstake_quantum_available->setToolTip(tr("Wallet-owned quantum balance currently visible for staking and delegation decisions."));
    m_coldstake_selection_summary = new QLabel(QStringLiteral("-"), coldstakeBox);
    m_coldstake_selection_summary->setObjectName(QStringLiteral("coldstakeSelectionSummary"));
    m_coldstake_selection_summary->setWordWrap(true);
    m_coldstake_lock_period = new QComboBox(coldstakeBox);
    m_coldstake_lock_period->setObjectName(QStringLiteral("coldstakeLockPeriod"));
    populateStakeLockCombo(m_coldstake_lock_period);
    m_coldstake_lock_period->setToolTip(tr("Creates a tiered cold-stake deposit address when a non-liquid lock period is selected."));
    m_coldstake_count = new QLabel(QStringLiteral("0"), coldstakeBox);
    m_coldstake_count->setObjectName(QStringLiteral("quantumColdstakeCount"));
    m_coldstake_operator_selector = new QComboBox(coldstakeBox);
    m_coldstake_operator_selector->setObjectName(QStringLiteral("coldstakeOperatorSelector"));
    m_coldstake_operator_selector->setEditable(false);
    m_coldstake_operator_selector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_coldstake_operator_selector->setToolTip(tr("Choose a verified cold-staking operator from the local registry, or select this wallet's operator key after creating one."));
    m_coldstake_operator_selector->addItem(tr("Refresh operators to select a cold-staking operator"), QString());
    m_coldstake_existing_selector = new QComboBox(coldstakeBox);
    m_coldstake_existing_selector->setObjectName(QStringLiteral("coldstakeDelegationSelector"));
    m_coldstake_existing_selector->setEditable(false);
    m_coldstake_existing_selector->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_coldstake_existing_selector->setToolTip(tr("Select a previously-created Quantum Cold-Stake delegation deposit address."));
    m_coldstake_existing_selector->addItem(tr("No saved delegation addresses"), QString());
    m_coldstake_address = new QLineEdit(coldstakeBox);
    m_coldstake_address->setObjectName(QStringLiteral("coldstakeAddress"));
    configureLineEdit(m_coldstake_address);
    m_coldstake_address->setReadOnly(true);
    m_coldstake_address->setToolTip(tr("Last wallet-backed Quantum Cold-Stake deposit address created or found by this wallet."));
    m_coldstake_new = new QPushButton(tr("Create delegation deposit address"), coldstakeBox);
    m_coldstake_new->setObjectName(QStringLiteral("newColdstakeAddress"));
    m_coldstake_copy = new QPushButton(tr("Copy"), coldstakeBox);
    m_coldstake_copy->setObjectName(QStringLiteral("coldstakeCopy"));
    m_coldstake_fund_amount = new BitcoinAmountField(coldstakeBox);
    m_coldstake_fund_amount->setObjectName(QStringLiteral("coldstakeFundAmount"));
    m_coldstake_fund_amount->SetMinValue(CENT);
    m_coldstake_fund_amount->setValue(COIN);
    m_coldstake_fund_amount->setToolTip(tr("Amount of spendable quantum balance to delegate to the selected operator."));
    m_coldstake_fund = new QPushButton(tr("Delegate coins"), coldstakeBox);
    m_coldstake_fund->setObjectName(QStringLiteral("coldstakeFund"));
    m_coldstake_fund->setToolTip(tr("Create, sign, and broadcast a quantum-only transaction funding this cold-stake delegation address."));
    m_coldstake_withdraw = new QPushButton(tr("Stop delegation"), coldstakeBox);
    m_coldstake_withdraw->setObjectName(QStringLiteral("coldstakeWithdraw"));
    m_coldstake_withdraw->setToolTip(tr("Owner-spend all available funds from this delegation back to a fresh wallet-backed quantum address."));
    m_coldstake_status = new QLabel(QStringLiteral("-"), coldstakeBox);
    m_coldstake_status->setObjectName(QStringLiteral("coldstakeStatus"));
    m_coldstake_status->setWordWrap(true);

    r = 0;
    selfStakeGrid->addWidget(selfStakeHeading, r++, 0, 1, 4);
    selfStakeGrid->addWidget(new QLabel(tr("Choose lock period:"), selfStakeTab), r, 0);
    selfStakeGrid->addWidget(m_selfstake_lock_period, r, 1, 1, 2);
    selfStakeGrid->addWidget(m_selfstake_new, r++, 3);
    selfStakeGrid->addWidget(new QLabel(tr("Saved staking address:"), selfStakeTab), r, 0);
    selfStakeGrid->addWidget(m_selfstake_selector, r++, 1, 1, 3);
    selfStakeGrid->addWidget(new QLabel(tr("Funding address:"), selfStakeTab), r, 0);
    selfStakeGrid->addWidget(m_selfstake_address, r, 1, 1, 2);
    selfStakeGrid->addWidget(m_selfstake_copy, r++, 3);
    selfStakeGrid->addWidget(new QLabel(tr("Fund amount:"), selfStakeTab), r, 0);
    selfStakeGrid->addWidget(m_selfstake_fund_amount, r, 1);
    selfStakeGrid->addWidget(m_selfstake_fund, r++, 2, 1, 2);
    selfStakeGrid->addWidget(new QLabel(tr("Existing stake output:"), selfStakeTab), r, 0);
    selfStakeGrid->addWidget(m_selfstake_output_selector, r++, 1, 1, 3);
    selfStakeGrid->addWidget(m_selfstake_withdraw, r++, 1, 1, 3);
    selfStakeGrid->addWidget(m_selfstake_status, r++, 0, 1, 4);
    selfStakeGrid->setColumnStretch(1, 1);
    selfStakeGrid->setColumnStretch(2, 1);

    r = 0;
    operatorGrid->addWidget(operatorHeading, r++, 0, 1, 4);
    operatorGrid->addWidget(new QLabel(tr("Operator lock:"), operatorTab), r, 0);
    operatorGrid->addWidget(new QLabel(tr("30 days fixed"), operatorTab), r++, 1, 1, 3);
    operatorGrid->addWidget(new QLabel(tr("Saved operator key:"), operatorTab), r, 0);
    operatorGrid->addWidget(m_operator_selector, r++, 1, 1, 3);
    operatorGrid->addWidget(new QLabel(tr("Operator address:"), operatorTab), r, 0);
    operatorGrid->addWidget(m_operator_address, r, 1, 1, 2);
    operatorGrid->addWidget(m_operator_new, r++, 3);
    operatorGrid->addWidget(new QLabel(tr("Operator public key:"), operatorTab), r, 0);
    operatorGrid->addWidget(m_operator_pubkey, r, 1, 1, 2);
    operatorGrid->addWidget(m_operator_copy, r++, 3);
    operatorGrid->addWidget(m_operator_use_for_delegation, r++, 1, 1, 3);
    operatorGrid->addWidget(new QLabel(tr("Bond amount:"), operatorTab), r, 0);
    operatorGrid->addWidget(m_operator_bond_amount, r, 1);
    operatorGrid->addWidget(m_operator_fund, r, 2);
    operatorGrid->addWidget(m_operator_withdraw, r++, 3);
    operatorGrid->addWidget(m_operator_status, r++, 0, 1, 4);
    operatorGrid->addWidget(new QLabel(tr("Available operators:"), operatorTab), r, 0);
    operatorGrid->addWidget(m_operator_registry_refresh, r, 1);
    operatorGrid->addWidget(m_operator_registry_use, r++, 2, 1, 2);
    operatorGrid->addWidget(m_operator_registry, r++, 0, 1, 4);
    operatorGrid->addWidget(m_operator_registry_status, r++, 0, 1, 4);
    operatorGrid->setColumnStretch(1, 1);
    operatorGrid->setColumnStretch(2, 1);

    r = 0;
    delegateGrid->addWidget(delegateHeading, r++, 0, 1, 4);
    delegateGrid->addWidget(new QLabel(tr("Available quantum balance:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_quantum_available, r++, 1, 1, 3);
    delegateGrid->addWidget(new QLabel(tr("Delegations:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_count, r++, 1);
    delegateGrid->addWidget(new QLabel(tr("Saved delegation:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_existing_selector, r++, 1, 1, 3);
    delegateGrid->addWidget(new QLabel(tr("Lock period:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_lock_period, r++, 1, 1, 3);
    delegateGrid->addWidget(new QLabel(tr("Operator:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_operator_selector, r++, 1, 1, 3);
    delegateGrid->addWidget(m_coldstake_selection_summary, r++, 0, 1, 4);
    delegateGrid->addWidget(new QLabel(tr("Delegation address:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_address, r, 1, 1, 2);
    delegateGrid->addWidget(m_coldstake_copy, r++, 3);
    delegateGrid->addWidget(m_coldstake_new, r++, 1, 1, 3);
    delegateGrid->addWidget(new QLabel(tr("Fund amount:"), delegateTab), r, 0);
    delegateGrid->addWidget(m_coldstake_fund_amount, r, 1);
    delegateGrid->addWidget(m_coldstake_fund, r, 2);
    delegateGrid->addWidget(m_coldstake_withdraw, r++, 3);
    delegateGrid->addWidget(m_coldstake_status, r++, 0, 1, 4);
    delegateGrid->setColumnStretch(1, 1);
    delegateGrid->setColumnStretch(2, 1);
    outer->addWidget(coldstakeBox);

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
    m_quantum_address = new QLineEdit(migrationBox);
    m_quantum_address->setObjectName(QStringLiteral("quantumAddress"));
    configureLineEdit(m_quantum_address);
    m_quantum_address->setReadOnly(true);
    m_quantum_address->setToolTip(tr("Last wallet-backed quantum migration address created or found by this wallet."));
    m_quantum_pubkey = new QLineEdit(migrationBox);
    m_quantum_pubkey->setObjectName(QStringLiteral("quantumPubkey"));
    configureLineEdit(m_quantum_pubkey);
    m_quantum_pubkey->setReadOnly(true);
    m_quantum_pubkey->setToolTip(tr("ML-DSA public key for the quantum address above. Share this public key with a cold wallet that will delegate staking to this wallet."));
    m_quantum_new = new QPushButton(tr("New quantum address"), migrationBox);
    m_quantum_new->setObjectName(QStringLiteral("newQuantumAddress"));
    m_quantum_new->setToolTip(tr("Create a wallet-backed ML-DSA quantum migration address."));
    m_quantum_copy = new QPushButton(tr("Copy"), migrationBox);
    m_quantum_copy->setObjectName(QStringLiteral("quantumCopy"));
    m_quantum_pubkey_copy = new QPushButton(tr("Copy key"), migrationBox);
    m_quantum_pubkey_copy->setObjectName(QStringLiteral("quantumPubkeyCopy"));
    m_migration_legacy_sweep = new QPushButton(tr("Move legacy to quantum"), migrationBox);
    m_migration_legacy_sweep->setObjectName(QStringLiteral("migrationLegacySweep"));
    m_migration_legacy_sweep->setToolTip(tr("Create, sign, and broadcast a transaction moving all spendable legacy wallet funds to a fresh wallet-backed quantum address."));
    m_migration_goldrush_sweep = new QPushButton(tr("Move Gold Rush rewards"), migrationBox);
    m_migration_goldrush_sweep->setObjectName(QStringLiteral("migrationGoldrushSweep"));
    m_migration_goldrush_sweep->setToolTip(tr("Move wallet-owned Gold Rush reward outputs to a fresh quantum address before using them for sends, staking, or delegation."));
    m_migration_action_status = new QLabel(QStringLiteral("-"), migrationBox);
    m_migration_action_status->setObjectName(QStringLiteral("migrationActionStatus"));
    m_migration_action_status->setWordWrap(true);

    m_demurrage_status = new QLabel(tr("Demurrage: unknown"), migrationBox);
    m_demurrage_status->setObjectName(QStringLiteral("demurrageStatus"));
    m_demurrage_status->setWordWrap(true);
    m_demurrage_amounts = new QLabel(QStringLiteral("-"), migrationBox);
    m_demurrage_amounts->setObjectName(QStringLiteral("demurrageAmounts"));
    m_demurrage_amounts->setWordWrap(true);
    m_demurrage_guards = new QLabel(QStringLiteral("-"), migrationBox);
    m_demurrage_guards->setObjectName(QStringLiteral("demurrageGuards"));
    m_demurrage_guards->setWordWrap(true);
    m_demurrage_attest = new QPushButton(tr("Attest selected quantum address"), migrationBox);
    m_demurrage_attest->setObjectName(QStringLiteral("demurrageAttest"));
    m_demurrage_attest->setToolTip(tr("Create a fee-paying liveness attestation for the selected wallet-backed quantum address."));

    m_rgb_assets = new QTableWidget(migrationBox);
    m_rgb_assets->setObjectName(QStringLiteral("rgbAssets"));
    m_rgb_assets->setColumnCount(5);
    m_rgb_assets->setHorizontalHeaderLabels(QStringList{tr("Asset"), tr("Balance"), tr("Supply"), tr("Assignments"), tr("Contract")});
    m_rgb_assets->horizontalHeader()->setStretchLastSection(true);
    m_rgb_assets->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_rgb_assets->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_rgb_assets->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_rgb_assets->setSelectionMode(QAbstractItemView::SingleSelection);
    m_rgb_assets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_rgb_assets->setAlternatingRowColors(true);
    m_rgb_assets->setMinimumHeight(88);
    m_rgb_assets->setMaximumHeight(140);
    m_rgb_assets->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_rgb_copy_contract = new QPushButton(tr("Copy RGB contract"), migrationBox);
    m_rgb_copy_contract->setObjectName(QStringLiteral("rgbCopyContract"));
    m_rgb_status = new QLabel(tr("RGB wallet assets not loaded."), migrationBox);
    m_rgb_status->setObjectName(QStringLiteral("rgbStatus"));
    m_rgb_status->setWordWrap(true);

    m_eutxo_states = new QTableWidget(migrationBox);
    m_eutxo_states->setObjectName(QStringLiteral("eutxoStates"));
    m_eutxo_states->setColumnCount(5);
    m_eutxo_states->setHorizontalHeaderLabels(QStringList{tr("Outpoint"), tr("Amount"), tr("Spent"), tr("Datum"), tr("Validator")});
    m_eutxo_states->horizontalHeader()->setStretchLastSection(true);
    m_eutxo_states->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_eutxo_states->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_eutxo_states->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eutxo_states->setSelectionMode(QAbstractItemView::SingleSelection);
    m_eutxo_states->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eutxo_states->setAlternatingRowColors(true);
    m_eutxo_states->setMinimumHeight(88);
    m_eutxo_states->setMaximumHeight(140);
    m_eutxo_states->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_eutxo_status = new QLabel(tr("EUTXO states not loaded."), migrationBox);
    m_eutxo_status->setObjectName(QStringLiteral("eutxoStatus"));
    m_eutxo_status->setWordWrap(true);

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
    mgrid->addWidget(m_quantum_address_count, r++, 1);
    mgrid->addWidget(new QLabel(tr("Address:"), migrationBox), r, 0);
    mgrid->addWidget(m_quantum_address, r, 1, 1, 2);
    mgrid->addWidget(m_quantum_copy, r++, 3);
    mgrid->addWidget(new QLabel(tr("Public key:"), migrationBox), r, 0);
    mgrid->addWidget(m_quantum_pubkey, r, 1, 1, 2);
    mgrid->addWidget(m_quantum_pubkey_copy, r++, 3);
    mgrid->addWidget(m_quantum_new, r++, 1, 1, 2);
    mgrid->addWidget(m_migration_legacy_sweep, r, 1);
    mgrid->addWidget(m_migration_goldrush_sweep, r++, 2);
    mgrid->addWidget(m_migration_action_status, r++, 0, 1, 4);
    mgrid->addWidget(new QLabel(tr("Demurrage:"), migrationBox), r, 0);
    mgrid->addWidget(m_demurrage_status, r++, 1, 1, 3);
    mgrid->addWidget(new QLabel(tr("Exposure:"), migrationBox), r, 0);
    mgrid->addWidget(m_demurrage_amounts, r++, 1, 1, 3);
    mgrid->addWidget(new QLabel(tr("Guards:"), migrationBox), r, 0);
    mgrid->addWidget(m_demurrage_guards, r, 1, 1, 2);
    mgrid->addWidget(m_demurrage_attest, r++, 3);
    mgrid->addWidget(new QLabel(tr("RGB assets:"), migrationBox), r, 0);
    mgrid->addWidget(m_rgb_copy_contract, r++, 3);
    mgrid->addWidget(m_rgb_assets, r++, 0, 1, 4);
    mgrid->addWidget(m_rgb_status, r++, 0, 1, 4);
    mgrid->addWidget(new QLabel(tr("EUTXO states:"), migrationBox), r++, 0, 1, 4);
    mgrid->addWidget(m_eutxo_states, r++, 0, 1, 4);
    mgrid->addWidget(m_eutxo_status, r++, 0, 1, 4);
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
    m_pow_settings_dirty = false;
    m_operator_registry_loaded = false;
    m_operator_registry_refresh_seconds = 0;
    m_operator_last_action_status.clear();

    if (m_wallet_model) {
        connect(m_wallet_model, &QObject::destroyed, this, [this] {
            m_wallet_model = nullptr;
            if (m_timer) m_timer->stop();
            m_updating = false;
            m_pow_apply_pending = false;
            m_pow_settings_dirty = false;
            m_operator_registry_loaded = false;
            m_operator_registry_refresh_seconds = 0;
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

void StakingMiningPage::onPowSettingsChanged(int)
{
    if (m_updating || !m_wallet_model) return;
    m_pow_settings_dirty = true;
    if (m_pow_enable->isChecked()) {
        m_pow_status->setText(tr("PoW miner settings changed. Click Apply to update the miner."));
    } else {
        m_pow_status->setText(tr("Enable Gold Rush PoW mining to use these settings."));
    }
    refreshControlsEnabled();
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
    m_pow_settings_dirty = false;
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
    m_migration_action_status->setText(tr("New wallet-backed quantum address created and copied. Back up this wallet before receiving funds."));
    QApplication::clipboard()->setText(m_quantum_address->text());
    m_force_full_refresh = true;
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

void StakingMiningPage::onMigrateLegacyToQuantum()
{
    if (!m_wallet_model) return;
    const int rc = QMessageBox::question(
        this,
        tr("Move legacy funds to quantum"),
        tr("This will create a fresh wallet-backed quantum address and move all spendable legacy wallet funds into it. Back up the wallet after the transaction is created. Continue?"));
    if (rc != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().migrateLegacyToQuantum();
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_migration_action_status->setText(msg);
        QMessageBox::warning(this, tr("Move legacy funds to quantum"), msg);
        return;
    }

    m_quantum_address->setText(QString::fromStdString(result->address));
    m_migration_action_status->setText(tr("Migration broadcast: %1. Moved %2 from %3 input(s); fee %4. Back up this wallet now.")
        .arg(QString::fromStdString(result->txid))
        .arg(formatBLK(result->amount))
        .arg(result->selected_inputs)
        .arg(formatBLK(result->fee)));
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onMigrateGoldRushRewards()
{
    if (!m_wallet_model) return;
    const int rc = QMessageBox::question(
        this,
        tr("Move Gold Rush rewards"),
        tr("This will create a fresh wallet-backed quantum address and move wallet-owned Gold Rush reward outputs into it. After confirmation, those funds can be used for sends, staking, operator bonds, or cold-stake delegation. Continue?"));
    if (rc != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().migrateGoldRushRewards();
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_migration_action_status->setText(msg);
        QMessageBox::warning(this, tr("Move Gold Rush rewards"), msg);
        return;
    }

    m_quantum_address->setText(QString::fromStdString(result->address));
    m_migration_action_status->setText(tr("Gold Rush reward move broadcast: %1. Fresh quantum address: %2. Moved %3 from %4 output(s); fee %5. Back up this wallet now.")
        .arg(QString::fromStdString(result->txid))
        .arg(QString::fromStdString(result->address))
        .arg(formatBLK(result->amount))
        .arg(result->selected_inputs)
        .arg(formatBLK(result->fee)));
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onSendDemurrageAttestation()
{
    if (!m_wallet_model) return;
    const QString address = m_quantum_address->text().trimmed();
    if (address.isEmpty()) {
        m_demurrage_status->setText(tr("Select or create a quantum address before sending an attestation."));
        return;
    }
    const int rc = QMessageBox::question(
        this,
        tr("Demurrage attestation"),
        tr("This will create a small fee-paying liveness attestation for the selected quantum address:\n%1\n\nContinue?")
            .arg(address));
    if (rc != QMessageBox::Yes) return;

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().sendDemurrageAttestation(address.toStdString());
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_demurrage_status->setText(msg);
        QMessageBox::warning(this, tr("Demurrage attestation"), msg);
        return;
    }

    m_demurrage_status->setText(tr("Demurrage attestation broadcast: %1. Fee: %2.")
        .arg(QString::fromStdString(result->txid))
        .arg(formatBLK(result->fee)));
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onCopySelectedRGBContract()
{
    if (!m_rgb_assets || m_rgb_assets->selectedItems().empty()) return;
    const int row = m_rgb_assets->selectedItems().front()->row();
    QTableWidgetItem* contract_item = m_rgb_assets->item(row, 4);
    if (!contract_item) return;
    const QString contract_id = contract_item->data(Qt::UserRole).toString();
    if (!contract_id.isEmpty()) QApplication::clipboard()->setText(contract_id);
}

void StakingMiningPage::onCreateSelfStakeAddress()
{
    if (!m_wallet_model) return;
    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    const uint16_t unbonding_blocks = selectedStakeLockBlocks(m_selfstake_lock_period);
    auto result = m_wallet_model->wallet().createQuantumStakeAddress("quantum-stake", unbonding_blocks);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_selfstake_status->setText(msg);
        QMessageBox::warning(this, tr("Quantum staking"), msg);
        return;
    }
    m_selfstake_address->setText(QString::fromStdString(result->address));
    m_selfstake_last_action_status.clear();
    m_selfstake_status->setText(tr("Tiered staking address created with %1 bonded blocks. Back up this wallet before funding it.").arg(result->unbonding_blocks));
    QApplication::clipboard()->setText(m_selfstake_address->text());
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onCopySelfStakeAddress()
{
    if (m_selfstake_address && !m_selfstake_address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_selfstake_address->text());
    }
}

void StakingMiningPage::onFundSelfStakeAddress()
{
    if (!m_wallet_model || !m_selfstake_fund_amount) return;
    if (m_selfstake_address->text().isEmpty()) {
        m_selfstake_status->setText(tr("Create a quantum staking address first."));
        return;
    }
    if (!m_selfstake_fund_amount->validate()) {
        m_selfstake_status->setText(tr("Enter a valid staking amount."));
        return;
    }
    const CAmount amount = m_selfstake_fund_amount->value();
    if (amount <= 0) {
        m_selfstake_status->setText(tr("Staking amount must be positive."));
        return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().fundQuantumStakeAddress(m_selfstake_address->text().toStdString(), amount);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_selfstake_status->setText(msg);
        QMessageBox::warning(this, tr("Activate staking"), msg);
        return;
    }

    m_selfstake_last_action_status = tr("Staking address funding broadcast: %1. Amount: %2. Fee: %3.")
        .arg(QString::fromStdString(result->txid))
        .arg(formatBLK(result->amount))
        .arg(formatBLK(result->fee));
    m_selfstake_status->setText(m_selfstake_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onWithdrawSelfStakeAddress()
{
    if (!m_wallet_model) return;
    if (m_selfstake_address->text().isEmpty()) {
        m_selfstake_status->setText(tr("Create a quantum staking address first."));
        return;
    }
    const std::optional<COutPoint> selected_outpoint = outpointFromSelectorData(m_selfstake_output_selector->currentData());

    const interfaces::WalletQuantumOperatorBondInfo info =
        m_wallet_model->wallet().getQuantumStakeAddressBondInfo(m_selfstake_address->text().toStdString());
    if (selected_outpoint) {
        const int rc = QMessageBox::question(
            this,
            tr("Stop selected quantum stake"),
            tr("This will act only on the selected staking output:\n%1\n\nIf it is bonded, unbonding starts. If it is already mature, it withdraws to a fresh quantum address. Continue?")
                .arg(m_selfstake_output_selector->currentText()));
        if (rc != QMessageBox::Yes) return;
    } else if (info.valid_operator_address && info.bonded_outputs > 0) {
        const int rc = QMessageBox::question(
            this,
            tr("Stop quantum staking"),
            tr("This will start unbonding for %1. The principal remains locked until the staking address's unlock height. Continue?")
                .arg(formatBLK(info.bonded_amount)));
        if (rc != QMessageBox::Yes) return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = selected_outpoint
        ? m_wallet_model->wallet().withdrawQuantumStakeOutput(m_selfstake_address->text().toStdString(), *selected_outpoint)
        : m_wallet_model->wallet().withdrawQuantumStakeAddress(m_selfstake_address->text().toStdString());
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_selfstake_status->setText(msg);
        QMessageBox::warning(this, tr("Stop quantum staking"), msg);
        return;
    }

    if (result->started_unbonding) {
        m_selfstake_last_action_status = tr("Quantum staking unbonding started: %1. Amount: %2. Unlock height: %3. Fee: %4.")
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(result->unlock_height)
            .arg(formatBLK(result->fee));
    } else {
        m_selfstake_last_action_status = tr("Quantum staking funds withdrawn: %1. Amount: %2. Destination: %3. Fee: %4.")
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(QString::fromStdString(result->address))
            .arg(formatBLK(result->fee));
    }
    m_selfstake_status->setText(m_selfstake_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onCreateOperatorKey()
{
    if (!m_wallet_model) return;
    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().createQuantumStakeAddress("coldstake-operator", OPERATOR_COMMITMENT_BLOCKS);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_operator_status->setText(msg);
        QMessageBox::warning(this, tr("Quantum cold staking"), msg);
        return;
    }
    m_operator_address->setText(QString::fromStdString(result->address));
    m_operator_pubkey->setText(QString::fromStdString(result->public_key));
    m_operator_last_action_status.clear();
    m_operator_status->setText(tr("30-day operator bond key ready. Back up this wallet before funding it; delegators use this public key to verify your operator commitment."));
    QApplication::clipboard()->setText(m_operator_pubkey->text());
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onCopyOperatorKey()
{
    if (m_operator_pubkey && !m_operator_pubkey->text().isEmpty()) {
        QApplication::clipboard()->setText(m_operator_pubkey->text());
    }
}

void StakingMiningPage::onUseOperatorKeyForDelegation()
{
    if (m_operator_pubkey && !m_operator_pubkey->text().isEmpty()) {
        setColdStakeOperatorSelection(m_operator_pubkey->text(), tr("This wallet operator key"));
    }
}

void StakingMiningPage::onFundOperatorBond()
{
    if (!m_wallet_model || !m_operator_bond_amount) return;
    if (m_operator_address->text().isEmpty()) {
        m_operator_status->setText(tr("Create or select an operator bond key first."));
        return;
    }
    if (!m_operator_bond_amount->validate()) {
        m_operator_status->setText(tr("Enter a valid operator bond amount."));
        return;
    }
    const CAmount amount = m_operator_bond_amount->value();
    if (amount <= 0) {
        m_operator_status->setText(tr("Operator bond amount must be positive."));
        return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().fundQuantumOperatorBond(m_operator_address->text().toStdString(), amount);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_operator_status->setText(msg);
        QMessageBox::warning(this, tr("Activate operator"), msg);
        return;
    }

    m_operator_last_action_status = tr("Operator bond funding broadcast: %1. Amount: %2. Fee: %3.")
        .arg(QString::fromStdString(result->txid))
        .arg(formatBLK(result->amount))
        .arg(formatBLK(result->fee));
    m_operator_status->setText(m_operator_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onWithdrawOperatorBond()
{
    if (!m_wallet_model) return;
    if (m_operator_address->text().isEmpty()) {
        m_operator_status->setText(tr("Create or select an operator bond key first."));
        return;
    }

    const interfaces::WalletQuantumOperatorBondInfo info =
        m_wallet_model->wallet().getQuantumOperatorBondInfo(m_operator_address->text().toStdString());
    if (info.valid_operator_address && info.bonded_outputs > 0) {
        const int rc = QMessageBox::question(
            this,
            tr("Stop cold-stake operator"),
            tr("This will start the 30-day unbonding period for %1. The principal remains locked until the unbonding height. Continue?")
                .arg(formatBLK(info.bonded_amount)));
        if (rc != QMessageBox::Yes) return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().withdrawQuantumOperatorBond(m_operator_address->text().toStdString());
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_operator_status->setText(msg);
        QMessageBox::warning(this, tr("Stop operator"), msg);
        return;
    }

    if (result->started_unbonding) {
        m_operator_last_action_status = tr("Operator unbonding started: %1. Amount: %2. Unlock height: %3. Fee: %4.")
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(result->unlock_height)
            .arg(formatBLK(result->fee));
    } else {
        m_operator_last_action_status = tr("Operator funds withdrawn: %1. Amount: %2. Destination: %3. Fee: %4.")
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(QString::fromStdString(result->address))
            .arg(formatBLK(result->fee));
    }
    m_operator_status->setText(m_operator_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onRefreshOperatorRegistry()
{
    refreshOperatorRegistry();
}

void StakingMiningPage::onUseRegistryOperatorForDelegation()
{
    if (!m_operator_registry) return;
    const QList<QTableWidgetItem*> selected = m_operator_registry->selectedItems();
    if (selected.empty()) return;

    const int row = selected.front()->row();
    QTableWidgetItem* operator_item = m_operator_registry->item(row, 0);
    if (!operator_item) return;
    const QString pubkey = operator_item->data(Qt::UserRole).toString();
    if (pubkey.isEmpty()) return;

    setColdStakeOperatorSelection(pubkey, operator_item->text());
}

void StakingMiningPage::onCreateColdStakeAddress()
{
    if (!m_wallet_model) return;
    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    const QString staking_pubkey = selectedColdStakeOperatorPubKey();
    if (staking_pubkey.isEmpty()) {
        m_coldstake_status->setText(tr("Select a cold-staking operator before creating a delegation address."));
        return;
    }
    const uint16_t unbonding_blocks = selectedStakeLockBlocks(m_coldstake_lock_period);
    auto result = m_wallet_model->wallet().createQuantumColdStakeAddress(staking_pubkey.toStdString(), "coldstake-gui", unbonding_blocks);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_coldstake_status->setText(msg);
        QMessageBox::warning(this, tr("Quantum cold staking"), msg);
        return;
    }
    m_coldstake_address->setText(QString::fromStdString(result->address));
    m_coldstake_last_action_status = result->has_staker_key
        ? tr("Cold-stake address created with %1 bonded blocks. This wallet can stake and owner-spend this delegation. Back up this wallet before funding it.").arg(result->unbonding_blocks)
        : tr("Cold-stake address created with %1 bonded blocks. This wallet holds the owner key. Back up this wallet before funding it.").arg(result->unbonding_blocks);
    m_coldstake_status->setText(m_coldstake_last_action_status);
    QApplication::clipboard()->setText(m_coldstake_address->text());
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onCopyColdStakeAddress()
{
    if (m_coldstake_address && !m_coldstake_address->text().isEmpty()) {
        QApplication::clipboard()->setText(m_coldstake_address->text());
    }
}

void StakingMiningPage::onFundColdStakeAddress()
{
    if (!m_wallet_model || !m_coldstake_fund_amount) return;
    if (m_coldstake_address->text().isEmpty()) {
        m_coldstake_status->setText(tr("Create or select a delegation address first."));
        return;
    }
    if (!m_coldstake_fund_amount->validate()) {
        m_coldstake_status->setText(tr("Enter a valid delegation amount."));
        return;
    }
    const CAmount amount = m_coldstake_fund_amount->value();
    if (amount <= 0) {
        m_coldstake_status->setText(tr("Delegation amount must be positive."));
        return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().fundQuantumColdStakeAddress(m_coldstake_address->text().toStdString(), amount);
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_coldstake_status->setText(msg);
        QMessageBox::warning(this, tr("Delegate coins"), msg);
        return;
    }

    if (result->created_migration && result->completed_delegation) {
        m_coldstake_last_action_status = tr("Gold Rush rewards were first moved to fresh quantum address %1 (%2, fee %3), then delegation funding was broadcast: %4. Delegated %5; delegation fee %6.")
            .arg(QString::fromStdString(result->migration_address))
            .arg(QString::fromStdString(result->migration_txid))
            .arg(formatBLK(result->migration_fee))
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(formatBLK(result->fee));
    } else if (result->created_migration) {
        m_coldstake_last_action_status = tr("Gold Rush rewards were moved to fresh quantum address %1 (%2, fee %3). Delegation was not broadcast yet: %4")
            .arg(QString::fromStdString(result->migration_address))
            .arg(QString::fromStdString(result->migration_txid))
            .arg(formatBLK(result->migration_fee))
            .arg(QString::fromStdString(result->warning));
        QMessageBox::information(this, tr("Gold Rush rewards moved"), m_coldstake_last_action_status);
    } else {
        m_coldstake_last_action_status = tr("Cold-stake delegation funding broadcast: %1. Amount: %2. Fee: %3.")
            .arg(QString::fromStdString(result->txid))
            .arg(formatBLK(result->amount))
            .arg(formatBLK(result->fee));
    }
    m_coldstake_status->setText(m_coldstake_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::onWithdrawColdStakeAddress()
{
    if (!m_wallet_model) return;
    if (m_coldstake_address->text().isEmpty()) {
        m_coldstake_status->setText(tr("Create or select a delegation address first."));
        return;
    }

    const interfaces::WalletQuantumColdStakeBalanceInfo info =
        m_wallet_model->wallet().getQuantumColdStakeBalanceInfo(m_coldstake_address->text().toStdString());
    if (info.valid_delegation_address && info.spendable_amount > 0) {
        const int rc = QMessageBox::question(
            this,
            tr("Withdraw cold-stake delegation"),
            tr("This will owner-spend %1 from the selected delegation to a fresh quantum address controlled by this wallet. The selected operator will stop staking those funds. Continue?")
                .arg(formatBLK(info.spendable_amount)));
        if (rc != QMessageBox::Yes) return;
    }

    WalletModel::UnlockContext ctx(m_wallet_model->requestUnlock());
    if (!ctx.isValid()) return;

    auto result = m_wallet_model->wallet().withdrawQuantumColdStakeAddress(m_coldstake_address->text().toStdString());
    if (!result) {
        const QString msg = QString::fromStdString(util::ErrorString(result).original);
        m_coldstake_status->setText(msg);
        QMessageBox::warning(this, tr("Withdraw delegation"), msg);
        return;
    }

    m_coldstake_last_action_status = tr("Cold-stake delegation withdrawn: %1. Amount: %2. Destination: %3. Fee: %4.")
        .arg(QString::fromStdString(result->txid))
        .arg(formatBLK(result->amount))
        .arg(QString::fromStdString(result->address))
        .arg(formatBLK(result->fee));
    m_coldstake_status->setText(m_coldstake_last_action_status);
    m_force_full_refresh = true;
    updateStatus();
}

void StakingMiningPage::refreshOperatorRegistry()
{
    if (!m_wallet_model || !m_operator_registry || !m_coldstake_operator_selector) return;

    const QString previous_selection = selectedColdStakeOperatorPubKey();
    const QString previous_label = m_coldstake_operator_selector->currentText();
    interfaces::WalletQuantumPoolInfo pool = m_wallet_model->wallet().getQuantumPoolInfo();

    m_operator_registry->setRowCount(0);
    {
        QSignalBlocker selector_blocker(m_coldstake_operator_selector);
        m_coldstake_operator_selector->clear();
    }

    if (!pool.available) {
        QSignalBlocker selector_blocker(m_coldstake_operator_selector);
        m_coldstake_operator_selector->addItem(tr("Operator registry busy; try Refresh again"), QString());
        m_operator_registry_status->setText(tr("Operator registry is busy. No delegation operator is selected."));
        m_operator_registry_loaded = false;
        m_operator_registry_refresh_seconds = 0;
        refreshControlsEnabled();
        return;
    }

    int selectable_count = 0;
    int previous_registry_row = -1;
    m_operator_registry->setRowCount(static_cast<int>(pool.operators.size()));
    for (int row = 0; row < static_cast<int>(pool.operators.size()); ++row) {
        const interfaces::WalletQuantumPoolOperatorInfo& op = pool.operators.at(row);
        const QString pubkey = QString::fromStdString(op.staking_pubkey);
        const QString label = !op.staking_pubkey.empty()
            ? shortenHex(op.staking_pubkey)
            : shortenHex(op.staking_pubkey_hash);
        const QString bond = op.operator_commitment_verified ? tr("ready") : tr("missing bond");
        const QString cap = op.over_cap ? tr("over 20%") : tr("ok");

        auto* operator_item = new QTableWidgetItem(label);
        operator_item->setData(Qt::UserRole, pubkey);
        operator_item->setToolTip(!pubkey.isEmpty() ? pubkey : QString::fromStdString(op.staking_pubkey_hash));
        m_operator_registry->setItem(row, 0, operator_item);
        m_operator_registry->setItem(row, 1, new QTableWidgetItem(formatBLK(op.verified_value)));
        m_operator_registry->setItem(row, 2, new QTableWidgetItem(formatBps(op.share_bps)));
        m_operator_registry->setItem(row, 3, new QTableWidgetItem(bond));
        m_operator_registry->setItem(row, 4, new QTableWidgetItem(cap));

        if (!pubkey.isEmpty()) {
            const QString selector_label = tr("%1  |  %2 delegated  |  %3 share  |  %4")
                .arg(label)
                .arg(formatBLK(op.verified_value))
                .arg(formatBps(op.share_bps))
                .arg(bond);
            m_coldstake_operator_selector->addItem(selector_label, pubkey);
            m_coldstake_operator_selector->setItemData(m_coldstake_operator_selector->count() - 1, QString::fromStdString(op.staking_pubkey_hash), Qt::UserRole + 1);
            ++selectable_count;
            if (!previous_selection.isEmpty() && pubkey == previous_selection) {
                previous_registry_row = row;
            }
        }
    }

    if (!previous_selection.isEmpty()) {
        const int previous_index = m_coldstake_operator_selector->findData(previous_selection);
        if (previous_index >= 0) {
            m_coldstake_operator_selector->setCurrentIndex(previous_index);
            if (previous_registry_row >= 0) m_operator_registry->selectRow(previous_registry_row);
        } else {
            const QString label = previous_label.trimmed().isEmpty() || previous_label == tr("No verified operators discovered")
                ? tr("%1  |  selected, not yet verified in registry").arg(shortenHex(previous_selection.toStdString()))
                : tr("%1  |  selected, not yet verified in registry").arg(previous_label);
            m_coldstake_operator_selector->addItem(label, previous_selection);
            m_coldstake_operator_selector->setCurrentIndex(m_coldstake_operator_selector->count() - 1);
        }
    } else if (selectable_count == 0) {
        QSignalBlocker selector_blocker(m_coldstake_operator_selector);
        m_coldstake_operator_selector->clear();
        m_coldstake_operator_selector->addItem(tr("No verified operators discovered"), QString());
    } else {
        m_coldstake_operator_selector->setCurrentIndex(0);
        if (m_operator_registry->rowCount() > 0) {
            m_operator_registry->selectRow(0);
        }
    }

    m_operator_registry_status->setText(pool.operators.empty()
        ? tr("No cold-staking operators are published in this node's local registry. Use getquantumpoolinfo in the console to inspect the same data.")
        : tr("%1 operator(s) discovered. Total delegated cold stake: %2. Operators become available after normal confirmations; the 30-day bond is the unbonding commitment. Wallet cap: %3.")
              .arg(static_cast<int>(pool.operators.size()))
              .arg(formatBLK(pool.total_coldstake))
              .arg(formatBps(pool.cap_bps)));
    m_operator_registry_loaded = true;
    m_operator_registry_refresh_seconds = 0;
    refreshControlsEnabled();
}

void StakingMiningPage::updateStatus()
{
    if (!m_wallet_model) {
        resetStatusForNoWallet();
        return;
    }
    m_updating = true;
    const bool full_refresh = m_force_full_refresh || m_status_refresh_tick == 0 || (m_status_refresh_tick % 12 == 0);
    ++m_status_refresh_tick;
    m_force_full_refresh = false;
    if (full_refresh) {
        m_selfstake_withdraw_available = false;
        m_operator_withdraw_available = false;
        m_coldstake_fund_available = false;
        m_coldstake_withdraw_available = false;
    }

    interfaces::Wallet& w = m_wallet_model->wallet();
    const interfaces::WalletBalances balances = w.getBalances();

    // Staking
    const bool staking = w.getEnabledStaking();
    const WalletModel::EncryptionStatus encryption_status = m_wallet_model->getEncryptionStatus();
    const bool normal_unlocked = encryption_status == WalletModel::Unlocked &&
                                 !w.getWalletUnlockStakingOnly();
    const bool normal_signing_available = encryption_status == WalletModel::Unencrypted || normal_unlocked;
    m_staking_enable->setChecked(staking);
    m_unlock_staking_only->setChecked(w.getWalletUnlockStakingOnly());
    m_unlock_quantum_legacy_staking->setChecked(normal_unlocked);
    m_staking_status->setText(staking ? tr("Staking is active") : tr("Staking is off"));
    uint64_t stake_weight{0};
    if (w.tryGetStakeWeight(stake_weight)) {
        m_stake_weight->setText(QString::number(static_cast<qulonglong>(stake_weight)));
    } else {
        m_stake_weight->setText(tr("refreshing..."));
    }

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
    if (info.shadow_whitelist_height > 0) {
        QString eligibility;
        if (!info.wallet_goldrush_status_available) {
            eligibility = tr("Wallet eligibility is temporarily unavailable.");
        } else if (info.wallet_whitelisted_scripts <= 0) {
            eligibility = tr("This wallet has no spendable script in the Gold Rush whitelist.");
        } else if (info.wallet_active_signal) {
            eligibility = tr("This wallet is whitelisted and actively signaled.");
        } else if (info.wallet_recent_solve_qualified) {
            eligibility = tr("This wallet is whitelisted and has a recent solve; unlock normally to signal.");
        } else {
            eligibility = tr("This wallet is whitelisted, but needs a recent PoS solve before it can signal.");
        }
        if (info.wallet_blocks_until_solver_expiry > 0) {
            eligibility += tr(" Recent-solve window: %1 blocks remaining.").arg(info.wallet_blocks_until_solver_expiry);
        }
        m_quantum_legacy_unlock_note->setText(
            tr("Gold Rush PoS requires >= 10,000 BLK aggregate balance at whitelist height %1. Reward window: %2-%3. %4")
                .arg(info.shadow_whitelist_height)
                .arg(info.shadow_reward_start_height)
                .arg(info.shadow_reward_end_height)
                .arg(eligibility));
    }
    if (!m_pow_apply_pending) {
        m_pow_enable->setChecked(info.enabled);
        m_pow_unlock_wallet->setChecked(normal_unlocked);
        if (!m_pow_settings_dirty) {
            const int display_threads = info.enabled && info.threads > 0
                ? info.threads
                : 1;
            const int display_percent = info.enabled && info.cpu_percent > 0
                ? info.cpu_percent
                : 1;
            if (!m_pow_cores->hasFocus()) m_pow_cores->setValue(display_threads);
            if (!m_pow_percent->hasFocus()) m_pow_percent->setValue(display_percent);
        }
    }
    if (info.payout_address_available || !info.payout_address.empty()) {
        m_pow_payout->setText(QString::fromStdString(info.payout_address));
    }

    m_goldrush_badge->setText(info.epoch_active
        ? tr("Gold Rush: ACTIVE (%1 blocks remaining)").arg(info.blocks_remaining)
        : tr("Gold Rush: not active"));
    const QString last_pos_payout = info.pos_last_payout_height > 0
        ? QString::number(info.pos_last_payout_height)
        : tr("none yet");
    QString wallet_signal_text;
    if (info.wallet_active_signal) {
        wallet_signal_text = tr("wallet signal active");
    } else if (info.wallet_recent_solve_qualified) {
        wallet_signal_text = tr("wallet qualified, signal pending");
    } else if (info.wallet_whitelisted_scripts > 0) {
        wallet_signal_text = tr("wallet whitelisted, waiting for solve");
    } else {
        wallet_signal_text = tr("wallet not whitelisted");
    }
    QString pos_goldrush_text = info.epoch_active
        ? tr("PoS Gold Rush jackpot: %1 next qualified payout pool (%2 accrued)   |   Active signalers: %3   |   Estimated split: %4   |   Last PoS payout: %5")
              .arg(formatBLK(info.pos_next_payout_pool))
              .arg(formatBLK(info.pos_accrued_jackpot))
              .arg(QString::number(info.pos_active_signalers))
              .arg(formatBLK(info.pos_estimated_payout_per_signaler))
              .arg(last_pos_payout)
        : tr("PoS Gold Rush jackpot: %1 accrued; Gold Rush is not active.")
              .arg(formatBLK(info.pos_accrued_jackpot));
    if (info.epoch_active && !normal_signing_available) {
        pos_goldrush_text += tr("   |   Unlock Quantum and Legacy Staking to broadcast QQSIGNAL.");
    }
    pos_goldrush_text += tr("   |   This wallet: %1.").arg(wallet_signal_text);
    m_pos_goldrush_status->setText(pos_goldrush_text);

    if (m_pow_apply_pending) {
        m_pow_status->setText(m_pow_pending_enabled ? tr("Starting Gold Rush PoW mining...") : tr("Stopping Gold Rush PoW mining..."));
    } else if (m_pow_settings_dirty && info.enabled) {
        m_pow_status->setText(tr("PoW miner settings changed. Click Apply to update the miner."));
    } else if (info.enabled && info.epoch_active) {
        m_pow_status->setText(tr("Hashrate: %1 tries/s   |   Next claim payout: %2   |   Claims submitted: %3")
            .arg(QString::number(info.hashrate, 'f', 1))
            .arg(formatBLK(info.next_claim_payout))
            .arg(QString::number(static_cast<qlonglong>(info.claims_submitted))));
    } else if (info.enabled) {
        m_pow_status->setText(tr("PoW mining is enabled and idle until the Gold Rush epoch is active."));
    } else if (info.epoch_active) {
        m_pow_status->setText(tr("PoW mining is off. Enable it to compete for the next claim payout: %1.")
            .arg(formatBLK(info.next_claim_payout)));
    } else {
        m_pow_status->setText(tr("PoW mining is off; Gold Rush epoch is not active."));
    }

    if (!full_refresh) {
        refreshControlsEnabled();
        m_updating = false;
        return;
    }

    // Quantum migration and advanced wallet tables are relatively expensive, so refresh
    // them on the slower full-refresh cadence instead of every status tick.
    const interfaces::WalletMigrationStatus migration = w.getMigrationStatus();
    if (migration.available) {
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
        const CAmount direct_delegation_balance = migration.direct_quantum_amount;
        m_coldstake_fund_available = direct_delegation_balance > 0;
        const QString staked_note = migration.staked_quantum_amount > 0
            ? tr(" %1 is already bonded or delegated for staking.")
                  .arg(formatBLK(migration.staked_quantum_amount))
            : QString();
        if (migration.goldrush_reward_amount_needing_move > 0) {
            m_coldstake_quantum_available->setText(tr("%1 total quantum wallet balance. %2 direct quantum available for delegation. %3 Gold Rush rewards need a fresh quantum migration before cold staking; Delegate coins will move them first when quantum spending is active.%4")
                .arg(formatBLK(balances.quantum_balance))
                .arg(formatBLK(direct_delegation_balance))
                .arg(formatBLK(migration.goldrush_reward_amount_needing_move))
                .arg(staked_note));
        } else {
            m_coldstake_quantum_available->setText(tr("%1 total quantum wallet balance. %2 direct quantum available for delegation.%3")
                .arg(formatBLK(balances.quantum_balance))
                .arg(formatBLK(direct_delegation_balance))
                .arg(staked_note));
        }
        m_migration_advice->setText(QString::fromStdString(migration.advice));
    } else {
        m_migration_advice->setText(tr("Wallet is busy; migration status will refresh shortly."));
        m_coldstake_quantum_available->setText(tr("Wallet is busy; quantum balance will refresh shortly."));
    }

    const interfaces::WalletDemurrageInfo demurrage = w.getDemurrageInfo();
    if (demurrage.available) {
        m_demurrage_status->setText(demurrage.demurrage_active
            ? tr("Demurrage active at evaluation height %1. Outputs due for attestation: %2.")
                  .arg(demurrage.evaluation_height)
                  .arg(demurrage.attestation_due_outputs)
            : tr("Demurrage inactive. Evaluation height %1; direct quantum outputs monitored: %2.")
                  .arg(demurrage.evaluation_height)
                  .arg(demurrage.quantum_outputs));
        m_demurrage_amounts->setText(tr("Nominal %1   |   Effective %2   |   Burned if spent %3   |   Decaying %4   |   Locked %5")
            .arg(formatBLK(demurrage.nominal_amount))
            .arg(formatBLK(demurrage.effective_amount))
            .arg(formatBLK(demurrage.burned_if_spent_amount))
            .arg(demurrage.decaying_outputs)
            .arg(demurrage.locked_outputs));
        m_demurrage_guards->setText(tr("Height guard: %1   |   Post-migration guard: %2")
            .arg(demurrage.demurrage_height_guard_satisfied ? tr("yes") : tr("no"))
            .arg(demurrage.demurrage_post_migration_guard_satisfied ? tr("yes") : tr("no")));
    } else {
        m_demurrage_status->setText(tr("Demurrage status is busy; it will refresh shortly."));
        m_demurrage_amounts->setText(QStringLiteral("-"));
        m_demurrage_guards->setText(QStringLiteral("-"));
    }

    const std::vector<interfaces::WalletRGBAssetInfo> rgb_assets = w.listRGBAssets(/*include_spent=*/false);
    {
        QSignalBlocker rgb_blocker(m_rgb_assets);
        m_rgb_assets->setRowCount(static_cast<int>(rgb_assets.size()));
        for (int row = 0; row < static_cast<int>(rgb_assets.size()); ++row) {
            const interfaces::WalletRGBAssetInfo& asset = rgb_assets.at(row);
            const QString contract_id = QString::fromStdString(asset.contract_id);
            m_rgb_assets->setItem(row, 0, readOnlyItem(QString::fromStdString(asset.ticker.empty() ? asset.name : asset.ticker)));
            m_rgb_assets->setItem(row, 1, readOnlyItem(formatAssetAmount(asset.balance)));
            m_rgb_assets->setItem(row, 2, readOnlyItem(formatAssetAmount(asset.total_supply)));
            m_rgb_assets->setItem(row, 3, readOnlyItem(QString::number(static_cast<int>(asset.assignments.size()))));
            auto* contract_item = readOnlyItem(shortenHex(asset.contract_id));
            contract_item->setData(Qt::UserRole, contract_id);
            contract_item->setToolTip(contract_id);
            m_rgb_assets->setItem(row, 4, contract_item);
        }
    }
    m_rgb_status->setText(rgb_assets.empty()
        ? tr("No RGB assets are stored in this wallet yet. Use the RPC console for validated consignment import/export until the guided transfer workflow is complete.")
        : tr("%1 RGB asset(s) loaded. Consignment import/export and transfer construction remain advanced console workflows.")
              .arg(static_cast<int>(rgb_assets.size())));

    const std::vector<interfaces::WalletEUTXOStateInfo> eutxo_states = w.listEUTXOStates(/*include_spent=*/true);
    {
        QSignalBlocker eutxo_blocker(m_eutxo_states);
        m_eutxo_states->setRowCount(static_cast<int>(eutxo_states.size()));
        for (int row = 0; row < static_cast<int>(eutxo_states.size()); ++row) {
            const interfaces::WalletEUTXOStateInfo& state = eutxo_states.at(row);
            const QString outpoint = QString::fromStdString(state.txid) + QStringLiteral(":") + QString::number(state.vout);
            auto* outpoint_item = readOnlyItem(shortenHex(outpoint.toStdString()));
            outpoint_item->setToolTip(outpoint);
            m_eutxo_states->setItem(row, 0, outpoint_item);
            m_eutxo_states->setItem(row, 1, readOnlyItem(formatBLK(state.amount)));
            m_eutxo_states->setItem(row, 2, readOnlyItem(state.spent ? tr("yes") : tr("no")));
            auto* datum_item = readOnlyItem(shortenHex(state.datum_hex));
            datum_item->setToolTip(QString::fromStdString(state.datum_hex));
            m_eutxo_states->setItem(row, 3, datum_item);
            auto* validator_item = readOnlyItem(shortenHex(state.validator_hex));
            validator_item->setToolTip(QString::fromStdString(state.validator_hex));
            m_eutxo_states->setItem(row, 4, validator_item);
        }
    }
    m_eutxo_status->setText(eutxo_states.empty()
        ? tr("No EUTXO state metadata is stored in this wallet yet.")
        : tr("%1 EUTXO state record(s) loaded. Use the RPC console for create/verify transition tooling until the guided EUTXO workflow is complete.")
              .arg(static_cast<int>(eutxo_states.size())));

    const std::vector<interfaces::WalletQuantumAddressInfo> quantum_addresses = w.listQuantumAddresses();
    const std::vector<interfaces::WalletQuantumColdStakeInfo> coldstake_delegations = w.listQuantumColdStakeDelegations();
    m_quantum_address_count->setText(QString::number(static_cast<int>(quantum_addresses.size())));
    m_coldstake_count->setText(QString::number(static_cast<int>(coldstake_delegations.size())));

    const QString previous_selfstake = m_selfstake_address->text();
    const QString previous_selfstake_output = m_selfstake_output_selector->currentData().toString();
    const QString previous_operator = m_operator_address->text();
    const QString previous_coldstake = m_coldstake_address->text();
    int saved_selfstake_count{0};
    int saved_operator_count{0};
    int saved_coldstake_count{0};
    {
        QSignalBlocker selfstake_blocker(m_selfstake_selector);
        m_selfstake_selector->clear();
        m_selfstake_selector->addItem(tr("Select saved staking address"), QString());
        for (const interfaces::WalletQuantumAddressInfo& info : quantum_addresses) {
            const QString address = QString::fromStdString(info.address);
            if (!info.tiered || info.label == "coldstake-operator" || !isBondedTieredStakingAddress(address)) continue;
            m_selfstake_selector->addItem(addressSelectorLabel(info.label, info.address, info.unbonding_blocks), address);
            ++saved_selfstake_count;
        }
        if (saved_selfstake_count == 0) {
            m_selfstake_selector->clear();
            m_selfstake_selector->addItem(tr("No saved staking addresses"), QString());
        } else if (!previous_selfstake.isEmpty()) {
            const int selected = m_selfstake_selector->findData(previous_selfstake);
            if (selected >= 0) m_selfstake_selector->setCurrentIndex(selected);
        } else {
            m_selfstake_selector->setCurrentIndex(m_selfstake_selector->count() - 1);
            m_selfstake_address->setText(m_selfstake_selector->currentData().toString());
        }
    }
    {
        QSignalBlocker operator_blocker(m_operator_selector);
        m_operator_selector->clear();
        m_operator_selector->addItem(tr("Select saved operator key"), QString());
        for (const interfaces::WalletQuantumAddressInfo& info : quantum_addresses) {
            const QString address = QString::fromStdString(info.address);
            if (!info.tiered || info.label != "coldstake-operator" ||
                info.unbonding_blocks != OPERATOR_COMMITMENT_BLOCKS ||
                !isBondedTieredStakingAddress(address)) {
                continue;
            }
            m_operator_selector->addItem(addressSelectorLabel(info.label, info.address, /*lock_blocks=*/0), address);
            m_operator_selector->setItemData(m_operator_selector->count() - 1, QString::fromStdString(info.public_key), Qt::UserRole + 1);
            ++saved_operator_count;
        }
        if (saved_operator_count == 0) {
            m_operator_selector->clear();
            m_operator_selector->addItem(tr("No saved operator keys"), QString());
        } else if (!previous_operator.isEmpty()) {
            const int selected = m_operator_selector->findData(previous_operator);
            if (selected >= 0) m_operator_selector->setCurrentIndex(selected);
        } else {
            m_operator_selector->setCurrentIndex(m_operator_selector->count() - 1);
            m_operator_address->setText(m_operator_selector->currentData().toString());
            m_operator_pubkey->setText(m_operator_selector->currentData(Qt::UserRole + 1).toString());
        }
    }
    {
        QSignalBlocker coldstake_blocker(m_coldstake_existing_selector);
        m_coldstake_existing_selector->clear();
        m_coldstake_existing_selector->addItem(tr("Select saved delegation address"), QString());
        for (const interfaces::WalletQuantumColdStakeInfo& info : coldstake_delegations) {
            m_coldstake_existing_selector->addItem(addressSelectorLabel(info.label, info.address, info.unbonding_blocks), QString::fromStdString(info.address));
            ++saved_coldstake_count;
        }
        if (saved_coldstake_count == 0) {
            m_coldstake_existing_selector->clear();
            m_coldstake_existing_selector->addItem(tr("No saved delegation addresses"), QString());
        } else if (!previous_coldstake.isEmpty()) {
            const int selected = m_coldstake_existing_selector->findData(previous_coldstake);
            if (selected >= 0) m_coldstake_existing_selector->setCurrentIndex(selected);
        } else {
            m_coldstake_existing_selector->setCurrentIndex(m_coldstake_existing_selector->count() - 1);
            m_coldstake_address->setText(m_coldstake_existing_selector->currentData().toString());
        }
    }

    if (m_quantum_address->text().isEmpty() && !quantum_addresses.empty()) {
        m_quantum_address->setText(QString::fromStdString(quantum_addresses.back().address));
        m_quantum_pubkey->setText(QString::fromStdString(quantum_addresses.back().public_key));
    }
    if (m_selfstake_address->text().isEmpty()) {
        const auto selfstake_it = std::find_if(quantum_addresses.begin(), quantum_addresses.end(), [](const interfaces::WalletQuantumAddressInfo& info) {
            return info.tiered && info.label == "quantum-stake";
        });
        if (selfstake_it != quantum_addresses.end()) {
            m_selfstake_address->setText(QString::fromStdString(selfstake_it->address));
            m_selfstake_status->setText(tr("Tiered staking address ready with %1 bonded blocks.").arg(selfstake_it->unbonding_blocks));
        }
    }

    std::vector<interfaces::WalletQuantumStakeOutputInfo> selfstake_outputs;
    if (!m_selfstake_address->text().isEmpty()) {
        selfstake_outputs = w.listQuantumStakeOutputs(m_selfstake_address->text().toStdString());
    }
    {
        QSignalBlocker output_blocker(m_selfstake_output_selector);
        m_selfstake_output_selector->clear();
        if (selfstake_outputs.empty()) {
            m_selfstake_output_selector->addItem(tr("No staking outputs for this address"), QString());
        } else {
            m_selfstake_output_selector->addItem(tr("All active / withdrawable outputs"), QString());
            for (const interfaces::WalletQuantumStakeOutputInfo& output : selfstake_outputs) {
                m_selfstake_output_selector->addItem(outputSelectorLabel(output), outputSelectorKey(output.txid, output.vout));
            }
            if (!previous_selfstake_output.isEmpty()) {
                const int selected = m_selfstake_output_selector->findData(previous_selfstake_output);
                if (selected >= 0) m_selfstake_output_selector->setCurrentIndex(selected);
            }
        }
    }

    if (!m_selfstake_address->text().isEmpty()) {
        const uint16_t lock_blocks = stakingAddressLockBlocks(m_selfstake_address->text());
        const interfaces::WalletQuantumOperatorBondInfo stake_info =
            w.getQuantumStakeAddressBondInfo(m_selfstake_address->text().toStdString());
        if (stake_info.valid_operator_address) {
            if (stake_info.bonded_outputs > 0) {
                m_selfstake_withdraw_available = true;
                m_selfstake_status->setText(tr("Quantum staking active: %1 across %2 output(s). Lock period: %3 blocks. Stop/withdraw starts this address's unbonding period.")
                    .arg(formatBLK(stake_info.bonded_amount))
                    .arg(stake_info.bonded_outputs)
                    .arg(lock_blocks));
                m_selfstake_withdraw->setText(tr("Start withdrawal"));
            } else if (stake_info.withdrawable_outputs > 0) {
                m_selfstake_status->setText(tr("Quantum staking funds are unbonded and withdrawable: %1 across %2 output(s).")
                    .arg(formatBLK(stake_info.withdrawable_amount))
                    .arg(stake_info.withdrawable_outputs));
                m_selfstake_withdraw->setText(tr("Complete withdrawal"));
                m_selfstake_withdraw_available = true;
            } else if (stake_info.unbonding_outputs > 0) {
                m_selfstake_status->setText(tr("Quantum staking funds are unbonding: %1 across %2 output(s). Next unlock height: %3.")
                    .arg(formatBLK(stake_info.unbonding_amount))
                    .arg(stake_info.unbonding_outputs)
                    .arg(stake_info.next_unlock_height));
                m_selfstake_withdraw->setText(tr("Withdrawal pending"));
            } else {
                m_selfstake_status->setText(tr("Quantum staking address ready with %1 bonded blocks. Click Activate staking to fund and start using it.")
                    .arg(lock_blocks));
                m_selfstake_withdraw->setText(tr("Stop staking"));
            }
        }
    } else {
        m_selfstake_withdraw->setText(tr("Stop staking"));
        m_selfstake_last_action_status.clear();
    }
    if (!m_selfstake_last_action_status.isEmpty() &&
        !m_selfstake_status->text().startsWith(m_selfstake_last_action_status)) {
        m_selfstake_status->setText(m_selfstake_last_action_status + QStringLiteral("\n") + m_selfstake_status->text());
    }
    bool local_bonded_operator = false;
    if (m_operator_pubkey->text().isEmpty()) {
        const auto operator_it = std::find_if(quantum_addresses.begin(), quantum_addresses.end(), [](const interfaces::WalletQuantumAddressInfo& info) {
            return info.tiered && info.label == "coldstake-operator" && info.unbonding_blocks == OPERATOR_COMMITMENT_BLOCKS;
        });
        if (operator_it != quantum_addresses.end()) {
            m_operator_address->setText(QString::fromStdString(operator_it->address));
            m_operator_pubkey->setText(QString::fromStdString(operator_it->public_key));
        } else {
            m_operator_status->setText(tr("No operator key selected. Operators must fund a 30-day bonded staking address before delegators can verify them."));
        }
    }
    if (!m_operator_address->text().isEmpty()) {
        const interfaces::WalletQuantumOperatorBondInfo bond_info =
            w.getQuantumOperatorBondInfo(m_operator_address->text().toStdString());
        if (bond_info.valid_operator_address) {
            if (bond_info.bonded_outputs > 0) {
                local_bonded_operator = true;
                m_operator_withdraw_available = true;
                m_operator_status->setText(tr("Operator bond active: %1 across %2 output(s). Delegators can verify this operator. Stop/withdraw starts the 30-day unbonding period.")
                    .arg(formatBLK(bond_info.bonded_amount))
                    .arg(bond_info.bonded_outputs));
                m_operator_withdraw->setText(tr("Start withdrawal"));
            } else if (bond_info.withdrawable_outputs > 0) {
                m_operator_status->setText(tr("Operator bond is unbonded and withdrawable: %1 across %2 output(s).")
                    .arg(formatBLK(bond_info.withdrawable_amount))
                    .arg(bond_info.withdrawable_outputs));
                m_operator_withdraw->setText(tr("Complete withdrawal"));
                m_operator_withdraw_available = true;
            } else if (bond_info.unbonding_outputs > 0) {
                m_operator_status->setText(tr("Operator bond is unbonding: %1 across %2 output(s). Next unlock height: %3.")
                    .arg(formatBLK(bond_info.unbonding_amount))
                    .arg(bond_info.unbonding_outputs)
                    .arg(bond_info.next_unlock_height));
                m_operator_withdraw->setText(tr("Withdrawal pending"));
            } else {
                m_operator_status->setText(tr("30-day operator bond key ready. Click Activate operator to create and sign the funding transaction. It becomes available after normal confirmations."));
                m_operator_withdraw->setText(tr("Stop operator"));
            }
        }
    } else {
        m_operator_withdraw->setText(tr("Stop operator"));
        m_operator_last_action_status.clear();
    }
    if (!m_operator_last_action_status.isEmpty() &&
        !m_operator_status->text().startsWith(m_operator_last_action_status)) {
        m_operator_status->setText(m_operator_last_action_status + QStringLiteral("\n") + m_operator_status->text());
    }
    if (m_coldstake_address->text().isEmpty() && !coldstake_delegations.empty()) {
        m_coldstake_address->setText(QString::fromStdString(coldstake_delegations.back().address));
    }
    CAmount wallet_delegated_amount{0};
    int wallet_delegated_outputs{0};
    CAmount selected_operator_delegated_amount{0};
    int selected_operator_delegation_count{0};
    const QString selected_operator_hash = selectedColdStakeOperatorHash();
    for (const interfaces::WalletQuantumColdStakeInfo& info : coldstake_delegations) {
        const interfaces::WalletQuantumColdStakeBalanceInfo balance =
            w.getQuantumColdStakeBalanceInfo(info.address);
        wallet_delegated_amount += balance.amount;
        wallet_delegated_outputs += balance.outputs;
        if (!selected_operator_hash.isEmpty() &&
            QString::fromStdString(info.staking_pubkey_hash) == selected_operator_hash) {
            selected_operator_delegated_amount += balance.amount;
            if (balance.outputs > 0) ++selected_operator_delegation_count;
        }
    }
    const QString selected_operator_label = selectedColdStakeOperatorPubKey().isEmpty()
        ? tr("none")
        : shortenHex(selectedColdStakeOperatorPubKey().toStdString());
    m_coldstake_selection_summary->setText(selected_operator_hash.isEmpty()
        ? tr("Selected operator: %1. Your delegations: %2 across %3 output(s).")
              .arg(selected_operator_label)
              .arg(formatBLK(wallet_delegated_amount))
              .arg(wallet_delegated_outputs)
        : tr("Selected operator: %1. Your delegations: %2 across %3 output(s); %4 to this operator across %5 delegation(s).")
              .arg(selected_operator_label)
              .arg(formatBLK(wallet_delegated_amount))
              .arg(wallet_delegated_outputs)
              .arg(formatBLK(selected_operator_delegated_amount))
              .arg(selected_operator_delegation_count));
    if (!m_coldstake_address->text().isEmpty()) {
        const interfaces::WalletQuantumColdStakeBalanceInfo delegation_info =
            w.getQuantumColdStakeBalanceInfo(m_coldstake_address->text().toStdString());
        if (delegation_info.valid_delegation_address) {
            if (delegation_info.spendable_outputs > 0) {
                m_coldstake_withdraw_available = true;
                m_coldstake_status->setText(tr("Delegation active: %1 spendable across %2 output(s). The selected operator can stake these coins; this wallet keeps the owner key.")
                    .arg(formatBLK(delegation_info.spendable_amount))
                    .arg(delegation_info.spendable_outputs));
            } else if (delegation_info.outputs > 0) {
                m_coldstake_status->setText(tr("Delegation funding is visible but not spendable yet: %1 across %2 output(s). Wait for confirmation before staking or withdrawing.")
                    .arg(formatBLK(delegation_info.amount))
                    .arg(delegation_info.outputs));
            } else {
                m_coldstake_status->setText(tr("Delegation address ready. Enter an amount and click Delegate coins to move spendable quantum coins under this operator."));
            }
        } else {
            m_coldstake_status->setText(tr("Selected delegation address is not backed by this wallet."));
        }
    } else {
        m_coldstake_last_action_status.clear();
        m_coldstake_status->setText(tr("Create or select a delegation address, then delegate quantum coins."));
    }
    if (!m_coldstake_last_action_status.isEmpty() &&
        !m_coldstake_status->text().startsWith(m_coldstake_last_action_status)) {
        m_coldstake_status->setText(m_coldstake_last_action_status + QStringLiteral("\n") + m_coldstake_status->text());
    }

    ++m_operator_registry_refresh_seconds;
    const bool registry_empty = m_operator_registry && m_operator_registry->rowCount() == 0;
    const bool should_refresh_registry =
        !m_operator_registry_loaded ||
        (local_bonded_operator && registry_empty && m_operator_registry_refresh_seconds >= 10) ||
        m_operator_registry_refresh_seconds >= 60;
    if (should_refresh_registry) {
        refreshOperatorRegistry();
    } else {
        refreshControlsEnabled();
    }
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
    m_pow_settings_dirty = false;
    m_pow_payout->clear();
    m_pow_status->setText(tr("Load a wallet to use Gold Rush PoW mining."));

    m_migration_phase->setText(QStringLiteral("-"));
    m_migration_deadline->setText(QStringLiteral("-"));
    m_migration_legacy_amount->setText(QStringLiteral("-"));
    m_migration_quantum_amount->setText(QStringLiteral("-"));
    m_migration_goldrush_amount->setText(QStringLiteral("-"));
    m_migration_advice->setText(tr("Load a wallet to view migration status."));
    m_migration_action_status->setText(QStringLiteral("-"));
    m_coldstake_quantum_available->setText(QStringLiteral("-"));
    m_demurrage_status->setText(tr("Load a wallet to view demurrage status."));
    m_demurrage_amounts->setText(QStringLiteral("-"));
    m_demurrage_guards->setText(QStringLiteral("-"));
    m_rgb_assets->setRowCount(0);
    m_rgb_status->setText(tr("Load a wallet to view RGB assets."));
    m_eutxo_states->setRowCount(0);
    m_eutxo_status->setText(tr("Load a wallet to view EUTXO states."));
    m_quantum_address_count->setText(QStringLiteral("0"));
    m_coldstake_count->setText(QStringLiteral("0"));
    m_quantum_address->clear();
    m_quantum_pubkey->clear();
    m_selfstake_address->clear();
    {
        QSignalBlocker selfstake_selector_blocker(m_selfstake_selector);
        m_selfstake_selector->clear();
        m_selfstake_selector->addItem(tr("Load a wallet to select a staking address"), QString());
    }
    {
        QSignalBlocker output_selector_blocker(m_selfstake_output_selector);
        m_selfstake_output_selector->clear();
        m_selfstake_output_selector->addItem(tr("Load a wallet to select staking outputs"), QString());
    }
    if (m_selfstake_fund_amount) m_selfstake_fund_amount->setValue(COIN);
    m_selfstake_last_action_status.clear();
    m_selfstake_status->setText(QStringLiteral("-"));
    m_selfstake_withdraw->setText(tr("Stop staking"));
    m_operator_address->clear();
    m_operator_pubkey->clear();
    {
        QSignalBlocker operator_selector_blocker(m_operator_selector);
        m_operator_selector->clear();
        m_operator_selector->addItem(tr("Load a wallet to select an operator key"), QString());
    }
    if (m_operator_bond_amount) m_operator_bond_amount->setValue(COIN);
    m_operator_last_action_status.clear();
    m_operator_status->setText(tr("No operator key selected. Operators must fund a 30-day bonded staking address before delegators can verify them."));
    m_operator_withdraw->setText(tr("Stop operator"));
    m_operator_registry->setRowCount(0);
    m_operator_registry_status->setText(tr("Load a wallet to view cold-staking operators."));
    {
        QSignalBlocker selector_blocker(m_coldstake_operator_selector);
        m_coldstake_operator_selector->clear();
        m_coldstake_operator_selector->addItem(tr("Load a wallet to select a cold-staking operator"), QString());
    }
    {
        QSignalBlocker delegation_selector_blocker(m_coldstake_existing_selector);
        m_coldstake_existing_selector->clear();
        m_coldstake_existing_selector->addItem(tr("Load a wallet to select a delegation address"), QString());
    }
    if (m_coldstake_fund_amount) m_coldstake_fund_amount->setValue(COIN);
    m_coldstake_last_action_status.clear();
    m_coldstake_address->clear();
    m_coldstake_selection_summary->setText(QStringLiteral("-"));
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
    m_migration_legacy_sweep->setEnabled(can_create_quantum);
    m_migration_goldrush_sweep->setEnabled(can_create_quantum);
    m_demurrage_attest->setEnabled(can_create_quantum && m_quantum_address && !m_quantum_address->text().isEmpty());
    m_rgb_copy_contract->setEnabled(has_wallet && m_rgb_assets && !m_rgb_assets->selectedItems().empty());
    m_selfstake_lock_period->setEnabled(can_create_quantum);
    m_selfstake_selector->setEnabled(has_wallet && m_selfstake_selector->count() > 1);
    m_selfstake_new->setEnabled(can_create_quantum);
    m_selfstake_copy->setEnabled(m_selfstake_address && !m_selfstake_address->text().isEmpty());
    m_selfstake_output_selector->setEnabled(has_wallet && m_selfstake_output_selector->count() > 1);
    const bool has_selfstake_address = m_selfstake_address && !m_selfstake_address->text().isEmpty();
    m_selfstake_fund_amount->setEnabled(can_create_quantum && has_selfstake_address);
    m_selfstake_fund->setEnabled(can_create_quantum && has_selfstake_address);
    m_selfstake_withdraw->setEnabled(can_create_quantum && has_selfstake_address && m_selfstake_withdraw_available);
    m_operator_new->setEnabled(can_create_quantum);
    m_operator_selector->setEnabled(has_wallet && m_operator_selector->count() > 1);
    m_operator_copy->setEnabled(m_operator_pubkey && !m_operator_pubkey->text().isEmpty());
    m_operator_use_for_delegation->setEnabled(m_operator_pubkey && !m_operator_pubkey->text().isEmpty());
    const bool has_operator_address = m_operator_address && !m_operator_address->text().isEmpty();
    m_operator_bond_amount->setEnabled(can_create_quantum && has_operator_address);
    m_operator_fund->setEnabled(can_create_quantum && has_operator_address);
    m_operator_withdraw->setEnabled(can_create_quantum && has_operator_address && m_operator_withdraw_available);
    m_operator_registry_refresh->setEnabled(has_wallet);
    bool registry_selection_has_pubkey{false};
    if (m_operator_registry && !m_operator_registry->selectedItems().empty()) {
        const int row = m_operator_registry->selectedItems().front()->row();
        QTableWidgetItem* operator_item = m_operator_registry->item(row, 0);
        registry_selection_has_pubkey = operator_item && !operator_item->data(Qt::UserRole).toString().isEmpty();
    }
    m_operator_registry_use->setEnabled(has_wallet && registry_selection_has_pubkey);
    m_coldstake_operator_selector->setEnabled(can_create_quantum && !selectedColdStakeOperatorPubKey().isEmpty());
    m_coldstake_existing_selector->setEnabled(has_wallet && m_coldstake_existing_selector->count() > 1);
    m_coldstake_lock_period->setEnabled(can_create_quantum);
    m_coldstake_new->setEnabled(can_create_quantum && !selectedColdStakeOperatorPubKey().isEmpty());
    m_coldstake_copy->setEnabled(m_coldstake_address && !m_coldstake_address->text().isEmpty());
    const bool has_coldstake_address = m_coldstake_address && !m_coldstake_address->text().isEmpty();
    m_coldstake_fund_amount->setEnabled(can_create_quantum && has_coldstake_address);
    m_coldstake_fund->setEnabled(can_create_quantum && has_coldstake_address && m_coldstake_fund_available);
    m_coldstake_withdraw->setEnabled(can_create_quantum && has_coldstake_address && m_coldstake_withdraw_available);
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

QString StakingMiningPage::selectedColdStakeOperatorPubKey() const
{
    if (!m_coldstake_operator_selector) return {};
    return m_coldstake_operator_selector->currentData().toString().trimmed();
}

QString StakingMiningPage::selectedColdStakeOperatorHash() const
{
    if (!m_coldstake_operator_selector) return {};
    return m_coldstake_operator_selector->itemData(m_coldstake_operator_selector->currentIndex(), Qt::UserRole + 1).toString().trimmed();
}

void StakingMiningPage::setColdStakeOperatorSelection(const QString& pubkey, const QString& label)
{
    if (!m_coldstake_operator_selector || pubkey.trimmed().isEmpty()) return;

    const QString clean_pubkey = pubkey.trimmed();
    int index = m_coldstake_operator_selector->findData(clean_pubkey);
    if (index < 0) {
        if (m_coldstake_operator_selector->count() == 1 &&
            m_coldstake_operator_selector->itemData(0).toString().isEmpty()) {
            m_coldstake_operator_selector->clear();
        }
        const QString display = label.trimmed().isEmpty()
            ? shortenHex(clean_pubkey.toStdString())
            : label.trimmed();
        m_coldstake_operator_selector->addItem(display, clean_pubkey);
        index = m_coldstake_operator_selector->count() - 1;
    }
    m_coldstake_operator_selector->setCurrentIndex(index);
    refreshControlsEnabled();
}
