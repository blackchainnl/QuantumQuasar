// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/accountpage.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>
#include <qt/quantumguides.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <limits>

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTextBrowser>
#include <QTextStream>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

namespace {

QString formatBLK(CAmount amount, bool plus = false)
{
    return BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, amount, plus, BitcoinUnits::SeparatorStyle::ALWAYS);
}

QLabel* makeCard(const QString& text, QWidget* parent)
{
    auto* label = new QLabel(text, parent);
    label->setWordWrap(true);
    label->setTextFormat(Qt::RichText);
    label->setMinimumHeight(78);
    label->setStyleSheet(QStringLiteral(
        "QLabel { background: #ffffff; border: 1px solid #cfd8e3; border-radius: 6px; padding: 10px; }"
        "QLabel[attention=\"true\"] { background: #fff7e6; border-color: #d8a441; }"));
    return label;
}

QString classifyOutput(const CTxDestination& dest, const CScript& script)
{
    if (IsQuantumColdStakeDestination(dest) || IsQuantumColdStakeScript(script)) return QObject::tr("Cold stake");
    if (IsEUTXOScript(script)) return QObject::tr("EUTXO");
    if (IsQuantumMigrationDestination(dest) || IsQuantumMigrationScript(script)) return QObject::tr("Quantum");
    if (IsValidDestination(dest)) return QObject::tr("Legacy");
    return QObject::tr("Other");
}

QString outputStatus(const interfaces::WalletTxOut& out)
{
    if (out.is_spent) return QObject::tr("spent");
    if (out.depth_in_main_chain < 0) return QObject::tr("conflicted");
    if (out.depth_in_main_chain == 0) return QObject::tr("unconfirmed");
    return QObject::tr("confirmed");
}

QString minDepthText(int min_depth)
{
    if (min_depth < 0) return QObject::tr("conflicted");
    return QString::number(min_depth);
}

QString addressNote(const QString& family)
{
    if (family == QObject::tr("Legacy")) return QObject::tr("Legacy spend path. Use for current-chain fees, sends, and legacy staking.");
    if (family == QObject::tr("Quantum")) return QObject::tr("Direct quantum spend path. Gold Rush rewards may require one fresh move before normal use.");
    if (family == QObject::tr("Cold stake")) return QObject::tr("Cold-stake contract path. Owner and staker authority are separated.");
    if (family == QObject::tr("EUTXO")) return QObject::tr("Extended UTXO state. Do not spend as ordinary BLK unless a guided workflow says to.");
    return QObject::tr("Nonstandard or wallet-internal script group.");
}

} // namespace

AccountPage::AccountPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_timer(new QTimer(this))
{
    Q_UNUSED(platformStyle);
    setupUi();
    connect(m_timer, &QTimer::timeout, this, &AccountPage::refresh);
    m_timer->setInterval(12000);
}

void AccountPage::setupUi()
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(16, 16, 16, 16);
    outer->setSpacing(10);

    auto* top = new QHBoxLayout();
    auto* title = new QLabel(tr("<b>Account detail</b><br>Inspect where this wallet's coins are, which addresses hold them, and which outputs need migration or staking attention."), this);
    title->setTextFormat(Qt::RichText);
    title->setWordWrap(true);
    top->addWidget(title, 1);
    m_guide = new QPushButton(tr("Guide"), this);
    m_guide->setToolTip(tr("Open a detailed guide for reading account balances and address-level coins."));
    top->addWidget(m_guide);
    outer->addLayout(top);

    auto* cards = new QGridLayout();
    cards->setHorizontalSpacing(8);
    cards->setVerticalSpacing(8);
    m_total_card = makeCard(tr("Wallet totals will appear here."), this);
    m_legacy_card = makeCard(tr("Legacy balance will appear here."), this);
    m_quantum_card = makeCard(tr("Quantum balance will appear here."), this);
    m_attention_card = makeCard(tr("Migration and staking attention items will appear here."), this);
    m_attention_card->setProperty("attention", true);
    cards->addWidget(m_total_card, 0, 0);
    cards->addWidget(m_legacy_card, 0, 1);
    cards->addWidget(m_quantum_card, 1, 0);
    cards->addWidget(m_attention_card, 1, 1);
    cards->setColumnStretch(0, 1);
    cards->setColumnStretch(1, 1);
    outer->addLayout(cards);

    auto* controls = new QHBoxLayout();
    m_family_filter = new QComboBox(this);
    m_family_filter->addItem(tr("All coin families"), QString());
    m_family_filter->addItem(tr("Legacy"), tr("Legacy"));
    m_family_filter->addItem(tr("Quantum"), tr("Quantum"));
    m_family_filter->addItem(tr("Cold stake"), tr("Cold stake"));
    m_family_filter->addItem(tr("EUTXO"), tr("EUTXO"));
    m_family_filter->addItem(tr("Other"), tr("Other"));
    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(tr("Search address, label, outpoint, or notes"));
    m_refresh = new QPushButton(tr("Refresh"), this);
    m_copy_address = new QPushButton(tr("Copy address"), this);
    m_copy_outpoint = new QPushButton(tr("Copy outpoint"), this);
    m_export = new QPushButton(tr("Export CSV"), this);
    controls->addWidget(m_family_filter);
    controls->addWidget(m_search, 1);
    controls->addWidget(m_refresh);
    controls->addWidget(m_copy_address);
    controls->addWidget(m_copy_outpoint);
    controls->addWidget(m_export);
    outer->addLayout(controls);

    m_tree = new QTreeWidget(this);
    m_tree->setObjectName(QStringLiteral("accountCoinTree"));
    m_tree->setColumnCount(ColumnCount);
    m_tree->setHeaderLabels(QStringList{
        tr("Type"), tr("Address / output"), tr("Label"), tr("Amount"), tr("Outputs"), tr("Conf."), tr("Status"), tr("Notes")});
    m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    m_tree->header()->setSectionResizeMode(Type, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Address, QHeaderView::Stretch);
    m_tree->header()->setSectionResizeMode(Label, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Amount, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Outputs, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Confirmations, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Status, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(Notes, QHeaderView::Stretch);
    outer->addWidget(m_tree, 1);

    m_status = new QLabel(tr("Load a wallet to inspect account details."), this);
    m_status->setWordWrap(true);
    outer->addWidget(m_status);

    connect(m_guide, &QPushButton::clicked, this, &AccountPage::showGuide);
    connect(m_refresh, &QPushButton::clicked, this, &AccountPage::refresh);
    connect(m_copy_address, &QPushButton::clicked, this, &AccountPage::copySelectedAddress);
    connect(m_copy_outpoint, &QPushButton::clicked, this, &AccountPage::copySelectedOutpoint);
    connect(m_export, &QPushButton::clicked, this, &AccountPage::exportCsv);
    connect(m_family_filter, qOverload<int>(&QComboBox::currentIndexChanged), this, &AccountPage::refresh);
    connect(m_search, &QLineEdit::textChanged, this, &AccountPage::refresh);
}

void AccountPage::setWalletModel(WalletModel* walletModel)
{
    if (m_wallet_model) {
        disconnect(m_wallet_model, nullptr, this, nullptr);
    }
    m_wallet_model = walletModel;
    if (m_wallet_model) {
        connect(m_wallet_model, &WalletModel::balanceChanged, this, &AccountPage::refresh);
        connect(m_wallet_model, &WalletModel::encryptionStatusChanged, this, &AccountPage::refresh);
        connect(m_wallet_model, &QObject::destroyed, this, [this] {
            m_wallet_model = nullptr;
            m_timer->stop();
            refresh();
        });
        m_timer->start();
    } else {
        m_timer->stop();
    }
    refresh();
}

void AccountPage::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    refresh();
}

bool AccountPage::rowMatchesFilter(const QString& family, const QString& address, const QString& label) const
{
    const QString selected_family = m_family_filter->currentData().toString();
    if (!selected_family.isEmpty() && family != selected_family) return false;

    const QString needle = m_search->text().trimmed();
    if (needle.isEmpty()) return true;
    return family.contains(needle, Qt::CaseInsensitive) ||
           address.contains(needle, Qt::CaseInsensitive) ||
           label.contains(needle, Qt::CaseInsensitive);
}

void AccountPage::refresh()
{
    if (m_privacy) {
        m_tree->clear();
        m_total_card->setText(tr("<b>Values hidden</b><br>Privacy mode is enabled."));
        m_legacy_card->setText(tr("<b>Legacy</b><br>Hidden"));
        m_quantum_card->setText(tr("<b>Quantum</b><br>Hidden"));
        m_attention_card->setText(tr("<b>Attention</b><br>Hidden"));
        m_status->setText(tr("Disable privacy mode to inspect account-level coins."));
        return;
    }

    if (!m_wallet_model) {
        m_tree->clear();
        m_total_card->setText(tr("Load a wallet to inspect account details."));
        m_legacy_card->setText(QStringLiteral("-"));
        m_quantum_card->setText(QStringLiteral("-"));
        m_attention_card->setText(QStringLiteral("-"));
        m_status->setText(tr("No wallet is loaded."));
        return;
    }

    interfaces::Wallet& wallet = m_wallet_model->wallet();
    const interfaces::WalletBalances balances = wallet.getBalances();
    const interfaces::WalletMigrationStatus migration = wallet.getMigrationStatus();
    const interfaces::WalletDemurrageInfo demurrage = wallet.getDemurrageInfo();
    const std::vector<interfaces::WalletRGBAssetInfo> rgb_assets = wallet.listRGBAssets(/*include_spent=*/false);
    const std::vector<interfaces::WalletEUTXOStateInfo> eutxo_states = wallet.listEUTXOStates(/*include_spent=*/true);
    const interfaces::Wallet::CoinsList coins = wallet.listCoins();

    m_total_card->setText(tr("<b>Total wallet balance</b><br>Available: %1<br>Pending: %2<br>Immature: %3")
        .arg(formatBLK(balances.balance))
        .arg(formatBLK(balances.unconfirmed_balance))
        .arg(formatBLK(balances.immature_balance)));
    m_legacy_card->setText(tr("<b>Legacy spend path</b><br>%1<br>Use for current-chain fees, legacy sends, and legacy staking.")
        .arg(formatBLK(balances.legacy_balance)));
    m_quantum_card->setText(tr("<b>Quantum spend path</b><br>%1<br>Use for migration, Gold Rush rewards, and quantum staking workflows.")
        .arg(formatBLK(balances.quantum_balance)));
    if (migration.available) {
        m_attention_card->setText(tr("<b>Attention</b><br>Legacy to migrate: %1<br>Gold Rush rewards to move: %2<br>Staked/delegated quantum: %3")
            .arg(formatBLK(migration.eligible_legacy_amount))
            .arg(formatBLK(migration.goldrush_reward_amount_needing_move))
            .arg(formatBLK(migration.staked_quantum_amount)));
    } else {
        m_attention_card->setText(tr("<b>Attention</b><br>Migration status is busy; refresh shortly."));
    }

    QSignalBlocker tree_blocker(m_tree);
    m_tree->clear();

    int visible_groups{0};
    int visible_outputs{0};
    CAmount visible_amount{0};
    for (const auto& entry : coins) {
        const CTxDestination& dest = entry.first;
        const QString address = QString::fromStdString(EncodeDestination(dest));
        std::string label_std;
        wallet.getAddress(dest, &label_std, /*is_mine=*/nullptr, /*purpose=*/nullptr);
        const QString label = QString::fromStdString(label_std);

        CAmount group_amount{0};
        int min_depth{std::numeric_limits<int>::max()};
        QString family = tr("Other");
        QString searchable = address + QStringLiteral(" ") + label;
        for (const auto& coin_tuple : entry.second) {
            const COutPoint& outpoint = std::get<0>(coin_tuple);
            const interfaces::WalletTxOut& out = std::get<1>(coin_tuple);
            group_amount += out.txout.nValue;
            min_depth = std::min(min_depth, out.depth_in_main_chain);
            const QString output_family = classifyOutput(dest, out.txout.scriptPubKey);
            if (family == tr("Other") || output_family != tr("Other")) family = output_family;
            searchable += QStringLiteral(" ") + QString::fromStdString(outpoint.ToString());
        }

        if (entry.second.empty()) continue;
        if (!rowMatchesFilter(family, searchable, label)) continue;

        auto* parent = new QTreeWidgetItem(m_tree);
        parent->setText(Type, family);
        parent->setText(Address, address.isEmpty() ? tr("(script without address)") : address);
        parent->setText(Label, label);
        parent->setText(Amount, formatBLK(group_amount));
        parent->setText(Outputs, QString::number(static_cast<int>(entry.second.size())));
        parent->setText(Confirmations, minDepthText(min_depth == std::numeric_limits<int>::max() ? 0 : min_depth));
        parent->setText(Status, min_depth <= 0 ? tr("needs confirmation") : tr("available"));
        parent->setText(Notes, addressNote(family));
        parent->setData(Address, Qt::UserRole, address);
        parent->setToolTip(Address, address);
        parent->setToolTip(Notes, parent->text(Notes));

        for (const auto& coin_tuple : entry.second) {
            const COutPoint& outpoint = std::get<0>(coin_tuple);
            const interfaces::WalletTxOut& out = std::get<1>(coin_tuple);
            const QString outpoint_text = QString::fromStdString(outpoint.ToString());
            auto* child = new QTreeWidgetItem(parent);
            child->setText(Type, classifyOutput(dest, out.txout.scriptPubKey));
            child->setText(Address, outpoint_text);
            child->setText(Label, label);
            child->setText(Amount, formatBLK(out.txout.nValue));
            child->setText(Outputs, tr("1"));
            child->setText(Confirmations, QString::number(out.depth_in_main_chain));
            child->setText(Status, outputStatus(out));
            child->setText(Notes, addressNote(child->text(Type)));
            child->setData(Address, Qt::UserRole, address);
            child->setData(Address, Qt::UserRole + 1, outpoint_text);
            child->setToolTip(Address, outpoint_text);
        }

        ++visible_groups;
        visible_outputs += static_cast<int>(entry.second.size());
        visible_amount += group_amount;
    }

    if (visible_groups <= 12) {
        m_tree->expandAll();
    } else {
        m_tree->expandToDepth(0);
    }

    m_status->setText(tr("%1 address group(s), %2 output(s), %3 visible after filters. RGB assets: %4. EUTXO state records: %5. Demurrage monitored outputs: %6.")
        .arg(visible_groups)
        .arg(visible_outputs)
        .arg(formatBLK(visible_amount))
        .arg(static_cast<int>(rgb_assets.size()))
        .arg(static_cast<int>(eutxo_states.size()))
        .arg(demurrage.available ? demurrage.quantum_outputs : 0));
}

void AccountPage::copySelectedAddress()
{
    const QList<QTreeWidgetItem*> selected = m_tree->selectedItems();
    if (selected.empty()) return;
    const QString address = selected.front()->data(Address, Qt::UserRole).toString();
    if (!address.isEmpty()) QApplication::clipboard()->setText(address);
}

void AccountPage::copySelectedOutpoint()
{
    const QList<QTreeWidgetItem*> selected = m_tree->selectedItems();
    if (selected.empty()) return;
    QString outpoint = selected.front()->data(Address, Qt::UserRole + 1).toString();
    if (outpoint.isEmpty()) outpoint = selected.front()->text(Address);
    if (!outpoint.isEmpty()) QApplication::clipboard()->setText(outpoint);
}

void AccountPage::exportCsv()
{
    const QString filename = QFileDialog::getSaveFileName(this, tr("Export account detail"), QString(), tr("Comma separated file (*.csv)"));
    if (filename.isEmpty()) return;

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        m_status->setText(tr("Unable to open %1 for writing.").arg(filename));
        return;
    }

    QTextStream out(&file);
    auto write_value = [&out](QString value) {
        value.replace('"', "\"\"");
        out << "\"" << value << "\"";
    };
    for (int col = 0; col < ColumnCount; ++col) {
        if (col) out << ",";
        write_value(m_tree->headerItem()->text(col));
    }
    out << "\n";
    for (int row = 0; row < m_tree->topLevelItemCount(); ++row) {
        QTreeWidgetItem* parent = m_tree->topLevelItem(row);
        const int rows = std::max(1, parent->childCount());
        for (int child_index = -1; child_index < rows; ++child_index) {
            QTreeWidgetItem* item = child_index < 0 ? parent : parent->child(child_index);
            for (int col = 0; col < ColumnCount; ++col) {
                if (col) out << ",";
                write_value(item->text(col));
            }
            out << "\n";
        }
    }
    m_status->setText(file.error() == QFile::NoError
        ? tr("Exported account detail to %1.").arg(filename)
        : tr("Export failed for %1.").arg(filename));
}

void AccountPage::showGuide()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Account detail guide"));
    dialog.resize(920, 720);
    dialog.setMinimumSize(620, 440);

    auto* layout = new QVBoxLayout(&dialog);
    auto* browser = new QTextBrowser(&dialog);
    browser->setOpenExternalLinks(false);
    browser->setReadOnly(true);
    browser->setHtml(QStringLiteral(
        "<html><body style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; line-height: 1.45;\">"
        "<style>"
        "h2 { margin-top: 20px; margin-bottom: 8px; }"
        "h3 { margin-top: 16px; margin-bottom: 6px; }"
        "p { margin-top: 4px; margin-bottom: 10px; }"
        "li { margin-bottom: 5px; }"
        "ol, ul { margin-top: 4px; }"
        "</style>%1</body></html>").arg(QuantumGuides::AccountGuide()));
    layout->addWidget(browser);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    dialog.exec();
}
