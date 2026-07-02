// Copyright (c) 2015-2022 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <addresstype.h>
#include <crypto/mldsa.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <qt/bitcoinamountfield.h>
#include <qt/bitcoinunits.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/stakingminingpage.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletview.h>
#include <qt/walletmodel.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <chrono>
#include <memory>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QLineEdit>
#include <QObject>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTableView>
#include <QTableWidget>
#include <QTest>
#include <QTimer>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QDialogButtonBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace
{
//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QTimer::singleShot(0, [text, confirm_type]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                SendConfirmationDialog* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                if (text) *text = dialog->text();
                QAbstractButton* button = dialog->button(confirm_type);
                button->setEnabled(true);
                button->click();
            }
        }
    });
}

//! Send coins to address and return txid.
uint256 SendCoins(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const CTxDestination& address, CAmount amount,
                  QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    uint256 txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const uint256& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    ConfirmSend(/*text=*/nullptr, confirm_type);
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    return txid;
}

//! Find index of txid in transaction list.
QModelIndex FindTx(const QAbstractItemModel& model, const uint256& txid)
{
    QString hash = QString::fromStdString(txid.ToString());
    int rows = model.rowCount({});
    for (int row = 0; row < rows; ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) {
            return index;
        }
    }
    return {};
}

/*
// Blackcoin
//! Invoke bumpfee on txid and check results.
void BumpFee(TransactionView& view, const uint256& txid, bool expectDisabled, std::string expectError, bool cancel)
{
    QTableView* table = view.findChild<QTableView*>("transactionView");
    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
    QVERIFY2(index.isValid(), "Could not find BumpFee txid");

    // Select row in table, invoke context menu, and make sure bumpfee action is
    // enabled or disabled as expected.
    QAction* action = view.findChild<QAction*>("bumpFeeAction");
    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    action->setEnabled(expectDisabled);
    table->customContextMenuRequested({});
    QCOMPARE(action->isEnabled(), !expectDisabled);

    action->setEnabled(true);
    QString text;
    if (expectError.empty()) {
        ConfirmSend(&text, cancel ? QMessageBox::Cancel : QMessageBox::Yes);
    } else {
        ConfirmMessage(&text, 0ms);
    }
    action->trigger();
    QVERIFY(text.indexOf(QString::fromStdString(expectError)) != -1);
}
*/

void CompareBalance(WalletModel& walletModel, CAmount expected_balance, QLabel* balance_label_to_check)
{
    BitcoinUnit unit = walletModel.getOptionsModel()->getDisplayUnit();
    QString balanceComparison = BitcoinUnits::formatWithUnit(unit, expected_balance, false, BitcoinUnits::SeparatorStyle::ALWAYS);
    QCOMPARE(balance_label_to_check->text().trimmed(), balanceComparison);
}

// Verify the 'useAvailableBalance' functionality. With and without manually selected coins.
// Case 1: No coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the total available balance
// Case 2: With coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the sum of the selected coins values.
void VerifyUseAvailableBalance(SendCoinsDialog& sendCoinsDialog, const WalletModel& walletModel)
{
    // Verify first entry amount and "useAvailableBalance" button
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries->count() == 1); // only one entry
    SendCoinsEntry* send_entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(send_entry->getValue().amount == 0);
    // Now click "useAvailableBalance", check updated balance (the entire wallet balance should be set)
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == walletModel.getCachedBalance().balance);

    // Now manually select two coins and click on "useAvailableBalance". Then check updated balance
    // (only the sum of the selected coins should be set).
    int COINS_TO_SELECT = 2;
    auto coins = walletModel.wallet().listCoins();
    CAmount sum_selected_coins = 0;
    int selected = 0;
    QVERIFY(coins.size() == 1); // context check, coins received only on one destination
    for (const auto& [outpoint, tx_out] : coins.begin()->second) {
        sendCoinsDialog.getCoinControl()->Select(outpoint);
        sum_selected_coins += tx_out.txout.nValue;
        if (++selected == COINS_TO_SELECT) break;
    }
    QVERIFY(selected == COINS_TO_SELECT);

    // Now that we have 2 coins selected, "useAvailableBalance" should update the balance label only with
    // the sum of them.
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == sum_selected_coins);
}

void SyncUpWallet(const std::shared_ptr<CWallet>& wallet, interfaces::Node& node)
{
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(Params().GetConsensus().hashGenesisBlock, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
    QCOMPARE(result.last_scanned_block, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    QVERIFY(result.last_failed_block.IsNull());
}

std::shared_ptr<CWallet> SetupLegacyWatchOnlyWallet(interfaces::Node& node, TestChain100Setup& test)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        wallet->SetupLegacyScriptPubKeyMan();
        // Add watched key
        CPubKey pubKey = test.coinbaseKey.GetPubKey();
        bool import_keys = wallet->ImportPubKeys({pubKey.GetID()}, {{pubKey.GetID(), pubKey}} , /*key_origins=*/{}, /*add_keypool=*/false, /*internal=*/false, /*timestamp=*/1);
        assert(import_keys);
        wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    }
    SyncUpWallet(wallet, node);
    return wallet;
}

std::shared_ptr<CWallet> SetupDescriptorsWallet(interfaces::Node& node, TestChain100Setup& test)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();

    // Add the coinbase key
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(test.coinbaseKey) + ")", provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    if (!wallet->AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
    CTxDestination dest = GetDestinationForKey(test.coinbaseKey.GetPubKey(), wallet->m_default_address_type);
    wallet->SetAddressBook(dest, "", wallet::AddressPurpose::RECEIVE);
    wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    SyncUpWallet(wallet, node);
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

struct MiniGUI {
public:
    SendCoinsDialog sendCoinsDialog;
    TransactionView transactionView;
    OptionsModel optionsModel;
    std::unique_ptr<ClientModel> clientModel;
    std::unique_ptr<WalletModel> walletModel;

    MiniGUI(interfaces::Node& node, const PlatformStyle* platformStyle) : sendCoinsDialog(platformStyle), transactionView(platformStyle), optionsModel(node) {
        bilingual_str error;
        QVERIFY(optionsModel.Init(error));
        clientModel = std::make_unique<ClientModel>(node, &optionsModel);
    }

    void initModelForWallet(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet, const PlatformStyle* platformStyle)
    {
        WalletContext& context = *node.walletLoader().context();
        AddWallet(context, wallet);
        walletModel = std::make_unique<WalletModel>(interfaces::MakeWallet(context, wallet), *clientModel, platformStyle);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
        sendCoinsDialog.setModel(walletModel.get());
        transactionView.setModel(walletModel.get());
    }
};

void TestStakingMiningPageControls(MiniGUI& mini_gui, const PlatformStyle* platformStyle)
{
    WalletModel& walletModel = *mini_gui.walletModel;
    struct PowMiningCleanup {
        WalletModel& wallet_model;
        ~PowMiningCleanup()
        {
            std::string ignored_error;
            wallet_model.wallet().setPowMining(false, 1, 10, ignored_error);
        }
    } cleanup{walletModel};

    std::string error;
    QVERIFY(walletModel.wallet().setPowMining(false, 1, 10, error));
    walletModel.wallet().setEnabledStaking(false);
    walletModel.wallet().setDonationPercentage(0);

    OverviewPage overview_page(platformStyle);
    overview_page.setClientModel(mini_gui.clientModel.get());
    overview_page.setWalletModel(&walletModel);
    QLabel* overview_donations = overview_page.findChild<QLabel*>("labelDonations");
    QVERIFY(overview_donations);

    StakingMiningPage page(platformStyle);
    page.setClientModel(mini_gui.clientModel.get());
    page.setWalletModel(&walletModel);

    QCheckBox* staking_enable = page.findChild<QCheckBox*>("stakingEnable");
    QCheckBox* unlock_staking_only = page.findChild<QCheckBox*>("unlockStakingOnly");
    QLabel* staking_status = page.findChild<QLabel*>("stakingStatus");
    QCheckBox* pow_enable = page.findChild<QCheckBox*>("powEnable");
    QCheckBox* pow_unlock_wallet = page.findChild<QCheckBox*>("powUnlockWallet");
    QCheckBox* donation_enable = page.findChild<QCheckBox*>("stakingDonationEnable");
    QSpinBox* donation_percent = page.findChild<QSpinBox*>("stakingDonationPercent");
    QLabel* donation_status = page.findChild<QLabel*>("stakingDonationStatus");
    QSpinBox* pow_cores = page.findChild<QSpinBox*>("powCores");
    QSpinBox* pow_percent = page.findChild<QSpinBox*>("powPercent");
    QLineEdit* pow_payout = page.findChild<QLineEdit*>("powPayout");
    QPushButton* pow_copy = page.findChild<QPushButton*>("powCopy");
    QLabel* pow_status = page.findChild<QLabel*>("powStatus");
    QLabel* pow_warning = page.findChild<QLabel*>("powWarning");
    QLabel* migration_phase = page.findChild<QLabel*>("migrationPhase");
    QLabel* migration_deadline = page.findChild<QLabel*>("migrationDeadline");
    QLabel* migration_legacy_amount = page.findChild<QLabel*>("migrationLegacyAmount");
    QLabel* migration_quantum_amount = page.findChild<QLabel*>("migrationQuantumAmount");
    QLabel* migration_goldrush_amount = page.findChild<QLabel*>("migrationGoldrushAmount");
    QLabel* migration_advice = page.findChild<QLabel*>("migrationAdvice");
    QLabel* quantum_address_count = page.findChild<QLabel*>("quantumAddressCount");
    QLabel* quantum_coldstake_count = page.findChild<QLabel*>("quantumColdstakeCount");
    QLineEdit* quantum_address = page.findChild<QLineEdit*>("quantumAddress");
    QLineEdit* quantum_pubkey = page.findChild<QLineEdit*>("quantumPubkey");
    QPushButton* quantum_new = page.findChild<QPushButton*>("newQuantumAddress");
    QPushButton* quantum_copy = page.findChild<QPushButton*>("quantumCopy");
    QPushButton* quantum_pubkey_copy = page.findChild<QPushButton*>("quantumPubkeyCopy");
    QComboBox* selfstake_lock_period = page.findChild<QComboBox*>("selfStakeLockPeriod");
    QComboBox* selfstake_selector = page.findChild<QComboBox*>("selfStakeAddressSelector");
    QLineEdit* selfstake_address = page.findChild<QLineEdit*>("selfStakeAddress");
    QPushButton* selfstake_new = page.findChild<QPushButton*>("newSelfStakeAddress");
    QPushButton* selfstake_copy = page.findChild<QPushButton*>("selfStakeCopy");
    QComboBox* selfstake_output_selector = page.findChild<QComboBox*>("selfStakeOutputSelector");
    BitcoinAmountField* selfstake_fund_amount = page.findChild<BitcoinAmountField*>("selfStakeFundAmount");
    QPushButton* selfstake_fund = page.findChild<QPushButton*>("selfStakeFund");
    QPushButton* selfstake_withdraw = page.findChild<QPushButton*>("selfStakeWithdraw");
    QLabel* selfstake_status = page.findChild<QLabel*>("selfStakeStatus");
    QLineEdit* coldstake_operator_address = page.findChild<QLineEdit*>("coldstakeOperatorAddress");
    QComboBox* coldstake_operator_address_selector = page.findChild<QComboBox*>("coldstakeOperatorAddressSelector");
    QLineEdit* coldstake_operator_pubkey = page.findChild<QLineEdit*>("coldstakeOperatorPubkey");
    QPushButton* coldstake_operator_new = page.findChild<QPushButton*>("newColdstakeOperatorKey");
    QPushButton* coldstake_operator_copy = page.findChild<QPushButton*>("coldstakeOperatorCopy");
    QPushButton* coldstake_operator_use = page.findChild<QPushButton*>("coldstakeOperatorUseForDelegation");
    BitcoinAmountField* coldstake_operator_bond_amount = page.findChild<BitcoinAmountField*>("coldstakeOperatorBondAmount");
    QPushButton* coldstake_operator_fund = page.findChild<QPushButton*>("coldstakeOperatorFund");
    QPushButton* coldstake_operator_withdraw = page.findChild<QPushButton*>("coldstakeOperatorWithdraw");
    QLabel* coldstake_operator_status = page.findChild<QLabel*>("coldstakeOperatorStatus");
    QTableWidget* coldstake_operator_registry = page.findChild<QTableWidget*>("coldstakeOperatorRegistry");
    QPushButton* coldstake_operator_refresh = page.findChild<QPushButton*>("coldstakeOperatorRefresh");
    QPushButton* coldstake_operator_select = page.findChild<QPushButton*>("coldstakeOperatorSelect");
    QLabel* coldstake_operator_registry_status = page.findChild<QLabel*>("coldstakeOperatorRegistryStatus");
    QComboBox* coldstake_lock_period = page.findChild<QComboBox*>("coldstakeLockPeriod");
    QComboBox* coldstake_operator_selector = page.findChild<QComboBox*>("coldstakeOperatorSelector");
    QComboBox* coldstake_delegation_selector = page.findChild<QComboBox*>("coldstakeDelegationSelector");
    QLineEdit* coldstake_address = page.findChild<QLineEdit*>("coldstakeAddress");
    QPushButton* coldstake_new = page.findChild<QPushButton*>("newColdstakeAddress");
    QPushButton* coldstake_copy = page.findChild<QPushButton*>("coldstakeCopy");
    QLabel* coldstake_status = page.findChild<QLabel*>("coldstakeStatus");

    QVERIFY(staking_enable);
    QVERIFY(unlock_staking_only);
    QVERIFY(staking_status);
    QVERIFY(pow_enable);
    QVERIFY(pow_unlock_wallet);
    QVERIFY(donation_enable);
    QVERIFY(donation_percent);
    QVERIFY(donation_status);
    QVERIFY(pow_cores);
    QVERIFY(pow_percent);
    QVERIFY(pow_payout);
    QVERIFY(pow_copy);
    QVERIFY(pow_status);
    QVERIFY(pow_warning);
    QVERIFY(migration_phase);
    QVERIFY(migration_deadline);
    QVERIFY(migration_legacy_amount);
    QVERIFY(migration_quantum_amount);
    QVERIFY(migration_goldrush_amount);
    QVERIFY(migration_advice);
    QVERIFY(quantum_address_count);
    QVERIFY(quantum_coldstake_count);
    QVERIFY(quantum_address);
    QVERIFY(quantum_pubkey);
    QVERIFY(quantum_new);
    QVERIFY(quantum_copy);
    QVERIFY(quantum_pubkey_copy);
    QVERIFY(selfstake_lock_period);
    QVERIFY(selfstake_selector);
    QVERIFY(selfstake_address);
    QVERIFY(selfstake_new);
    QVERIFY(selfstake_copy);
    QVERIFY(selfstake_output_selector);
    QVERIFY(selfstake_fund_amount);
    QVERIFY(selfstake_fund);
    QVERIFY(selfstake_withdraw);
    QVERIFY(selfstake_status);
    QVERIFY(coldstake_operator_address);
    QVERIFY(coldstake_operator_address_selector);
    QVERIFY(coldstake_operator_pubkey);
    QVERIFY(coldstake_operator_new);
    QVERIFY(coldstake_operator_copy);
    QVERIFY(coldstake_operator_use);
    QVERIFY(coldstake_operator_bond_amount);
    QVERIFY(coldstake_operator_fund);
    QVERIFY(coldstake_operator_withdraw);
    QVERIFY(coldstake_operator_status);
    QVERIFY(coldstake_operator_registry);
    QVERIFY(coldstake_operator_refresh);
    QVERIFY(coldstake_operator_select);
    QVERIFY(coldstake_operator_registry_status);
    QVERIFY(coldstake_lock_period);
    QVERIFY(coldstake_operator_selector);
    QVERIFY(coldstake_delegation_selector);
    QVERIFY(coldstake_address);
    QVERIFY(coldstake_new);
    QVERIFY(coldstake_copy);
    QVERIFY(coldstake_status);

    QVERIFY(QMetaObject::invokeMethod(&page, "updateStatus", Qt::DirectConnection));
    QCOMPARE(staking_enable->isChecked(), false);
    QCOMPARE(unlock_staking_only->isChecked(), false);
    QVERIFY(!unlock_staking_only->isEnabled());
    QCOMPARE(pow_unlock_wallet->isChecked(), false);
    QVERIFY(!pow_unlock_wallet->isEnabled());
    QCOMPARE(staking_status->text(), QString("Staking is off"));
    QCOMPARE(donation_enable->isChecked(), false);
    QCOMPARE(walletModel.wallet().getDonationPercentage(), 0U);
    QVERIFY(donation_status->text().contains(QString("off")));
    QVERIFY(overview_donations->text().contains(QString("0%")));
    QVERIFY(!migration_phase->text().isEmpty());
    QVERIFY(!migration_deadline->text().isEmpty());
    QVERIFY(migration_legacy_amount->text().contains(QString("BLK")));
    QVERIFY(migration_quantum_amount->text().contains(QString("BLK")));
    QVERIFY(migration_goldrush_amount->text().contains(QString("BLK")));
    QVERIFY(!migration_advice->text().isEmpty());
    QCOMPARE(quantum_address_count->text(), QString("0"));
    QCOMPARE(quantum_coldstake_count->text(), QString("0"));
    QVERIFY(!quantum_copy->isEnabled());
    QVERIFY(!quantum_pubkey_copy->isEnabled());
    QVERIFY(selfstake_new->isEnabled());
    QVERIFY(!selfstake_selector->isEnabled());
    QVERIFY(!selfstake_copy->isEnabled());
    QVERIFY(!selfstake_output_selector->isEnabled());
    QVERIFY(!selfstake_fund_amount->isEnabled());
    QVERIFY(!selfstake_fund->isEnabled());
    QVERIFY(!selfstake_withdraw->isEnabled());
    QVERIFY(coldstake_operator_new->isEnabled());
    QVERIFY(!coldstake_operator_address_selector->isEnabled());
    QVERIFY(!coldstake_operator_copy->isEnabled());
    QVERIFY(!coldstake_operator_use->isEnabled());
    QVERIFY(!coldstake_operator_bond_amount->isEnabled());
    QVERIFY(!coldstake_operator_fund->isEnabled());
    QVERIFY(!coldstake_operator_withdraw->isEnabled());
    QVERIFY(coldstake_operator_refresh->isEnabled());
    QVERIFY(!coldstake_operator_select->isEnabled());
    QCOMPARE(coldstake_operator_registry->rowCount(), 0);
    QVERIFY(!coldstake_operator_selector->currentData().toString().size());
    QVERIFY(!coldstake_delegation_selector->isEnabled());
    QVERIFY(!coldstake_new->isEnabled());
    QVERIFY(!coldstake_copy->isEnabled());

    quantum_new->click();
    qApp->processEvents();
    const CTxDestination gui_quantum_dest = DecodeDestination(quantum_address->text().toStdString());
    QVERIFY(IsValidDestination(gui_quantum_dest));
    QVERIFY(IsQuantumMigrationDestination(gui_quantum_dest));
    QVERIFY(IsHex(quantum_pubkey->text().toStdString()));
    QCOMPARE(quantum_pubkey->text().size(), int{ML_DSA::PUBLICKEY_BYTES * 2});
    QCOMPARE(quantum_address_count->text(), QString("1"));
    QVERIFY(quantum_copy->isEnabled());
    QVERIFY(quantum_pubkey_copy->isEnabled());

    quantum_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), quantum_address->text());
    quantum_pubkey_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), quantum_pubkey->text());

    selfstake_lock_period->setCurrentIndex(5);
    selfstake_new->click();
    qApp->processEvents();
    const CTxDestination gui_selfstake_dest = DecodeDestination(selfstake_address->text().toStdString());
    QVERIFY(IsValidDestination(gui_selfstake_dest));
    QVERIFY(IsQuantumMigrationDestination(gui_selfstake_dest));
    QVERIFY(selfstake_copy->isEnabled());
    QVERIFY(selfstake_selector->isEnabled());
    QVERIFY(selfstake_selector->findData(selfstake_address->text()) >= 0);
    QVERIFY(!selfstake_output_selector->isEnabled());
    QVERIFY(selfstake_fund_amount->isEnabled());
    QVERIFY(selfstake_fund->isEnabled());
    QVERIFY(selfstake_withdraw->isEnabled());
    QVERIFY(selfstake_status->text().contains(QString("9450")));

    selfstake_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), selfstake_address->text());

    coldstake_operator_new->click();
    qApp->processEvents();
    const CTxDestination gui_operator_dest = DecodeDestination(coldstake_operator_address->text().toStdString());
    QVERIFY(IsValidDestination(gui_operator_dest));
    QVERIFY(IsQuantumMigrationDestination(gui_operator_dest));
    QVERIFY(IsHex(coldstake_operator_pubkey->text().toStdString()));
    QCOMPARE(coldstake_operator_pubkey->text().size(), int{ML_DSA::PUBLICKEY_BYTES * 2});
    QVERIFY(coldstake_operator_address_selector->isEnabled());
    QVERIFY(coldstake_operator_address_selector->findData(coldstake_operator_address->text()) >= 0);
    QVERIFY(coldstake_operator_copy->isEnabled());
    QVERIFY(coldstake_operator_use->isEnabled());
    QVERIFY(coldstake_operator_status->text().contains(QString("30-day")));

    coldstake_operator_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), coldstake_operator_pubkey->text());
    coldstake_operator_use->click();
    QCOMPARE(coldstake_operator_selector->currentData().toString(), coldstake_operator_pubkey->text());
    QVERIFY(coldstake_operator_selector->currentText().contains(QString("operator")));

    coldstake_lock_period->setCurrentIndex(5);
    QVERIFY(coldstake_new->isEnabled());
    coldstake_new->click();
    qApp->processEvents();

    const CTxDestination gui_coldstake_dest = DecodeDestination(coldstake_address->text().toStdString());
    QVERIFY(IsValidDestination(gui_coldstake_dest));
    QVERIFY(IsQuantumColdStakeDestination(gui_coldstake_dest));
    QCOMPARE(quantum_coldstake_count->text(), QString("1"));
    QVERIFY(quantum_address_count->text().toInt() >= 2);
    QVERIFY(coldstake_delegation_selector->isEnabled());
    QVERIFY(coldstake_delegation_selector->findData(coldstake_address->text()) >= 0);
    QVERIFY(coldstake_copy->isEnabled());
    QVERIFY(coldstake_status->text().contains(QString("Cold-stake address created")));

    coldstake_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), coldstake_address->text());

    staking_enable->click();
    QVERIFY(walletModel.wallet().getEnabledStaking());
    QCOMPARE(staking_status->text(), QString("Staking is active"));

    staking_enable->click();
    QVERIFY(!walletModel.wallet().getEnabledStaking());
    QCOMPARE(staking_status->text(), QString("Staking is off"));

    donation_percent->setValue(15);
    donation_enable->click();
    QCOMPARE(walletModel.wallet().getDonationPercentage(), 15U);
    QVERIFY(donation_status->text().contains(QString("15")));
    QCOMPARE(overview_donations->text(), QString("15% of stake rewards"));

    donation_percent->setValue(7);
    qApp->processEvents();
    QCOMPARE(walletModel.wallet().getDonationPercentage(), 7U);
    QVERIFY(donation_status->text().contains(QString("7")));
    QCOMPARE(overview_donations->text(), QString("7% of stake rewards"));

    donation_enable->click();
    QCOMPARE(walletModel.wallet().getDonationPercentage(), 0U);
    QVERIFY(donation_status->text().contains(QString("off")));
    QCOMPARE(overview_donations->text(), QString("0% of stake rewards"));

    QCOMPARE(pow_enable->isChecked(), false);
    QVERIFY(!walletModel.wallet().getPowMiningInfo().enabled);

    const int requested_threads = std::min(2, pow_cores->maximum());
    pow_cores->setValue(requested_threads);
    pow_percent->setValue(25);
    pow_enable->click();
    qApp->processEvents();

    interfaces::WalletPowMiningInfo info;
    for (int i = 0; i < 50; ++i) {
        info = walletModel.wallet().getPowMiningInfo();
        if (info.enabled && info.payout_address_available && !info.payout_address.empty()) break;
        QTest::qWait(20);
    }
    QVERIFY(info.enabled);
    QCOMPARE(info.threads, requested_threads);
    QCOMPARE(info.cpu_percent, 25);
    QVERIFY(info.payout_address_available);
    QVERIFY(!info.payout_address.empty());

    const CTxDestination payout_dest = DecodeDestination(info.payout_address);
    QVERIFY(IsValidDestination(payout_dest));
    QVERIFY(IsQuantumMigrationDestination(payout_dest));
    QCOMPARE(pow_payout->text(), QString::fromStdString(info.payout_address));
    QVERIFY(pow_copy->isEnabled());

    pow_copy->click();
    QCOMPARE(QApplication::clipboard()->text(), pow_payout->text());
    QVERIFY(pow_warning->text().contains(QString("migration window")));

    pow_enable->click();
    qApp->processEvents();
    QVERIFY(!walletModel.wallet().getPowMiningInfo().enabled);
}

void TestStakingMiningPageSurvivesWalletModelDeletion(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet, const PlatformStyle* platformStyle)
{
    MiniGUI mini_gui(node, platformStyle);
    mini_gui.initModelForWallet(node, wallet, platformStyle);

    WalletModel* wallet_model = mini_gui.walletModel.get();
    wallet_model->wallet().setEnabledStaking(true);

    StakingMiningPage page(platformStyle);
    page.setClientModel(mini_gui.clientModel.get());
    page.setWalletModel(wallet_model);

    QCheckBox* staking_enable = page.findChild<QCheckBox*>("stakingEnable");
    QLabel* staking_status = page.findChild<QLabel*>("stakingStatus");
    QCheckBox* donation_enable = page.findChild<QCheckBox*>("stakingDonationEnable");
    QSpinBox* donation_percent = page.findChild<QSpinBox*>("stakingDonationPercent");
    QCheckBox* pow_enable = page.findChild<QCheckBox*>("powEnable");
    QLineEdit* pow_payout = page.findChild<QLineEdit*>("powPayout");
    QLabel* pow_status = page.findChild<QLabel*>("powStatus");

    QVERIFY(staking_enable);
    QVERIFY(staking_status);
    QVERIFY(donation_enable);
    QVERIFY(donation_percent);
    QVERIFY(pow_enable);
    QVERIFY(pow_payout);
    QVERIFY(pow_status);
    QVERIFY(staking_enable->isEnabled());
    QVERIFY(staking_enable->isChecked());

    mini_gui.walletModel.reset();
    qApp->processEvents();

    QVERIFY(QMetaObject::invokeMethod(&page, "updateStatus", Qt::DirectConnection));
    QCOMPARE(staking_enable->isChecked(), false);
    QCOMPARE(staking_status->text(), QString("No wallet loaded"));
    QVERIFY(!staking_enable->isEnabled());
    QVERIFY(!donation_enable->isEnabled());
    QVERIFY(!donation_percent->isEnabled());
    QVERIFY(!pow_enable->isEnabled());
    QVERIFY(pow_payout->text().isEmpty());
    QVERIFY(pow_status->text().contains(QString("Load a wallet")));
}

void TestWalletPagesScale(MiniGUI& mini_gui, const PlatformStyle* platformStyle)
{
    TransactionView& transaction_view = mini_gui.transactionView;
    transaction_view.resize(480, 320);
    transaction_view.show();
    qApp->processEvents();

    auto* table = transaction_view.findChild<QTableView*>(QStringLiteral("transactionView"));
    QVERIFY(table);
    QVERIFY(table->isVisible());
    QVERIFY(transaction_view.minimumSizeHint().width() <= 480);
    transaction_view.hide();

    WalletView wallet_view(mini_gui.walletModel.get(), platformStyle, nullptr);
    wallet_view.setClientModel(mini_gui.clientModel.get());
    wallet_view.resize(640, 480);
    wallet_view.show();
    wallet_view.gotoHistoryPage();
    qApp->processEvents();

    QVERIFY(wallet_view.findChild<QTableView*>(QStringLiteral("transactionView")));
    QVERIFY(wallet_view.minimumSizeHint().width() <= 640);

    wallet_view.gotoStakingMiningPage();
    qApp->processEvents();
    auto* staking_scroll = wallet_view.findChild<QScrollArea*>(QStringLiteral("stakingMiningScrollPage"));
    QVERIFY(staking_scroll);
    QCOMPARE(wallet_view.currentWidget(), staking_scroll);
    wallet_view.hide();
}

//! Simple qt wallet tests.
//
// Test widgets can be debugged interactively calling show() on them and
// manually running the event loop, e.g.:
//
//     sendCoinsDialog.show();
//     QEventLoop().exec();
//
// This also requires overriding the default minimal Qt platform:
//
//     QT_QPA_PLATFORM=xcb     src/qt/test/test_blackcoin-qt  # Linux
//     QT_QPA_PLATFORM=windows src/qt/test/test_blackcoin-qt  # Windows
//     QT_QPA_PLATFORM=cocoa   src/qt/test/test_blackcoin-qt  # macOS
void TestGUI(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    // Create widgets for sending coins and listing transactions.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;

    TestStakingMiningPageControls(mini_gui, platformStyle.get());
    TestWalletPagesScale(mini_gui, platformStyle.get());
    TestStakingMiningPageSurvivesWalletModelDeletion(node, wallet, platformStyle.get());

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalance(), sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Check 'UseAvailableBalance' functionality
    VerifyUseAvailableBalance(sendCoinsDialog, walletModel);

    // Send two transactions, and verify they are added to transaction list.
    TransactionTableModel* transactionTableModel = walletModel.getTransactionTableModel();
    QCOMPARE(transactionTableModel->rowCount({}), 105);
    // Blackcoin
    uint256 txid1 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN);
    uint256 txid2 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 10 * COIN);
    // Transaction table model updates on a QueuedConnection, so process events to ensure it's updated.
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), 107);
    QVERIFY(FindTx(*transactionTableModel, txid1).isValid());
    QVERIFY(FindTx(*transactionTableModel, txid2).isValid());

    // Blackcoin
    // Call bumpfee. Test disabled, canceled, enabled, then failing cases.
    // BumpFee(transactionView, txid1, /*expectDisabled=*/true, /*expectError=*/"not BIP 125 replaceable", /*cancel=*/false);
    // BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    // BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/false);
    // BumpFee(transactionView, txid2, /*expectDisabled=*/true, /*expectError=*/"already bumped", /*cancel=*/false);

    // Check current balance on OverviewPage
    OverviewPage overviewPage(platformStyle.get());
    overviewPage.setWalletModel(&walletModel);
    walletModel.pollBalanceChanged(); // Manual balance polling update
    CompareBalance(walletModel, walletModel.wallet().getBalance(), overviewPage.findChild<QLabel*>("labelBalance"));

    // Check Request Payment button
    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(&walletModel);
    RecentRequestsTableModel* requestTableModel = walletModel.getRecentRequestsTableModel();

    // Label input
    QLineEdit* labelInput = receiveCoinsDialog.findChild<QLineEdit*>("reqLabel");
    labelInput->setText("TEST_LABEL_1");

    // Amount input
    BitcoinAmountField* amountInput = receiveCoinsDialog.findChild<BitcoinAmountField*>("reqAmount");
    amountInput->setValue(1);

    // Message input
    QLineEdit* messageInput = receiveCoinsDialog.findChild<QLineEdit*>("reqMessage");
    messageInput->setText("TEST_MESSAGE_1");
    QComboBox* addressType = receiveCoinsDialog.findChild<QComboBox*>("addressType");
    QVERIFY(addressType);
    QLabel* receive_type_notice = receiveCoinsDialog.findChild<QLabel*>("label_5");
    QVERIFY(receive_type_notice);
    QVERIFY(addressType->currentText().contains(QString("Legacy Blackcoin")));
    QVERIFY(receive_type_notice->text().contains(QString("Legacy Blackcoin address")));
    int initialRowCount = requestTableModel->rowCount({});
    QPushButton* requestPaymentButton = receiveCoinsDialog.findChild<QPushButton*>("receiveButton");
    requestPaymentButton->click();
    QString address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("payment_header")->text(), QString("Payment information"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("uri_tag")->text(), QString("URI:"));
            QString uri = receiveRequestDialog->QObject::findChild<QLabel*>("uri_content")->text();
            QCOMPARE(uri.count("blackcoin:"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("address_tag")->text(), QString("Address:"));
            QVERIFY(address.isEmpty());
            address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            QVERIFY(!address.isEmpty());

            QCOMPARE(uri.count("amount=0.00000001"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_tag")->text(), QString("Amount:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_content")->text(), QString::fromStdString("0.00000001 " + CURRENCY_UNIT));

            QCOMPARE(uri.count("label=TEST_LABEL_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_tag")->text(), QString("Label:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text(), QString("TEST_LABEL_1"));

            QCOMPARE(uri.count("message=TEST_MESSAGE_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_tag")->text(), QString("Message:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_content")->text(), QString("TEST_MESSAGE_1"));
            receiveRequestDialog->close();
        }
    }

    // Clear button
    QPushButton* clearButton = receiveCoinsDialog.findChild<QPushButton*>("clearButton");
    clearButton->click();
    QCOMPARE(labelInput->text(), QString(""));
    QCOMPARE(amountInput->value(), CAmount(0));
    QCOMPARE(messageInput->text(), QString(""));

    // Check addition to history
    int currentRowCount = requestTableModel->rowCount({});
    QCOMPARE(currentRowCount, initialRowCount+1);

    // Check addition to wallet
    std::vector<std::string> requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    RecentRequestEntry entry;
    DataStream{MakeUCharSpan(requests[0])} >> entry;
    QCOMPARE(entry.nVersion, int{1});
    QCOMPARE(entry.id, int64_t{1});
    QVERIFY(entry.date.isValid());
    QCOMPARE(entry.recipient.address, address);
    QCOMPARE(entry.recipient.label, QString{"TEST_LABEL_1"});
    QCOMPARE(entry.recipient.amount, CAmount{1});
    QCOMPARE(entry.recipient.message, QString{"TEST_MESSAGE_1"});
    QCOMPARE(entry.recipient.sPaymentRequest, std::string{});
    QCOMPARE(entry.recipient.authenticatedMerchant, QString{});

    // Check Remove button
    QTableView* table = receiveCoinsDialog.findChild<QTableView*>("recentRequestsView");
    table->selectRow(currentRowCount-1);
    QPushButton* removeRequestButton = receiveCoinsDialog.findChild<QPushButton*>("removeRequestButton");
    removeRequestButton->click();
    QCOMPARE(requestTableModel->rowCount({}), currentRowCount-1);

    // Check removal from wallet
    QCOMPARE(walletModel.wallet().getAddressReceiveRequests().size(), size_t{0});

    const int quantum_index = addressType->findText(QString("Quantum-resistant ML-DSA (upgraded wallet)"));
    QVERIFY(quantum_index >= 0);
    addressType->setCurrentIndex(quantum_index);
    QVERIFY(receive_type_notice->text().contains(QString("Quantum-resistant ML-DSA address")));
    QCOMPARE(requestPaymentButton->text(), QString("Create quantum ML-DSA address"));
    labelInput->setText("TEST_QUANTUM_LABEL");
    amountInput->clear();
    messageInput->setText("TEST_QUANTUM_MESSAGE");
    requestPaymentButton->click();
    qApp->processEvents();

    QString quantum_address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            if (receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text() == QString("TEST_QUANTUM_LABEL")) {
                quantum_address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            }
            receiveRequestDialog->close();
        }
    }
    QVERIFY(!quantum_address.isEmpty());
    const CTxDestination quantum_dest = DecodeDestination(quantum_address.toStdString());
    QVERIFY(IsValidDestination(quantum_dest));
    QVERIFY(IsQuantumMigrationDestination(quantum_dest));
    QCOMPARE(requestTableModel->rowCount({}), initialRowCount + 1);

    requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    DataStream{MakeUCharSpan(requests[0])} >> entry;
    QCOMPARE(entry.recipient.address, quantum_address);
    QCOMPARE(entry.recipient.label, QString{"TEST_QUANTUM_LABEL"});
    QCOMPARE(entry.recipient.message, QString{"TEST_QUANTUM_MESSAGE"});
}

void TestGUIWatchOnly(interfaces::Node& node, TestChain100Setup& test)
{
    const std::shared_ptr<CWallet>& wallet = SetupLegacyWatchOnlyWallet(node, test);

    // Create widgets and init models
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalances().watch_only_balance,
                   sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Set change address
    sendCoinsDialog.getCoinControl()->destChange = GetDestinationForKey(test.coinbaseKey.GetPubKey(), OutputType::LEGACY);

    // Time to reject "save" PSBT dialog ('SendCoins' locks the main thread until the dialog receives the event).
    QTimer timer;
    timer.setInterval(500);
    QObject::connect(&timer, &QTimer::timeout, [&](){
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox")) {
                QMessageBox* dialog = qobject_cast<QMessageBox*>(widget);
                QAbstractButton* button = dialog->button(QMessageBox::Discard);
                button->setEnabled(true);
                button->click();
                timer.stop();
                break;
            }
        }
    });
    timer.start(500);

    // Send tx and verify PSBT copied to the clipboard.
    // Blackcoin
    SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, QMessageBox::Save);
    const std::string& psbt_string = QApplication::clipboard()->text().toStdString();
    QVERIFY(!psbt_string.empty());

    // Decode psbt
    std::optional<std::vector<unsigned char>> decoded_psbt = DecodeBase64(psbt_string);
    QVERIFY(decoded_psbt);
    PartiallySignedTransaction psbt;
    std::string err;
    QVERIFY(DecodeRawPSBT(psbt, MakeByteSpan(*decoded_psbt), err));
}

void TestGUI(interfaces::Node& node)
{
    // Set up wallet and chain with 105 blocks (5 mature blocks for spending).
    TestChain100Setup test;
    for (int i = 0; i < 5; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    }
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    // "Full" GUI tests, use descriptor wallet
    const std::shared_ptr<CWallet>& desc_wallet = SetupDescriptorsWallet(node, test);
    TestGUI(node, desc_wallet);

    // Legacy watch-only wallet test
    // Verify PSBT creation.
    TestGUIWatchOnly(node, test);
}

} // namespace

void WalletTests::walletTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        QWARN("Skipping WalletTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
              "with 'QT_QPA_PLATFORM=cocoa test_blackcoin-qt' on mac, or else use a linux or windows build.");
        return;
    }
#endif
    TestGUI(m_node);
}
