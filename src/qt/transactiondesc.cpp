// Copyright (c) 2011-2022 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include <qt/transactiondesc.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/paymentserver.h>
#include <qt/transactionrecord.h>

#include <addresstype.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <logging.h>
#include <policy/policy.h>
#include <validation.h>
#include <wallet/types.h>

#include <stdint.h>
#include <string>

#include <QLatin1String>
#include <QObject>

using wallet::ISMINE_ALL;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

namespace {
QString GoldRushWalletControlLabel(const interfaces::WalletTx& wtx)
{
    const auto it = wtx.value_map.find("comment");
    if (it == wtx.value_map.end()) return {};
    if (it->second == "Blackcoin shadow signal") return QObject::tr("PoS Claim");
    if (it->second == "Quantum Quasar built-in shadow PoW claim" ||
        it->second == "Blackcoin shadow PoW claim") {
        return QObject::tr("PoW Claim");
    }
    return {};
}

QString GoldRushClaimLabel(const interfaces::WalletTx& wtx)
{
    const auto it = wtx.value_map.find("comment");
    if (it == wtx.value_map.end()) return {};
    if (it->second == "PoS - Quantum Stake") return QObject::tr("Quantum PoS Reward");
    if (it->second == "PoW - Quantum Claim") return QObject::tr("Quantum PoW Reward");
    return {};
}

QString GoldRushClaimAction(const interfaces::WalletTx& wtx)
{
    QString action = GoldRushClaimLabel(wtx);
    if (action.isEmpty()) return {};

    const auto to_it = wtx.value_map.find("to");
    if (to_it != wtx.value_map.end() && !to_it->second.empty()) {
        action += QObject::tr(" -> ") + GUIUtil::HtmlEscape(to_it->second);
    }
    return action;
}

bool IsQuantumOutput(const CTxOut& txout)
{
    return IsQuantumMigrationScript(txout.scriptPubKey) || IsQuantumColdStakeScript(txout.scriptPubKey);
}

bool IsQuantumWalletTransferTx(const interfaces::WalletTx& wtx)
{
    if (wtx.is_coinbase || wtx.is_coinstake || !GoldRushWalletControlLabel(wtx).isEmpty()) return false;
    if (wtx.txout_is_mine.size() < wtx.tx->vout.size()) return false;
    if (wtx.txout_is_change.size() < wtx.tx->vout.size()) return false;

    bool any_from_me{false};
    bool all_from_me{true};
    for (const isminetype mine : wtx.txin_is_mine) {
        any_from_me = any_from_me || mine;
        all_from_me = all_from_me && (mine & ISMINE_SPENDABLE);
    }
    if (!any_from_me || !all_from_me) return false;

    bool any_value_output{false};
    bool any_quantum_output{false};
    for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
        const CTxOut& txout = wtx.tx->vout[i];
        if (txout.nValue <= 0 || txout.scriptPubKey.IsUnspendable()) continue;
        any_value_output = true;
        if (!(wtx.txout_is_mine[i] & ISMINE_SPENDABLE)) return false;
        any_quantum_output = any_quantum_output || IsQuantumOutput(txout);
    }

    return any_value_output && any_quantum_output;
}
} // namespace

QString TransactionDesc::FormatTxStatus(const interfaces::WalletTxStatus& status, bool inMempool)
{
    int depth = status.depth_in_main_chain;
    if (depth < 0) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents an unconfirmed transaction that conflicts with a confirmed
            transaction. */
        return tr("conflicted with a transaction with %1 confirmations").arg(-depth);
    } else if (depth == 0) {
        QString s;
        if (inMempool) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is in the memory pool. */
            s = tr("0/unconfirmed, in memory pool");
        } else {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This status
                represents an unconfirmed transaction that is not in the memory pool. */
            s = tr("0/unconfirmed, not in memory pool");
        }
        if (status.is_abandoned) {
            /*: Text explaining the current status of a transaction, shown in the
                status field of the details window for this transaction. This
                status represents an abandoned transaction. */
            s += QLatin1String(", ") + tr("abandoned");
        }
        return s;
    } else if (depth < 10) {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This
            status represents a transaction confirmed in at least one block,
            but less than 10 blocks. */
        return tr("%1/unconfirmed").arg(depth);
    } else {
        /*: Text explaining the current status of a transaction, shown in the
            status field of the details window for this transaction. This status
            represents a transaction confirmed in 10 or more blocks. */
        return tr("%1 confirmations").arg(depth);
    }
}

// Takes an encoded PaymentRequest as a string and tries to find the Common Name of the X.509 certificate
// used to sign the PaymentRequest.
bool GetPaymentRequestMerchant(const std::string& pr, QString& merchant)
{
    // Search for the supported pki type strings
    if (pr.find(std::string({0x12, 0x0b}) + "x509+sha256") != std::string::npos || pr.find(std::string({0x12, 0x09}) + "x509+sha1") != std::string::npos) {
        // We want the common name of the Subject of the cert. This should be the second occurrence
        // of the bytes 0x0603550403. The first occurrence of those is the common name of the issuer.
        // After those bytes will be either 0x13 or 0x0C, then length, then either the ascii or utf8
        // string with the common name which is the merchant name
        size_t cn_pos = pr.find({0x06, 0x03, 0x55, 0x04, 0x03});
        if (cn_pos != std::string::npos) {
            cn_pos = pr.find({0x06, 0x03, 0x55, 0x04, 0x03}, cn_pos + 5);
            if (cn_pos != std::string::npos) {
                cn_pos += 5;
                if (pr[cn_pos] == 0x13 || pr[cn_pos] == 0x0c) {
                    cn_pos++; // Consume the type
                    int str_len = pr[cn_pos];
                    cn_pos++; // Consume the string length
                    merchant = QString::fromUtf8(pr.data() + cn_pos, str_len);
                    return true;
                }
            }
        }
    }
    return false;
}

QString TransactionDesc::toHTML(interfaces::Node& node, interfaces::Wallet& wallet, TransactionRecord* rec, BitcoinUnit unit)
{
    int numBlocks;
    interfaces::WalletTxStatus status;
    interfaces::WalletOrderForm orderForm;
    bool inMempool;
    interfaces::WalletTx wtx = wallet.getWalletTxDetails(rec->hash, status, orderForm, inMempool, numBlocks);

    QString strHTML;

    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    const QString gold_rush_control_label = GoldRushWalletControlLabel(wtx);
    const QString gold_rush_claim_label = GoldRushClaimLabel(wtx);
    const bool quantum_wallet_transfer = IsQuantumWalletTransferTx(wtx);

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(status, inMempool);
    strHTML += "<br>";

    strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";

    //
    // From
    //
    if (!gold_rush_claim_label.isEmpty())
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Quantum reward") + "<br>";
        strHTML += "<b>" + tr("Action") + ":</b> " + GoldRushClaimAction(wtx) + "<br>";
    }
    else if (!gold_rush_control_label.isEmpty())
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Wallet self-authentication") + "<br>";
        strHTML += "<b>" + tr("Action") + ":</b> " + gold_rush_control_label + "<br>";
    }
    else if (quantum_wallet_transfer)
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Wallet quantum transfer") + "<br>";
        strHTML += "<b>" + tr("Ledger") + ":</b> ";
        if (status.depth_in_main_chain == 0 && inMempool) {
            strHTML += tr("On-chain quantum transaction, waiting in mempool for a block") + "<br>";
        } else if (status.depth_in_main_chain > 0) {
            strHTML += tr("Confirmed on-chain quantum transaction") + "<br>";
        } else {
            strHTML += tr("On-chain quantum transaction, not currently in mempool") + "<br>";
        }
    }
    else if (wtx.is_coinbase)
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    }
    else if (wtx.is_coinstake)
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Staked") + "<br>";
    }
    else if (wtx.value_map.count("from") && !wtx.value_map["from"].empty())
    {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.value_map["from"]) + "<br>";
    }
    else
    {
        // Offline transaction
        if (nNet > 0)
        {
            // Credit
            CTxDestination address = DecodeDestination(rec->address);
            if (IsValidDestination(address)) {
                std::string name;
                isminetype ismine;
                if (wallet.getAddress(address, &name, &ismine, /* purpose= */ nullptr))
                {
                    strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->address);
                    QString addressOwned = ismine == ISMINE_SPENDABLE ? tr("own address") : tr("watch-only");
                    if (!name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (!gold_rush_claim_label.isEmpty() && wtx.value_map.count("to") && !wtx.value_map["to"].empty())
    {
        strHTML += "<b>" + tr("To") + ":</b> ";
        strHTML += GUIUtil::HtmlEscape(wtx.value_map["to"]) + "<br>";
    }
    else if (wtx.value_map.count("to") && !wtx.value_map["to"].empty())
    {
        // Online transaction
        std::string strAddress = wtx.value_map["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = DecodeDestination(strAddress);
        std::string name;
        if (wallet.getAddress(
                dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
            strHTML += GUIUtil::HtmlEscape(name) + " ";
        strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
    }

    //
    // Amount
    //
    if (!gold_rush_claim_label.isEmpty())
    {
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nCredit) + "<br>";
    }
    else if (!gold_rush_control_label.isEmpty())
    {
        const CAmount nTxFee = nDebit - wtx.tx->GetValueOut();
        if (nTxFee > 0) {
            strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";
    }
    else if (quantum_wallet_transfer)
    {
        for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
            const CTxOut& txout = wtx.tx->vout[i];
            if (txout.nValue <= 0 || !IsQuantumOutput(txout)) continue;
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address)) {
                strHTML += "<b>" + (wtx.txout_is_change[i] ? tr("Quantum change") : tr("Quantum output")) + ":</b> ";
                strHTML += GUIUtil::HtmlEscape(EncodeDestination(address));
                strHTML += " " + BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
            }
        }
        const CAmount nTxFee = nDebit - wtx.tx->GetValueOut();
        if (nTxFee > 0) {
            strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";
    }
    else if (wtx.is_coinbase && nCredit == 0)
    {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        for (const CTxOut& txout : wtx.tx->vout)
            nUnmatured += wallet.getCredit(txout, ISMINE_ALL);
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (status.is_in_main_chain)
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured)+ " (" + tr("matures in %n more block(s)", "", status.blocks_to_maturity) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    }
    else if (nNet > 0)
    {
        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    }
    else
    {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMe)
        {
            if(fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            auto mine = wtx.txout_is_mine.begin();
            for (const CTxOut& txout : wtx.tx->vout)
            {
                // Ignore change
                isminetype toSelf = *(mine++);
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;

                if (!wtx.value_map.count("to") || wtx.value_map["to"].empty())
                {
                    // Offline transaction
                    CTxDestination address;
                    if (ExtractDestination(txout.scriptPubKey, address))
                    {
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        std::string name;
                        if (wallet.getAddress(
                                address, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
                            strHTML += GUIUtil::HtmlEscape(name) + " ";
                        strHTML += GUIUtil::HtmlEscape(EncodeDestination(address));
                        if(toSelf == ISMINE_SPENDABLE)
                            strHTML += " (" + tr("own address") + ")";
                        else if(toSelf & ISMINE_WATCH_ONLY)
                            strHTML += " (" + tr("watch-only") + ")";
                        strHTML += "<br>";
                    }
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                if(toSelf)
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
            }

            if (fAllToMe)
            {
                // Payment to self
                CAmount nChange = wtx.change;
                CAmount nValue = nCredit - nChange;
                strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nValue) + "<br>";
                strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nValue) + "<br>";
            }

            CAmount nTxFee = nDebit - wtx.tx->GetValueOut();
            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        else
        {
            //
            // Mixed debit transaction
            //
            auto mine = wtx.txin_is_mine.begin();
            for (const CTxIn& txin : wtx.tx->vin) {
                if (*(mine++)) {
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet.getDebit(txin, ISMINE_ALL)) + "<br>";
                }
            }
            mine = wtx.txout_is_mine.begin();
            for (const CTxOut& txout : wtx.tx->vout) {
                if (*(mine++)) {
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet.getCredit(txout, ISMINE_ALL)) + "<br>";
                }
            }
        }
    }

    if (gold_rush_control_label.isEmpty() && gold_rush_claim_label.isEmpty() && !quantum_wallet_transfer) {
        strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";
    }

    //
    // Message
    //
    if (wtx.value_map.count("message") && !wtx.value_map["message"].empty())
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.value_map["message"], true) + "<br>";
    if (wtx.value_map.count("comment") && !wtx.value_map["comment"].empty())
        strHTML += "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.value_map["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxHash() + "<br>";
    strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
    strHTML += "<b>" + tr("Transaction virtual size") + ":</b> " + QString::number(GetVirtualTransactionSize(*wtx.tx)) + " bytes<br>";
    strHTML += "<b>" + tr("Output index") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";

    // Message from normal blackcoin:URI (blackcoin:123...?message=example)
    for (const std::pair<std::string, std::string>& r : orderForm) {
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

        //
        // PaymentRequest info:
        //
        if (r.first == "PaymentRequest")
        {
            QString merchant;
            if (!GetPaymentRequestMerchant(r.second, merchant)) {
                merchant.clear();
            } else {
                merchant += tr(" (Certificate was not verified)");
            }
            if (!merchant.isNull()) {
                strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
            }
        }
    }

    if (wtx.is_coinbase || wtx.is_coinstake)
    {
        quint32 numBlocksToMaturity = Params().GetConsensus().nCoinbaseMaturity + 1;
        strHTML += "<br>" + tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(numBlocksToMaturity)) + "<br>";
    }

    //
    // Debug view
    //
    if (node.getLogCategories() != BCLog::NONE)
    {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        for (const CTxIn& txin : wtx.tx->vin)
            if(wallet.txinIsMine(txin))
                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet.getDebit(txin, ISMINE_ALL)) + "<br>";
        for (const CTxOut& txout : wtx.tx->vout)
            if(wallet.txoutIsMine(txout))
                strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet.getCredit(txout, ISMINE_ALL)) + "<br>";

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        if (quantum_wallet_transfer) {
            strHTML += tr("Raw debug rendering is suppressed for quantum transactions because ML-DSA witnesses are very large.") + "<br>";
        } else {
            strHTML += GUIUtil::HtmlEscape(wtx.tx->ToString(), true);
        }

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        for (const CTxIn& txin : wtx.tx->vin)
        {
            COutPoint prevout = txin.prevout;

            Coin prev;
            if(node.getUnspentOutput(prevout, prev))
            {
                {
                    strHTML += "<li>";
                    const CTxOut &vout = prev.out;
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        std::string name;
                        if (wallet.getAddress(address, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr) && !name.empty())
                            strHTML += GUIUtil::HtmlEscape(name) + " ";
                        strHTML += QString::fromStdString(EncodeDestination(address));
                    }
                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet.txoutIsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false")) + "</li>";
                    strHTML = strHTML + " IsWatchOnly=" + (wallet.txoutIsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) + "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
