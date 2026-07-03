// Copyright (c) 2011-2022 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <addresstype.h>
#include <chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <script/solver.h>
#include <wallet/types.h>

#include <stdint.h>

#include <map>
#include <string>

#include <QDateTime>

namespace {
bool IsGoldRushWalletControlTx(const std::map<std::string, std::string>& map_value)
{
    const auto it = map_value.find("comment");
    if (it == map_value.end()) return false;
    return it->second == "Quantum Quasar built-in shadow PoW claim" ||
           it->second == "Blackcoin shadow PoW claim" ||
           it->second == "Gold Rush PoW claim" ||
           it->second == "Quantum PoW Claim" ||
           it->second == "Quantum PoS Claim" ||
           it->second == "goldrush-pow" ||
           it->second == "pos-goldrush-test" ||
           it->second == "Blackcoin shadow signal";
}

std::string GoldRushWalletControlLabel(const std::map<std::string, std::string>& map_value)
{
    const auto it = map_value.find("comment");
    if (it == map_value.end()) return {};
    if (it->second == "Quantum PoS Claim" || it->second.find("signal") != std::string::npos || it->second == "pos-goldrush-test") return "PoS Claim";
    if (it->second == "Quantum PoW Claim" || it->second.find("PoW claim") != std::string::npos || it->second.find("shadow PoW") != std::string::npos || it->second == "goldrush-pow") return "PoW Claim";
    return "Quantum Claim";
}

TransactionRecord::Type GoldRushClaimType(const std::map<std::string, std::string>& map_value)
{
    const auto it = map_value.find("comment");
    if (it == map_value.end()) return TransactionRecord::Other;
    if (it->second == "PoS - Quantum Stake") return TransactionRecord::GoldRushPosStake;
    if (it->second == "PoW - Quantum Claim") return TransactionRecord::GoldRushPowClaim;
    return TransactionRecord::Other;
}

bool IsQuantumOutput(const CTxOut& txout)
{
    return IsQuantumMigrationScript(txout.scriptPubKey) || IsQuantumColdStakeScript(txout.scriptPubKey);
}

bool IsQuantumWalletTransferTx(const interfaces::WalletTx& wtx)
{
    if (wtx.is_coinbase || wtx.is_coinstake || IsGoldRushWalletControlTx(wtx.value_map)) return false;
    if (wtx.txout_is_mine.size() < wtx.tx->vout.size()) return false;
    if (wtx.txout_is_change.size() < wtx.tx->vout.size()) return false;

    bool any_from_me{false};
    bool all_from_me{true};
    for (const wallet::isminetype mine : wtx.txin_is_mine) {
        any_from_me = any_from_me || mine;
        all_from_me = all_from_me && (mine & wallet::ISMINE_SPENDABLE);
    }
    if (!any_from_me || !all_from_me) return false;

    bool any_value_output{false};
    bool any_quantum_output{false};
    for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
        const CTxOut& txout = wtx.tx->vout[i];
        if (txout.nValue <= 0 || txout.scriptPubKey.IsUnspendable()) continue;
        any_value_output = true;
        if (!(wtx.txout_is_mine[i] & wallet::ISMINE_SPENDABLE)) return false;
        any_quantum_output = any_quantum_output || IsQuantumOutput(txout);
    }

    return any_value_output && any_quantum_output;
}

CAmount QuantumWalletTransferAmount(const interfaces::WalletTx& wtx)
{
    if (wtx.txout_is_change.size() < wtx.tx->vout.size()) return 0;

    CAmount amount{0};
    for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
        const CTxOut& txout = wtx.tx->vout[i];
        if (txout.nValue <= 0 || wtx.txout_is_change[i] || !IsQuantumOutput(txout)) continue;
        amount += txout.nValue;
    }
    if (amount > 0) return amount;

    for (const CTxOut& txout : wtx.tx->vout) {
        if (txout.nValue <= 0 || !IsQuantumOutput(txout)) continue;
        amount += txout.nValue;
    }
    return amount;
}

std::string FirstQuantumOutputAddress(const interfaces::WalletTx& wtx)
{
    for (const CTxOut& txout : wtx.tx->vout) {
        if (txout.nValue <= 0 || !IsQuantumOutput(txout)) continue;
        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) return EncodeDestination(dest);
    }
    return {};
}
} // namespace

using wallet::ISMINE_NO;
using wallet::ISMINE_SPENDABLE;
using wallet::ISMINE_WATCH_ONLY;
using wallet::isminetype;

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const interfaces::WalletTx& wtx)
{
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    const TransactionRecord::Type goldrush_claim_type = GoldRushClaimType(mapValue);
    if (goldrush_claim_type == TransactionRecord::GoldRushPosStake || goldrush_claim_type == TransactionRecord::GoldRushPowClaim) {
        std::string address;
        const auto to_it = mapValue.find("to");
        if (to_it != mapValue.end()) address = to_it->second;
        if (address.empty()) address = FirstQuantumOutputAddress(wtx);
        TransactionRecord sub(hash, nTime, goldrush_claim_type, address, 0, nCredit > 0 ? nCredit : wtx.tx->GetValueOut());
        sub.idx = 0;
        sub.involvesWatchAddress = false;
        parts.append(sub);
        return parts;
    }

    if (IsGoldRushWalletControlTx(mapValue)) {
        TransactionRecord sub(hash, nTime, TransactionRecord::Other, GoldRushWalletControlLabel(mapValue), nNet, 0);
        sub.idx = 0;
        sub.involvesWatchAddress = false;
        parts.append(sub);
        return parts;
    }

    if (IsQuantumWalletTransferTx(wtx)) {
        TransactionRecord sub(hash, nTime, TransactionRecord::Other, "Quantum wallet transfer", 0, QuantumWalletTransferAmount(wtx));
        sub.idx = 0;
        sub.involvesWatchAddress = false;
        parts.append(sub);
        return parts;
    }

    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    bool any_from_me = false;
    if (wtx.is_coinbase || wtx.is_coinstake) {
        fAllFromMe = ISMINE_NO;
    } else {
        for (const isminetype mine : wtx.txin_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
            if (mine) any_from_me = true;
        }
    }

    if (fAllFromMe || !any_from_me) {
        for (const isminetype mine : wtx.txout_is_mine)
        {
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        }

        CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];

            if (fAllFromMe) {
                // Change is only really possible if we're the sender
                // Otherwise, someone just sent bitcoins to a change address, which should be shown
                if (wtx.txout_is_change[i]) {
                    continue;
                }

                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;
                sub.involvesWatchAddress = involvesWatchAddress;

                if (!std::get_if<CNoDestination>(&wtx.txout_address[i]))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }

            isminetype mine = wtx.txout_is_mine[i];
            if(mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                if (wtx.is_coinstake) // Combine into single output for coinstake
                {
                    sub.idx = 1; // vout index
                    sub.credit = nNet;
                }
                else
                {
                    sub.idx = i; // vout index
                    sub.credit = txout.nValue;
                }
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }
                else if (wtx.is_coinstake)
                {
                    // Staked
                    sub.type = TransactionRecord::Staked;
                }

                parts.append(sub);

                if (wtx.is_coinstake)
                    break; // Single output for coinstake
            }
        }
    } else {
        //
        // Mixed debit transaction, can't break down payees
        //
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        parts.last().involvesWatchAddress = involvesWatchAddress;
    }

    return parts;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, const uint256& block_hash, int numBlocks, int64_t block_time)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case SendToAddress: case SendToOther:
        typesort = 2; break;
    case RecvWithAddress: case RecvFromOther:
        typesort = 3; break;
    default:
        typesort = 9;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        wtx.block_height,
        (wtx.is_coinbase || wtx.is_coinstake) ? 1 : 0,
        wtx.time_received,
        idx,
        typesort);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.m_cur_block_hash = block_hash;

    // For generated transactions, determine maturity
    if (type == TransactionRecord::Generated || type == TransactionRecord::Staked) {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(const uint256& block_hash) const
{
    assert(!block_hash.IsNull());
    return status.m_cur_block_hash != block_hash || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
