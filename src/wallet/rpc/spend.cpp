// Copyright (c) 2011-2022 Blackcoin Core Developers
// Copyright (c) 2011-2022 Blackcoin More Developers
// Copyright (c) 2011-2022 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/util.h>
#include <rgb/engine.h>
#include <script/script.h>
#include <shadow.h>
#include <util/translation.h>
#include <util/vector.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <set>

namespace wallet {
static CFeeRate FeeRateFromSatVbValue(const UniValue& value)
{
    return CFeeRate{AmountFromValue(value, /*decimals=*/3)};
}

static bool IsDirectQuantumMigrationScript(const CScript& script_pub_key)
{
    const auto tier = GetQuantumStakeTierProgram(script_pub_key);
    return tier && !tier->tiered && !tier->cold_stake;
}

static std::optional<CCoinControl::InputFamily> InferRecipientInputFamily(const CScript& script_pub_key)
{
    if (script_pub_key.empty() || script_pub_key.IsUnspendable()) return std::nullopt;
    if (IsQuantumMigrationScript(script_pub_key) || IsQuantumColdStakeScript(script_pub_key) || IsEUTXOScript(script_pub_key)) {
        return std::nullopt;
    }
    return CCoinControl::InputFamily::LEGACY;
}

static void MergeRecipientInputFamily(std::optional<CCoinControl::InputFamily>& inferred, const std::optional<CCoinControl::InputFamily>& candidate)
{
    if (!candidate) return;
    inferred = candidate;
}

static void ApplyInferredInputFamily(CCoinControl& coin_control, const std::optional<CCoinControl::InputFamily>& inferred)
{
    if (!inferred || coin_control.m_input_family) return;
    coin_control.m_input_family = *inferred;
}

static void ApplyRecipientInputFamily(CCoinControl& coin_control, const std::vector<CRecipient>& recipients)
{
    std::optional<CCoinControl::InputFamily> inferred;
    for (const CRecipient& recipient : recipients) {
        const CScript script_pub_key = recipient.scriptPubKey ? *recipient.scriptPubKey : GetScriptForDestination(recipient.dest);
        MergeRecipientInputFamily(inferred, InferRecipientInputFamily(script_pub_key));
    }
    ApplyInferredInputFamily(coin_control, inferred);
}

static void ApplyOutputInputFamily(CCoinControl& coin_control, const std::vector<CTxOut>& outputs)
{
    std::optional<CCoinControl::InputFamily> inferred;
    for (const CTxOut& output : outputs) {
        MergeRecipientInputFamily(inferred, InferRecipientInputFamily(output.scriptPubKey));
    }
    ApplyInferredInputFamily(coin_control, inferred);
}

static void CommitWalletTransactionOrThrow(CWallet& wallet, const CTransactionRef& tx, mapValue_t map_value, const std::string& action)
{
    std::string broadcast_error;
    if (!wallet.CommitTransaction(tx, std::move(map_value), {}, &broadcast_error)) {
        const std::string reason = broadcast_error.empty() ? "transaction was not accepted into the mempool" : broadcast_error;
        if (!wallet.AbandonTransaction(tx->GetHash())) {
            wallet.WalletLogPrintf("%s transaction could not be abandoned after broadcast failure: txid=%s\n", action, tx->GetHash().ToString());
        }
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("%s transaction was created but could not be broadcast: %s", action, reason));
    }
}

static void ParseRecipients(const UniValue& address_amounts, const UniValue& subtract_fee_outputs, std::vector<CRecipient>& recipients)
{
    std::set<CTxDestination> destinations;
    int i = 0;
    for (const std::string& address: address_amounts.getKeys()) {
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Blackcoin address: ") + address);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + address);
        }
        destinations.insert(dest);

        CAmount amount = AmountFromValue(address_amounts[i++]);

        bool subtract_fee = false;
        for (unsigned int idx = 0; idx < subtract_fee_outputs.size(); idx++) {
            const UniValue& addr = subtract_fee_outputs[idx];
            if (addr.get_str() == address) {
                subtract_fee = true;
            }
        }

        CRecipient recipient = {dest, amount, subtract_fee};
        recipients.push_back(recipient);
    }
}

UniValue SendMoneyToScript(CWallet& wallet, const CScript scriptPubKey, CAmount nValue, const CCoinControl &coin_control, mapValue_t map_value)
{
    EnsureWalletIsUnlocked(wallet);

    // This function is only used by sendtoaddress and sendmany.
    // This should always try to sign, if we don't have private keys, don't try to do anything here.
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    const auto bal = GetBalance(wallet);
    CAmount curBalance = bal.m_mine_trusted;

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (wallet.m_wallet_unlock_staking_only)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet unlocked for staking only, unable to create transaction");

    std::vector<CRecipient> recipients;
    CTxDestination dest;
    ExtractDestination(scriptPubKey, dest);
    CRecipient recipient = {dest, nValue, false};
    recipients.push_back(recipient);

    // Shuffle recipient list
    std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

    // Send
    constexpr int RANDOM_CHANGE_POSITION = -1;
    auto res = CreateTransaction(wallet, recipients, RANDOM_CHANGE_POSITION, coin_control, true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
    }
    const CTransactionRef& tx = res->tx;
    wallet.CommitTransaction(tx, std::move(map_value), {} /* orderForm */);
    return tx->GetHash().GetHex();
}

static UniValue FinishTransaction(const std::shared_ptr<CWallet> pwallet, const UniValue& options, const CMutableTransaction& rawTx)
{
    // Make a blank psbt
    PartiallySignedTransaction psbtx(rawTx);

    // First fill transaction with our data without signing,
    // so external signers are not asked to sign more than once.
    bool complete;
    pwallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
    const TransactionError err{pwallet->FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false)};
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    CMutableTransaction mtx;
    complete = pwallet->FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);

    const bool psbt_opt_in{options.exists("psbt") && options["psbt"].get_bool()};
    bool add_to_wallet{options.exists("add_to_wallet") ? options["add_to_wallet"].get_bool() : true};
    if (psbt_opt_in || !complete || !add_to_wallet) {
        // Serialize the PSBT
        CDataStream ssTx(SER_NETWORK);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
    }

    if (complete) {
        std::string hex{EncodeHexTx(CTransaction(mtx))};
        CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
        result.pushKV("txid", tx->GetHash().GetHex());
        if (add_to_wallet && !psbt_opt_in) {
            pwallet->CommitTransaction(tx, {}, /*orderForm=*/{});
        } else {
            result.pushKV("hex", hex);
        }
    }
    result.pushKV("complete", complete);

    return result;
}

static void PreventOutdatedOptions(const UniValue& options)
{
    if (options.exists("feeRate")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use fee_rate (" + CURRENCY_ATOM + "/vB) instead of feeRate");
    }
    if (options.exists("changeAddress")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use change_address instead of changeAddress");
    }
    if (options.exists("changePosition")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use change_position instead of changePosition");
    }
    if (options.exists("includeWatching")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use include_watching instead of includeWatching");
    }
    if (options.exists("lockUnspents")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use lock_unspents instead of lockUnspents");
    }
    if (options.exists("subtractFeeFromOutputs")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use subtract_fee_from_outputs instead of subtractFeeFromOutputs");
    }
}

UniValue SendMoney(CWallet& wallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose)
{
    EnsureWalletIsUnlocked(wallet);

    // This function is only used by sendtoaddress and sendmany.
    // This should always try to sign, if we don't have private keys, don't try to do anything here.
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    if (wallet.m_wallet_unlock_staking_only)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet unlocked for staking only, unable to create transaction");

    // Shuffle recipient list
    std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

    // Send
    constexpr int RANDOM_CHANGE_POSITION = -1;
    auto res = CreateTransaction(wallet, recipients, RANDOM_CHANGE_POSITION, coin_control, true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
    }
    const CTransactionRef& tx = res->tx;
    wallet.CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});
    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", tx->GetHash().GetHex());
        entry.pushKV("fee_reason", "Minimum required fee");
        return entry;
    }
    return tx->GetHash().GetHex();
}

// Blackcoin: burn RPC
RPCHelpMan burn()
{
    return RPCHelpMan{"burn",
            "\nBurn specified amount of coins\n"
            "This will make specified amount of coins unspendable, making OP_RETURN transaction.\n" +
        HELP_REQUIRING_PASSPHRASE,
            {
                {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to burn. eg 0.1"},
                {"hex_string", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded string."},
            },
            RPCResult{
                RPCResult::Type::STR_HEX, "txid", "The transaction id."
            },
            RPCExamples{
                HelpExampleCli("burn", "0.1 \"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CScript scriptPubKey;
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    if (request.params.size() > 1) {
        std::vector<unsigned char> data;
        if (request.params[1].get_str().size() > 0){
            data = ParseHexV(request.params[1], "data");
        } else {
            // Empty data is valid
        }
        scriptPubKey = CScript() << OP_RETURN << data;
    } else {
        scriptPubKey = CScript() << OP_RETURN;
    }

    CAmount nAmount = AmountFromValue(request.params[0]);

    EnsureWalletIsUnlocked(*pwallet);

    CCoinControl coin_control;
    mapValue_t mapValue;

    return SendMoneyToScript(*pwallet, scriptPubKey, nAmount, coin_control, std::move(mapValue));
},
    };
}

// Blackcoin: burnwallet RPC
RPCHelpMan burnwallet()
{
    return RPCHelpMan{"burnwallet",
            "\nBurn all coins in a wallet\n"
            "This will make all coins unspendable, making OP_RETURN transaction.\n" +
        HELP_REQUIRING_PASSPHRASE,
            {
                {"hex_string", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded string."},
                {"force", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Force burn."},
            },
            RPCResult{
                RPCResult::Type::STR_HEX, "txid", "The transaction id."
            },
            RPCExamples{
                HelpExampleCli("burnwallet", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CScript scriptPubKey;
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    if (request.params.size() > 0) {
        std::vector<unsigned char> data;
        if (request.params[0].get_str().size() > 0){
            data = ParseHexV(request.params[0], "data");
        } else {
            // Empty data is valid
        }
        scriptPubKey = CScript() << OP_RETURN << data;
    } else {
        scriptPubKey = CScript() << OP_RETURN;
    }

    bool fForce = false;
    if (request.params.size() > 1)
        fForce = request.params[1].get_bool();

    EnsureWalletIsUnlocked(*pwallet);

    CCoinControl coin_control;
    mapValue_t mapValue;

    const auto bal = GetBalance(*pwallet);
    CAmount nAmount = bal.m_mine_trusted;

    if (!fForce) {
        if (scriptPubKey.size() <= 32)
            throw JSONRPCError(RPC_WALLET_ERROR, "Warning: small data");
        if (bal.m_mine_stake != 0)
            throw JSONRPCError(RPC_WALLET_ERROR, "Warning: stake balance != 0");
        if (bal.m_mine_untrusted_pending != 0)
            throw JSONRPCError(RPC_WALLET_ERROR, "Warning: unconfirmed balance != 0");
        if (bal.m_mine_immature != 0)
            throw JSONRPCError(RPC_WALLET_ERROR, "Warning: immature balance != 0");
    }

    std::vector<CRecipient> recipients;
    CTxDestination dest;
    ExtractDestination(scriptPubKey, dest);
    CRecipient recipient = {dest, nAmount, true};
    recipients.push_back(recipient);

    // Shuffle recipient list
    std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

    // Send
    constexpr int RANDOM_CHANGE_POSITION = -1;
    auto res = CreateTransaction(*pwallet, recipients, RANDOM_CHANGE_POSITION, coin_control, true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
    }
    const CTransactionRef& tx = res->tx;
    pwallet->CommitTransaction(tx, std::move(mapValue), {});

    return tx->GetHash().GetHex();
},
    };
}

// Peercoin
RPCHelpMan optimizeutxoset()
{
    return RPCHelpMan{"optimizeutxoset",
                "\nOptimize the UTXO set in order to maximize the PoS yield. This is only valid for continuous minting. The accumulated coinage will be reset!" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Blackcoin address to recieve all the new UTXOs. If not provided, new UTOXs will be assigned to the address of the input UTXOs."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The " + CURRENCY_UNIT + " amount to set the value of new UTXOs, i.e. make new UTXOs with value of 1000. If amount is not provided, hardcoded value will be used."},
                    {"transmit", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, transmit transaction after generating it."},
                    {"fromAddress", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The Blackcoin address to split coins from. If not provided, all available coins will be used."},
                },
                {
                    RPCResult{"if transmit is not set or set to false",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "tx", /*optional=*/true, "The transaction hex."}
                        },
                    },
                    RPCResult{"if transmit is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id."}
                        },
                    },
                },
                RPCExamples{
                    "\nTrigger UTXO optimization and assign all the new UTXOs to some Blackcoin address with user defined UTXO value\n"
                    + HelpExampleCli("optimizeutxoset", EXAMPLE_ADDRESS[0] + " 1000")
               },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    CAmount availableCoins = 0;
    mapValue_t mapValue;
    CCoinControl coin_control;
    const std::string address = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(address);

    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Blackcoin address: ") + address);
    }

    coin_control.destChange = dest;
    CAmount amount = AmountFromValue(request.params[1]);

    std::vector<CRecipient> recipients;
    const bool transmit{request.params[2].isNull() ? false : request.params[2].get_bool()};

    if (request.params[3].isNull() == false) {
        CTxDestination tmpAddress, fromAddress;
        fromAddress = DecodeDestination(request.params[3].get_str());

        if (!IsValidDestination(fromAddress)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Blackcoin address: ") + request.params[3].get_str());
        }

        std::vector<COutput> vAvailableCoins = AvailableCoins(*pwallet, &coin_control).All();
        for (const COutput& out : vAvailableCoins) {
            const CScript& scriptPubKey = out.txout.scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, tmpAddress);
            if (fValidAddress && (tmpAddress == fromAddress)) {
                coin_control.Select(out.outpoint);
                availableCoins += out.txout.nValue;
            }
        }
        coin_control.m_allow_other_inputs = false;
    } else {
        const auto bal = GetBalance(*pwallet);
        availableCoins = bal.m_mine_trusted;
    }

    if (availableCoins == 0)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No available coins to optimize");

    LogPrintf("optimizing outputs %d satoshis\n", availableCoins);
    CScript script_pub_key = GetScriptForDestination(dest);
    CAmount remaining = availableCoins;

    CRecipient recipient = {dest, amount, false};
    CMutableTransaction txTmp;
    const uint32_t nSequence{CTxIn::MAX_SEQUENCE_NONFINAL};
    std::vector<COutPoint> preset_inputs = coin_control.ListSelected();
    for (const COutPoint& outpoint : preset_inputs) {
        txTmp.vin.push_back(CTxIn(outpoint, CScript(), nSequence));
    }

    // Calculate transaction input size
    const CWallet& wallet{*pwallet};
    TxSize tx_sizes = CalculateMaximumSignedTxSize(CTransaction(txTmp), &wallet, &coin_control);
    int nBytes = tx_sizes.vsize;

    // calculate size of output
    CTxOut txout(amount, script_pub_key);
    txTmp.vout.push_back(txout);
    tx_sizes = CalculateMaximumSignedTxSize(CTransaction(txTmp), &wallet, &coin_control);
    int nBytesPerOut = tx_sizes.vsize - nBytes;

    CAmount fee = GetMinFee(nBytes + (unsigned int)(remaining / amount) * nBytesPerOut, GetAdjustedTimeSeconds());
    while (remaining > amount + fee) {
        recipients.push_back(recipient);
        remaining -= amount;
    }

    // Send
    constexpr int RANDOM_CHANGE_POSITION = -1;
    auto res = CreateTransaction(*pwallet, recipients, RANDOM_CHANGE_POSITION, coin_control, true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
    }
    const CTransactionRef& tx = res->tx;

    UniValue entry(UniValue::VOBJ);
    if (transmit) {
        pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */);
        entry.pushKV("txid", tx->GetHash().GetHex());
    }
    else {
        entry.pushKV("tx", EncodeHexTx(*tx));
    }
    return entry;
},
    };
}


RPCHelpMan sendtoaddress()
{
    return RPCHelpMan{"sendtoaddress",
                "\nSend an amount to a given address." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Blackcoin address to send to."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment used to store what the transaction is for.\n"
                                         "This is not part of the transaction, just kept in your wallet."},
                    {"comment_to", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment to store the name of the person or organization\n"
                                         "to which you're sending the transaction. This is not part of the \n"
                                         "transaction, just kept in your wallet."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "The fee will be deducted from the amount being sent.\n"
                                         "The recipient will receive less blackcoins than you enter in the amount field."},
                    {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Avoid spending from dirty addresses; addresses are considered\n"
                                         "dirty if they have previously been used in a transaction. If true, this also activates avoidpartialspends, grouping outputs by their addresses."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::STR, "fee_reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
                    "\nSend 0.1 BLK\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1") +
                    "\nSend 0.1 BLK using positional arguments\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1 \"donation\" \"sean's outpost\" false true") +
                    "\nSend 0.2 BLK using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.2") +
                    "\nSend 0.5 BLK with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25")
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25 subtractfeefromamount=false avoid_reuse=true comment=\"2 pizzas\" comment_to=\"jeremy\" verbose=true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    // Wallet comments
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["to"] = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coin_control;

    coin_control.m_avoid_address_reuse = GetAvoidReuseFlag(*pwallet, request.params[5]);
    // We also enable partial spend avoidance if reuse avoidance is set.
    coin_control.m_avoid_partial_spends |= coin_control.m_avoid_address_reuse;
    if (!request.params[6].isNull()) {
        coin_control.m_feerate = FeeRateFromSatVbValue(request.params[6]);
        coin_control.fOverrideFeeRate = true;
    }

    EnsureWalletIsUnlocked(*pwallet);

    UniValue address_amounts(UniValue::VOBJ);
    const std::string address = request.params[0].get_str();
    address_amounts.pushKV(address, request.params[1]);
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (fSubtractFeeFromAmount) {
        subtractFeeFromAmount.push_back(address);
    }

    std::vector<CRecipient> recipients;
    ParseRecipients(address_amounts, subtractFeeFromAmount, recipients);
    const bool verbose{request.params[7].isNull() ? false : request.params[7].get_bool()};
    ApplyRecipientInputFamily(coin_control, recipients);

    return SendMoney(*pwallet, coin_control, recipients, mapValue, verbose);
},
    };
}

RPCHelpMan sendmany()
{
    return RPCHelpMan{"sendmany",
        "Send multiple times. Amounts are double-precision floating point numbers." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"dummy", RPCArg::Type::STR, RPCArg::Default{"\"\""}, "Must be set to \"\" for backwards compatibility.",
                     RPCArgOptions{
                         .oneline_description = "\"\"",
                     }},
                    {"amounts", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The addresses and amounts",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The Blackcoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value"},
                        },
                    },
                    {"minconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Ignored dummy value"},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment"},
                    {"subtractfeefrom", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The addresses.\n"
                                       "The fee will be equally deducted from the amount of each selected address.\n"
                                       "Those recipients will receive less blackcoins than you enter in their corresponding amount field.\n"
                                       "If no addresses are specified here, the sender pays the fee.",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Subtract fee from this address"},
                        },
                    },
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."},
                            {RPCResult::Type::STR, "fee_reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" 1 \"\" \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("sendmany", "\"\", {\"" + EXAMPLE_ADDRESS[0] + "\":0.01,\"" + EXAMPLE_ADDRESS[1] + "\":0.02}, 6, \"testing\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Dummy value must be set to \"\"");
    }
    UniValue sendTo = request.params[1].get_obj();

    mapValue_t mapValue;
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (!request.params[4].isNull())
        subtractFeeFromAmount = request.params[4].get_array();

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.m_feerate = FeeRateFromSatVbValue(request.params[5]);
        coin_control.fOverrideFeeRate = true;
    }

    std::vector<CRecipient> recipients;
    ParseRecipients(sendTo, subtractFeeFromAmount, recipients);
    const bool verbose{request.params[6].isNull() ? false : request.params[6].get_bool()};
    ApplyRecipientInputFamily(coin_control, recipients);

    return SendMoney(*pwallet, coin_control, recipients, std::move(mapValue), verbose);
},
    };
}

RPCHelpMan settxfee()
{
    return RPCHelpMan{"settxfee",
                "\nSet the transaction fee rate in " + CURRENCY_UNIT + "/kvB for this wallet. Overrides the global -paytxfee command line parameter.\n"
                "Can be deactivated by passing 0 as the fee. In that case automatic fee selection will be used by default.\n",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The transaction fee rate in " + CURRENCY_UNIT + "/kvB"},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true if successful"
                },
                RPCExamples{
                    HelpExampleCli("settxfee", "0.00001")
            + HelpExampleRpc("settxfee", "0.00001")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CAmount nAmount = AmountFromValue(request.params[0]);
    CFeeRate tx_fee_rate(nAmount, 1000);
    CFeeRate max_tx_fee_rate(pwallet->m_default_max_tx_fee, 1000);
    if (tx_fee_rate == CFeeRate(0)) {
        // automatic selection
    } else if (tx_fee_rate < pwallet->chain().relayMinFee()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("txfee cannot be less than min relay tx fee (%s)", pwallet->chain().relayMinFee().ToString()));
    } else if (tx_fee_rate > max_tx_fee_rate) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("txfee cannot be more than wallet max tx fee (%s)", max_tx_fee_rate.ToString()));
    }

    pwallet->m_pay_tx_fee = tx_fee_rate;
    return true;
},
    };
}


// Only includes key documentation where the key is snake_case in all RPC methods. MixedCase keys can be added later.
static std::vector<RPCArg> FundTxDoc(bool solving_data = true)
{
    std::vector<RPCArg> args = {
    };
    if (solving_data) {
        args.push_back({"solving_data", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Keys and scripts needed for producing a final transaction with a dummy signature.\n"
        "Used for fee estimation during coin selection.",
            {
                {
                    "pubkeys", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Public keys involved in this transaction.",
                    {
                        {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A public key"},
                    }
                },
                {
                    "scripts", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Scripts involved in this transaction.",
                    {
                        {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A script"},
                    }
                },
                {
                    "descriptors", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Descriptors that provide solving data for this transaction.",
                    {
                        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A descriptor"},
                    }
                },
            }
        });
    }
    return args;
}

void FundTransaction(CWallet& wallet, CMutableTransaction& tx, CAmount& fee_out, int& change_position, const UniValue& options, CCoinControl& coinControl, bool override_min_fee)
{
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    change_position = -1;
    bool lockUnspents = false;
    UniValue subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    if (!options.isNull()) {
      if (options.type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        coinControl.fAllowWatchOnly = options.get_bool();
      }
      else {
        RPCTypeCheckObj(options,
            {
                {"add_inputs", UniValueType(UniValue::VBOOL)},
                {"include_unsafe", UniValueType(UniValue::VBOOL)},
                {"add_to_wallet", UniValueType(UniValue::VBOOL)},
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"change_address", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"change_position", UniValueType(UniValue::VNUM)},
                {"change_type", UniValueType(UniValue::VSTR)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"include_watching", UniValueType(UniValue::VBOOL)},
                {"inputs", UniValueType(UniValue::VARR)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"lock_unspents", UniValueType(UniValue::VBOOL)},
                {"locktime", UniValueType(UniValue::VNUM)},
                {"fee_rate", UniValueType()}, // will be checked by AmountFromValue()
                {"feeRate", UniValueType()}, // will be checked by AmountFromValue() below
                {"psbt", UniValueType(UniValue::VBOOL)},
                {"solving_data", UniValueType(UniValue::VOBJ)},
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
                {"subtract_fee_from_outputs", UniValueType(UniValue::VARR)},
                {"input_weights", UniValueType(UniValue::VARR)},
            },
            true, true);

        if (options.exists("add_inputs")) {
            coinControl.m_allow_other_inputs = options["add_inputs"].get_bool();
        }

        if (options.exists("changeAddress") || options.exists("change_address")) {
            const std::string change_address_str = (options.exists("change_address") ? options["change_address"] : options["changeAddress"]).get_str();
            CTxDestination dest = DecodeDestination(change_address_str);

            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Change address must be a valid Blackcoin address");
            }

            coinControl.destChange = dest;
        }

        if (options.exists("changePosition") || options.exists("change_position")) {
            change_position = (options.exists("change_position") ? options["change_position"] : options["changePosition"]).getInt<int>();
        }

        if (options.exists("change_type")) {
            if (options.exists("changeAddress") || options.exists("change_address")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both change address and address type options");
            }
            if (std::optional<OutputType> parsed = ParseOutputType(options["change_type"].get_str())) {
                coinControl.m_change_type.emplace(parsed.value());
            } else {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown change type '%s'", options["change_type"].get_str()));
            }
        }

        const UniValue include_watching_option = options.exists("include_watching") ? options["include_watching"] : options["includeWatching"];
        coinControl.fAllowWatchOnly = ParseIncludeWatchonly(include_watching_option, wallet);

        if (options.exists("lockUnspents") || options.exists("lock_unspents")) {
            lockUnspents = (options.exists("lock_unspents") ? options["lock_unspents"] : options["lockUnspents"]).get_bool();
        }

        if (options.exists("include_unsafe")) {
            coinControl.m_include_unsafe_inputs = options["include_unsafe"].get_bool();
        }

        if (options.exists("feeRate")) {
            if (options.exists("fee_rate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both fee_rate (" + CURRENCY_ATOM + "/vB) and feeRate (" + CURRENCY_UNIT + "/kvB)");
            }
            coinControl.m_feerate = CFeeRate(AmountFromValue(options["feeRate"]));
            coinControl.fOverrideFeeRate = true;
        }
        if (options.exists("fee_rate")) {
            coinControl.m_feerate = FeeRateFromSatVbValue(options["fee_rate"]);
            coinControl.fOverrideFeeRate = true;
        }

        if (options.exists("subtractFeeFromOutputs") || options.exists("subtract_fee_from_outputs") )
            subtractFeeFromOutputs = (options.exists("subtract_fee_from_outputs") ? options["subtract_fee_from_outputs"] : options["subtractFeeFromOutputs"]).get_array();

      }
    } else {
        // if options is null and not a bool
        coinControl.fAllowWatchOnly = ParseIncludeWatchonly(NullUniValue, wallet);
    }

    if (options.exists("solving_data")) {
        const UniValue solving_data = options["solving_data"].get_obj();
        if (solving_data.exists("pubkeys")) {
            for (const UniValue& pk_univ : solving_data["pubkeys"].get_array().getValues()) {
                const std::string& pk_str = pk_univ.get_str();
                if (!IsHex(pk_str)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("'%s' is not hex", pk_str));
                }
                const std::vector<unsigned char> data(ParseHex(pk_str));
                const CPubKey pubkey(data.begin(), data.end());
                if (!pubkey.IsFullyValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("'%s' is not a valid public key", pk_str));
                }
                coinControl.m_external_provider.pubkeys.emplace(pubkey.GetID(), pubkey);
                // Add witness script for pubkeys
                const CScript wit_script = GetScriptForDestination(WitnessV0KeyHash(pubkey));
                coinControl.m_external_provider.scripts.emplace(CScriptID(wit_script), wit_script);
            }
        }

        if (solving_data.exists("scripts")) {
            for (const UniValue& script_univ : solving_data["scripts"].get_array().getValues()) {
                const std::string& script_str = script_univ.get_str();
                if (!IsHex(script_str)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("'%s' is not hex", script_str));
                }
                std::vector<unsigned char> script_data(ParseHex(script_str));
                const CScript script(script_data.begin(), script_data.end());
                coinControl.m_external_provider.scripts.emplace(CScriptID(script), script);
            }
        }

        if (solving_data.exists("descriptors")) {
            for (const UniValue& desc_univ : solving_data["descriptors"].get_array().getValues()) {
                const std::string& desc_str  = desc_univ.get_str();
                FlatSigningProvider desc_out;
                std::string error;
                std::vector<CScript> scripts_temp;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, desc_out, error, true);
                if (!desc) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unable to parse descriptor '%s': %s", desc_str, error));
                }
                desc->Expand(0, desc_out, scripts_temp, desc_out);
                coinControl.m_external_provider.Merge(std::move(desc_out));
            }
        }
    }

    if (options.exists("input_weights")) {
        for (const UniValue& input : options["input_weights"].get_array().getValues()) {
            uint256 txid = ParseHashO(input, "txid");

            const UniValue& vout_v = input.find_value("vout");
            if (!vout_v.isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
            }
            int vout = vout_v.getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");
            }

            const UniValue& weight_v = input.find_value("weight");
            if (!weight_v.isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing weight key");
            }
            int64_t weight = weight_v.getInt<int64_t>();
            const int64_t min_input_weight = GetTransactionInputWeight(CTxIn());
            CHECK_NONFATAL(min_input_weight == 165);
            if (weight < min_input_weight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, weight cannot be less than 165 (41 bytes (size of outpoint + sequence + empty scriptSig) * 4 (witness scaling factor)) + 1 (empty witness)");
            }
            if (weight > MAX_STANDARD_TX_WEIGHT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, weight cannot be greater than the maximum standard tx weight of %d", MAX_STANDARD_TX_WEIGHT));
            }

            coinControl.SetInputWeight(COutPoint(txid, vout), weight);
        }
    }

    if (tx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (coinControl.m_allow_other_inputs) {
        ApplyOutputInputFamily(coinControl, tx.vout);
    }

    if (change_position != -1 && (change_position < 0 || (unsigned int)change_position > tx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].getInt<int>();
        if (setSubtractFeeFromOutputs.count(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        if (pos >= int(tx.vout.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        setSubtractFeeFromOutputs.insert(pos);
    }

    bilingual_str error;

    if (!FundTransaction(wallet, tx, fee_out, change_position, error, lockUnspents, setSubtractFeeFromOutputs, coinControl)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
}

static void SetOptionsInputWeights(const UniValue& inputs, UniValue& options)
{
    if (options.exists("input_weights")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Input weights should be specified in inputs rather than in options.");
    }
    if (inputs.size() == 0) {
        return;
    }
    UniValue weights(UniValue::VARR);
    for (const UniValue& input : inputs.getValues()) {
        if (input.exists("weight")) {
            weights.push_back(input);
        }
    }
    options.pushKV("input_weights", weights);
}

RPCHelpMan fundrawtransaction()
{
    return RPCHelpMan{"fundrawtransaction",
                "\nIf the transaction has no inputs, they will be automatically selected to meet its out value.\n"
                "It will add at most one change output to the outputs.\n"
                "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                "The inputs added will not be signed, use signrawtransactionwithkey\n"
                "or signrawtransactionwithwallet for that.\n"
                "All existing inputs must either have their previous output transaction be in the wallet\n"
                "or be in the UTXO set. Solving data must be provided for non-wallet inputs.\n"
                "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "For backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}",
                        Cat<std::vector<RPCArg>>(
                        {
                            {"add_inputs", RPCArg::Type::BOOL, RPCArg::Default{true}, "For a transaction with existing inputs, automatically include more if they are not enough."},
                            {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                            {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                            {"changeAddress", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Blackcoin address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                            {"change_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -changetype"}, "The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", \"bech32\", and \"bech32m\"."},
                            {"includeWatching", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also select inputs which are watch only.\n"
                                                          "Only solvable inputs can be used. Watch-only destinations are solvable if the public key and/or output script was imported,\n"
                                                          "e.g. with 'importpubkey' or 'importmulti' with the 'pubkeys' or 'desc' field."},
                            {"lockUnspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"feeRate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_UNIT + "/kvB."},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The integers.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less blackcoins than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                            {"input_weights", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Inputs and their corresponding weights",
                                {
                                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                        {
                                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output index"},
                                            {"weight", RPCArg::Type::NUM, RPCArg::Optional::NO, "The maximum weight for this input, "
                                                "including the weight of the outpoint and sequence number. "
                                                "Note that serialized signature sizes are not guaranteed to be consistent, "
                                                "so the maximum DER signatures size of 73 bytes should be used when considering ECDSA signatures."
                                                "Remember to convert serialized sizes to weight units when necessary."},
                                        },
                                    },
                                },
                             },
                        },
                        FundTxDoc()),
                        RPCArgOptions{
                            .skip_type_check = true,
                            .oneline_description = "options",
                        }},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The resulting raw transaction (hex-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransactionwithwallet", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // parse hex string from parameter
    CMutableTransaction tx;
    bool try_witness = request.params[2].isNull() ? true : request.params[2].get_bool();
    bool try_no_witness = request.params[2].isNull() ? true : !request.params[2].get_bool();
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    CAmount fee;
    int change_position;
    CCoinControl coin_control;
    // Automatically select (additional) coins. Can be overridden by options.add_inputs.
    coin_control.m_allow_other_inputs = true;
    FundTransaction(*pwallet, tx, fee, change_position, request.params[1], coin_control, /*override_min_fee=*/true);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("changepos", change_position);

    return result;
},
    };
}

RPCHelpMan signrawtransactionwithwallet()
{
    return RPCHelpMan{"signrawtransactionwithwallet",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                                },
                            },
                        },
                    },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"")
            + HelpExampleRpc("signrawtransactionwithwallet", "\"myhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    // Sign the transaction
    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[1], nullptr, coins);

    int nHashType = ParseSighashString(request.params[2]);

    // Script verification errors
    std::map<int, bilingual_str> input_errors;

    bool complete = pwallet->SignTransaction(mtx, coins, nHashType, input_errors);
    UniValue result(UniValue::VOBJ);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
    return result;
},
    };
}

// Definition of allowed formats of specifying transaction outputs in
// `send` and `walletcreatefundedpsbt` RPCs.
static std::vector<RPCArg> OutputsDoc()
{
    return
    {
        {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
            {
                {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Blackcoin address,\n"
                         "the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
            },
        },
        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
            {
                {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"},
                {"rgb_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"rgb_commitment\", the value is a 32-byte RGB state commitment"},
                {"eutxo", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A key-value pair. The key must be \"eutxo\", the value describes a V4 EUTXO commitment",
                    {
                        {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT},
                        {"datum", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded datum committed by the EUTXO output"},
                        {"validator", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded validator script committed by the EUTXO output"},
                    },
                },
            },
        },
    };
}

RPCHelpMan send()
{
    return RPCHelpMan{"send",
        "\nEXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nSend a transaction.\n",
        {
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                    "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                    "At least one output of either type must be specified.\n"
                    "For convenience, a dictionary, which holds the key-value pairs directly, is also accepted.",
                OutputsDoc(),
                RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                Cat<std::vector<RPCArg>>(
                {
                    {"add_inputs", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false when \"inputs\" are specified, true otherwise"},"Automatically include coins from the wallet to cover the target amount.\n"},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                    {"add_to_wallet", RPCArg::Type::BOOL, RPCArg::Default{true}, "When false, returns a serialized transaction which will not be added to the wallet or broadcast"},
                    {"change_address", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Blackcoin address to receive the change"},
                    {"change_position", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                    {"change_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -changetype"}, "The output type to use. Only valid if change_address is not specified. Options are \"legacy\", \"p2sh-segwit\", \"bech32\" and \"bech32m\"."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB.", RPCArgOptions{.also_positional = true}},
                    {"include_watching", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also select inputs which are watch only.\n"
                                          "Only solvable inputs can be used. Watch-only destinations are solvable if the public key and/or output script was imported,\n"
                                          "e.g. with 'importpubkey' or 'importmulti' with the 'pubkeys' or 'desc' field."},
                    {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Specify inputs instead of adding them automatically. A JSON array of JSON objects",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::NO, "The sequence number"},
                            {"weight", RPCArg::Type::NUM, RPCArg::DefaultHint{"Calculated from wallet and solving data"}, "The maximum weight for this input, "
                                        "including the weight of the outpoint and sequence number. "
                                        "Note that signature sizes are not guaranteed to be consistent, "
                                        "so the maximum DER signatures size of 73 bytes should be used when considering ECDSA signatures."
                                        "Remember to convert serialized sizes to weight units when necessary."},
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                    {"psbt", RPCArg::Type::BOOL,  RPCArg::DefaultHint{"automatic"}, "Always return a PSBT, implies add_to_wallet=false."},
                    {"subtract_fee_from_outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Outputs to subtract the fee from, specified as integer indices.\n"
                    "The fee will be equally deducted from the amount of each specified output.\n"
                    "Those recipients will receive less blackcoins than you enter in their corresponding amount field.\n"
                    "If no outputs are specified here, the sender pays the fee.",
                        {
                            {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                        },
                    },
                },
                FundTxDoc()),
                RPCArgOptions{.oneline_description="options"}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id for the send. Only 1 transaction is created regardless of the number of addresses."},
                    {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "If add_to_wallet is false, the hex-encoded raw transaction with signature(s)"},
                    {RPCResult::Type::STR, "psbt", /*optional=*/true, "If more signatures are needed, or if add_to_wallet is false, the base64-encoded (partially) signed transaction"}
                }
        },
        RPCExamples{""
        "\nSend 0.1 BTC with a confirmation target of 6 blocks in economical fee estimate mode\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 6 economical\n") +
        "Send 0.2 BTC with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB using positional arguments\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" 1.1\n") +
        "Send 0.2 BTC with a fee rate of 1 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" null '{\"fee_rate\": 1}'\n") +
        "Send 0.3 BTC with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
        + HelpExampleCli("-named send", "outputs='{\"" + EXAMPLE_ADDRESS[0] + "\": 0.3}' fee_rate=25\n") +
        "Create a transaction that should confirm the next block, with a specific input, and return result without adding to wallet or broadcasting to the network\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 1 economical '{\"add_to_wallet\": false, \"inputs\": [{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\", \"vout\":1}]}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            UniValue options{request.params[4].isNull() ? (request.params[1].isObject() ? request.params[1] : UniValue(UniValue::VOBJ)) : request.params[4]};
            PreventOutdatedOptions(options);


            CAmount fee;
            int change_position;
            CMutableTransaction rawTx = ConstructTransaction(options["inputs"], request.params[0], options["locktime"]);
            CCoinControl coin_control;
            // Automatically select coins, unless at least one is manually selected. Can
            // be overridden by options.add_inputs.
            coin_control.m_allow_other_inputs = rawTx.vin.size() == 0;
            SetOptionsInputWeights(options["inputs"], options);
            FundTransaction(*pwallet, rawTx, fee, change_position, options, coin_control, /*override_min_fee=*/false);

            return FinishTransaction(pwallet, options, rawTx);
        }
    };
}

RPCHelpMan sendall()
{
    return RPCHelpMan{"sendall",
        "EXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nSpend the value of all (or specific) confirmed UTXOs in the wallet to one or more recipients.\n"
        "Unconfirmed inbound UTXOs and locked UTXOs will not be spent. Sendall will respect the avoid_reuse wallet flag.\n"
        "If your wallet contains many small inputs, either because it received tiny payments or as a result of accumulating change, consider using `send_max` to exclude inputs that are worth less than the fees needed to spend them.\n",
        {
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "The sendall destinations. Each address may only appear once.\n"
                "Optionally some recipients can be specified with an amount to perform payments, but at least one address must appear without a specified amount.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "A Blackcoin address which receives an equal share of the unspecified amount."},
                    {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Blackcoin address, the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
                        },
                    },
                },
            },
            {
                "options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                Cat<std::vector<RPCArg>>(
                    {
                        {"add_to_wallet", RPCArg::Type::BOOL, RPCArg::Default{true}, "When false, returns the serialized transaction without broadcasting or adding it to the wallet"},
                        {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB.", RPCArgOptions{.also_positional = true}},
                        {"include_watching", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also select inputs which are watch-only.\n"
                                              "Only solvable inputs can be used. Watch-only destinations are solvable if the public key and/or output script was imported,\n"
                                              "e.g. with 'importpubkey' or 'importmulti' with the 'pubkeys' or 'desc' field."},
                        {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Use exactly the specified inputs to build the transaction. Specifying inputs is incompatible with the send_max, minconf, and maxconf options.",
                            {
                                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                    {
                                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                                    },
                                },
                            },
                        },
                        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                        {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                        {"psbt", RPCArg::Type::BOOL,  RPCArg::DefaultHint{"automatic"}, "Always return a PSBT, implies add_to_wallet=false."},
                        {"send_max", RPCArg::Type::BOOL, RPCArg::Default{false}, "When true, only use UTXOs that can pay for their own fees to maximize the output amount. When 'false' (default), no UTXO is left behind. send_max is incompatible with providing specific inputs."},
                        {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Require inputs with at least this many confirmations."},
                        {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Require inputs with at most this many confirmations."},
                    },
                    FundTxDoc()
                ),
                RPCArgOptions{.oneline_description="options"}
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id for the send. Only 1 transaction is created regardless of the number of addresses."},
                    {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "If add_to_wallet is false, the hex-encoded raw transaction with signature(s)"},
                    {RPCResult::Type::STR, "psbt", /*optional=*/true, "If more signatures are needed, or if add_to_wallet is false, the base64-encoded (partially) signed transaction"}
                }
        },
        RPCExamples{""
        "\nSpend all UTXOs from the wallet with a fee rate of 1 " + CURRENCY_ATOM + "/vB using named arguments\n"
        + HelpExampleCli("-named sendall", "recipients='[\"" + EXAMPLE_ADDRESS[0] + "\"]' fee_rate=1\n") +
        "Spend all UTXOs with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB using positional arguments\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\"]' null \"unset\" 1.1\n") +
        "Spend all UTXOs split into equal amounts to two addresses with a fee rate of 1.5 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\", \"" + EXAMPLE_ADDRESS[1] + "\"]' null \"unset\" null '{\"fee_rate\": 1.5}'\n") +
        "Leave dust UTXOs in wallet, spend only UTXOs with positive effective value with a fee rate of 10 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\"]' null \"unset\" null '{\"fee_rate\": 10, \"send_max\": true}'\n") +
        "Spend all UTXOs with a fee rate of 1.3 " + CURRENCY_ATOM + "/vB using named arguments and sending a 0.25 " + CURRENCY_UNIT + " to another recipient\n"
        + HelpExampleCli("-named sendall", "recipients='[{\"" + EXAMPLE_ADDRESS[1] + "\": 0.25}, \""+ EXAMPLE_ADDRESS[0] + "\"]' fee_rate=1.3\n")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;
            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue options{request.params[4].isNull() ? (request.params[1].isObject() ? request.params[1] : UniValue(UniValue::VOBJ)) : request.params[4]};
            PreventOutdatedOptions(options);


            std::set<std::string> addresses_without_amount;
            UniValue recipient_key_value_pairs(UniValue::VARR);
            const UniValue& recipients{request.params[0]};
            for (unsigned int i = 0; i < recipients.size(); ++i) {
                const UniValue& recipient{recipients[i]};
                if (recipient.isStr()) {
                    UniValue rkvp(UniValue::VOBJ);
                    rkvp.pushKV(recipient.get_str(), 0);
                    recipient_key_value_pairs.push_back(rkvp);
                    addresses_without_amount.insert(recipient.get_str());
                } else {
                    recipient_key_value_pairs.push_back(recipient);
                }
            }

            if (addresses_without_amount.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide at least one address without a specified amount");
            }

            CCoinControl coin_control;
            if (options.exists("fee_rate")) {
                coin_control.m_feerate = FeeRateFromSatVbValue(options["fee_rate"]);
                coin_control.fOverrideFeeRate = true;
            }

            coin_control.fAllowWatchOnly = ParseIncludeWatchonly(options["include_watching"], *pwallet);

            if (options.exists("minconf")) {
                if (options["minconf"].getInt<int>() < 0)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid minconf (minconf cannot be negative): %s", options["minconf"].getInt<int>()));
                }

                coin_control.m_min_depth = options["minconf"].getInt<int>();
            }

            if (options.exists("maxconf")) {
                coin_control.m_max_depth = options["maxconf"].getInt<int>();

                if (coin_control.m_max_depth < coin_control.m_min_depth) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("maxconf can't be lower than minconf: %d < %d", coin_control.m_max_depth, coin_control.m_min_depth));
                }
            }

            CFeeRate fee_rate{GetMinimumFeeRate(*pwallet, coin_control, GetAdjustedTimeSeconds())};
            // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly
            // provided one
            if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
               throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB)));
            }

            CMutableTransaction rawTx{ConstructTransaction(options["inputs"], recipient_key_value_pairs, options["locktime"])};
            LOCK(pwallet->cs_wallet);
            if (!options.exists("inputs")) {
                ApplyOutputInputFamily(coin_control, rawTx.vout);
            }

            CAmount total_input_value(0);
            bool send_max{options.exists("send_max") ? options["send_max"].get_bool() : false};
            if (options.exists("inputs") && options.exists("send_max")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine send_max with specific inputs.");
            } else if (options.exists("inputs") && (options.exists("minconf") || options.exists("maxconf"))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine minconf or maxconf with specific inputs.");
            } else if (options.exists("inputs")) {
                for (const CTxIn& input : rawTx.vin) {
                    if (pwallet->IsSpent(input.prevout)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input not available. UTXO (%s:%d) was already spent.", input.prevout.hash.ToString(), input.prevout.n));
                    }
                    const CWalletTx* tx{pwallet->GetWalletTx(input.prevout.hash)};
                    if (!tx || input.prevout.n >= tx->tx->vout.size() || !(pwallet->IsMine(tx->tx->vout[input.prevout.n]) & (coin_control.fAllowWatchOnly ? ISMINE_ALL : ISMINE_SPENDABLE))) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input not found. UTXO (%s:%d) is not part of wallet.", input.prevout.hash.ToString(), input.prevout.n));
                    }
                    total_input_value += tx->tx->vout[input.prevout.n].nValue;
                }
            } else {
                CoinFilterParams coins_params;
                coins_params.min_amount = 0;
                for (const COutput& output : AvailableCoins(*pwallet, &coin_control, fee_rate, coins_params).All()) {
                    CHECK_NONFATAL(output.input_bytes > 0);
                    if (send_max && fee_rate.GetFee(output.input_bytes) > output.txout.nValue) {
                        continue;
                    }
                    CTxIn input(output.outpoint.hash, output.outpoint.n, CScript(), CTxIn::SEQUENCE_FINAL);
                    rawTx.vin.push_back(input);
                    total_input_value += output.txout.nValue;
                }
            }

            // estimate final size of tx
            const TxSize tx_size{CalculateMaximumSignedTxSize(CTransaction(rawTx), pwallet.get())};
            if (tx_size.vsize == -1 || tx_size.weight == -1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Missing solving data for estimating transaction size");
            }
            const CAmount fee_from_size{std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), GetAdjustedTimeSeconds()), fee_rate.GetFee(tx_size.vsize))};
            const CAmount effective_value{total_input_value - fee_from_size};

            if (fee_from_size > pwallet->m_default_max_tx_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR, TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
            }

            if (effective_value <= 0) {
                if (send_max) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Total value of UTXO pool too low to pay for transaction, try using lower feerate.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Total value of UTXO pool too low to pay for transaction. Try using lower feerate or excluding uneconomic UTXOs with 'send_max' option.");
                }
            }

            // If this transaction is too large, e.g. because the wallet has many UTXOs, it will be rejected by the node's mempool.
            if (tx_size.weight > MAX_STANDARD_TX_WEIGHT) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction too large.");
            }

            CAmount output_amounts_claimed{0};
            for (const CTxOut& out : rawTx.vout) {
                output_amounts_claimed += out.nValue;
            }

            if (output_amounts_claimed > total_input_value) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Assigned more value to outputs than available funds.");
            }

            const CAmount remainder{effective_value - output_amounts_claimed};
            if (remainder < 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds for fees after creating specified outputs.");
            }

            const CAmount per_output_without_amount{remainder / (long)addresses_without_amount.size()};

            bool gave_remaining_to_first{false};
            for (CTxOut& out : rawTx.vout) {
                CTxDestination dest;
                ExtractDestination(out.scriptPubKey, dest);
                std::string addr{EncodeDestination(dest)};
                if (addresses_without_amount.count(addr) > 0) {
                    out.nValue = per_output_without_amount;
                    if (!gave_remaining_to_first) {
                        out.nValue += remainder % addresses_without_amount.size();
                        gave_remaining_to_first = true;
                    }
                    if (IsDust(out, pwallet->chain().relayDustFee())) {
                        // Dynamically generated output amount is dust
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Dynamically assigned remainder results in dust output.");
                    }
                } else {
                    if (IsDust(out, pwallet->chain().relayDustFee())) {
                        // Specified output amount is dust
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Specified output amount to %s is below dust threshold.", addr));
                    }
                }
            }

            const bool lock_unspents{options.exists("lock_unspents") ? options["lock_unspents"].get_bool() : false};
            if (lock_unspents) {
                for (const CTxIn& txin : rawTx.vin) {
                    pwallet->LockCoin(txin.prevout);
                }
            }

            return FinishTransaction(pwallet, options, rawTx);
        }
    };
}

RPCHelpMan walletprocesspsbt()
{
    return RPCHelpMan{"walletprocesspsbt",
                "\nUpdate a PSBT with input information from our wallet and then sign inputs\n"
                "that we can sign for." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"sign", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also sign the transaction when updating (requires wallet to be unlocked)"},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                    {"finalize", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also finalize inputs if possible"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The base64-encoded partially signed transaction"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if complete"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("walletprocesspsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet{*pwallet};
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    // Get the sighash type
    int nHashType = ParseSighashString(request.params[2]);

    // Fill transaction with our data and also sign
    bool sign = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool finalize = request.params[4].isNull() ? true : request.params[4].get_bool();
    bool complete = true;

    if (sign) EnsureWalletIsUnlocked(*pwallet);

    const TransactionError err{wallet.FillPSBT(psbtx, complete, nHashType, sign, bip32derivs, nullptr, finalize)};
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    UniValue result(UniValue::VOBJ);
    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("complete", complete);
    if (complete) {
        CMutableTransaction mtx;
        // Returns true if complete, which we already think it is.
        CHECK_NONFATAL(wallet.FinalizeAndExtractPSBT(psbtx, mtx));
        DataStream ssTx_final;
        ssTx_final << TX_WITH_WITNESS(mtx);
        result.pushKV("hex", HexStr(ssTx_final));
    }

    return result;
},
    };
}

RPCHelpMan walletcreatefundedpsbt()
{
    return RPCHelpMan{"walletcreatefundedpsbt",
                "\nCreates and funds a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator and Updater roles.\n"
                "All existing inputs must either have their previous output transaction be in the wallet\n"
                "or be in the UTXO set. Solving data must be provided for non-wallet inputs.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Leave empty to add inputs automatically. See add_inputs option.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'locktime' argument"}, "The sequence number"},
                                    {"weight", RPCArg::Type::NUM, RPCArg::DefaultHint{"Calculated from wallet and solving data"}, "The maximum weight for this input, "
                                        "including the weight of the outpoint and sequence number. "
                                        "Note that signature sizes are not guaranteed to be consistent, "
                                        "so the maximum DER signatures size of 73 bytes should be used when considering ECDSA signatures."
                                        "Remember to convert serialized sizes to weight units when necessary."},
                                },
                            },
                        },
                        },
                    {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                            "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                            "At least one output of either type must be specified.\n"
                            "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                            "accepted as second parameter.",
                        OutputsDoc(),
                        RPCArgOptions{.skip_type_check = true}},
                    {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        Cat<std::vector<RPCArg>>(
                        {
                            {"add_inputs", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false when \"inputs\" are specified, true otherwise"}, "Automatically include coins from the wallet to cover the target amount.\n"},
                            {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                            {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                            {"changeAddress", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Blackcoin address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                            {"change_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -changetype"}, "The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", \"bech32\", and \"bech32m\"."},
                            {"includeWatching", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also select inputs which are watch only"},
                            {"lockUnspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"feeRate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_UNIT + "/kvB."},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The outputs to subtract the fee from.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less blackcoins than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                        },
                        FundTxDoc()),
                        RPCArgOptions{.oneline_description="options"}},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The resulting raw transaction (base64-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("walletcreatefundedpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CWallet& wallet{*pwallet};
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    UniValue options{request.params[3].isNull() ? UniValue::VOBJ : request.params[3]};

    CAmount fee;
    int change_position;
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2]);
    CCoinControl coin_control;
    // Automatically select coins, unless at least one is manually selected. Can
    // be overridden by options.add_inputs.
    coin_control.m_allow_other_inputs = rawTx.vin.size() == 0;
    SetOptionsInputWeights(request.params[0], options);
    FundTransaction(wallet, rawTx, fee, change_position, options, coin_control, /*override_min_fee=*/true);

    // Make a blank psbt
    PartiallySignedTransaction psbtx(rawTx);

    // Fill transaction with out data but don't sign
    bool bip32derivs = request.params[4].isNull() ? true : request.params[4].get_bool();
    bool complete = true;
    const TransactionError err{wallet.FillPSBT(psbtx, complete, 1, /*sign=*/false, /*bip32derivs=*/bip32derivs)};
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("changepos", change_position);
    return result;
},
    };
}

static std::string QQPhaseName(Consensus::QuantumQuasarPhase phase)
{
    switch (phase) {
    case Consensus::QuantumQuasarPhase::LEGACY: return "legacy";
    case Consensus::QuantumQuasarPhase::GOLD_RUSH: return "gold_rush";
    case Consensus::QuantumQuasarPhase::MIGRATION: return "migration";
    case Consensus::QuantumQuasarPhase::FINAL_LOCKOUT: return "final_lockout";
    }
    return "unknown";
}

RPCHelpMan migratetoquantum()
{
    return RPCHelpMan{"migratetoquantum",
        "\nSweep all spendable legacy (non-quantum) coins in this wallet into a single\n"
        "wallet-backed Blackcoin ML-DSA migration (witness-v16) address.\n"
        "\nThe destination ML-DSA key is generated and written to the wallet database BEFORE\n"
        "any funds are moved; the call refuses to proceed unless the key is confirmed stored.\n"
        "Because ML-DSA keys are NOT derived from the wallet seed, you MUST back up the wallet\n"
        "again after a new address is generated, or the migrated funds can be lost on restore.\n"
        "\nAfter the migration deadline, legacy coins become permanently unspendable, so run this\n"
        "before the deadline reported by getmigrationstatus.\n",
        {
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Estimate only; do not sign, broadcast, or create a new quantum key. Requires existing_address."},
                    {"existing_address", RPCArg::Type::STR, RPCArg::Default{""}, "Migrate into this already-owned wallet-backed quantum address instead of generating a new one. Required for dry_run."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{"migration"}, "Label for a newly generated migration address."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet default"}, "Fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include unconfirmed/unsafe legacy coins."},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "phase", "current Blackcoin phase"},
            {RPCResult::Type::NUM_TIME, "deadline_mtp", "final migration deadline MTP (0 if unscheduled)"},
            {RPCResult::Type::NUM, "eligible_inputs", "count of legacy UTXOs swept"},
            {RPCResult::Type::STR_AMOUNT, "eligible_amount", "total legacy value selected"},
            {RPCResult::Type::STR, "destination", "quantum address funds were sent to"},
            {RPCResult::Type::BOOL, "newly_generated", "whether destination was freshly minted"},
            {RPCResult::Type::BOOL, "stored_in_wallet", "destination key confirmed persisted"},
            {RPCResult::Type::STR_AMOUNT, "amount", "value of migration output after fee"},
            {RPCResult::Type::STR_AMOUNT, "fee", "fee paid"},
            {RPCResult::Type::NUM, "vsize", "virtual transaction size"},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "txid (absent for dry_run)"},
            {RPCResult::Type::STR, "warning", /*optional=*/true, "backup reminder"},
        }},
        RPCExamples{
            HelpExampleCli("migratetoquantum", "")
          + HelpExampleCli("migratetoquantum", "'{\"dry_run\":true,\"existing_address\":\"<addr>\"}'")
          + HelpExampleRpc("migratetoquantum", "{\"existing_address\":\"<addr>\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();
        const bool dry_run = options.exists("dry_run") && options["dry_run"].get_bool();
        const bool include_unsafe = options.exists("include_unsafe") && options["include_unsafe"].get_bool();
        const std::string label = options.exists("label") ? options["label"].get_str() : "migration";
        const std::string existing = options.exists("existing_address") ? options["existing_address"].get_str() : "";
        if (dry_run && existing.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "dry_run requires existing_address so the estimate does not create wallet metadata");
        }

        LOCK2(cs_main, pwallet->cs_wallet);
        if (!dry_run) {
            EnsureWalletIsUnlocked(*pwallet);
            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
            }
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        int64_t mtp = 0;
        if (const CBlockIndex* tip = pwallet->chain().chainman().ActiveChain().Tip()) mtp = tip->GetMedianTimePast();
        if (consensus.IsQuantumFinalLockout(mtp)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "The migration deadline has passed; legacy coins are no longer spendable and cannot be migrated.");
        }
        const std::string phase = QQPhaseName(consensus.GetQuantumQuasarPhase(mtp));

        CTxDestination dest;
        bool newly_generated = false;
        if (!existing.empty()) {
            std::string err;
            dest = DecodeDestination(existing, err);
            const auto* w = std::get_if<WitnessUnknown>(&dest);
            if (!IsValidDestination(dest) || !w ||
                !IsQuantumMigrationWitnessProgram(w->GetWitnessVersion(), w->GetWitnessProgram())) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "existing_address is not a Blackcoin migration address");
            }
            if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "existing_address is not wallet-backed (no ML-DSA private key in this wallet)");
            }
        } else {
            auto op_dest = pwallet->GetNewQuantumDestination(label);
            if (!op_dest) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(op_dest).original);
            dest = *op_dest;
            newly_generated = true;
        }
        if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Refusing to migrate: destination ML-DSA key is not confirmed stored in the wallet.");
        }

        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = false;
        coin_control.m_include_unsafe_inputs = include_unsafe;
        coin_control.destChange = CNoDestination{};
        if (options.exists("fee_rate")) {
            coin_control.m_feerate = CFeeRate(AmountFromValue(options["fee_rate"]), COIN);
            coin_control.fOverrideFeeRate = true;
        }
        CoinFilterParams filter;
        filter.only_spendable = true;
        filter.skip_locked = true;
        filter.include_immature_coinbase = false;

        CAmount eligible_amount = 0;
        unsigned int eligible_inputs = 0;
        for (const COutput& out : AvailableCoins(*pwallet, &coin_control, std::nullopt, filter).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (IsQuantumMigrationScript(spk)) continue;
            if (IsQuantumColdStakeScript(spk)) continue;
            if (IsEUTXOScript(spk)) continue;
            if (!out.spendable) continue;
            coin_control.Select(out.outpoint);
            eligible_amount += out.txout.nValue;
            ++eligible_inputs;
        }
        if (eligible_inputs == 0) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable legacy coins to migrate.");
        }

        std::vector<CRecipient> recipients;
        recipients.push_back({dest, eligible_amount, /*fSubtractFeeFromAmount=*/true});

        constexpr int RANDOM_CHANGE_POSITION = -1;
        auto res = CreateTransaction(*pwallet, recipients, RANDOM_CHANGE_POSITION, coin_control, /*sign=*/!dry_run);
        if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);

        const CTransactionRef& tx = res->tx;
        if (tx->vout.size() != 1 || IsDust(tx->vout[0], pwallet->chain().relayDustFee())) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                "Migration would strand funds: swept value is below the dust threshold after fees.");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("phase", phase);
        result.pushKV("deadline_mtp", consensus.nQuantumMigrationDeadlineTime);
        result.pushKV("eligible_inputs", (int)eligible_inputs);
        result.pushKV("eligible_amount", ValueFromAmount(eligible_amount));
        result.pushKV("destination", EncodeDestination(dest));
        result.pushKV("newly_generated", newly_generated);
        result.pushKV("stored_in_wallet", true);
        result.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
        result.pushKV("fee", ValueFromAmount(res->fee));
        result.pushKV("vsize", (int)GetVirtualTransactionSize(*tx, 0, 0));
        if (!dry_run) {
            CommitWalletTransactionOrThrow(*pwallet, tx, {}, "Blackcoin quantum migration");
            result.pushKV("txid", tx->GetHash().GetHex());
        }
        if (newly_generated) {
            result.pushKV("warning",
                "A new ML-DSA migration address was created. ML-DSA keys are not recoverable from "
                "your seed phrase. Back up the wallet now (e.g. backupwallet) before relying on the "
                "migrated funds.");
        }
        return result;
    }};
}

RPCHelpMan migrategoldrushrewards()
{
    return RPCHelpMan{"migrategoldrushrewards",
        "\nMove wallet-owned Gold Rush reward outputs to a fresh Blackcoin ML-DSA\n"
        "migration address once quantum reward spends are active, including during Gold Rush, and before the final lockout deadline.\n",
        {
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Estimate only; do not sign, broadcast, or create a new quantum key. Requires existing_address."},
                    {"existing_address", RPCArg::Type::STR, RPCArg::Default{""}, "Move into this already-owned wallet-backed quantum address instead of generating a fresh one. Required for dry_run."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{"goldrush-remigration"}, "Label for a newly generated destination address."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet default"}, "Fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include unconfirmed/unsafe reward coins."},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "phase", "current Blackcoin phase"},
            {RPCResult::Type::NUM_TIME, "deadline_mtp", "final migration deadline MTP"},
            {RPCResult::Type::NUM, "eligible_inputs", "count of Gold Rush reward UTXOs moved"},
            {RPCResult::Type::STR_AMOUNT, "eligible_amount", "total Gold Rush reward value selected"},
            {RPCResult::Type::STR, "destination", "new quantum address funds were sent to"},
            {RPCResult::Type::BOOL, "newly_generated", "whether destination was freshly generated"},
            {RPCResult::Type::BOOL, "stored_in_wallet", "destination key confirmed persisted"},
            {RPCResult::Type::STR_AMOUNT, "amount", "value of the new quantum output after fee"},
            {RPCResult::Type::STR_AMOUNT, "fee", "fee paid"},
            {RPCResult::Type::NUM, "vsize", "virtual transaction size"},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "txid (absent for dry_run)"},
            {RPCResult::Type::STR, "warning", /*optional=*/true, "backup reminder"},
        }},
        RPCExamples{
            HelpExampleCli("migrategoldrushrewards", "")
          + HelpExampleCli("migrategoldrushrewards", "'{\"dry_run\":true,\"existing_address\":\"<addr>\"}'")
          + HelpExampleRpc("migrategoldrushrewards", "{\"existing_address\":\"<addr>\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();
        const bool dry_run = options.exists("dry_run") && options["dry_run"].get_bool();
        const bool include_unsafe = options.exists("include_unsafe") && options["include_unsafe"].get_bool();
        const std::string label = options.exists("label") ? options["label"].get_str() : "goldrush-remigration";
        const std::string existing = options.exists("existing_address") ? options["existing_address"].get_str() : "";
        if (dry_run && existing.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "dry_run requires existing_address so the estimate does not create wallet metadata");
        }

        LOCK2(cs_main, pwallet->cs_wallet);
        if (!dry_run) {
            EnsureWalletIsUnlocked(*pwallet);
            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
            }
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        int64_t mtp = 0;
        int next_height = 0;
        if (const CBlockIndex* tip = pwallet->chain().getTip()) {
            mtp = tip->GetMedianTimePast();
            next_height = tip->nHeight + 1;
        }
        const bool goldrush_move_active = !consensus.IsQuantumFinalLockout(mtp) &&
            IsQuantumWitnessSpendActive(consensus, mtp, next_height);
        if (!goldrush_move_active) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Gold Rush reward migration is only allowed once quantum reward spends are active and before the final quantum lockout deadline.");
        }
        const std::string phase = QQPhaseName(consensus.GetQuantumQuasarPhase(mtp));

        CTxDestination dest;
        bool newly_generated = false;
        if (!existing.empty()) {
            std::string err;
            dest = DecodeDestination(existing, err);
            const auto* w = std::get_if<WitnessUnknown>(&dest);
            if (!IsValidDestination(dest) || !w ||
                !IsQuantumMigrationWitnessProgram(w->GetWitnessVersion(), w->GetWitnessProgram())) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "existing_address is not a Blackcoin migration address");
            }
            if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "existing_address is not wallet-backed (no ML-DSA private key in this wallet)");
            }
        } else {
            auto op_dest = pwallet->GetNewQuantumDestination(label);
            if (!op_dest) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(op_dest).original);
            dest = *op_dest;
            newly_generated = true;
        }
        if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Refusing to move Gold Rush reward outputs: destination ML-DSA key is not confirmed stored in the wallet.");
        }
        const CScript destination_script = GetScriptForDestination(dest);

        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = false;
        coin_control.m_include_unsafe_inputs = include_unsafe;
        coin_control.destChange = CNoDestination{};
        if (options.exists("fee_rate")) {
            coin_control.m_feerate = FeeRateFromSatVbValue(options["fee_rate"]);
            coin_control.fOverrideFeeRate = true;
        }
        CoinFilterParams filter;
        filter.only_spendable = true;
        filter.skip_locked = true;
        filter.include_immature_coinbase = false;

        ChainstateManager& chainman = pwallet->chain().chainman();
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        CAmount eligible_amount = 0;
        unsigned int eligible_inputs = 0;
        for (const COutput& out : AvailableCoins(*pwallet, &coin_control, std::nullopt, filter).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (!IsQuantumMigrationScript(spk) || spk == destination_script) continue;
            CScript marker_script;
            if (!IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) || marker_script != spk) continue;
            coin_control.Select(out.outpoint);
            eligible_amount += out.txout.nValue;
            ++eligible_inputs;
        }
        if (eligible_inputs == 0) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No wallet-owned Gold Rush reward outputs need migration.");
        }

        std::vector<CRecipient> recipients;
        recipients.push_back({dest, eligible_amount, /*fSubtractFeeFromAmount=*/true});

        constexpr int RANDOM_CHANGE_POSITION = -1;
        auto res = CreateTransaction(*pwallet, recipients, RANDOM_CHANGE_POSITION, coin_control, /*sign=*/!dry_run);
        if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);

        const CTransactionRef& tx = res->tx;
        if (tx->vout.size() != 1 || IsDust(tx->vout[0], pwallet->chain().relayDustFee())) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                "Gold Rush reward migration would strand funds: selected value is below the dust threshold after fees.");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("phase", phase);
        result.pushKV("deadline_mtp", consensus.nQuantumMigrationDeadlineTime);
        result.pushKV("eligible_inputs", (int)eligible_inputs);
        result.pushKV("eligible_amount", ValueFromAmount(eligible_amount));
        result.pushKV("destination", EncodeDestination(dest));
        result.pushKV("newly_generated", newly_generated);
        result.pushKV("stored_in_wallet", true);
        result.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
        result.pushKV("fee", ValueFromAmount(res->fee));
        result.pushKV("vsize", (int)GetVirtualTransactionSize(*tx, 0, 0));
        if (!dry_run) {
            CommitWalletTransactionOrThrow(*pwallet, tx, {}, "Blackcoin Gold Rush reward migration");
            result.pushKV("txid", tx->GetHash().GetHex());
        }
        if (newly_generated) {
            result.pushKV("warning",
                "A new ML-DSA migration address was created. Back up the wallet before relying on the moved Gold Rush reward outputs.");
        }
        return result;
    }};
}

static uint64_t ParseRGBWalletAmount(const UniValue& obj, const std::string& key)
{
    const UniValue& value = obj.find_value(key);
    if (!value.isNum()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-negative integer asset amount", key));
    }
    const int64_t amount = value.getInt<int64_t>();
    if (amount < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-negative integer asset amount", key));
    }
    return static_cast<uint64_t>(amount);
}

static std::vector<unsigned char> ParseHexOAllowEmpty(const UniValue& obj, const std::string& key)
{
    const UniValue& value = obj.find_value(key);
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be hex", key));
    }
    const std::string hex = value.get_str();
    if (hex.empty()) return {};
    return ParseHexV(value, key);
}

static int64_t ParseWalletRecordTimestamp(const UniValue& obj)
{
    const UniValue& value = obj.find_value("timestamp");
    if (value.isNull()) return GetTime();
    if (!value.isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, "timestamp must be numeric");
    const int64_t timestamp = value.getInt<int64_t>();
    if (timestamp < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "timestamp cannot be negative");
    return timestamp;
}

static COutPoint ParseWalletOutPoint(const UniValue& obj)
{
    RPCTypeCheckObj(obj, {
        {"txid", UniValueType(UniValue::VSTR)},
        {"vout", UniValueType(UniValue::VNUM)},
    });
    const int64_t vout = obj.find_value("vout").getInt<int64_t>();
    if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout is out of range");
    }
    return COutPoint{Txid::FromUint256(ParseHashO(obj, "txid")), static_cast<uint32_t>(vout)};
}

static UniValue RGBContractToJSON(const uint256& contract_id, const RGBContractRecord& record, uint64_t balance, UniValue assignments)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("contract_id", contract_id.GetHex());
    out.pushKV("ticker", record.ticker);
    out.pushKV("name", record.name);
    out.pushKV("total_supply", record.total_supply);
    out.pushKV("balance", balance);
    out.pushKV("timestamp", record.creation_time);
    out.pushKV("assignments", std::move(assignments));
    return out;
}

static UniValue RGBAssignmentToJSON(const uint256& contract_id, const COutPoint& outpoint, const RGBOwnedAssignmentRecord& record)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("contract_id", contract_id.GetHex());
    out.pushKV("txid", outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(outpoint.n));
    out.pushKV("amount", record.amount);
    out.pushKV("spent", record.spent);
    out.pushKV("timestamp", record.creation_time);
    return out;
}

static UniValue RGBOutPointToJSON(const COutPoint& outpoint)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(outpoint.n));
    return out;
}

static UniValue RGBTransitionToJSON(const uint256& contract_id, const uint256& transition_id, const RGBTransitionRecord& record)
{
    UniValue inputs(UniValue::VARR);
    for (const COutPoint& input : record.inputs) {
        inputs.push_back(RGBOutPointToJSON(input));
    }
    UniValue outputs(UniValue::VARR);
    for (const COutPoint& output : record.outputs) {
        outputs.push_back(RGBOutPointToJSON(output));
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("contract_id", contract_id.GetHex());
    out.pushKV("transition_id", transition_id.GetHex());
    out.pushKV("anchor_commitment", record.anchor_commitment.GetHex());
    out.pushKV("anchor_checked", record.anchor_checked);
    if (!record.anchor_txid.IsNull()) {
        out.pushKV("anchor_txid", record.anchor_txid.GetHex());
    }
    if (record.anchor_vout != std::numeric_limits<uint32_t>::max()) {
        out.pushKV("anchor_vout", static_cast<uint64_t>(record.anchor_vout));
    }
    out.pushKV("timestamp", record.creation_time);
    out.pushKV("inputs", std::move(inputs));
    out.pushKV("outputs", std::move(outputs));
    return out;
}

static rgb::Seal ParseRGBWalletSeal(const UniValue& obj)
{
    return rgb::Seal{ParseWalletOutPoint(obj)};
}

static rgb::Assignment ParseRGBWalletAssignment(const UniValue& obj)
{
    return rgb::Assignment{ParseRGBWalletSeal(obj), ParseRGBWalletAmount(obj, "amount")};
}

static bool AddRGBAmount(uint64_t& total, uint64_t amount)
{
    if (amount > std::numeric_limits<uint64_t>::max() - total) return false;
    total += amount;
    return true;
}

static std::vector<rgb::Seal> ParseRGBTransferInputSeals(const UniValue& value)
{
    if (!value.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "inputs must be an array");
    if (value.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "inputs cannot be empty");

    std::set<COutPoint> seen;
    std::vector<rgb::Seal> inputs;
    inputs.reserve(value.size());
    for (const UniValue& input : value.get_array().getValues()) {
        const COutPoint outpoint = ParseWalletOutPoint(input.get_obj());
        if (outpoint.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "input seal is null");
        if (!seen.insert(outpoint).second) throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate input seal");
        inputs.push_back(rgb::Seal{outpoint});
    }
    std::sort(inputs.begin(), inputs.end(), [](const rgb::Seal& a, const rgb::Seal& b) { return a < b; });
    return inputs;
}

static std::vector<rgb::Assignment> ParseRGBTransferOutputAssignments(const UniValue& value)
{
    if (!value.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs must be an array");
    if (value.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs cannot be empty");

    std::set<COutPoint> seen;
    std::vector<rgb::Assignment> outputs;
    outputs.reserve(value.size());
    for (const UniValue& output : value.get_array().getValues()) {
        rgb::Assignment assignment = ParseRGBWalletAssignment(output.get_obj());
        if (assignment.seal.outpoint.IsNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "output seal is null");
        if (assignment.amount == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "output amount cannot be zero");
        if (!seen.insert(assignment.seal.outpoint).second) throw JSONRPCError(RPC_INVALID_PARAMETER, "duplicate output seal");
        outputs.push_back(std::move(assignment));
    }
    std::sort(outputs.begin(), outputs.end(), [](const rgb::Assignment& a, const rgb::Assignment& b) {
        return a.seal < b.seal;
    });
    return outputs;
}

static rgb::Genesis ParseRGBWalletGenesis(const UniValue& obj)
{
    RPCTypeCheckObj(obj, {
        {"ticker", UniValueType(UniValue::VSTR)},
        {"name", UniValueType(UniValue::VSTR)},
        {"total_supply", UniValueType(UniValue::VNUM)},
        {"allocations", UniValueType(UniValue::VARR)},
    });

    rgb::Genesis genesis;
    genesis.ticker = obj.find_value("ticker").get_str();
    genesis.name = obj.find_value("name").get_str();
    genesis.total_supply = ParseRGBWalletAmount(obj, "total_supply");
    for (const UniValue& allocation : obj.find_value("allocations").get_array().getValues()) {
        genesis.allocations.push_back(ParseRGBWalletAssignment(allocation.get_obj()));
    }
    return genesis;
}

static std::vector<rgb::Transition> ParseRGBWalletTransitions(const UniValue& value, const uint256& default_contract_id)
{
    std::vector<rgb::Transition> transitions;
    if (value.isNull()) return transitions;
    if (!value.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "transitions must be an array");

    for (const UniValue& transition_value : value.get_array().getValues()) {
        const UniValue& transition_obj = transition_value.get_obj();
        RPCTypeCheckObj(transition_obj, {
            {"inputs", UniValueType(UniValue::VARR)},
            {"outputs", UniValueType(UniValue::VARR)},
        });

        rgb::Transition transition;
        transition.contract_id = transition_obj.find_value("contract_id").isNull()
            ? default_contract_id
            : ParseHashO(transition_obj, "contract_id");
        for (const UniValue& input : transition_obj.find_value("inputs").get_array().getValues()) {
            transition.inputs.push_back(ParseRGBWalletSeal(input.get_obj()));
        }
        for (const UniValue& output : transition_obj.find_value("outputs").get_array().getValues()) {
            transition.outputs.push_back(ParseRGBWalletAssignment(output.get_obj()));
        }
        transitions.push_back(std::move(transition));
    }
    return transitions;
}

static std::vector<uint256> RGBTransitionIds(const std::vector<rgb::Transition>& transitions)
{
    std::vector<uint256> transition_ids;
    transition_ids.reserve(transitions.size());
    for (const rgb::Transition& transition : transitions) {
        transition_ids.push_back(rgb::TransitionId(transition));
    }
    return transition_ids;
}

static std::vector<uint256> ResolveRGBAnchorTransitionIds(const UniValue& value, const std::vector<uint256>& transition_ids)
{
    if (value.isNull()) return transition_ids;
    if (!value.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "anchor_transition_ids must be an array");
    if (value.get_array().empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "anchor_transition_ids cannot be empty");

    const std::set<uint256> known_ids{transition_ids.begin(), transition_ids.end()};
    std::set<uint256> seen_ids;
    std::vector<uint256> anchor_transition_ids;
    anchor_transition_ids.reserve(value.get_array().size());
    for (const UniValue& id_value : value.get_array().getValues()) {
        const uint256 transition_id = ParseHashV(id_value, "anchor_transition_id");
        if (!known_ids.count(transition_id)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "anchor_transition_ids contains a transition id not present in the consignment");
        }
        if (!seen_ids.insert(transition_id).second) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "anchor_transition_ids contains a duplicate transition id");
        }
        anchor_transition_ids.push_back(transition_id);
    }
    return anchor_transition_ids;
}

static std::vector<rgb::Transition> RGBTransitionsForIds(
    const std::vector<rgb::Transition>& transitions,
    const std::vector<uint256>& transition_ids,
    const std::vector<uint256>& selected_ids)
{
    std::vector<rgb::Transition> selected;
    selected.reserve(selected_ids.size());
    for (const uint256& selected_id : selected_ids) {
        bool found{false};
        for (size_t i = 0; i < transition_ids.size(); ++i) {
            if (transition_ids[i] == selected_id) {
                selected.push_back(transitions[i]);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "selected RGB transition id was not resolved");
        }
    }
    return selected;
}

static UniValue RGBTransitionIdsToJSON(const std::vector<uint256>& transition_ids)
{
    UniValue out(UniValue::VARR);
    for (const uint256& transition_id : transition_ids) {
        out.push_back(transition_id.GetHex());
    }
    return out;
}

static RGBProofAssignment RGBProofAssignmentFromRGB(const rgb::Assignment& assignment)
{
    RGBProofAssignment proof;
    proof.outpoint = assignment.seal.outpoint;
    proof.amount = assignment.amount;
    return proof;
}

static rgb::Assignment RGBProofAssignmentToRGB(const RGBProofAssignment& proof)
{
    return rgb::Assignment{rgb::Seal{proof.outpoint}, proof.amount};
}

static RGBGenesisProofRecord RGBGenesisProofFromRGB(const rgb::Genesis& genesis)
{
    RGBGenesisProofRecord proof;
    proof.allocations.reserve(genesis.allocations.size());
    for (const rgb::Assignment& allocation : genesis.allocations) {
        proof.allocations.push_back(RGBProofAssignmentFromRGB(allocation));
    }
    return proof;
}

static RGBTransitionProofRecord RGBTransitionProofFromRGB(const rgb::Transition& transition, uint64_t order = 0)
{
    RGBTransitionProofRecord proof;
    proof.inputs.reserve(transition.inputs.size());
    for (const rgb::Seal& input : transition.inputs) {
        proof.inputs.push_back(input.outpoint);
    }
    proof.outputs.reserve(transition.outputs.size());
    for (const rgb::Assignment& output : transition.outputs) {
        proof.outputs.push_back(RGBProofAssignmentFromRGB(output));
    }
    proof.order = order;
    return proof;
}

static rgb::Genesis RGBGenesisFromProof(const RGBContractRecord& contract, const RGBGenesisProofRecord& proof)
{
    rgb::Genesis genesis;
    genesis.ticker = contract.ticker;
    genesis.name = contract.name;
    genesis.total_supply = contract.total_supply;
    genesis.allocations.reserve(proof.allocations.size());
    for (const RGBProofAssignment& allocation : proof.allocations) {
        genesis.allocations.push_back(RGBProofAssignmentToRGB(allocation));
    }
    return genesis;
}

static rgb::Transition RGBTransitionFromProof(const uint256& contract_id, const RGBTransitionProofRecord& proof)
{
    rgb::Transition transition;
    transition.contract_id = contract_id;
    transition.inputs.reserve(proof.inputs.size());
    for (const COutPoint& input : proof.inputs) {
        transition.inputs.push_back(rgb::Seal{input});
    }
    transition.outputs.reserve(proof.outputs.size());
    for (const RGBProofAssignment& output : proof.outputs) {
        transition.outputs.push_back(RGBProofAssignmentToRGB(output));
    }
    return transition;
}

static UniValue RGBProofAssignmentToConsignmentJSON(const RGBProofAssignment& assignment)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", assignment.outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(assignment.outpoint.n));
    out.pushKV("amount", assignment.amount);
    return out;
}

static UniValue RGBSealToConsignmentJSON(const COutPoint& outpoint)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(outpoint.n));
    return out;
}

static bool RGBAnchorCanSpendWalletAssignments(const CWallet& wallet, const uint256& anchor_txid) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto wtx_it = wallet.mapWallet.find(anchor_txid);
    if (wtx_it == wallet.mapWallet.end()) return false;

    const CWalletTx& wtx = wtx_it->second;
    if (wtx.isAbandoned() || wtx.isConflicted()) return false;
    return wallet.GetTxDepthInMainChain(wtx) > 0 || wtx.InMempool();
}

static UniValue RGBGenesisToConsignmentJSON(const RGBContractRecord& contract, const RGBGenesisProofRecord& proof)
{
    UniValue allocations(UniValue::VARR);
    for (const RGBProofAssignment& allocation : proof.allocations) {
        allocations.push_back(RGBProofAssignmentToConsignmentJSON(allocation));
    }

    UniValue genesis(UniValue::VOBJ);
    genesis.pushKV("ticker", contract.ticker);
    genesis.pushKV("name", contract.name);
    genesis.pushKV("total_supply", contract.total_supply);
    genesis.pushKV("allocations", std::move(allocations));
    return genesis;
}

static UniValue RGBTransitionProofToConsignmentJSON(const uint256& contract_id, const RGBTransitionProofRecord& proof)
{
    UniValue inputs(UniValue::VARR);
    for (const COutPoint& input : proof.inputs) {
        inputs.push_back(RGBSealToConsignmentJSON(input));
    }
    UniValue outputs(UniValue::VARR);
    for (const RGBProofAssignment& output : proof.outputs) {
        outputs.push_back(RGBProofAssignmentToConsignmentJSON(output));
    }

    UniValue transition(UniValue::VOBJ);
    transition.pushKV("contract_id", contract_id.GetHex());
    transition.pushKV("inputs", std::move(inputs));
    transition.pushKV("outputs", std::move(outputs));
    return transition;
}

static UniValue RGBConsignmentToJSON(
    const RGBContractRecord& contract,
    const RGBGenesisProofRecord& genesis_proof,
    const std::vector<rgb::Transition>& transitions)
{
    UniValue transitions_json(UniValue::VARR);
    for (const rgb::Transition& transition : transitions) {
        transitions_json.push_back(RGBTransitionProofToConsignmentJSON(
            transition.contract_id, RGBTransitionProofFromRGB(transition)));
    }

    UniValue consignment(UniValue::VOBJ);
    consignment.pushKV("genesis", RGBGenesisToConsignmentJSON(contract, genesis_proof));
    consignment.pushKV("transitions", std::move(transitions_json));
    return consignment;
}

static std::vector<rgb::Transition> BuildTopologicalRGBProof(
    const uint256& contract_id,
    const rgb::Genesis& genesis,
    const std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionProofRecord>>& all_proofs,
    std::vector<uint256>& ordered_transition_ids,
    std::string& error)
{
    std::map<rgb::Seal, uint64_t> unspent;
    for (const rgb::Assignment& allocation : genesis.allocations) {
        unspent.emplace(allocation.seal, allocation.amount);
    }

    std::vector<std::pair<uint256, RGBTransitionProofRecord>> ordered_proofs;
    for (const auto& [key, proof] : all_proofs) {
        if (key.first == contract_id) {
            ordered_proofs.emplace_back(key.second, proof);
        }
    }
    std::sort(ordered_proofs.begin(), ordered_proofs.end(), [](const auto& a, const auto& b) {
        if (a.second.order != b.second.order) return a.second.order < b.second.order;
        return a.first < b.first;
    });

    std::vector<rgb::Transition> ordered;
    ordered_transition_ids.clear();
    std::set<uint64_t> seen_orders;
    for (const auto& [transition_id, proof] : ordered_proofs) {
        if (!seen_orders.insert(proof.order).second) {
            error = "stored RGB transition proof order is duplicated";
            return {};
        }
        const rgb::Transition transition = RGBTransitionFromProof(contract_id, proof);
        const uint256 computed_transition_id = rgb::TransitionId(transition);
        if (computed_transition_id != transition_id) {
            error = "stored RGB transition proof id mismatch";
            return {};
        }
        for (const rgb::Seal& input : transition.inputs) {
            if (!unspent.count(input)) {
                error = "RGB proof graph has missing dependencies or invalid transition order";
                return {};
            }
        }

        for (const rgb::Seal& input : transition.inputs) {
            unspent.erase(input);
        }
        for (const rgb::Assignment& output : transition.outputs) {
            if (!unspent.emplace(output.seal, output.amount).second) {
                error = "RGB proof graph has conflicting transition outputs";
                return {};
            }
        }
        ordered_transition_ids.push_back(transition_id);
        ordered.push_back(transition);
    }

    if (!ordered_proofs.empty()) {
        for (uint64_t i = 0; i < ordered_proofs.size(); ++i) {
            if (!seen_orders.count(i)) {
                error = "stored RGB transition proof order is not contiguous";
                return {};
            }
        }
    }

    const rgb::ValidationResult validation = rgb::ValidateConsignment(genesis, ordered);
    if (!validation.valid) {
        UniValue errors(UniValue::VARR);
        for (const std::string& validation_error : validation.errors) {
            errors.push_back(validation_error);
        }
        error = "RGB proof graph validation failed: " + errors.write();
        return {};
    }
    error.clear();
    return ordered;
}

RPCHelpMan acceptrgbconsignment()
{
    return RPCHelpMan{"acceptrgbconsignment",
        "\nValidate an RGB fixed-supply asset consignment and persist current wallet-owned assignments.\n"
        "If anchor_tx is supplied, its first RGB commitment must match the scoped anchor commitment and close every scoped transition input seal.\n",
        {
            {"consignment", RPCArg::Type::OBJ, RPCArg::Optional::NO, "RGB consignment using the verifyrgbconsignment schema",
             {
                 {"genesis", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Contract genesis",
                  {
                      {"ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Ticker/symbol"},
                      {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset name"},
                      {"total_supply", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer fixed supply"},
                      {"allocations", RPCArg::Type::ARR, RPCArg::Optional::NO, "Initial allocations", {
                          {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Allocation", {
                              {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                              {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                              {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                          }},
                      }},
                  }},
                 {"transitions", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Transitions in topological order", {
                     {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Transition", {
                         {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Contract id; defaults to genesis contract id"},
                         {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Consumed seals", {
                             {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Input seal", {
                                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                             }},
                         }},
                         {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Created assignments", {
                             {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Output assignment", {
                                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                                 {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                             }},
                         }},
                     }},
                 }},
             }},
            {"anchor_tx", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"not checked"}, "Optional raw transaction hex containing the first RGB anchor commitment."},
            {"anchor_transition_ids", RPCArg::Type::ARR, RPCArg::DefaultHint{"all transitions"}, "Transition ids committed by anchor_tx. Use this for full-history consignments where only the newest transition is anchored by the supplied transaction.",
             {
                 {"transition_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Transition id to include in anchor order"},
             }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether the consignment validated and was imported"},
            {RPCResult::Type::STR_HEX, "contract_id", "Deterministic RGB contract id"},
            {RPCResult::Type::STR_HEX, "anchor_commitment", "Legacy bundle commitment over every transition in the supplied consignment"},
            {RPCResult::Type::STR_HEX, "consignment_anchor_commitment", "Bundle commitment over every transition in the supplied consignment"},
            {RPCResult::Type::STR_HEX, "transfer_anchor_commitment", "Scoped anchor commitment checked against anchor_tx"},
            {RPCResult::Type::ARR, "anchor_transition_ids", "Transition ids committed by transfer_anchor_commitment", {{RPCResult::Type::STR_HEX, "", "Transition id"}}},
            {RPCResult::Type::BOOL, "anchor_checked", "Whether anchor_tx was supplied and checked"},
            {RPCResult::Type::NUM, "imported_transitions", "Number of validated transition records imported"},
            {RPCResult::Type::NUM, "spent_assignments", "Number of existing wallet-owned assignments marked spent by transition inputs"},
            {RPCResult::Type::NUM, "validated_assignments", "Number of current unspent assignments in the validated consignment"},
            {RPCResult::Type::NUM, "imported_assignments", "Number of current wallet-owned unspent assignments imported"},
            {RPCResult::Type::NUM, "skipped_assignments", "Number of validated assignments skipped because this wallet does not control the live seal UTXO"},
            {RPCResult::Type::NUM, "balance", "Imported wallet-owned unspent balance"},
        }},
        RPCExamples{HelpExampleCli("acceptrgbconsignment", "'{\"genesis\":{\"ticker\":\"QQT\",\"name\":\"Test\",\"total_supply\":100,\"allocations\":[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"amount\":100}]},\"transitions\":[]}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        const UniValue& consignment = request.params[0].get_obj();
        const rgb::Genesis genesis = ParseRGBWalletGenesis(consignment.find_value("genesis").get_obj());
        const uint256 contract_id = rgb::ContractId(genesis);
        const std::vector<rgb::Transition> transitions = ParseRGBWalletTransitions(consignment.find_value("transitions"), contract_id);
        const rgb::ValidationResult validation = rgb::ValidateConsignment(genesis, transitions);
        if (!validation.valid) {
            UniValue errors(UniValue::VARR);
            for (const std::string& error : validation.errors) errors.push_back(error);
            throw JSONRPCError(RPC_VERIFY_REJECTED, "RGB consignment validation failed: " + errors.write());
        }

        const std::vector<uint256> transition_ids = RGBTransitionIds(transitions);
        const std::vector<uint256> anchor_transition_ids = ResolveRGBAnchorTransitionIds(request.params[2], transition_ids);
        const std::set<uint256> anchor_transition_id_set{anchor_transition_ids.begin(), anchor_transition_ids.end()};
        const std::vector<rgb::Transition> anchor_transitions = RGBTransitionsForIds(transitions, transition_ids, anchor_transition_ids);
        const uint256 consignment_anchor_commitment = rgb::AnchorCommitment(transition_ids);
        const uint256 transfer_anchor_commitment = rgb::AnchorCommitment(anchor_transition_ids);
        bool anchor_checked{false};
        bool anchor_tx_present{false};
        uint256 anchor_txid;
        uint32_t anchor_vout{std::numeric_limits<uint32_t>::max()};
        if (!request.params[1].isNull()) {
            CMutableTransaction anchor_mtx;
            if (!DecodeHexTx(anchor_mtx, request.params[1].get_str(), true, true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "anchor_tx decode failed");
            }
            CTransaction decoded_anchor(anchor_mtx);
            std::string anchor_error;
            if (!rgb::ValidateRGBAnchor(decoded_anchor, transfer_anchor_commitment, anchor_transitions, anchor_error)) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, anchor_error);
            }
            if (const auto first = rgb::FirstRGBCommitment(decoded_anchor)) {
                anchor_vout = first->first;
            }
            anchor_txid = decoded_anchor.GetHash();
            anchor_tx_present = true;
            anchor_checked = true;
        }

        std::set<COutPoint> wallet_assignment_outpoints;
        std::set<COutPoint> unspent_wallet_assignment_outpoints;
        bool anchor_can_spend_wallet_assignments{false};
        {
            LOCK(pwallet->cs_wallet);
            for (const auto& entry : pwallet->ListRGBAssignments()) {
                const auto& key = entry.first;
                const RGBOwnedAssignmentRecord& assignment = entry.second;
                if (key.first != contract_id) continue;
                wallet_assignment_outpoints.insert(key.second);
                if (!assignment.spent) unspent_wallet_assignment_outpoints.insert(key.second);
            }
            if (anchor_tx_present) {
                anchor_can_spend_wallet_assignments = RGBAnchorCanSpendWalletAssignments(*pwallet, anchor_txid);
            }
        }
        for (size_t i = 0; i < transitions.size(); ++i) {
            const bool transition_anchor_checked = anchor_checked && anchor_transition_id_set.count(transition_ids[i]) != 0;
            for (const rgb::Seal& input : transitions[i].inputs) {
                if (!unspent_wallet_assignment_outpoints.count(input.outpoint)) continue;
                if (transition_anchor_checked) {
                    if (!anchor_can_spend_wallet_assignments) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "RGB anchor transaction is not live in this wallet");
                    }
                } else {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Unanchored RGB transition spends an unspent wallet-owned assignment");
                }
            }
        }

        RGBContractRecord contract_record;
        contract_record.ticker = genesis.ticker;
        contract_record.name = genesis.name;
        contract_record.total_supply = genesis.total_supply;
        contract_record.creation_time = GetTime();
        if (!pwallet->AddRGBContract(contract_id, contract_record)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB contract metadata");
        }
        if (!pwallet->AddRGBGenesisProof(contract_id, RGBGenesisProofFromRGB(genesis))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB genesis proof");
        }

        uint64_t imported_transitions{0};
        for (size_t i = 0; i < transitions.size(); ++i) {
            RGBTransitionRecord transition_record;
            const bool transition_anchor_checked = anchor_checked && anchor_transition_id_set.count(transition_ids[i]) != 0;
            transition_record.anchor_commitment = transition_anchor_checked
                ? transfer_anchor_commitment
                : rgb::AnchorCommitment(std::vector<uint256>{transition_ids[i]});
            transition_record.creation_time = contract_record.creation_time;
            transition_record.anchor_checked = transition_anchor_checked;
            if (transition_anchor_checked && anchor_tx_present) {
                transition_record.anchor_txid = anchor_txid;
                transition_record.anchor_vout = anchor_vout;
            }
            for (const rgb::Seal& input : transitions[i].inputs) {
                transition_record.inputs.push_back(input.outpoint);
            }
            for (const rgb::Assignment& output : transitions[i].outputs) {
                transition_record.outputs.push_back(output.seal.outpoint);
            }
            if (!pwallet->AddRGBTransition(contract_id, transition_ids[i], transition_record)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB transition metadata");
            }
            if (!pwallet->AddRGBTransitionProof(contract_id, transition_ids[i], RGBTransitionProofFromRGB(transitions[i], i))) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB transition proof");
            }
            ++imported_transitions;
        }

        uint64_t spent_assignments{0};
        for (size_t i = 0; i < transitions.size(); ++i) {
            const bool transition_anchor_checked = anchor_checked && anchor_transition_id_set.count(transition_ids[i]) != 0;
            if (!transition_anchor_checked) continue;
            for (const rgb::Seal& input : transitions[i].inputs) {
                if (!wallet_assignment_outpoints.count(input.outpoint)) continue;
                if (!unspent_wallet_assignment_outpoints.count(input.outpoint)) continue;
                if (!anchor_can_spend_wallet_assignments) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "RGB anchor transaction is not live in this wallet");
                }
                bool changed{false};
                if (!pwallet->SetRGBAssignmentSpent(contract_id, input.outpoint, true, changed)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to mark RGB input assignment spent");
                }
                if (changed) ++spent_assignments;
            }
        }

        std::map<COutPoint, Coin> coins;
        for (const auto& [seal, amount] : validation.unspent) {
            coins.emplace(seal.outpoint, Coin{});
        }
        pwallet->chain().findCoins(coins);

        uint64_t balance{0};
        uint64_t imported{0};
        uint64_t skipped{0};
        for (const auto& [seal, amount] : validation.unspent) {
            const auto coin_it = coins.find(seal.outpoint);
            const bool live_coin = coin_it != coins.end() && !coin_it->second.IsSpent();
            bool wallet_owned{false};
            if (live_coin) {
                LOCK(pwallet->cs_wallet);
                wallet_owned = (pwallet->IsMine(coin_it->second.out) & ISMINE_SPENDABLE) != 0;
            }
            if (!wallet_owned) {
                ++skipped;
                continue;
            }
            if (amount > std::numeric_limits<uint64_t>::max() - balance) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "RGB assignment balance overflow");
            }
            RGBOwnedAssignmentRecord assignment_record;
            assignment_record.amount = amount;
            assignment_record.creation_time = contract_record.creation_time;
            assignment_record.spent = false;
            if (!pwallet->AddRGBAssignment(contract_id, seal.outpoint, assignment_record)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB assignment metadata");
            }
            balance += amount;
            ++imported;
        }

        UniValue out(UniValue::VOBJ);
        out.pushKV("valid", true);
        out.pushKV("contract_id", contract_id.GetHex());
        out.pushKV("anchor_commitment", consignment_anchor_commitment.GetHex());
        out.pushKV("consignment_anchor_commitment", consignment_anchor_commitment.GetHex());
        out.pushKV("transfer_anchor_commitment", transfer_anchor_commitment.GetHex());
        out.pushKV("anchor_transition_ids", RGBTransitionIdsToJSON(anchor_transition_ids));
        out.pushKV("anchor_checked", anchor_checked);
        out.pushKV("imported_transitions", imported_transitions);
        out.pushKV("spent_assignments", spent_assignments);
        out.pushKV("validated_assignments", static_cast<uint64_t>(validation.unspent.size()));
        out.pushKV("imported_assignments", imported);
        out.pushKV("skipped_assignments", skipped);
        out.pushKV("balance", balance);
        return out;
    }};
}

RPCHelpMan creatergbtransfer()
{
    return RPCHelpMan{"creatergbtransfer",
        "\nCreate, sign, and optionally commit a wallet-originated RGB fixed-supply transfer.\n"
        "The input seals must be unspent RGB assignments owned by this wallet and must contain\n"
        "enough BLK value to pay the anchor transaction fee. Output seals must already be live\n"
        "UTXOs; creating output seals is a separate funding step because a seal commits to a\n"
        "txid/vout and cannot refer to the anchor transaction that spends the inputs.\n",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "RGB contract id."},
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Wallet-owned RGB assignment seals to spend.", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Input seal", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                }},
            }},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "New RGB assignments. Amounts must exactly equal the selected input assignment total.", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Output assignment", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                    {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                }},
            }},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "Transfer options.",
             {
                 {"add_to_wallet", RPCArg::Type::BOOL, RPCArg::Default{true}, "Commit the signed anchor transaction and persist the RGB transition metadata."},
                 {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Build and sign the anchor transaction without committing or changing wallet RGB metadata."},
                 {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Allow unsafe selected input seals."},
                 {"change_address", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "Address to receive BLK change from the anchor transaction."},
                 {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Fee rate in " + CURRENCY_ATOM + "/vB."},
             },
             RPCArgOptions{.skip_type_check = true, .oneline_description = "options"}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "complete", "Whether the anchor transaction was fully signed"},
            {RPCResult::Type::BOOL, "committed", "Whether the anchor transaction and RGB metadata were committed to the wallet"},
            {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
            {RPCResult::Type::STR_HEX, "transition_id", "New transition id"},
            {RPCResult::Type::STR_HEX, "transfer_anchor_commitment", "Scoped anchor commitment for the new transition"},
            {RPCResult::Type::ARR, "anchor_transition_ids", "Transition ids committed by transfer_anchor_commitment", {{RPCResult::Type::STR_HEX, "", "Transition id"}}},
            {RPCResult::Type::STR_HEX, "anchor_txid", "Anchor transaction id"},
            {RPCResult::Type::NUM, "anchor_vout", "Anchor output index containing the RGB commitment"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Anchor transaction fee in " + CURRENCY_UNIT},
            {RPCResult::Type::NUM, "vsize", "Anchor transaction virtual size"},
            {RPCResult::Type::STR_HEX, "hex", "Signed anchor transaction hex"},
            {RPCResult::Type::NUM, "input_asset_amount", "Total RGB asset amount consumed"},
            {RPCResult::Type::NUM, "output_asset_amount", "Total RGB asset amount created"},
            {RPCResult::Type::NUM, "imported_assignments", "Number of new output assignments imported because this wallet controls their live seals"},
            {RPCResult::Type::OBJ, "consignment", "Full consignment proof graph including the new transition", {
                {RPCResult::Type::OBJ, "genesis", "Contract genesis", {
                    {RPCResult::Type::STR, "ticker", "Ticker/symbol"},
                    {RPCResult::Type::STR, "name", "Asset name"},
                    {RPCResult::Type::NUM, "total_supply", "Integer fixed supply"},
                    {RPCResult::Type::ARR, "allocations", "Initial allocations", {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                            {RPCResult::Type::NUM, "vout", "Seal vout"},
                            {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "transitions", "State transitions in topological order", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "contract_id", "Contract id"},
                        {RPCResult::Type::ARR, "inputs", "Consumed seals", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                            }},
                        }},
                        {RPCResult::Type::ARR, "outputs", "Created assignments", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                                {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                            }},
                        }},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("creatergbtransfer", "\"00...01\" '[{\"txid\":\"00...02\",\"vout\":0}]' '[{\"txid\":\"00...03\",\"vout\":0,\"amount\":100}]' '{\"dry_run\":true}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        pwallet->BlockUntilSyncedToCurrentChain();
        EnsureWalletIsUnlocked(*pwallet);
        if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private keys are disabled for this wallet");
        }
        if (pwallet->m_wallet_unlock_staking_only) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet unlocked for staking only, unable to create RGB transfer");
        }

        const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
        const std::vector<rgb::Seal> input_seals = ParseRGBTransferInputSeals(request.params[1]);
        const std::vector<rgb::Assignment> output_assignments = ParseRGBTransferOutputAssignments(request.params[2]);

        UniValue options(UniValue::VOBJ);
        if (!request.params[3].isNull()) {
            if (!request.params[3].isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
            options = request.params[3].get_obj();
            RPCTypeCheckObj(options, {
                {"add_to_wallet", UniValueType(UniValue::VBOOL)},
                {"dry_run", UniValueType(UniValue::VBOOL)},
                {"include_unsafe", UniValueType(UniValue::VBOOL)},
                {"change_address", UniValueType(UniValue::VSTR)},
                {"fee_rate", UniValueType()},
            }, true, true);
        }
        const bool dry_run = options.exists("dry_run") && options["dry_run"].get_bool();
        const bool add_to_wallet = !dry_run && (!options.exists("add_to_wallet") || options["add_to_wallet"].get_bool());

        std::optional<RGBContractRecord> contract;
        std::optional<RGBGenesisProofRecord> genesis_proof;
        std::vector<std::pair<std::pair<uint256, COutPoint>, RGBOwnedAssignmentRecord>> wallet_assignments;
        std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionProofRecord>> transition_proofs;
        {
            LOCK(pwallet->cs_wallet);
            contract = pwallet->GetRGBContract(contract_id);
            genesis_proof = pwallet->GetRGBGenesisProof(contract_id);
            wallet_assignments = pwallet->ListRGBAssignments();
            transition_proofs = pwallet->ListRGBTransitionProofs();
        }
        if (!contract) throw JSONRPCError(RPC_WALLET_ERROR, "RGB contract not found");
        if (!genesis_proof) {
            throw JSONRPCError(RPC_WALLET_ERROR, "RGB proof graph is not available for this contract; import a validated consignment first");
        }

        std::map<COutPoint, RGBOwnedAssignmentRecord> owned_assignments;
        for (const auto& [key, assignment] : wallet_assignments) {
            if (key.first == contract_id) owned_assignments.emplace(key.second, assignment);
        }

        std::map<COutPoint, Coin> coins;
        for (const rgb::Seal& input : input_seals) coins.emplace(input.outpoint, Coin{});
        for (const rgb::Assignment& output : output_assignments) coins.emplace(output.seal.outpoint, Coin{});
        pwallet->chain().findCoins(coins);

        uint64_t input_amount{0};
        for (const rgb::Seal& input : input_seals) {
            const auto assignment_it = owned_assignments.find(input.outpoint);
            if (assignment_it == owned_assignments.end() || assignment_it->second.spent) {
                throw JSONRPCError(RPC_WALLET_ERROR, "input seal is not an unspent wallet-owned RGB assignment");
            }
            if (!AddRGBAmount(input_amount, assignment_it->second.amount)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "RGB input amount overflow");
            }
            const auto coin_it = coins.find(input.outpoint);
            const bool live_coin = coin_it != coins.end() && !coin_it->second.IsSpent();
            bool wallet_owned{false};
            if (live_coin) {
                LOCK(pwallet->cs_wallet);
                wallet_owned = (pwallet->IsMine(coin_it->second.out) & ISMINE_SPENDABLE) != 0;
            }
            if (!wallet_owned) {
                throw JSONRPCError(RPC_WALLET_ERROR, "input seal is not a live wallet-spendable UTXO");
            }
        }

        uint64_t output_amount{0};
        for (const rgb::Assignment& output : output_assignments) {
            if (!AddRGBAmount(output_amount, output.amount)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "RGB output amount overflow");
            }
            const auto coin_it = coins.find(output.seal.outpoint);
            if (coin_it == coins.end() || coin_it->second.IsSpent()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "output seal is not a live UTXO");
            }
        }
        if (input_amount != output_amount) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "RGB input and output asset amounts do not balance");
        }

        const rgb::Genesis genesis = RGBGenesisFromProof(*contract, *genesis_proof);
        std::vector<uint256> ordered_transition_ids;
        std::string proof_error;
        std::vector<rgb::Transition> ordered_transitions = BuildTopologicalRGBProof(
            contract_id, genesis, transition_proofs, ordered_transition_ids, proof_error);
        if (!proof_error.empty()) throw JSONRPCError(RPC_WALLET_ERROR, proof_error);

        rgb::Transition transition;
        transition.contract_id = contract_id;
        transition.inputs = input_seals;
        transition.outputs = output_assignments;
        const uint256 transition_id = rgb::TransitionId(transition);
        ordered_transitions.push_back(transition);
        ordered_transition_ids.push_back(transition_id);

        const rgb::ValidationResult validation = rgb::ValidateConsignment(genesis, ordered_transitions);
        if (!validation.valid) {
            UniValue errors(UniValue::VARR);
            for (const std::string& error : validation.errors) errors.push_back(error);
            throw JSONRPCError(RPC_VERIFY_REJECTED, "RGB transfer validation failed: " + errors.write());
        }

        const uint256 transfer_anchor_commitment = rgb::AnchorCommitment(std::vector<uint256>{transition_id});
        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = false;
        coin_control.m_include_unsafe_inputs = options.exists("include_unsafe") && options["include_unsafe"].get_bool();
        if (options.exists("fee_rate")) {
            coin_control.m_feerate = FeeRateFromSatVbValue(options["fee_rate"]);
            coin_control.fOverrideFeeRate = true;
        }
        if (options.exists("change_address")) {
            const std::string change_address = options["change_address"].get_str();
            const CTxDestination dest = DecodeDestination(change_address);
            if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "change_address is not valid");
            coin_control.destChange = dest;
        }
        for (const rgb::Seal& input : input_seals) {
            coin_control.Select(input.outpoint);
        }

        std::vector<CRecipient> recipients;
        recipients.emplace_back(CreateRGBCommitment(transfer_anchor_commitment), 0, false);
        constexpr int RANDOM_CHANGE_POSITION = -1;
        auto tx_res = CreateTransaction(*pwallet, recipients, RANDOM_CHANGE_POSITION, coin_control, /*sign=*/true);
        if (!tx_res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(tx_res).original);
        const CTransactionRef& tx = tx_res->tx;

        std::string anchor_error;
        if (!rgb::ValidateRGBAnchor(*tx, transfer_anchor_commitment, std::vector<rgb::Transition>{transition}, anchor_error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "created RGB anchor transaction is invalid: " + anchor_error);
        }
        const auto first_anchor = rgb::FirstRGBCommitment(*tx);
        if (!first_anchor) throw JSONRPCError(RPC_INTERNAL_ERROR, "created RGB anchor transaction has no RGB commitment");
        const uint32_t anchor_vout = first_anchor->first;
        const uint256 anchor_txid = tx->GetHash();

        uint64_t imported_assignments{0};
        if (add_to_wallet) {
            RGBTransitionRecord transition_record;
            transition_record.anchor_commitment = transfer_anchor_commitment;
            transition_record.anchor_txid = anchor_txid;
            transition_record.anchor_vout = anchor_vout;
            transition_record.creation_time = GetTime();
            transition_record.anchor_checked = true;
            for (const rgb::Seal& input : input_seals) {
                transition_record.inputs.push_back(input.outpoint);
            }
            for (const rgb::Assignment& output : output_assignments) {
                transition_record.outputs.push_back(output.seal.outpoint);
            }

            RGBTxCommitData rgb_commit_data;
            rgb_commit_data.contract_id = contract_id;
            rgb_commit_data.transition_id = transition_id;
            rgb_commit_data.transition_record = transition_record;
            rgb_commit_data.transition_proof = RGBTransitionProofFromRGB(transition, ordered_transition_ids.size() - 1);
            for (const rgb::Seal& input : input_seals) {
                rgb_commit_data.spent_assignments.push_back(input.outpoint);
            }
            for (const rgb::Assignment& output : output_assignments) {
                const auto coin_it = coins.find(output.seal.outpoint);
                bool wallet_owned{false};
                if (coin_it != coins.end() && !coin_it->second.IsSpent()) {
                    LOCK(pwallet->cs_wallet);
                    wallet_owned = (pwallet->IsMine(coin_it->second.out) & ISMINE_SPENDABLE) != 0;
                }
                if (!wallet_owned) continue;
                RGBOwnedAssignmentRecord assignment_record;
                assignment_record.amount = output.amount;
                assignment_record.creation_time = transition_record.creation_time;
                assignment_record.spent = false;
                rgb_commit_data.output_assignments.emplace_back(output.seal.outpoint, assignment_record);
                ++imported_assignments;
            }

            std::string commit_error;
            if (!pwallet->CommitRGBTransaction(tx, {}, {}, rgb_commit_data, commit_error)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit RGB anchor transaction: " + commit_error);
            }
        }

        UniValue anchor_transition_ids(UniValue::VARR);
        anchor_transition_ids.push_back(transition_id.GetHex());

        UniValue out(UniValue::VOBJ);
        out.pushKV("complete", true);
        out.pushKV("committed", add_to_wallet);
        out.pushKV("contract_id", contract_id.GetHex());
        out.pushKV("transition_id", transition_id.GetHex());
        out.pushKV("transfer_anchor_commitment", transfer_anchor_commitment.GetHex());
        out.pushKV("anchor_transition_ids", std::move(anchor_transition_ids));
        out.pushKV("anchor_txid", anchor_txid.GetHex());
        out.pushKV("anchor_vout", static_cast<uint64_t>(anchor_vout));
        out.pushKV("fee", ValueFromAmount(tx_res->fee));
        out.pushKV("vsize", static_cast<int64_t>(GetVirtualTransactionSize(*tx, 0, 0)));
        out.pushKV("hex", EncodeHexTx(*tx));
        out.pushKV("input_asset_amount", input_amount);
        out.pushKV("output_asset_amount", output_amount);
        out.pushKV("imported_assignments", imported_assignments);
        out.pushKV("consignment", RGBConsignmentToJSON(*contract, *genesis_proof, ordered_transitions));
        return out;
    }};
}

RPCHelpMan exportrgbconsignment()
{
    return RPCHelpMan{"exportrgbconsignment",
        "\nExport a wallet-persisted RGB consignment proof graph for a contract.\n"
        "Only validated consignments accepted with acceptrgbconsignment carry enough proof data to export.\n",
        {
            {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "RGB contract id to export."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "proof_complete", "Whether the wallet has a complete validated proof graph for export"},
            {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
            {RPCResult::Type::NUM, "transition_count", "Number of exported transitions"},
            {RPCResult::Type::ARR, "transition_ids", "Transition ids in exported topological order", {
                {RPCResult::Type::STR_HEX, "", "Transition id"},
            }},
            {RPCResult::Type::STR_HEX, "bundle_anchor_commitment", "Anchor commitment for the exported transition bundle"},
            {RPCResult::Type::OBJ, "consignment", "RGB consignment using the verifyrgbconsignment/acceptrgbconsignment schema", {
                {RPCResult::Type::OBJ, "genesis", "Contract genesis", {
                    {RPCResult::Type::STR, "ticker", "Ticker/symbol"},
                    {RPCResult::Type::STR, "name", "Asset name"},
                    {RPCResult::Type::NUM, "total_supply", "Integer fixed supply"},
                    {RPCResult::Type::ARR, "allocations", "Initial allocations", {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                            {RPCResult::Type::NUM, "vout", "Seal vout"},
                            {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "transitions", "State transitions in topological order", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "contract_id", "Contract id"},
                        {RPCResult::Type::ARR, "inputs", "Consumed seals", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                            }},
                        }},
                        {RPCResult::Type::ARR, "outputs", "Created assignments", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                                {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                            }},
                        }},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("exportrgbconsignment", "\"00...01\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<const CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;

        const uint256 contract_id = ParseHashV(request.params[0], "contract_id");
        std::optional<RGBContractRecord> contract;
        std::optional<RGBGenesisProofRecord> genesis_proof;
        std::vector<std::pair<std::pair<uint256, uint256>, RGBTransitionProofRecord>> transition_proofs;
        {
            LOCK(pwallet->cs_wallet);
            contract = pwallet->GetRGBContract(contract_id);
            genesis_proof = pwallet->GetRGBGenesisProof(contract_id);
            transition_proofs = pwallet->ListRGBTransitionProofs();
        }
        if (!contract) {
            throw JSONRPCError(RPC_WALLET_ERROR, "RGB contract not found");
        }
        if (!genesis_proof) {
            throw JSONRPCError(RPC_WALLET_ERROR, "RGB proof graph is not available for this contract; import a validated consignment first");
        }

        const rgb::Genesis genesis = RGBGenesisFromProof(*contract, *genesis_proof);
        std::vector<uint256> ordered_transition_ids;
        std::string error;
        const std::vector<rgb::Transition> ordered_transitions = BuildTopologicalRGBProof(contract_id, genesis, transition_proofs, ordered_transition_ids, error);
        if (!error.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }

        UniValue transition_ids(UniValue::VARR);
        for (const uint256& transition_id : ordered_transition_ids) {
            transition_ids.push_back(transition_id.GetHex());
        }

        UniValue transitions_json(UniValue::VARR);
        for (const rgb::Transition& transition : ordered_transitions) {
            transitions_json.push_back(RGBTransitionProofToConsignmentJSON(contract_id, RGBTransitionProofFromRGB(transition)));
        }

        UniValue consignment(UniValue::VOBJ);
        consignment.pushKV("genesis", RGBGenesisToConsignmentJSON(*contract, *genesis_proof));
        consignment.pushKV("transitions", std::move(transitions_json));

        UniValue out(UniValue::VOBJ);
        out.pushKV("proof_complete", true);
        out.pushKV("contract_id", contract_id.GetHex());
        out.pushKV("transition_count", static_cast<uint64_t>(ordered_transition_ids.size()));
        out.pushKV("transition_ids", std::move(transition_ids));
        out.pushKV("bundle_anchor_commitment", rgb::AnchorCommitment(ordered_transition_ids).GetHex());
        out.pushKV("consignment", std::move(consignment));
        return out;
    }};
}

RPCHelpMan importrgbcontract()
{
    return RPCHelpMan{"importrgbcontract",
        "\nPersist RGB fixed-supply asset contract metadata in this wallet.\n"
        "This does not validate a full consignment; use verifyrgbconsignment for RGB validation before importing.\n",
        {
            {"contract", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Contract metadata",
             {
                 {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Deterministic RGB contract id"},
                 {"ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ticker/symbol"},
                 {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset name"},
                 {"total_supply", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer fixed supply"},
                 {"timestamp", RPCArg::Type::NUM, RPCArg::DefaultHint{"now"}, "Creation/import timestamp"},
             }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "contract_id", "Imported contract id"},
            {RPCResult::Type::STR, "ticker", "Asset ticker/symbol"},
            {RPCResult::Type::STR, "name", "Asset name"},
            {RPCResult::Type::NUM, "total_supply", "Integer fixed supply"},
            {RPCResult::Type::NUM_TIME, "timestamp", "Creation/import timestamp"},
        }},
        RPCExamples{HelpExampleCli("importrgbcontract", "'{\"contract_id\":\"00...01\",\"ticker\":\"QQT\",\"name\":\"Test\",\"total_supply\":1000}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        const UniValue& c = request.params[0].get_obj();
        RPCTypeCheckObj(c, {
            {"contract_id", UniValueType(UniValue::VSTR)},
            {"ticker", UniValueType(UniValue::VSTR)},
            {"name", UniValueType(UniValue::VSTR)},
            {"total_supply", UniValueType(UniValue::VNUM)},
        });

        RGBContractRecord record;
        const uint256 contract_id = ParseHashO(c, "contract_id");
        record.ticker = c.find_value("ticker").get_str();
        record.name = c.find_value("name").get_str();
        record.total_supply = ParseRGBWalletAmount(c, "total_supply");
        record.creation_time = ParseWalletRecordTimestamp(c);
        if (!pwallet->AddRGBContract(contract_id, record)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB contract metadata");
        }

        UniValue out(UniValue::VOBJ);
        out.pushKV("contract_id", contract_id.GetHex());
        out.pushKV("ticker", record.ticker);
        out.pushKV("name", record.name);
        out.pushKV("total_supply", record.total_supply);
        out.pushKV("timestamp", record.creation_time);
        return out;
    }};
}

RPCHelpMan importrgbassignment()
{
    return RPCHelpMan{"importrgbassignment",
        "\nPersist an owned RGB assignment seal in this wallet.\n"
        "Import the contract with importrgbcontract first.\n",
        {
            {"assignment", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Owned assignment",
             {
                 {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "RGB contract id"},
                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                 {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                 {"spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether this assignment has already been spent by an RGB transition"},
                 {"timestamp", RPCArg::Type::NUM, RPCArg::DefaultHint{"now"}, "Creation/import timestamp"},
             }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
            {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
            {RPCResult::Type::NUM, "vout", "Seal vout"},
            {RPCResult::Type::NUM, "amount", "Integer asset amount"},
            {RPCResult::Type::BOOL, "spent", "Whether this assignment is marked spent"},
            {RPCResult::Type::NUM_TIME, "timestamp", "Creation/import timestamp"},
        }},
        RPCExamples{HelpExampleCli("importrgbassignment", "'{\"contract_id\":\"00...01\",\"txid\":\"00...02\",\"vout\":0,\"amount\":1000}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        const UniValue& a = request.params[0].get_obj();
        RPCTypeCheckObj(a, {
            {"contract_id", UniValueType(UniValue::VSTR)},
            {"txid", UniValueType(UniValue::VSTR)},
            {"vout", UniValueType(UniValue::VNUM)},
            {"amount", UniValueType(UniValue::VNUM)},
        });
        const UniValue& spent_value = a.find_value("spent");
        if (!spent_value.isNull() && !spent_value.isBool()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "spent must be boolean");
        }

        const uint256 contract_id = ParseHashO(a, "contract_id");
        const COutPoint outpoint = ParseWalletOutPoint(a);
        RGBOwnedAssignmentRecord record;
        record.amount = ParseRGBWalletAmount(a, "amount");
        record.spent = !spent_value.isNull() && spent_value.get_bool();
        record.creation_time = ParseWalletRecordTimestamp(a);
        if (!pwallet->AddRGBAssignment(contract_id, outpoint, record)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import RGB assignment; import the contract first and ensure amount is non-zero");
        }
        return RGBAssignmentToJSON(contract_id, outpoint, record);
    }};
}

RPCHelpMan listrgbassets()
{
    return RPCHelpMan{"listrgbassets",
        "\nList wallet-persisted RGB contracts and owned assignment balances.\n",
        {
            {"include_spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include assignments marked spent in the assignment list."},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
                {RPCResult::Type::STR, "ticker", "Asset ticker/symbol"},
                {RPCResult::Type::STR, "name", "Asset name"},
                {RPCResult::Type::NUM, "total_supply", "Integer fixed supply"},
                {RPCResult::Type::NUM, "balance", "Unspent wallet-owned assignment amount"},
                {RPCResult::Type::NUM_TIME, "timestamp", "Contract timestamp"},
                {RPCResult::Type::BOOL, "proof_available", "Whether the wallet can export a validated proof graph for this contract"},
                {RPCResult::Type::NUM, "proof_transition_count", "Number of persisted transition proofs available for export"},
                {RPCResult::Type::ARR, "transitions", "Validated RGB transition records", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
                        {RPCResult::Type::STR_HEX, "transition_id", "RGB transition id"},
                        {RPCResult::Type::STR_HEX, "anchor_commitment", "RGB anchor commitment"},
                        {RPCResult::Type::BOOL, "anchor_checked", "Whether an anchor tx was checked when imported"},
                        {RPCResult::Type::STR_HEX, "anchor_txid", /*optional=*/true, "Anchor transaction id when supplied"},
                        {RPCResult::Type::NUM, "anchor_vout", /*optional=*/true, "Anchor commitment output index when supplied"},
                        {RPCResult::Type::NUM_TIME, "timestamp", "Transition import timestamp"},
                        {RPCResult::Type::ARR, "inputs", "Consumed RGB seals", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                            }},
                        }},
                        {RPCResult::Type::ARR, "outputs", "Created RGB seals", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                                {RPCResult::Type::NUM, "vout", "Seal vout"},
                            }},
                        }},
                    }},
                }},
                {RPCResult::Type::ARR, "assignments", "Wallet-owned assignments", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "contract_id", "RGB contract id"},
                        {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                        {RPCResult::Type::NUM, "vout", "Seal vout"},
                        {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                        {RPCResult::Type::BOOL, "spent", "Whether this assignment is marked spent"},
                        {RPCResult::Type::NUM_TIME, "timestamp", "Assignment timestamp"},
                    }},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("listrgbassets", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<const CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        const bool include_spent = !request.params[0].isNull() && request.params[0].get_bool();

        LOCK(pwallet->cs_wallet);
        const auto contracts = pwallet->ListRGBContracts();
        const auto assignments = pwallet->ListRGBAssignments();
        const auto transitions = pwallet->ListRGBTransitions();
        const auto transition_proofs = pwallet->ListRGBTransitionProofs();

        UniValue result(UniValue::VARR);
        for (const auto& [contract_id, contract] : contracts) {
            uint64_t balance{0};
            UniValue entries(UniValue::VARR);
            for (const auto& [key, assignment] : assignments) {
                if (key.first != contract_id) continue;
                if (!assignment.spent) {
                    if (assignment.amount > std::numeric_limits<uint64_t>::max() - balance) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "RGB assignment balance overflow");
                    }
                    balance += assignment.amount;
                }
                if (include_spent || !assignment.spent) {
                    entries.push_back(RGBAssignmentToJSON(contract_id, key.second, assignment));
                }
            }
            UniValue transition_entries(UniValue::VARR);
            for (const auto& [key, transition] : transitions) {
                if (key.first != contract_id) continue;
                transition_entries.push_back(RGBTransitionToJSON(contract_id, key.second, transition));
            }
            UniValue asset = RGBContractToJSON(contract_id, contract, balance, std::move(entries));
            const bool proof_available = pwallet->GetRGBGenesisProof(contract_id).has_value();
            uint64_t proof_transition_count{0};
            for (const auto& [key, proof] : transition_proofs) {
                if (key.first == contract_id) ++proof_transition_count;
            }
            asset.pushKV("proof_available", proof_available);
            asset.pushKV("proof_transition_count", proof_transition_count);
            asset.pushKV("transitions", std::move(transition_entries));
            result.push_back(std::move(asset));
        }
        return result;
    }};
}

static UniValue EUTXOStateToJSON(const COutPoint& outpoint, const EUTXOStateRecord& record, std::optional<bool> spent = std::nullopt)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(outpoint.n));
    out.pushKV("amount", ValueFromAmount(record.amount));
    out.pushKV("datum", HexStr(record.datum));
    out.pushKV("validator", HexStr(record.validator_script));
    out.pushKV("address", EncodeDestination(WitnessUnknown{EUTXO_WITNESS_VERSION, EUTXOProgramForDatumAndValidator(record.datum, record.validator_script)}));
    out.pushKV("timestamp", record.creation_time);
    if (spent.has_value()) out.pushKV("spent", *spent);
    return out;
}

RPCHelpMan importeutxostate()
{
    return RPCHelpMan{"importeutxostate",
        "\nPersist EUTXO datum/validator metadata for a wallet-known state output.\n"
        "If the outpoint is currently unspent, the live UTXO must match the supplied EUTXO commitment.\n",
        {
            {"state", RPCArg::Type::OBJ, RPCArg::Optional::NO, "EUTXO state metadata",
             {
                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "State txid"},
                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "State vout"},
                 {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Output amount"},
                 {"datum", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Committed datum"},
                 {"validator", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Committed validator script"},
                 {"timestamp", RPCArg::Type::NUM, RPCArg::DefaultHint{"now"}, "Creation/import timestamp"},
             }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "State txid"},
            {RPCResult::Type::NUM, "vout", "State vout"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Output amount"},
            {RPCResult::Type::STR_HEX, "datum", "Committed datum"},
            {RPCResult::Type::STR_HEX, "validator", "Committed validator script"},
            {RPCResult::Type::STR, "address", "EUTXO commitment address"},
            {RPCResult::Type::NUM_TIME, "timestamp", "Creation/import timestamp"},
        }},
        RPCExamples{HelpExampleCli("importeutxostate", "'{\"txid\":\"00...01\",\"vout\":0,\"amount\":1,\"datum\":\"01\",\"validator\":\"51\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        const UniValue& s = request.params[0].get_obj();
        RPCTypeCheckObj(s, {
            {"txid", UniValueType(UniValue::VSTR)},
            {"vout", UniValueType(UniValue::VNUM)},
            {"amount", UniValueType()},
            {"datum", UniValueType(UniValue::VSTR)},
            {"validator", UniValueType(UniValue::VSTR)},
        });

        const COutPoint outpoint = ParseWalletOutPoint(s);
        EUTXOStateRecord record;
        record.amount = AmountFromValue(s.find_value("amount"));
        record.datum = ParseHexOAllowEmpty(s, "datum");
        const std::vector<unsigned char> validator = ParseHexOAllowEmpty(s, "validator");
        record.validator_script = CScript(validator.begin(), validator.end());
        record.creation_time = ParseWalletRecordTimestamp(s);
        if (record.datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
            record.validator_script.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "datum/validator exceed 4096 bytes");
        }

        std::map<COutPoint, Coin> coins{{outpoint, Coin{}}};
        pwallet->chain().findCoins(coins);
        const auto coin_it = coins.find(outpoint);
        if (coin_it != coins.end() && !coin_it->second.IsSpent()) {
            const CScript expected = GetScriptForEUTXO(record.datum, record.validator_script);
            if (coin_it->second.out.scriptPubKey != expected || coin_it->second.out.nValue != record.amount) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, "Live UTXO does not match supplied EUTXO state metadata");
            }
        }
        if (!pwallet->AddEUTXOState(outpoint, record)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import EUTXO state metadata");
        }
        return EUTXOStateToJSON(outpoint, record);
    }};
}

RPCHelpMan listeutxostates()
{
    return RPCHelpMan{"listeutxostates",
        "\nList wallet-persisted EUTXO state metadata.\n",
        {
            {"include_spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include state metadata whose on-chain UTXO is already spent."},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "txid", "State txid"},
                {RPCResult::Type::NUM, "vout", "State vout"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Output amount"},
                {RPCResult::Type::STR_HEX, "datum", "Committed datum"},
                {RPCResult::Type::STR_HEX, "validator", "Committed validator script"},
                {RPCResult::Type::STR, "address", "EUTXO commitment address"},
                {RPCResult::Type::NUM_TIME, "timestamp", "Creation/import timestamp"},
                {RPCResult::Type::BOOL, "spent", "Whether the state output is absent from the current UTXO set"},
            }},
        }},
        RPCExamples{HelpExampleCli("listeutxostates", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<const CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        const bool include_spent = !request.params[0].isNull() && request.params[0].get_bool();

        std::vector<std::pair<COutPoint, EUTXOStateRecord>> states;
        {
            LOCK(pwallet->cs_wallet);
            states = pwallet->ListEUTXOStates();
        }

        std::map<COutPoint, Coin> coins;
        for (const auto& [outpoint, record] : states) {
            coins.emplace(outpoint, Coin{});
        }
        pwallet->chain().findCoins(coins);

        UniValue result(UniValue::VARR);
        for (const auto& [outpoint, record] : states) {
            const auto coin_it = coins.find(outpoint);
            const bool spent = coin_it == coins.end() || coin_it->second.IsSpent();
            if (spent && !include_spent) continue;
            result.push_back(EUTXOStateToJSON(outpoint, record, spent));
        }
        return result;
    }};
}

RPCHelpMan getmigrationstatus()
{
    return RPCHelpMan{"getmigrationstatus",
        "\nReport progress and the remaining window for migrating legacy coins to\n"
        "Blackcoin ML-DSA (witness-v16) addresses before the final lockout deadline.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "phase", "legacy | gold_rush | migration | final_lockout"},
            {RPCResult::Type::NUM_TIME, "mediantime", "tip median-time-past driving the schedule"},
            {RPCResult::Type::NUM_TIME, "deadline_mtp", "final migration deadline MTP (0 if unscheduled)"},
            {RPCResult::Type::BOOL, "deadline_scheduled", "whether a deadline is configured"},
            {RPCResult::Type::NUM, "seconds_until_deadline", "max(0, deadline - mtp)"},
            {RPCResult::Type::NUM, "blocks_until_deadline_est", "rough estimate (seconds / target spacing)"},
            {RPCResult::Type::BOOL, "deadline_passed", "whether legacy coins are already locked out"},
            {RPCResult::Type::NUM, "eligible_legacy_inputs", "spendable legacy UTXOs remaining"},
            {RPCResult::Type::STR_AMOUNT, "eligible_legacy_amount", "total value of eligible legacy coins"},
            {RPCResult::Type::NUM, "migrated_quantum_outputs", "wallet-owned quantum UTXOs"},
            {RPCResult::Type::STR_AMOUNT, "migrated_quantum_amount", "total value already in quantum addresses"},
            {RPCResult::Type::NUM, "direct_quantum_outputs", "wallet-owned ordinary quantum UTXOs ready for normal sends and delegation funding"},
            {RPCResult::Type::STR_AMOUNT, "direct_quantum_amount", "ordinary quantum value ready for normal sends and delegation funding"},
            {RPCResult::Type::NUM, "staked_quantum_outputs", "wallet-owned bonded or staking quantum UTXOs"},
            {RPCResult::Type::STR_AMOUNT, "staked_quantum_amount", "bonded or staking quantum value"},
            {RPCResult::Type::NUM, "goldrush_reward_outputs_needing_move", "wallet-owned Gold Rush reward UTXOs that still need migration"},
            {RPCResult::Type::STR_AMOUNT, "goldrush_reward_amount_needing_move", "total Gold Rush reward value still needing migration"},
            {RPCResult::Type::BOOL, "goldrush_remigration_active", "whether Gold Rush reward migration is currently allowed"},
            {RPCResult::Type::BOOL, "quantum_spends_active", "whether ML-DSA spends are enforceable at the tip"},
            {RPCResult::Type::STR, "advice", "human-readable next step"},
        }},
        RPCExamples{HelpExampleCli("getmigrationstatus", "") + HelpExampleRpc("getmigrationstatus", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return UniValue::VNULL;
        LOCK2(cs_main, pwallet->cs_wallet);

        const Consensus::Params& c = Params().GetConsensus();
        int64_t mtp = 0;
        int next_height = 0;
        if (const CBlockIndex* tip = pwallet->chain().getTip()) {
            mtp = tip->GetMedianTimePast();
            next_height = tip->nHeight + 1;
        }

        const bool scheduled = c.nQuantumMigrationDeadlineTime != 0;
        const bool passed = c.IsQuantumFinalLockout(mtp);
        const int64_t secs = (scheduled && c.nQuantumMigrationDeadlineTime > mtp)
                                 ? (c.nQuantumMigrationDeadlineTime - mtp) : 0;
        const bool quantum_active = IsQuantumWitnessSpendActive(c, mtp, next_height);

        CAmount legacy_amt = 0, quantum_amt = 0, direct_quantum_amt = 0, staked_quantum_amt = 0, goldrush_reward_amt = 0;
        unsigned int legacy_n = 0, quantum_n = 0, direct_quantum_n = 0, staked_quantum_n = 0, goldrush_reward_n = 0;
        ChainstateManager& chainman = pwallet->chain().chainman();
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        for (const COutput& out : AvailableCoinsListUnspent(*pwallet).All()) {
            const CScript& spk = out.txout.scriptPubKey;
            if (IsQuantumMigrationScript(spk)) {
                CTxDestination d;
                const bool wallet_owned = ExtractDestination(spk, d) && pwallet->GetQuantumKeyInfo(d).has_value();
                if (wallet_owned) { quantum_amt += out.txout.nValue; ++quantum_n; }
                CScript marker_script;
                if (IsGoldRushDirectPayoutOutput(view, out.outpoint, &marker_script) && marker_script == spk) {
                    goldrush_reward_amt += out.txout.nValue;
                    ++goldrush_reward_n;
                } else if (wallet_owned && IsDirectQuantumMigrationScript(spk)) {
                    direct_quantum_amt += out.txout.nValue;
                    ++direct_quantum_n;
                } else if (wallet_owned) {
                    staked_quantum_amt += out.txout.nValue;
                    ++staked_quantum_n;
                }
            } else if (IsQuantumColdStakeScript(spk)) {
                continue;
            } else if (!IsEUTXOScript(spk) && out.spendable) {
                legacy_amt += out.txout.nValue; ++legacy_n;
            }
        }

        const int64_t spacing = std::max<int64_t>(1, c.nTargetSpacing);
        UniValue r(UniValue::VOBJ);
        r.pushKV("phase", QQPhaseName(c.GetQuantumQuasarPhase(mtp)));
        r.pushKV("mediantime", mtp);
        r.pushKV("deadline_mtp", c.nQuantumMigrationDeadlineTime);
        r.pushKV("deadline_scheduled", scheduled);
        r.pushKV("seconds_until_deadline", secs);
        r.pushKV("blocks_until_deadline_est", (int64_t)(secs / spacing));
        r.pushKV("deadline_passed", passed);
        r.pushKV("eligible_legacy_inputs", (int)legacy_n);
        r.pushKV("eligible_legacy_amount", ValueFromAmount(legacy_amt));
        r.pushKV("migrated_quantum_outputs", (int)quantum_n);
        r.pushKV("migrated_quantum_amount", ValueFromAmount(quantum_amt));
        r.pushKV("direct_quantum_outputs", (int)direct_quantum_n);
        r.pushKV("direct_quantum_amount", ValueFromAmount(direct_quantum_amt));
        r.pushKV("staked_quantum_outputs", (int)staked_quantum_n);
        r.pushKV("staked_quantum_amount", ValueFromAmount(staked_quantum_amt));
        r.pushKV("goldrush_reward_outputs_needing_move", (int)goldrush_reward_n);
        r.pushKV("goldrush_reward_amount_needing_move", ValueFromAmount(goldrush_reward_amt));
        const bool goldrush_move_active = !passed && quantum_active;
        r.pushKV("goldrush_remigration_active", goldrush_move_active);
        r.pushKV("quantum_spends_active", quantum_active);
        std::string advice;
        if (passed && goldrush_reward_n > 0) advice = "Deadline passed. Remaining Gold Rush reward outputs are permanently unspendable.";
        else if (passed)         advice = "Deadline passed. Remaining legacy coins are permanently unspendable.";
        else if (goldrush_reward_n > 0 && goldrush_move_active) advice = "Run migrategoldrushrewards before staking, delegation, or final lockout to move Gold Rush reward outputs to a fresh quantum address.";
        else if (goldrush_reward_n > 0) advice = "Gold Rush reward outputs become ordinary quantum funds after they are moved to a fresh quantum address.";
        else if (legacy_n == 0)  advice = "No legacy coins remain to migrate.";
        else if (!scheduled)     advice = "No deadline scheduled yet, but you can migrate now with migratetoquantum.";
        else                     advice = "Run migratetoquantum before the deadline to move legacy coins into a quantum address.";
        r.pushKV("advice", advice);
        return r;
    }};
}
} // namespace wallet
