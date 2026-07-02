// Copyright (c) 2014-2023 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/tx_verify.h>
#include <core_io.h>
#include <crypto/mldsa.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <shadow.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/quantum_stake_ops.h>
#include <wallet/rpc/util.h>
#include <wallet/rpc/staking.h>
#include <wallet/spend.h>
#include <wallet/staking.h>
#include <wallet/redelegation.h>
#include <wallet/wallet.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/quantum_pool.h>
#include <key_io.h> // For EncodeDestination
#include <pow.h> // For GetNextTargetRequired
#include <script/solver.h>
#include <util/strencodings.h>
#include <warnings.h>

#include <univalue.h>

#include <algorithm>
#include <limits>
#include <map>
#include <optional>

using node::BlockAssembler;

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

static UniValue QuantumOperatorBondInfoToJSON(const interfaces::WalletQuantumOperatorBondInfo& info)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("available", info.available);
    obj.pushKV("valid_address", info.valid_operator_address);
    obj.pushKV("current_height", info.current_height);
    obj.pushKV("bonded_amount", ValueFromAmount(info.bonded_amount));
    obj.pushKV("bonded_outputs", info.bonded_outputs);
    obj.pushKV("unbonding_amount", ValueFromAmount(info.unbonding_amount));
    obj.pushKV("unbonding_outputs", info.unbonding_outputs);
    obj.pushKV("withdrawable_amount", ValueFromAmount(info.withdrawable_amount));
    obj.pushKV("withdrawable_outputs", info.withdrawable_outputs);
    obj.pushKV("next_unlock_height", info.next_unlock_height);
    return obj;
}

static UniValue QuantumStakeOutputsToJSON(const std::vector<interfaces::WalletQuantumStakeOutputInfo>& outputs)
{
    UniValue arr(UniValue::VARR);
    for (const auto& output : outputs) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("txid", output.txid);
        obj.pushKV("vout", output.vout);
        obj.pushKV("address", output.address);
        obj.pushKV("amount", ValueFromAmount(output.amount));
        obj.pushKV("depth", output.depth);
        obj.pushKV("state", output.state);
        obj.pushKV("unlock_height", output.unlock_height);
        obj.pushKV("spendable", output.spendable);
        arr.push_back(std::move(obj));
    }
    return arr;
}

static UniValue QuantumColdStakeBalanceToJSON(const interfaces::WalletQuantumColdStakeBalanceInfo& info)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("available", info.available);
    obj.pushKV("valid_delegation_address", info.valid_delegation_address);
    obj.pushKV("current_height", info.current_height);
    obj.pushKV("amount", ValueFromAmount(info.amount));
    obj.pushKV("outputs", info.outputs);
    obj.pushKV("confirmed_amount", ValueFromAmount(info.confirmed_amount));
    obj.pushKV("confirmed_outputs", info.confirmed_outputs);
    obj.pushKV("unconfirmed_amount", ValueFromAmount(info.unconfirmed_amount));
    obj.pushKV("unconfirmed_outputs", info.unconfirmed_outputs);
    obj.pushKV("spendable_amount", ValueFromAmount(info.spendable_amount));
    obj.pushKV("spendable_outputs", info.spendable_outputs);
    return obj;
}

static UniValue QuantumStakeTxToJSON(const interfaces::WalletQuantumOperatorBondTx& tx)
{
    UniValue obj(UniValue::VOBJ);
    if (!tx.txid.empty()) obj.pushKV("txid", tx.txid);
    obj.pushKV("address", tx.address);
    obj.pushKV("amount", ValueFromAmount(tx.amount));
    obj.pushKV("fee", ValueFromAmount(tx.fee));
    obj.pushKV("unlock_height", tx.unlock_height);
    obj.pushKV("started_unbonding", tx.started_unbonding);
    obj.pushKV("completed_withdrawal", tx.completed_withdrawal);
    obj.pushKV("created_goldrush_migration", tx.created_migration);
    obj.pushKV("completed_delegation", tx.completed_delegation);
    if (!tx.migration_txid.empty()) obj.pushKV("migration_txid", tx.migration_txid);
    if (!tx.migration_address.empty()) obj.pushKV("migration_address", tx.migration_address);
    if (tx.migration_amount > 0) obj.pushKV("migration_amount", ValueFromAmount(tx.migration_amount));
    if (tx.migration_fee > 0) obj.pushKV("migration_fee", ValueFromAmount(tx.migration_fee));
    if (!tx.warning.empty()) obj.pushKV("warning", tx.warning);
    return obj;
}

static COutPoint OutPointFromRPCOptions(const UniValue& options)
{
    if (!options.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outpoint must be an object with txid and vout");
    }
    const UniValue& txid_v = options.find_value("txid");
    const UniValue& vout_v = options.find_value("vout");
    if (!txid_v.isStr() || !vout_v.isNum()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outpoint must include string txid and numeric vout");
    }
    const int vout = vout_v.getInt<int>();
    if (vout < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
    }
    return COutPoint{ParseHashV(txid_v, "txid"), static_cast<uint32_t>(vout)};
}

static UniValue StakingDonationInfoToJSON(const CWallet& wallet)
{
    const unsigned int percentage = wallet.m_donation_percentage;
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("enabled", percentage > 0);
    obj.pushKV("percentage", percentage);
    obj.pushKV("minimum_percentage", MIN_DONATION_PERCENTAGE);
    obj.pushKV("maximum_percentage", MAX_DONATION_PERCENTAGE);
    obj.pushKV("default_percentage", DEFAULT_DONATION_PERCENTAGE);
    obj.pushKV("pre_migration_suggested_percentage", DEFAULT_DONATION_SUGGESTED_PERCENTAGE);
    obj.pushKV("post_migration_default_percentage", DEFAULT_POST_MIGRATION_DONATION_PERCENTAGE);
    obj.pushKV("target_address", Params().GetDevFundAddress());
    obj.pushKV("note", "Set percentage to 0 to disable staking donations. Nonzero values are honored when the active staking reward format permits donation outputs.");
    return obj;
}

static std::vector<RPCResult> QuantumOperatorBondInfoResult()
{
    return {
        {RPCResult::Type::BOOL, "available", "false if wallet state could not be locked"},
        {RPCResult::Type::BOOL, "valid_address", "true if the address is a wallet-backed staking/operator address"},
        {RPCResult::Type::NUM, "current_height", "Wallet chain height"},
        {RPCResult::Type::STR_AMOUNT, "bonded_amount", "Currently bonded amount"},
        {RPCResult::Type::NUM, "bonded_outputs", "Number of bonded outputs"},
        {RPCResult::Type::STR_AMOUNT, "unbonding_amount", "Amount in the unbonding state"},
        {RPCResult::Type::NUM, "unbonding_outputs", "Number of unbonding outputs"},
        {RPCResult::Type::STR_AMOUNT, "withdrawable_amount", "Amount matured enough to withdraw"},
        {RPCResult::Type::NUM, "withdrawable_outputs", "Number of withdrawable outputs"},
        {RPCResult::Type::NUM, "next_unlock_height", "Next unbonding output unlock height, or 0"},
    };
}

static std::vector<RPCResult> QuantumStakeTxResult()
{
    return {
        {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast transaction id, when a transaction was completed"},
        {RPCResult::Type::STR, "address", "Destination or staking address"},
        {RPCResult::Type::STR_AMOUNT, "amount", "Transaction amount"},
        {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
        {RPCResult::Type::NUM, "unlock_height", "Unlock height for newly unbonding funds, or 0"},
        {RPCResult::Type::BOOL, "started_unbonding", "true if the transaction started an unbonding period"},
        {RPCResult::Type::BOOL, "completed_withdrawal", "true if the transaction withdrew matured funds"},
        {RPCResult::Type::BOOL, "created_goldrush_migration", "true if Gold Rush rewards were first moved to a fresh quantum address"},
        {RPCResult::Type::BOOL, "completed_delegation", "true if the requested delegation/funding transaction completed"},
        {RPCResult::Type::STR_HEX, "migration_txid", /*optional=*/true, "Gold Rush reward migration transaction id"},
        {RPCResult::Type::STR, "migration_address", /*optional=*/true, "Fresh quantum migration address"},
        {RPCResult::Type::STR_AMOUNT, "migration_amount", /*optional=*/true, "Amount moved by the Gold Rush migration"},
        {RPCResult::Type::STR_AMOUNT, "migration_fee", /*optional=*/true, "Fee paid by the Gold Rush migration"},
        {RPCResult::Type::STR, "warning", /*optional=*/true, "Follow-up warning"},
    };
}

static UniValue ThrowOrReturnQuantumStakeTx(util::Result<interfaces::WalletQuantumOperatorBondTx>&& result)
{
    if (!result) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(result).original);
    }
    return QuantumStakeTxToJSON(*result);
}

static RPCHelpMan getstakinginfo()
{
    return RPCHelpMan{"getstakinginfo",
                "\nReturns an object containing staking-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "'true' if staking is enabled"},
                        {RPCResult::Type::BOOL, "staking", "'true' if wallet is currently staking"},
                        {RPCResult::Type::STR, "errors", "error messages"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM, "search-interval", "The staker search interval"},
                        {RPCResult::Type::NUM, "weight", "The staker weight"},
                        {RPCResult::Type::NUM, "netstakeweight", "Network stake weight"},
                        {RPCResult::Type::NUM, "expectedtime", "Expected time to earn reward"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getstakinginfo", "")
            + HelpExampleRpc("getstakinginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    uint64_t nWeight = 0;
    uint64_t lastCoinStakeSearchInterval = 0;

    if (pwallet)
    {
        LOCK(pwallet->cs_wallet);
        nWeight = pwallet->GetStakeWeight();
        lastCoinStakeSearchInterval = pwallet->m_enabled_staking ? pwallet->m_last_coin_stake_search_interval : 0;
    }

    const CTxMemPool& mempool = pwallet->chain().mempool();
    ChainstateManager& chainman = pwallet->chain().chainman();
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    UniValue obj(UniValue::VOBJ);

    uint64_t nNetworkWeight = 1.1429 * GetPoSKernelPS(chainman);
    bool staking = lastCoinStakeSearchInterval && nWeight;

    const Consensus::Params& consensusParams = Params().GetConsensus();
    int64_t nTargetSpacing = consensusParams.nTargetSpacing;
    uint64_t nExpectedTime = staking ? 1.0455 * nTargetSpacing * nNetworkWeight / nWeight : 0;

    obj.pushKV("enabled", pwallet->m_enabled_staking.load());
    obj.pushKV("staking", staking);

    obj.pushKV("blocks", active_chain.Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("pooledtx", (uint64_t)mempool.size());

    obj.pushKV("difficulty", GetDifficulty(GetLastBlockIndex(chainman.m_best_header, true)));

    obj.pushKV("search-interval", (int)lastCoinStakeSearchInterval);
    obj.pushKV("weight", (uint64_t)nWeight);
    obj.pushKV("netstakeweight", (uint64_t)nNetworkWeight);
    obj.pushKV("expectedtime", nExpectedTime);

    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("warnings", GetWarnings(false).original);
    return obj;
},
    };
}

static RPCHelpMan staking()
{
    return RPCHelpMan{"staking",
            "Gets or sets the current staking configuration.\n"
            "When called without an argument, returns the current status of staking.\n"
            "When called with an argument, enables or disables staking.\n",
            {
                {"generate", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "To enable or disable staking."},

            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "staking", "if staking is active or not. false: inactive, true: active"},
                }
            },
            RPCExamples{
                HelpExampleCli("staking", "true")
                + HelpExampleRpc("staking", "true")
            },
            [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    std::string error = "";
    if (request.params.size() > 0)
    {
        if (request.params[0].get_bool() && node::CanStake())
        {
            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                error = "The wallet can't contain any private keys";
            } else if (pwallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
                error = "The wallet is blank";
            }
            if (!pwallet->m_enabled_staking)
                StartStake(*pwallet);
        }
        else {
            StopStake(*pwallet);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("staking", pwallet->m_enabled_staking.load());
    if (!error.empty()) {
        result.pushKV("error", error);
    }
    return result;
},
    };
}

static RPCHelpMan reservebalance()
{
    return RPCHelpMan{"reservebalance",
            "\nSet reserve amount not participating in network protection."
            "\nIf no parameters provided current setting is printed.\n",
            {
                {"reserve", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED,"is true or false to turn balance reserve on or off."},
                {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "is a real and rounded to cent."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "reserve", "Balance reserve on or off"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount reserve rounded to cent"}
                }
            },
             RPCExamples{
            "\nSet reserve balance to 100\n"
            + HelpExampleCli("reservebalance", "true 100") +
            "\nSet reserve balance to 0\n"
            + HelpExampleCli("reservebalance", "false") +
            "\nGet reserve balance\n"
            + HelpExampleCli("reservebalance", "")			},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);
    if (request.params.size() > 0)
    {
        bool fReserve = request.params[0].get_bool();
        if (fReserve)
        {
            if (request.params.size() == 1)
                throw std::runtime_error("must provide amount to reserve balance.\n");
            int64_t nAmount = AmountFromValue(request.params[1]);
            nAmount = (nAmount / CENT) * CENT;  // round to cent
            if (nAmount < 0)
                throw std::runtime_error("amount cannot be negative.\n");
            pwallet->m_reserve_balance = nAmount;
        }
        else
        {
            if (request.params.size() > 1)
                throw std::runtime_error("cannot specify amount to turn off reserve.\n");
            pwallet->m_reserve_balance = 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("reserve", (pwallet->m_reserve_balance > 0));
    result.pushKV("amount", ValueFromAmount(pwallet->m_reserve_balance));
    return result;
},
    };
}

static RPCHelpMan getstakingdonationinfo()
{
    return RPCHelpMan{"getstakingdonationinfo",
        "\nReturns wallet staking donation settings used by coinstake creation.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "true when staking donations are enabled"},
            {RPCResult::Type::NUM, "percentage", "Percentage of eligible stake rewards to donate"},
            {RPCResult::Type::NUM, "minimum_percentage", "Minimum accepted donation percentage"},
            {RPCResult::Type::NUM, "maximum_percentage", "Maximum accepted donation percentage"},
            {RPCResult::Type::NUM, "default_percentage", "Startup default donation percentage"},
            {RPCResult::Type::NUM, "pre_migration_suggested_percentage", "GUI suggested percentage before migration completes"},
            {RPCResult::Type::NUM, "post_migration_default_percentage", "GUI default after migration completes when the user has not chosen otherwise"},
            {RPCResult::Type::STR, "target_address", "Configured project donation address"},
            {RPCResult::Type::STR, "note", "Operational note"},
        }},
        RPCExamples{HelpExampleCli("getstakingdonationinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);
    return StakingDonationInfoToJSON(*pwallet);
},
    };
}

static RPCHelpMan setstakingdonation()
{
    return RPCHelpMan{"setstakingdonation",
        "\nSets the wallet staking donation percentage. Use 0 to turn donations off.\n",
        {
            {"percentage", RPCArg::Type::NUM, RPCArg::Optional::NO, "Donation percentage from 0 to 95."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "true when staking donations are enabled"},
            {RPCResult::Type::NUM, "percentage", "Percentage of eligible stake rewards to donate"},
            {RPCResult::Type::NUM, "minimum_percentage", "Minimum accepted donation percentage"},
            {RPCResult::Type::NUM, "maximum_percentage", "Maximum accepted donation percentage"},
            {RPCResult::Type::STR, "target_address", "Configured project donation address"},
        }},
        RPCExamples{
            HelpExampleCli("setstakingdonation", "0") +
            HelpExampleCli("setstakingdonation", "5")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    int64_t percentage_signed{0};
    if (!ParseInt64(request.params[0].getValStr(), &percentage_signed)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "percentage must be an integer");
    }
    if (percentage_signed < MIN_DONATION_PERCENTAGE || percentage_signed > MAX_DONATION_PERCENTAGE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("percentage must be between %u and %u", MIN_DONATION_PERCENTAGE, MAX_DONATION_PERCENTAGE));
    }

    LOCK(pwallet->cs_wallet);
    pwallet->m_donation_percentage = static_cast<unsigned int>(percentage_signed);
    return StakingDonationInfoToJSON(*pwallet);
},
    };
}

static RPCHelpMan getquantumstakeaddressinfo()
{
    return RPCHelpMan{"getquantumstakeaddressinfo",
        "\nReturns wallet-owned bonded quantum staking balance state for a staking address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed bonded quantum staking address."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumOperatorBondInfoResult()},
        RPCExamples{HelpExampleCli("getquantumstakeaddressinfo", "\"quantum_stake_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    return QuantumOperatorBondInfoToJSON(MakeWalletTieredStakeBondInfo(*pwallet, request.params[0].get_str(), /*require_operator_lock=*/false));
},
    };
}

static RPCHelpMan listquantumstakeoutputs()
{
    return RPCHelpMan{"listquantumstakeoutputs",
        "\nLists wallet-owned bonded, unbonding, and withdrawable quantum staking outputs for a staking address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed bonded quantum staking address."},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "txid", "Funding or unbonding transaction id"},
                {RPCResult::Type::NUM, "vout", "Output index"},
                {RPCResult::Type::STR, "address", "Staking address"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Output amount"},
                {RPCResult::Type::NUM, "depth", "Confirmation depth"},
                {RPCResult::Type::STR, "state", "bonded, unbonding, or withdrawable"},
                {RPCResult::Type::NUM, "unlock_height", "Unlock height for unbonding outputs"},
                {RPCResult::Type::BOOL, "spendable", "true if wallet can currently spend this output"},
            }},
        }},
        RPCExamples{HelpExampleCli("listquantumstakeoutputs", "\"quantum_stake_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    return QuantumStakeOutputsToJSON(ListTieredStakeOutputs(*pwallet, request.params[0].get_str(), /*require_operator_lock=*/false));
},
    };
}

static RPCHelpMan fundquantumstakeaddress()
{
    return RPCHelpMan{"fundquantumstakeaddress",
        "\nFunds a wallet-backed bonded quantum staking address from legacy wallet coins.\n" + HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed bonded quantum staking address."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to bond."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("fundquantumstakeaddress", "\"quantum_stake_address\" 10000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    return ThrowOrReturnQuantumStakeTx(FundTieredStakeAddress(
        *pwallet,
        request.params[0].get_str(),
        AmountFromValue(request.params[1]),
        /*require_operator_lock=*/false,
        "Blackcoin quantum staking address funding"));
},
    };
}

static RPCHelpMan withdrawquantumstakeaddress()
{
    return RPCHelpMan{"withdrawquantumstakeaddress",
        "\nStarts unbonding or withdraws matured quantum staking funds for a staking address.\n" + HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed bonded quantum staking address."},
            {"outpoint", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional single staking output to withdraw/unbond.", {
                {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id."},
                {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("withdrawquantumstakeaddress", "\"quantum_stake_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    std::optional<COutPoint> outpoint;
    if (request.params.size() > 1 && !request.params[1].isNull()) outpoint = OutPointFromRPCOptions(request.params[1]);
    return ThrowOrReturnQuantumStakeTx(WithdrawTieredStakeAddress(
        *pwallet,
        request.params[0].get_str(),
        /*require_operator_lock=*/false,
        "quantum-stake-unbonding",
        "quantum-stake-withdrawal",
        "Blackcoin quantum staking address unbond",
        "Blackcoin quantum staking address withdrawal",
        outpoint));
},
    };
}

static RPCHelpMan getquantumoperatorbondinfo()
{
    return RPCHelpMan{"getquantumoperatorbondinfo",
        "\nReturns wallet-owned operator bond state for a fixed 30-day cold-stake operator address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed fixed 30-day cold-stake operator address."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumOperatorBondInfoResult()},
        RPCExamples{HelpExampleCli("getquantumoperatorbondinfo", "\"operator_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    return QuantumOperatorBondInfoToJSON(MakeWalletOperatorBondInfo(*pwallet, request.params[0].get_str()));
},
    };
}

static RPCHelpMan fundquantumoperatorbond()
{
    return RPCHelpMan{"fundquantumoperatorbond",
        "\nFunds a fixed 30-day cold-stake operator bond from legacy wallet coins.\n" + HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed fixed 30-day cold-stake operator address."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to bond."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("fundquantumoperatorbond", "\"operator_address\" 10000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    return ThrowOrReturnQuantumStakeTx(FundTieredStakeAddress(
        *pwallet,
        request.params[0].get_str(),
        AmountFromValue(request.params[1]),
        /*require_operator_lock=*/true,
        "Blackcoin cold-stake operator bond"));
},
    };
}

static RPCHelpMan withdrawquantumoperatorbond()
{
    return RPCHelpMan{"withdrawquantumoperatorbond",
        "\nStarts unbonding or withdraws matured cold-stake operator bond funds.\n" + HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed fixed 30-day cold-stake operator address."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("withdrawquantumoperatorbond", "\"operator_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    return ThrowOrReturnQuantumStakeTx(WithdrawTieredStakeAddress(
        *pwallet,
        request.params[0].get_str(),
        /*require_operator_lock=*/true,
        "coldstake-operator-unbonding",
        "coldstake-operator-withdrawal",
        "Blackcoin cold-stake operator unbond",
        "Blackcoin cold-stake operator withdrawal"));
},
    };
}

static RPCHelpMan getquantumcoldstakebalance()
{
    return RPCHelpMan{"getquantumcoldstakebalance",
        "\nReturns wallet-owned balance state for a quantum cold-stake delegation address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed quantum cold-stake delegation address."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "available", "false if wallet state could not be locked"},
            {RPCResult::Type::BOOL, "valid_delegation_address", "true if this is a wallet-backed cold-stake delegation address"},
            {RPCResult::Type::NUM, "current_height", "Wallet chain height"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Total delegated amount"},
            {RPCResult::Type::NUM, "outputs", "Total delegation outputs"},
            {RPCResult::Type::STR_AMOUNT, "confirmed_amount", "Confirmed delegated amount"},
            {RPCResult::Type::NUM, "confirmed_outputs", "Confirmed delegation outputs"},
            {RPCResult::Type::STR_AMOUNT, "unconfirmed_amount", "Unconfirmed delegated amount"},
            {RPCResult::Type::NUM, "unconfirmed_outputs", "Unconfirmed delegation outputs"},
            {RPCResult::Type::STR_AMOUNT, "spendable_amount", "Currently spendable delegated amount"},
            {RPCResult::Type::NUM, "spendable_outputs", "Currently spendable delegation outputs"},
        }},
        RPCExamples{HelpExampleCli("getquantumcoldstakebalance", "\"coldstake_delegation_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    return QuantumColdStakeBalanceToJSON(MakeWalletColdStakeBalanceInfo(*pwallet, request.params[0].get_str()));
},
    };
}

static RPCHelpMan fundquantumcoldstakeaddress()
{
    return RPCHelpMan{"fundquantumcoldstakeaddress",
        "\nFunds a quantum cold-stake delegation address from direct quantum funds.\n"
        "If only wallet-owned Gold Rush reward outputs are available, the wallet first moves them to a fresh quantum address and then funds the delegation.\n" +
        HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed quantum cold-stake delegation address."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to delegate."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("fundquantumcoldstakeaddress", "\"coldstake_delegation_address\" 1000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    return ThrowOrReturnQuantumStakeTx(FundColdStakeDelegationAddress(*pwallet, request.params[0].get_str(), AmountFromValue(request.params[1])));
},
    };
}

static RPCHelpMan withdrawquantumcoldstakeaddress()
{
    return RPCHelpMan{"withdrawquantumcoldstakeaddress",
        "\nStarts unbonding or withdraws matured funds from a quantum cold-stake delegation address.\n" + HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed quantum cold-stake delegation address."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", QuantumStakeTxResult()},
        RPCExamples{HelpExampleCli("withdrawquantumcoldstakeaddress", "\"coldstake_delegation_address\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    pwallet->BlockUntilSyncedToCurrentChain();

    return ThrowOrReturnQuantumStakeTx(WithdrawColdStakeDelegationAddress(*pwallet, request.params[0].get_str()));
},
    };
}

static RPCHelpMan sendshadowsignal()
{
    return RPCHelpMan{"sendshadowsignal",
                "\nBroadcast a Blackcoin Gold Rush activity signal for a whitelisted address that solved a block in the last 14 days.\n"
                "The transaction spends one wallet UTXO from the signaling address, pays change back to the same address, and attaches the QQSIGNAL payload.\n"
                "The signal links the whitelisted legacy address to the required quantum migration payout address.\n"
                "Consensus counts this signal only if the referenced solve has a deterministic solver marker and the signal is mined inside the 14-day activity window.\n" +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet address whose aggregate snapshot balance qualified for the shadow whitelist."},
                    {"solve_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Height of a block solved by this address within the last 14 days."},
                    {"solve_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the solved block at solve_height."},
                    {"quantum_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Quantum migration address that should receive this address's Gold Rush shadow-ledger credit."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Optional fee rate in " + CURRENCY_ATOM + "/vB. Must not be below the wallet minimum fee rate."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The broadcast signal transaction id."},
                        {RPCResult::Type::STR_HEX, "hex", "The signed signal transaction hex."},
                        {RPCResult::Type::STR_AMOUNT, "fee", "The fee paid by the signal transaction."},
                        {RPCResult::Type::STR_AMOUNT, "change", "The amount paid back to the signaling address."},
                        {RPCResult::Type::NUM, "vsize", "Estimated virtual transaction size used for fee calculation."},
                        {RPCResult::Type::STR, "address", "The signaling address."},
                        {RPCResult::Type::STR, "quantum_address", "The linked quantum migration payout address."},
                        {RPCResult::Type::NUM, "solve_height", "The referenced solved block height."},
                        {RPCResult::Type::STR_HEX, "solve_hash", "The referenced solved block hash."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("sendshadowsignal", "\"" + EXAMPLE_ADDRESS[0] + "\" 5921234 \"0000000000000000000000000000000000000000000000000000000000000001\" \"quantum_address\"")
            + HelpExampleCli("-named sendshadowsignal", "address=\"" + EXAMPLE_ADDRESS[0] + "\" solve_height=5921234 solve_hash=\"0000000000000000000000000000000000000000000000000000000000000001\" quantum_address=\"quantum_address\" fee_rate=1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(*pwallet);
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }
    if (pwallet->m_wallet_unlock_staking_only) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet unlocked for staking only, unable to create signal transaction");
    }

    const std::string address = request.params[0].get_str();
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Blackcoin address");
    }
    const CScript target = GetScriptForDestination(dest);
    if (target.empty() || target.IsUnspendable()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not resolve to a signalable script");
    }

    const int64_t solve_height_signed = request.params[1].getInt<int64_t>();
    if (solve_height_signed <= 0 || solve_height_signed > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "solve_height out of range");
    }
    const uint32_t solve_height = static_cast<uint32_t>(solve_height_signed);
    const uint256 solve_hash = ParseHashV(request.params[2], "solve_hash");
    CScript quantum_payout_script;
    const std::string quantum_address = request.params[3].get_str();
    const CTxDestination quantum_dest = DecodeDestination(quantum_address);
    if (!IsValidDestination(quantum_dest) || !IsQuantumMigrationDestination(quantum_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "quantum_address must be a Blackcoin migration address");
    }
    quantum_payout_script = GetScriptForDestination(quantum_dest);
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "quantum_address must be an ordinary quantum receive address, not a bonded staking or cold-stake address");
    }

    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        const CChain& active_chain = chainman.ActiveChain();
        const CBlockIndex* tip = active_chain.Tip();
        if (!tip) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "No active chain tip");
        }
        const Consensus::Params& consensus = Params().GetConsensus();
        if (!consensus.IsGoldRushEpoch(tip->GetMedianTimePast())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Shadow signaling is only active during the Gold Rush epoch");
        }
        if (solve_height > static_cast<uint32_t>(tip->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "solve_height is above the active chain tip");
        }
        const CBlockIndex* solved = active_chain[solve_height];
        if (!solved || solved->GetBlockHash() != solve_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "solve_hash does not match the active-chain block at solve_height");
        }
        if (tip->nHeight - static_cast<int>(solve_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "referenced solve is outside the 14-day height window");
        }
        if (tip->GetBlockTime() - solved->GetBlockTime() > SHADOW_SOLVER_ACTIVITY_SECONDS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "referenced solve is outside the 14-day time window");
        }
        if (tip->nHeight >= SHADOW_REWARD_START_HEIGHT) {
            if (!IsWhitelisted(chainman.ActiveChainstate().CoinsTip(), target)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "address is not in the deterministic Gold Rush whitelist");
            }
            bool has_solver_activity = HasRecentShadowSolverActivity(chainman.ActiveChainstate().CoinsTip(), tip, target, solve_height, solve_hash);
            if (!has_solver_activity && solve_height == static_cast<uint32_t>(tip->nHeight)) {
                const auto recent_solvers = GetRecentShadowSolverActivity(chainman.ActiveChainstate().CoinsTip(), tip);
                const auto it = recent_solvers.find(target);
                has_solver_activity = it != recent_solvers.end() && it->second.height == solve_height;
            }
            if (!has_solver_activity) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "referenced solve is not an active Gold Rush solver marker for this address");
            }
        }
    }

    std::vector<unsigned char> signal;
    const bool built_signal = BuildShadowSignalData(target, quantum_payout_script, solve_height, solve_hash, signal);
    if (!built_signal) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build shadow signal payload");
    }

    CCoinControl coin_control;
    coin_control.destChange = dest;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_address_reuse = false;
    if (!request.params[4].isNull()) {
        coin_control.m_feerate = FeeRateFromSatVbValue(request.params[4]);
        coin_control.fOverrideFeeRate = true;
    }

    CMutableTransaction signal_tx;
    CAmount fee{0};
    CAmount change{0};
    int64_t vsize{-1};
    {
        LOCK(pwallet->cs_wallet);
        const int64_t current_time = GetAdjustedTimeSeconds();
        const CFeeRate fee_rate = GetMinimumFeeRate(*pwallet, coin_control, current_time);
        if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB)));
        }
        for (const COutput& output : AvailableCoins(*pwallet, &coin_control).All()) {
            if (output.txout.scriptPubKey != target || output.input_bytes < 0) continue;

            CMutableTransaction candidate;
            candidate.nVersion = CTransaction::CURRENT_VERSION;
            candidate.nTime = current_time;
            static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
            candidate.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
            candidate.vout.emplace_back(output.txout.nValue, target);
            candidate.vout.emplace_back(0, CScript() << OP_RETURN << signal);

            const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(candidate), pwallet.get(), &coin_control);
            if (tx_size.vsize <= 0) continue;
            const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
            const CAmount candidate_change = output.txout.nValue - candidate_fee;
            CTxOut change_out(candidate_change, target);
            if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, pwallet->chain().relayDustFee())) continue;
            if (candidate_fee > pwallet->m_default_max_tx_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Fee exceeds wallet max transaction fee (%s)", FormatMoney(pwallet->m_default_max_tx_fee)));
            }

            candidate.vout[0].nValue = candidate_change;
            std::map<int, bilingual_str> input_errors;
            if (!pwallet->SignTransaction(candidate, input_errors)) {
                if (!input_errors.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Signing signal transaction failed: %s", input_errors.begin()->second.original));
                }
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing signal transaction failed");
            }

            signal_tx = std::move(candidate);
            fee = candidate_fee;
            change = candidate_change;
            vsize = tx_size.vsize;
            break;
        }
    }

    if (signal_tx.vin.empty()) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable non-dust UTXO found for the signaling address");
    }

    CTransactionRef tx = MakeTransactionRef(std::move(signal_tx));
    const std::string hex = EncodeHexTx(*tx);
    mapValue_t map_value;
    map_value["comment"] = "Blackcoin shadow signal";
    CommitWalletTransactionOrThrow(*pwallet, tx, std::move(map_value), "Blackcoin shadow signal");

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("hex", hex);
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("change", ValueFromAmount(change));
    result.pushKV("vsize", vsize);
    result.pushKV("address", address);
    result.pushKV("quantum_address", quantum_address);
    result.pushKV("solve_height", solve_height);
    result.pushKV("solve_hash", solve_hash.GetHex());
    return result;
},
    };
}

static RPCHelpMan sendshadowpowclaim()
{
    return RPCHelpMan{"sendshadowpowclaim",
                "\nGrind or submit an Argon2id Blackcoin shadow PoW proof and broadcast the claim transaction.\n"
                "The transaction spends one wallet UTXO from the target legacy address, pays change back to the same address, and attaches the QQSPROOF payload.\n"
                "PoW claims are NOT whitelist-gated. A valid mined claim credits the upgraded shadow ledger to quantum_address without changing the legacy block subsidy.\n"
                "If proof is omitted, grinding is memory-hard (Argon2id, ~1 MiB per try) and synchronous; tune max_tries accordingly.\n"
                "If proof is supplied, it must be the hex QQSPROOF payload for the current tip, target address, and quantum payout address.\n"
                "Only valid during the Gold Rush reward window.\n" +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet legacy address that owns the UTXO authenticating this PoW claim. It does not need to be whitelisted."},
                    {"quantum_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Quantum migration address that should receive this address's Gold Rush PoW shadow-ledger credit."},
                    {"max_tries", RPCArg::Type::NUM, RPCArg::Default{1000000}, "Maximum Argon2id nonces to grind before giving up. Ignored when proof is supplied."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Optional fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional externally mined QQSPROOF payload hex from getshadowpowwork parameters."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The broadcast claim transaction id."},
                        {RPCResult::Type::STR_HEX, "hex", "The signed claim transaction hex."},
                        {RPCResult::Type::STR_HEX, "proof", "The QQSPROOF payload committed by the transaction."},
                        {RPCResult::Type::BOOL, "external_proof", "Whether the proof was supplied by the caller instead of ground by this RPC."},
                        {RPCResult::Type::STR_AMOUNT, "fee", "The fee paid by the claim transaction."},
                        {RPCResult::Type::STR_AMOUNT, "change", "The amount paid back to the target address."},
                        {RPCResult::Type::NUM, "vsize", "Estimated virtual transaction size."},
                        {RPCResult::Type::STR, "address", "The target legacy address."},
                        {RPCResult::Type::STR, "quantum_address", "The linked quantum migration payout address."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("sendshadowpowclaim", "\"" + EXAMPLE_ADDRESS[0] + "\" \"quantum_address\"")
            + HelpExampleCli("-named sendshadowpowclaim", "address=\"" + EXAMPLE_ADDRESS[0] + "\" quantum_address=\"quantum_address\" max_tries=2000000 fee_rate=1")
            + HelpExampleCli("-named sendshadowpowclaim", "address=\"" + EXAMPLE_ADDRESS[0] + "\" quantum_address=\"quantum_address\" proof=\"51515350524f4f46...\" fee_rate=1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(*pwallet);
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }
    if (pwallet->m_wallet_unlock_staking_only) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet unlocked for staking only, unable to create claim transaction");
    }

    const std::string address = request.params[0].get_str();
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Blackcoin address");
    }
    const CScript target = GetScriptForDestination(dest);
    if (target.empty() || target.IsUnspendable() || IsQuantumMigrationScript(target) || IsQuantumColdStakeScript(target) || IsEUTXOScript(target)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "address must be a spendable legacy script (not a quantum/EUTXO script)");
    }

    const std::string quantum_address = request.params[1].get_str();
    const CTxDestination quantum_dest = DecodeDestination(quantum_address);
    if (!IsValidDestination(quantum_dest) || !IsQuantumMigrationDestination(quantum_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "quantum_address must be a Blackcoin migration address");
    }
    const CScript quantum_payout_script = GetScriptForDestination(quantum_dest);
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "quantum_address must be an ordinary quantum receive address, not a bonded staking or cold-stake address");
    }

    std::optional<std::vector<unsigned char>> supplied_proof;
    if (!request.params[4].isNull()) {
        std::vector<unsigned char> parsed_proof = ParseHexV(request.params[4], "proof");
        const std::vector<unsigned char>& prefix = GetShadowPrefix();
        if (parsed_proof.size() <= prefix.size() ||
            parsed_proof.size() > MAX_SCRIPT_ELEMENT_SIZE ||
            !std::equal(prefix.begin(), prefix.end(), parsed_proof.begin())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "proof must be a hex-encoded QQSPROOF payload");
        }
        supplied_proof = std::move(parsed_proof);
    }

    uint64_t max_tries = 1000000;
    if (!request.params[2].isNull()) {
        const int64_t mt = request.params[2].getInt<int64_t>();
        if (mt <= 0) {
            if (!supplied_proof) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_tries must be positive");
        } else {
            max_tries = static_cast<uint64_t>(mt);
        }
    }

    CCoinControl coin_control;
    coin_control.destChange = dest;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_avoid_address_reuse = false;
    if (!request.params[3].isNull()) {
        coin_control.m_feerate = FeeRateFromSatVbValue(request.params[3]);
        coin_control.fOverrideFeeRate = true;
    }

    ShadowPowWork pow_work;
    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        if (!tip) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "No active chain tip");
        }
        const Consensus::Params& consensus = Params().GetConsensus();
        if (!consensus.IsGoldRushEpoch(tip->GetMedianTimePast())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Shadow PoW claims are only active during the Gold Rush epoch");
        }
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        pow_work = PrepareShadowPowWork(target, quantum_payout_script, tip, view);
        if (!pow_work.valid) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to prepare shadow PoW work (outside the reward window or invalid payout script)");
        }
    }

    {
        LOCK(pwallet->cs_wallet);
        const int64_t current_time = GetAdjustedTimeSeconds();
        const CFeeRate fee_rate = GetMinimumFeeRate(*pwallet, coin_control, current_time);
        if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB)));
        }

        // QQSPROOF payload size is deterministic for internally ground proofs:
        // OP_RETURN data = prefix(8) + proof header(13) + target/payout length fields(4) + scripts.
        std::vector<unsigned char> dummy_proof;
        const std::vector<unsigned char>* fee_probe_proof = nullptr;
        if (supplied_proof) {
            fee_probe_proof = &*supplied_proof;
        } else {
            dummy_proof.assign(GetShadowPrefix().size() + 17 + target.size() + quantum_payout_script.size(), 0);
            std::copy(GetShadowPrefix().begin(), GetShadowPrefix().end(), dummy_proof.begin());
            fee_probe_proof = &dummy_proof;
        }
        bool can_submit_claim = false;
        for (const COutput& output : AvailableCoins(*pwallet, &coin_control).All()) {
            if (output.txout.scriptPubKey != target || output.input_bytes < 0) continue;

            CMutableTransaction candidate;
            candidate.nVersion = CTransaction::CURRENT_VERSION;
            candidate.nTime = current_time;
            static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
            candidate.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
            candidate.vout.emplace_back(output.txout.nValue, target);
            candidate.vout.emplace_back(0, CScript() << OP_RETURN << *fee_probe_proof);

            const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(candidate), pwallet.get(), &coin_control);
            if (tx_size.vsize <= 0) continue;
            const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
            const CAmount candidate_change = output.txout.nValue - candidate_fee;
            CTxOut change_out(candidate_change, target);
            if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, pwallet->chain().relayDustFee())) continue;
            if (candidate_fee > pwallet->m_default_max_tx_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Fee exceeds wallet max transaction fee (%s)", FormatMoney(pwallet->m_default_max_tx_fee)));
            }
            can_submit_claim = true;
            break;
        }
        if (!can_submit_claim) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable non-dust UTXO found for the target address");
        }
    }

    std::vector<unsigned char> proof;
    if (supplied_proof) {
        proof = *supplied_proof;
    } else if (!GrindShadowPowWork(pow_work, /*start_nonce=*/0, /*nonce_step=*/1, max_tries, proof)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to grind a valid shadow PoW proof (max_tries exhausted)");
    }

    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        const Consensus::Params& consensus = Params().GetConsensus();
        if (!tip || tip->GetBlockHash() != pow_work.prev_hash ||
            !consensus.IsGoldRushEpoch(tip->GetMedianTimePast())) {
            throw JSONRPCError(RPC_VERIFY_REJECTED, "Active chain tip changed while grinding; retry the PoW claim");
        }
    }

    CMutableTransaction claim_tx;
    CAmount fee{0};
    CAmount change{0};
    int64_t vsize{-1};
    {
        LOCK(pwallet->cs_wallet);
        const int64_t current_time = GetAdjustedTimeSeconds();
        const CFeeRate fee_rate = GetMinimumFeeRate(*pwallet, coin_control, current_time);
        if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB)));
        }
        for (const COutput& output : AvailableCoins(*pwallet, &coin_control).All()) {
            if (output.txout.scriptPubKey != target || output.input_bytes < 0) continue;

            CMutableTransaction candidate;
            candidate.nVersion = CTransaction::CURRENT_VERSION;
            candidate.nTime = current_time;
            static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
            candidate.vin.emplace_back(output.outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
            candidate.vout.emplace_back(output.txout.nValue, target);
            candidate.vout.emplace_back(0, CScript() << OP_RETURN << proof);

            const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(candidate), pwallet.get(), &coin_control);
            if (tx_size.vsize <= 0) continue;
            const CAmount candidate_fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
            const CAmount candidate_change = output.txout.nValue - candidate_fee;
            CTxOut change_out(candidate_change, target);
            if (!MoneyRange(candidate_change) || candidate_change <= 0 || IsDust(change_out, pwallet->chain().relayDustFee())) continue;
            if (candidate_fee > pwallet->m_default_max_tx_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Fee exceeds wallet max transaction fee (%s)", FormatMoney(pwallet->m_default_max_tx_fee)));
            }

            candidate.vout[0].nValue = candidate_change;
            std::map<int, bilingual_str> input_errors;
            if (!pwallet->SignTransaction(candidate, input_errors)) {
                if (!input_errors.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Signing claim transaction failed: %s", input_errors.begin()->second.original));
                }
                throw JSONRPCError(RPC_WALLET_ERROR, "Signing claim transaction failed");
            }

            claim_tx = std::move(candidate);
            fee = candidate_fee;
            change = candidate_change;
            vsize = tx_size.vsize;
            break;
        }
    }

    if (claim_tx.vin.empty()) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable non-dust UTXO found for the target address");
    }

    CTransactionRef tx = MakeTransactionRef(std::move(claim_tx));
    const std::string hex = EncodeHexTx(*tx);
    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        const MempoolAcceptResult accept = chainman.ProcessTransaction(tx, /*test_accept=*/true);
        if (accept.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("Shadow PoW claim rejected: %s", accept.m_state.ToString()));
        }
    }

    mapValue_t map_value;
    map_value["comment"] = "Blackcoin shadow PoW claim";
    CommitWalletTransactionOrThrow(*pwallet, tx, std::move(map_value), "Blackcoin shadow PoW claim");

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("hex", hex);
    result.pushKV("proof", HexStr(proof));
    result.pushKV("external_proof", supplied_proof.has_value());
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("change", ValueFromAmount(change));
    result.pushKV("vsize", vsize);
    result.pushKV("address", address);
    result.pushKV("quantum_address", quantum_address);
    return result;
},
    };
}

static RPCHelpMan getgoldrushinfo()
{
    return RPCHelpMan{"getgoldrushinfo",
                "\nReturns Blackcoin Gold Rush shadow jackpot and wallet qualification status.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "active", "Whether the Gold Rush shadow reward phase is active by median-time-past."},
                        {RPCResult::Type::NUM, "height", "Current chain height."},
                        {RPCResult::Type::NUM_TIME, "mediantime", "Current tip median-time-past."},
                        {RPCResult::Type::STR_AMOUNT, "pos_jackpot", "Accrued PoS-side jackpot awaiting the next qualified solver/signaler payout."},
                        {RPCResult::Type::STR_AMOUNT, "pow_jackpot", "Estimated PoW-side payout awaiting the next valid memory-hard PoW claim."},
                        {RPCResult::Type::NUM, "pos_amount", "Accrued PoS-side jackpot in satoshis."},
                        {RPCResult::Type::NUM, "pow_amount", "Estimated PoW-side payout awaiting the next valid memory-hard PoW claim in satoshis."},
                        {RPCResult::Type::STR_AMOUNT, "pow_pool_jackpot", "PoW-side jackpot currently accrued in the pool before the next block reward is added."},
                        {RPCResult::Type::NUM, "pow_pool_amount", "PoW-side jackpot currently accrued in the pool before the next block reward is added, in satoshis."},
                        {RPCResult::Type::NUM, "claimed_amount", "Total Gold Rush amount already materialized to wallet-spendable quantum payout coins in satoshis."},
                        {RPCResult::Type::NUM, "recent_solver_participants", "Unique whitelisted solver scripts with a solve marker still inside the 14-day window."},
                        {RPCResult::Type::NUM, "active_signalers", "Whitelisted recent solvers that have an unexpired QQSIGNAL marker and can receive the next qualified PoS split."},
                        {RPCResult::Type::NUM, "recent_count", "Recent solver/claim accounting count from the consensus pool."},
                        {RPCResult::Type::STR_AMOUNT, "estimated_pos_payout_per_recent_solver", "Estimated PoS payout if every recent solver signals in the next qualified payout block."},
                        {RPCResult::Type::STR_AMOUNT, "next_pos_payout_pool", "PoS-side jackpot plus the next block's PoS-side Gold Rush reward, if the next height is inside the reward window."},
                        {RPCResult::Type::NUM, "next_pos_payout_amount", "PoS-side jackpot plus the next block's PoS-side Gold Rush reward in satoshis."},
                        {RPCResult::Type::STR_AMOUNT, "estimated_pos_payout_per_active_signaler", "Estimated next qualified PoS payout per active signaler."},
                        {RPCResult::Type::NUM, "pow_target_bits", "Current next-block Shadow PoW leading-zero target bits."},
                        {RPCResult::Type::NUM, "pos_claim_count", "Number of accepted PoS-side Shadow payouts recorded in pool state."},
                        {RPCResult::Type::NUM, "pow_claim_count", "Number of accepted PoW-side Shadow claims recorded in pool state."},
                        {RPCResult::Type::NUM, "pos_count", "Alias for pos_claim_count."},
                        {RPCResult::Type::NUM, "pow_count", "Alias for pow_claim_count."},
                        {RPCResult::Type::NUM, "last_pos_height", "Most recent accepted PoS-side Shadow payout height, or 0 if none."},
                        {RPCResult::Type::NUM, "last_pow_height", "Most recent accepted PoW-side Shadow claim height, or 0 if none."},
                        {RPCResult::Type::BOOL, "wallet_recent_solve_qualified", "Whether this wallet has at least one spendable whitelisted script with a recent solver marker."},
                        {RPCResult::Type::ARR, "wallet_scripts", "Spendable wallet scripts relevant to Gold Rush signaling.",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "scriptPubKey", "Wallet output script."},
                                {RPCResult::Type::STR, "address", "Address if the script has a standard destination."},
                                {RPCResult::Type::BOOL, "whitelisted", "Whether this script is in the deterministic snapshot whitelist."},
                                {RPCResult::Type::BOOL, "recent_solver", "Whether this script has solved a block within the current 14-day activity window."},
                                {RPCResult::Type::NUM, "last_solve_height", "Most recent qualifying solve height, or 0 if none."},
                                {RPCResult::Type::NUM_TIME, "last_solve_time", "Most recent qualifying solve time, or 0 if none."},
                                {RPCResult::Type::NUM, "blocks_until_expiry", "Blocks remaining before the recent-solver marker expires by height."},
                                {RPCResult::Type::NUM, "seconds_until_expiry", "Seconds remaining before the recent-solver marker expires by time."},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getgoldrushinfo", "")
            + HelpExampleRpc("getgoldrushinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    pwallet->BlockUntilSyncedToCurrentChain();

    std::set<CScript> wallet_scripts;
    {
        LOCK(pwallet->cs_wallet);
        CCoinControl coin_control;
        coin_control.m_avoid_address_reuse = false;
        for (const COutput& output : AvailableCoins(*pwallet, &coin_control).All()) {
            if (output.txout.nValue > 0 && !output.txout.scriptPubKey.empty() && !output.txout.scriptPubKey.IsUnspendable()) {
                wallet_scripts.insert(output.txout.scriptPubKey);
            }
        }
    }

    UniValue wallet_entries(UniValue::VARR);
    ShadowGoldRushInfo shadow_info;
    std::map<CScript, ShadowSolverActivity> recent_solvers;
    int tip_height{-1};
    int64_t tip_time{0};
    int64_t mtp{0};
    bool active{false};
    bool wallet_recent_solve_qualified{false};
    uint64_t active_signalers{0};
    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        Chainstate& active_chainstate = chainman.ActiveChainstate();
        const CBlockIndex* tip = active_chainstate.m_chain.Tip();
        if (!tip) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "No active chain tip");
        }

        const Consensus::Params& consensus = Params().GetConsensus();
        tip_height = tip->nHeight;
        tip_time = tip->GetBlockTime();
        mtp = tip->GetMedianTimePast();
        active = consensus.IsGoldRushEpoch(mtp);
        shadow_info = GetShadowGoldRushInfo(active_chainstate.CoinsTip(), tip);
        recent_solvers = GetRecentShadowSolverActivity(active_chainstate.CoinsTip(), tip);
        active_signalers = GetActiveShadowSignalCount(active_chainstate.CoinsTip(), tip);

        for (const CScript& script : wallet_scripts) {
            const bool whitelisted = IsWhitelisted(active_chainstate.CoinsTip(), script);
            const auto activity_it = recent_solvers.find(script);
            const bool recent_solver = activity_it != recent_solvers.end();
            if (whitelisted && recent_solver) wallet_recent_solve_qualified = true;

            CTxDestination dest;
            const bool has_dest = ExtractDestination(script, dest);
            const int last_solve_height = recent_solver ? static_cast<int>(activity_it->second.height) : 0;
            const int64_t last_solve_time = recent_solver ? activity_it->second.time : 0;
            const int blocks_until_expiry = recent_solver ? std::max(0, SHADOW_SOLVER_ACTIVITY_WINDOW - (tip_height - last_solve_height)) : 0;
            const int64_t seconds_until_expiry = recent_solver ? std::max<int64_t>(0, SHADOW_SOLVER_ACTIVITY_SECONDS - (tip_time - last_solve_time)) : 0;

            UniValue entry(UniValue::VOBJ);
            entry.pushKV("scriptPubKey", HexStr(script));
            entry.pushKV("address", has_dest ? EncodeDestination(dest) : "");
            entry.pushKV("whitelisted", whitelisted);
            entry.pushKV("recent_solver", recent_solver);
            entry.pushKV("last_solve_height", last_solve_height);
            entry.pushKV("last_solve_time", last_solve_time);
            entry.pushKV("blocks_until_expiry", blocks_until_expiry);
            entry.pushKV("seconds_until_expiry", seconds_until_expiry);
            wallet_entries.push_back(std::move(entry));
        }
    }

    const int next_height = tip_height + 1;
    const bool next_reward_height_active = active &&
                                           next_height >= SHADOW_REWARD_START_HEIGHT &&
                                           next_height <= SHADOW_REWARD_END_HEIGHT;
    const CAmount next_reward = next_reward_height_active ? ShadowBaseReward(next_height) : 0;
    const CAmount next_pow_reward = next_reward / 2;
    const CAmount next_pos_reward = next_reward - next_pow_reward;
    const CAmount next_pow_payout = next_reward_height_active ? shadow_info.pow_amount + next_pow_reward : shadow_info.pow_amount;
    const CAmount next_pos_payout_pool = next_reward_height_active ? shadow_info.pos_amount + next_pos_reward : shadow_info.pos_amount;
    const size_t participants = recent_solvers.size();
    const CAmount estimated_pos_payout = participants > 0 ? shadow_info.pos_amount / static_cast<CAmount>(participants) : 0;
    const CAmount estimated_active_pos_payout = active_signalers > 0 ? next_pos_payout_pool / static_cast<CAmount>(active_signalers) : 0;

    UniValue result(UniValue::VOBJ);
    result.pushKV("active", active);
    result.pushKV("height", tip_height);
    result.pushKV("mediantime", mtp);
    result.pushKV("pos_jackpot", ValueFromAmount(shadow_info.pos_amount));
    result.pushKV("pow_jackpot", ValueFromAmount(next_pow_payout));
    result.pushKV("pos_amount", shadow_info.pos_amount);
    result.pushKV("pow_amount", next_pow_payout);
    result.pushKV("pow_pool_jackpot", ValueFromAmount(shadow_info.pow_amount));
    result.pushKV("pow_pool_amount", shadow_info.pow_amount);
    result.pushKV("claimed_amount", shadow_info.claimed_amount);
    result.pushKV("recent_solver_participants", static_cast<uint64_t>(participants));
    result.pushKV("active_signalers", active_signalers);
    result.pushKV("recent_count", shadow_info.recent_count);
    result.pushKV("estimated_pos_payout_per_recent_solver", ValueFromAmount(estimated_pos_payout));
    result.pushKV("next_pos_payout_pool", ValueFromAmount(next_pos_payout_pool));
    result.pushKV("next_pos_payout_amount", next_pos_payout_pool);
    result.pushKV("estimated_pos_payout_per_active_signaler", ValueFromAmount(estimated_active_pos_payout));
    result.pushKV("pow_target_bits", shadow_info.pow_target_bits);
    result.pushKV("pos_claim_count", shadow_info.pos_count);
    result.pushKV("pow_claim_count", shadow_info.pow_count);
    result.pushKV("pos_count", shadow_info.pos_count);
    result.pushKV("pow_count", shadow_info.pow_count);
    result.pushKV("last_pos_height", shadow_info.last_pos_height);
    result.pushKV("last_pow_height", shadow_info.last_pow_height);
    result.pushKV("wallet_recent_solve_qualified", wallet_recent_solve_qualified);
    result.pushKV("wallet_scripts", std::move(wallet_entries));
    return result;
},
    };
}

static RPCHelpMan checkkernel()
{
    return RPCHelpMan{"checkkernel",
                "\nCheck if one of given inputs is a kernel input at the moment.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'locktime' argument"}, "The sequence number"},
                                },
                            },
                        },
                    },
                    {"createblocktemplate", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create block template?"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "found", "?"},
                        {RPCResult::Type::OBJ, "kernel", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The transaction hash in hex"},
                                {RPCResult::Type::NUM, "vout", "?"},
                                {RPCResult::Type::NUM, "time", "?"},
                            }},
                        {RPCResult::Type::STR_HEX, "blocktemplate", /*optional=*/true, "?"},
                        {RPCResult::Type::NUM, "blocktemplatefees", /*optional=*/true, "?"},
                        {RPCResult::Type::STR_HEX, "blocktemplatesignkey", /*optional=*/true, "?"},
                    },
                },
                RPCExamples{
                HelpExampleCli("checkkernel", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"false\"")
                + HelpExampleCli("checkkernel", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"true\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const CTxMemPool& mempool = pwallet->chain().mempool();
    ChainstateManager& chainman = pwallet->chain().chainman();
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    UniValue inputs = request.params[0].get_array();
    bool fCreateBlockTemplate = request.params.size() > 1 ? request.params[1].get_bool() : false;

    if (!Params().IsTestChain()) {
        if (pwallet->chain().getNodeCount(ConnectionDirection::Both) == 0) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");
        }

        if (chainman.IsInitialBlockDownload()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is in initial sync and waiting for blocks...");
        }
    }

    COutPoint kernel;
    CBlockIndex* pindexPrev = active_chain.Tip();
    unsigned int nBits = GetNextTargetRequired(pindexPrev, Params().GetConsensus(), true);
    int64_t nTime = GetAdjustedTimeSeconds();
    nTime &= ~Params().GetConsensus().nStakeTimestampMask;

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& o = inputs[idx].get_obj();

        const UniValue& txid_v = o.find_value("txid");
        if (!txid_v.isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");
        string txid = txid_v.get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        const UniValue& vout_v = o.find_value("vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.getInt<int>();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint cInput(uint256S(txid), nOutput);
        if (CheckKernel(pindexPrev, nBits, nTime, cInput, active_chainstate.CoinsTip()))
        {
            kernel = cInput;
            break;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("found", !kernel.IsNull());

    if (kernel.IsNull())
        return result;

    UniValue oKernel(UniValue::VOBJ);
    oKernel.pushKV("txid", kernel.hash.GetHex());
    oKernel.pushKV("vout", (int64_t)kernel.n);
    oKernel.pushKV("time", nTime);
    result.pushKV("kernel", oKernel);

    if (!fCreateBlockTemplate)
        return result;

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    bool fPoSCancel = false;
    int64_t nFees;
    std::unique_ptr<node::CBlockTemplate> pblocktemplate(BlockAssembler{active_chainstate, &mempool}.CreateNewBlock(CScript(), nullptr, &fPoSCancel, &nFees));
    if (!pblocktemplate.get())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");

    CBlock *pblock = &pblocktemplate->block;
    CMutableTransaction coinstakeTx(*pblock->vtx[0]);
    pblock->nTime = coinstakeTx.nTime = nTime;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinstakeTx));

    CDataStream ss(SER_DISK);
    ss << RPCTxSerParams(*pblock);

    result.pushKV("blocktemplate", HexStr(ss));
    result.pushKV("blocktemplatefees", nFees);

    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    // Prepare reserve destination
    OutputType output_type = pwallet->m_default_change_type ? *pwallet->m_default_change_type : pwallet->m_default_address_type;
    auto op_dest = pwallet->GetNewChangeDestination(output_type);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Keypool ran out, please call keypoolrefill first");
    }
    std::vector<valtype> vSolutionsTmp;
    CScript scriptPubKeyTmp = GetScriptForDestination(*op_dest);
    Solver(scriptPubKeyTmp, vSolutionsTmp);
    std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKeyTmp);
    if (!provider) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: failed to get signing provider");
    }
    CKeyID ckey = CKeyID(uint160(vSolutionsTmp[0]));
    CPubKey pkey;
    if (!provider.get()->GetPubKey(ckey, pkey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: failed to get key");
    }
    result.pushKV("blocktemplatesignkey", HexStr(pkey));

    return result;
},
    };
}

static RPCHelpMan setpowmining()
{
    return RPCHelpMan{"setpowmining",
        "\nStart, stop, or reconfigure the built-in (in-process) Gold Rush Proof-of-Work miner.\n"
        "No external miner is required. Mining only produces claims during the Gold Rush reward window,\n"
        "requires an unlocked wallet with private keys, and credits valid claims to an auto-created quantum address in the upgraded shadow ledger.\n"
        "Claim submission is not whitelist-gated, but it does require a spendable non-dust legacy UTXO to authenticate the QQSPROOF transaction and pay the minimal network fee.\n",
        {
            {"enabled", RPCArg::Type::BOOL, RPCArg::Optional::NO, "true to start mining, false to stop."},
            {"threads", RPCArg::Type::NUM, RPCArg::Default{1}, "Worker threads (CPU cores) to use, 1..256."},
            {"cpu_percent", RPCArg::Type::NUM, RPCArg::Default{1}, "Per-core CPU duty-cycle target, 1..100."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether in-process PoW mining is now enabled."},
            {RPCResult::Type::NUM, "threads", "Configured worker threads."},
            {RPCResult::Type::NUM, "cpu_percent", "Configured per-core CPU duty cycle."},
            {RPCResult::Type::STR, "payout_address", "The quantum payout address (created if needed)."},
        }},
        RPCExamples{
            HelpExampleCli("setpowmining", "true 2 50")
          + HelpExampleRpc("setpowmining", "true, 2, 50")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const bool enabled = request.params[0].get_bool();
    const int threads = request.params[1].isNull() ? 1 : request.params[1].getInt<int>();
    const int cpu_percent = request.params[2].isNull() ? 1 : request.params[2].getInt<int>();

    bilingual_str error;
    const bool ok = pwallet->SetPowMining(enabled, threads, cpu_percent, error);
    if (!ok) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("enabled", pwallet->m_pow_mining_enabled.load());
    result.pushKV("threads", pwallet->m_pow_threads.load());
    result.pushKV("cpu_percent", pwallet->m_pow_cpu_percent.load());
    {
        LOCK(pwallet->cs_wallet);
        result.pushKV("payout_address", pwallet->m_pow_payout_quantum);
    }
    return result;
},
    };
}

static RPCHelpMan getpowmininginfo()
{
    return RPCHelpMan{"getpowmininginfo",
        "\nReturns the status of the built-in Gold Rush Proof-of-Work miner.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether in-process PoW mining is enabled."},
            {RPCResult::Type::NUM, "threads", "Worker threads configured."},
            {RPCResult::Type::NUM, "cpu_percent", "Per-core CPU duty-cycle target."},
            {RPCResult::Type::NUM, "hashrate", "Aggregate Argon2id tries per second."},
            {RPCResult::Type::BOOL, "epoch_active", "Whether the Gold Rush reward window is currently open."},
            {RPCResult::Type::NUM, "blocks_remaining", "Blocks left in the Gold Rush reward window."},
            {RPCResult::Type::STR, "payout_address", "Quantum payout address (empty until created)."},
            {RPCResult::Type::STR_AMOUNT, "accrued_jackpot", "PoW jackpot accrued in the pool."},
            {RPCResult::Type::STR_AMOUNT, "next_claim_payout", "Estimated payout for a valid PoW claim in the next block."},
            {RPCResult::Type::NUM, "next_claim_amount", "Estimated payout for a valid PoW claim in the next block, in satoshis."},
            {RPCResult::Type::NUM, "claims_submitted", "Claims submitted by this miner since it started."},
        }},
        RPCExamples{
            HelpExampleCli("getpowmininginfo", "")
          + HelpExampleRpc("getpowmininginfo", "")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("enabled", pwallet->m_pow_mining_enabled.load());
    obj.pushKV("threads", pwallet->m_pow_threads.load());
    obj.pushKV("cpu_percent", pwallet->m_pow_cpu_percent.load());
    obj.pushKV("hashrate", pwallet->m_pow_hashrate.load());
    obj.pushKV("claims_submitted", (int64_t)pwallet->m_pow_claims_submitted.load());
    {
        LOCK(pwallet->cs_wallet);
        obj.pushKV("payout_address", pwallet->m_pow_payout_quantum);
    }

    bool epoch_active = false;
    int blocks_remaining = 0;
    CAmount accrued = 0;
    CAmount next_claim = 0;
    {
        ChainstateManager& chainman = pwallet->chain().chainman();
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        if (tip) {
            const Consensus::Params& consensus = Params().GetConsensus();
            const int next_height = tip->nHeight + 1;
            epoch_active = consensus.IsGoldRushEpoch(tip->GetMedianTimePast()) &&
                           next_height >= SHADOW_REWARD_START_HEIGHT &&
                           next_height <= SHADOW_REWARD_END_HEIGHT;
            blocks_remaining = epoch_active ? std::max(0, SHADOW_REWARD_END_HEIGHT - next_height + 1) : 0;
            accrued = GetShadowGoldRushInfo(chainman.ActiveChainstate().CoinsTip(), tip).pow_amount;
            next_claim = epoch_active ? accrued + ShadowBaseReward(next_height) / 2 : accrued;
        }
    }
    obj.pushKV("epoch_active", epoch_active);
    obj.pushKV("blocks_remaining", blocks_remaining);
    obj.pushKV("accrued_jackpot", ValueFromAmount(accrued));
    obj.pushKV("next_claim_payout", ValueFromAmount(next_claim));
    obj.pushKV("next_claim_amount", next_claim);
    return obj;
},
    };
}

static RPCHelpMan getquantumredelegationinfo()
{
    return RPCHelpMan{"getquantumredelegationinfo",
        "\nDry-run Quantum Cold-Stake redelegation policy against the local pool registry.\n"
        "This wallet-policy RPC does not create, sign, or broadcast a transaction. It evaluates\n"
        "the zero-win trigger/rate-limit/probation policy and returns verified target candidates.\n"
        "Over-cap candidates are filtered out when any under-cap alternative exists; if no under-cap\n"
        "candidate exists, all otherwise-valid candidates are returned for bootstrap.\n",
        {
            {"current_staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current operator/staker ML-DSA-44 public key."},
            {"delegation_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Delegation value to redelegate."},
            {"zero_win_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "Consecutive blocks without a realized win for this delegation."},
            {"expected_interval_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "Wallet-estimated expected blocks between wins for this delegation."},
            {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Optional policy state.", {
                {"last_redelegation_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height of the last redelegation for this delegation."},
                {"last_successful_redelegation_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height of the last successful redelegation for this delegation."},
                {"target_activation_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height when the current target became active."},
                {"delegation_id", RPCArg::Type::STR_HEX, RPCArg::Default{uint256::ONE.GetHex()}, "Stable 32-byte id used for deterministic jitter."},
                {"trigger_multiplier", RPCArg::Type::NUM, RPCArg::Default{6}, "Policy override for test/dry-run trigger multiplier."},
                {"max_patience_blocks", RPCArg::Type::NUM, RPCArg::Default{4050}, "Policy override for max zero-win patience."},
                {"min_trigger_blocks", RPCArg::Type::NUM, RPCArg::Default{300}, "Policy override for absolute minimum zero-win trigger."},
                {"rate_limit_blocks", RPCArg::Type::NUM, RPCArg::Default{1350}, "Policy override for redelegation rate limit."},
                {"probation_blocks", RPCArg::Type::NUM, RPCArg::Default{1350}, "Policy override for new-target probation."},
                {"stampede_jitter_blocks", RPCArg::Type::NUM, RPCArg::Default{1350}, "Policy override for deterministic stampede jitter."},
                {"liveness_improvement_blocks", RPCArg::Type::NUM, RPCArg::Default{300}, "Policy override for minimum target win-history improvement."},
                {"top_liveness_candidates", RPCArg::Type::NUM, RPCArg::Default{4}, "Policy override for deterministic spread set size among live candidates."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "should_redelegate", "Whether policy recommends redelegation now."},
            {RPCResult::Type::NUM, "current_height", "Active chain height used for the decision."},
            {RPCResult::Type::NUM, "trigger_blocks", "Zero-win blocks required before redelegation is eligible."},
            {RPCResult::Type::NUM, "eligible_height", "Earliest height after rate-limit, probation, and jitter."},
            {RPCResult::Type::BOOL, "rate_limited", "Whether the delegation is rate-limited."},
            {RPCResult::Type::BOOL, "success_rate_limited", "Whether the delegation is rate-limited by the last successful redelegation."},
            {RPCResult::Type::BOOL, "probation", "Whether the current target is still in probation."},
            {RPCResult::Type::NUM, "jitter_blocks", "Deterministic client-side stampede jitter."},
            {RPCResult::Type::ARR, "candidates", "Ranked verified target operators after per-pool cap bootstrap filtering.", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                    {RPCResult::Type::STR_HEX, "staking_pubkey", "Operator/staker ML-DSA public key for new QCS address creation."},
                    {RPCResult::Type::STR_AMOUNT, "verified_value", "Verified operator delegated value."},
                    {RPCResult::Type::NUM, "last_win_height", "Most recent observed win height for this operator known to this wallet, if any."},
                    {RPCResult::Type::NUM, "share_bps", "Current verified cold-stake share in basis points."},
                    {RPCResult::Type::BOOL, "would_exceed_cap", "Whether this candidate would exceed the per-pool cap for the proposed amount."},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getquantumredelegationinfo", "\"<current_staking_pubkey>\" 100 600 100")
          + HelpExampleRpc("getquantumredelegationinfo", "\"<current_staking_pubkey>\", 100, 600, 100")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const std::vector<unsigned char> current_pubkey = ParseHexV(request.params[0], "current_staking_pubkey");
    if (current_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("current_staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }
    const uint256 current_hash = node::QuantumPoolHashPubKey(current_pubkey);
    const CAmount delegation_amount = AmountFromValue(request.params[1]);
    if (delegation_amount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegation_amount must be positive");
    }
    const int64_t zero_win_blocks = request.params[2].getInt<int64_t>();
    const int64_t expected_interval_blocks = request.params[3].getInt<int64_t>();
    if (zero_win_blocks < 0 || expected_interval_blocks < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "zero_win_blocks and expected_interval_blocks cannot be negative");
    }

    const UniValue options = request.params[4].isNull() ? UniValue(UniValue::VOBJ) : request.params[4].get_obj();
    const int64_t last_redelegation_height = options.exists("last_redelegation_height") ? options["last_redelegation_height"].getInt<int64_t>() : 0;
    const int64_t last_successful_redelegation_height = options.exists("last_successful_redelegation_height") ? options["last_successful_redelegation_height"].getInt<int64_t>() : 0;
    const int64_t target_activation_height = options.exists("target_activation_height") ? options["target_activation_height"].getInt<int64_t>() : 0;
    const uint256 delegation_id = options.exists("delegation_id") ? ParseHashV(options["delegation_id"], "delegation_id") : current_hash;
    QuantumRedelegationPolicy policy;
    if (options.exists("trigger_multiplier")) policy.trigger_multiplier = options["trigger_multiplier"].getInt<int64_t>();
    if (options.exists("max_patience_blocks")) policy.max_patience_blocks = options["max_patience_blocks"].getInt<int64_t>();
    if (options.exists("min_trigger_blocks")) policy.min_trigger_blocks = options["min_trigger_blocks"].getInt<int64_t>();
    if (options.exists("rate_limit_blocks")) policy.rate_limit_blocks = options["rate_limit_blocks"].getInt<int64_t>();
    if (options.exists("probation_blocks")) policy.probation_blocks = options["probation_blocks"].getInt<int64_t>();
    if (options.exists("stampede_jitter_blocks")) policy.stampede_jitter_blocks = options["stampede_jitter_blocks"].getInt<int64_t>();
    if (options.exists("liveness_improvement_blocks")) policy.liveness_improvement_blocks = options["liveness_improvement_blocks"].getInt<int64_t>();
    if (options.exists("top_liveness_candidates")) policy.top_liveness_candidates = options["top_liveness_candidates"].getInt<int64_t>();
    if (policy.trigger_multiplier <= 0 || policy.max_patience_blocks <= 0 || policy.min_trigger_blocks <= 0 ||
        policy.rate_limit_blocks < 0 || policy.probation_blocks < 0 || policy.stampede_jitter_blocks < 0 ||
        policy.liveness_improvement_blocks <= 0 || policy.top_liveness_candidates <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "redelegation policy values are out of range");
    }

    ChainstateManager& chainman = pwallet->chain().chainman();
    int current_height{0};
    std::vector<QuantumRedelegationCandidate> candidates;
    std::map<uint256, int> operator_last_win_height;
    {
        LOCK(pwallet->cs_wallet);
        for (const QuantumColdStakeDelegationInfo& info : pwallet->ListQuantumColdStakeDelegationInfos()) {
            const auto win = pwallet->m_redelegation_last_win_height.find(info.witness_program);
            if (win == pwallet->m_redelegation_last_win_height.end()) continue;
            auto& height = operator_last_win_height[info.staker_pubkey_hash];
            height = std::max(height, win->second);
        }
    }
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        current_height = tip ? tip->nHeight : 0;
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        for (const uint256& staker_hash : node::ListQuantumPoolOperators()) {
            const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));
            QuantumRedelegationCandidate candidate;
            candidate.staker_pubkey_hash = staker_hash;
            candidate.staker_pubkey = share.operator_share.staker_pubkey;
            candidate.operator_value = share.operator_share.verified_value;
            candidate.total_coldstake = share.total_coldstake;
            const auto win = operator_last_win_height.find(staker_hash);
            candidate.last_win_height = win == operator_last_win_height.end() ? 0 : win->second;
            candidate.operator_commitment_verified = share.operator_share.operator_commitment_verified;
            candidate.current_operator = staker_hash == current_hash;
            candidates.push_back(std::move(candidate));
        }
    }

    const QuantumRedelegationStatus status = EvaluateQuantumRedelegation(
        zero_win_blocks,
        expected_interval_blocks,
        current_height,
        last_redelegation_height,
        last_successful_redelegation_height,
        target_activation_height,
        delegation_id,
        current_hash,
        policy);
    const auto ranked = RankQuantumRedelegationCandidates(candidates, delegation_amount, policy);

    UniValue candidate_values(UniValue::VARR);
    for (const QuantumRedelegationCandidateScore& score : ranked) {
        UniValue candidate(UniValue::VOBJ);
        candidate.pushKV("staking_pubkey_hash", score.candidate.staker_pubkey_hash.GetHex());
        candidate.pushKV("staking_pubkey", HexStr(score.candidate.staker_pubkey));
        candidate.pushKV("verified_value", ValueFromAmount(score.candidate.operator_value));
        candidate.pushKV("last_win_height", score.last_win_height);
        candidate.pushKV("share_bps", score.share_bps);
        candidate.pushKV("would_exceed_cap", score.would_exceed_cap);
        candidate_values.push_back(std::move(candidate));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("should_redelegate", status.should_redelegate);
    obj.pushKV("current_height", current_height);
    obj.pushKV("trigger_blocks", status.trigger_blocks);
    obj.pushKV("eligible_height", status.eligible_height);
    obj.pushKV("rate_limited", status.rate_limited);
    obj.pushKV("success_rate_limited", status.success_rate_limited);
    obj.pushKV("probation", status.probation);
    obj.pushKV("jitter_blocks", status.jitter_blocks);
    obj.pushKV("candidates", candidate_values);
    return obj;
},
    };
}

static RPCHelpMan redelegatequantumcoldstake()
{
    return RPCHelpMan{"redelegatequantumcoldstake",
        "\nCreate or broadcast an owner-branch Quantum Cold-Stake redelegation transaction.\n"
        "The wallet spends all selected UTXOs from a wallet-owned source QCS address into a new\n"
        "wallet-backed QCS address for the target staking public key. Consensus is unchanged; this is\n"
        "ordinary owner spending with per-pool cap and redelegation wallet policy checks.\n",
        {
            {"source_coldstake_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-owned source Quantum Cold-Stake address."},
            {"target_staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Target operator/staker ML-DSA-44 public key."},
            {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Redelegation options.", {
                {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{true}, "Build and return the transaction plan without broadcasting. This still creates the new wallet-backed target QCS address so returned transaction hex remains spendable if used later."},
                {"enforce_pool_cap", RPCArg::Type::BOOL, RPCArg::Default{true}, "Refuse over-cap redelegation only when an under-cap alternative exists; otherwise allow bootstrap and report the over-cap projection."},
                {"require_verified_operator", RPCArg::Type::BOOL, RPCArg::Default{true}, "Refuse if the target operator has no locally verified 30-day Operator-tier commitment."},
                {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Optional fee rate in " + CURRENCY_ATOM + "/vB."},
                {"label", RPCArg::Type::STR, RPCArg::Default{"redelegated-coldstake"}, "Label for the new QCS address."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "dry_run", "Whether the transaction was only planned."},
            {RPCResult::Type::STR, "source_address", "Source QCS address."},
            {RPCResult::Type::STR, "target_address", "New wallet-backed target QCS address."},
            {RPCResult::Type::BOOL, "target_wallet_backed", "Whether this wallet stores the target owner key and QCS metadata."},
            {RPCResult::Type::STR_AMOUNT, "input_amount", "Selected source value."},
            {RPCResult::Type::STR_AMOUNT, "output_amount", "Redelegated output value after fees."},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee."},
            {RPCResult::Type::NUM, "vsize", "Virtual transaction size."},
            {RPCResult::Type::OBJ, "pool_policy", "Per-pool cap and redelegation local pool policy result.", {
                {RPCResult::Type::BOOL, "operator_commitment_verified", "Whether the target has a verified Operator-tier commitment in the local registry."},
                {RPCResult::Type::STR_AMOUNT, "post_total_coldstake", "Projected total cold-stake UTXO value after the redelegation."},
                {RPCResult::Type::STR_AMOUNT, "post_operator_value", "Projected verified target operator value after the redelegation."},
                {RPCResult::Type::NUM, "post_share_bps", "Projected target operator share in basis points."},
                {RPCResult::Type::BOOL, "would_exceed_cap", "Whether the projected redelegation exceeds the local per-pool cap."},
                {RPCResult::Type::BOOL, "cap_enforced", "Whether over-cap projections are refused."},
                {RPCResult::Type::BOOL, "cap_filter_unlocked", "Whether the over-cap target was allowed because no under-cap alternative exists."},
            }},
            {RPCResult::Type::STR_HEX, "hex", "Transaction hex."},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast transaction id."},
        }},
        RPCExamples{
            HelpExampleCli("redelegatequantumcoldstake", "\"<source_qcs_address>\" \"<target_staking_pubkey>\" '{\"dry_run\":true}'")
          + HelpExampleRpc("redelegatequantumcoldstake", "\"<source_qcs_address>\", \"<target_staking_pubkey>\", {\"dry_run\":true}")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const std::string source_address = request.params[0].get_str();
    const CTxDestination source_dest = DecodeDestination(source_address);
    if (!IsValidDestination(source_dest) || !IsQuantumColdStakeDestination(source_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "source_coldstake_address is not a Quantum Cold-Stake address");
    }

    const std::vector<unsigned char> target_staking_pubkey = ParseHexV(request.params[1], "target_staking_pubkey");
    if (target_staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("target_staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }

    const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
    QuantumColdStakeRedelegationOptions redelegation_options;
    redelegation_options.dry_run = !options.exists("dry_run") || options["dry_run"].get_bool();
    redelegation_options.enforce_pool_cap = !options.exists("enforce_pool_cap") || options["enforce_pool_cap"].get_bool();
    redelegation_options.require_verified_operator = !options.exists("require_verified_operator") || options["require_verified_operator"].get_bool();
    redelegation_options.label = options.exists("label") ? LabelFromValue(options["label"]) : "redelegated-coldstake";
    if (options.exists("fee_rate")) {
        redelegation_options.fee_rate = FeeRateFromSatVbValue(options["fee_rate"]);
    }

    QuantumColdStakeRedelegationResult redelegation;
    bilingual_str error;
    if (!CreateQuantumColdStakeRedelegationTransaction(*pwallet, source_dest, target_staking_pubkey, redelegation_options, redelegation, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    UniValue pool_policy(UniValue::VOBJ);
    pool_policy.pushKV("operator_commitment_verified", redelegation.operator_commitment_verified);
    pool_policy.pushKV("post_total_coldstake", ValueFromAmount(redelegation.post_total_coldstake));
    pool_policy.pushKV("post_operator_value", ValueFromAmount(redelegation.post_operator_value));
    pool_policy.pushKV("post_share_bps", redelegation.post_share_bps);
    pool_policy.pushKV("would_exceed_cap", redelegation.would_exceed_cap);
    pool_policy.pushKV("cap_enforced", redelegation.cap_enforced);
    pool_policy.pushKV("cap_filter_unlocked", redelegation.cap_filter_unlocked);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("dry_run", redelegation.dry_run);
    obj.pushKV("source_address", source_address);
    obj.pushKV("target_address", EncodeDestination(redelegation.target_dest));
    obj.pushKV("target_wallet_backed", redelegation.target_wallet_backed);
    obj.pushKV("input_amount", ValueFromAmount(redelegation.input_amount));
    obj.pushKV("output_amount", ValueFromAmount(redelegation.output_amount));
    obj.pushKV("fee", ValueFromAmount(redelegation.fee));
    obj.pushKV("vsize", redelegation.vsize);
    obj.pushKV("pool_policy", pool_policy);
    obj.pushKV("hex", EncodeHexTx(*redelegation.tx));
    if (!redelegation.dry_run) {
        obj.pushKV("txid", redelegation.tx->GetHash().GetHex());
    }
    return obj;
},
    };
}

static RPCHelpMan senddemurrageattestation()
{
    return RPCHelpMan{"senddemurrageattestation",
        "\nCreate a fee-paying demurrage liveness attestation for a wallet-backed Blackcoin ML-DSA address.\n"
        "The attestation output carries no value; it refreshes the key's inactivity clock once mined after -qqdemurrageheight is active.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-backed Blackcoin migration address to attest."},
            {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Attestation options.",
            {
                {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Build and return the transaction without committing it to the wallet."},
                {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in sat/vB."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "dry_run", "Whether the transaction was only planned."},
            {RPCResult::Type::STR, "address", "Attested Blackcoin migration address."},
            {RPCResult::Type::STR_HEX, "witness_program", "Attested witness program / public-key hash."},
            {RPCResult::Type::STR_HEX, "public_key", "Attested ML-DSA public key."},
            {RPCResult::Type::STR_HEX, "replay_anchor", "First input outpoint bound into the ML-DSA attestation signature."},
            {RPCResult::Type::NUM, "attestation_vout", "Output index carrying the zero-value demurrage attestation."},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee."},
            {RPCResult::Type::NUM, "vsize", "Virtual transaction size."},
            {RPCResult::Type::STR_HEX, "hex", "Transaction hex."},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast transaction id."},
        }},
        RPCExamples{
            HelpExampleCli("senddemurrageattestation", "\"<quantum_address>\"")
          + HelpExampleRpc("senddemurrageattestation", "\"<quantum_address>\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    std::string error_msg;
    const CTxDestination dest = DecodeDestination(request.params[0].get_str(), error_msg);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg.empty() ? "Invalid address" : error_msg);
    }
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not a Blackcoin migration address");
    }

    const UniValue options = request.params[1].isNull() ? UniValue(UniValue::VOBJ) : request.params[1].get_obj();
    const bool dry_run = options.exists("dry_run") && options["dry_run"].get_bool();

    CCoinControl coin_control;
    if (options.exists("fee_rate")) {
        coin_control.m_feerate = FeeRateFromSatVbValue(options["fee_rate"]);
        coin_control.fOverrideFeeRate = true;
    }

    pwallet->BlockUntilSyncedToCurrentChain();

    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);
        if (pwallet->m_wallet_unlock_staking_only) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet unlocked for staking only, unable to create demurrage attestation");
        }
    }

    DemurrageAttestationTxResult tx_result;
    bilingual_str error;
    if (!CreateDemurrageAttestationTransaction(*pwallet, witness->GetWitnessProgram(), coin_control, /*sign=*/!dry_run, tx_result, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
    const CTransactionRef& tx = tx_result.tx;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("dry_run", dry_run);
    obj.pushKV("address", EncodeDestination(dest));
    obj.pushKV("witness_program", HexStr(witness->GetWitnessProgram()));
    obj.pushKV("public_key", HexStr(tx_result.public_key));
    obj.pushKV("replay_anchor", tx_result.replay_anchor.ToString());
    obj.pushKV("attestation_vout", tx_result.attestation_vout);
    obj.pushKV("fee", ValueFromAmount(tx_result.fee));
    obj.pushKV("vsize", (int)GetVirtualTransactionSize(*tx, 0, 0));
    obj.pushKV("hex", EncodeHexTx(*tx));
    if (!dry_run) {
        mapValue_t map_value;
        map_value["comment"] = "Blackcoin demurrage attestation";
        CommitWalletTransactionOrThrow(*pwallet, tx, std::move(map_value), "Blackcoin demurrage attestation");
        obj.pushKV("txid", tx->GetHash().GetHex());
    }
    return obj;
},
    };
}

static RPCHelpMan getdemurragewalletinfo()
{
    return RPCHelpMan{"getdemurragewalletinfo",
        "\nReport demurrage exposure for wallet-owned Blackcoin ML-DSA outputs.\n"
        "Amounts are evaluated for the next block so the result matches wallet funding behavior once -qqdemurrageheight is active.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "demurrage_active", "Whether demurrage is active for the evaluation height"},
            {RPCResult::Type::NUM, "tip_height", "Current active-chain tip height"},
            {RPCResult::Type::NUM, "evaluation_height", "Height used for spend/effective-value evaluation"},
            {RPCResult::Type::NUM_TIME, "evaluation_time", "Parent MedianTimePast used for next-block spend/effective-value evaluation"},
            {RPCResult::Type::NUM, "demurrage_activation_height", "Configured demurrage activation height"},
            {RPCResult::Type::NUM, "demurrage_effective_activation_height", "Demurrage activation height after the post-Gold-Rush clamp"},
            {RPCResult::Type::NUM_TIME, "quantum_migration_deadline_time", "Final quantum migration deadline time used by the demurrage post-migration guard"},
            {RPCResult::Type::BOOL, "demurrage_height_guard_satisfied", "Whether evaluation_height is at or above demurrage_effective_activation_height"},
            {RPCResult::Type::BOOL, "demurrage_post_migration_guard_satisfied", "Whether evaluation_time is after quantum_migration_deadline_time"},
            {RPCResult::Type::BOOL, "wallet_staking_enabled", "Whether this wallet has staking enabled"},
            {RPCResult::Type::NUM, "quantum_outputs", "Wallet-owned direct quantum outputs considered"},
            {RPCResult::Type::NUM, "decaying_outputs", "Outputs whose effective value is below nominal value"},
            {RPCResult::Type::NUM, "locked_outputs", "Outputs at the 24-month demurrage lock point"},
            {RPCResult::Type::NUM, "attestation_due_outputs", "Outputs at or beyond the 3-month auto-attestation policy threshold"},
            {RPCResult::Type::STR_AMOUNT, "nominal_amount", "Nominal value of considered wallet-owned direct quantum outputs"},
            {RPCResult::Type::STR_AMOUNT, "effective_amount", "Demurrage-adjusted spendable value at evaluation_height"},
            {RPCResult::Type::STR_AMOUNT, "burned_if_spent_amount", "Amount that would be burned if all considered outputs were spent at evaluation_height"},
            {RPCResult::Type::ARR, "outputs", "Per-output demurrage state",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                    {RPCResult::Type::NUM, "vout", "Output index"},
                    {RPCResult::Type::STR, "address", "Wallet-backed Blackcoin migration address"},
                    {RPCResult::Type::NUM, "depth", "Wallet confirmation depth"},
                    {RPCResult::Type::NUM, "coin_height", "Consensus coin height used for evaluation"},
                    {RPCResult::Type::BOOL, "chainstate_backed", "Whether the output was found in chainstate/mempool lookup"},
                    {RPCResult::Type::NUM, "latest_attestation_height", /*optional=*/true, "Latest mined liveness attestation height for this key"},
                    {RPCResult::Type::NUM, "inactive_blocks", "Blocks since the effective last-active height"},
                    {RPCResult::Type::NUM, "remaining_ppm", "Remaining value in parts per million"},
                    {RPCResult::Type::STR_AMOUNT, "nominal_amount", "Nominal output value"},
                    {RPCResult::Type::STR_AMOUNT, "effective_amount", "Demurrage-adjusted output value"},
                    {RPCResult::Type::STR_AMOUNT, "burned_if_spent_amount", "Amount burned if this output is spent now"},
                    {RPCResult::Type::BOOL, "locked", "Whether this output has reached the 24-month lock"},
                    {RPCResult::Type::STR, "exemption", "Reason the output is currently whole, or empty when decaying"},
                    {RPCResult::Type::NUM, "blocks_until_decay", "Blocks until decay starts; zero if already decaying"},
                    {RPCResult::Type::NUM, "blocks_until_lock", "Blocks until hard lock; zero if already locked"},
                    {RPCResult::Type::BOOL, "attestation_due", "Whether this output is beyond the 3-month auto-attestation policy threshold"},
                    {RPCResult::Type::STR, "action", "Suggested wallet action"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getdemurragewalletinfo", "")
          + HelpExampleRpc("getdemurragewalletinfo", "")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const Consensus::Params& consensus = Params().GetConsensus();
    const CBlockIndex* tip = pwallet->chain().getTip();
    const int tip_height = tip ? tip->nHeight : -1;
    const int evaluation_height = tip_height >= 0 ? tip_height + 1 : 0;
    const int64_t evaluation_time = tip ? tip->GetMedianTimePast() : 0;
    const bool demurrage_active = consensus.IsDemurrageActive(evaluation_height, evaluation_time);
    const bool wallet_staking_enabled = pwallet->m_enabled_staking.load();

    CoinsResult available = AvailableCoinsListUnspent(*pwallet);
    std::map<COutPoint, Coin> chain_coins;
    std::vector<COutput> quantum_outputs;
    for (const COutput& out : available.All()) {
        if (!IsQuantumMigrationScript(out.txout.scriptPubKey)) continue;
        CTxDestination dest;
        if (!ExtractDestination(out.txout.scriptPubKey, dest) || !pwallet->GetQuantumKeyInfo(dest).has_value()) continue;
        chain_coins.emplace(out.outpoint, Coin{});
        quantum_outputs.push_back(out);
    }
    pwallet->chain().findCoins(chain_coins);

    CAmount nominal_total{0};
    CAmount effective_total{0};
    CAmount burned_total{0};
    int decaying_count{0};
    int locked_count{0};
    int attestation_due_count{0};
    UniValue outputs(UniValue::VARR);

    const CCoinsViewCache& view = pwallet->chain().getCoinsTip();
    for (const COutput& out : quantum_outputs) {
        CTxDestination dest;
        CHECK_NONFATAL(ExtractDestination(out.txout.scriptPubKey, dest));

        const auto coin_it = chain_coins.find(out.outpoint);
        const bool chainstate_backed = coin_it != chain_coins.end() && !coin_it->second.IsSpent();
        Coin coin = chainstate_backed ? coin_it->second : Coin{out.txout, out.depth > 0 ? tip_height - out.depth + 1 : evaluation_height, false, false, static_cast<int>(out.time)};
        const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, out.txout.scriptPubKey);
        const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin, consensus, evaluation_height, evaluation_time, latest_attestation);
        const bool attestation_due = demurrage_active && !eval.locked && eval.inactive_blocks >= consensus.DemurrageAutoAttestBlocks();

        nominal_total += eval.nominal_value;
        effective_total += eval.effective_value;
        burned_total += eval.burned_value;
        if (eval.burned_value > 0) ++decaying_count;
        if (eval.locked) ++locked_count;
        if (attestation_due) ++attestation_due_count;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.outpoint.hash.GetHex());
        entry.pushKV("vout", static_cast<int>(out.outpoint.n));
        entry.pushKV("address", EncodeDestination(dest));
        entry.pushKV("depth", out.depth);
        entry.pushKV("coin_height", static_cast<int>(coin.nHeight));
        entry.pushKV("chainstate_backed", chainstate_backed);
        if (latest_attestation) entry.pushKV("latest_attestation_height", *latest_attestation);
        entry.pushKV("inactive_blocks", eval.inactive_blocks);
        entry.pushKV("remaining_ppm", eval.remaining_ppm);
        entry.pushKV("nominal_amount", ValueFromAmount(eval.nominal_value));
        entry.pushKV("effective_amount", ValueFromAmount(eval.effective_value));
        entry.pushKV("burned_if_spent_amount", ValueFromAmount(eval.burned_value));
        entry.pushKV("locked", eval.locked);
        entry.pushKV("exemption", eval.exemption);
        entry.pushKV("blocks_until_decay", std::max(0, consensus.DemurrageGraceBlocks() - eval.inactive_blocks));
        entry.pushKV("blocks_until_lock", std::max(0, consensus.DemurrageZeroBlocks() - eval.inactive_blocks));
        entry.pushKV("attestation_due", attestation_due);
        std::string action;
        if (!demurrage_active) {
            action = "none: demurrage is inactive";
        } else if (eval.locked) {
            action = "locked: this output can no longer be spent";
        } else if (attestation_due && wallet_staking_enabled) {
            action = "auto-attest eligible while staking";
        } else if (attestation_due) {
            action = "senddemurrageattestation recommended";
        } else if (eval.burned_value > 0) {
            action = "full-sweep spend recommended to realize decay in one transaction";
        } else {
            action = "none";
        }
        entry.pushKV("action", action);
        outputs.push_back(std::move(entry));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("demurrage_active", demurrage_active);
    obj.pushKV("tip_height", tip_height);
    obj.pushKV("evaluation_height", evaluation_height);
    obj.pushKV("evaluation_time", evaluation_time);
    obj.pushKV("demurrage_activation_height", consensus.nDemurrageActivationHeight);
    obj.pushKV("demurrage_effective_activation_height", consensus.EffectiveDemurrageActivationHeight());
    obj.pushKV("quantum_migration_deadline_time", consensus.nQuantumMigrationDeadlineTime);
    obj.pushKV("demurrage_height_guard_satisfied", evaluation_height >= consensus.EffectiveDemurrageActivationHeight());
    obj.pushKV("demurrage_post_migration_guard_satisfied", consensus.nQuantumMigrationDeadlineTime != 0 && evaluation_time > consensus.nQuantumMigrationDeadlineTime);
    obj.pushKV("wallet_staking_enabled", wallet_staking_enabled);
    obj.pushKV("quantum_outputs", static_cast<int>(quantum_outputs.size()));
    obj.pushKV("decaying_outputs", decaying_count);
    obj.pushKV("locked_outputs", locked_count);
    obj.pushKV("attestation_due_outputs", attestation_due_count);
    obj.pushKV("nominal_amount", ValueFromAmount(nominal_total));
    obj.pushKV("effective_amount", ValueFromAmount(effective_total));
    obj.pushKV("burned_if_spent_amount", ValueFromAmount(burned_total));
    obj.pushKV("outputs", std::move(outputs));
    return obj;
},
    };
}

static RPCHelpMan sweepdemurragedecay()
{
    return RPCHelpMan{"sweepdemurragedecay",
        "\nSweep wallet-owned direct Blackcoin ML-DSA outputs that are already decaying under demurrage.\n"
        "The transaction consumes the selected decaying UTXOs, realizes the demurrage burn, and pays the remaining effective value\n"
        "minus fees to a wallet-backed quantum address.\n",
        {
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"dry_run", RPCArg::Type::BOOL, RPCArg::Default{false}, "Build and return the transaction without committing it to the wallet."},
                    {"source_address", RPCArg::Type::STR, RPCArg::Default{""}, "Sweep only decaying UTXOs paying this wallet-backed quantum address."},
                    {"destination_address", RPCArg::Type::STR, RPCArg::Default{""}, "Wallet-backed quantum address to receive the effective value; omitted generates a fresh address."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{"demurrage-sweep"}, "Label for a freshly generated destination address."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in sat/vB."},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include unconfirmed or unsafe selected outputs."},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "dry_run", "Whether the transaction was only planned."},
            {RPCResult::Type::NUM, "evaluation_height", "Height used for demurrage evaluation"},
            {RPCResult::Type::NUM_TIME, "evaluation_time", "Parent MedianTimePast used for next-block demurrage evaluation"},
            {RPCResult::Type::NUM, "selected_inputs", "Number of decaying UTXOs selected"},
            {RPCResult::Type::NUM, "skipped_locked_outputs", "Number of fully locked decayed UTXOs skipped"},
            {RPCResult::Type::STR_AMOUNT, "nominal_amount", "Nominal selected value before demurrage"},
            {RPCResult::Type::STR_AMOUNT, "effective_amount", "Selected value after demurrage"},
            {RPCResult::Type::STR_AMOUNT, "burned_amount", "Demurrage amount realized as burn"},
            {RPCResult::Type::STR_AMOUNT, "skipped_locked_amount", "Nominal value of locked outputs skipped"},
            {RPCResult::Type::STR, "destination", "Quantum address receiving the effective value after fee"},
            {RPCResult::Type::BOOL, "newly_generated", "Whether the destination address was freshly generated"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Value of the new quantum output after fee"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
            {RPCResult::Type::NUM, "vsize", "Virtual transaction size"},
            {RPCResult::Type::STR_HEX, "hex", "Transaction hex"},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast transaction id"},
            {RPCResult::Type::STR, "warning", /*optional=*/true, "Backup warning"},
        }},
        RPCExamples{
            HelpExampleCli("sweepdemurragedecay", "")
          + HelpExampleCli("sweepdemurragedecay", "'{\"dry_run\":true}'")
          + HelpExampleRpc("sweepdemurragedecay", "{\"source_address\":\"<quantum_addr>\"}")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();
    const bool dry_run = options.exists("dry_run") && options["dry_run"].get_bool();
    const bool include_unsafe = options.exists("include_unsafe") && options["include_unsafe"].get_bool();
    const std::string source_address = options.exists("source_address") ? options["source_address"].get_str() : "";
    const std::string destination_address = options.exists("destination_address") ? options["destination_address"].get_str() : "";
    const std::string label = options.exists("label") ? options["label"].get_str() : "demurrage-sweep";

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);
    if (pwallet->m_wallet_unlock_staking_only) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet unlocked for staking only, unable to sweep demurrage outputs");
    }
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const CBlockIndex* tip = pwallet->chain().getTip();
    const int tip_height = tip ? tip->nHeight : -1;
    const int evaluation_height = tip_height >= 0 ? tip_height + 1 : 0;
    const int64_t evaluation_time = tip ? tip->GetMedianTimePast() : 0;
    if (!consensus.IsDemurrageActive(evaluation_height, evaluation_time)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "demurrage is not active for the next block");
    }

    std::optional<CScript> source_script;
    if (!source_address.empty()) {
        std::string error_msg;
        const CTxDestination source_dest = DecodeDestination(source_address, error_msg);
        const auto* witness = std::get_if<WitnessUnknown>(&source_dest);
        if (!IsValidDestination(source_dest) || !witness ||
            !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg.empty() ? "source_address is not a Blackcoin migration address" : error_msg);
        }
        if (!pwallet->GetQuantumKeyInfo(source_dest).has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "source_address is not wallet-backed");
        }
        source_script = GetScriptForDestination(source_dest);
    }

    CTxDestination dest;
    bool newly_generated{false};
    if (!destination_address.empty()) {
        std::string error_msg;
        dest = DecodeDestination(destination_address, error_msg);
        const auto* witness = std::get_if<WitnessUnknown>(&dest);
        if (!IsValidDestination(dest) || !witness ||
            !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg.empty() ? "destination_address is not a Blackcoin migration address" : error_msg);
        }
        if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "destination_address is not wallet-backed");
        }
    } else {
        auto op_dest = pwallet->GetNewQuantumDestination(label);
        if (!op_dest) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(op_dest).original);
        dest = *op_dest;
        newly_generated = true;
    }
    if (!pwallet->GetQuantumKeyInfo(dest).has_value()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Refusing to sweep: destination ML-DSA key is not confirmed stored in the wallet");
    }

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

    CoinsResult available = AvailableCoins(*pwallet, &coin_control, std::nullopt, filter);
    std::map<COutPoint, Coin> chain_coins;
    std::vector<COutput> candidates;
    for (const COutput& out : available.All()) {
        if (!IsQuantumMigrationScript(out.txout.scriptPubKey)) continue;
        if (source_script && out.txout.scriptPubKey != *source_script) continue;
        CTxDestination out_dest;
        if (!ExtractDestination(out.txout.scriptPubKey, out_dest) || !pwallet->GetQuantumKeyInfo(out_dest).has_value()) continue;
        chain_coins.emplace(out.outpoint, Coin{});
        candidates.push_back(out);
    }
    pwallet->chain().findCoins(chain_coins);

    CAmount nominal_amount{0};
    CAmount effective_amount{0};
    CAmount burned_amount{0};
    CAmount skipped_locked_amount{0};
    int selected_inputs{0};
    int skipped_locked_outputs{0};
    std::vector<COutPoint> selected_outpoints;
    const CCoinsViewCache& view = pwallet->chain().getCoinsTip();
    for (const COutput& out : candidates) {
        const auto coin_it = chain_coins.find(out.outpoint);
        if (coin_it == chain_coins.end() || coin_it->second.IsSpent()) continue;
        const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(view, out.txout.scriptPubKey);
        const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin_it->second, consensus, evaluation_height, evaluation_time, latest_attestation);
        if (eval.locked) {
            ++skipped_locked_outputs;
            skipped_locked_amount += eval.nominal_value;
            continue;
        }
        if (eval.burned_value <= 0) continue;
        selected_outpoints.push_back(out.outpoint);
        nominal_amount += eval.nominal_value;
        effective_amount += eval.effective_value;
        burned_amount += eval.burned_value;
        ++selected_inputs;
    }
    if (selected_inputs == 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable wallet-owned quantum outputs are currently decaying");
    }
    if (effective_amount <= 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Selected decaying outputs have no spendable effective value");
    }

    const int64_t current_time = GetAdjustedTimeSeconds();
    const CFeeRate fee_rate = GetMinimumFeeRate(*pwallet, coin_control, current_time);
    if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), fee_rate.ToString(FeeEstimateMode::SAT_VB)));
    }

    CMutableTransaction sweep_tx;
    sweep_tx.nVersion = CTransaction::CURRENT_VERSION;
    sweep_tx.nTime = current_time;
    static constexpr uint32_t MAX_SEQUENCE_NONFINAL = 0xfffffffe;
    for (const COutPoint& outpoint : selected_outpoints) {
        sweep_tx.vin.emplace_back(outpoint, CScript(), MAX_SEQUENCE_NONFINAL);
    }
    sweep_tx.vout.emplace_back(effective_amount, GetScriptForDestination(dest));

    const TxSize tx_size = CalculateMaximumSignedTxSize(CTransaction(sweep_tx), pwallet.get(), &coin_control);
    if (tx_size.vsize <= 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to estimate demurrage sweep transaction size");
    }
    const CAmount fee = std::max(GetMinFee(static_cast<size_t>(tx_size.vsize), static_cast<uint32_t>(current_time)), fee_rate.GetFee(static_cast<uint32_t>(tx_size.vsize)));
    if (fee > pwallet->m_default_max_tx_fee) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Fee exceeds wallet max transaction fee (%s)", FormatMoney(pwallet->m_default_max_tx_fee)));
    }
    const CAmount output_amount = effective_amount - fee;
    if (!MoneyRange(output_amount) || output_amount <= 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Selected decaying outputs cannot pay the sweep fee");
    }
    sweep_tx.vout[0].nValue = output_amount;

    if (IsDust(sweep_tx.vout[0], pwallet->chain().relayDustFee())) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Demurrage sweep would strand the effective value below dust after fees");
    }
    if (!dry_run) {
        std::map<int, bilingual_str> input_errors;
        if (!pwallet->SignTransaction(sweep_tx, input_errors)) {
            if (!input_errors.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Signing demurrage sweep failed: %s", input_errors.begin()->second.original));
            }
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing demurrage sweep failed");
        }
    }
    CTransactionRef tx = MakeTransactionRef(std::move(sweep_tx));
    const int result_vsize = dry_run ? static_cast<int>(tx_size.vsize) : static_cast<int>(GetVirtualTransactionSize(*tx, 0, 0));

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("dry_run", dry_run);
    obj.pushKV("evaluation_height", evaluation_height);
    obj.pushKV("evaluation_time", evaluation_time);
    obj.pushKV("selected_inputs", selected_inputs);
    obj.pushKV("skipped_locked_outputs", skipped_locked_outputs);
    obj.pushKV("nominal_amount", ValueFromAmount(nominal_amount));
    obj.pushKV("effective_amount", ValueFromAmount(effective_amount));
    obj.pushKV("burned_amount", ValueFromAmount(burned_amount));
    obj.pushKV("skipped_locked_amount", ValueFromAmount(skipped_locked_amount));
    obj.pushKV("destination", EncodeDestination(dest));
    obj.pushKV("newly_generated", newly_generated);
    obj.pushKV("amount", ValueFromAmount(tx->vout[0].nValue));
    obj.pushKV("fee", ValueFromAmount(fee));
    obj.pushKV("vsize", result_vsize);
    obj.pushKV("hex", EncodeHexTx(*tx));
    if (!dry_run) {
        mapValue_t map_value;
        map_value["comment"] = "Blackcoin demurrage sweep";
        CommitWalletTransactionOrThrow(*pwallet, tx, std::move(map_value), "Blackcoin demurrage sweep");
        obj.pushKV("txid", tx->GetHash().GetHex());
    }
    if (newly_generated) {
        obj.pushKV("warning", "A new ML-DSA quantum address was created. Back up the wallet before relying on the swept funds.");
    }
    return obj;
},
    };
}

Span<const CRPCCommand> GetStakingRPCCommands()
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              actor (function)
  //  ------------------    ------------------------
    { "staking",            &getstakinginfo,                 },
    { "staking",            &getstakingdonationinfo,         },
    { "staking",            &setstakingdonation,             },
    { "staking",            &getgoldrushinfo,                },
    { "staking",            &reservebalance,                 },
    { "staking",            &sendshadowsignal,               },
    { "staking",            &sendshadowpowclaim,             },
    { "staking",            &setpowmining,                   },
    { "staking",            &getpowmininginfo,               },
    { "staking",            &getquantumstakeaddressinfo,     },
    { "staking",            &listquantumstakeoutputs,        },
    { "staking",            &fundquantumstakeaddress,        },
    { "staking",            &withdrawquantumstakeaddress,    },
    { "staking",            &getquantumoperatorbondinfo,     },
    { "staking",            &fundquantumoperatorbond,        },
    { "staking",            &withdrawquantumoperatorbond,    },
    { "staking",            &getquantumcoldstakebalance,     },
    { "staking",            &fundquantumcoldstakeaddress,    },
    { "staking",            &withdrawquantumcoldstakeaddress,},
    { "staking",            &getquantumredelegationinfo,     },
    { "staking",            &redelegatequantumcoldstake,     },
    { "staking",            &senddemurrageattestation,       },
    { "staking",            &getdemurragewalletinfo,         },
    { "staking",            &sweepdemurragedecay,            },
    { "staking",            &staking,                        },
    { "staking",            &checkkernel,                    },
};
// clang-format on
    return commands;
}

} // namespace wallet
