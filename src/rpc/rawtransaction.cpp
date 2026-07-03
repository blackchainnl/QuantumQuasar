// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <eutxo/transition.h>
#include <hash.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <rgb/engine.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <shadow.h>
#include <support/cleanse.h>
#include <uint256.h>
#include <undo.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdint.h>
#include <stdexcept>

#include <univalue.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;

namespace {

struct QuantumSigningKey {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

std::vector<unsigned char> QuantumProgramForPubkey(const std::vector<uint8_t>& pubkey)
{
    std::vector<unsigned char> program(QUANTUM_MIGRATION_PROGRAM_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(program.data());
    return program;
}

std::vector<unsigned char> QuantumSigningLookupProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program)
{
    QuantumStakeTierProgram tier;
    if (witness_version == QUANTUM_MIGRATION_WITNESS_VERSION &&
        DecodeQuantumStakeTierProgram(witness_version, witness_program, tier) &&
        tier.tiered) {
        return {tier.commitment.begin(), tier.commitment.end()};
    }
    return witness_program;
}

bool IsQuantumProtectedScript(const CScript& script_pubkey)
{
    return IsQuantumMigrationScript(script_pubkey) || IsQuantumColdStakeScript(script_pubkey);
}

bool IsQuantumProtectedSpendAllowedOutput(const CTransaction& tx, unsigned int output_index)
{
    const CTxOut& txout = tx.vout[output_index];
    if (tx.IsCoinStake() && output_index == 0 && txout.IsEmpty()) return true;
    if (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == OP_RETURN) return true;
    return IsQuantumProtectedScript(txout.scriptPubKey) || IsEUTXOScript(txout.scriptPubKey);
}

bool IsValidQuantumColdStakeSelector(const std::vector<unsigned char>& selector)
{
    return selector.empty() || (selector.size() == 1 && selector[0] == 1);
}

bool IsQuantumColdStakeStakerBranch(const std::vector<unsigned char>& selector)
{
    return selector.size() == 1 && selector[0] == 1;
}

void QuantumTxInErrorToJSON(const CTxIn& txin, UniValue& errors, const std::string& message)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("txid", txin.prevout.hash.ToString());
    entry.pushKV("vout", static_cast<uint64_t>(txin.prevout.n));
    UniValue witness(UniValue::VARR);
    for (const auto& item : txin.scriptWitness.stack) {
        witness.push_back(HexStr(item));
    }
    entry.pushKV("witness", witness);
    entry.pushKV("scriptSig", HexStr(txin.scriptSig));
    entry.pushKV("sequence", static_cast<uint64_t>(txin.nSequence));
    entry.pushKV("error", message);
    errors.push_back(entry);
}

template <typename Byte>
void CleanseVector(std::vector<Byte>& bytes)
{
    if (!bytes.empty()) {
        memory_cleanse(bytes.data(), bytes.size() * sizeof(Byte));
        bytes.clear();
    }
}

std::vector<unsigned char> ParseHexOAllowEmpty(const UniValue& obj, const std::string& key)
{
    const std::string s = obj.find_value(key).get_str();
    if (s.empty()) return {};
    if (!IsHex(s)) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a hexadecimal string", key));
    return ParseHex(s);
}

} // namespace

static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in blackcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, RPCSerializationWithoutWitness(), txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                if (!entry.exists("time"))
                    entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            }
            else
                entry.pushKV("confirmations", 0);
        }
    }
}

static std::vector<RPCResult> ScriptPubKeyDoc() {
    return
         {
             {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
             {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
             {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
             {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
             {RPCResult::Type::NUM, "witness_version", /*optional=*/true, "The witness version for EUTXO commitment outputs"},
             {RPCResult::Type::STR_HEX, "witness_program", /*optional=*/true, "The witness program for EUTXO commitment outputs"},
             {RPCResult::Type::STR, "rgb_magic", /*optional=*/true, "The RGB commitment magic/version bytes"},
             {RPCResult::Type::STR_HEX, "rgb_state_hash", /*optional=*/true, "The committed 32-byte RGB state hash"},
             {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
         };
}

static std::vector<RPCResult> DecodeTxDoc(const std::string& txid_field_doc)
{
    return {
        {RPCResult::Type::STR_HEX, "txid", txid_field_doc},
        {RPCResult::Type::STR_HEX, "hash", "The transaction hash (differs from txid for witness transactions)"},
        {RPCResult::Type::NUM, "size", "The serialized transaction size"},
        {RPCResult::Type::NUM, "vsize", "The virtual transaction size (differs from size for witness transactions)"},
        {RPCResult::Type::NUM, "weight", "The transaction's weight (between vsize*4-3 and vsize*4)"},
        {RPCResult::Type::NUM, "version", "The version"},
        {RPCResult::Type::NUM_TIME, "locktime", "The lock time"},
        {RPCResult::Type::NUM_TIME, "time", /*optional=*/true, "The transaction time, present for legacy timestamped transactions"},
        {RPCResult::Type::ARR, "vin", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "coinbase", /*optional=*/true, "The coinbase value (only if coinbase transaction)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id (if not coinbase transaction)"},
                {RPCResult::Type::NUM, "vout", /*optional=*/true, "The output number (if not coinbase transaction)"},
                {RPCResult::Type::OBJ, "scriptSig", /*optional=*/true, "The script (if not coinbase transaction)",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the signature script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw signature script bytes, hex-encoded"},
                }},
                {RPCResult::Type::ARR, "txinwitness", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR_HEX, "hex", "hex-encoded witness data (if any)"},
                }},
                {RPCResult::Type::NUM, "sequence", "The script sequence number"},
            }},
        }},
        {RPCResult::Type::ARR, "vout", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::NUM, "n", "index"},
                {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
            }},
        }},
    };
}

static std::vector<RPCArg> CreateTxDoc()
{
    return {
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
        {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                "At least one output of either type must be specified.\n"
                "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                "                             accepted as second parameter.",
            {
                {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                    {
                        {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Blackcoin address, the value (float or string) is the amount in " + CURRENCY_UNIT},
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
            },
         RPCArgOptions{.skip_type_check = true}},
        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
        {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{false}, "Marks this transaction as BIP125-replaceable. Allows this transaction to be replaced by a transaction with higher fees"},
    };
}

// Update PSBT with information from the mempool, the UTXO set, the txindex, and the provided descriptors.
// Optionally, sign the inputs that we can using information from the descriptors.
PartiallySignedTransaction ProcessPSBT(const std::string& psbt_string, const std::any& context, const HidingSigningProvider& provider, int sighash_type, bool finalize)
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, psbt_string, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();
    const NodeContext& node = EnsureAnyNodeContext(context);

    // If we can't find the corresponding full transaction for all of our inputs,
    // this will be used to find just the utxos for the segwit inputs for which
    // the full transaction isn't found
    std::map<COutPoint, Coin> coins;

    // Fetch previous transactions:
    // First, look in the txindex and the mempool
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& psbt_input = psbtx.inputs.at(i);
        const CTxIn& tx_in = psbtx.tx->vin.at(i);

        // The `non_witness_utxo` is the whole previous transaction
        if (psbt_input.non_witness_utxo) continue;

        CTransactionRef tx;

        // Look in the txindex
        if (g_txindex) {
            uint256 block_hash;
            g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx);
        }
        // If we still don't have it look in the mempool
        if (!tx) {
            tx = node.mempool->get(tx_in.prevout.hash);
        }
        if (tx) {
            psbt_input.non_witness_utxo = tx;
        } else {
            coins[tx_in.prevout]; // Create empty map entry keyed by prevout
        }
    }

    // If we still haven't found all of the inputs, look for the missing ones in the utxo set
    if (!coins.empty()) {
        FindCoins(node, coins);
        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs.at(i);

            // If there are still missing utxos, add them if they were found in the utxo set
            if (!input.non_witness_utxo) {
                const CTxIn& tx_in = psbtx.tx->vin.at(i);
                const Coin& coin = coins.at(tx_in.prevout);
                if (!coin.out.IsNull() && IsSegWitOutput(provider, coin.out.scriptPubKey)) {
                    input.witness_utxo = coin.out;
                }
            }
        }
    }

    const PrecomputedTransactionData& txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        if (PSBTInputSigned(psbtx.inputs.at(i))) {
            continue;
        }

        // Update script/keypath information using descriptor data.
        // Note that SignPSBTInput does a lot more than just constructing ECDSA signatures.
        // We only actually care about those if our signing provider doesn't hide private
        // information, as is the case with `descriptorprocesspsbt`
        SignPSBTInput(provider, psbtx, /*index=*/i, &txdata, sighash_type, /*out_sigdata=*/nullptr, finalize);
    }

    // Update script/keypath information using descriptor data.
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        UpdatePSBTOutput(provider, psbtx, i);
    }

    RemoveUnnecessaryTransactions(psbtx, /*sighash_type=*/1);

    return psbtx;
}

static RPCHelpMan getrawtransaction()
{
    return RPCHelpMan{
                "getrawtransaction",

                "By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled\n"
                "and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.\n"
                "If a blockhash argument is passed, it will return the transaction if\n"
                "the specified block is available and the transaction is in that block.\n\n"
                "Hint: Use gettransaction for wallet transactions.\n\n"

                "If verbosity is 0 or omitted, returns the serialized transaction as a hex-encoded string.\n"
                "If verbosity is 1, returns a JSON Object with information about the transaction.\n"
                "If verbosity is 2, returns a JSON Object with information about the transaction, including fee and prevout information.",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for hex-encoded data, 1 for a JSON object, and 2 for JSON object with fee and prevout",
                     RPCArgOptions{.skip_type_check = true}},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The block in which to look for the transaction"},
                },
                {
                    RPCResult{"if verbosity is not set or set to 0",
                         RPCResult::Type::STR, "data", "The serialized transaction as a hex-encoded string for 'txid'"
                     },
                     RPCResult{"if verbosity is set to 1",
                         RPCResult::Type::OBJ, "", "",
                         Cat<std::vector<RPCResult>>(
                         {
                             {RPCResult::Type::BOOL, "in_active_chain", /*optional=*/true, "Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)"},
                             {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "the block hash"},
                             {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The confirmations"},
                             {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME},
                             {RPCResult::Type::NUM, "time", /*optional=*/true, "Same as \"blocktime\""},
                             {RPCResult::Type::STR_HEX, "hex", "The serialized, hex-encoded data for 'txid'"},
                         },
                         DecodeTxDoc(/*txid_field_doc=*/"The transaction id (same as provided)")),
                    },
                    RPCResult{"for verbosity = 2",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "utxo being spent",
                                {
                                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                                    {RPCResult::Type::OBJ, "prevout", /*optional=*/true, "The previous output, omitted if block undo data is not available",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                    }},
                                }},
                            }},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 0 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 2 \"myblockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");
    const CBlockIndex* blockindex = nullptr;

    if (hash == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
        // Special exception for the genesis block coinbase transaction
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
    }

    // Accept either a bool (true) or a num (>=0) to indicate verbosity.
    int verbosity{0};
    if (!request.params[1].isNull()) {
        if (request.params[1].isBool()) {
            verbosity = request.params[1].get_bool();
        } else {
            verbosity = request.params[1].getInt<int>();
        }
    }

    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), hash, hash_block, chainman.m_blockman);
    if (!tx) {
        std::string errmsg;
        if (blockindex) {
            const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
            if (!block_has_data) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }

    if (verbosity <= 0) {
        return EncodeHexTx(*tx, /*without_witness=*/RPCSerializationWithoutWitness());
    }

    UniValue result(UniValue::VOBJ);
    if (blockindex) {
        LOCK(cs_main);
        result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex));
    }
    // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
    if (request.params[2].isNull()) {
        LOCK(cs_main);
        blockindex = chainman.m_blockman.LookupBlockIndex(hash_block);
    }
    if (verbosity == 1 || !blockindex) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CBlockUndo blockUndo;
    CBlock block;

    if (tx->IsCoinBase() ||
        !(chainman.m_blockman.UndoReadFromDisk(blockUndo, *blockindex) && chainman.m_blockman.ReadBlockFromDisk(block, *blockindex))) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }
    TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    return result;
},
    };
}

static RPCHelpMan createrawtransaction()
{
    return RPCHelpMan{"createrawtransaction",
                "\nCreate a transaction spending the given inputs and creating new outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"
                },
                RPCExamples{
                    HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], request.params[3]);

    return EncodeHexTx(CTransaction(rawTx));
},
    };
}

static RPCHelpMan decoderawtransaction()
{
    return RPCHelpMan{"decoderawtransaction",
                "Return a JSON object representing the serialized, hex-encoded transaction.",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
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
                    DecodeTxDoc(/*txid_field_doc=*/"The transaction id"),
                },
                RPCExamples{
                    HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;

    bool try_witness = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool try_no_witness = request.params[1].isNull() ? true : !request.params[1].get_bool();

    if (!DecodeHexTx(mtx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VOBJ);
    TxToUniv(CTransaction(std::move(mtx)), /*block_hash=*/uint256(), /*entry=*/result, /*include_hex=*/false);

    return result;
},
    };
}

static RPCHelpMan decodergbcommitment()
{
    return RPCHelpMan{"decodergbcommitment",
                "Decode RGB output commitments (Layer-2 anchors) from a hex-encoded transaction or RGB scriptPubKey.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction or scriptPubKey hex string"},
                },
                {
                    RPCResult{"if input is a transaction",
                        RPCResult::Type::ARR, "", "Array of RGB output commitments",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "n", "The output index (vout)"},
                                {RPCResult::Type::STR, "type", "The output type"},
                                {RPCResult::Type::STR_HEX, "prefix", "The 4-byte RGB prefix"},
                                {RPCResult::Type::STR, "magic", "The ASCII RGB commitment magic"},
                                {RPCResult::Type::STR_HEX, "state_hash", "The 32-byte state hash"},
                                {RPCResult::Type::BOOL, "spendable", "Whether the commitment is directly spendable"},
                            }},
                        }},
                    RPCResult{"if input is an RGB scriptPubKey",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "type", "The output type"},
                            {RPCResult::Type::STR_HEX, "prefix", "The 4-byte RGB prefix"},
                            {RPCResult::Type::STR, "magic", "The ASCII RGB commitment magic"},
                            {RPCResult::Type::STR_HEX, "state_hash", "The 32-byte state hash"},
                            {RPCResult::Type::BOOL, "spendable", "Whether the commitment is directly spendable"},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("decodergbcommitment", "\"hexstring\"")
            + HelpExampleRpc("decodergbcommitment", "\"hexstring\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    const std::string hex = request.params[0].get_str();

    auto decode_script = [](const CScript& script, int output_index) -> UniValue {
        std::vector<std::vector<unsigned char>> solns;
        if (Solver(script, solns) != TxoutType::RGB_COMMITMENT || solns.size() != 1 || solns[0].size() != 4 + uint256::size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "scriptPubKey is not an RGB commitment");
        }

        UniValue obj(UniValue::VOBJ);
        if (output_index >= 0) obj.pushKV("n", output_index);
        obj.pushKV("type", "rgb_commitment");
        obj.pushKV("prefix", HexStr(Span<const unsigned char>(solns[0].data(), 4)));
        obj.pushKV("magic", std::string(solns[0].begin(), solns[0].begin() + 4));
        obj.pushKV("state_hash", HexStr(Span<const unsigned char>(solns[0].data() + 4, uint256::size())));
        obj.pushKV("spendable", false);
        return obj;
    };

    if (DecodeHexTx(mtx, hex, true, true)) {
        UniValue result(UniValue::VARR);
        for (unsigned int i = 0; i < mtx.vout.size(); ++i) {
            const CTxOut& txout = mtx.vout[i];
            try {
                result.push_back(decode_script(txout.scriptPubKey, static_cast<int>(i)));
            } catch (const UniValue&) {
                // Non-RGB outputs are expected when decoding a full transaction.
            }
        }
        return result;
    }

    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    const std::vector<unsigned char> script_data = ParseHex(hex);
    const CScript script(script_data.begin(), script_data.end());
    return decode_script(script, -1);
},
    };
}

static uint64_t ParseRGBAssetAmount(const UniValue& obj, const std::string& key)
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

static rgb::Seal ParseRGBSeal(const UniValue& obj)
{
    RPCTypeCheckObj(obj, {
        {"txid", UniValueType(UniValue::VSTR)},
        {"vout", UniValueType(UniValue::VNUM)},
    });
    const int64_t vout = obj.find_value("vout").getInt<int64_t>();
    if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout is out of range");
    }
    return rgb::Seal{COutPoint{Txid::FromUint256(ParseHashO(obj, "txid")), static_cast<uint32_t>(vout)}};
}

static rgb::Assignment ParseRGBAssignment(const UniValue& obj)
{
    return rgb::Assignment{ParseRGBSeal(obj), ParseRGBAssetAmount(obj, "amount")};
}

static UniValue RGBSealToUniv(const rgb::Seal& seal)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", seal.outpoint.hash.GetHex());
    out.pushKV("vout", static_cast<uint64_t>(seal.outpoint.n));
    return out;
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

static UniValue RGBTransitionIdsToUniv(const std::vector<uint256>& transition_ids)
{
    UniValue out(UniValue::VARR);
    for (const uint256& transition_id : transition_ids) {
        out.push_back(transition_id.GetHex());
    }
    return out;
}

static RPCHelpMan verifyrgbconsignment()
{
    return RPCHelpMan{"verifyrgbconsignment",
        "Verify a Blackcoin RGB fixed-supply fungible-asset consignment.\n"
        "This is client-side RGB validation: it validates deterministic contract/transition\n"
        "state and returns the anchor commitment to publish with an rgb_commitment OP_RETURN.\n",
        {
            {"consignment", RPCArg::Type::OBJ, RPCArg::Optional::NO, "RGB consignment",
             {
                 {"genesis", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Contract genesis",
                  {
                      {"ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Ticker/symbol"},
                      {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset name"},
                      {"total_supply", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset supply"},
                      {"allocations", RPCArg::Type::ARR, RPCArg::Optional::NO, "Initial owned UTXO-seal allocations, sorted by txid/vout",
                       {
                           {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Allocation", {
                               {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                               {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                               {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                           }},
                       }},
                  }},
                 {"transitions", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "State transitions in topological order",
                  {
                      {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Transition", {
                          {"contract_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Expected contract id; defaults to this genesis contract id"},
                          {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Consumed owned seals, sorted by txid/vout", {
                              {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Input seal", {
                                  {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                                  {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                              }},
                          }},
                          {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Created owned seals, sorted by txid/vout", {
                              {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Output assignment", {
                                  {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Seal txid"},
                                  {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Seal vout"},
                                  {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Integer asset amount"},
                              }},
                          }},
                      }},
                  }},
             }},
            {"anchor_transition_ids", RPCArg::Type::ARR, RPCArg::DefaultHint{"all transitions"}, "Transition ids to commit in the anchor commitment. Use this for full-history consignments where only the newest transition is anchored by the current transaction.",
             {
                 {"transition_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Transition id to include in anchor order"},
             }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether the consignment validates"},
                {RPCResult::Type::STR_HEX, "contract_id", "Deterministic contract id"},
                {RPCResult::Type::NUM, "current_supply", "Validated current supply"},
                {RPCResult::Type::NUM, "unspent_assignments", "Number of current owned assignments"},
                {RPCResult::Type::ARR, "errors", "Validation errors", {{RPCResult::Type::STR, "", "Error"}}},
                {RPCResult::Type::ARR, "transition_ids", "Transition ids in supplied order", {{RPCResult::Type::STR_HEX, "", "Transition id"}}},
                {RPCResult::Type::ARR, "anchor_transition_ids", "Transition ids committed by transfer_anchor_commitment", {{RPCResult::Type::STR_HEX, "", "Transition id"}}},
                {RPCResult::Type::STR_HEX, "anchor_commitment", "Legacy bundle commitment over every transition in the supplied consignment"},
                {RPCResult::Type::STR_HEX, "consignment_anchor_commitment", "Bundle commitment over every transition in the supplied consignment"},
                {RPCResult::Type::STR_HEX, "transfer_anchor_commitment", "Scoped bundle commitment to publish using createrawtransaction rgb_commitment"},
                {RPCResult::Type::ARR, "unspent", "Current owned assignments after validation",
                 {
                     {RPCResult::Type::OBJ, "", "", {
                         {RPCResult::Type::STR_HEX, "txid", "Seal txid"},
                         {RPCResult::Type::NUM, "vout", "Seal vout"},
                         {RPCResult::Type::NUM, "amount", "Integer asset amount"},
                     }},
                 }},
            }},
        RPCExamples{
            HelpExampleCli("verifyrgbconsignment", "'{\"genesis\":{\"ticker\":\"QQT\",\"name\":\"Test\",\"total_supply\":100,\"allocations\":[{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"amount\":100}]},\"transitions\":[]}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& c = request.params[0].get_obj();
    const UniValue& genesis_obj = c.find_value("genesis").get_obj();
    RPCTypeCheckObj(genesis_obj, {
        {"ticker", UniValueType(UniValue::VSTR)},
        {"name", UniValueType(UniValue::VSTR)},
        {"total_supply", UniValueType(UniValue::VNUM)},
        {"allocations", UniValueType(UniValue::VARR)},
    });

    rgb::Genesis genesis;
    genesis.ticker = genesis_obj.find_value("ticker").get_str();
    genesis.name = genesis_obj.find_value("name").get_str();
    genesis.total_supply = ParseRGBAssetAmount(genesis_obj, "total_supply");
    for (const UniValue& allocation : genesis_obj.find_value("allocations").get_array().getValues()) {
        genesis.allocations.push_back(ParseRGBAssignment(allocation.get_obj()));
    }

    const uint256 contract_id = rgb::ContractId(genesis);
    std::vector<rgb::Transition> transitions;
    const UniValue& transitions_value = c.find_value("transitions");
    if (!transitions_value.isNull()) {
        if (!transitions_value.isArray()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "transitions must be an array");
        }
        for (const UniValue& transition_value : transitions_value.get_array().getValues()) {
            const UniValue& transition_obj = transition_value.get_obj();
            RPCTypeCheckObj(transition_obj, {
                {"inputs", UniValueType(UniValue::VARR)},
                {"outputs", UniValueType(UniValue::VARR)},
            });

            rgb::Transition transition;
            transition.contract_id = transition_obj.find_value("contract_id").isNull()
                ? contract_id
                : ParseHashO(transition_obj, "contract_id");
            for (const UniValue& input : transition_obj.find_value("inputs").get_array().getValues()) {
                transition.inputs.push_back(ParseRGBSeal(input.get_obj()));
            }
            for (const UniValue& output : transition_obj.find_value("outputs").get_array().getValues()) {
                transition.outputs.push_back(ParseRGBAssignment(output.get_obj()));
            }
            transitions.push_back(std::move(transition));
        }
    }

    const rgb::ValidationResult validation = rgb::ValidateConsignment(genesis, transitions);

    std::vector<uint256> transition_ids;
    transition_ids.reserve(transitions.size());
    for (const rgb::Transition& transition : transitions) {
        transition_ids.push_back(rgb::TransitionId(transition));
    }
    const std::vector<uint256> anchor_transition_ids = ResolveRGBAnchorTransitionIds(request.params[1], transition_ids);

    UniValue out(UniValue::VOBJ);
    out.pushKV("valid", validation.valid);
    out.pushKV("contract_id", validation.contract_id.GetHex());
    out.pushKV("current_supply", static_cast<uint64_t>(validation.current_supply));
    out.pushKV("unspent_assignments", static_cast<uint64_t>(validation.unspent_assignments));
    UniValue errors(UniValue::VARR);
    for (const std::string& error : validation.errors) errors.push_back(error);
    out.pushKV("errors", errors);
    out.pushKV("transition_ids", RGBTransitionIdsToUniv(transition_ids));
    out.pushKV("anchor_transition_ids", RGBTransitionIdsToUniv(anchor_transition_ids));
    out.pushKV("anchor_commitment", rgb::AnchorCommitment(transition_ids).GetHex());
    out.pushKV("consignment_anchor_commitment", rgb::AnchorCommitment(transition_ids).GetHex());
    out.pushKV("transfer_anchor_commitment", rgb::AnchorCommitment(anchor_transition_ids).GetHex());
    UniValue unspent(UniValue::VARR);
    for (const auto& [seal, amount] : validation.unspent) {
        UniValue assignment = RGBSealToUniv(seal);
        assignment.pushKV("amount", static_cast<uint64_t>(amount));
        unspent.push_back(assignment);
    }
    out.pushKV("unspent", unspent);
    return out;
},
    };
}

static RPCHelpMan decodeeutxospend()
{
    return RPCHelpMan{"decodeeutxospend",
                "Decode EUTXO witness spend candidates from a hex-encoded transaction.\n"
                "WARNING: This matches ANY input with >=3 witness items (e.g. P2WSH multisig or tapscript spends). "
                "The extracted elements are unverified candidates; tooling should not treat this as authoritative.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Array of EUTXO spend candidates",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "vin", "The input index"},
                            {RPCResult::Type::STR_HEX, "datum", "The datum hex"},
                            {RPCResult::Type::STR_HEX, "redeemer", "The redeemer hex"},
                            {RPCResult::Type::STR_HEX, "validator", "The validator script hex"},
                            {RPCResult::Type::BOOL, "unverified", "Always true. Represents unverified candidates since prevout witversion is not checked."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("decodeeutxospend", "\"hexstring\"")
            + HelpExampleRpc("decodeeutxospend", "\"hexstring\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str(), true, true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VARR);
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        const CTxIn& txin = mtx.vin[i];
        const CScriptWitness& witness = txin.scriptWitness;

        if (witness.stack.size() >= 3) {
            bool valid_size = true;
            for (const auto& item : witness.stack) {
                if (item.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
                    valid_size = false;
                    break;
                }
            }
            if (valid_size) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("vin", (int)i);

                const valtype& validator_script_bytes = witness.stack[witness.stack.size() - 1];
                const valtype& redeemer = witness.stack[witness.stack.size() - 2];
                const valtype& datum = witness.stack[witness.stack.size() - 3];

                obj.pushKV("datum", HexStr(datum));
                obj.pushKV("redeemer", HexStr(redeemer));
                obj.pushKV("validator", HexStr(validator_script_bytes));
                obj.pushKV("unverified", true);

                result.push_back(obj);
            }
        }
    }
    return result;
},
    };
}

static RPCHelpMan decodescript()
{
    return RPCHelpMan{
        "decodescript",
        "\nDecode a hex-encoded script.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded script"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "asm", "Script public key"},
                {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                {RPCResult::Type::STR, "type", "The output type (e.g. " + GetAllOutputTypes() + ")"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
                {RPCResult::Type::STR, "p2sh", /*optional=*/true,
                 "address of P2SH script wrapping this redeem script (not returned for types that should not be wrapped)"},
                {RPCResult::Type::OBJ, "segwit", /*optional=*/true,
                 "Result of a witness script public key wrapping this redeem script (not returned for types that should not be wrapped)",
                 {
                     {RPCResult::Type::STR, "asm", "String representation of the script public key"},
                     {RPCResult::Type::STR_HEX, "hex", "Hex string of the script public key"},
                     {RPCResult::Type::STR, "type", "The type of the script public key (e.g. witness_v0_keyhash or witness_v0_scripthash)"},
                     {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
                     {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                     {RPCResult::Type::STR, "p2sh-segwit", "address of the P2SH script wrapping this witness redeem script"},
                 }},
            },
        },
        RPCExamples{
            HelpExampleCli("decodescript", "\"hexstring\"")
          + HelpExampleRpc("decodescript", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptToUniv(script, /*out=*/r, /*include_hex=*/false, /*include_address=*/true);

    std::vector<std::vector<unsigned char>> solutions_data;
    const TxoutType which_type{Solver(script, solutions_data)};

    const bool can_wrap{[&] {
        switch (which_type) {
        case TxoutType::MULTISIG:
        case TxoutType::NONSTANDARD:
        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            // Can be wrapped if the checks below pass
            break;
        case TxoutType::NULL_DATA:
        case TxoutType::RGB_COMMITMENT:
        case TxoutType::SCRIPTHASH:
        case TxoutType::EUTXO_COMMITMENT:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
            // Should not be wrapped
            return false;
        } // no default case, so the compiler can warn about missing cases
        if (!script.HasValidOps() || script.IsUnspendable()) {
            return false;
        }
        for (CScript::const_iterator it{script.begin()}; it != script.end();) {
            opcodetype op;
            CHECK_NONFATAL(script.GetOp(it, op));
            if (op == OP_CHECKSIGADD || IsOpSuccess(op)) {
                return false;
            }
        }
        return true;
    }()};

    if (can_wrap) {
        r.pushKV("p2sh", EncodeDestination(ScriptHash(script)));
        // P2SH and witness programs cannot be wrapped in P2WSH, if this script
        // is a witness program, don't return addresses for a segwit programs.
        const bool can_wrap_P2WSH{[&] {
            switch (which_type) {
            case TxoutType::MULTISIG:
            case TxoutType::PUBKEY:
            // Uncompressed pubkeys cannot be used with segwit checksigs.
            // If the script contains an uncompressed pubkey, skip encoding of a segwit program.
                for (const auto& solution : solutions_data) {
                    if ((solution.size() != 1) && !CPubKey(solution).IsCompressed()) {
                        return false;
                    }
                }
                return true;
            case TxoutType::NONSTANDARD:
            case TxoutType::PUBKEYHASH:
                // Can be P2WSH wrapped
                return true;
            case TxoutType::NULL_DATA:
            case TxoutType::RGB_COMMITMENT:
            case TxoutType::SCRIPTHASH:
            case TxoutType::EUTXO_COMMITMENT:
            case TxoutType::WITNESS_UNKNOWN:
            case TxoutType::WITNESS_V0_KEYHASH:
            case TxoutType::WITNESS_V0_SCRIPTHASH:
            case TxoutType::WITNESS_V1_TAPROOT:
                // Should not be wrapped
                return false;
            } // no default case, so the compiler can warn about missing cases
            NONFATAL_UNREACHABLE();
        }()};
        if (can_wrap_P2WSH) {
            UniValue sr(UniValue::VOBJ);
            CScript segwitScr;
            FlatSigningProvider provider;
            if (which_type == TxoutType::PUBKEY) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(Hash160(solutions_data[0])));
            } else if (which_type == TxoutType::PUBKEYHASH) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(uint160{solutions_data[0]}));
            } else {
                // Scripts that are not fit for P2WPKH are encoded as P2WSH.
                provider.scripts[CScriptID(script)] = script;
                segwitScr = GetScriptForDestination(WitnessV0ScriptHash(script));
            }
            ScriptToUniv(segwitScr, /*out=*/sr, /*include_hex=*/true, /*include_address=*/true, /*provider=*/&provider);
            sr.pushKV("p2sh-segwit", EncodeDestination(ScriptHash(segwitScr)));
            r.pushKV("segwit", sr);
        }
    }

    return r;
},
    };
}

static RPCHelpMan combinerawtransaction()
{
    return RPCHelpMan{"combinerawtransaction",
                "\nCombine multiple partially signed transactions into one transaction.\n"
                "The combined transaction may be another partially signed transaction or a \n"
                "fully signed transaction.",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The hex strings of partially signed transactions",
                        {
                            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded raw transaction"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The hex-encoded raw transaction with signature(s)"
                },
                RPCExamples{
                    HelpExampleCli("combinerawtransaction", R"('["myhex1", "myhex2", "myhex3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    UniValue txs = request.params[0].get_array();
    std::vector<CMutableTransaction> txVariants(txs.size());

    for (unsigned int idx = 0; idx < txs.size(); idx++) {
        if (!DecodeHexTx(txVariants[idx], txs[idx].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx));
        }
    }

    if (txVariants.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transactions");
    }

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Input not found or already spent");
        }
        SignatureData sigdata;

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            if (txv.vin.size() > i) {
                sigdata.MergeSignatureData(DataFromTransaction(txv, i, coin.out));
            }
        }
        ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(mergedTx, i, coin.out.nValue, 1), coin.out.scriptPubKey, sigdata);

        UpdateInput(txin, sigdata);
    }

    return EncodeHexTx(CTransaction(mergedTx));
},
    };
}

static RPCHelpMan signrawtransactionwithkey()
{
    return RPCHelpMan{"signrawtransactionwithkey",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second argument is an array of base58-encoded private\n"
                "keys that will be the only keys used to sign the transaction.\n"
                "The third optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base58-encoded private keys for signing",
                        {
                            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "private key in base58-encoding"},
                        },
                        },
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
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of:\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"ALL|FORKID\"\n"
            "       \"NONE\"\n"
            "       \"NONE|FORKID\"\n"
            "       \"SINGLE\"\n"
            "       \"SINGLE|FORKID\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"ALL|FORKID|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"NONE|FORKID|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
            "       \"SINGLE|FORKID|ANYONECANPAY\"\n"
                    },
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
                    HelpExampleCli("signrawtransactionwithkey", "\"myhex\" \"[\\\"key1\\\",\\\"key2\\\"]\"")
            + HelpExampleRpc("signrawtransactionwithkey", "\"myhex\", \"[\\\"key1\\\",\\\"key2\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    FillableSigningProvider keystore;
    const UniValue& keys = request.params[1].get_array();
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        UniValue k = keys[idx];
        CKey key = DecodeSecret(k.get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }
        keystore.AddKey(key);
    }

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    FindCoins(node, coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[2], &keystore, coins);

    UniValue result(UniValue::VOBJ);
    UniValue sighash{request.params[3]};
    const bool use_forkid_default{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip() && chainman.GetConsensus().IsNewNetworkStakeOnly(chainman.ActiveChain().Tip()->GetMedianTimePast());)};
    if (sighash.isNull() && use_forkid_default) {
        sighash = UniValue{UniValue::VSTR, "ALL|FORKID"};
    }
    SignTransaction(mtx, &keystore, coins, sighash, result);
    return result;
},
    };
}

static RPCHelpMan signrawtransactionwithquantumkey()
{
    return RPCHelpMan{"signrawtransactionwithquantumkey",
                "\nSign Blackcoin ML-DSA witness inputs for a raw transaction.\n"
                "Keys are raw hex values returned by createquantumkey and are not loaded from or stored in the wallet.\n"
                "For Quantum Cold-Stake inputs, prefill the witness with [empty signature, empty pubkey,\n"
                "other_pubkey_hash, branch_selector] so the RPC can identify the owner or staker branch.\n"
                "The transaction can only be accepted by consensus once the scheduled quantum migration spend rules are active.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"quantumkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "ML-DSA keypairs to use for signing",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"public_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The ML-DSA-44 public key hex from createquantumkey"},
                                    {"private_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The ML-DSA-44 private key hex from createquantumkey"},
                                }},
                        }},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The previous transaction outputs this transaction depends on",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The output amount. Required because the ML-DSA signature commits to the spent output."},
                                }},
                        }},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with ML-DSA witness signatures"},
                        {RPCResult::Type::BOOL, "complete", "Whether all inputs were signed and verified by this RPC"},
                        {RPCResult::Type::BOOL, "quantum_spend_enforcement_active", "Whether the current chain tip is in the scheduled ML-DSA spend window"},
                        {RPCResult::Type::STR, "warning", /*optional=*/true, "Warning if the signed transaction is not yet relayable by schedule"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Signing or verification errors",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The previous transaction id"},
                                {RPCResult::Type::NUM, "vout", "The previous output index"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "The input sequence number"},
                                {RPCResult::Type::STR, "error", "The signing or verification error"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithquantumkey", "\"myhex\" '[{\"public_key\":\"pubhex\",\"private_key\":\"privhex\"}]'")
            + HelpExampleRpc("signrawtransactionwithquantumkey", "\"myhex\", [{\"public_key\":\"pubhex\",\"private_key\":\"privhex\"}]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    std::map<std::vector<unsigned char>, QuantumSigningKey> keys_by_program;
    const UniValue& keys = request.params[1].get_array();
    if (keys.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one ML-DSA keypair is required");
    }
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        if (!keys[idx].isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Each quantum key entry must be an object");
        }
        const UniValue& key_obj = keys[idx].get_obj();
        RPCTypeCheckObj(key_obj,
            {
                {"public_key", UniValueType(UniValue::VSTR)},
                {"private_key", UniValueType(UniValue::VSTR)},
            });

        const std::vector<unsigned char> public_key_bytes = ParseHexV(key_obj.find_value("public_key"), "public_key");
        std::vector<unsigned char> private_key_bytes = ParseHexV(key_obj.find_value("private_key"), "private_key");
        if (public_key_bytes.size() != ML_DSA::PUBLICKEY_BYTES) {
            CleanseVector(private_key_bytes);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("public_key must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
        }
        if (private_key_bytes.size() != ML_DSA::SECRETKEY_BYTES) {
            CleanseVector(private_key_bytes);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("private_key must be exactly %u bytes", ML_DSA::SECRETKEY_BYTES));
        }

        QuantumSigningKey key;
        key.public_key.assign(public_key_bytes.begin(), public_key_bytes.end());
        key.private_key.assign(private_key_bytes.begin(), private_key_bytes.end());
        CleanseVector(private_key_bytes);
        const std::vector<unsigned char> program = QuantumProgramForPubkey(key.public_key);
        if (!keys_by_program.emplace(program, std::move(key)).second) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate ML-DSA public key program");
        }
    }

    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout];
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    FindCoins(node, coins);
    ParsePrevouts(request.params[2], nullptr, coins);

    bool v4_active{false};
    bool quantum_spend_active{false};
    bool eutxo_spend_active{false};
    bool final_lockout_active{false};
    bool stake_tiers_active{false};
    {
        LOCK(::cs_main);
        if (const CBlockIndex* tip = chainman.ActiveChain().Tip()) {
            const int64_t tip_mtp = tip->GetMedianTimePast();
            const auto& consensus = chainman.GetConsensus();
            v4_active = consensus.IsProtocolV4(tip_mtp);
            quantum_spend_active = IsQuantumWitnessSpendActive(consensus, tip_mtp, tip->nHeight + 1);
            eutxo_spend_active = quantum_spend_active;
            final_lockout_active = consensus.IsQuantumFinalLockout(tip_mtp);
            stake_tiers_active = consensus.IsStakeTiersActive(tip->nHeight + 1);
        }
    }

    std::map<unsigned int, std::string> input_errors;
    std::vector<bool> quantum_inputs(mtx.vin.size(), false);
    std::vector<bool> quantum_coldstake_inputs(mtx.vin.size(), false);
    std::vector<bool> eutxo_inputs(mtx.vin.size(), false);
    bool spends_quantum_migration_output = false;

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        const auto coin_it = coins.find(mtx.vin[i].prevout);
        if (coin_it == coins.end() || coin_it->second.IsSpent()) {
            input_errors[i] = "Input not found or already spent";
            continue;
        }

        int witness_version{0};
        std::vector<unsigned char> witness_program;
        const bool is_witness_program = coin_it->second.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program);
        quantum_inputs[i] = is_witness_program &&
                            IsQuantumMigrationWitnessProgram(witness_version, witness_program);
        quantum_coldstake_inputs[i] = is_witness_program &&
                                      IsQuantumColdStakeWitnessProgram(witness_version, witness_program);
        eutxo_inputs[i] = IsEUTXOScript(coin_it->second.out.scriptPubKey);
        if (quantum_inputs[i] || quantum_coldstake_inputs[i]) {
            spends_quantum_migration_output = true;
            if (!quantum_spend_active) {
                input_errors[i] = "Quantum-protected spends are not active until the post-Gold-Rush migration window";
                continue;
            }
            mtx.vin[i].scriptSig.clear();
        } else if (eutxo_inputs[i]) {
            if (!eutxo_spend_active) {
                input_errors[i] = "EUTXO spends are not active until the post-Gold-Rush migration window";
            }
        } else if (final_lockout_active) {
            input_errors[i] = "Legacy spends are disabled after the Blackcoin migration deadline";
        }
    }

    if (spends_quantum_migration_output && input_errors.empty()) {
        for (unsigned int i = 0; i < mtx.vout.size(); ++i) {
            if (IsQuantumProtectedSpendAllowedOutput(CTransaction{mtx}, i)) {
                continue;
            }
            input_errors[0] = strprintf("Quantum-protected spends may only create quantum outputs (output %u)", i);
            break;
        }
    }

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(mtx.vin.size());
    for (const CTxIn& txin : mtx.vin) {
        const auto coin_it = coins.find(txin.prevout);
        spent_outputs.push_back(coin_it == coins.end() || coin_it->second.IsSpent() ? CTxOut{} : coin_it->second.out);
    }

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        if (input_errors.count(i)) continue;
        if (!quantum_inputs[i] && !quantum_coldstake_inputs[i]) continue;

        const Coin& coin = coins.at(mtx.vin[i].prevout);
        if (coin.out.nValue == MAX_MONEY) {
            input_errors[i] = "Missing amount";
            continue;
        }

        int witness_version{0};
        std::vector<unsigned char> witness_program;
        const bool is_quantum_migration = coin.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                                          IsQuantumMigrationWitnessProgram(witness_version, witness_program);
        const bool is_quantum_coldstake = coin.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                                          IsQuantumColdStakeWitnessProgram(witness_version, witness_program);
        if (!is_quantum_migration && !is_quantum_coldstake) {
            input_errors[i] = "Input is not a Blackcoin ML-DSA witness output";
            continue;
        }

        std::vector<unsigned char> signing_key_program;
        if (is_quantum_migration) {
            signing_key_program = QuantumSigningLookupProgram(witness_version, witness_program);
        } else {
            const auto& stack = mtx.vin[i].scriptWitness.stack;
            if (stack.size() != 4 || stack[2].size() != uint256::size() || !IsValidQuantumColdStakeSelector(stack[3])) {
                if (mtx.vin[i].scriptWitness.IsNull()) {
                    input_errors[i] = "Quantum cold-stake signing requires a witness template containing other_pubkey_hash and branch_selector";
                }
                continue;
            }
            uint256 other_pubkey_hash;
            std::copy(stack[2].begin(), stack[2].end(), other_pubkey_hash.begin());
            const bool staker_branch = IsQuantumColdStakeStakerBranch(stack[3]);
            for (const auto& [key_program, key] : keys_by_program) {
                if (key_program.size() != uint256::size()) continue;
                uint256 revealed_pubkey_hash;
                std::copy(key_program.begin(), key_program.end(), revealed_pubkey_hash.begin());
                const std::vector<unsigned char> expected_program = staker_branch
                    ? QuantumColdStakeProgramForKeyHashes(revealed_pubkey_hash, other_pubkey_hash)
                    : QuantumColdStakeProgramForKeyHashes(other_pubkey_hash, revealed_pubkey_hash);
                if (expected_program == witness_program) {
                    signing_key_program = key_program;
                    break;
                }
            }
        }

        const auto key_it = keys_by_program.find(signing_key_program);
        if (key_it == keys_by_program.end()) {
            if (mtx.vin[i].scriptWitness.IsNull() ||
                (is_quantum_coldstake && mtx.vin[i].scriptWitness.stack.size() == 4 &&
                 (mtx.vin[i].scriptWitness.stack[0].empty() || mtx.vin[i].scriptWitness.stack[1].empty()))) {
                input_errors[i] = is_quantum_coldstake
                    ? "No ML-DSA key matches this quantum cold-stake witness template"
                    : "No ML-DSA key matches this quantum witness program";
            }
            continue;
        }

        const CTransaction tx_to{mtx};
        const uint32_t quantum_chain_id = chainman.GetConsensus().nQuantumSighashChainId;
        const uint256 sighash = QuantumSignatureHash(tx_to, i, spent_outputs, quantum_chain_id);
        std::vector<uint8_t> signature;
        if (!ML_DSA::Sign(key_it->second.private_key, sighash.begin(), uint256::size(), signature)) {
            input_errors[i] = "ML-DSA signing failed";
            continue;
        }

        if (is_quantum_migration) {
            CScriptWitness witness;
            witness.stack.emplace_back(signature.begin(), signature.end());
            witness.stack.emplace_back(key_it->second.public_key.begin(), key_it->second.public_key.end());
            mtx.vin[i].scriptWitness = std::move(witness);
        } else {
            CScriptWitness witness = mtx.vin[i].scriptWitness;
            witness.stack[0].assign(signature.begin(), signature.end());
            witness.stack[1].assign(key_it->second.public_key.begin(), key_it->second.public_key.end());
            mtx.vin[i].scriptWitness = std::move(witness);
        }
    }

    const CTransaction tx_const{mtx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, std::move(spent_outputs), true);
    txdata.m_quantum_sighash_chain_id = chainman.GetConsensus().nQuantumSighashChainId;

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        if (input_errors.count(i)) continue;
        const Coin& coin = coins.at(mtx.vin[i].prevout);
        if (coin.out.nValue == MAX_MONEY && !mtx.vin[i].scriptWitness.IsNull()) {
            input_errors[i] = "Missing amount";
            continue;
        }
        ScriptError serror = SCRIPT_ERR_OK;
        unsigned int verify_flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (v4_active) {
            verify_flags |= SCRIPT_VERIFY_ISCOINSTAKE;
            verify_flags |= SCRIPT_VERIFY_STRICTENC;
        }
        if (final_lockout_active) {
            verify_flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
        }
        if (quantum_spend_active) {
            verify_flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
            verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
            verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
        }
        if (eutxo_spend_active) {
            verify_flags |= SCRIPT_VERIFY_EUTXO;
        }
        if (stake_tiers_active) {
            verify_flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
        }
        if (final_lockout_active) {
            verify_flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
        }
        if (!VerifyScript(mtx.vin[i].scriptSig, coin.out.scriptPubKey, &mtx.vin[i].scriptWitness, verify_flags,
                          TransactionSignatureChecker(&tx_const, i, coin.out.nValue, txdata, MissingDataBehavior::FAIL), &serror)) {
            input_errors[i] = ScriptErrorString(serror);
        }
    }

    if (final_lockout_active && input_errors.empty()) {
        for (unsigned int i = 0; i < mtx.vout.size(); ++i) {
            const CTxOut& txout = mtx.vout[i];
            if (txout.IsEmpty() || (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == OP_RETURN) ||
                IsQuantumProtectedScript(txout.scriptPubKey) || IsEUTXOScript(txout.scriptPubKey)) {
                continue;
            }
            input_errors[0] = strprintf("Legacy outputs are disabled after the Blackcoin migration deadline (output %u)", i);
            break;
        }
    }

    for (auto& [program, key] : keys_by_program) {
        CleanseVector(key.private_key);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", input_errors.empty());
    result.pushKV("quantum_spend_enforcement_active", quantum_spend_active);
    if (!quantum_spend_active) {
        result.pushKV("warning", "Transaction is signed, but scheduled ML-DSA spend enforcement is not active at the current chain tip.");
    }
    if (!input_errors.empty()) {
        UniValue errors(UniValue::VARR);
        for (const auto& [input_index, message] : input_errors) {
            if (input_index < mtx.vin.size()) {
                QuantumTxInErrorToJSON(mtx.vin.at(input_index), errors, message);
            } else {
                // Transaction-level error not tied to a specific input (e.g. a
                // disabled legacy output on a transaction with no inputs). Report
                // it without indexing vin, which would otherwise throw.
                UniValue tx_error(UniValue::VOBJ);
                tx_error.pushKV("error", message);
                errors.push_back(tx_error);
            }
        }
        result.pushKV("errors", errors);
    }
    return result;
},
    };
}

const RPCResult decodepsbt_inputs{
    RPCResult::Type::ARR, "inputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "non_witness_utxo", /*optional=*/true, "Decoded network transaction for non-witness UTXOs",
            {
                {RPCResult::Type::ELISION, "",""},
            }},
            {RPCResult::Type::OBJ, "witness_utxo", /*optional=*/true, "Transaction output for witness UTXOs",
            {
                {RPCResult::Type::NUM, "amount", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "partial_signatures", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "pubkey", "The public key and signature that corresponds to it."},
            }},
            {RPCResult::Type::STR, "sighash", /*optional=*/true, "The sighash type to be used"},
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key with the derivation path as the value."},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::OBJ, "final_scriptSig", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the final signature script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw final signature script bytes, hex-encoded"},
            }},
            {RPCResult::Type::ARR, "final_scriptwitness", /*optional=*/true, "",
            {
                {RPCResult::Type::STR_HEX, "", "hex-encoded witness data (if any)"},
            }},
            {RPCResult::Type::OBJ_DYN, "ripemd160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "sha256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::STR_HEX, "taproot_key_path_sig", /*optional=*/ true, "hex-encoded signature for the Taproot key path spend"},
            {RPCResult::Type::ARR, "taproot_script_path_sigs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "signature", /*optional=*/ true, "The signature for the pubkey and leaf hash combination",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only pubkey for this signature"},
                    {RPCResult::Type::STR, "leaf_hash", "The leaf hash for this signature"},
                    {RPCResult::Type::STR, "sig", "The signature itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_scripts", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "script", "A leaf script"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version number for the leaf script"},
                    {RPCResult::Type::ARR, "control_blocks", "The control blocks for this script",
                    {
                        {RPCResult::Type::STR_HEX, "control_block", "A hex-encoded control block for this script"},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::STR_HEX, "taproot_merkle_root", /*optional=*/ true, "The hex-encoded Taproot merkle root"},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/ true, "The unknown input fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The input proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

const RPCResult decodepsbt_outputs{
    RPCResult::Type::ARR, "outputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::ARR, "taproot_tree", /*optional=*/ true, "The tuples that make up the Taproot tree, in depth first search order",
            {
                {RPCResult::Type::OBJ, "tuple", /*optional=*/ true, "A single leaf script in the taproot tree",
                {
                    {RPCResult::Type::NUM, "depth", "The depth of this element in the tree"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version of this leaf"},
                    {RPCResult::Type::STR, "script", "The hex-encoded script itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/true, "The unknown output fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The output proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

static RPCHelpMan decodepsbt()
{
    return RPCHelpMan{
        "decodepsbt",
        "Return a JSON object representing the serialized, base64-encoded partially signed Blackcoin transaction.",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "tx", "The decoded network-serialized unsigned transaction.",
                        {
                            {RPCResult::Type::ELISION, "", "The layout is the same as the output of decoderawtransaction."},
                        }},
                        {RPCResult::Type::ARR, "global_xpubs", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "xpub", "The extended public key this path corresponds to"},
                                {RPCResult::Type::STR_HEX, "master_fingerprint", "The fingerprint of the master key"},
                                {RPCResult::Type::STR, "path", "The path"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "psbt_version", "The PSBT version number. Not to be confused with the unsigned transaction version"},
                        {RPCResult::Type::ARR, "proprietary", "The global proprietary map",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                                {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                                {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                                {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                            }},
                        }},
                        {RPCResult::Type::OBJ_DYN, "unknown", "The unknown global fields",
                        {
                             {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                        }},
                        decodepsbt_inputs,
                        decodepsbt_outputs,
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid if all UTXOs slots in the PSBT have been filled."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("decodepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    UniValue result(UniValue::VOBJ);

    // Add the decoded tx
    UniValue tx_univ(UniValue::VOBJ);
    TxToUniv(CTransaction(*psbtx.tx), /*block_hash=*/uint256(), /*entry=*/tx_univ, /*include_hex=*/false);
    result.pushKV("tx", tx_univ);

    // Add the global xpubs
    UniValue global_xpubs(UniValue::VARR);
    for (std::pair<KeyOriginInfo, std::set<CExtPubKey>> xpub_pair : psbtx.m_xpubs) {
        for (auto& xpub : xpub_pair.second) {
            std::vector<unsigned char> ser_xpub;
            ser_xpub.assign(BIP32_EXTKEY_WITH_VERSION_SIZE, 0);
            xpub.EncodeWithVersion(ser_xpub.data());

            UniValue keypath(UniValue::VOBJ);
            keypath.pushKV("xpub", EncodeBase58Check(ser_xpub));
            keypath.pushKV("master_fingerprint", HexStr(Span<unsigned char>(xpub_pair.first.fingerprint, xpub_pair.first.fingerprint + 4)));
            keypath.pushKV("path", WriteHDKeypath(xpub_pair.first.path));
            global_xpubs.push_back(keypath);
        }
    }
    result.pushKV("global_xpubs", global_xpubs);

    // PSBT version
    result.pushKV("psbt_version", static_cast<uint64_t>(psbtx.GetVersion()));

    // Proprietary
    UniValue proprietary(UniValue::VARR);
    for (const auto& entry : psbtx.m_proprietary) {
        UniValue this_prop(UniValue::VOBJ);
        this_prop.pushKV("identifier", HexStr(entry.identifier));
        this_prop.pushKV("subtype", entry.subtype);
        this_prop.pushKV("key", HexStr(entry.key));
        this_prop.pushKV("value", HexStr(entry.value));
        proprietary.push_back(this_prop);
    }
    result.pushKV("proprietary", proprietary);

    // Unknown data
    UniValue unknowns(UniValue::VOBJ);
    for (auto entry : psbtx.unknown) {
        unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
    }
    result.pushKV("unknown", unknowns);

    // inputs
    CAmount total_in = 0;
    bool have_all_utxos = true;
    UniValue inputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const PSBTInput& input = psbtx.inputs[i];
        UniValue in(UniValue::VOBJ);
        // UTXOs
        bool have_a_utxo = false;
        CTxOut txout;
        if (!input.witness_utxo.IsNull()) {
            txout = input.witness_utxo;

            UniValue o(UniValue::VOBJ);
            ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);

            UniValue out(UniValue::VOBJ);
            out.pushKV("amount", ValueFromAmount(txout.nValue));
            out.pushKV("scriptPubKey", o);

            in.pushKV("witness_utxo", out);

            have_a_utxo = true;
        }
        if (input.non_witness_utxo) {
            txout = input.non_witness_utxo->vout[psbtx.tx->vin[i].prevout.n];

            UniValue non_wit(UniValue::VOBJ);
            TxToUniv(*input.non_witness_utxo, /*block_hash=*/uint256(), /*entry=*/non_wit, /*include_hex=*/false);
            in.pushKV("non_witness_utxo", non_wit);

            have_a_utxo = true;
        }
        if (have_a_utxo) {
            if (MoneyRange(txout.nValue) && MoneyRange(total_in + txout.nValue)) {
                total_in += txout.nValue;
            } else {
                // Hack to just not show fee later
                have_all_utxos = false;
            }
        } else {
            have_all_utxos = false;
        }

        // Partial sigs
        if (!input.partial_sigs.empty()) {
            UniValue partial_sigs(UniValue::VOBJ);
            for (const auto& sig : input.partial_sigs) {
                partial_sigs.pushKV(HexStr(sig.second.first), HexStr(sig.second.second));
            }
            in.pushKV("partial_signatures", partial_sigs);
        }

        // Sighash
        if (input.sighash_type != std::nullopt) {
            in.pushKV("sighash", SighashToStr((unsigned char)*input.sighash_type));
        }

        // Redeem script and witness script
        if (!input.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.redeem_script, /*out=*/r);
            in.pushKV("redeem_script", r);
        }
        if (!input.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.witness_script, /*out=*/r);
            in.pushKV("witness_script", r);
        }

        // keypaths
        if (!input.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : input.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));

                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(keypath);
            }
            in.pushKV("bip32_derivs", keypaths);
        }

        // Final scriptSig and scriptwitness
        if (!input.final_script_sig.empty()) {
            UniValue scriptsig(UniValue::VOBJ);
            scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true));
            scriptsig.pushKV("hex", HexStr(input.final_script_sig));
            in.pushKV("final_scriptSig", scriptsig);
        }
        if (!input.final_script_witness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : input.final_script_witness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("final_scriptwitness", txinwitness);
        }

        // Ripemd160 hash preimages
        if (!input.ripemd160_preimages.empty()) {
            UniValue ripemd160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.ripemd160_preimages) {
                ripemd160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("ripemd160_preimages", ripemd160_preimages);
        }

        // Sha256 hash preimages
        if (!input.sha256_preimages.empty()) {
            UniValue sha256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.sha256_preimages) {
                sha256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("sha256_preimages", sha256_preimages);
        }

        // Hash160 hash preimages
        if (!input.hash160_preimages.empty()) {
            UniValue hash160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash160_preimages) {
                hash160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash160_preimages", hash160_preimages);
        }

        // Hash256 hash preimages
        if (!input.hash256_preimages.empty()) {
            UniValue hash256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash256_preimages) {
                hash256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash256_preimages", hash256_preimages);
        }

        // Taproot key path signature
        if (!input.m_tap_key_sig.empty()) {
            in.pushKV("taproot_key_path_sig", HexStr(input.m_tap_key_sig));
        }

        // Taproot script path signatures
        if (!input.m_tap_script_sigs.empty()) {
            UniValue script_sigs(UniValue::VARR);
            for (const auto& [pubkey_leaf, sig] : input.m_tap_script_sigs) {
                const auto& [xonly, leaf_hash] = pubkey_leaf;
                UniValue sigobj(UniValue::VOBJ);
                sigobj.pushKV("pubkey", HexStr(xonly));
                sigobj.pushKV("leaf_hash", HexStr(leaf_hash));
                sigobj.pushKV("sig", HexStr(sig));
                script_sigs.push_back(sigobj);
            }
            in.pushKV("taproot_script_path_sigs", script_sigs);
        }

        // Taproot leaf scripts
        if (!input.m_tap_scripts.empty()) {
            UniValue tap_scripts(UniValue::VARR);
            for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
                const auto& [script, leaf_ver] = leaf;
                UniValue script_info(UniValue::VOBJ);
                script_info.pushKV("script", HexStr(script));
                script_info.pushKV("leaf_ver", leaf_ver);
                UniValue control_blocks_univ(UniValue::VARR);
                for (const auto& control_block : control_blocks) {
                    control_blocks_univ.push_back(HexStr(control_block));
                }
                script_info.pushKV("control_blocks", control_blocks_univ);
                tap_scripts.push_back(script_info);
            }
            in.pushKV("taproot_scripts", tap_scripts);
        }

        // Taproot bip32 keypaths
        if (!input.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", leaf_hashes_arr);
                keypaths.push_back(path_obj);
            }
            in.pushKV("taproot_bip32_derivs", keypaths);
        }

        // Taproot internal key
        if (!input.m_tap_internal_key.IsNull()) {
            in.pushKV("taproot_internal_key", HexStr(input.m_tap_internal_key));
        }

        // Write taproot merkle root
        if (!input.m_tap_merkle_root.IsNull()) {
            in.pushKV("taproot_merkle_root", HexStr(input.m_tap_merkle_root));
        }

        // Proprietary
        if (!input.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : input.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(this_prop);
            }
            in.pushKV("proprietary", proprietary);
        }

        // Unknown data
        if (input.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : input.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            in.pushKV("unknown", unknowns);
        }

        inputs.push_back(in);
    }
    result.pushKV("inputs", inputs);

    // outputs
    CAmount output_value = 0;
    UniValue outputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        const PSBTOutput& output = psbtx.outputs[i];
        UniValue out(UniValue::VOBJ);
        // Redeem script and witness script
        if (!output.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.redeem_script, /*out=*/r);
            out.pushKV("redeem_script", r);
        }
        if (!output.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.witness_script, /*out=*/r);
            out.pushKV("witness_script", r);
        }

        // keypaths
        if (!output.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : output.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));
                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(keypath);
            }
            out.pushKV("bip32_derivs", keypaths);
        }

        // Taproot internal key
        if (!output.m_tap_internal_key.IsNull()) {
            out.pushKV("taproot_internal_key", HexStr(output.m_tap_internal_key));
        }

        // Taproot tree
        if (!output.m_tap_tree.empty()) {
            UniValue tree(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : output.m_tap_tree) {
                UniValue elem(UniValue::VOBJ);
                elem.pushKV("depth", (int)depth);
                elem.pushKV("leaf_ver", (int)leaf_ver);
                elem.pushKV("script", HexStr(script));
                tree.push_back(elem);
            }
            out.pushKV("taproot_tree", tree);
        }

        // Taproot bip32 keypaths
        if (!output.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : output.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", leaf_hashes_arr);
                keypaths.push_back(path_obj);
            }
            out.pushKV("taproot_bip32_derivs", keypaths);
        }

        // Proprietary
        if (!output.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : output.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(this_prop);
            }
            out.pushKV("proprietary", proprietary);
        }

        // Unknown data
        if (output.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : output.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            out.pushKV("unknown", unknowns);
        }

        outputs.push_back(out);

        // Fee calculation
        if (MoneyRange(psbtx.tx->vout[i].nValue) && MoneyRange(output_value + psbtx.tx->vout[i].nValue)) {
            output_value += psbtx.tx->vout[i].nValue;
        } else {
            // Hack to just not show fee later
            have_all_utxos = false;
        }
    }
    result.pushKV("outputs", outputs);
    if (have_all_utxos) {
        result.pushKV("fee", ValueFromAmount(total_in - output_value));
    }

    return result;
},
    };
}

static RPCHelpMan combinepsbt()
{
    return RPCHelpMan{"combinepsbt",
                "\nCombine multiple partially signed Blackcoin transactions into one transaction.\n"
                "Implements the Combiner role.\n",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                        {
                            {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A base64 string of a PSBT"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
                },
                RPCExamples{
                    HelpExampleCli("combinepsbt", R"('["mybase64_1", "mybase64_2", "mybase64_3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();
    if (txs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txs' cannot be empty");
    }
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
    }

    PartiallySignedTransaction merged_psbt;
    const TransactionError error = CombinePSBTs(merged_psbt, psbtxs);
    if (error != TransactionError::OK) {
        throw JSONRPCTransactionError(error);
    }

    CDataStream ssTx(SER_NETWORK);
    ssTx << merged_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan finalizepsbt()
{
    return RPCHelpMan{"finalizepsbt",
                "Finalize the inputs of a PSBT. If the transaction is fully signed, it will produce a\n"
                "network serialized transaction which can be broadcast with sendrawtransaction. Otherwise a PSBT will be\n"
                "created which has the final_scriptSig and final_scriptWitness fields filled for inputs that are complete.\n"
                "Implements the Finalizer and Extractor roles.\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                    {"extract", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true and the transaction is complete,\n"
            "                             extract and return the complete transaction in normal network serialization instead of the PSBT."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", /*optional=*/true, "The base64-encoded partially signed transaction if not extracted"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if extracted"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("finalizepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    bool extract = request.params[1].isNull() || (!request.params[1].isNull() && request.params[1].get_bool());

    CMutableTransaction mtx;
    bool complete = FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);
    CDataStream ssTx(SER_NETWORK);
    std::string result_str;

    if (complete && extract) {
        ssTx << TX_WITH_WITNESS(mtx);
        result_str = HexStr(ssTx);
        result.pushKV("hex", result_str);
    } else {
        ssTx << psbtx;
        result_str = EncodeBase64(ssTx.str());
        result.pushKV("psbt", result_str);
    }
    result.pushKV("complete", complete);

    return result;
},
    };
}

static RPCHelpMan createpsbt()
{
    return RPCHelpMan{"createpsbt",
                "\nCreates a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator role.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                    HelpExampleCli("createpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], request.params[3]);

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = rawTx;
    for (unsigned int i = 0; i < rawTx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < rawTx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan converttopsbt()
{
    return RPCHelpMan{"converttopsbt",
                "\nConverts a network serialized transaction to a PSBT. This should be used only with createrawtransaction and fundrawtransaction\n"
                "createpsbt and walletcreatefundedpsbt should be used for new applications.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of a raw transaction"},
                    {"permitsigdata", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, any signatures in the input will be discarded and conversion\n"
                            "                              will continue. If false, RPC will fail if any signatures are present."},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                            "\nCreate a transaction\n"
                            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"") +
                            "\nConvert the transaction to a PSBT\n"
                            + HelpExampleCli("converttopsbt", "\"rawtransaction\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // parse hex string from parameter
    CMutableTransaction tx;
    bool permitsigdata = request.params[1].isNull() ? false : request.params[1].get_bool();
    bool witness_specified = !request.params[2].isNull();
    bool iswitness = witness_specified ? request.params[2].get_bool() : false;
    const bool try_witness = witness_specified ? iswitness : true;
    const bool try_no_witness = witness_specified ? !iswitness : true;
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Remove all scriptSigs and scriptWitnesses from inputs
    for (CTxIn& input : tx.vin) {
        if ((!input.scriptSig.empty() || !input.scriptWitness.IsNull()) && !permitsigdata) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Inputs must not have scriptSigs and scriptWitnesses");
        }
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan utxoupdatepsbt()
{
    return RPCHelpMan{"utxoupdatepsbt",
            "\nUpdates all segwit inputs and outputs in a PSBT with data from output descriptors, the UTXO set, txindex, or the mempool.\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of either strings or objects", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                         {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                         {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                    }},
                }},
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction with inputs updated"
            },
            RPCExamples {
                HelpExampleCli("utxoupdatepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Parse descriptors, if any.
    FlatSigningProvider provider;
    if (!request.params[1].isNull()) {
        auto descs = request.params[1].get_array();
        for (size_t i = 0; i < descs.size(); ++i) {
            EvalDescriptorStringOrObject(descs[i], provider);
        }
    }

    // We don't actually need private keys further on; hide them as a precaution.
    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/true, /*hide_origin=*/false),
        /*sighash_type=*/SIGHASH_ALL,
        /*finalize=*/false);

    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan joinpsbts()
{
    return RPCHelpMan{"joinpsbts",
            "\nJoins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs\n"
            "No input in any of the PSBTs can be in more than one of the PSBTs.\n",
            {
                {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                    {
                        {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
                    }}
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
            },
            RPCExamples {
                HelpExampleCli("joinpsbts", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();

    if (txs.size() <= 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least two PSBTs are required to join PSBTs.");
    }

    uint32_t best_version = 1;
    uint32_t best_locktime = 0xffffffff;
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
        // Choose the highest version number
        if (static_cast<uint32_t>(psbtx.tx->nVersion) > best_version) {
            best_version = static_cast<uint32_t>(psbtx.tx->nVersion);
        }
        // Choose the lowest lock time
        if (psbtx.tx->nLockTime < best_locktime) {
            best_locktime = psbtx.tx->nLockTime;
        }
    }

    // Create a blank psbt where everything will be added
    PartiallySignedTransaction merged_psbt;
    merged_psbt.tx = CMutableTransaction();
    merged_psbt.tx->nVersion = static_cast<int32_t>(best_version);
    merged_psbt.tx->nLockTime = best_locktime;

    // Merge
    for (auto& psbt : psbtxs) {
        for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
            if (!merged_psbt.AddInput(psbt.tx->vin[i], psbt.inputs[i])) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input %s:%d exists in multiple PSBTs", psbt.tx->vin[i].prevout.hash.ToString(), psbt.tx->vin[i].prevout.n));
            }
        }
        for (unsigned int i = 0; i < psbt.tx->vout.size(); ++i) {
            merged_psbt.AddOutput(psbt.tx->vout[i], psbt.outputs[i]);
        }
        for (auto& xpub_pair : psbt.m_xpubs) {
            if (merged_psbt.m_xpubs.count(xpub_pair.first) == 0) {
                merged_psbt.m_xpubs[xpub_pair.first] = xpub_pair.second;
            } else {
                merged_psbt.m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
            }
        }
        merged_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
    }

    // Generate list of shuffled indices for shuffling inputs and outputs of the merged PSBT
    std::vector<int> input_indices(merged_psbt.inputs.size());
    std::iota(input_indices.begin(), input_indices.end(), 0);
    std::vector<int> output_indices(merged_psbt.outputs.size());
    std::iota(output_indices.begin(), output_indices.end(), 0);

    // Shuffle input and output indices lists
    Shuffle(input_indices.begin(), input_indices.end(), FastRandomContext());
    Shuffle(output_indices.begin(), output_indices.end(), FastRandomContext());

    PartiallySignedTransaction shuffled_psbt;
    shuffled_psbt.tx = CMutableTransaction();
    shuffled_psbt.tx->nVersion = merged_psbt.tx->nVersion;
    shuffled_psbt.tx->nLockTime = merged_psbt.tx->nLockTime;
    for (int i : input_indices) {
        shuffled_psbt.AddInput(merged_psbt.tx->vin[i], merged_psbt.inputs[i]);
    }
    for (int i : output_indices) {
        shuffled_psbt.AddOutput(merged_psbt.tx->vout[i], merged_psbt.outputs[i]);
    }
    shuffled_psbt.unknown.insert(merged_psbt.unknown.begin(), merged_psbt.unknown.end());

    CDataStream ssTx(SER_NETWORK);
    ssTx << shuffled_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan analyzepsbt()
{
    return RPCHelpMan{"analyzepsbt",
            "\nAnalyzes and provides information about the current status of a PSBT and its inputs\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
            },
            RPCResult {
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ARR, "inputs", /*optional=*/true, "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "has_utxo", "Whether a UTXO is provided"},
                            {RPCResult::Type::BOOL, "is_final", "Whether the input is finalized"},
                            {RPCResult::Type::OBJ, "missing", /*optional=*/true, "Things that are missing that are required to complete this input",
                            {
                                {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose BIP 32 derivation path is missing"},
                                }},
                                {RPCResult::Type::ARR, "signatures", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose signature is missing"},
                                }},
                                {RPCResult::Type::STR_HEX, "redeemscript", /*optional=*/true, "Hash160 of the redeemScript that is missing"},
                                {RPCResult::Type::STR_HEX, "witnessscript", /*optional=*/true, "SHA256 of the witnessScript that is missing"},
                            }},
                            {RPCResult::Type::STR, "next", /*optional=*/true, "Role of the next person that this input needs to go to"},
                        }},
                    }},
                    {RPCResult::Type::NUM, "estimated_vsize", /*optional=*/true, "Estimated vsize of the final signed transaction"},
                    {RPCResult::Type::STR_AMOUNT, "estimated_feerate", /*optional=*/true, "Estimated feerate of the final signed transaction in " + CURRENCY_UNIT + "/kvB. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR, "next", "Role of the next person that this psbt needs to go to"},
                    {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"},
                }
            },
            RPCExamples {
                HelpExampleCli("analyzepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    PSBTAnalysis psbta = AnalyzePSBT(psbtx);

    UniValue result(UniValue::VOBJ);
    UniValue inputs_result(UniValue::VARR);
    for (const auto& input : psbta.inputs) {
        UniValue input_univ(UniValue::VOBJ);
        UniValue missing(UniValue::VOBJ);

        input_univ.pushKV("has_utxo", input.has_utxo);
        input_univ.pushKV("is_final", input.is_final);
        input_univ.pushKV("next", PSBTRoleName(input.next));

        if (!input.missing_pubkeys.empty()) {
            UniValue missing_pubkeys_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_pubkeys) {
                missing_pubkeys_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("pubkeys", missing_pubkeys_univ);
        }
        if (!input.missing_redeem_script.IsNull()) {
            missing.pushKV("redeemscript", HexStr(input.missing_redeem_script));
        }
        if (!input.missing_witness_script.IsNull()) {
            missing.pushKV("witnessscript", HexStr(input.missing_witness_script));
        }
        if (!input.missing_sigs.empty()) {
            UniValue missing_sigs_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_sigs) {
                missing_sigs_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("signatures", missing_sigs_univ);
        }
        if (!missing.getKeys().empty()) {
            input_univ.pushKV("missing", missing);
        }
        inputs_result.push_back(input_univ);
    }
    if (!inputs_result.empty()) result.pushKV("inputs", inputs_result);

    if (psbta.estimated_vsize != std::nullopt) {
        result.pushKV("estimated_vsize", (int)*psbta.estimated_vsize);
    }
    if (psbta.estimated_feerate != std::nullopt) {
        result.pushKV("estimated_feerate", ValueFromAmount(psbta.estimated_feerate->GetFeePerK()));
    }
    if (psbta.fee != std::nullopt) {
        result.pushKV("fee", ValueFromAmount(*psbta.fee));
    }
    result.pushKV("next", PSBTRoleName(psbta.next));
    if (!psbta.error.empty()) {
        result.pushKV("error", psbta.error);
    }

    return result;
},
    };
}

RPCHelpMan descriptorprocesspsbt()
{
    return RPCHelpMan{"descriptorprocesspsbt",
                "\nUpdate all segwit inputs in a PSBT with information from output descriptors, the UTXO set or the mempool. \n"
                "Then, sign the inputs we are able to with information from the output descriptors. ",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of either strings or objects", {
                        {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                             {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                             {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                        }},
                    }},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"ALL|FORKID\"\n"
            "       \"NONE\"\n"
            "       \"NONE|FORKID\"\n"
            "       \"SINGLE\"\n"
            "       \"SINGLE|FORKID\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"ALL|FORKID|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"NONE|FORKID|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
            "       \"SINGLE|FORKID|ANYONECANPAY\""},
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
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[\\\"descriptor1\\\", \\\"descriptor2\\\"]\"") +
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[{\\\"desc\\\":\\\"mydescriptor\\\", \\\"range\\\":21}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Add descriptor information to a signing provider
    FlatSigningProvider provider;

    auto descs = request.params[1].get_array();
    for (size_t i = 0; i < descs.size(); ++i) {
        EvalDescriptorStringOrObject(descs[i], provider, /*expand_priv=*/true);
    }

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    UniValue sighash{request.params[2]};
    const bool use_forkid_default{WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip() && chainman.GetConsensus().IsNewNetworkStakeOnly(chainman.ActiveChain().Tip()->GetMedianTimePast());)};
    if (sighash.isNull() && use_forkid_default) {
        sighash = UniValue{UniValue::VSTR, "ALL|FORKID"};
    }
    int sighash_type = ParseSighashString(sighash);
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool finalize = request.params[4].isNull() ? true : request.params[4].get_bool();

    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/false, !bip32derivs),
        sighash_type,
        finalize);

    // Check whether or not all of the inputs are now signed
    bool complete = true;
    for (const auto& input : psbtx.inputs) {
        complete &= PSBTInputSigned(input);
    }

    CDataStream ssTx(SER_NETWORK);
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);

    result.pushKV("psbt", EncodeBase64(ssTx));
    result.pushKV("complete", complete);
    if (complete) {
        CMutableTransaction mtx;
        PartiallySignedTransaction psbtx_copy = psbtx;
        CHECK_NONFATAL(FinalizeAndExtractPSBT(psbtx_copy, mtx));
        DataStream ssTx_final;
        ssTx_final << TX_WITH_WITNESS(mtx);
        result.pushKV("hex", HexStr(ssTx_final));
    }
    return result;
},
    };
}

static RPCHelpMan verifyeutxospend()
{
    return RPCHelpMan{"verifyeutxospend",
        "Authoritatively decode EUTXO (witness-v15) spends in a transaction by resolving each\n"
        "input's prevout from the UTXO set and mempool. Unlike decodeeutxospend, this only\n"
        "reports inputs whose prevout is a real EUTXO commitment, and verifies that the witness\n"
        "[datum, redeemer, validator] reproduces the committed 32-byte program.\n",
        {
            {"tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Transaction hex, or a txid known to the node (raw mempool/index or confirmed)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validity", "\"enforced\" if SCRIPT_VERIFY_EUTXO is active at the tip, else \"premature\""},
                {RPCResult::Type::ARR, "spends", "Confirmed EUTXO spends in this transaction",
                 {
                     {RPCResult::Type::OBJ, "", "",
                      {
                          {RPCResult::Type::NUM, "vin", "Input index"},
                          {RPCResult::Type::STR_HEX, "prevout_txid", "Spent commitment txid"},
                          {RPCResult::Type::NUM, "prevout_vout", "Spent commitment vout"},
                          {RPCResult::Type::STR_AMOUNT, "value", "Spent output amount"},
                          {RPCResult::Type::BOOL, "in_mempool", "Prevout sourced from mempool (unconfirmed)"},
                          {RPCResult::Type::STR_HEX, "committed_program", "The 32-byte program in the prevout scriptPubKey"},
                          {RPCResult::Type::STR_HEX, "datum", "Datum from the witness"},
                          {RPCResult::Type::STR_HEX, "redeemer", "Redeemer from the witness"},
                          {RPCResult::Type::STR_HEX, "validator", "Validator script from the witness"},
                          {RPCResult::Type::BOOL, "commitment_ok", "True iff recomputed program == committed program"},
                          {RPCResult::Type::BOOL, "script_valid", "True iff the EUTXO validator script succeeds under the node's current flags"},
                          {RPCResult::Type::STR, "script_error", "Script validation result"},
                          {RPCResult::Type::STR, "transition_status", "\"none\", \"valid\", \"malformed\", or \"invalid\" for structured EUTXO state transitions"},
                          {RPCResult::Type::BOOL, "transition_valid", "True iff no structured transition is present, or the structured transition satisfies consensus checks"},
                          {RPCResult::Type::STR, "transition_error", "Structured transition validation result"},
                      }},
                 }},
            }},
        RPCExamples{HelpExampleCli("verifyeutxospend", "\"<txhex-or-txid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    CMutableTransaction mtx;
    const std::string& s = request.params[0].get_str();
    CTransactionRef txref;
    if (DecodeHexTx(mtx, s, true, true)) {
        txref = MakeTransactionRef(CMutableTransaction(mtx));
    } else if (s.size() == 64 && IsHex(s)) {
        const uint256 hash(ParseHashV(request.params[0], "tx"));
        uint256 hashBlock;
        txref = GetTransaction(/*block_index=*/nullptr, node.mempool.get(), hash,
                               hashBlock, chainman.m_blockman);
        if (!txref) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found");
    } else {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Argument is neither tx hex nor a txid");
    }
    const CTransaction& tx = *txref;

    bool v4_active{false};
    bool enforced{false};
    bool final_lockout_active{false};
    bool new_network_stake_only{false};
    bool stake_tiers_active{false};
    {
        LOCK(::cs_main);
        if (const CBlockIndex* tip = chainman.ActiveChain().Tip()) {
            const int64_t tip_mtp = tip->GetMedianTimePast();
            const auto& consensus = chainman.GetConsensus();
            v4_active = consensus.IsProtocolV4(tip_mtp);
            enforced = IsQuantumWitnessSpendActive(consensus, tip_mtp, tip->nHeight + 1);
            final_lockout_active = consensus.IsQuantumFinalLockout(tip_mtp);
            new_network_stake_only = consensus.IsNewNetworkStakeOnly(tip_mtp);
            stake_tiers_active = consensus.IsStakeTiersActive(tip->nHeight + 1);
        }
    }

    std::map<COutPoint, Coin> coins;
    for (const CTxIn& in : tx.vin) coins[in.prevout];
    FindCoins(node, coins);

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(tx.vin.size());
    for (const CTxIn& in : tx.vin) {
        const auto coin_it = coins.find(in.prevout);
        spent_outputs.push_back(coin_it == coins.end() || coin_it->second.IsSpent() ? CTxOut{} : coin_it->second.out);
    }
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);
    txdata.m_quantum_sighash_chain_id = chainman.GetConsensus().nQuantumSighashChainId;

    unsigned int verify_flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (v4_active) {
        verify_flags |= SCRIPT_VERIFY_ISCOINSTAKE;
        verify_flags |= SCRIPT_VERIFY_STRICTENC;
    }
    if (new_network_stake_only) {
        verify_flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
    }
    if (enforced) {
        verify_flags |= SCRIPT_VERIFY_V4_LARGE_SCRIPT_ELEMENT;
        verify_flags |= SCRIPT_VERIFY_EUTXO;
        verify_flags |= SCRIPT_VERIFY_QUANTUM_ML_DSA;
        verify_flags |= SCRIPT_VERIFY_QUANTUM_COLDSTAKE;
    }
    if (stake_tiers_active) {
        verify_flags |= SCRIPT_VERIFY_QUANTUM_STAKE_TIERS;
    }
    if (final_lockout_active) {
        verify_flags |= SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT;
    }

    UniValue spends(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const auto it = coins.find(tx.vin[i].prevout);
        if (it == coins.end() || it->second.IsSpent()) continue;
        const CTxOut& prevout = it->second.out;

        int witver{0};
        std::vector<unsigned char> witprog;
        if (!prevout.scriptPubKey.IsWitnessProgram(witver, witprog)) continue;
        if (!IsEUTXOWitnessProgram(witver, witprog)) continue;

        const auto& stack = tx.vin[i].scriptWitness.stack;
        if (stack.size() < 3) continue;
        const std::vector<unsigned char>& validator = stack[stack.size() - 1];
        const std::vector<unsigned char>& redeemer  = stack[stack.size() - 2];
        const std::vector<unsigned char>& datum     = stack[stack.size() - 3];

        const CScript validator_script(validator.begin(), validator.end());
        const std::vector<unsigned char> recomputed =
            EUTXOProgramForDatumAndValidator(datum, validator_script);
        const bool ok = recomputed.size() == witprog.size() &&
                        std::equal(recomputed.begin(), recomputed.end(), witprog.begin());
        ScriptError serror = SCRIPT_ERR_OK;
        const bool script_valid = VerifyScript(tx.vin[i].scriptSig, prevout.scriptPubKey,
                                               &tx.vin[i].scriptWitness, verify_flags,
                                               TransactionSignatureChecker(&tx, i, prevout.nValue, txdata, MissingDataBehavior::FAIL),
                                               &serror);
        eutxo::StateTransition transition;
        std::string transition_error;
        std::string transition_status{"none"};
        bool transition_valid{true};
        const eutxo::DecodeStateTransitionResult transition_decode =
            eutxo::DecodeStateTransition(redeemer, transition, transition_error);
        if (transition_decode == eutxo::DecodeStateTransitionResult::MALFORMED) {
            transition_status = "malformed";
            transition_valid = false;
        } else if (transition_decode == eutxo::DecodeStateTransitionResult::OK) {
            transition_valid = eutxo::CheckStateTransition(tx, i, prevout, transition, transition_error);
            transition_status = transition_valid ? "valid" : "invalid";
        }

        UniValue o(UniValue::VOBJ);
        o.pushKV("vin", (int)i);
        o.pushKV("prevout_txid", tx.vin[i].prevout.hash.GetHex());
        o.pushKV("prevout_vout", (int)tx.vin[i].prevout.n);
        o.pushKV("value", ValueFromAmount(prevout.nValue));
        o.pushKV("in_mempool", it->second.nHeight == MEMPOOL_HEIGHT);
        o.pushKV("committed_program", HexStr(witprog));
        o.pushKV("datum", HexStr(datum));
        o.pushKV("redeemer", HexStr(redeemer));
        o.pushKV("validator", HexStr(validator));
        o.pushKV("commitment_ok", ok);
        o.pushKV("script_valid", script_valid);
        o.pushKV("script_error", ScriptErrorString(serror));
        o.pushKV("transition_status", transition_status);
        o.pushKV("transition_valid", transition_valid);
        o.pushKV("transition_error", transition_error);
        spends.push_back(o);
    }

    UniValue r(UniValue::VOBJ);
    r.pushKV("validity", enforced ? "enforced" : "premature");
    r.pushKV("spends", spends);
    return r;
},
    };
}

static RPCHelpMan createeutxospend()
{
    return RPCHelpMan{"createeutxospend",
        "Build an unsigned transaction that spends a Blackcoin EUTXO (witness-v15)\n"
        "commitment output. The commitment input's witness is fully populated as\n"
        "[datum, redeemer, validator]; the surrounding transaction is NOT funded or signed.\n"
        "Fund it with fundrawtransaction and sign any added inputs with\n"
        "signrawtransactionwithwallet. The EUTXO input itself needs no signature unless the\n"
        "validator script requires one inside the redeemer.\n",
        {
            {"eutxo_commitment", RPCArg::Type::OBJ, RPCArg::Optional::NO,
             "The EUTXO commitment output being spent",
             {
                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The commitment txid"},
                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The commitment output index"},
                 {"datum", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex datum committed by the output"},
                 {"validator", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex validator script committed by the output"},
                 {"redeemer", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex redeemer satisfying the validator"},
                 {"sequence", RPCArg::Type::NUM, RPCArg::Default{(int64_t)0xffffffff}, "Sequence number for the input"},
             }},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO,
             "Outputs (same schema as createrawtransaction outputs)",
             {
                 {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "", {{"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}}},
             }},
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Unsigned transaction hex, EUTXO input witness populated"},
                {RPCResult::Type::STR_HEX, "expected_program", "The 32-byte program recomputed from datum+validator"},
                {RPCResult::Type::STR, "address", "The expected eutxo_commitment address of the spent output"},
            }},
        RPCExamples{
            HelpExampleCli("createeutxospend",
                "'{\"txid\":\"...\",\"vout\":0,\"datum\":\"01\",\"validator\":\"51\",\"redeemer\":\"\"}' '[{\"bcrt1...\":0.5}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& c = request.params[0].get_obj();
    RPCTypeCheckObj(c, {
        {"txid", UniValueType(UniValue::VSTR)},
        {"vout", UniValueType(UniValue::VNUM)},
        {"datum", UniValueType(UniValue::VSTR)},
        {"validator", UniValueType(UniValue::VSTR)},
        {"redeemer", UniValueType(UniValue::VSTR)},
    });

    const uint256 txid = ParseHashO(c, "txid");
    const int vout = c.find_value("vout").getInt<int>();
    if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be positive");

    // datum/redeemer may legitimately be empty (e.g. an OP_TRUE validator needs no redeemer),
    // so accept "" as an empty push rather than rejecting it like ParseHexO would.
    const std::vector<unsigned char> datum     = ParseHexOAllowEmpty(c, "datum");
    const std::vector<unsigned char> validator = ParseHexOAllowEmpty(c, "validator");
    const std::vector<unsigned char> redeemer  = ParseHexOAllowEmpty(c, "redeemer");

    if (datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        validator.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        redeemer.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "datum/redeemer/validator exceed 4096 bytes");
    }

    const CScript validator_script(validator.begin(), validator.end());
    const std::vector<unsigned char> program = EUTXOProgramForDatumAndValidator(datum, validator_script);

    CMutableTransaction rawTx = ConstructTransaction(UniValue(UniValue::VARR), request.params[1], request.params[2]);

    CTxIn in(COutPoint(Txid::FromUint256(txid), (uint32_t)vout));
    if (!c.find_value("sequence").isNull()) {
        const int64_t seq = c.find_value("sequence").getInt<int64_t>();
        if (seq < 0 || seq > CTxIn::SEQUENCE_FINAL) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sequence");
        in.nSequence = (uint32_t)seq;
    }
    in.scriptWitness.stack.push_back(datum);
    in.scriptWitness.stack.push_back(redeemer);
    in.scriptWitness.stack.push_back(std::vector<unsigned char>(validator.begin(), validator.end()));
    rawTx.vin.insert(rawTx.vin.begin(), in);

    const CScript expected_spk = GetScriptForEUTXO(datum, validator_script);

    UniValue out(UniValue::VOBJ);
    out.pushKV("hex", EncodeHexTx(CTransaction(rawTx)));
    out.pushKV("expected_program", HexStr(program));
    CTxDestination dest;
    if (ExtractDestination(expected_spk, dest)) out.pushKV("address", EncodeDestination(dest));
    return out;
},
    };
}

static RPCHelpMan createeutxotransition()
{
    return RPCHelpMan{"createeutxotransition",
        "Build an unsigned transaction that spends a Blackcoin EUTXO commitment\n"
        "into a committed successor EUTXO state. The structured redeemer is enforced by\n"
        "consensus: if a redeemer begins with QQEUTXO1, the transaction must create the\n"
        "exact successor output encoded in that redeemer.\n",
        {
            {"eutxo_commitment", RPCArg::Type::OBJ, RPCArg::Optional::NO,
             "The EUTXO commitment output being spent",
             {
                 {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The commitment txid"},
                 {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The commitment output index"},
                 {"datum", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex datum committed by the output"},
                 {"validator", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex validator script committed by the output"},
                 {"sequence", RPCArg::Type::NUM, RPCArg::Default{(int64_t)0xffffffff}, "Sequence number for the input"},
             }},
            {"next_state", RPCArg::Type::OBJ, RPCArg::Optional::NO,
             "The successor EUTXO state",
             {
                 {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Successor amount in " + CURRENCY_UNIT},
                 {"datum", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex datum committed by the successor output"},
                 {"validator", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex validator script committed by the successor output"},
             }},
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Unsigned transaction hex, EUTXO input witness populated"},
                {RPCResult::Type::STR_HEX, "redeemer", "Structured transition redeemer placed in the input witness"},
                {RPCResult::Type::STR_HEX, "spent_program", "The 32-byte program recomputed from the spent datum+validator"},
                {RPCResult::Type::STR_HEX, "successor_program", "The 32-byte program committed by the successor EUTXO output"},
                {RPCResult::Type::NUM, "successor_vout", "The successor output index encoded in the redeemer"},
                {RPCResult::Type::STR, "successor_address", "The successor eutxo_commitment address"},
            }},
        RPCExamples{
            HelpExampleCli("createeutxotransition",
                "'{\"txid\":\"...\",\"vout\":0,\"datum\":\"01\",\"validator\":\"51\"}' '{\"amount\":0.5,\"datum\":\"02\",\"validator\":\"51\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& c = request.params[0].get_obj();
    RPCTypeCheckObj(c, {
        {"txid", UniValueType(UniValue::VSTR)},
        {"vout", UniValueType(UniValue::VNUM)},
        {"datum", UniValueType(UniValue::VSTR)},
        {"validator", UniValueType(UniValue::VSTR)},
    });
    const UniValue& next = request.params[1].get_obj();
    RPCTypeCheckObj(next, {
        {"amount", UniValueType()},
        {"datum", UniValueType(UniValue::VSTR)},
        {"validator", UniValueType(UniValue::VSTR)},
    });

    const uint256 txid = ParseHashO(c, "txid");
    const int vout = c.find_value("vout").getInt<int>();
    if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be positive");

    const std::vector<unsigned char> datum = ParseHexOAllowEmpty(c, "datum");
    const std::vector<unsigned char> validator = ParseHexOAllowEmpty(c, "validator");
    const std::vector<unsigned char> next_datum = ParseHexOAllowEmpty(next, "datum");
    const std::vector<unsigned char> next_validator = ParseHexOAllowEmpty(next, "validator");
    const CAmount next_amount = AmountFromValue(next.find_value("amount"));
    if (!MoneyRange(next_amount)) throw JSONRPCError(RPC_INVALID_PARAMETER, "amount out of range");

    if (datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        validator.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        next_datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        next_validator.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "datum/validator exceed 4096 bytes");
    }

    const CScript validator_script(validator.begin(), validator.end());
    const CScript next_validator_script(next_validator.begin(), next_validator.end());
    const CScript successor_spk = GetScriptForEUTXO(next_datum, next_validator_script);

    eutxo::StateTransition transition;
    transition.output_index = 0;
    transition.amount = next_amount;
    transition.datum = next_datum;
    transition.validator_script = next_validator_script;
    std::vector<unsigned char> redeemer;
    try {
        redeemer = eutxo::EncodeStateTransition(transition);
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
    }

    CMutableTransaction rawTx;
    rawTx.nVersion = CTransaction::CURRENT_VERSION;
    if (!request.params[2].isNull()) {
        const int64_t locktime = request.params[2].getInt<int64_t>();
        if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid locktime");
        }
        rawTx.nLockTime = static_cast<uint32_t>(locktime);
    }
    CTxIn in(COutPoint(Txid::FromUint256(txid), static_cast<uint32_t>(vout)));
    if (!c.find_value("sequence").isNull()) {
        const int64_t seq = c.find_value("sequence").getInt<int64_t>();
        if (seq < 0 || seq > CTxIn::SEQUENCE_FINAL) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sequence");
        in.nSequence = static_cast<uint32_t>(seq);
    } else if (rawTx.nLockTime != 0) {
        in.nSequence = CTxIn::SEQUENCE_FINAL - 1;
    }
    in.scriptWitness.stack.push_back(datum);
    in.scriptWitness.stack.push_back(redeemer);
    in.scriptWitness.stack.push_back(std::vector<unsigned char>(validator.begin(), validator.end()));
    rawTx.vin.push_back(in);
    rawTx.vout.emplace_back(next_amount, successor_spk);

    UniValue out(UniValue::VOBJ);
    out.pushKV("hex", EncodeHexTx(CTransaction(rawTx)));
    out.pushKV("redeemer", HexStr(redeemer));
    out.pushKV("spent_program", HexStr(EUTXOProgramForDatumAndValidator(datum, validator_script)));
    out.pushKV("successor_program", HexStr(EUTXOProgramForDatumAndValidator(next_datum, next_validator_script)));
    out.pushKV("successor_vout", 0);
    CTxDestination dest;
    if (ExtractDestination(successor_spk, dest)) out.pushKV("successor_address", EncodeDestination(dest));
    return out;
},
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &getrawtransaction},
        {"rawtransactions", &createrawtransaction},
        {"rawtransactions", &decoderawtransaction},
        {"rawtransactions", &decodescript},
        {"rawtransactions", &combinerawtransaction},
        {"rawtransactions", &signrawtransactionwithkey},
        {"rawtransactions", &signrawtransactionwithquantumkey},
        {"rawtransactions", &decodepsbt},
        {"rawtransactions", &combinepsbt},
        {"rawtransactions", &finalizepsbt},
        {"rawtransactions", &createpsbt},
        {"rawtransactions", &converttopsbt},
        {"rawtransactions", &utxoupdatepsbt},
        {"rawtransactions", &descriptorprocesspsbt},
        {"rawtransactions", &joinpsbts},
        {"rawtransactions", &analyzepsbt},
        {"rawtransactions", &decodergbcommitment},
        {"rawtransactions", &verifyrgbconsignment},
        {"rawtransactions", &decodeeutxospend},
        {"rawtransactions", &verifyeutxospend},
        {"rawtransactions", &createeutxospend},
        {"rawtransactions", &createeutxotransition},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
