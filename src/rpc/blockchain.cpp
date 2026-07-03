// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/quantum_pool.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <shadow.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <warnings.h>
#include <crypto/mldsa.h>

#include <stdint.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;

using node::BlockManager;
using node::NodeContext;
using node::SnapshotMetadata;

struct CUpdatedBlock
{
    uint256 hash;
    int height;
};

static GlobalMutex cs_blockchange;
static std::condition_variable cond_blockchange;
static CUpdatedBlock latestblock GUARDED_BY(cs_blockchange);

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex* blockindex)
{
    CHECK_NONFATAL(blockindex);

    int nShift = (blockindex->nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double GetPoSKernelPS(ChainstateManager& chainman)
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = chainman.m_best_header;
    CBlockIndex* pindexPrevStake = nullptr;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            if (pindexPrevStake)
            {
                dStakeKernelsTriedAvg += GetDifficulty(pindexPrevStake) * 4294967296.0;
                nStakesTime += pindexPrevStake->nTime - pindex->nTime;
                nStakesHandled++;
            }
            pindexPrevStake = pindex;
        }

        pindex = pindex->pprev;
    }

    double result = 0;

    if (nStakesTime)
        result = dStakeKernelsTriedAvg / nStakesTime;

    result *= Params().GetConsensus().nStakeTimestampMask + 1;

    return result;
}

static int ComputeNextBlockAndDepth(const CBlockIndex* tip, const CBlockIndex* blockindex, const CBlockIndex*& next)
{
    next = tip->GetAncestor(blockindex->nHeight + 1);
    if (next && next->pprev == blockindex) {
        return tip->nHeight - blockindex->nHeight + 1;
    }
    next = nullptr;
    return blockindex == tip ? 1 : -1;
}

static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.getInt<int>()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex* tip, const CBlockIndex* blockindex)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex->nVersion));
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)blockindex->nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex->nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    result.pushKV("nTx", (uint64_t)blockindex->nTx);

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex* tip, const CBlockIndex* blockindex, TxVerbosity verbosity)
{
    UniValue result = blockheaderToJSON(tip, blockindex);

    result.pushKV("strippedsize", (int)::GetSerializeSize(TX_NO_WITNESS(block)));
    result.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", (int)::GetBlockWeight(block));
    UniValue txs(UniValue::VARR);

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (const CTransactionRef& tx : block.vtx) {
                txs.push_back(tx->GetHash().GetHex());
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool have_undo{blockman.UndoReadFromDisk(blockUndo, *blockindex)};

            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, /*block_hash=*/uint256(), /*entry=*/objTx, /*include_hex=*/true, /*without_witness=*/RPCSerializationWithoutWitness(), txundo, verbosity);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    result.pushKV("flags", strprintf("%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work"));
    result.pushKV("modifier", blockindex->nStakeModifier.GetHex());
    if (block.IsProofOfStake())
        result.pushKV("signature", HexStr(block.vchBlockSig));

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{"getblockcount",
                "\nReturns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{"getbestblockhash",
                "\nReturns the hash of the best (tip) block in the most-work fully-validated chain.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

void RPCNotifyBlockChange(const CBlockIndex* pindex)
{
    if(pindex) {
        LOCK(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{"waitfornewblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].getInt<int>();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{"waitforblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{"waitforblockheight",
                "\nWaits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].getInt<int>();

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{"syncwithvalidationinterfacequeue",
                "\nWaits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    SyncWithValidationInterfaceQueue();
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{"getdifficulty",
                "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
                "\nReturns the proof-of-stake difficulty as a multiple of the minimum difficulty.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "proof-of-work", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
                        {RPCResult::Type::NUM, "proof-of-stake", "the proof-of-stake difficulty as a multiple of the minimum difficulty."},
                    }},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    const CBlockIndex* tip = chainman.ActiveChain().Tip();
    obj.pushKV("proof-of-work",  GetDifficulty(GetLastBlockIndex(tip, false)));
    obj.pushKV("proof-of-stake", GetDifficulty(GetLastBlockIndex(tip, true)));
    return obj;
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "Subsequent calls for the same block may cause the response from the previous peer to be ignored.\n"
        "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
        "When a peer does not respond with a block, we will disconnect.\n"
        "Note: The block could be re-pruned as soon as it is received.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].getInt<int64_t>()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    // Fetching blocks before the node has syncing past their height can prevent block files from
    // being pruned, so we avoid it if the node is in prune mode.
    if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
        throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto err{peerman.FetchBlock(peer_id, *index)}) {
        throw JSONRPCError(RPC_MISC_ERROR, err.value());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{"getblockhash",
                "\nReturns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    int nHeight = request.params[0].getInt<int>();
    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    const CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{"getblockheader",
                "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", "The bits"},
                            {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the current chain"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(tip, pblockindex);
},
    };
}

static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex* pblockindex)
{
    CBlock block;

    if (!blockman.ReadBlockFromDisk(block, *pblockindex)) {
        // Block not found on disk. This could be because we have the block
        // header in our index but not yet have the block or did not accept the
        // block. Or if the block was pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex* pblockindex)
{
    CBlockUndo blockUndo;

    // The Genesis block does not have undo data
    if (pblockindex->nHeight == 0) return blockUndo;

    if (!blockman.UndoReadFromDisk(blockUndo, *pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

const RPCResult getblock_vin{
    RPCResult::Type::ARR, "vin", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
            {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
            {
                {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                {RPCResult::Type::NUM, "height", "The height of the prevout"},
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
                    {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                }},
            }},
        }},
    }
};

static RPCHelpMan getblock()
{
    return RPCHelpMan{"getblock",
                "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs",
                     RPCArgOptions{.skip_type_check = true}},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", "The bits"},
                    {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the chain up to this block (in hex)"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            getblock_vin,
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity = 1;
    if (!request.params[1].isNull()) {
        if (request.params[1].isBool()) {
            verbosity = request.params[1].get_bool() ? 1 : 0;
        } else {
            verbosity = request.params[1].getInt<int>();
        }
    }

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    const CBlock block{GetBlockChecked(chainman.m_blockman, pblockindex)};

    if (verbosity <= 0)
    {
        CDataStream ssBlock(SER_NETWORK);
        ssBlock << RPCTxSerParams(block);
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(chainman.m_blockman, block, tip, pblockindex, tx_verbosity);
},
    };
}

CoinStatsHashType ParseHashType(const std::string& hash_type_input)
{
    if (hash_type_input == "hash_serialized_3") {
        return CoinStatsHashType::HASH_SERIALIZED;
    } else if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

/**
 * Calculate statistics about the unspent transaction output set
 *
 * @param[in] index_requested Signals if the coinstatsindex should be used (when available).
 */
static std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                       kernel::CoinStatsHashType hash_type,
                                                       const std::function<void()>& interruption_point = {},
                                                       const CBlockIndex* pindex = nullptr,
                                                       bool index_requested = true)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return g_coin_stats_index->LookUpStats(*pindex);
        } else {
            CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
            return g_coin_stats_index->LookUpStats(block_index);
        }
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{"gettxoutsetinfo",
                "\nReturns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_3"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (only available with coinstatsindex).",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "hash_serialized_3", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    const CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
    bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk();

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
        pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_3 hash type cannot be queried for a specific block");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    const std::optional<CCoinsStats> maybe_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (maybe_stats.has_value()) {
        const CCoinsStats& stats = maybe_stats.value();
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            ret.pushKV("hash_serialized_3", stats.hashSerialized.GetHex());
        }
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.hashSerialized.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            ret.pushKV("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

            CCoinsStats prev_stats{};
            if (pindex->nHeight > 0) {
                const std::optional<CCoinsStats> maybe_prev_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex->pprev, index_requested);
                if (!maybe_prev_stats) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                prev_stats = maybe_prev_stats.value();
            }

            UniValue block_info(UniValue::VOBJ);
            block_info.pushKV("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount));
            block_info.pushKV("coinbase", ValueFromAmount(stats.total_coinbase_amount - prev_stats.total_coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount));
            block_info.pushKV("unspendable", ValueFromAmount(stats.total_unspendable_amount - prev_stats.total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", unspendables);

            ret.pushKV("block_info", block_info);
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan getcirculatingsupply()
{
    return RPCHelpMan{"getcirculatingsupply",
        "\nScans the current UTXO set and returns the demurrage-adjusted circulating supply.\n"
        "This is computed on demand and may take some time. It does not use or maintain an in-block accumulator.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "height", "The active-chain height used for the scan"},
                {RPCResult::Type::STR_HEX, "bestblock", "The active-chain block hash used for the scan"},
                {RPCResult::Type::BOOL, "demurrage_active", "Whether demurrage is active at this height"},
                {RPCResult::Type::NUM, "demurrage_activation_height", "The configured demurrage activation height"},
                {RPCResult::Type::NUM, "demurrage_effective_activation_height", "The demurrage activation height after the post-Gold-Rush clamp"},
                {RPCResult::Type::NUM_TIME, "quantum_migration_deadline_time", "Final quantum migration deadline time used by the demurrage post-migration guard"},
                {RPCResult::Type::BOOL, "demurrage_height_guard_satisfied", "Whether the height is at or above demurrage_effective_activation_height"},
                {RPCResult::Type::BOOL, "demurrage_post_migration_guard_satisfied", "Whether MedianTimePast is after quantum_migration_deadline_time"},
                {RPCResult::Type::STR_AMOUNT, "nominal_amount", "Nominal UTXO-set amount before demurrage"},
                {RPCResult::Type::STR_AMOUNT, "circulating_amount", "Demurrage-adjusted effective circulating amount"},
                {RPCResult::Type::STR_AMOUNT, "decayed_amount", "Nominal minus effective amount"},
                {RPCResult::Type::NUM, "txouts", "The number of scanned UTXOs"},
                {RPCResult::Type::NUM, "decayed_txouts", "The number of non-exempt UTXOs with realized decay at this height"},
                {RPCResult::Type::NUM, "locked_txouts", "The number of non-exempt UTXOs that have reached the 24-month lock"},
            }
        },
        RPCExamples{
            HelpExampleCli("getcirculatingsupply", "") +
            HelpExampleRpc("getcirculatingsupply", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    const Consensus::Params& consensus = chainman.GetConsensus();

    const CBlockIndex* tip{nullptr};
    std::unique_ptr<CCoinsViewCursor> cursor;
    std::unique_ptr<CCoinsViewCache> lookup_view;
    {
        LOCK(::cs_main);
        active_chainstate.ForceFlushStateToDisk();
        CCoinsView& coins_db = active_chainstate.CoinsDB();
        tip = CHECK_NONFATAL(active_chainstate.m_blockman.LookupBlockIndex(coins_db.GetBestBlock()));
        cursor = coins_db.Cursor();
        lookup_view = std::make_unique<CCoinsViewCache>(&coins_db);
    }

    CAmount nominal{0};
    CAmount circulating{0};
    int64_t txouts{0};
    int64_t decayed_txouts{0};
    int64_t locked_txouts{0};
    const int64_t tip_mtp = tip->GetMedianTimePast();
    COutPoint key;
    Coin coin;
    while (cursor->Valid()) {
        node.rpc_interruption_point();
        if (cursor->GetKey(key) && cursor->GetValue(coin)) {
            ++txouts;
            nominal += coin.out.nValue;
            const std::optional<int> latest_attestation = Consensus::LatestDemurrageAttestationHeightForScript(*lookup_view, coin.out.scriptPubKey);
            const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(coin, consensus, tip->nHeight, tip_mtp, latest_attestation);
            circulating += eval.effective_value;
            if (eval.locked) ++locked_txouts;
            if (eval.burned_value > 0) ++decayed_txouts;
        }
        cursor->Next();
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("height", tip->nHeight);
    ret.pushKV("bestblock", tip->GetBlockHash().GetHex());
    ret.pushKV("demurrage_active", consensus.IsDemurrageActive(tip->nHeight, tip_mtp));
    ret.pushKV("demurrage_activation_height", consensus.nDemurrageActivationHeight);
    ret.pushKV("demurrage_effective_activation_height", consensus.EffectiveDemurrageActivationHeight());
    ret.pushKV("quantum_migration_deadline_time", consensus.nQuantumMigrationDeadlineTime);
    ret.pushKV("demurrage_height_guard_satisfied", tip->nHeight >= consensus.EffectiveDemurrageActivationHeight());
    ret.pushKV("demurrage_post_migration_guard_satisfied", consensus.nQuantumMigrationDeadlineTime != 0 && tip_mtp > consensus.nQuantumMigrationDeadlineTime);
    ret.pushKV("nominal_amount", ValueFromAmount(nominal));
    ret.pushKV("circulating_amount", ValueFromAmount(circulating));
    ret.pushKV("decayed_amount", ValueFromAmount(nominal - circulating));
    ret.pushKV("txouts", txouts);
    ret.pushKV("decayed_txouts", decayed_txouts);
    ret.pushKV("locked_txouts", locked_txouts);
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{"gettxout",
        "\nReturns details about an unspent transaction output.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Blackcoin address (only if a well-defined address exists)"},
                    {RPCResult::Type::NUM, "witness_version", /*optional=*/true, "The witness version for witness outputs"},
                    {RPCResult::Type::STR_HEX, "witness_program", /*optional=*/true, "The witness program for witness outputs"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
                {RPCResult::Type::BOOL, "coinstake", "Coinstake or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    COutPoint out{hash, request.params[1].getInt<uint32_t>()};
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    Coin coin;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!view.GetCoin(out, coin) || mempool.isSpent(out)) {
            return UniValue::VNULL;
        }
    } else {
        if (!coins_view->GetCoin(out, coin)) {
            return UniValue::VNULL;
        }
    }

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin.nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin.nHeight + 1));
    }
    ret.pushKV("value", ValueFromAmount(coin.out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptToUniv(coin.out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
    ret.pushKV("scriptPubKey", o);
    ret.pushKV("coinbase", (bool)coin.fCoinBase);
    ret.pushKV("coinstake", (bool)coin.fCoinStake);

    return ret;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{"verifychain",
                "\nVerifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB(chainman.GetNotifications()).VerifyDB(
               active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
},
    };
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    // For buried deployments.

    if (!DeploymentEnabled(chainman, dep)) return;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "buried");
    // getdeploymentinfo reports the softfork as active from when the chain height is
    // one below the activation height
    rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, dep));
    rv.pushKV("height", chainman.GetConsensus().DeploymentHeight(dep));
    softforks.pushKV(DeploymentName(dep), rv);
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::DeploymentPos id)
{
    // For BIP9 deployments.

    if (!DeploymentEnabled(chainman, id)) return;
    if (blockindex == nullptr) return;

    if (id == Consensus::DEPLOYMENT_SEGWIT && HasSegwitHeightOverride(chainman.GetConsensus())) {
        UniValue rv(UniValue::VOBJ);
        rv.pushKV("type", "buried");
        rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, id));
        rv.pushKV("height", chainman.GetConsensus().SegwitHeight);
        softforks.pushKV(DeploymentName(id), rv);
        return;
    }

    auto get_state_name = [](const ThresholdState state) -> std::string {
        switch (state) {
        case ThresholdState::DEFINED: return "defined";
        case ThresholdState::STARTED: return "started";
        case ThresholdState::LOCKED_IN: return "locked_in";
        case ThresholdState::ACTIVE: return "active";
        case ThresholdState::FAILED: return "failed";
        }
        return "invalid";
    };

    UniValue bip9(UniValue::VOBJ);

    const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
    const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex->pprev, chainman.GetConsensus(), id);

    const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);

    // BIP9 parameters
    if (has_signal) {
        bip9.pushKV("bit", chainman.GetConsensus().vDeployments[id].bit);
    }
    bip9.pushKV("start_time", chainman.GetConsensus().vDeployments[id].nStartTime);
    bip9.pushKV("timeout", chainman.GetConsensus().vDeployments[id].nTimeout);
    bip9.pushKV("min_activation_height", chainman.GetConsensus().vDeployments[id].min_activation_height);

    // BIP9 status
    bip9.pushKV("status", get_state_name(current_state));
    bip9.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(blockindex->pprev, chainman.GetConsensus(), id));
    bip9.pushKV("status_next", get_state_name(next_state));

    // BIP9 signalling status, if applicable
    if (has_signal) {
        UniValue statsUV(UniValue::VOBJ);
        std::vector<bool> signals;
        BIP9Stats statsStruct = chainman.m_versionbitscache.Statistics(blockindex, chainman.GetConsensus(), id, &signals);
        statsUV.pushKV("period", statsStruct.period);
        statsUV.pushKV("elapsed", statsStruct.elapsed);
        statsUV.pushKV("count", statsStruct.count);
        if (ThresholdState::LOCKED_IN != current_state) {
            statsUV.pushKV("threshold", statsStruct.threshold);
            statsUV.pushKV("possible", statsStruct.possible);
        }
        bip9.pushKV("statistics", statsUV);

        std::string sig;
        sig.reserve(signals.size());
        for (const bool s : signals) {
            sig.push_back(s ? '#' : '-');
        }
        bip9.pushKV("signalling", sig);
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "bip9");
    if (ThresholdState::ACTIVE == next_state) {
        rv.pushKV("height", chainman.m_versionbitscache.StateSinceHeight(blockindex, chainman.GetConsensus(), id));
    }
    rv.pushKV("active", ThresholdState::ACTIVE == next_state);
    rv.pushKV("bip9", bip9);

    softforks.pushKV(DeploymentName(id), rv);
}

static const char* QuantumQuasarPhaseName(Consensus::QuantumQuasarPhase phase)
{
    switch (phase) {
    case Consensus::QuantumQuasarPhase::LEGACY:
        return "legacy";
    case Consensus::QuantumQuasarPhase::GOLD_RUSH:
        return "gold_rush";
    case Consensus::QuantumQuasarPhase::MIGRATION:
        return "migration";
    case Consensus::QuantumQuasarPhase::FINAL_LOCKOUT:
        return "final_lockout";
    }
    return "unknown";
}

static int64_t SecondsUntil(int64_t now, int64_t deadline)
{
    if (deadline == 0 || now >= deadline) return 0;
    return deadline - now;
}

static int64_t SecondsUntilAfterBoundary(int64_t now, int64_t boundary)
{
    if (boundary == 0 || now > boundary) return 0;
    return boundary - now + 1;
}

static const char* QuantumReadinessStateName(const ThresholdState state)
{
    switch (state) {
    case ThresholdState::DEFINED:
        return "defined";
    case ThresholdState::STARTED:
        return "started";
    case ThresholdState::LOCKED_IN:
        return "locked_in";
    case ThresholdState::ACTIVE:
        return "active";
    case ThresholdState::FAILED:
        return "failed";
    }
    return "invalid";
}

static UniValue QuantumReadinessStatus(const CBlockIndex& tip, const ChainstateManager& chainman, Consensus::DeploymentPos id)
{
    const Consensus::Params& consensus = chainman.GetConsensus();
    const ThresholdState current_state = chainman.m_versionbitscache.State(tip.pprev, consensus, id);
    const ThresholdState next_state = chainman.m_versionbitscache.State(&tip, consensus, id);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("bit", consensus.vDeployments[id].bit);
    obj.pushKV("start_time", consensus.vDeployments[id].nStartTime);
    obj.pushKV("timeout", consensus.vDeployments[id].nTimeout);
    obj.pushKV("status", QuantumReadinessStateName(current_state));
    obj.pushKV("status_next", QuantumReadinessStateName(next_state));
    obj.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(tip.pprev, consensus, id));
    obj.pushKV("enforces_consensus", false);
    obj.pushKV("purpose", "readiness signalling only");
    return obj;
}

static UniValue QuantumQuasarStatus(const CBlockIndex& tip, const ChainstateManager& chainman)
{
    const Consensus::Params& consensus = chainman.GetConsensus();
    const int64_t mtp = tip.GetMedianTimePast();
    const Consensus::QuantumQuasarPhase phase = consensus.GetQuantumQuasarPhase(mtp);
    const int next_height = tip.nHeight + 1;
    const bool quantum_spend_active = IsQuantumWitnessSpendActive(consensus, mtp, next_height);
    const bool new_network_stake_only = consensus.IsNewNetworkStakeOnly(mtp);
    const bool base_network_stake_compatible = consensus.IsBaseNetworkStakeCompatible(mtp);
    const bool shadow_merge_mining_active = IsShadowGoldRushRewardActive(consensus, mtp, next_height);
    const bool final_lockout_active = consensus.IsQuantumFinalLockout(mtp);
    const bool shadow_reward_height_active = IsShadowGoldRushRewardHeight(next_height);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("phase", QuantumQuasarPhaseName(phase));
    obj.pushKV("mediantime", mtp);
    obj.pushKV("v4_activation_time", consensus.nProtocolV4Time);
    obj.pushKV("gold_rush_end_time", consensus.nGoldRushEndTime);
    obj.pushKV("quantum_migration_deadline_time", consensus.nQuantumMigrationDeadlineTime);
    obj.pushKV("seconds_until_v4", SecondsUntilAfterBoundary(mtp, consensus.nProtocolV4Time));
    obj.pushKV("seconds_until_gold_rush_end", SecondsUntil(mtp, consensus.nGoldRushEndTime));
    obj.pushKV("seconds_until_quantum_migration_deadline", SecondsUntil(mtp, consensus.nQuantumMigrationDeadlineTime));
    obj.pushKV("base_network_stake_compatible", base_network_stake_compatible);
    obj.pushKV("shadow_merge_mining_active", shadow_merge_mining_active);
    obj.pushKV("shadow_reward_height_active", shadow_reward_height_active);
    obj.pushKV("shadow_reward_next_height", next_height);
    obj.pushKV("shadow_reward_start_height", SHADOW_REWARD_START_HEIGHT);
    obj.pushKV("shadow_reward_end_height", SHADOW_REWARD_END_HEIGHT);
    obj.pushKV("new_network_stake_only", new_network_stake_only);
    obj.pushKV("replay_protection_active", new_network_stake_only);
    obj.pushKV("legacy_address_lockout_scheduled", consensus.nQuantumMigrationDeadlineTime != 0);
    obj.pushKV("quantum_address_required_by_schedule", final_lockout_active);
    obj.pushKV("legacy_addresses_accepted", !final_lockout_active);
    obj.pushKV("quantum_address_required", final_lockout_active);
    obj.pushKV("quantum_spend_enforcement_active", quantum_spend_active);
    obj.pushKV("quantum_migration_outputs_fundable", true);
    UniValue readiness(UniValue::VOBJ);
    readiness.pushKV(VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_QUANTUM_QUASAR].name, QuantumReadinessStatus(tip, chainman, Consensus::DEPLOYMENT_QUANTUM_QUASAR));
    readiness.pushKV(VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_QUANTUM_MIGRATION].name, QuantumReadinessStatus(tip, chainman, Consensus::DEPLOYMENT_QUANTUM_MIGRATION));
    obj.pushKV("readiness_signalling", readiness);
    obj.pushKV("migration_policy", "Quantum witness-v16 addresses are fundable now. Gold Rush credits accrue in the upgraded shadow ledger while legacy nodes can still follow the base chain. ML-DSA spends activate after the Gold Rush reward-height window during migration/final lockout. After the migration deadline, consensus rejects non-quantum spends and value-bearing non-quantum outputs.");
    return obj;
}

static const std::vector<RPCResult> RPCHelpForQuantumReadiness{
    {RPCResult::Type::NUM, "bit", "version bit used for readiness signalling"},
    {RPCResult::Type::NUM_TIME, "start_time", "minimum median time past at which the bit gains its readiness meaning"},
    {RPCResult::Type::NUM_TIME, "timeout", "readiness signalling timeout"},
    {RPCResult::Type::STR, "status", "current versionbits state for the readiness signal"},
    {RPCResult::Type::STR, "status_next", "next-block versionbits state for the readiness signal"},
    {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
    {RPCResult::Type::BOOL, "enforces_consensus", "false because these bits advertise readiness only"},
    {RPCResult::Type::STR, "purpose", "human-readable purpose"},
};

static const std::vector<RPCResult> RPCHelpForQuantumQuasar{
    {RPCResult::Type::STR, "phase", "current Blackcoin upgrade phase"},
    {RPCResult::Type::NUM_TIME, "mediantime", "current tip median time used for schedule state"},
    {RPCResult::Type::NUM_TIME, "v4_activation_time", "first V4 hard-fork activation boundary"},
    {RPCResult::Type::NUM_TIME, "gold_rush_end_time", "end of the Gold Rush phase"},
    {RPCResult::Type::NUM_TIME, "quantum_migration_deadline_time", "planned final post-quantum migration deadline"},
    {RPCResult::Type::NUM, "seconds_until_v4", "seconds until V4 rules become active, or 0 if reached"},
    {RPCResult::Type::NUM, "seconds_until_gold_rush_end", "seconds until Gold Rush end, or 0 if reached"},
    {RPCResult::Type::NUM, "seconds_until_quantum_migration_deadline", "seconds until final migration deadline, or 0 if reached"},
    {RPCResult::Type::BOOL, "base_network_stake_compatible", "whether stakers should keep producing base-network-compatible coinstakes"},
    {RPCResult::Type::BOOL, "shadow_merge_mining_active", "whether Gold Rush shadow proof merge-mining is active"},
    {RPCResult::Type::BOOL, "shadow_reward_height_active", "whether the next block is inside the deterministic height-based Gold Rush payout window"},
    {RPCResult::Type::NUM, "shadow_reward_next_height", "height of the next block checked against the deterministic payout window"},
    {RPCResult::Type::NUM, "shadow_reward_start_height", "first deterministic Gold Rush payout height"},
    {RPCResult::Type::NUM, "shadow_reward_end_height", "last deterministic Gold Rush payout height"},
    {RPCResult::Type::BOOL, "new_network_stake_only", "whether staking has crossed the final quantum-only lockout cutover"},
    {RPCResult::Type::BOOL, "replay_protection_active", "whether SIGHASH_FORKID replay protection is enforced by schedule"},
    {RPCResult::Type::BOOL, "legacy_address_lockout_scheduled", "whether the upgrade schedule contains a final legacy lockout deadline"},
    {RPCResult::Type::BOOL, "quantum_address_required_by_schedule", "whether the upgrade schedule has reached the scheduled quantum-address phase"},
    {RPCResult::Type::BOOL, "legacy_addresses_accepted", "whether this node currently accepts legacy addresses under implemented rules"},
    {RPCResult::Type::BOOL, "quantum_address_required", "whether this node currently enforces quantum-only destinations"},
    {RPCResult::Type::BOOL, "quantum_spend_enforcement_active", "whether ML-DSA spend enforcement is implemented and active"},
    {RPCResult::Type::BOOL, "quantum_migration_outputs_fundable", "whether ordinary wallet/RPC policy permits funding reserved migration outputs"},
    {RPCResult::Type::OBJ_DYN, "readiness_signalling", "versionbits readiness signals keyed by deployment name", {
        {RPCResult::Type::OBJ, "deployment", "readiness signal", RPCHelpForQuantumReadiness},
    }},
    {RPCResult::Type::STR, "migration_policy", "human-readable migration policy"},
};

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    return RPCHelpMan{"getblockchaininfo",
        "Returns an object containing various state info regarding blockchain processing.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "chain", "current network name (main, test, signet, regtest)"},
                {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                {RPCResult::Type::NUM, "difficulty", "the current difficulty"},
                {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                {RPCResult::Type::STR_HEX, "chainwork", "total amount of work in active chain, in hexadecimal"},
                {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                {RPCResult::Type::OBJ, "quantumquasar", "Blackcoin V4 and migration schedule state", RPCHelpForQuantumQuasar},
                {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
            }},
        RPCExamples{
            HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    const int height{tip.nHeight};
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("blocks", height);
    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    obj.pushKV("bestblockhash", tip.GetBlockHash().GetHex());
    obj.pushKV("difficulty", GetDifficulty(&tip));
    obj.pushKV("time", tip.GetBlockTime());
    obj.pushKV("mediantime", tip.GetMedianTimePast());
    obj.pushKV("verificationprogress", GuessVerificationProgress(chainman.GetParams().TxData(), &tip));
    obj.pushKV("initialblockdownload", chainman.IsInitialBlockDownload());
    obj.pushKV("chainwork", tip.nChainWork.GetHex());
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("quantumquasar", QuantumQuasarStatus(tip, chainman));

    obj.pushKV("warnings", GetWarnings(false).original);
    return obj;
},
    };
}

static RPCHelpMan getquantumquasarinfo()
{
    return RPCHelpMan{"getquantumquasarinfo",
        "Returns Blackcoin V4, Gold Rush, and post-quantum migration schedule state.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", RPCHelpForQuantumQuasar},
        RPCExamples{
            HelpExampleCli("getquantumquasarinfo", "")
            + HelpExampleRpc("getquantumquasarinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    return QuantumQuasarStatus(tip, chainman);
},
    };
}

namespace {
const std::vector<RPCResult> RPCHelpForDeployment{
    {RPCResult::Type::STR, "type", "one of \"buried\", \"bip9\""},
    {RPCResult::Type::NUM, "height", /*optional=*/true, "height of the first block which the rules are or will be enforced (only for \"buried\" type, or \"bip9\" type with \"active\" status)"},
    {RPCResult::Type::BOOL, "active", "true if the rules are enforced for the mempool and the next block"},
    {RPCResult::Type::OBJ, "bip9", /*optional=*/true, "status of bip9 softforks (only for \"bip9\" type)",
    {
        {RPCResult::Type::NUM, "bit", /*optional=*/true, "the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)"},
        {RPCResult::Type::NUM_TIME, "start_time", "the minimum median time past of a block at which the bit gains its meaning"},
        {RPCResult::Type::NUM_TIME, "timeout", "the median time past of a block at which the deployment expires"},
        {RPCResult::Type::NUM, "min_activation_height", "minimum height of blocks for which the rules may be enforced"},
        {RPCResult::Type::STR, "status", "status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\")"},
        {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
        {RPCResult::Type::STR, "status_next", "status of deployment at the next block"},
        {RPCResult::Type::OBJ, "statistics", /*optional=*/true, "numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)",
        {
            {RPCResult::Type::NUM, "period", "the length in blocks of the signalling period"},
            {RPCResult::Type::NUM, "threshold", /*optional=*/true, "the number of blocks with the version bit set required to activate the feature (only for \"started\" status)"},
            {RPCResult::Type::NUM, "elapsed", "the number of blocks elapsed since the beginning of the current period"},
            {RPCResult::Type::NUM, "count", "the number of blocks with the version bit set in the current period"},
            {RPCResult::Type::BOOL, "possible", /*optional=*/true, "returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)"},
        }},
        {RPCResult::Type::STR, "signalling", /*optional=*/true, "indicates blocks that signalled with a # and blocks that did not with a -"},
    }},
};

UniValue DeploymentInfo(const CBlockIndex* blockindex, const ChainstateManager& chainman)
{
    UniValue softforks(UniValue::VOBJ);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CSV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_SEGWIT);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TESTDUMMY);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TAPROOT);
    return softforks;
}
} // anon namespace

RPCHelpMan getdeploymentinfo()
{
    return RPCHelpMan{"getdeploymentinfo",
        "Returns an object containing various state info regarding deployments of consensus changes.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                {RPCResult::Type::OBJ_DYN, "deployments", "", {
                    {RPCResult::Type::OBJ, "xxxx", "name of the deployment", RPCHelpForDeployment}
                }},
            }
        },
        RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const Chainstate& active_chainstate = chainman.ActiveChainstate();

            const CBlockIndex* blockindex;
            if (request.params[0].isNull()) {
                blockindex = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            } else {
                const uint256 hash(ParseHashV(request.params[0], "blockhash"));
                blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                if (!blockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            UniValue deploymentinfo(UniValue::VOBJ);
            deploymentinfo.pushKV("hash", blockindex->GetBlockHash().ToString());
            deploymentinfo.pushKV("height", blockindex->nHeight);
            deploymentinfo.pushKV("deployments", DeploymentInfo(blockindex, chainman));
            return deploymentinfo;
        },
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const auto& [_, block_index] : chainman.BlockIndex()) {
        if (!active_chain.Contains(&block_index)) {
            setOrphans.insert(&block_index);
            setPrevs.insert(block_index.pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveNumChainTxs()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(obj);
    }

    return res;
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{"preciousblock",
                "\nTreats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{"invalidateblock",
                "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    BlockValidationState state;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    CBlockIndex* pblockindex;
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{"reconsiderblock",
                "\nRemoves invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    {
        LOCK(cs_main);
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getgoldrushstate()
{
    return RPCHelpMan{"getgoldrushstate",
                "Returns chain-level Shadow Network Gold Rush state. Use wallet getgoldrushinfo for wallet qualification details.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "pow_amount", "Total accrued PoW jackpot"},
                        {RPCResult::Type::NUM, "pos_amount", "Total accrued PoS jackpot"},
                        {RPCResult::Type::NUM, "claimed_amount", "Total Gold Rush amount already materialized to quantum payout coins"},
                        {RPCResult::Type::NUM, "pow_count", "Number of PoW solves"},
                        {RPCResult::Type::NUM, "pos_count", "Number of PoS claims"},
                        {RPCResult::Type::NUM, "last_pow_height", "Block height of the last PoW"},
                        {RPCResult::Type::NUM, "last_pos_height", "Block height of the last PoS"},
                        {RPCResult::Type::NUM, "recent_count", "Recent Shadow claim samples tracked for PoW retargeting"},
                        {RPCResult::Type::NUM, "pow_target_bits", "Current PoW target bits"},
                    }},
                RPCExamples{
                    HelpExampleCli("getgoldrushstate", "")
            + HelpExampleRpc("getgoldrushstate", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CBlockIndex* pindex = active_chainstate.m_chain.Tip();
    if (!pindex) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Chain is not initialized or still downloading");
    }

    ShadowGoldRushInfo info = GetShadowGoldRushInfo(active_chainstate.CoinsTip(), pindex);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("pow_amount", info.pow_amount);
    obj.pushKV("pos_amount", info.pos_amount);
    obj.pushKV("claimed_amount", info.claimed_amount);
    obj.pushKV("pow_count", info.pow_count);
    obj.pushKV("pos_count", info.pos_count);
    obj.pushKV("last_pow_height", info.last_pow_height);
    obj.pushKV("last_pos_height", info.last_pos_height);
    obj.pushKV("recent_count", info.recent_count);
    obj.pushKV("pow_target_bits", (uint64_t)info.pow_target_bits);

    return obj;
},
    };
}

static node::QuantumPoolClaim ParseQuantumPoolClaim(const UniValue& obj, const uint256& staker_pubkey_hash)
{
    if (!obj.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegation claim must be an object");
    }

    const UniValue& txid = obj.find_value("txid");
    const UniValue& vout = obj.find_value("vout");
    const UniValue& owner_pubkey_value = obj.find_value("owner_pubkey");
    if (txid.isNull() || vout.isNull() || owner_pubkey_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegation claim requires txid, vout, and owner_pubkey");
    }

    const std::vector<unsigned char> owner_pubkey = ParseHexV(owner_pubkey_value, "owner_pubkey");
    if (owner_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("owner_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }

    node::QuantumPoolClaim claim;
    claim.outpoint = COutPoint{ParseHashV(txid, "txid"), vout.getInt<uint32_t>()};
    claim.staker_pubkey_hash = staker_pubkey_hash;
    claim.owner_pubkey_hash = node::QuantumPoolHashPubKey(owner_pubkey);
    claim.tiered = obj.exists("tiered") && obj["tiered"].get_bool();
    if (claim.tiered) {
        claim.state = obj.exists("state") ? obj["state"].getInt<unsigned char>() : QUANTUM_TIERED_STATE_BONDED;
        claim.unbonding_blocks = obj.exists("unbonding_blocks") ? obj["unbonding_blocks"].getInt<uint16_t>() : 0;
        claim.unlock_height = obj.exists("unlock_height") ? obj["unlock_height"].getInt<uint32_t>() : 0;
    }
    return claim;
}

static UniValue QuantumPoolOperatorShareToJSON(const node::QuantumPoolShare& share, CAmount prospective_amount = 0)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("staking_pubkey_hash", share.operator_share.staker_pubkey_hash.GetHex());
    if (!share.operator_share.staker_pubkey.empty()) {
        obj.pushKV("staking_pubkey", HexStr(share.operator_share.staker_pubkey));
    }
    obj.pushKV("verified_value", ValueFromAmount(share.operator_share.verified_value));
    obj.pushKV("share_bps", node::QuantumPoolShareBps(share.operator_share.verified_value, share.total_coldstake));
    obj.pushKV("verified_claims", share.operator_share.verified_claims);
    obj.pushKV("invalid_claims", share.operator_share.invalid_claims);
    obj.pushKV("operator_commitment_verified", share.operator_share.operator_commitment_verified);
    obj.pushKV("over_cap", node::WouldQuantumPoolExceedCap(share.total_coldstake, share.operator_share.verified_value, 0));
    if (prospective_amount > 0) {
        obj.pushKV("prospective_amount", ValueFromAmount(prospective_amount));
        obj.pushKV("would_exceed_cap", node::WouldQuantumPoolExceedCap(share.total_coldstake, share.operator_share.verified_value, prospective_amount));
    }
    return obj;
}

static RPCHelpMan submitquantumpoolclaim()
{
    return RPCHelpMan{"submitquantumpoolclaim",
                "\nRegister a non-consensus Quantum Cold-Stake pool discovery claim for this node.\n"
                "The node verifies each advertised delegation against the active chainstate by recomputing\n"
                "the existing hidden QCS commitment from staking/owner public keys and checking the live UTXO.\n"
                "Invalid claims are not accepted into the local registry. This RPC does not affect consensus.\n",
                {
                    {"staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Operator/staker ML-DSA-44 public key."},
                    {"delegations", RPCArg::Type::ARR, RPCArg::Optional::NO, "Advertised delegation UTXOs for this operator.", {
                        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Delegation claim", {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id containing the cold-stake UTXO."},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index of the cold-stake UTXO."},
                            {"owner_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Owner/cold-wallet ML-DSA-44 public key committed by the QCS output."},
                            {"tiered", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether the output uses the tiered QCS witness program."},
                            {"state", RPCArg::Type::NUM, RPCArg::Default{QUANTUM_TIERED_STATE_BONDED}, "Tiered QCS state byte."},
                            {"unbonding_blocks", RPCArg::Type::NUM, RPCArg::Default{0}, "Tiered QCS unbonding delay."},
                            {"unlock_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Tiered QCS unlock height."},
                        }},
                    }},
                    {"operator_commitment", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Optional live Operator-tier self-stake proof for redelegation candidate eligibility.", {
                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Transaction id containing the bonded Operator-tier quantum UTXO."},
                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index of the bonded Operator-tier quantum UTXO."},
                    }},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::BOOL, "accepted", "True when all claims verify and the registry was updated."},
                    {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                    {RPCResult::Type::STR_AMOUNT, "total_coldstake", "Total live cold-stake UTXO value in chainstate."},
                    {RPCResult::Type::OBJ, "operator", "Verified operator share.", {
                        {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                        {RPCResult::Type::STR_HEX, "staking_pubkey", /*optional=*/true, "Operator/staker ML-DSA public key."},
                        {RPCResult::Type::STR_AMOUNT, "verified_value", "Verified live value claimed by this operator."},
                        {RPCResult::Type::NUM, "share_bps", "Verified share of cold-staked value in basis points."},
                        {RPCResult::Type::NUM, "verified_claims", "Number of accepted claim UTXOs."},
                        {RPCResult::Type::NUM, "invalid_claims", "Number of rejected claim UTXOs."},
                        {RPCResult::Type::BOOL, "operator_commitment_verified", "Whether this operator has a live 40,500-block bonded self-stake proof."},
                        {RPCResult::Type::BOOL, "over_cap", "Whether the verified current share is over the wallet/policy cap."},
                    }},
                }},
                RPCExamples{
                    HelpExampleCli("submitquantumpoolclaim", "\"<staking_pubkey>\" '[{\"txid\":\"<txid>\",\"vout\":0,\"owner_pubkey\":\"<owner_pubkey>\"}]'")
            + HelpExampleRpc("submitquantumpoolclaim", "\"<staking_pubkey>\", [{\"txid\":\"<txid>\",\"vout\":0,\"owner_pubkey\":\"<owner_pubkey>\"}]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::vector<unsigned char> staking_pubkey = ParseHexV(request.params[0], "staking_pubkey");
    if (staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }
    const uint256 staker_hash = node::QuantumPoolHashPubKey(staking_pubkey);

    const UniValue& delegations = request.params[1].get_array();
    std::vector<node::QuantumPoolClaim> claims;
    claims.reserve(delegations.size());
    for (const UniValue& delegation : delegations.getValues()) {
        claims.push_back(ParseQuantumPoolClaim(delegation, staker_hash));
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
    bool operator_commitment_verified{false};
    COutPoint operator_commitment_outpoint;
    const UniValue operator_commitment = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
    if (operator_commitment.exists("txid") || operator_commitment.exists("vout")) {
        if (!operator_commitment.exists("txid") || !operator_commitment.exists("vout")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operator_commitment requires both txid and vout");
        }
        operator_commitment_outpoint = COutPoint{
            ParseHashV(operator_commitment["txid"], "operator_commitment.txid"),
            operator_commitment["vout"].getInt<uint32_t>()};
        operator_commitment_verified = node::VerifyQuantumPoolOperatorCommitment(view, staking_pubkey, operator_commitment_outpoint);
    }

    if (delegations.empty() && !operator_commitment_verified) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegations must not be empty unless a live operator_commitment is provided");
    }

    const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, claims);
    const bool accepted = share.operator_share.invalid_claims == 0 &&
                          (share.operator_share.verified_claims > 0 || operator_commitment_verified);

    if (accepted) {
        node::UpsertQuantumPoolOperator(staker_hash, staking_pubkey, std::move(claims), operator_commitment_verified, operator_commitment_outpoint);
    }

    node::QuantumPoolShare response_share = share;
    response_share.operator_share.staker_pubkey = staking_pubkey;
    response_share.operator_share.operator_commitment_verified = operator_commitment_verified;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("accepted", accepted);
    obj.pushKV("staking_pubkey_hash", staker_hash.GetHex());
    obj.pushKV("total_coldstake", ValueFromAmount(share.total_coldstake));
    obj.pushKV("operator", QuantumPoolOperatorShareToJSON(response_share));
    return obj;
},
    };
}

static RPCHelpMan getquantumpoolinfo()
{
    return RPCHelpMan{"getquantumpoolinfo",
                "\nReturn non-consensus Quantum Cold-Stake pool share information from the local discovery registry.\n"
                "The denominator is recomputed from active chainstate. Each operator numerator is recomputed\n"
                "from locally registered discovery claims and verified against live QCS UTXOs.\n",
                {
                    {"staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"all registered operators"}, "Optional operator/staker ML-DSA public key to report or preflight."},
                    {"prospective_amount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"none"}, "Optional new delegation amount to test against the wallet/policy cap."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_AMOUNT, "total_coldstake", "Total live cold-stake UTXO value in chainstate."},
                    {RPCResult::Type::NUM, "cap_bps", "Wallet/policy cap in basis points."},
                    {RPCResult::Type::NUM, "operator_count", "Operators reported."},
                    {RPCResult::Type::ARR, "operators", "Operator share entries.", {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                            {RPCResult::Type::STR_HEX, "staking_pubkey", /*optional=*/true, "Operator/staker ML-DSA public key."},
                            {RPCResult::Type::STR_AMOUNT, "verified_value", "Verified live value claimed by this operator."},
                            {RPCResult::Type::NUM, "share_bps", "Verified share of cold-staked value in basis points."},
                            {RPCResult::Type::NUM, "verified_claims", "Number of accepted claim UTXOs."},
                            {RPCResult::Type::NUM, "invalid_claims", "Number of rejected claim UTXOs."},
                            {RPCResult::Type::BOOL, "operator_commitment_verified", "Whether this operator has a live 40,500-block bonded self-stake proof."},
                            {RPCResult::Type::BOOL, "over_cap", "Whether the verified current share is over the wallet/policy cap."},
                            {RPCResult::Type::STR_AMOUNT, "prospective_amount", /*optional=*/true, "Prospective delegation amount."},
                            {RPCResult::Type::BOOL, "would_exceed_cap", /*optional=*/true, "Whether the prospective delegation would exceed the cap."},
                        }},
                    }},
                }},
                RPCExamples{
                    HelpExampleCli("getquantumpoolinfo", "")
            + HelpExampleRpc("getquantumpoolinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::optional<uint256> requested_staker;
    if (!request.params[0].isNull()) {
        const std::vector<unsigned char> staking_pubkey = ParseHexV(request.params[0], "staking_pubkey");
        if (staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
        }
        requested_staker = node::QuantumPoolHashPubKey(staking_pubkey);
    }
    const CAmount prospective_amount = request.params[1].isNull() ? 0 : AmountFromValue(request.params[1]);
    if (prospective_amount < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "prospective_amount cannot be negative");
    }

    std::vector<uint256> operators;
    if (requested_staker) {
        operators.push_back(*requested_staker);
    } else {
        operators = node::ListQuantumPoolOperators();
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
    const CAmount total = node::ComputeQuantumColdStakeTotal(view);

    UniValue entries(UniValue::VARR);
    for (const uint256& staker_hash : operators) {
        const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));
        entries.push_back(QuantumPoolOperatorShareToJSON(share, requested_staker ? prospective_amount : 0));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("total_coldstake", ValueFromAmount(total));
    obj.pushKV("cap_bps", node::QUANTUM_POOL_CAP_BPS);
    obj.pushKV("operator_count", entries.size());
    obj.pushKV("operators", entries);
    return obj;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{"getchaintxstats",
                "\nCompute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", "The total number of transactions in the chain up to that point"},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true, "The number of transactions in the window. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true, "The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0"},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / chainman.GetParams().GetConsensus().nTargetSpacing; // By default: 1 month

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].getInt<int>();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
    const int64_t nTimeDiff{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};
    const int nTxDiff = pindex->nChainTx - past_block.nChainTx;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    ret.pushKV("txcount", (int64_t)pindex->nChainTx);
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_tx_count", nTxDiff);
        ret.pushKV("window_interval", nTimeDiff);
        if (nTimeDiff > 0) {
            ret.pushKV("txrate", ((double)nTxDiff) / nTimeDiff);
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static CAmount GetUndoAwareBlockSubsidy(const CBlockIndex& pindex, const CBlock& block, const CBlockUndo& blockUndo, const Consensus::Params& consensus)
{
    if (!block.IsProofOfStake()) {
        return GetBlockSubsidy(pindex.nHeight, consensus, /*fProofOfStake=*/false);
    }

    const int64_t mtp = pindex.pprev ? pindex.pprev->GetMedianTimePast() : pindex.GetBlockTime();
    const bool coldstake_active = consensus.IsProtocolV4(mtp);
    const bool coldstake = coldstake_active &&
                           block.vtx.size() > 1 &&
                           blockUndo.vtxundo.size() > 0 &&
                           HasColdStakeInputs(*block.vtx[1], blockUndo.vtxundo.front());
    return GetProofOfStakeSubsidyForCoinstake(coldstake);
}

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{"getblockstats",
                "\nCompute per block statistics for a given window. All amounts are in satoshis.\n"
                "Block subsidy won't be shown correctly for proof-of-stake blocks with dynamic reward (before PoSv3).\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description="stats"}},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex& pindex{*CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman))};

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    const CBlock& block = GetBlockChecked(chainman.m_blockman, &pindex);
    const CBlockUndo& blockUndo = GetUndoChecked(chainman.m_blockman, &pindex);

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_increase", "utxo_increase_actual", "utxo_size_inc", "utxo_size_inc_actual", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxos = 0;
    int64_t utxo_size_inc = 0;
    int64_t utxo_size_inc_actual = 0;
    std::vector<CAmount> fee_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        if (loop_outputs) {
            for (const CTxOut& out : tx->vout) {
                tx_total_out += out.nValue;

                size_t out_size = GetSerializeSize(out) + PER_UTXO_OVERHEAD;
                utxo_size_inc += out_size;

                // The Genesis block doesn't change the UTXO
                // set counts, so they have to be excluded from the statistics
                if (pindex.nHeight == 0) continue;
                // Skip unspendable outputs since they are not included in the UTXO set
                if (out.scriptPubKey.IsUnspendable()) continue;

                ++utxos;
                utxo_size_inc_actual += out_size;
            }
        }

        if (tx->IsCoinBase() || tx->IsCoinStake()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in = 0;
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += prevoutput.nValue;
                size_t prevout_size = GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD;
                utxo_size_inc -= prevout_size;
                utxo_size_inc_actual -= prevout_size;
            }

            CAmount txfee = tx_total_in - tx_total_out;
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex.GetBlockHash().GetHex());
    ret_all.pushKV("height", (int64_t)pindex.nHeight);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", pindex.GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", GetUndoAwareBlockSubsidy(pindex, block, blockUndo, chainman.GetParams().GetConsensus()));
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", pindex.GetBlockTime());
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);
    ret_all.pushKV("utxo_increase_actual", utxos - inputs);
    ret_all.pushKV("utxo_size_inc_actual", utxo_size_inc_actual);

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *key.hash.begin() + *(key.hash.begin() + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit CoinsViewScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress.exchange(true)) {
            return false;
        }
        CHECK_NONFATAL(g_scan_progress == 0);
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            g_scan_in_progress = false;
            g_scan_progress = 0;
        }
    }
};

static const auto scan_action_arg_desc = RPCArg{
    "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
};

static const auto scan_objects_arg_desc = RPCArg{
    "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
    {
        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
            {
                {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
            }},
    },
    RPCArgOptions{.oneline_description="[scanobjects,...]"},
};

static const auto scan_result_abort = RPCResult{
    "when action=='abort'", RPCResult::Type::BOOL, "success",
    "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
};
static const auto scan_result_status_none = RPCResult{
    "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
};
static const auto scan_result_status_some = RPCResult{
    "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
    {{RPCResult::Type::NUM, "progress", "Approximate percent complete"},}
};


static RPCHelpMan scantxoutset()
{
    // scriptPubKey corresponding to mainnet address 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

    return RPCHelpMan{"scantxoutset",
        "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                      Outputs whose scriptPubKey corresponds to the specified address (does not include P2PK)\n"
        "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
        "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
        "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
        "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
        "    tr(<pubkey>)                         P2TR\n"
        "    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript\n"
        "    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner\n"
        "    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
        },
        {
            RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The current block height (index)"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The script key"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched scriptPubKey"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                    }},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
            scan_result_abort,
            scan_result_status_some,
            scan_result_status_none,
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return UniValue::VNULL;
        }
        result.pushKV("progress", g_scan_progress.load());
        return result;
    } else if (request.params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params.size() < 2) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (CScript& script : scripts) {
                std::string inferred = InferDescriptor(script, provider)->ToString();
                needles.emplace(script);
                descriptors.emplace(std::move(script), std::move(inferred));
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        const CBlockIndex* tip;
        NodeContext& node = EnsureAnyNodeContext(request.context);
        {
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
            pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
            tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
        result.pushKV("success", res);
        result.pushKV("txouts", count);
        result.pushKV("height", tip->nHeight);
        result.pushKV("bestblock", tip->GetBlockHash().GetHex());

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            input_txos.push_back(txo);
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", (int32_t)outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("coinbase", coin.IsCoinBase());
            unspent.pushKV("height", (int32_t)coin.nHeight);

            unspents.push_back(unspent);
        }
        result.pushKV("unspents", unspents);
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
    }
    return result;
},
    };
}

/** RAII object to prevent concurrency issue when scanning blockfilters */
static std::atomic<int> g_scanfilter_progress;
static std::atomic<int> g_scanfilter_progress_height;
static std::atomic<bool> g_scanfilter_in_progress;
static std::atomic<bool> g_scanfilter_should_abort_scan;
class BlockFiltersScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit BlockFiltersScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scanfilter_in_progress.exchange(true)) {
            return false;
        }
        m_could_reserve = true;
        return true;
    }

    ~BlockFiltersScanReserver() {
        if (m_could_reserve) {
            g_scanfilter_in_progress = false;
        }
    }
};

static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const GCSFilter::ElementSet& needles)
{
    const CBlock block{GetBlockChecked(blockman, &blockindex)};
    const CBlockUndo block_undo{GetUndoChecked(blockman, &blockindex)};

    // Check if any of the outputs match the scriptPubKey
    for (const auto& tx : block.vtx) {
        if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                return needles.count(std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }
    // Check if any of the inputs match the scriptPubKey
    for (const auto& txundo : block_undo.vtxundo) {
        if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                return needles.count(std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }

    return false;
}

static RPCHelpMan scanblocks()
{
    return RPCHelpMan{"scanblocks",
        "\nReturn relevant blockhashes for given descriptors (requires blockfilterindex).\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
            RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
            RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            RPCArg{"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        {
            scan_result_status_none,
            RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                    {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                }},
                {RPCResult::Type::BOOL, "completed", "true if the scan process was not aborted"}
            }},
            RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                },
            },
            scan_result_abort,
        },
        RPCExamples{
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 300000") +
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 100 150 basic") +
            HelpExampleCli("scanblocks", "status") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 300000") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 100, 150, \"basic\"") +
            HelpExampleRpc("scanblocks", "\"status\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        ret.pushKV("progress", g_scanfilter_progress.load());
        ret.pushKV("current_height", g_scanfilter_progress_height.load());
        return ret;
    } else if (request.params[0].get_str() == "abort") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_scanfilter_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        BlockFiltersScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        const std::string filtertype_name{request.params[4].isNull() ? "basic" : request.params[4].get_str()};

        BlockFilterType filtertype;
        if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        UniValue options{request.params[5].isNull() ? UniValue::VOBJ : request.params[5]};
        bool filter_false_positives{options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false};

        BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
        }

        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureChainman(node);

        // set the start-height
        const CBlockIndex* start_index = nullptr;
        const CBlockIndex* stop_block = nullptr;
        {
            LOCK(cs_main);
            CChain& active_chain = chainman.ActiveChain();
            start_index = active_chain.Genesis();
            stop_block = active_chain.Tip(); // If no stop block is provided, stop at the chain tip.
            if (!request.params[2].isNull()) {
                start_index = active_chain[request.params[2].getInt<int>()];
                if (!start_index) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid start_height");
                }
            }
            if (!request.params[3].isNull()) {
                stop_block = active_chain[request.params[3].getInt<int>()];
                if (!stop_block || stop_block->nHeight < start_index->nHeight) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid stop_height");
                }
            }
        }
        CHECK_NONFATAL(start_index);
        CHECK_NONFATAL(stop_block);

        // loop through the scan objects, add scripts to the needle_set
        GCSFilter::ElementSet needle_set;
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const CScript& script : scripts) {
                needle_set.emplace(script.begin(), script.end());
            }
        }
        UniValue blocks(UniValue::VARR);
        const int amount_per_chunk = 10000;
        std::vector<BlockFilter> filters;
        int start_block_height = start_index->nHeight; // for progress reporting
        const int total_blocks_to_process = stop_block->nHeight - start_block_height;

        g_scanfilter_should_abort_scan = false;
        g_scanfilter_progress = 0;
        g_scanfilter_progress_height = start_block_height;
        bool completed = true;

        const CBlockIndex* end_range = nullptr;
        do {
            node.rpc_interruption_point(); // allow a clean shutdown
            if (g_scanfilter_should_abort_scan) {
                completed = false;
                break;
            }

            // split the lookup range in chunks if we are deeper than 'amount_per_chunk' blocks from the stopping block
            int start_block = !end_range ? start_index->nHeight : start_index->nHeight + 1; // to not include the previous round 'end_range' block
            end_range = (start_block + amount_per_chunk < stop_block->nHeight) ?
                    WITH_LOCK(::cs_main, return chainman.ActiveChain()[start_block + amount_per_chunk]) :
                    stop_block;

            if (index->LookupFilterRange(start_block, end_range, filters)) {
                for (const BlockFilter& filter : filters) {
                    // compare the elements-set with each filter
                    if (filter.GetFilter().MatchAny(needle_set)) {
                        if (filter_false_positives) {
                            // Double check the filter matches by scanning the block
                            const CBlockIndex& blockindex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                            if (!CheckBlockFilterMatches(chainman.m_blockman, blockindex, needle_set)) {
                                continue;
                            }
                        }

                        blocks.push_back(filter.GetBlockHash().GetHex());
                    }
                }
            }
            start_index = end_range;

            // update progress
            int blocks_processed = end_range->nHeight - start_block_height;
            if (total_blocks_to_process > 0) { // avoid division by zero
                g_scanfilter_progress = (int)(100.0 / total_blocks_to_process * blocks_processed);
            } else {
                g_scanfilter_progress = 100;
            }
            g_scanfilter_progress_height = end_range->nHeight;

        // Finish if we reached the stop block
        } while (start_index != stop_block);

        ret.pushKV("from_height", start_block_height);
        ret.pushKV("to_height", start_index->nHeight); // start_index is always the last scanned block here
        ret.pushKV("relevant_blocks", blocks);
        ret.pushKV("completed", completed);
    }
    else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
    }
    return ret;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{"getblockfilter",
                "\nRetrieve a BIP 157 content filter for a particular block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    std::string filtertype_name = BlockFilterTypeName(BlockFilterType::BASIC);
    if (!request.params[1].isNull()) {
        filtertype_name = request.params[1].get_str();
    }

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to disk.",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
        },
        RPCExamples{
            HelpExampleCli("dumptxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.u8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + temppath.u8string() + " for writing.");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    UniValue result = CreateUTXOSnapshot(
        node, node.chainman->ActiveChainstate(), afile, path, temppath);
    fs::rename(temppath, path);

    result.pushKV("path", path.u8string());
    return result;
},
    };
}

UniValue CreateUTXOSnapshot(
    NodeContext& node,
    Chainstate& chainstate,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& temppath)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    std::optional<CCoinsStats> maybe_stats;
    const CBlockIndex* tip;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use below this block.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        LOCK(::cs_main);

        chainstate.ForceFlushStateToDisk();

        maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::HASH_SERIALIZED, node.rpc_interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybe_stats->hashBlock));
    }

    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{tip->GetBlockHash(), maybe_stats->coins_count};

    afile << metadata;

    COutPoint key;
    Coin coin;
    unsigned int iter{0};
    uint64_t coins_written{0};

    while (pcursor->Valid()) {
        if (iter % 5000 == 0) node.rpc_interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (kernel::IsQuantumQuasarInternalMarkerScript(coin.out.scriptPubKey)) {
                pcursor->Next();
                continue;
            }
            afile << key;
            afile << coin;
            ++coins_written;
        }

        pcursor->Next();
    }

    afile.fclose();

    if (coins_written != maybe_stats->coins_count) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf(
            "UTXO snapshot writer serialized %u coins, but the hash/count pass reported %u",
            coins_written, maybe_stats->coins_count));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", maybe_stats->coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.u8string());
    result.pushKV("txoutset_hash", maybe_stats->hashSerialized.ToString());
    result.pushKV("nchaintx", tip->nChainTx);
    return result;
}

static RPCHelpMan loadtxoutset()
{
    return RPCHelpMan{
        "loadtxoutset",
        "Load the serialized UTXO set from disk.\n"
        "Once this snapshot is loaded, its contents will be "
        "deserialized into a second chainstate data structure, which is then used to sync to "
        "the network's tip. "
        "Meanwhile, the original chainstate will complete the initial block download process in "
        "the background, eventually validating up to the block that the snapshot is based upon.\n\n"

        "The result is a usable bitcoind instance that is current with the network tip in a "
        "matter of minutes rather than hours. UTXO snapshot are typically obtained from "
        "third-party sources (HTTP, torrent, etc.) which is reasonable since their "
        "contents are always checked by hash.\n\n"

        "You can find more information on this process in the `assumeutxo` design "
        "document (<https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md>).",
        {
            {"path",
                RPCArg::Type::STR,
                RPCArg::Optional::NO,
                "path to the snapshot file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the snapshot"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was loaded from"},
                }
        },
        RPCExamples{
            HelpExampleCli("loadtxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    fs::path path{AbsPathForConfigVal(EnsureArgsman(node), fs::u8path(request.params[0].get_str()))};

    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.u8string() + " for reading.");
    }

    SnapshotMetadata metadata;
    afile >> metadata;

    uint256 base_blockhash = metadata.m_base_blockhash;
    if (!chainman.GetParams().AssumeutxoForBlockhash(base_blockhash).has_value()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to load UTXO snapshot, "
            "assumeutxo block hash in snapshot metadata not recognized (%s)", base_blockhash.ToString()));
    }
    int max_secs_to_wait_for_headers = 60 * 10;
    CBlockIndex* snapshot_start_block = nullptr;

    LogPrintf("[snapshot] waiting to see blockheader %s in headers chain before snapshot activation\n",
        base_blockhash.ToString());

    while (max_secs_to_wait_for_headers > 0) {
        snapshot_start_block = WITH_LOCK(::cs_main,
            return chainman.m_blockman.LookupBlockIndex(base_blockhash));
        max_secs_to_wait_for_headers -= 1;

        if (!IsRPCRunning()) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        }

        if (!snapshot_start_block) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            break;
        }
    }

    if (!snapshot_start_block) {
        LogPrintf("[snapshot] timed out waiting for snapshot start blockheader %s\n",
            base_blockhash.ToString());
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            "Timed out waiting for base block header to appear in headers chain");
    }
    if (!chainman.ActivateSnapshot(afile, metadata, false)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to load UTXO snapshot " + fs::PathToString(path));
    }
    CBlockIndex* new_tip{WITH_LOCK(::cs_main, return chainman.ActiveTip())};

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", new_tip->GetBlockHash().ToString());
    result.pushKV("base_height", new_tip->nHeight);
    result.pushKV("path", fs::PathToString(path));
    return result;
},
    };
}

const std::vector<RPCResult> RPCHelpForChainstate{
    {RPCResult::Type::NUM, "blocks", "number of blocks in this chainstate"},
    {RPCResult::Type::STR_HEX, "bestblockhash", "blockhash of the tip"},
    {RPCResult::Type::NUM, "difficulty", "difficulty of the tip"},
    {RPCResult::Type::NUM, "verificationprogress", "progress towards the network tip"},
    {RPCResult::Type::STR_HEX, "snapshot_blockhash", /*optional=*/true, "the base block of the snapshot this chainstate is based on, if any"},
    {RPCResult::Type::NUM, "coins_db_cache_bytes", "size of the coinsdb cache"},
    {RPCResult::Type::NUM, "coins_tip_cache_bytes", "size of the coinstip cache"},
    {RPCResult::Type::BOOL, "validated", "whether the chainstate is fully validated. True if all blocks in the chainstate were validated, false if the chain is based on a snapshot and the snapshot has not yet been validated."},
};

static RPCHelpMan getchainstates()
{
return RPCHelpMan{
        "getchainstates",
        "\nReturn information about chainstates.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "headers", "the number of headers seen so far"},
                {RPCResult::Type::ARR, "chainstates", "list of the chainstates ordered by work, with the most-work (active) chainstate last", {{RPCResult::Type::OBJ, "", "", RPCHelpForChainstate},}},
            }
        },
        RPCExamples{
            HelpExampleCli("getchainstates", "")
    + HelpExampleRpc("getchainstates", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto make_chain_data = [&](const Chainstate& cs, bool validated) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        UniValue data(UniValue::VOBJ);
        if (!cs.m_chain.Tip()) {
            return data;
        }
        const CChain& chain = cs.m_chain;
        const CBlockIndex* tip = chain.Tip();

        data.pushKV("blocks",                (int)chain.Height());
        data.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
        data.pushKV("difficulty",            (double)GetDifficulty(tip));
        data.pushKV("verificationprogress",  GuessVerificationProgress(Params().TxData(), tip));
        data.pushKV("coins_db_cache_bytes",  cs.m_coinsdb_cache_size_bytes);
        data.pushKV("coins_tip_cache_bytes", cs.m_coinstip_cache_size_bytes);
        if (cs.m_from_snapshot_blockhash) {
            data.pushKV("snapshot_blockhash", cs.m_from_snapshot_blockhash->ToString());
        }
        data.pushKV("validated", validated);
        return data;
    };

    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);

    const auto& chainstates = chainman.GetAll();
    UniValue obj_chainstates{UniValue::VARR};
    for (Chainstate* cs : chainstates) {
      obj_chainstates.push_back(make_chain_data(*cs, !cs->m_from_snapshot_blockhash || chainstates.size() == 1));
    }
    obj.pushKV("chainstates", std::move(obj_chainstates));
    return obj;
}
    };
}


void RegisterBlockchainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getblockchaininfo},
        {"blockchain", &getgoldrushstate},
        {"blockchain", &submitquantumpoolclaim},
        {"blockchain", &getquantumpoolinfo},
        {"blockchain", &getchaintxstats},
        {"blockchain", &getblockstats},
        {"blockchain", &getbestblockhash},
        {"blockchain", &getblockcount},
        {"blockchain", &getblock},
        {"blockchain", &getblockfrompeer},
        {"blockchain", &getblockhash},
        {"blockchain", &getblockheader},
        {"blockchain", &getchaintips},
        {"blockchain", &getdifficulty},
        {"blockchain", &getdeploymentinfo},
        {"blockchain", &getquantumquasarinfo},
        {"blockchain", &gettxout},
        {"blockchain", &gettxoutsetinfo},
        {"blockchain", &getcirculatingsupply},
        {"blockchain", &verifychain},
        {"blockchain", &preciousblock},
        {"blockchain", &scantxoutset},
        {"blockchain", &scanblocks},
        {"blockchain", &getblockfilter},
        {"blockchain", &dumptxoutset},
        {"blockchain", &loadtxoutset},
        {"blockchain", &getchainstates},
        {"hidden", &invalidateblock},
        {"hidden", &reconsiderblock},
        {"hidden", &waitfornewblock},
        {"hidden", &waitforblock},
        {"hidden", &waitforblockheight},
        {"hidden", &syncwithvalidationinterfacequeue},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
