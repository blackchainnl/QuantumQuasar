// Copyright (c) 2016-2022 Blackcoin Core Developers
// Copyright (c) 2016-2022 Blackcoin More Developers
// Copyright (c) 2016-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <rpc/blockchain.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <univalue.h>

namespace {

struct TestBlockAndIndex {
    const std::unique_ptr<const TestingSetup> testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST)};
    CBlock block{};
    uint256 blockHash{};
    CBlockIndex blockindex{};

    TestBlockAndIndex()
    {
        const auto blocks{CreateBlockChain(1, testing_setup->m_node.chainman->GetParams())};
        block = *blocks.at(0);

        blockHash = block.GetHash();
        blockindex.phashBlock = &blockHash;
        blockindex.nHeight = 1;
        blockindex.nVersion = block.nVersion;
        blockindex.hashMerkleRoot = block.hashMerkleRoot;
        blockindex.nTime = block.nTime;
        blockindex.nBits = block.nBits;
        blockindex.nNonce = block.nNonce;
        blockindex.nFlags = block.nFlags;
        blockindex.nTx = block.vtx.size();
    }
};

} // namespace

static void BlockToJsonVerbose(benchmark::Bench& bench)
{
    TestBlockAndIndex data;
    bench.run([&] {
        auto univalue = blockToJSON(data.testing_setup->m_node.chainman->m_blockman, data.block, &data.blockindex, &data.blockindex, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
        ankerl::nanobench::doNotOptimizeAway(univalue);
    });
}

BENCHMARK(BlockToJsonVerbose, benchmark::PriorityLevel::HIGH);

static void BlockToJsonVerboseWrite(benchmark::Bench& bench)
{
    TestBlockAndIndex data;
    auto univalue = blockToJSON(data.testing_setup->m_node.chainman->m_blockman, data.block, &data.blockindex, &data.blockindex, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    bench.run([&] {
        auto str = univalue.write();
        ankerl::nanobench::doNotOptimizeAway(str);
    });
}

BENCHMARK(BlockToJsonVerboseWrite, benchmark::PriorityLevel::HIGH);
