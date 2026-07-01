// Copyright (c) 2016-2022 Blackcoin Core Developers
// Copyright (c) 2016-2022 Blackcoin More Developers
// Copyright (c) 2016-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <chainparams.h>
#include <common/args.h>
#include <consensus/validation.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

namespace {

CDataStream NativeBlockStream(const CChainParams& params)
{
    const auto blocks{CreateBlockChain(1, params)};
    CDataStream stream(SER_NETWORK);
    stream << TX_WITH_WITNESS(*blocks.at(0));
    return stream;
}

} // namespace

// These are the two major time-sinks which happen after we have fully received
// a block off the wire, but before we can relay the block on to peers using
// compact block relay.

static void DeserializeBlockTest(benchmark::Bench& bench)
{
    ArgsManager bench_args;
    const auto chainParams = CreateChainParams(bench_args, ChainType::REGTEST);
    CDataStream stream{NativeBlockStream(*chainParams)};
    const size_t block_data_size{stream.size()};
    std::byte a{0};
    stream.write({&a, 1}); // Prevent compaction

    bench.unit("block").run([&] {
        CBlock block;
        stream >> TX_WITH_WITNESS(block);
        bool rewound = stream.Rewind(block_data_size);
        assert(rewound);
    });
}

static void DeserializeAndCheckBlockTest(benchmark::Bench& bench)
{
    ArgsManager bench_args;
    const auto chainParams = CreateChainParams(bench_args, ChainType::REGTEST);
    CDataStream stream{NativeBlockStream(*chainParams)};
    const size_t block_data_size{stream.size()};
    std::byte a{0};
    stream.write({&a, 1}); // Prevent compaction

    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST);
    Chainstate& chainstate = testing_setup->m_node.chainman->ActiveChainstate();

    bench.unit("block").run([&] {
        CBlock block; // Note that CBlock caches its checked state, so we need to recreate it here
        stream >> TX_WITH_WITNESS(block);
        bool rewound = stream.Rewind(block_data_size);
        assert(rewound);

        BlockValidationState validationState;
        bool checked = CheckBlock(block, validationState, chainParams->GetConsensus(), chainstate);
        assert(checked);
    });
}

BENCHMARK(DeserializeBlockTest, benchmark::PriorityLevel::HIGH);
BENCHMARK(DeserializeAndCheckBlockTest, benchmark::PriorityLevel::HIGH);
