// Copyright (c) 2011-2022 Blackcoin Core Developers
// Copyright (c) 2011-2022 Blackcoin More Developers
// Copyright (c) 2011-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <node/miner.h>
#include <random.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <validation.h>

#include <stdexcept>
#include <vector>

static void AssembleBlock(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST);

    CScriptWitness witness;
    witness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);

    // Collect some loose transactions that spend the coinbases of our mined blocks
    constexpr size_t NUM_BLOCKS{1000};
    const size_t coinbase_maturity{static_cast<size_t>(Params().GetConsensus().nCoinbaseMaturity)};
    std::vector<CTransactionRef> txs;
    txs.reserve(NUM_BLOCKS > coinbase_maturity ? NUM_BLOCKS - coinbase_maturity + 1 : 0);
    for (size_t b{0}; b < NUM_BLOCKS; ++b) {
        CMutableTransaction tx;
        tx.vin.emplace_back(MineBlock(test_setup->m_node, P2WSH_OP_TRUE));
        tx.vin.back().scriptWitness = witness;
        tx.vout.emplace_back(COIN, P2WSH_OP_TRUE);
        if (NUM_BLOCKS - b >= coinbase_maturity) {
            txs.push_back(MakeTransactionRef(tx));
        }
    }
    {
        LOCK(::cs_main);

        for (const auto& txr : txs) {
            const MempoolAcceptResult res = test_setup->m_node.chainman->ProcessTransaction(txr);
            if (res.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                throw std::runtime_error(strprintf("AssembleBlock setup transaction %s rejected: %s", txr->GetHash().ToString(), res.m_state.ToString()));
            }
        }
    }

    bench.run([&] {
        PrepareBlock(test_setup->m_node, P2WSH_OP_TRUE);
    });
}
static void BlockAssemblerAddPackageTxns(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    testing_setup->PopulateMempool(det_rand, /*num_transactions=*/1000, /*submit=*/true);
    node::BlockAssembler::Options assembler_options;
    assembler_options.test_block_validity = false;

    bench.run([&] {
        PrepareBlock(testing_setup->m_node, P2WSH_OP_TRUE, assembler_options);
    });
}

BENCHMARK(AssembleBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(BlockAssemblerAddPackageTxns, benchmark::PriorityLevel::LOW);
