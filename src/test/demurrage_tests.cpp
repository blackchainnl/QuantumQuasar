// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <crypto/mldsa.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(demurrage_tests, BasicTestingSetup)

namespace {

static constexpr int64_t TEST_MIGRATION_DEADLINE_TIME = 2000;
static constexpr int64_t TEST_POST_MIGRATION_TIME = TEST_MIGRATION_DEADLINE_TIME + 1;

CScript PlainScript(unsigned char tag)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
}

CScript QuantumColdStakeScript()
{
    const std::vector<unsigned char> staker(ML_DSA::PUBLICKEY_BYTES, 0x11);
    const std::vector<unsigned char> owner(ML_DSA::PUBLICKEY_BYTES, 0x22);
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        QuantumColdStakeProgramForPubkeys(staker, owner)});
}

Coin TestCoin(CAmount value, int height, const CScript& script)
{
    return Coin{CTxOut{value, script}, height, false, false, 0};
}

CScript QuantumMigrationScriptForPubkey(const std::vector<unsigned char>& pubkey)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumMigrationProgramForPubkey(pubkey)});
}

std::vector<unsigned char> SignAttestation(const std::vector<unsigned char>& private_key, const COutPoint& replay_anchor, const std::vector<unsigned char>& public_key)
{
    const uint256 msg_hash = Consensus::DemurrageAttestationMessageHash(replay_anchor, public_key);
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(ML_DSA::Sign(private_key, msg_hash.begin(), uint256::size(), signature));
    return signature;
}

void InitTestIndex(CBlockIndex& index, int height, const uint256& block_hash)
{
    index.nHeight = height;
    index.nTime = 1000 + height;
    index.phashBlock = &block_hash;
}

Consensus::Params ActiveParams(int activation_height = 100)
{
    Consensus::Params params;
    params.nDemurrageActivationHeight = activation_height;
    params.nQuantumMigrationDeadlineTime = TEST_MIGRATION_DEADLINE_TIME;
    return params;
}

} // namespace

BOOST_AUTO_TEST_CASE(curve_boundaries_and_flooring)
{
    using namespace Consensus;

    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(0), DEMURRAGE_PPM);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_GRACE_BLOCKS), DEMURRAGE_PPM);
    BOOST_CHECK(DemurrageRemainingPpm(DEMURRAGE_GRACE_BLOCKS + 1000) < DEMURRAGE_PPM);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_ZERO_BLOCKS), 0);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_ZERO_BLOCKS + 1), 0);

    const int twelve_months = 12 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int fifteen_months = 15 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int eighteen_months = 18 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int twenty_one_months = 21 * DEMURRAGE_BLOCKS_PER_MONTH;
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(twelve_months), 888890);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(fifteen_months), 750000);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(eighteen_months), 555557);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(twenty_one_months), 305557);

    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1 * COIN, DEMURRAGE_PPM), 1 * COIN);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1 * COIN, 750000), 75000000);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1, 999999), 0);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(MAX_MONEY, DEMURRAGE_PPM), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(gate_off_and_non_retroactive_clock)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1000);
    const Coin old_coin = TestCoin(10 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x33)));

    DemurrageEvaluation before = EvaluateDemurrage(old_coin, params, /*spend_height=*/999, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!before.active);
    BOOST_CHECK_EQUAL(before.effective_value, 10 * COIN);

    DemurrageEvaluation at_activation = EvaluateDemurrage(old_coin, params, /*spend_height=*/1000, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(at_activation.active);
    BOOST_CHECK(at_activation.exempt);
    BOOST_CHECK_EQUAL(at_activation.exemption, "young");
    BOOST_CHECK_EQUAL(at_activation.inactive_blocks, 0);
    BOOST_CHECK_EQUAL(at_activation.effective_value, 10 * COIN);

    DemurrageEvaluation after_grace = EvaluateDemurrage(old_coin, params, 1000 + DEMURRAGE_GRACE_BLOCKS + 1000, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(after_grace.active);
    BOOST_CHECK(!after_grace.exempt);
    BOOST_CHECK(!after_grace.locked);
    BOOST_CHECK(after_grace.effective_value < 10 * COIN);
    BOOST_CHECK(after_grace.burned_value > 0);
}

BOOST_AUTO_TEST_CASE(activation_requires_post_migration_deadline_and_gold_rush_clamp)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    params.nDemurrageMinActivationHeight = 100;
    const Coin quantum_coin = TestCoin(10 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x34)));

    BOOST_CHECK(!params.IsDemurrageActive(/*nHeight=*/99, TEST_POST_MIGRATION_TIME));
    BOOST_CHECK(!params.IsDemurrageActive(/*nHeight=*/100, TEST_MIGRATION_DEADLINE_TIME));
    BOOST_CHECK(params.IsDemurrageActive(/*nHeight=*/100, TEST_POST_MIGRATION_TIME));

    DemurrageEvaluation before_deadline = EvaluateDemurrage(quantum_coin, params, DEMURRAGE_ZERO_BLOCKS, TEST_MIGRATION_DEADLINE_TIME);
    BOOST_CHECK(!before_deadline.active);
    BOOST_CHECK_EQUAL(before_deadline.effective_value, 10 * COIN);

    DemurrageEvaluation before_min_height = EvaluateDemurrage(quantum_coin, params, /*spend_height=*/99, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!before_min_height.active);
    BOOST_CHECK_EQUAL(before_min_height.effective_value, 10 * COIN);
}

BOOST_AUTO_TEST_CASE(exemptions_and_locked_spend_state)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    const int spend_height = 1 + DEMURRAGE_ZERO_BLOCKS;

    const Coin cold = TestCoin(5 * COIN, /*height=*/1, QuantumColdStakeScript());
    DemurrageEvaluation cold_eval = EvaluateDemurrage(cold, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(cold_eval.exempt);
    BOOST_CHECK_EQUAL(cold_eval.exemption, "coldstake");
    BOOST_CHECK_EQUAL(cold_eval.effective_value, 5 * COIN);

    const CScript treasury_script = PlainScript(0x44);
    params.m_demurrage_exempt_scripts.push_back(treasury_script);
    const Coin treasury = TestCoin(6 * COIN, /*height=*/1, treasury_script);
    DemurrageEvaluation treasury_eval = EvaluateDemurrage(treasury, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(treasury_eval.exempt);
    BOOST_CHECK_EQUAL(treasury_eval.exemption, "treasury");
    BOOST_CHECK_EQUAL(treasury_eval.effective_value, 6 * COIN);

    const Coin attested = TestCoin(7 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x55)));
    DemurrageEvaluation attested_eval = EvaluateDemurrage(attested, params, spend_height, TEST_POST_MIGRATION_TIME, spend_height - 100);
    BOOST_CHECK(attested_eval.exempt);
    BOOST_CHECK_EQUAL(attested_eval.exemption, "attested");
    BOOST_CHECK_EQUAL(attested_eval.effective_value, 7 * COIN);

    const Coin locked = TestCoin(8 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x66)));
    DemurrageEvaluation locked_eval = EvaluateDemurrage(locked, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(locked_eval.locked);
    BOOST_CHECK_EQUAL(locked_eval.remaining_ppm, 0);
    BOOST_CHECK_EQUAL(locked_eval.effective_value, 0);
    BOOST_CHECK_EQUAL(locked_eval.burned_value, 8 * COIN);
}

BOOST_AUTO_TEST_CASE(attestation_index_connect_disconnect)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const int height = 1234;
    const COutPoint replay_anchor{uint256::ONE, 0};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(replay_anchor);
    mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(replay_anchor, public_key, signature));
    const CTransaction tx{mtx};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));
    const uint256 block_hash = block.GetHash();
    CBlockIndex index;
    InitTestIndex(index, height, block_hash);
    Consensus::Params params = ActiveParams(/*activation_height=*/1);

    CCoinsView base;
    CCoinsViewCache view(&base);
    std::string reject_reason;
    BOOST_CHECK(ApplyDemurrageBlock(view, block, &index, params, reject_reason));
    const uint256 pubkey_hash = DemurragePubKeyHash(public_key);
    BOOST_REQUIRE(LatestDemurrageAttestationHeight(view, pubkey_hash).has_value());
    BOOST_CHECK_EQUAL(*LatestDemurrageAttestationHeight(view, pubkey_hash), height);

    const CScript migration_script = QuantumMigrationScriptForPubkey(public_key);
    BOOST_REQUIRE(LatestDemurrageAttestationHeightForScript(view, migration_script).has_value());
    BOOST_CHECK_EQUAL(*LatestDemurrageAttestationHeightForScript(view, migration_script), height);

    BOOST_CHECK(UndoDemurrageBlock(view, block, &index, params));
    BOOST_CHECK(!LatestDemurrageAttestationHeight(view, pubkey_hash).has_value());
}

BOOST_AUTO_TEST_CASE(attestation_rejects_bad_signature_and_height)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const int height = 2000;
    const COutPoint replay_anchor{uint256::ONE, 7};
    std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);
    signature[0] ^= 0x01;

    CMutableTransaction bad_sig_mtx;
    bad_sig_mtx.vin.emplace_back(replay_anchor);
    bad_sig_mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(replay_anchor, public_key, signature));
    CBlock bad_sig_block;
    bad_sig_block.vtx.push_back(MakeTransactionRef(CTransaction{bad_sig_mtx}));
    const uint256 bad_sig_hash = bad_sig_block.GetHash();
    CBlockIndex bad_sig_index;
    InitTestIndex(bad_sig_index, height, bad_sig_hash);

    CCoinsView base;
    CCoinsViewCache view(&base);
    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    std::string reject_reason;
    BOOST_CHECK(!ApplyDemurrageBlock(view, bad_sig_block, &bad_sig_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation-signature");

    signature = SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction bad_anchor_mtx;
    bad_anchor_mtx.vin.emplace_back(COutPoint{uint256::ONE, 8});
    bad_anchor_mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(replay_anchor, public_key, signature));
    CBlock bad_anchor_block;
    bad_anchor_block.vtx.push_back(MakeTransactionRef(CTransaction{bad_anchor_mtx}));
    const uint256 bad_anchor_hash = bad_anchor_block.GetHash();
    CBlockIndex bad_height_index;
    InitTestIndex(bad_height_index, height + 1, bad_anchor_hash);
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, bad_anchor_block, &bad_height_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation");

    const COutPoint null_anchor;
    signature = SignAttestation(private_key, null_anchor, public_key);
    CMutableTransaction coinbase_mtx;
    coinbase_mtx.vin.emplace_back(null_anchor);
    coinbase_mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(null_anchor, public_key, signature));
    CBlock coinbase_attest_block;
    coinbase_attest_block.vtx.push_back(MakeTransactionRef(CTransaction{coinbase_mtx}));
    const uint256 coinbase_attest_hash = coinbase_attest_block.GetHash();
    CBlockIndex coinbase_attest_index;
    InitTestIndex(coinbase_attest_index, height + 2, coinbase_attest_hash);
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, coinbase_attest_block, &coinbase_attest_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation");
}

BOOST_AUTO_TEST_CASE(attestation_is_standard_even_above_default_op_return_limit)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const COutPoint replay_anchor{uint256::ONE, 3};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(replay_anchor);
    mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(replay_anchor, public_key, signature));
    BOOST_CHECK(mtx.vout[0].scriptPubKey.size() > MAX_OP_RETURN_RELAY);
    BOOST_CHECK(IsDemurrageAttestationScript(mtx.vout[0].scriptPubKey));

    std::string reason;
    BOOST_CHECK(IsStandardTx(
        CTransaction{mtx},
        MAX_OP_RETURN_RELAY,
        /*permit_bare_multisig=*/true,
        CFeeRate{DUST_RELAY_TX_FEE},
        reason,
        /*witnessEnabled=*/true));
    BOOST_CHECK(reason.empty());

    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(mtx.vout[0].scriptPubKey.size() - 3, 0x42);
    reason.clear();
    BOOST_CHECK(!IsStandardTx(
        CTransaction{mtx},
        MAX_OP_RETURN_RELAY,
        /*permit_bare_multisig=*/true,
        CFeeRate{DUST_RELAY_TX_FEE},
        reason,
        /*witnessEnabled=*/true));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
}

BOOST_AUTO_TEST_CASE(adjusted_value_in_uses_attestation_index)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    const CScript migration_script = QuantumMigrationScriptForPubkey(public_key);
    const COutPoint prevout{uint256::ONE, 1};

    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(prevout, TestCoin(10 * COIN, /*height=*/1, migration_script), false);

    CMutableTransaction spend_mtx;
    spend_mtx.vin.emplace_back(prevout);
    spend_mtx.vout.emplace_back(1 * COIN, PlainScript(0x77));
    const CTransaction spend{spend_mtx};

    const int spend_height = 1 + DEMURRAGE_ZERO_BLOCKS;
    BOOST_CHECK_EQUAL(GetDemurrageAdjustedValueIn(spend, view, params, spend_height, TEST_POST_MIGRATION_TIME), 0);

    const int attest_height = spend_height - 100;
    const COutPoint replay_anchor{uint256::ONE, 9};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction attest_mtx;
    attest_mtx.vin.emplace_back(replay_anchor);
    attest_mtx.vout.emplace_back(0, BuildDemurrageAttestationScript(replay_anchor, public_key, signature));
    CBlock attest_block;
    attest_block.vtx.push_back(MakeTransactionRef(CTransaction{attest_mtx}));
    const uint256 attest_block_hash = attest_block.GetHash();
    CBlockIndex attest_index;
    InitTestIndex(attest_index, attest_height, attest_block_hash);
    std::string reject_reason;
    BOOST_REQUIRE(ApplyDemurrageBlock(view, attest_block, &attest_index, params, reject_reason));

    BOOST_CHECK_EQUAL(GetDemurrageAdjustedValueIn(spend, view, params, spend_height, TEST_POST_MIGRATION_TIME), 10 * COIN);
}

BOOST_AUTO_TEST_SUITE_END()
