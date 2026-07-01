// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <eutxo/transition.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/solver.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <optional>
#include <string>
#include <vector>

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck>* pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_FIXTURE_TEST_SUITE(blackcoin_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> QuantumProgramForPubkey(const std::vector<uint8_t>& pubkey)
{
    std::vector<unsigned char> program(QUANTUM_MIGRATION_PROGRAM_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(program.data());
    return program;
}

} // namespace

BOOST_AUTO_TEST_CASE(phase_schedule_boundaries)
{
    Consensus::Params consensus;
    consensus.nProtocolV4Time = Consensus::QUANTUM_QUASAR_MAINNET_V4_TIME;
    consensus.nGoldRushEndTime = consensus.nProtocolV4Time + Consensus::QUANTUM_QUASAR_GOLD_RUSH_SECONDS;
    consensus.nQuantumMigrationDeadlineTime = consensus.nGoldRushEndTime + Consensus::QUANTUM_QUASAR_MIGRATION_SECONDS;

    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nProtocolV4Time) == Consensus::QuantumQuasarPhase::LEGACY);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nProtocolV4Time + 1) == Consensus::QuantumQuasarPhase::GOLD_RUSH);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nGoldRushEndTime) == Consensus::QuantumQuasarPhase::GOLD_RUSH);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nGoldRushEndTime + 1) == Consensus::QuantumQuasarPhase::MIGRATION);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nQuantumMigrationDeadlineTime) == Consensus::QuantumQuasarPhase::MIGRATION);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nQuantumMigrationDeadlineTime + 1) == Consensus::QuantumQuasarPhase::FINAL_LOCKOUT);
    BOOST_CHECK(consensus.IsBaseNetworkStakeCompatible(consensus.nProtocolV4Time));
    BOOST_CHECK(consensus.IsBaseNetworkStakeCompatible(consensus.nProtocolV4Time + 1));
    BOOST_CHECK(consensus.IsBaseNetworkStakeCompatible(consensus.nGoldRushEndTime));
    BOOST_CHECK(consensus.IsBaseNetworkStakeCompatible(consensus.nGoldRushEndTime + 1));
    BOOST_CHECK(!consensus.IsNewNetworkStakeOnly(consensus.nGoldRushEndTime));
    BOOST_CHECK(!consensus.IsNewNetworkStakeOnly(consensus.nGoldRushEndTime + 1));
    BOOST_CHECK(consensus.IsNewNetworkStakeOnly(consensus.nQuantumMigrationDeadlineTime + 1));
    BOOST_CHECK(!consensus.IsQuantumSpendEnforcementActive(consensus.nGoldRushEndTime));
    BOOST_CHECK(consensus.IsQuantumSpendEnforcementActive(consensus.nGoldRushEndTime + 1));
    BOOST_CHECK(consensus.IsQuantumSpendEnforcementActive(consensus.nQuantumMigrationDeadlineTime + 1));

    consensus.nQuantumMigrationDeadlineTime = 0;
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nGoldRushEndTime + 1) == Consensus::QuantumQuasarPhase::MIGRATION);
    BOOST_CHECK(!consensus.IsNewNetworkStakeOnly(consensus.nGoldRushEndTime + 1));
    BOOST_CHECK(consensus.IsQuantumSpendEnforcementActive(consensus.nGoldRushEndTime + 1));

    consensus.nGoldRushEndTime = 0;
    BOOST_CHECK(consensus.IsBaseNetworkStakeCompatible(consensus.nProtocolV4Time + 1));
    BOOST_CHECK(!consensus.IsNewNetworkStakeOnly(consensus.nProtocolV4Time + 1));
    BOOST_CHECK(!consensus.IsQuantumMigrationWindow(consensus.nProtocolV4Time + 1));
    BOOST_CHECK(!consensus.IsQuantumFinalLockout(consensus.nProtocolV4Time + 1));

    consensus.nQuantumMigrationDeadlineTime = consensus.nProtocolV4Time + 10;
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nProtocolV4Time + 1) == Consensus::QuantumQuasarPhase::GOLD_RUSH);
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nProtocolV4Time + 11) == Consensus::QuantumQuasarPhase::FINAL_LOCKOUT);
    BOOST_CHECK(!consensus.IsBaseNetworkStakeCompatible(consensus.nProtocolV4Time + 11));
    BOOST_CHECK(consensus.IsNewNetworkStakeOnly(consensus.nProtocolV4Time + 11));
    BOOST_CHECK(consensus.IsQuantumSpendEnforcementActive(consensus.nProtocolV4Time + 11));

    consensus.nGoldRushEndTime = consensus.nProtocolV4Time + 100;
    consensus.nQuantumMigrationDeadlineTime = consensus.nProtocolV4Time + 50;
    BOOST_CHECK(consensus.GetQuantumQuasarPhase(consensus.nProtocolV4Time + 51) == Consensus::QuantumQuasarPhase::FINAL_LOCKOUT);
    BOOST_CHECK(!consensus.IsGoldRushEpoch(consensus.nProtocolV4Time + 51));
    BOOST_CHECK(!consensus.IsBaseNetworkStakeCompatible(consensus.nProtocolV4Time + 51));
    BOOST_CHECK(consensus.IsNewNetworkStakeOnly(consensus.nProtocolV4Time + 51));
    BOOST_CHECK(consensus.IsQuantumSpendEnforcementActive(consensus.nProtocolV4Time + 51));
}

BOOST_AUTO_TEST_CASE(quantum_migration_witness_v16_address_roundtrip)
{
    SelectParams(ChainType::MAIN);

    const std::vector<unsigned char> commitment(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x42);
    const CTxDestination dest = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, commitment};
    BOOST_CHECK(IsValidDestination(dest));
    BOOST_CHECK(IsQuantumMigrationDestination(dest));

    const CScript expected_script = CScript() << OP_16 << commitment;
    BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(dest)), HexStr(expected_script));
    TxoutType which_type;
    BOOST_CHECK(IsStandard(expected_script, /*max_datacarrier_bytes=*/std::nullopt, which_type, /*witnessEnabled=*/true));
    BOOST_CHECK(which_type == TxoutType::WITNESS_UNKNOWN);

    const std::string encoded = EncodeDestination(dest);
    BOOST_REQUIRE(!encoded.empty());

    const CTxDestination decoded = DecodeDestination(encoded);
    BOOST_CHECK(IsValidDestination(decoded));
    BOOST_CHECK(IsQuantumMigrationDestination(decoded));
    BOOST_CHECK_EQUAL(EncodeDestination(decoded), encoded);

    const CTxDestination wrong_size = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE - 1, 0x42)};
    BOOST_CHECK(!IsQuantumMigrationDestination(wrong_size));

    const CTxDestination wrong_version = WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION - 1, commitment};
    BOOST_CHECK(!IsQuantumMigrationDestination(wrong_version));
}

BOOST_AUTO_TEST_CASE(quantum_tiered_programs_parse_canonically)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const std::vector<unsigned char> bonded = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_BONDED, 9450, 0);
    BOOST_REQUIRE_EQUAL(bonded.size(), QUANTUM_TIERED_PROGRAM_SIZE);
    BOOST_CHECK(IsQuantumMigrationWitnessProgram(QUANTUM_MIGRATION_WITNESS_VERSION, bonded));
    QuantumStakeTierProgram bonded_tier;
    BOOST_REQUIRE(DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, bonded, bonded_tier));
    BOOST_CHECK(bonded_tier.tiered);
    BOOST_CHECK(bonded_tier.IsBonded());
    BOOST_CHECK_EQUAL(bonded_tier.unbonding_blocks, 9450);
    BOOST_CHECK_EQUAL(bonded_tier.unlock_height, 0U);
    BOOST_CHECK_EQUAL(bonded_tier.EffectiveUnbondingBlocks(100), 9450);

    const std::vector<unsigned char> unbonding = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_UNBONDING, 9450, 200);
    QuantumStakeTierProgram unbonding_tier;
    BOOST_REQUIRE(DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, unbonding, unbonding_tier));
    BOOST_CHECK(unbonding_tier.IsUnbonding());
    BOOST_CHECK_EQUAL(unbonding_tier.EffectiveUnbondingBlocks(150), 50);
    BOOST_CHECK_EQUAL(unbonding_tier.EffectiveUnbondingBlocks(200), 0);

    std::vector<unsigned char> bad_bonded = bonded;
    bad_bonded[4] = 1; // bonded unlock_height must be zero
    BOOST_CHECK(!IsQuantumMigrationWitnessProgram(QUANTUM_MIGRATION_WITNESS_VERSION, bad_bonded));

    uint256 staker_hash;
    uint256 owner_hash;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(staker_hash.begin());
    owner_hash = uint256::ONE;
    const std::vector<unsigned char> qcs = QuantumTieredColdStakeProgramForKeyHashes(staker_hash, owner_hash, QUANTUM_TIERED_STATE_BONDED, 1350, 0);
    BOOST_CHECK(IsQuantumColdStakeWitnessProgram(QUANTUM_COLDSTAKE_WITNESS_VERSION, qcs));
}

BOOST_AUTO_TEST_CASE(mldsa_key_sign_verify_roundtrip)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    BOOST_CHECK_EQUAL(pubkey.size(), ML_DSA::PUBLICKEY_BYTES);
    BOOST_CHECK_EQUAL(privkey.size(), ML_DSA::SECRETKEY_BYTES);

    const uint256 message = uint256::ONE;
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, message.begin(), uint256::size(), signature));
    BOOST_CHECK_EQUAL(signature.size(), ML_DSA::SIGNATURE_BYTES);
    BOOST_CHECK(ML_DSA::Verify(pubkey, message.begin(), uint256::size(), signature));

    uint256 tampered_message{message};
    *tampered_message.begin() ^= 0x01;
    BOOST_CHECK(!ML_DSA::Verify(pubkey, tampered_message.begin(), uint256::size(), signature));

    signature[0] ^= 0x01;
    BOOST_CHECK(!ML_DSA::Verify(pubkey, message.begin(), uint256::size(), signature));
}

BOOST_AUTO_TEST_CASE(quantum_migration_witness_spend_enforces_mldsa)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const std::vector<unsigned char> program = QuantumProgramForPubkey(pubkey);
    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, program});
    const CTxOut spent_output{10 * COIN, quantum_script};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(9 * COIN, quantum_script);

    const CTransaction unsigned_tx{mtx};
    const uint256 sighash = QuantumSignatureHash(unsigned_tx, 0, spent_output);
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, sighash.begin(), uint256::size(), signature));

    mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction spend_tx{mtx};

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker checker(&spend_tx, 0, spent_output.nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                             checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    BOOST_CHECK(!VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
                              checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    CMutableTransaction tampered_mtx{spend_tx};
    tampered_mtx.vin[0].scriptWitness.stack[0][0] ^= 0x01;
    const CTransaction tampered_tx{tampered_mtx};
    PrecomputedTransactionData tampered_txdata;
    tampered_txdata.Init(tampered_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker tampered_checker(&tampered_tx, 0, spent_output.nValue, tampered_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), quantum_script, &tampered_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                              tampered_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ML_DSA_SIG);
}

BOOST_AUTO_TEST_CASE(quantum_tiered_migration_spend_requires_stake_tier_flag)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const std::vector<unsigned char> program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_BONDED, 9450, 0);
    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, program});
    const CTxOut spent_output{10 * COIN, quantum_script};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(9 * COIN, quantum_script);

    const CTransaction unsigned_tx{mtx};
    const uint256 sighash = QuantumSignatureHash(unsigned_tx, 0, spent_output);
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, sighash.begin(), uint256::size(), signature));

    mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction spend_tx{mtx};

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker checker(&spend_tx, 0, spent_output.nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(!VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                              checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    BOOST_CHECK(VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA | SCRIPT_VERIFY_QUANTUM_STAKE_TIERS,
                             checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(quantum_tiered_principal_covenant_enforces_unbonding)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    constexpr uint16_t delay = 100;
    constexpr int spend_height = 250;
    const std::vector<unsigned char> bonded_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_BONDED, delay, 0);
    const CScript bonded_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, bonded_program});
    const COutPoint bonded_outpoint{uint256::ONE, 3};
    const CTxOut bonded_prevout{10 * COIN, bonded_script};

    CCoinsView coins_dummy;
    CCoinsViewCache coins{&coins_dummy};
    coins.AddCoin(bonded_outpoint, Coin{bonded_prevout, 100, false, false, 0}, false);

    auto make_spend = [&](const CScript& output_script, CAmount amount) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(bonded_outpoint);
        mtx.vin[0].scriptWitness.stack.emplace_back(ML_DSA::SIGNATURE_BYTES, 0x00);
        mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
        mtx.vout.emplace_back(amount, output_script);
        return CTransaction{mtx};
    };

    const std::vector<unsigned char> min_unbonding_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_UNBONDING, delay, spend_height + delay);
    const CScript min_unbonding_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, min_unbonding_program});
    std::string reason;
    BOOST_CHECK(CheckTieredStakePrincipalCovenant(make_spend(min_unbonding_script, 10 * COIN), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, spend_height, reason));
    BOOST_CHECK(reason.empty());

    const std::vector<unsigned char> early_unbonding_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_UNBONDING, delay, spend_height + delay - 1);
    const CScript early_unbonding_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, early_unbonding_program});
    reason.clear();
    BOOST_CHECK(!CheckTieredStakePrincipalCovenant(make_spend(early_unbonding_script, 10 * COIN), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, spend_height, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-tier-transition");

    const CScript legacy_quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumMigrationProgramForPubkey(pubkey)});
    reason.clear();
    BOOST_CHECK(!CheckTieredStakePrincipalCovenant(make_spend(legacy_quantum_script, 10 * COIN), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, spend_height, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-tier-transition");

    reason.clear();
    BOOST_CHECK(CheckTieredStakePrincipalCovenant(make_spend(legacy_quantum_script, 10 * COIN), coins, SCRIPT_VERIFY_NONE, spend_height, reason));
}

BOOST_AUTO_TEST_CASE(quantum_tiered_principal_covenant_uses_demurrage_effective_value)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    constexpr uint16_t delay = 100;
    constexpr int coin_height = 100;
    const int spend_height = coin_height + Consensus::DEMURRAGE_GRACE_BLOCKS + 1000;
    constexpr int64_t migration_deadline = 2000;
    constexpr int64_t spend_time = migration_deadline + 1;

    Consensus::Params params;
    params.nDemurrageActivationHeight = 1;
    params.nQuantumMigrationDeadlineTime = migration_deadline;

    const std::vector<unsigned char> bonded_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_BONDED, delay, 0);
    const CScript bonded_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, bonded_program});
    const COutPoint bonded_outpoint{uint256::ONE, 31};
    Coin bonded_coin{CTxOut{10 * COIN, bonded_script}, coin_height, false, false, 0};

    CCoinsView coins_dummy;
    CCoinsViewCache coins{&coins_dummy};
    coins.AddCoin(bonded_outpoint, Coin{bonded_coin}, false);

    const Consensus::DemurrageEvaluation eval = Consensus::EvaluateDemurrage(bonded_coin, params, spend_height, spend_time);
    BOOST_REQUIRE(eval.burned_value > 0);
    BOOST_REQUIRE(eval.effective_value < bonded_coin.out.nValue);

    const std::vector<unsigned char> unbonding_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_UNBONDING, delay, spend_height + delay);
    const CScript unbonding_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, unbonding_program});

    auto make_spend = [&](CAmount amount) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(bonded_outpoint);
        mtx.vin[0].scriptWitness.stack.emplace_back(ML_DSA::SIGNATURE_BYTES, 0x00);
        mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
        mtx.vout.emplace_back(amount, unbonding_script);
        return CTransaction{mtx};
    };

    std::string reason;
    BOOST_CHECK(CheckTieredStakePrincipalCovenant(make_spend(eval.effective_value), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, spend_height, reason, &params, spend_time));
    BOOST_CHECK(reason.empty());

    reason.clear();
    BOOST_CHECK(!CheckTieredStakePrincipalCovenant(make_spend(eval.effective_value - 1), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, spend_height, reason, &params, spend_time));
    BOOST_CHECK_EQUAL(reason, "bad-stake-tier-transition");
}

BOOST_AUTO_TEST_CASE(quantum_tiered_unbonding_and_coinstake_covenant)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    constexpr uint16_t delay = 100;
    constexpr uint32_t unlock_height = 500;
    const std::vector<unsigned char> unbonding_program = QuantumTieredMigrationProgramForPubkey(pubkey, QUANTUM_TIERED_STATE_UNBONDING, delay, unlock_height);
    const CScript unbonding_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, unbonding_program});
    const COutPoint outpoint{uint256{2}, 4};
    const CTxOut prevout{10 * COIN, unbonding_script};

    CCoinsView coins_dummy;
    CCoinsViewCache coins{&coins_dummy};
    coins.AddCoin(outpoint, Coin{prevout, 100, false, false, 0}, false);

    const CScript legacy_quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumMigrationProgramForPubkey(pubkey)});
    auto make_spend = [&](const CScript& output_script) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(outpoint);
        mtx.vin[0].scriptWitness.stack.emplace_back(ML_DSA::SIGNATURE_BYTES, 0x00);
        mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
        mtx.vout.emplace_back(10 * COIN, output_script);
        return CTransaction{mtx};
    };

    std::string reason;
    BOOST_CHECK(!CheckTieredStakePrincipalCovenant(make_spend(legacy_quantum_script), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, unlock_height - 1, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-tier-transition");

    reason.clear();
    BOOST_CHECK(CheckTieredStakePrincipalCovenant(make_spend(legacy_quantum_script), coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, unlock_height, reason));

    CMutableTransaction coinstake;
    coinstake.nVersion = 2;
    coinstake.vin.emplace_back(outpoint);
    coinstake.vout.emplace_back(0, CScript{});
    coinstake.vout.emplace_back(10 * COIN, unbonding_script);
    reason.clear();
    BOOST_CHECK(CheckTieredStakePrincipalCovenant(CTransaction{coinstake}, coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, unlock_height - 10, reason));

    CMutableTransaction bad_coinstake{coinstake};
    bad_coinstake.vout[1].scriptPubKey = legacy_quantum_script;
    reason.clear();
    BOOST_CHECK(!CheckTieredStakePrincipalCovenant(CTransaction{bad_coinstake}, coins, SCRIPT_VERIFY_QUANTUM_STAKE_TIERS, unlock_height - 10, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-tier-covenant");
}

BOOST_AUTO_TEST_CASE(quantum_migration_witness_sigops_are_charged)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumProgramForPubkey(pubkey)});
    CScriptWitness witness;
    witness.stack.emplace_back(ML_DSA::SIGNATURE_BYTES, 0x42);
    witness.stack.emplace_back(pubkey.begin(), pubkey.end());

    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript{}, quantum_script, &witness, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS), QUANTUM_ML_DSA_WITNESS_SIGOPS);
}

BOOST_AUTO_TEST_CASE(quantum_coldstake_witness_enforces_branch_rules)
{
    std::vector<uint8_t> owner_pubkey;
    std::vector<uint8_t> owner_privkey;
    std::vector<uint8_t> staker_pubkey;
    std::vector<uint8_t> staker_privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(owner_pubkey, owner_privkey));
    BOOST_REQUIRE(ML_DSA::KeyGen(staker_pubkey, staker_privkey));
    const std::vector<unsigned char> owner_pubkey_bytes(owner_pubkey.begin(), owner_pubkey.end());
    const std::vector<unsigned char> staker_pubkey_bytes(staker_pubkey.begin(), staker_pubkey.end());

    const std::vector<unsigned char> qcs_program = QuantumColdStakeProgramForPubkeys(staker_pubkey_bytes, owner_pubkey_bytes);
    const CScript qcs_script = GetScriptForDestination(WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, qcs_program});
    const CTxOut spent_output{10 * COIN, qcs_script};
    const std::vector<unsigned char> owner_hash = QuantumMigrationProgramForPubkey(owner_pubkey_bytes);
    const std::vector<unsigned char> staker_hash = QuantumMigrationProgramForPubkey(staker_pubkey_bytes);
    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                               SCRIPT_VERIFY_QUANTUM_ML_DSA | SCRIPT_VERIFY_QUANTUM_COLDSTAKE;

    CMutableTransaction owner_mtx;
    owner_mtx.nVersion = 2;
    owner_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    owner_mtx.vout.emplace_back(9 * COIN, qcs_script);
    const CTransaction owner_unsigned_tx{owner_mtx};
    const uint256 owner_sighash = QuantumSignatureHash(owner_unsigned_tx, 0, spent_output);
    std::vector<uint8_t> owner_signature;
    BOOST_REQUIRE(ML_DSA::Sign(owner_privkey, owner_sighash.begin(), uint256::size(), owner_signature));
    owner_mtx.vin[0].scriptWitness.stack.emplace_back(owner_signature.begin(), owner_signature.end());
    owner_mtx.vin[0].scriptWitness.stack.emplace_back(owner_pubkey.begin(), owner_pubkey.end());
    owner_mtx.vin[0].scriptWitness.stack.emplace_back(staker_hash.begin(), staker_hash.end());
    owner_mtx.vin[0].scriptWitness.stack.emplace_back();
    const CTransaction owner_spend{owner_mtx};
    PrecomputedTransactionData owner_txdata;
    owner_txdata.Init(owner_spend, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker owner_checker(&owner_spend, 0, spent_output.nValue, owner_txdata, MissingDataBehavior::FAIL);
    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript(), qcs_script, &owner_spend.vin[0].scriptWitness, flags, owner_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    CMutableTransaction staker_mtx;
    staker_mtx.nVersion = 2;
    staker_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    staker_mtx.vout.emplace_back(9 * COIN, qcs_script);
    const CTransaction staker_unsigned_tx{staker_mtx};
    const uint256 staker_sighash = QuantumSignatureHash(staker_unsigned_tx, 0, spent_output);
    std::vector<uint8_t> staker_signature;
    BOOST_REQUIRE(ML_DSA::Sign(staker_privkey, staker_sighash.begin(), uint256::size(), staker_signature));
    staker_mtx.vin[0].scriptWitness.stack.emplace_back(staker_signature.begin(), staker_signature.end());
    staker_mtx.vin[0].scriptWitness.stack.emplace_back(staker_pubkey.begin(), staker_pubkey.end());
    staker_mtx.vin[0].scriptWitness.stack.emplace_back(owner_hash.begin(), owner_hash.end());
    staker_mtx.vin[0].scriptWitness.stack.emplace_back(std::vector<unsigned char>{1});
    const CTransaction staker_non_coinstake{staker_mtx};
    PrecomputedTransactionData staker_non_coinstake_txdata;
    staker_non_coinstake_txdata.Init(staker_non_coinstake, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker staker_non_coinstake_checker(&staker_non_coinstake, 0, spent_output.nValue, staker_non_coinstake_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), qcs_script, &staker_non_coinstake.vin[0].scriptWitness, flags, staker_non_coinstake_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_QUANTUM_COLDSTAKE_NOT_COINSTAKE);

    CMutableTransaction coinstake_mtx;
    coinstake_mtx.nVersion = 2;
    coinstake_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    coinstake_mtx.vout.emplace_back(0, CScript{});
    coinstake_mtx.vout.emplace_back(9 * COIN, qcs_script);
    const CTransaction coinstake_unsigned_tx{coinstake_mtx};
    const uint256 coinstake_sighash = QuantumSignatureHash(coinstake_unsigned_tx, 0, spent_output);
    BOOST_REQUIRE(ML_DSA::Sign(staker_privkey, coinstake_sighash.begin(), uint256::size(), staker_signature));
    coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(staker_signature.begin(), staker_signature.end());
    coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(staker_pubkey.begin(), staker_pubkey.end());
    coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(owner_hash.begin(), owner_hash.end());
    coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(std::vector<unsigned char>{1});
    const CTransaction coinstake_spend{coinstake_mtx};
    BOOST_REQUIRE(coinstake_spend.IsCoinStake());
    PrecomputedTransactionData coinstake_txdata;
    coinstake_txdata.Init(coinstake_spend, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker coinstake_checker(&coinstake_spend, 0, spent_output.nValue, coinstake_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(VerifyScript(CScript(), qcs_script, &coinstake_spend.vin[0].scriptWitness, flags, coinstake_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    CMutableTransaction owner_coinstake_mtx;
    owner_coinstake_mtx.nVersion = 2;
    owner_coinstake_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    owner_coinstake_mtx.vout.emplace_back(0, CScript{});
    owner_coinstake_mtx.vout.emplace_back(9 * COIN, qcs_script);
    const CTransaction owner_coinstake_unsigned_tx{owner_coinstake_mtx};
    const uint256 owner_coinstake_sighash = QuantumSignatureHash(owner_coinstake_unsigned_tx, 0, spent_output);
    BOOST_REQUIRE(ML_DSA::Sign(owner_privkey, owner_coinstake_sighash.begin(), uint256::size(), owner_signature));
    owner_coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(owner_signature.begin(), owner_signature.end());
    owner_coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(owner_pubkey.begin(), owner_pubkey.end());
    owner_coinstake_mtx.vin[0].scriptWitness.stack.emplace_back(staker_hash.begin(), staker_hash.end());
    owner_coinstake_mtx.vin[0].scriptWitness.stack.emplace_back();
    const CTransaction owner_coinstake_spend{owner_coinstake_mtx};
    BOOST_REQUIRE(owner_coinstake_spend.IsCoinStake());
    PrecomputedTransactionData owner_coinstake_txdata;
    owner_coinstake_txdata.Init(owner_coinstake_spend, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker owner_coinstake_checker(&owner_coinstake_spend, 0, spent_output.nValue, owner_coinstake_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), qcs_script, &owner_coinstake_spend.vin[0].scriptWitness, flags, owner_coinstake_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_QUANTUM_COLDSTAKE_OWNER_COINSTAKE);

    BOOST_CHECK(!VerifyScript(CScript(), qcs_script, &coinstake_spend.vin[0].scriptWitness,
                              flags & ~SCRIPT_VERIFY_QUANTUM_COLDSTAKE, coinstake_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    CMutableTransaction wrong_hash_mtx{owner_spend};
    wrong_hash_mtx.vin[0].scriptWitness.stack[2][0] ^= 0x01;
    const CTransaction wrong_hash_spend{wrong_hash_mtx};
    PrecomputedTransactionData wrong_hash_txdata;
    wrong_hash_txdata.Init(wrong_hash_spend, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker wrong_hash_checker(&wrong_hash_spend, 0, spent_output.nValue, wrong_hash_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), qcs_script, &wrong_hash_spend.vin[0].scriptWitness, flags, wrong_hash_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

BOOST_AUTO_TEST_CASE(quantum_migration_sighash_commits_all_spent_outputs)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumProgramForPubkey(pubkey)});
    std::vector<CTxOut> spent_outputs{
        CTxOut{10 * COIN, quantum_script},
        CTxOut{20 * COIN, quantum_script},
    };

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 1});
    mtx.vout.emplace_back(29 * COIN, quantum_script);

    const CTransaction unsigned_tx{mtx};
    const uint256 sighash = QuantumSignatureHash(unsigned_tx, 0, spent_outputs);
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, sighash.begin(), uint256::size(), signature));

    mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction spend_tx{mtx};

    std::vector<CTxOut> spent_outputs_copy = spent_outputs;
    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, std::move(spent_outputs_copy));
    TransactionSignatureChecker checker(&spend_tx, 0, spent_outputs[0].nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                             checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    std::vector<CTxOut> tampered_spent_outputs{spent_outputs};
    tampered_spent_outputs[1].nValue += COIN;
    PrecomputedTransactionData tampered_txdata;
    tampered_txdata.Init(spend_tx, std::move(tampered_spent_outputs));
    TransactionSignatureChecker tampered_checker(&spend_tx, 0, spent_outputs[0].nValue, tampered_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), quantum_script, &spend_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                              tampered_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ML_DSA_SIG);
}

BOOST_AUTO_TEST_CASE(v4_transaction_version_is_standard_for_roadmap_tooling)
{
    const std::vector<unsigned char> commitment(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x42);
    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, commitment});

    CMutableTransaction mtx;
    mtx.nVersion = 4;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(1 * COIN, quantum_script);

    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction{mtx}, /*max_datacarrier_bytes=*/std::nullopt, /*permit_bare_multisig=*/true, CFeeRate{0}, reason, /*witnessEnabled=*/true));
    BOOST_CHECK(reason.empty());
}

BOOST_AUTO_TEST_CASE(check_input_scripts_enforces_quantum_schedule_flags)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumProgramForPubkey(pubkey)});
    const CTxOut quantum_prevout{10 * COIN, quantum_script};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(9 * COIN, quantum_script);
    const CTransaction unsigned_tx{mtx};
    const uint256 sighash = QuantumSignatureHash(unsigned_tx, 0, quantum_prevout);
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, sighash.begin(), uint256::size(), signature));
    mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction quantum_spend{mtx};

    CCoinsView coins_dummy;
    CCoinsViewCache coins{&coins_dummy};
    coins.AddCoin(COutPoint{uint256::ONE, 0}, Coin{quantum_prevout, 1, false, false, 0}, false);

    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(!CheckInputScripts(quantum_spend, state, coins,
                                       SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
                                       true, true, txdata, nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "blackcoin-migration-spend-premature");
    }

    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(quantum_spend, state, coins,
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                                      true, true, txdata, nullptr));
    }

    CMutableTransaction downgrade_mtx;
    downgrade_mtx.nVersion = 2;
    downgrade_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    downgrade_mtx.vout.emplace_back(9 * COIN, CScript() << OP_TRUE);
    const CTransaction unsigned_downgrade_tx{downgrade_mtx};
    const uint256 downgrade_sighash = QuantumSignatureHash(unsigned_downgrade_tx, 0, quantum_prevout);
    BOOST_REQUIRE(ML_DSA::Sign(privkey, downgrade_sighash.begin(), uint256::size(), signature));
    downgrade_mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    downgrade_mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction downgrade_tx{downgrade_mtx};

    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(!CheckInputScripts(downgrade_tx, state, coins,
                                       SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                                       true, true, txdata, nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "quantum-output-downgrade");
    }

    CMutableTransaction op_return_mtx;
    op_return_mtx.nVersion = 2;
    op_return_mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    op_return_mtx.vout.emplace_back(9 * COIN, quantum_script);
    op_return_mtx.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{'Q', 'Q'});
    const CTransaction unsigned_op_return_tx{op_return_mtx};
    const uint256 op_return_sighash = QuantumSignatureHash(unsigned_op_return_tx, 0, quantum_prevout);
    BOOST_REQUIRE(ML_DSA::Sign(privkey, op_return_sighash.begin(), uint256::size(), signature));
    op_return_mtx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    op_return_mtx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    const CTransaction op_return_tx{op_return_mtx};

    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(op_return_tx, state, coins,
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
                                      true, true, txdata, nullptr));
    }

    CCoinsView legacy_dummy;
    CCoinsViewCache legacy_coins{&legacy_dummy};
    const CScript legacy_script = CScript() << OP_TRUE;
    legacy_coins.AddCoin(COutPoint{uint256{2}, 0}, Coin{CTxOut{1 * COIN, legacy_script}, 1, false, false, 0}, false);
    CMutableTransaction legacy_mtx;
    legacy_mtx.nVersion = 2;
    legacy_mtx.vin.emplace_back(COutPoint{uint256{2}, 0});
    legacy_mtx.vout.emplace_back(1 * COIN, quantum_script);
    const CTransaction legacy_spend{legacy_mtx};

    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(!CheckInputScripts(legacy_spend, state, legacy_coins,
                                       SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT,
                                       true, true, txdata, nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "legacy-spend-disabled");
    }
}

BOOST_AUTO_TEST_CASE(mldsa_self_test_runs)
{
    BOOST_CHECK(ML_DSA::SelfTest());
}

BOOST_AUTO_TEST_CASE(quantum_dust_threshold_accounts_for_large_witness)
{
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));

    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, QuantumProgramForPubkey(pubkey)});
    const CScript legacy_witness_script = CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x11);
    const CFeeRate dust_relay_fee{DUST_RELAY_TX_FEE};

    BOOST_CHECK_GT(GetDustThreshold(CTxOut{1 * COIN, quantum_script}, dust_relay_fee),
                   GetDustThreshold(CTxOut{1 * COIN, legacy_witness_script}, dust_relay_fee));
}

BOOST_AUTO_TEST_CASE(eutxo_commitment_solver_roundtrip)
{
    const std::vector<unsigned char> datum{0x01};
    const CScript validator_script = CScript() << OP_2 << OP_EQUALVERIFY << OP_1 << OP_EQUAL;
    const CScript eutxo_script = CreateEUTXOCommitment(datum, validator_script);

    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    BOOST_REQUIRE(eutxo_script.IsWitnessProgram(witness_version, witness_program));
    BOOST_CHECK_EQUAL(witness_version, static_cast<int>(EUTXO_WITNESS_VERSION));
    BOOST_CHECK_EQUAL(HexStr(witness_program), HexStr(EUTXOProgramForDatumAndValidator(datum, validator_script)));
    BOOST_CHECK(IsEUTXOScript(eutxo_script));

    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(eutxo_script, solutions) == TxoutType::EUTXO_COMMITMENT);
    BOOST_REQUIRE_EQUAL(solutions.size(), 2U);
    BOOST_CHECK_EQUAL(solutions[0][0], EUTXO_WITNESS_VERSION);
    BOOST_CHECK_EQUAL(HexStr(solutions[1]), HexStr(witness_program));

    TxoutType which_type;
    BOOST_CHECK(IsStandard(eutxo_script, /*max_datacarrier_bytes=*/std::nullopt, which_type, /*witnessEnabled=*/true));
    BOOST_CHECK(which_type == TxoutType::EUTXO_COMMITMENT);
}

BOOST_AUTO_TEST_CASE(eutxo_commitment_witness_spend_enforces_validator_and_commitment)
{
    const std::vector<unsigned char> datum{0x01};
    const std::vector<unsigned char> redeemer{0x02};
    const CScript validator_script = CScript() << OP_2 << OP_EQUALVERIFY << OP_1 << OP_EQUAL;
    const std::vector<unsigned char> validator_bytes{validator_script.begin(), validator_script.end()};
    const CScript eutxo_script = CreateEUTXOCommitment(datum, validator_script);
    const CTxOut spent_output{10 * COIN, eutxo_script};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(9 * COIN, CScript() << OP_TRUE);
    mtx.vin[0].scriptWitness.stack.push_back(datum);
    mtx.vin[0].scriptWitness.stack.push_back(redeemer);
    mtx.vin[0].scriptWitness.stack.push_back(validator_bytes);
    const CTransaction spend_tx{mtx};

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker checker(&spend_tx, 0, spent_output.nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript(), eutxo_script, &spend_tx.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_EUTXO,
                             checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    BOOST_CHECK(VerifyScript(CScript(), eutxo_script, &spend_tx.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_EUTXO | SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT,
                             checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    BOOST_CHECK(!VerifyScript(CScript(), eutxo_script, &spend_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
                              checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    CMutableTransaction tampered_mtx{spend_tx};
    tampered_mtx.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>{0x03};
    const CTransaction tampered_tx{tampered_mtx};
    PrecomputedTransactionData tampered_txdata;
    tampered_txdata.Init(tampered_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker tampered_checker(&tampered_tx, 0, spent_output.nValue, tampered_txdata, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(CScript(), eutxo_script, &tampered_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_EUTXO,
                              tampered_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

BOOST_AUTO_TEST_CASE(eutxo_final_lockout_rejects_legacy_signature_validators)
{
    const std::vector<unsigned char> datum{0x01};
    const std::vector<unsigned char> redeemer{};
    const CScript validator_script = CScript() << OP_CHECKSIG;
    const std::vector<unsigned char> validator_bytes{validator_script.begin(), validator_script.end()};
    const CScript eutxo_script = CreateEUTXOCommitment(datum, validator_script);
    const CTxOut spent_output{10 * COIN, eutxo_script};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(9 * COIN, CScript() << OP_TRUE);
    mtx.vin[0].scriptWitness.stack.push_back(datum);
    mtx.vin[0].scriptWitness.stack.push_back(redeemer);
    mtx.vin[0].scriptWitness.stack.push_back(validator_bytes);
    const CTransaction spend_tx{mtx};

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, std::vector<CTxOut>{spent_output});
    TransactionSignatureChecker checker(&spend_tx, 0, spent_output.nValue, txdata, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(!VerifyScript(CScript(), eutxo_script, &spend_tx.vin[0].scriptWitness,
                              SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_EUTXO | SCRIPT_VERIFY_LEGACY_ECDSA_LOCKOUT,
                              checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EUTXO_LEGACY_SIGOP);
}

BOOST_AUTO_TEST_CASE(eutxo_witness_sigops_are_charged)
{
    const std::vector<unsigned char> datum{0x01};
    const CScript validator_script = CScript() << OP_CHECKSIG;
    const std::vector<unsigned char> validator_bytes{validator_script.begin(), validator_script.end()};
    const CScript eutxo_script = CreateEUTXOCommitment(datum, validator_script);

    CScriptWitness witness;
    witness.stack.push_back(datum);
    witness.stack.push_back(std::vector<unsigned char>{0x02});
    witness.stack.push_back(validator_bytes);

    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript{}, eutxo_script, &witness, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS), 1U);
}

BOOST_AUTO_TEST_CASE(eutxo_state_transition_redeemer_roundtrip_and_successor_checks)
{
    const std::vector<unsigned char> old_datum{0x01};
    const CScript old_validator = CScript() << OP_TRUE;
    const CTxOut spent_output{10 * COIN, GetScriptForEUTXO(old_datum, old_validator)};

    eutxo::StateTransition transition;
    transition.output_index = 0;
    transition.amount = 9 * COIN;
    transition.datum = {0x02, 0x03};
    transition.validator_script = CScript() << OP_2 << OP_EQUALVERIFY << OP_1 << OP_EQUAL;

    const std::vector<unsigned char> encoded = eutxo::EncodeStateTransition(transition);
    eutxo::StateTransition decoded;
    std::string error;
    BOOST_CHECK(eutxo::DecodeStateTransition(encoded, decoded, error) == eutxo::DecodeStateTransitionResult::OK);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(decoded.output_index, transition.output_index);
    BOOST_CHECK_EQUAL(decoded.amount, transition.amount);
    BOOST_CHECK_EQUAL(HexStr(decoded.datum), HexStr(transition.datum));
    BOOST_CHECK_EQUAL(HexStr(decoded.validator_script), HexStr(transition.validator_script));

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(transition.amount, GetScriptForEUTXO(transition.datum, transition.validator_script));
    mtx.vin[0].scriptWitness.stack.push_back(old_datum);
    mtx.vin[0].scriptWitness.stack.push_back(encoded);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>{old_validator.begin(), old_validator.end()});
    BOOST_CHECK(eutxo::CheckStateTransition(CTransaction{mtx}, 0, spent_output, decoded, error));
    BOOST_CHECK(error.empty());

    CMutableTransaction wrong_amount{mtx};
    wrong_amount.vout[0].nValue -= 1;
    BOOST_CHECK(!eutxo::CheckStateTransition(CTransaction{wrong_amount}, 0, spent_output, decoded, error));
    BOOST_CHECK_EQUAL(error, "EUTXO transition successor amount mismatch");

    CMutableTransaction wrong_commitment{mtx};
    wrong_commitment.vout[0].scriptPubKey = GetScriptForEUTXO(std::vector<unsigned char>{0x04}, transition.validator_script);
    BOOST_CHECK(!eutxo::CheckStateTransition(CTransaction{wrong_commitment}, 0, spent_output, decoded, error));
    BOOST_CHECK_EQUAL(error, "EUTXO transition successor commitment mismatch");

    std::vector<unsigned char> malformed = encoded;
    malformed.pop_back();
    BOOST_CHECK(eutxo::DecodeStateTransition(malformed, decoded, error) == eutxo::DecodeStateTransitionResult::MALFORMED);
    BOOST_CHECK_EQUAL(error, "EUTXO transition redeemer length mismatch");

    const std::vector<unsigned char> ordinary_redeemer{0x51};
    BOOST_CHECK(eutxo::DecodeStateTransition(ordinary_redeemer, decoded, error) == eutxo::DecodeStateTransitionResult::NO_TRANSITION);
}

BOOST_AUTO_TEST_CASE(rgb_commitment_solver_and_decode_expose_payload)
{
    const uint256 state_hash = uint256::ONE;
    const CScript rgb_script = CreateRGBCommitment(state_hash);

    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(rgb_script, solutions) == TxoutType::RGB_COMMITMENT);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1U);
    BOOST_REQUIRE_EQUAL(solutions[0].size(), 4U + uint256::size());
    BOOST_CHECK_EQUAL(std::string(solutions[0].begin(), solutions[0].begin() + 4), "RGB1");

    UniValue script_univ{UniValue::VOBJ};
    ScriptToUniv(rgb_script, script_univ, /*include_hex=*/true, /*include_address=*/false);
    BOOST_CHECK_EQUAL(script_univ.find_value("type").get_str(), "rgb_commitment");
    BOOST_CHECK_EQUAL(script_univ.find_value("rgb_magic").get_str(), "RGB1");
    BOOST_CHECK_EQUAL(script_univ.find_value("rgb_state_hash").get_str(), state_hash.GetHex());

    TxoutType which_type;
    BOOST_CHECK(IsStandard(rgb_script, MAX_OP_RETURN_RELAY, which_type, /*witnessEnabled=*/true));
    BOOST_CHECK(which_type == TxoutType::RGB_COMMITMENT);
}

BOOST_AUTO_TEST_SUITE_END()
