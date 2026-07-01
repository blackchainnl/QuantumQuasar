// Copyright (c) 2024-2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/mldsa.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <undo.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(coldstake_tests, BasicTestingSetup)

namespace {

CScript QuantumColdStakeScript(unsigned char tag)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        std::vector<unsigned char>(QUANTUM_COLDSTAKE_PROGRAM_SIZE, tag)});
}

CScript LegacyColdScript(unsigned char staker_tag, unsigned char owner_tag)
{
    std::vector<unsigned char> staker(33, staker_tag);
    std::vector<unsigned char> owner(33, owner_tag);
    staker[0] = 0x02;
    owner[0] = 0x03;
    return CScript() << OP_ISCOINSTAKE
                     << OP_IF << staker
                     << OP_ELSE << owner
                     << OP_ENDIF
                     << OP_CHECKSIG;
}

CScript P2WSH(const CScript& witness_script)
{
    WitnessV0ScriptHash wsh(witness_script);
    return CScript() << OP_0 << std::vector<unsigned char>(wsh.begin(), wsh.end());
}

CScript P2SH(const CScript& redeem_script)
{
    const ScriptHash hash{redeem_script};
    return GetScriptForDestination(hash);
}

CScript PlainScript(unsigned char tag)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
}

std::vector<unsigned char> QuantumPubkey(unsigned char tag)
{
    return std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, tag);
}

CScript QuantumMigrationScriptForPubkey(const std::vector<unsigned char>& pubkey)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumMigrationProgramForPubkey(pubkey)});
}

CScript QuantumColdStakeScriptForPubkeys(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        QuantumColdStakeProgramForPubkeys(staker_pubkey, owner_pubkey)});
}

void SetColdStakeStakerWitness(CTxIn& input, const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey)
{
    input.scriptWitness.stack = {
        std::vector<unsigned char>(ML_DSA::SIGNATURE_BYTES, 0x55),
        staker_pubkey,
        QuantumMigrationProgramForPubkey(owner_pubkey),
        std::vector<unsigned char>{0x01},
    };
}

Coin MakeCoin(const CScript& spk, CAmount value)
{
    return Coin(CTxOut(value, spk), /*nHeightIn=*/100, /*fCoinBaseIn=*/false, /*fCoinStakeIn=*/true, /*nTimeIn=*/0);
}

CTxUndo MakeUndo(const std::vector<std::pair<CScript, CAmount>>& prevouts)
{
    CTxUndo undo;
    for (const auto& [script, amount] : prevouts) {
        undo.vprevout.push_back(MakeCoin(script, amount));
    }
    return undo;
}

} // namespace

BOOST_AUTO_TEST_CASE(coldstake_subsidy_is_discounted)
{
    BOOST_CHECK_GT(GetColdStakeProofOfStakeSubsidy(), 0);
    BOOST_CHECK_LT(GetColdStakeProofOfStakeSubsidy(), GetProofOfStakeSubsidy());
    BOOST_CHECK_EQUAL(GetColdStakeProofOfStakeSubsidy(), GetProofOfStakeSubsidy() / 2);
    BOOST_CHECK_EQUAL(GetProofOfStakeSubsidyForCoinstake(false), GetProofOfStakeSubsidy());
    BOOST_CHECK_EQUAL(GetProofOfStakeSubsidyForCoinstake(true), GetColdStakeProofOfStakeSubsidy());
}

BOOST_AUTO_TEST_CASE(b4_reward_split_self_stake_routes_full_pie_and_fees)
{
    const CAmount principal = 1000 * COIN;
    const CAmount fees = 12 * CENT;
    const CScript self_script = PlainScript(0x51);

    CMutableTransaction cs;
    cs.vin.emplace_back(uint256::ONE, 0);
    cs.vout.emplace_back(0, CScript{});
    cs.vout.emplace_back(principal + GetProofOfStakeSubsidy() + fees, self_script);
    CTxUndo undo = MakeUndo({{self_script, principal}});

    StakeRewardSplit split;
    std::string reason;
    BOOST_CHECK(CheckStakeRewardSplit(CTransaction(cs), undo, fees, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason));
    BOOST_CHECK_EQUAL(split.total_reward, GetProofOfStakeSubsidy() + fees);
    BOOST_CHECK_EQUAL(split.operator_comp, 0);
    BOOST_CHECK_EQUAL(split.required_outputs[self_script], principal + GetProofOfStakeSubsidy() + fees);
}

BOOST_AUTO_TEST_CASE(b4_reward_split_uses_demurrage_effective_principal)
{
    const CAmount nominal_principal = 1000 * COIN;
    const CAmount effective_principal = 750 * COIN;
    const CScript self_script = QuantumMigrationScriptForPubkey(QuantumPubkey(0x59));

    CMutableTransaction cs;
    cs.vin.emplace_back(uint256::ONE, 0);
    cs.vout.emplace_back(0, CScript{});
    cs.vout.emplace_back(effective_principal + GetProofOfStakeSubsidy(), self_script);
    CTxUndo undo = MakeUndo({{self_script, nominal_principal}});
    std::vector<CAmount> effective_principals{effective_principal};

    StakeRewardSplit split;
    std::string reason;
    BOOST_CHECK(CheckStakeRewardSplit(CTransaction(cs), undo, /*block_fees=*/0, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason, &effective_principals));
    BOOST_CHECK_EQUAL(split.total_reward, GetProofOfStakeSubsidy());
    BOOST_CHECK_EQUAL(split.required_outputs[self_script], effective_principal + GetProofOfStakeSubsidy());

    reason.clear();
    BOOST_CHECK(!CheckStakeRewardSplit(CTransaction(cs), undo, /*block_fees=*/0, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-reward-split");
}

BOOST_AUTO_TEST_CASE(b4_reward_split_coldstake_operator_floor)
{
    const CAmount principal = 1000 * COIN;
    const std::vector<unsigned char> staker = QuantumPubkey(0x61);
    const std::vector<unsigned char> owner = QuantumPubkey(0x62);
    const CScript qcs_script = QuantumColdStakeScriptForPubkeys(staker, owner);
    const CScript operator_script = QuantumMigrationScriptForPubkey(staker);
    const CAmount operator_floor = (GetProofOfStakeSubsidy() * 5) / 100;

    CMutableTransaction cs;
    cs.vin.emplace_back(uint256::ONE, 0);
    SetColdStakeStakerWitness(cs.vin[0], staker, owner);
    cs.vout.emplace_back(0, CScript{});
    cs.vout.emplace_back(principal + GetProofOfStakeSubsidy() - operator_floor, qcs_script);
    cs.vout.emplace_back(operator_floor, operator_script);
    CTxUndo undo = MakeUndo({{qcs_script, principal}});

    StakeRewardSplit split;
    std::string reason;
    BOOST_CHECK(CheckStakeRewardSplit(CTransaction(cs), undo, /*block_fees=*/0, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason));
    BOOST_CHECK_EQUAL(split.delegated_gross_reward, GetProofOfStakeSubsidy());
    BOOST_CHECK_EQUAL(split.operator_comp, operator_floor);
    BOOST_CHECK_EQUAL(split.required_outputs[qcs_script], principal + GetProofOfStakeSubsidy() - operator_floor);
    BOOST_CHECK_EQUAL(split.required_outputs[operator_script], operator_floor);
}

BOOST_AUTO_TEST_CASE(b4_reward_split_coldstake_fees_dominate_operator_floor)
{
    const CAmount principal = 1000 * COIN;
    const CAmount fees = 10 * CENT;
    const std::vector<unsigned char> staker = QuantumPubkey(0x71);
    const std::vector<unsigned char> owner = QuantumPubkey(0x72);
    const CScript qcs_script = QuantumColdStakeScriptForPubkeys(staker, owner);
    const CScript operator_script = QuantumMigrationScriptForPubkey(staker);

    CMutableTransaction cs;
    cs.vin.emplace_back(uint256::ONE, 0);
    SetColdStakeStakerWitness(cs.vin[0], staker, owner);
    cs.vout.emplace_back(0, CScript{});
    cs.vout.emplace_back(principal + GetProofOfStakeSubsidy(), qcs_script);
    cs.vout.emplace_back(fees, operator_script);
    CTxUndo undo = MakeUndo({{qcs_script, principal}});

    StakeRewardSplit split;
    std::string reason;
    BOOST_CHECK(CheckStakeRewardSplit(CTransaction(cs), undo, fees, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason));
    BOOST_CHECK_EQUAL(split.operator_comp, fees);
    BOOST_CHECK_EQUAL(split.total_reward, GetProofOfStakeSubsidy() + fees);
    BOOST_CHECK_EQUAL(split.required_outputs[qcs_script], principal + GetProofOfStakeSubsidy());
    BOOST_CHECK_EQUAL(split.required_outputs[operator_script], fees);
}

BOOST_AUTO_TEST_CASE(b4_reward_split_rejects_value_leakage)
{
    const CAmount principal = 1000 * COIN;
    const CScript self_script = PlainScript(0x81);
    const CScript leaked_script = PlainScript(0x82);

    CMutableTransaction cs;
    cs.vin.emplace_back(uint256::ONE, 0);
    cs.vout.emplace_back(0, CScript{});
    cs.vout.emplace_back(principal + GetProofOfStakeSubsidy(), self_script);
    cs.vout.emplace_back(1, leaked_script);
    CTxUndo undo = MakeUndo({{self_script, principal}});

    StakeRewardSplit split;
    std::string reason;
    BOOST_CHECK(!CheckStakeRewardSplit(CTransaction(cs), undo, /*block_fees=*/0, /*candidate_height=*/200, /*stake_tiers_active=*/true, split, reason));
    BOOST_CHECK_EQUAL(reason, "bad-stake-reward-split-output");
}

BOOST_AUTO_TEST_CASE(coldstake_input_detection_is_exact_qcs_only)
{
    const CScript qcs = QuantumColdStakeScript(0x11);
    CMutableTransaction qcs_cs;
    qcs_cs.vin.resize(1);
    CTxUndo qcs_undo = MakeUndo({{qcs, 1000}});
    BOOST_CHECK(IsColdStakeInput(qcs_undo.vprevout[0].out, qcs_cs.vin[0]));
    BOOST_CHECK(HasColdStakeInputs(CTransaction(qcs_cs), qcs_undo));

    const CScript legacy_bare = LegacyColdScript(1, 2);
    CMutableTransaction bare_cs;
    bare_cs.vin.resize(1);
    CTxUndo bare_undo = MakeUndo({{legacy_bare, 1000}});
    BOOST_CHECK(!IsColdStakeInput(bare_undo.vprevout[0].out, bare_cs.vin[0]));
    BOOST_CHECK(!HasColdStakeInputs(CTransaction(bare_cs), bare_undo));

    const CScript legacy_p2wsh = P2WSH(legacy_bare);
    CMutableTransaction p2wsh_cs;
    p2wsh_cs.vin.resize(1);
    CTxUndo p2wsh_undo = MakeUndo({{legacy_p2wsh, 1000}});
    BOOST_CHECK(!IsColdStakeInput(p2wsh_undo.vprevout[0].out, p2wsh_cs.vin[0]));
    BOOST_CHECK(!HasColdStakeInputs(CTransaction(p2wsh_cs), p2wsh_undo));

    const CScript legacy_p2sh_p2wsh = P2SH(legacy_p2wsh);
    CMutableTransaction p2sh_cs;
    p2sh_cs.vin.resize(1);
    CTxUndo p2sh_undo = MakeUndo({{legacy_p2sh_p2wsh, 1000}});
    BOOST_CHECK(!IsColdStakeInput(p2sh_undo.vprevout[0].out, p2sh_cs.vin[0]));
    BOOST_CHECK(!HasColdStakeInputs(CTransaction(p2sh_cs), p2sh_undo));
}

BOOST_AUTO_TEST_CASE(coldstake_accept_principal_preserved)
{
    const CScript qcs = QuantumColdStakeScript(0x21);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1000, qcs);
    cs.vout.emplace_back(50, PlainScript(9));

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::string reason;
    BOOST_CHECK(CheckColdStakeCovenant(CTransaction(cs), undo, reason));
}

BOOST_AUTO_TEST_CASE(coldstake_accept_reward_added_to_same_script)
{
    const CScript qcs = QuantumColdStakeScript(0x22);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1050, qcs);

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::string reason;
    BOOST_CHECK(CheckColdStakeCovenant(CTransaction(cs), undo, reason));
}

BOOST_AUTO_TEST_CASE(coldstake_reject_principal_short)
{
    const CScript qcs = QuantumColdStakeScript(0x23);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(999, qcs);
    cs.vout.emplace_back(51, PlainScript(9));

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::string reason;
    BOOST_CHECK(!CheckColdStakeCovenant(CTransaction(cs), undo, reason));
    BOOST_CHECK_EQUAL(reason, "bad-coldstake-covenant");
}

BOOST_AUTO_TEST_CASE(coldstake_reject_full_redirect)
{
    const CScript qcs = QuantumColdStakeScript(0x24);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1000, PlainScript(9));

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::string reason;
    BOOST_CHECK(!CheckColdStakeCovenant(CTransaction(cs), undo, reason));
    BOOST_CHECK_EQUAL(reason, "bad-coldstake-covenant");
}

BOOST_AUTO_TEST_CASE(coldstake_accept_no_cold_input)
{
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1050, PlainScript(7));

    CTxUndo undo = MakeUndo({{PlainScript(7), 1000}});
    std::string reason;
    BOOST_CHECK(CheckColdStakeCovenant(CTransaction(cs), undo, reason));
}

BOOST_AUTO_TEST_CASE(coldstake_multi_script)
{
    const CScript qcs1 = QuantumColdStakeScript(0x31);
    const CScript qcs2 = QuantumColdStakeScript(0x32);

    CMutableTransaction ok;
    ok.vin.resize(2);
    ok.vout.emplace_back(0, CScript());
    ok.vout.emplace_back(1000, qcs1);
    ok.vout.emplace_back(500, qcs2);

    CTxUndo undo = MakeUndo({{qcs1, 1000}, {qcs2, 500}});
    std::string reason;
    BOOST_CHECK(CheckColdStakeCovenant(CTransaction(ok), undo, reason));

    CMutableTransaction bad = ok;
    bad.vout[2].nValue = 499;
    BOOST_CHECK(!CheckColdStakeCovenant(CTransaction(bad), undo, reason));
    BOOST_CHECK_EQUAL(reason, "bad-coldstake-covenant");
}

BOOST_AUTO_TEST_CASE(coldstake_shadow_payout_does_not_count_as_principal)
{
    const CScript qcs = QuantumColdStakeScript(0x41);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1000, qcs);

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::map<CScript, CAmount> shadow_payouts{{qcs, 1000}};
    std::string reason;
    BOOST_CHECK(!CheckColdStakeCovenant(CTransaction(cs), undo, shadow_payouts, CScript{}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-coldstake-covenant");

    cs.vout.emplace_back(1000, qcs);
    reason.clear();
    BOOST_CHECK(CheckColdStakeCovenant(CTransaction(cs), undo, shadow_payouts, CScript{}, reason));
}

BOOST_AUTO_TEST_CASE(coldstake_dev_output_does_not_count_as_principal)
{
    const CScript qcs = QuantumColdStakeScript(0x42);
    CMutableTransaction cs;
    cs.vin.resize(1);
    cs.vout.emplace_back(0, CScript());
    cs.vout.emplace_back(1000, qcs);

    CTxUndo undo = MakeUndo({{qcs, 1000}});
    std::string reason;
    BOOST_CHECK(!CheckColdStakeCovenant(CTransaction(cs), undo, {}, qcs, reason));
    BOOST_CHECK_EQUAL(reason, "bad-coldstake-covenant");
}

BOOST_AUTO_TEST_SUITE_END()
