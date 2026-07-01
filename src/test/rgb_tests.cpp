// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <rgb/engine.h>

#include <script/solver.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

rgb::Seal SealFor(uint8_t tag, uint32_t n = 0)
{
    uint256 txid;
    txid.begin()[0] = tag;
    return rgb::Seal{COutPoint{Txid::FromUint256(txid), n}};
}

rgb::Assignment AssignmentFor(uint8_t tag, uint64_t amount, uint32_t n = 0)
{
    return rgb::Assignment{SealFor(tag, n), amount};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(rgb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rgb_fixed_supply_transfer_validates_and_preserves_supply)
{
    rgb::Genesis genesis;
    genesis.ticker = "QQT";
    genesis.name = "Quantum Quasar Test Asset";
    genesis.total_supply = 1000;
    genesis.allocations = {AssignmentFor(1, 1000)};

    const uint256 contract_id = rgb::ContractId(genesis);
    rgb::Transition split;
    split.contract_id = contract_id;
    split.inputs = {SealFor(1)};
    split.outputs = {AssignmentFor(2, 400), AssignmentFor(3, 600)};

    const rgb::ValidationResult result = rgb::ValidateConsignment(genesis, {split});
    BOOST_CHECK(result.valid);
    BOOST_CHECK(result.errors.empty());
    BOOST_CHECK_EQUAL(result.current_supply, 1000U);
    BOOST_CHECK_EQUAL(result.unspent_assignments, 2U);
    BOOST_CHECK_EQUAL(result.unspent.at(SealFor(2)), 400U);
    BOOST_CHECK_EQUAL(result.unspent.at(SealFor(3)), 600U);
}

BOOST_AUTO_TEST_CASE(rgb_rejects_inflation_double_spends_and_noncanonical_state)
{
    rgb::Genesis genesis;
    genesis.ticker = "QQT";
    genesis.name = "Quantum Quasar Test Asset";
    genesis.total_supply = 1000;
    genesis.allocations = {AssignmentFor(1, 1000)};
    const uint256 contract_id = rgb::ContractId(genesis);

    rgb::Transition inflated;
    inflated.contract_id = contract_id;
    inflated.inputs = {SealFor(1)};
    inflated.outputs = {AssignmentFor(2, 1001)};
    BOOST_CHECK(!rgb::ValidateConsignment(genesis, {inflated}).valid);

    rgb::Transition first;
    first.contract_id = contract_id;
    first.inputs = {SealFor(1)};
    first.outputs = {AssignmentFor(2, 1000)};
    rgb::Transition double_spend;
    double_spend.contract_id = contract_id;
    double_spend.inputs = {SealFor(1)};
    double_spend.outputs = {AssignmentFor(3, 1000)};
    BOOST_CHECK(!rgb::ValidateConsignment(genesis, {first, double_spend}).valid);

    rgb::Genesis noncanonical = genesis;
    noncanonical.total_supply = 1001;
    noncanonical.allocations = {AssignmentFor(2, 1), AssignmentFor(1, 1000)};
    const rgb::ValidationResult noncanonical_result = rgb::ValidateConsignment(noncanonical, {});
    BOOST_CHECK(!noncanonical_result.valid);
}

BOOST_AUTO_TEST_CASE(rgb_anchor_uses_first_compatible_commitment)
{
    rgb::Genesis genesis;
    genesis.ticker = "QQT";
    genesis.name = "Quantum Quasar Test Asset";
    genesis.total_supply = 1000;
    genesis.allocations = {AssignmentFor(1, 1000)};

    rgb::Transition transition;
    transition.contract_id = rgb::ContractId(genesis);
    transition.inputs = {SealFor(1)};
    transition.outputs = {AssignmentFor(2, 1000)};
    const uint256 expected = rgb::AnchorCommitment(transition);
    const uint256 wrong = uint256::ONE;

    CMutableTransaction tx;
    tx.vout.emplace_back(0, CreateRGBCommitment(wrong));
    tx.vout.emplace_back(0, CreateRGBCommitment(expected));

    std::string error;
    BOOST_CHECK(!rgb::ValidateFirstRGBAnchor(CTransaction{tx}, expected, error));
    BOOST_CHECK_EQUAL(error, "first RGB anchor does not match expected commitment");

    tx.vout.clear();
    tx.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<unsigned char>{0x01});
    tx.vout.emplace_back(0, CreateRGBCommitment(expected));
    BOOST_CHECK(rgb::ValidateFirstRGBAnchor(CTransaction{tx}, expected, error));
    BOOST_CHECK(error.empty());

    BOOST_CHECK(!rgb::ValidateRGBAnchor(CTransaction{tx}, expected, {transition}, error));
    BOOST_CHECK_EQUAL(error.find("RGB anchor does not close input seal"), 0U);

    tx.vin.emplace_back(SealFor(1).outpoint);
    BOOST_CHECK(rgb::ValidateRGBAnchor(CTransaction{tx}, expected, {transition}, error));
    BOOST_CHECK(error.empty());

    tx.vin.emplace_back(SealFor(2).outpoint);
    BOOST_CHECK(!rgb::ValidateRGBAnchor(CTransaction{tx}, expected, {transition}, error));
    BOOST_CHECK_EQUAL(error.find("RGB anchor closes output seal"), 0U);
    tx.vin.pop_back();

    rgb::Transition followup;
    followup.contract_id = rgb::ContractId(genesis);
    followup.inputs = {SealFor(2)};
    followup.outputs = {AssignmentFor(3, 1000)};
    const uint256 scoped_expected = rgb::AnchorCommitment(followup);

    CMutableTransaction scoped_tx;
    scoped_tx.vin.emplace_back(SealFor(2).outpoint);
    scoped_tx.vout.emplace_back(0, CreateRGBCommitment(scoped_expected));
    BOOST_CHECK(rgb::ValidateRGBAnchor(CTransaction{scoped_tx}, scoped_expected, {followup}, error));
    BOOST_CHECK(error.empty());

    BOOST_CHECK(!rgb::ValidateRGBAnchor(CTransaction{scoped_tx}, scoped_expected, {transition, followup}, error));
    BOOST_CHECK_EQUAL(error.find("RGB anchor does not close input seal"), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
