// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/mldsa.h>
#include <node/quantum_pool.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(quantum_pool_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> PubKey(unsigned char tag)
{
    return std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, tag);
}

CScript QcsScript(const std::vector<unsigned char>& staker, const std::vector<unsigned char>& owner)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        QuantumColdStakeProgramForPubkeys(staker, owner)});
}

CScript TieredQcsScript(const std::vector<unsigned char>& staker, const std::vector<unsigned char>& owner)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        QuantumTieredColdStakeProgramForPubkeys(staker, owner, QUANTUM_TIERED_STATE_BONDED, 40500, 0)});
}

node::QuantumPoolClaim Claim(const COutPoint& outpoint, const std::vector<unsigned char>& staker, const std::vector<unsigned char>& owner)
{
    node::QuantumPoolClaim claim;
    claim.outpoint = outpoint;
    claim.staker_pubkey_hash = node::QuantumPoolHashPubKey(staker);
    claim.owner_pubkey_hash = node::QuantumPoolHashPubKey(owner);
    return claim;
}

node::QuantumPoolClaim TieredClaim(const COutPoint& outpoint, const std::vector<unsigned char>& staker, const std::vector<unsigned char>& owner)
{
    node::QuantumPoolClaim claim = Claim(outpoint, staker, owner);
    claim.tiered = true;
    claim.state = QUANTUM_TIERED_STATE_BONDED;
    claim.unbonding_blocks = 40500;
    claim.unlock_height = 0;
    return claim;
}

class MapCoinsCursor final : public CCoinsViewCursor
{
    using Map = std::map<COutPoint, Coin>;
    const Map& m_map;
    Map::const_iterator m_it;

public:
    explicit MapCoinsCursor(const Map& map) : CCoinsViewCursor(uint256::ONE), m_map(map), m_it(m_map.begin()) {}

    bool GetKey(COutPoint& key) const override
    {
        if (m_it == m_map.end()) return false;
        key = m_it->first;
        return true;
    }

    bool GetValue(Coin& coin) const override
    {
        if (m_it == m_map.end()) return false;
        coin = m_it->second;
        return true;
    }

    bool Valid() const override { return m_it != m_map.end(); }
    void Next() override { ++m_it; }
};

class MapCoinsView final : public CCoinsView
{
    std::map<COutPoint, Coin> m_coins;

public:
    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override
    {
        const auto it = m_coins.find(outpoint);
        if (it == m_coins.end() || it->second.IsSpent()) return false;
        coin = it->second;
        return true;
    }

    uint256 GetBestBlock() const override { return uint256::ONE; }
    std::unique_ptr<CCoinsViewCursor> Cursor() const override { return std::make_unique<MapCoinsCursor>(m_coins); }

    void Add(const COutPoint& outpoint, CAmount amount, const CScript& script)
    {
        m_coins.emplace(outpoint, Coin{CTxOut{amount, script}, /*nHeightIn=*/100, /*fCoinBaseIn=*/false, /*fCoinStakeIn=*/false, /*nTimeIn=*/0});
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(chainstate_share_verifies_discovery_claims)
{
    const auto staker_a = PubKey(0x11);
    const auto owner_a = PubKey(0x21);
    const auto staker_b = PubKey(0x12);
    const auto owner_b = PubKey(0x22);
    const auto staker_tiered = PubKey(0x13);
    const auto owner_tiered = PubKey(0x23);

    const COutPoint out_a{uint256::ONE, 0};
    const COutPoint out_b{uint256::ONE, 1};
    const COutPoint out_tiered{uint256::ONE, 2};
    const COutPoint out_plain{uint256::ONE, 3};

    MapCoinsView view;
    view.Add(out_a, 100 * COIN, QcsScript(staker_a, owner_a));
    view.Add(out_b, 400 * COIN, QcsScript(staker_b, owner_b));
    view.Add(out_tiered, 50 * COIN, TieredQcsScript(staker_tiered, owner_tiered));
    view.Add(out_plain, 999 * COIN, CScript() << OP_TRUE);

    BOOST_CHECK_EQUAL(node::ComputeQuantumColdStakeTotal(view), 550 * COIN);

    const auto claim_a = Claim(out_a, staker_a, owner_a);
    const auto share_a = node::ComputeQuantumPoolShare(view, node::QuantumPoolHashPubKey(staker_a), {claim_a});
    BOOST_CHECK_EQUAL(share_a.total_coldstake, 550 * COIN);
    BOOST_CHECK_EQUAL(share_a.operator_share.verified_value, 100 * COIN);
    BOOST_CHECK_EQUAL(share_a.operator_share.verified_claims, 1);
    BOOST_CHECK_EQUAL(share_a.operator_share.invalid_claims, 0);

    auto forged = Claim(out_a, staker_a, owner_b);
    const auto forged_result = node::VerifyQuantumPoolClaim(view, forged);
    BOOST_CHECK(!forged_result.valid);
    BOOST_CHECK_EQUAL(forged_result.reject_reason, "commitment-mismatch");

    const auto duplicate_share = node::ComputeQuantumPoolShare(view, node::QuantumPoolHashPubKey(staker_a), {claim_a, claim_a});
    BOOST_CHECK_EQUAL(duplicate_share.operator_share.verified_value, 100 * COIN);
    BOOST_CHECK_EQUAL(duplicate_share.operator_share.verified_claims, 1);
    BOOST_CHECK_EQUAL(duplicate_share.operator_share.invalid_claims, 1);

    const auto tiered_claim = TieredClaim(out_tiered, staker_tiered, owner_tiered);
    const auto tiered_result = node::VerifyQuantumPoolClaim(view, tiered_claim);
    BOOST_CHECK(tiered_result.valid);
    BOOST_CHECK_EQUAL(tiered_result.value, 50 * COIN);

    BOOST_CHECK_EQUAL(node::QuantumPoolShareBps(100 * COIN, 500 * COIN), 2000);
    BOOST_CHECK(node::WouldQuantumPoolExceedCap(500 * COIN, 100 * COIN, 1 * COIN));
    BOOST_CHECK(!node::WouldQuantumPoolExceedCap(500 * COIN, 0, 1 * COIN));
}

BOOST_AUTO_TEST_SUITE_END()
