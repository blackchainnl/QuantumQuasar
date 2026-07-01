// Copyright (c) 2012-2022 Blackcoin Core Developers
// Copyright (c) 2012-2022 Blackcoin More Developers
// Copyright (c) 2012-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>

#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <key.h>
#include <key_io.h>
#include <merkleblock.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> PubKeyA()
{
    return ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91");
}

std::vector<unsigned char> PubKeyB()
{
    return ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45af");
}

std::vector<unsigned char> HashA()
{
    return ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19");
}

std::vector<unsigned char> HashB()
{
    return ParseHex("a266436d2965547608b9e15d9032a7b9d64fa431");
}

CScript PushDataScript(const std::vector<unsigned char>& data)
{
    return CScript{} << data;
}

CScript PayToPubKey(const std::vector<unsigned char>& pubkey)
{
    return CScript{} << pubkey << OP_CHECKSIG;
}

CScript PayToPubKeyHash(const std::vector<unsigned char>& hash)
{
    return CScript{} << OP_DUP << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG;
}

CTransactionRef MakeTx(std::vector<CTxIn> vin, std::vector<CTxOut> vout)
{
    CMutableTransaction tx;
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.nTime = 0;
    tx.nLockTime = 0;
    tx.vin = std::move(vin);
    tx.vout = std::move(vout);
    return MakeTransactionRef(std::move(tx));
}

CBlock BuildSyntheticBlock()
{
    CBlock block;
    block.nVersion = 7;
    block.hashPrevBlock = uint256S("0x01");
    block.nTime = 1713938400;
    block.nBits = 0x207fffff;
    block.nNonce = 0;

    CTxIn coinbase_in;
    coinbase_in.prevout.SetNull();
    coinbase_in.scriptSig = CScript{} << OP_1;
    auto coinbase = MakeTx({coinbase_in}, {CTxOut{50 * COIN, PayToPubKey(PubKeyA())}});

    auto tx1 = MakeTx(
        {CTxIn{COutPoint{coinbase->GetHash(), 0}, PushDataScript(HashA())}},
        {CTxOut{10 * COIN, PayToPubKeyHash(HashA())}, CTxOut{1 * COIN, PayToPubKey(PubKeyB())}});
    auto tx2 = MakeTx(
        {CTxIn{COutPoint{tx1->GetHash(), 0}, PushDataScript(ParseHex("0102"))}},
        {CTxOut{9 * COIN, PayToPubKeyHash(ParseHex("00112233445566778899aabbccddeeff00112233"))}});
    auto tx3 = MakeTx(
        {CTxIn{COutPoint{tx1->GetHash(), 1}, CScript{}}},
        {CTxOut{1 * COIN, PayToPubKey(PubKeyA())}});
    auto tx4 = MakeTx(
        {CTxIn{COutPoint{uint256S("0x04"), 0}, PushDataScript(HashB())}},
        {CTxOut{2 * COIN, PayToPubKeyHash(HashB())}});
    auto tx5 = MakeTx(
        {CTxIn{COutPoint{uint256S("0x05"), 0}, CScript{}}},
        {CTxOut{3 * COIN, CScript{} << OP_RETURN << HashA()}});
    auto tx6 = MakeTx(
        {CTxIn{COutPoint{uint256S("0x06"), 0}, CScript{}}},
        {CTxOut{4 * COIN, PayToPubKeyHash(ParseHex("ffeeddccbbaa99887766554433221100ffeeddcc"))}});

    block.vtx = {coinbase, tx1, tx2, tx3, tx4, tx5, tx6};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

uint256 TxHash(const CTransaction& tx)
{
    return tx.GetHash().ToUint256();
}

void CheckMerkleMatches(const CBlock& block, const CBloomFilter& filter, const std::vector<unsigned int>& expected)
{
    CBloomFilter mutable_filter{filter};
    CMerkleBlock merkle_block{block, mutable_filter};

    BOOST_CHECK(merkle_block.header.GetHash() == block.GetHash());
    BOOST_REQUIRE_EQUAL(merkle_block.vMatchedTxn.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK_EQUAL(merkle_block.vMatchedTxn[i].first, expected[i]);
        BOOST_CHECK(merkle_block.vMatchedTxn[i].second == block.vtx[expected[i]]->GetHash());
    }

    std::vector<uint256> matched;
    std::vector<unsigned int> indexes;
    BOOST_CHECK(merkle_block.txn.ExtractMatches(matched, indexes) == block.hashMerkleRoot);
    BOOST_CHECK_EQUAL(matched.size(), expected.size());
    BOOST_CHECK_EQUAL(indexes.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK(matched[i] == block.vtx[expected[i]]->GetHash());
        BOOST_CHECK_EQUAL(indexes[i], expected[i]);
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter should be empty!");
    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    std::vector<uint8_t> expected = ParseHex("03614e9b050000000000000001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    std::vector<uint8_t> expected = ParseHex("03ce4299050000000100008001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    std::string strSecret = std::string("6AGd6aPXsyZz6TEL4JnQtRenZtA3qYUpFhupPwkbQnF9EwhVZM7");
    CKey key = DecodeSecret(strSecret);
    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(hash);

    DataStream stream{};
    stream << filter;

    std::vector<unsigned char> expected = ParseHex("038fc16b080000000000000001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    CBlock block = BuildSyntheticBlock();
    const CTransaction& tx = *block.vtx[1];
    const CTransaction& spending_tx = *block.vtx[2];

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(TxHash(tx));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    const uint256 tx_hash = TxHash(tx);
    filter.insert(Span<const unsigned char>{tx_hash.begin(), tx_hash.end()});
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(HashA());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input or output data");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spending_tx), "Simple Bloom filter didn't add matched output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(HashB());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(*block.vtx[4]), "Simple Bloom filter didn't match second output address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(tx.vin[0].prevout);
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("0x09"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(tx.vin[0].prevout.hash, 1));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched unrelated output index");
}

BOOST_AUTO_TEST_CASE(merkle_block_hash_matches)
{
    CBlock block = BuildSyntheticBlock();

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(TxHash(*block.vtx[6]));
    CheckMerkleMatches(block, filter, {6});

    filter.insert(TxHash(*block.vtx[3]));
    CheckMerkleMatches(block, filter, {3, 6});
}

BOOST_AUTO_TEST_CASE(merkle_block_update_all)
{
    CBlock block = BuildSyntheticBlock();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);

    filter.insert(PubKeyB());
    CheckMerkleMatches(block, filter, {1, 3});
}

BOOST_AUTO_TEST_CASE(merkle_block_update_none)
{
    CBlock block = BuildSyntheticBlock();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);

    filter.insert(PubKeyB());
    CheckMerkleMatches(block, filter, {1});
}

BOOST_AUTO_TEST_CASE(merkle_block_p2pubkey_only)
{
    CBlock block = BuildSyntheticBlock();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);

    filter.insert(PubKeyB());
    filter.insert(HashA());

    CMerkleBlock merkle_block(block, filter);
    BOOST_CHECK(merkle_block.header.GetHash() == block.GetHash());
    BOOST_CHECK(filter.contains(COutPoint(block.vtx[1]->GetHash(), 1)));
    BOOST_CHECK(!filter.contains(COutPoint(block.vtx[1]->GetHash(), 0)));
}

BOOST_AUTO_TEST_CASE(merkle_block_serialize)
{
    CBlock block = BuildSyntheticBlock();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(TxHash(*block.vtx[4]));

    CMerkleBlock merkle_block(block, filter);
    CDataStream stream{SER_NETWORK};
    stream << merkle_block;

    CMerkleBlock roundtrip;
    stream >> roundtrip;

    BOOST_CHECK(roundtrip.header.GetHash() == block.GetHash());
    std::vector<uint256> matched;
    std::vector<unsigned int> indexes;
    BOOST_CHECK(roundtrip.txn.ExtractMatches(matched, indexes) == block.hashMerkleRoot);
    BOOST_REQUIRE_EQUAL(matched.size(), 1U);
    BOOST_CHECK(matched[0] == block.vtx[4]->GetHash());
    BOOST_REQUIRE_EQUAL(indexes.size(), 1U);
    BOOST_CHECK_EQUAL(indexes[0], 4U);
}

static std::vector<unsigned char> RandomData()
{
    uint256 r = InsecureRand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    SeedInsecureRand(SeedRand::ZEROS);
    g_mock_deterministic_tests = true;

    CRollingBloomFilter rb1(100, 0.01);

    static const int DATASIZE = 399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData())) ++nHits;
    }
    BOOST_CHECK_EQUAL(nHits, 75U);

    BOOST_CHECK(rb1.contains(data[DATASIZE - 1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE - 1]));

    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100) BOOST_CHECK(rb1.contains(data[i - 100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }

    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i])) ++nHits;
    }
    BOOST_CHECK_EQUAL(nHits, 6U);

    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
    g_mock_deterministic_tests = false;
}

BOOST_AUTO_TEST_SUITE_END()
