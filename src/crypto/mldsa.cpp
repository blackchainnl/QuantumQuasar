#include <crypto/mldsa.h>

#include <crypto/sha256.h>

#include <oqs/oqs.h>

#include <algorithm>
#include <array>

namespace {

uint64_t g_kat_rng_state_0;
uint64_t g_kat_rng_state_1;

uint64_t KatNextRandom()
{
    uint64_t x = g_kat_rng_state_0;
    const uint64_t y = g_kat_rng_state_1;
    g_kat_rng_state_0 = y;
    x ^= x << 23;
    g_kat_rng_state_1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return g_kat_rng_state_1 + y;
}

void KatRandomBytes(uint8_t* out, size_t len)
{
    size_t pos{0};
    while (pos < len) {
        uint64_t v = KatNextRandom();
        for (int i = 0; i < 8 && pos < len; ++i) {
            out[pos++] = static_cast<uint8_t>(v & 0xff);
            v >>= 8;
        }
    }
}

bool RunKnownAnswerTest()
{
    static constexpr std::array<uint8_t, 32> MSG{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static constexpr std::array<uint8_t, CSHA256::OUTPUT_SIZE> EXPECTED_PUBKEY_SIG_HASH{
        0xa7, 0x20, 0xc2, 0xa4, 0xa4, 0xbb, 0xc4, 0xb3,
        0x43, 0xb8, 0xa9, 0xeb, 0x1e, 0xf3, 0xd9, 0x4d,
        0x34, 0xb2, 0x47, 0x47, 0x0d, 0xc3, 0x31, 0x0c,
        0x90, 0x5c, 0x4e, 0x2a, 0x87, 0x3d, 0x33, 0x0c,
    };

    g_kat_rng_state_0 = 0x9e3779b97f4a7c15ULL;
    g_kat_rng_state_1 = 0xd1b54a32d192ed03ULL;
    OQS_randombytes_custom_algorithm(&KatRandomBytes);

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    std::vector<uint8_t> signature;
    bool ok = ML_DSA::KeyGen(pubkey, privkey) &&
              pubkey.size() == ML_DSA::PUBLICKEY_BYTES &&
              privkey.size() == ML_DSA::SECRETKEY_BYTES &&
              ML_DSA::Sign(privkey, MSG.data(), MSG.size(), signature) &&
              signature.size() == ML_DSA::SIGNATURE_BYTES;
    std::fill(privkey.begin(), privkey.end(), 0);

    if (ok) {
        std::array<uint8_t, CSHA256::OUTPUT_SIZE> actual_hash{};
        CSHA256()
            .Write(pubkey.data(), pubkey.size())
            .Write(signature.data(), signature.size())
            .Finalize(actual_hash.data());
        ok = actual_hash == EXPECTED_PUBKEY_SIG_HASH;
    }
    if (ok) {
        ok = ML_DSA::Verify(pubkey, MSG.data(), MSG.size(), signature);
    }
    if (ok) {
        std::vector<uint8_t> tampered_signature{signature};
        tampered_signature[0] ^= 0x01;
        ok = !ML_DSA::Verify(pubkey, MSG.data(), MSG.size(), tampered_signature);
    }
    if (ok) {
        std::array<uint8_t, MSG.size()> tampered_message{MSG};
        tampered_message[0] ^= 0x01;
        ok = !ML_DSA::Verify(pubkey, tampered_message.data(), tampered_message.size(), signature);
    }

    const bool restored = OQS_randombytes_switch_algorithm(OQS_RAND_alg_system) == OQS_SUCCESS;
    return ok && restored;
}

} // namespace

bool ML_DSA::KeyGen(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == nullptr) {
        pubkey.clear();
        privkey.clear();
        return false;
    }
    if (sig->length_public_key != PUBLICKEY_BYTES || sig->length_secret_key != SECRETKEY_BYTES || sig->length_signature != SIGNATURE_BYTES) {
        OQS_SIG_free(sig);
        pubkey.clear();
        privkey.clear();
        return false;
    }

    pubkey.assign(PUBLICKEY_BYTES, 0);
    privkey.assign(SECRETKEY_BYTES, 0);
    const bool ok = OQS_SIG_keypair(sig, pubkey.data(), privkey.data()) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    if (!ok) {
        std::fill(pubkey.begin(), pubkey.end(), 0);
        std::fill(privkey.begin(), privkey.end(), 0);
        pubkey.clear();
        privkey.clear();
    }
    return ok;
}

bool ML_DSA::Sign(const std::vector<uint8_t>& privkey, const uint8_t* hash, size_t hash_len, std::vector<uint8_t>& signature) {
    signature.clear();
    if (privkey.size() != SECRETKEY_BYTES || hash == nullptr || hash_len == 0) return false;

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == nullptr) return false;
    if (sig->length_secret_key != SECRETKEY_BYTES || sig->length_signature != SIGNATURE_BYTES) {
        OQS_SIG_free(sig);
        return false;
    }

    signature.assign(SIGNATURE_BYTES, 0);
    size_t signature_len = 0;
    const bool ok = OQS_SIG_sign(sig, signature.data(), &signature_len, hash, hash_len, privkey.data()) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    if (!ok || signature_len != SIGNATURE_BYTES) {
        std::fill(signature.begin(), signature.end(), 0);
        signature.clear();
        return false;
    }
    return true;
}

bool ML_DSA::Verify(const std::vector<uint8_t>& pubkey, const uint8_t* hash, size_t hash_len, const std::vector<uint8_t>& signature) {
    if (pubkey.size() != PUBLICKEY_BYTES || signature.size() != SIGNATURE_BYTES || hash == nullptr || hash_len == 0) return false;

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == nullptr) return false;
    if (sig->length_public_key != PUBLICKEY_BYTES || sig->length_signature != SIGNATURE_BYTES) {
        OQS_SIG_free(sig);
        return false;
    }

    const bool ok = OQS_SIG_verify(sig, hash, hash_len, signature.data(), signature.size(), pubkey.data()) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
}

bool ML_DSA::SelfTest()
{
    if (!RunKnownAnswerTest()) return false;

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    if (!KeyGen(pubkey, privkey)) return false;
    if (pubkey.size() != PUBLICKEY_BYTES || privkey.size() != SECRETKEY_BYTES) return false;

    std::array<uint8_t, 32> message{};
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<uint8_t>(i);
    }

    std::vector<uint8_t> signature;
    const bool signed_ok = Sign(privkey, message.data(), message.size(), signature);
    std::fill(privkey.begin(), privkey.end(), 0);
    if (!signed_ok || signature.size() != SIGNATURE_BYTES) return false;
    if (!Verify(pubkey, message.data(), message.size(), signature)) return false;

    std::vector<uint8_t> tampered_signature{signature};
    tampered_signature[0] ^= 0x01;
    if (Verify(pubkey, message.data(), message.size(), tampered_signature)) return false;

    message[0] ^= 0x01;
    if (Verify(pubkey, message.data(), message.size(), signature)) return false;

    return true;
}
