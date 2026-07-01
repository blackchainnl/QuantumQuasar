#include <crypto/mldsa.h>

#include <oqs/oqs.h>

#include <algorithm>
#include <array>

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
