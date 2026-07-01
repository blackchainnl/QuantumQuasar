#ifndef BLACKCOIN_CRYPTO_MLDSA_H
#define BLACKCOIN_CRYPTO_MLDSA_H

#include <vector>
#include <stdint.h>
#include <stddef.h>

/**
 * Quantum Quasar Post-Quantum Cryptography Engine
 * Wraps the NIST standard ML-DSA-44 implementation provided by liboqs.
 */

class ML_DSA {
public:
    static constexpr size_t PUBLICKEY_BYTES = 1312;
    static constexpr size_t SECRETKEY_BYTES = 2560;
    static constexpr size_t SIGNATURE_BYTES = 2420;

    /** Generate a new ML-DSA keypair */
    static bool KeyGen(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey);

    /** Sign a 32-byte message hash using the ML-DSA private key */
    static bool Sign(const std::vector<uint8_t>& privkey, const uint8_t* hash, size_t hash_len, std::vector<uint8_t>& signature);

    /** Verify an ML-DSA signature against a message hash and public key */
    static bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* hash, size_t hash_len, const std::vector<uint8_t>& signature);

    /** Startup self-test for linked ML-DSA implementation */
    static bool SelfTest();
};

#endif // BLACKCOIN_CRYPTO_MLDSA_H
