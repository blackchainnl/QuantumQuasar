// Copyright (c) 2023 Blackcoin Core Developers
// Copyright (c) 2023 Blackcoin More Developers
// Copyright (c) 2023 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRESSTYPE_H
#define BITCOIN_ADDRESSTYPE_H

#include <consensus/quantum_witness.h>
#include <pubkey.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <script/script.h>
#include <uint256.h>
#include <util/hash_type.h>

#include <variant>
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>

static constexpr unsigned int EUTXO_WITNESS_VERSION = 15;
static constexpr unsigned int EUTXO_PROGRAM_SIZE = 32;

class CNoDestination
{
private:
    CScript m_script;

public:
    CNoDestination() = default;
    explicit CNoDestination(const CScript& script) : m_script(script) {}

    const CScript& GetScript() const LIFETIMEBOUND { return m_script; }

    friend bool operator==(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() == b.GetScript(); }
    friend bool operator<(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() < b.GetScript(); }
};

struct PubKeyDestination {
private:
    CPubKey m_pubkey;

public:
    explicit PubKeyDestination(const CPubKey& pubkey) : m_pubkey(pubkey) {}

    const CPubKey& GetPubKey() const LIFETIMEBOUND { return m_pubkey; }

    friend bool operator==(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() == b.GetPubKey(); }
    friend bool operator<(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() < b.GetPubKey(); }
};

struct PKHash : public BaseHash<uint160>
{
    PKHash() : BaseHash() {}
    explicit PKHash(const uint160& hash) : BaseHash(hash) {}
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};
CKeyID ToKeyID(const PKHash& key_hash);

struct WitnessV0KeyHash;

struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};
CScriptID ToScriptID(const ScriptHash& script_hash);

struct WitnessV0ScriptHash : public BaseHash<uint256>
{
    WitnessV0ScriptHash() : BaseHash() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV0ScriptHash(const CScript& script);
};

struct WitnessV0KeyHash : public BaseHash<uint160>
{
    WitnessV0KeyHash() : BaseHash() {}
    explicit WitnessV0KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
    explicit WitnessV0KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash);

struct WitnessV1Taproot : public XOnlyPubKey
{
    WitnessV1Taproot() : XOnlyPubKey() {}
    explicit WitnessV1Taproot(const XOnlyPubKey& xpk) : XOnlyPubKey(xpk) {}
};

//! CTxDestination subtype to encode any future Witness version
struct WitnessUnknown
{
private:
    unsigned int m_version;
    std::vector<unsigned char> m_program;

public:
    WitnessUnknown(unsigned int version, const std::vector<unsigned char>& program) : m_version(version), m_program(program) {}
    WitnessUnknown(int version, const std::vector<unsigned char>& program) : m_version(static_cast<unsigned int>(version)), m_program(program) {}

    unsigned int GetWitnessVersion() const { return m_version; }
    const std::vector<unsigned char>& GetWitnessProgram() const LIFETIMEBOUND { return m_program; }

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() != w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() == w2.GetWitnessProgram();
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() < w2.GetWitnessVersion()) return true;
        if (w1.GetWitnessVersion() > w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() < w2.GetWitnessProgram();
    }
};

/**
 * A txout script categorized into standard templates.
 *  * CNoDestination: Optionally a script, no corresponding address.
 *  * PubKeyDestination: TxoutType::PUBKEY (P2PK), no corresponding address
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH address)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH address)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH address)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH address)
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR address)
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN destination (P2W??? address)
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, WitnessUnknown>;

/** Check whether a CTxDestination corresponds to one with an address. */
bool IsValidDestination(const CTxDestination& dest);
std::optional<QuantumStakeTierProgram> GetQuantumStakeTierProgram(const CScript& scriptPubKey);
std::vector<unsigned char> QuantumMigrationProgramForPubkey(const std::vector<unsigned char>& public_key);
std::vector<unsigned char> QuantumTieredMigrationProgramForPubkey(const std::vector<unsigned char>& public_key, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height);
bool IsQuantumMigrationDestination(const CTxDestination& dest);
bool IsQuantumMigrationScript(const CScript& scriptPubKey);
bool ExtractQuantumBlockSigningPubKey(const CScript& scriptPubKey, std::vector<unsigned char>& pubkey);
inline std::vector<unsigned char> QuantumColdStakeProgramForKeyHashes(const uint256& staker_pubkey_hash, const uint256& owner_pubkey_hash)
{
    HashWriter ss{};
    ss << std::string("Quantum Quasar Cold Stake v1");
    ss << staker_pubkey_hash;
    ss << owner_pubkey_hash;
    const uint256 program_hash = ss.GetHash();
    return {program_hash.begin(), program_hash.end()};
}

std::vector<unsigned char> QuantumColdStakeProgramForPubkeys(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey);
std::vector<unsigned char> QuantumTieredColdStakeProgramForPubkeys(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height);
bool IsQuantumColdStakeDestination(const CTxDestination& dest);
bool IsQuantumColdStakeScript(const CScript& scriptPubKey);
bool IsEUTXOWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program);
bool IsEUTXOScript(const CScript& scriptPubKey);
CScript GetScriptForEUTXO(const std::vector<unsigned char>& datum, const CScript& validator_script);

inline std::vector<unsigned char> EUTXOProgramForDatumAndValidator(const std::vector<unsigned char>& datum, const CScript& validator_script)
{
    uint256 datum_hash;
    uint256 validator_hash;
    CSHA256().Write(datum.data(), datum.size()).Finalize(datum_hash.begin());
    CSHA256().Write(validator_script.data(), validator_script.size()).Finalize(validator_hash.begin());

    HashWriter ss{};
    ss << std::string("Quantum Quasar EUTXO v1");
    ss << datum_hash;
    ss << validator_hash;
    const uint256 program_hash = ss.GetHash();
    return {program_hash.begin(), program_hash.end()};
}

/**
 * Parse a scriptPubKey for the destination.
 *
 * For standard scripts that have addresses (and P2PK as an exception), a corresponding CTxDestination
 * is assigned to addressRet.
 * For all other scripts. addressRet is assigned as a CNoDestination containing the scriptPubKey.
 *
 * Returns true for standard destinations with addresses - P2PKH, P2SH, P2WPKH, P2WSH, P2TR and P2W??? scripts.
 * Returns false for non-standard destinations and those without addresses - P2PK, bare multisig, null data, and nonstandard scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Generate a Bitcoin scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

#endif // BITCOIN_ADDRESSTYPE_H
