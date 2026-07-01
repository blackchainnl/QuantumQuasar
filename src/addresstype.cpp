// Copyright (c) 2023 Blackcoin Core Developers
// Copyright (c) 2023 Blackcoin More Developers
// Copyright (c) 2023 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>

#include <crypto/mldsa.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/hash_type.h>

#include <cassert>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

typedef std::vector<unsigned char> valtype;

ScriptHash::ScriptHash(const CScript& in) : BaseHash(Hash160(in)) {}
ScriptHash::ScriptHash(const CScriptID& in) : BaseHash{in} {}

PKHash::PKHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
PKHash::PKHash(const CKeyID& pubkey_id) : BaseHash(pubkey_id) {}

WitnessV0KeyHash::WitnessV0KeyHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
WitnessV0KeyHash::WitnessV0KeyHash(const PKHash& pubkey_hash) : BaseHash{pubkey_hash} {}

CKeyID ToKeyID(const PKHash& key_hash)
{
    return CKeyID{uint160{key_hash}};
}

CKeyID ToKeyID(const WitnessV0KeyHash& key_hash)
{
    return CKeyID{uint160{key_hash}};
}

CScriptID ToScriptID(const ScriptHash& script_hash)
{
    return CScriptID{uint160{script_hash}};
}

WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript& in)
{
    CSHA256().Write(in.data(), in.size()).Finalize(begin());
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    switch (whichType) {
    case TxoutType::PUBKEY: {
        CPubKey pubKey(vSolutions[0]);

        /*
        if (!pubKey.IsValid()) {
            addressRet = CNoDestination(scriptPubKey);
        } else {
            addressRet = PubKeyDestination(pubKey);
        }
        return false;
        */

        // Blackcoin: Reinterpret P2PK scripts as PKHash
        // We need to do that because proof-of-stake mechanism uses P2PK outputs
        // It partially reverts Bitcoin Core PR#28246 https://github.com/bitcoin/bitcoin/pull/28246
        if (!pubKey.IsValid())
            return false;

        addressRet = PKHash(pubKey);
        return true;
    }
    case TxoutType::PUBKEYHASH: {
        addressRet = PKHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        addressRet = ScriptHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::WITNESS_V0_KEYHASH: {
        WitnessV0KeyHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH: {
        WitnessV0ScriptHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::WITNESS_V1_TAPROOT: {
        WitnessV1Taproot tap;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), tap.begin());
        addressRet = tap;
        return true;
    }
    case TxoutType::EUTXO_COMMITMENT:
    case TxoutType::WITNESS_UNKNOWN: {
        addressRet = WitnessUnknown{vSolutions[0][0], vSolutions[1]};
        return true;
    }
    case TxoutType::MULTISIG:
    case TxoutType::RGB_COMMITMENT:
    case TxoutType::NULL_DATA:
    case TxoutType::NONSTANDARD: {
        addressRet = CNoDestination(scriptPubKey);
        
        // Blackcoin: Allow non-standard type with empty scriptPubKey
        if (scriptPubKey.empty()) {
            return true;
        }

        return false;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
    return false;
}

namespace {
class CScriptVisitor
{
public:
    CScript operator()(const CNoDestination& dest) const
    {
        return dest.GetScript();
    }

    CScript operator()(const PubKeyDestination& dest) const
    {
        return CScript() << ToByteVector(dest.GetPubKey()) << OP_CHECKSIG;
    }

    CScript operator()(const PKHash& keyID) const
    {
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const ScriptHash& scriptID) const
    {
        return CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    }

    CScript operator()(const WitnessV0KeyHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV0ScriptHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV1Taproot& tap) const
    {
        return CScript() << OP_1 << ToByteVector(tap);
    }

    CScript operator()(const WitnessUnknown& id) const
    {
        return CScript() << CScript::EncodeOP_N(id.GetWitnessVersion()) << id.GetWitnessProgram();
    }
};

class ValidDestinationVisitor
{
public:
    bool operator()(const CNoDestination& dest) const { return false; }
    bool operator()(const PubKeyDestination& dest) const { return false; }
    bool operator()(const PKHash& dest) const { return true; }
    bool operator()(const ScriptHash& dest) const { return true; }
    bool operator()(const WitnessV0KeyHash& dest) const { return true; }
    bool operator()(const WitnessV0ScriptHash& dest) const { return true; }
    bool operator()(const WitnessV1Taproot& dest) const { return true; }
    bool operator()(const WitnessUnknown& dest) const { return true; }
};
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    return std::visit(CScriptVisitor(), dest);
}

bool IsValidDestination(const CTxDestination& dest) {
    return std::visit(ValidDestinationVisitor(), dest);
}

std::optional<QuantumStakeTierProgram> GetQuantumStakeTierProgram(const CScript& scriptPubKey)
{
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    if (!scriptPubKey.IsWitnessProgram(witness_version, witness_program)) return std::nullopt;
    QuantumStakeTierProgram tier;
    if (!DecodeQuantumStakeTierProgram(static_cast<unsigned int>(witness_version), witness_program, tier)) return std::nullopt;
    return tier;
}

std::vector<unsigned char> QuantumMigrationProgramForPubkey(const std::vector<unsigned char>& public_key)
{
    uint256 pubkey_hash;
    CSHA256().Write(public_key.data(), public_key.size()).Finalize(pubkey_hash.begin());
    return {pubkey_hash.begin(), pubkey_hash.end()};
}

std::vector<unsigned char> QuantumTieredMigrationProgramForPubkey(const std::vector<unsigned char>& public_key, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height)
{
    uint256 pubkey_hash;
    CSHA256().Write(public_key.data(), public_key.size()).Finalize(pubkey_hash.begin());
    return QuantumTieredProgramForCommitment(state, unbonding_blocks, unlock_height, pubkey_hash);
}

bool IsQuantumMigrationDestination(const CTxDestination& dest)
{
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    return witness && IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram());
}

bool IsQuantumMigrationScript(const CScript& scriptPubKey)
{
    int witness_version;
    std::vector<unsigned char> witness_program;
    return scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
           IsQuantumMigrationWitnessProgram(witness_version, witness_program);
}

bool ExtractQuantumBlockSigningPubKey(const CScript& scriptPubKey, std::vector<unsigned char>& pubkey)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> push_value;
    if (!scriptPubKey.GetOp(pc, opcode, push_value) || opcode != OP_RETURN) return false;
    if (!scriptPubKey.GetOp(pc, opcode, push_value) || push_value.size() != ML_DSA::PUBLICKEY_BYTES) return false;
    if (pc != scriptPubKey.end()) return false;
    pubkey = std::move(push_value);
    return true;
}

std::vector<unsigned char> QuantumColdStakeProgramForPubkeys(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey)
{
    uint256 staker_hash;
    uint256 owner_hash;
    CSHA256().Write(staker_pubkey.data(), staker_pubkey.size()).Finalize(staker_hash.begin());
    CSHA256().Write(owner_pubkey.data(), owner_pubkey.size()).Finalize(owner_hash.begin());
    return QuantumColdStakeProgramForKeyHashes(staker_hash, owner_hash);
}

std::vector<unsigned char> QuantumTieredColdStakeProgramForPubkeys(const std::vector<unsigned char>& staker_pubkey, const std::vector<unsigned char>& owner_pubkey, unsigned char state, uint16_t unbonding_blocks, uint32_t unlock_height)
{
    uint256 staker_hash;
    uint256 owner_hash;
    CSHA256().Write(staker_pubkey.data(), staker_pubkey.size()).Finalize(staker_hash.begin());
    CSHA256().Write(owner_pubkey.data(), owner_pubkey.size()).Finalize(owner_hash.begin());
    return QuantumTieredColdStakeProgramForKeyHashes(staker_hash, owner_hash, state, unbonding_blocks, unlock_height);
}

bool IsQuantumColdStakeDestination(const CTxDestination& dest)
{
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    return witness && IsQuantumColdStakeWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram());
}

bool IsQuantumColdStakeScript(const CScript& scriptPubKey)
{
    int witness_version;
    std::vector<unsigned char> witness_program;
    return scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
           IsQuantumColdStakeWitnessProgram(witness_version, witness_program);
}

bool IsEUTXOWitnessProgram(unsigned int witness_version, const std::vector<unsigned char>& witness_program)
{
    return witness_version == EUTXO_WITNESS_VERSION &&
           witness_program.size() == EUTXO_PROGRAM_SIZE;
}

bool IsEUTXOScript(const CScript& scriptPubKey)
{
    int witness_version;
    std::vector<unsigned char> witness_program;
    return scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
           IsEUTXOWitnessProgram(witness_version, witness_program);
}

CScript GetScriptForEUTXO(const std::vector<unsigned char>& datum, const CScript& validator_script)
{
    return CScript() << CScript::EncodeOP_N(EUTXO_WITNESS_VERSION) << EUTXOProgramForDatumAndValidator(datum, validator_script);
}
