// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RGB_ENGINE_H
#define BITCOIN_RGB_ENGINE_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

class CScript;

namespace rgb {

struct Seal {
    COutPoint outpoint;

    friend bool operator==(const Seal& a, const Seal& b) { return a.outpoint == b.outpoint; }
    friend bool operator<(const Seal& a, const Seal& b) { return a.outpoint < b.outpoint; }
};

struct Assignment {
    Seal seal;
    uint64_t amount{0};

    friend bool operator==(const Assignment& a, const Assignment& b)
    {
        return a.seal == b.seal && a.amount == b.amount;
    }
};

struct Genesis {
    std::string ticker;
    std::string name;
    uint64_t total_supply{0};
    std::vector<Assignment> allocations;
};

struct Transition {
    uint256 contract_id;
    std::vector<Seal> inputs;
    std::vector<Assignment> outputs;
};

struct ValidationResult {
    bool valid{false};
    uint256 contract_id;
    uint64_t current_supply{0};
    size_t unspent_assignments{0};
    std::vector<std::string> errors;
    std::map<Seal, uint64_t> unspent;
};

uint256 ContractId(const Genesis& genesis);
uint256 TransitionId(const Transition& transition);
uint256 AnchorCommitment(const std::vector<uint256>& transition_ids);
uint256 AnchorCommitment(const Transition& transition);

ValidationResult ValidateConsignment(const Genesis& genesis, const std::vector<Transition>& transitions);

std::optional<uint256> DecodeRGBCommitment(const CScript& script);
std::optional<std::pair<unsigned int, uint256>> FirstRGBCommitment(const CTransaction& tx);
bool ValidateFirstRGBAnchor(const CTransaction& tx, const uint256& expected_commitment, std::string& error);
bool ValidateRGBAnchor(const CTransaction& tx, const uint256& expected_commitment, const std::vector<Transition>& transitions, std::string& error);

} // namespace rgb

#endif // BITCOIN_RGB_ENGINE_H
