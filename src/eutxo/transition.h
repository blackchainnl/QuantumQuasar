// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EUTXO_TRANSITION_H
#define BITCOIN_EUTXO_TRANSITION_H

#include <consensus/amount.h>
#include <script/script.h>

#include <cstdint>
#include <string>
#include <vector>

class CTransaction;
class CTxOut;

namespace eutxo {

struct StateTransition {
    uint32_t output_index{0};
    CAmount amount{0};
    std::vector<unsigned char> datum;
    CScript validator_script;
};

enum class DecodeStateTransitionResult {
    NO_TRANSITION,
    MALFORMED,
    OK,
};

std::vector<unsigned char> EncodeStateTransition(const StateTransition& transition);
DecodeStateTransitionResult DecodeStateTransition(const std::vector<unsigned char>& redeemer, StateTransition& transition, std::string& error);
bool CheckStateTransition(const CTransaction& tx, unsigned int input_index, const CTxOut& spent_output, const StateTransition& transition, std::string& error);

} // namespace eutxo

#endif // BITCOIN_EUTXO_TRANSITION_H
