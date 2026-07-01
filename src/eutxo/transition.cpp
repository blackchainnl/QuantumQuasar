// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <eutxo/transition.h>

#include <addresstype.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace eutxo {
namespace {

constexpr std::array<unsigned char, 8> TRANSITION_MAGIC{'Q', 'Q', 'E', 'U', 'T', 'X', 'O', '1'};
constexpr size_t HEADER_SIZE = TRANSITION_MAGIC.size() + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint16_t);

bool HasTransitionMagic(const std::vector<unsigned char>& redeemer)
{
    return redeemer.size() >= TRANSITION_MAGIC.size() &&
           std::equal(TRANSITION_MAGIC.begin(), TRANSITION_MAGIC.end(), redeemer.begin());
}

} // namespace

std::vector<unsigned char> EncodeStateTransition(const StateTransition& transition)
{
    if (transition.amount < 0 || !MoneyRange(transition.amount)) {
        throw std::runtime_error("EUTXO transition amount out of range");
    }
    if (transition.datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        transition.validator_script.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        transition.datum.size() > std::numeric_limits<uint16_t>::max() ||
        transition.validator_script.size() > std::numeric_limits<uint16_t>::max()) {
        throw std::runtime_error("EUTXO transition datum/validator too large");
    }

    std::vector<unsigned char> out(HEADER_SIZE + transition.datum.size() + transition.validator_script.size());
    std::copy(TRANSITION_MAGIC.begin(), TRANSITION_MAGIC.end(), out.begin());
    WriteLE32(out.data() + TRANSITION_MAGIC.size(), transition.output_index);
    WriteLE64(out.data() + TRANSITION_MAGIC.size() + sizeof(uint32_t), static_cast<uint64_t>(transition.amount));
    WriteLE16(out.data() + TRANSITION_MAGIC.size() + sizeof(uint32_t) + sizeof(uint64_t), static_cast<uint16_t>(transition.datum.size()));
    WriteLE16(out.data() + TRANSITION_MAGIC.size() + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint16_t), static_cast<uint16_t>(transition.validator_script.size()));
    auto it = out.begin() + HEADER_SIZE;
    it = std::copy(transition.datum.begin(), transition.datum.end(), it);
    std::copy(transition.validator_script.begin(), transition.validator_script.end(), it);
    return out;
}

DecodeStateTransitionResult DecodeStateTransition(const std::vector<unsigned char>& redeemer, StateTransition& transition, std::string& error)
{
    if (!HasTransitionMagic(redeemer)) {
        error.clear();
        return DecodeStateTransitionResult::NO_TRANSITION;
    }
    if (redeemer.size() < HEADER_SIZE) {
        error = "truncated EUTXO transition redeemer";
        return DecodeStateTransitionResult::MALFORMED;
    }

    const unsigned char* ptr = redeemer.data() + TRANSITION_MAGIC.size();
    const uint32_t output_index = ReadLE32(ptr);
    ptr += sizeof(uint32_t);
    const uint64_t raw_amount = ReadLE64(ptr);
    ptr += sizeof(uint64_t);
    const uint16_t datum_size = ReadLE16(ptr);
    ptr += sizeof(uint16_t);
    const uint16_t validator_size = ReadLE16(ptr);

    if (raw_amount > static_cast<uint64_t>(MAX_MONEY)) {
        error = "EUTXO transition amount out of range";
        return DecodeStateTransitionResult::MALFORMED;
    }
    if (datum_size > V4_MAX_SCRIPT_ELEMENT_SIZE || validator_size > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        error = "EUTXO transition datum/validator too large";
        return DecodeStateTransitionResult::MALFORMED;
    }
    if (redeemer.size() != HEADER_SIZE + datum_size + validator_size) {
        error = "EUTXO transition redeemer length mismatch";
        return DecodeStateTransitionResult::MALFORMED;
    }

    transition.output_index = output_index;
    transition.amount = static_cast<CAmount>(raw_amount);
    auto data_it = redeemer.begin() + HEADER_SIZE;
    transition.datum.assign(data_it, data_it + datum_size);
    data_it += datum_size;
    transition.validator_script = CScript(data_it, data_it + validator_size);
    error.clear();
    return DecodeStateTransitionResult::OK;
}

bool CheckStateTransition(const CTransaction& tx, unsigned int input_index, const CTxOut& spent_output, const StateTransition& transition, std::string& error)
{
    if (input_index >= tx.vin.size()) {
        error = "EUTXO transition input index out of range";
        return false;
    }
    if (transition.output_index >= tx.vout.size()) {
        error = "EUTXO transition output index out of range";
        return false;
    }
    if (transition.amount < 0 || !MoneyRange(transition.amount)) {
        error = "EUTXO transition amount out of range";
        return false;
    }
    if (transition.amount > spent_output.nValue) {
        error = "EUTXO transition amount exceeds spent EUTXO value";
        return false;
    }
    if (transition.datum.size() > V4_MAX_SCRIPT_ELEMENT_SIZE ||
        transition.validator_script.size() > V4_MAX_SCRIPT_ELEMENT_SIZE) {
        error = "EUTXO transition datum/validator too large";
        return false;
    }

    const CTxOut& successor = tx.vout[transition.output_index];
    if (successor.nValue != transition.amount) {
        error = "EUTXO transition successor amount mismatch";
        return false;
    }
    if (successor.scriptPubKey != GetScriptForEUTXO(transition.datum, transition.validator_script)) {
        error = "EUTXO transition successor commitment mismatch";
        return false;
    }

    error.clear();
    return true;
}

} // namespace eutxo
