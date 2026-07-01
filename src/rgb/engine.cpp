// Copyright (c) 2026 Blackcoin Core Developers
// Copyright (c) 2026 Blackcoin More Developers
// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <rgb/engine.h>

#include <hash.h>
#include <script/solver.h>

#include <algorithm>
#include <limits>
#include <set>

namespace rgb {
namespace {

bool AddAmount(uint64_t& acc, uint64_t value)
{
    if (value > std::numeric_limits<uint64_t>::max() - acc) return false;
    acc += value;
    return true;
}

template <typename T, typename Less>
bool IsStrictlySorted(const std::vector<T>& values, Less less)
{
    return std::adjacent_find(values.begin(), values.end(), [&](const T& a, const T& b) {
        return !less(a, b);
    }) == values.end();
}

bool IsCanonicalSeals(const std::vector<Seal>& seals)
{
    return IsStrictlySorted(seals, [](const Seal& a, const Seal& b) { return a < b; });
}

bool IsCanonicalAssignments(const std::vector<Assignment>& assignments)
{
    return IsStrictlySorted(assignments, [](const Assignment& a, const Assignment& b) {
        return a.seal < b.seal;
    });
}

void HashSeal(HashWriter& ss, const Seal& seal)
{
    ss << seal.outpoint;
}

void HashAssignment(HashWriter& ss, const Assignment& assignment)
{
    HashSeal(ss, assignment.seal);
    ss << assignment.amount;
}

} // namespace

uint256 ContractId(const Genesis& genesis)
{
    HashWriter ss{};
    ss << std::string{"Quantum Quasar RGB fixed fungible genesis v1"};
    ss << genesis.ticker;
    ss << genesis.name;
    ss << genesis.total_supply;
    ss << static_cast<uint64_t>(genesis.allocations.size());
    for (const Assignment& assignment : genesis.allocations) {
        HashAssignment(ss, assignment);
    }
    return ss.GetHash();
}

uint256 TransitionId(const Transition& transition)
{
    HashWriter ss{};
    ss << std::string{"Quantum Quasar RGB fixed fungible transition v1"};
    ss << transition.contract_id;
    ss << static_cast<uint64_t>(transition.inputs.size());
    for (const Seal& input : transition.inputs) {
        HashSeal(ss, input);
    }
    ss << static_cast<uint64_t>(transition.outputs.size());
    for (const Assignment& output : transition.outputs) {
        HashAssignment(ss, output);
    }
    return ss.GetHash();
}

uint256 AnchorCommitment(const std::vector<uint256>& transition_ids)
{
    HashWriter ss{};
    ss << std::string{"Quantum Quasar RGB anchor bundle v1"};
    ss << static_cast<uint64_t>(transition_ids.size());
    for (const uint256& transition_id : transition_ids) {
        ss << transition_id;
    }
    return ss.GetHash();
}

uint256 AnchorCommitment(const Transition& transition)
{
    return AnchorCommitment(std::vector<uint256>{TransitionId(transition)});
}

ValidationResult ValidateConsignment(const Genesis& genesis, const std::vector<Transition>& transitions)
{
    ValidationResult result;
    result.contract_id = ContractId(genesis);

    auto fail = [&](std::string error) {
        result.errors.push_back(std::move(error));
    };

    if (genesis.ticker.empty()) fail("genesis ticker is empty");
    if (genesis.total_supply == 0) fail("genesis total supply is zero");
    if (genesis.allocations.empty()) fail("genesis allocations are empty");
    if (!IsCanonicalAssignments(genesis.allocations)) fail("genesis allocations are not strictly sorted by seal");

    uint64_t genesis_sum{0};
    for (const Assignment& allocation : genesis.allocations) {
        if (allocation.amount == 0) fail("genesis allocation amount is zero");
        if (!AddAmount(genesis_sum, allocation.amount)) fail("genesis allocation amount overflow");
        if (!result.unspent.emplace(allocation.seal, allocation.amount).second) {
            fail("duplicate genesis allocation seal");
        }
    }
    if (genesis_sum != genesis.total_supply) fail("genesis allocations do not equal total supply");

    std::set<uint256> seen_transition_ids;
    for (const Transition& transition : transitions) {
        if (transition.contract_id != result.contract_id) {
            fail("transition contract id mismatch");
            continue;
        }
        if (transition.inputs.empty()) fail("transition inputs are empty");
        if (transition.outputs.empty()) fail("transition outputs are empty");
        if (!IsCanonicalSeals(transition.inputs)) fail("transition inputs are not strictly sorted");
        if (!IsCanonicalAssignments(transition.outputs)) fail("transition outputs are not strictly sorted by seal");

        const uint256 transition_id = TransitionId(transition);
        if (!seen_transition_ids.insert(transition_id).second) fail("duplicate transition");

        std::set<Seal> consumed;
        uint64_t input_sum{0};
        bool transition_inputs_ok{true};
        for (const Seal& input : transition.inputs) {
            if (!consumed.insert(input).second) {
                fail("duplicate transition input seal");
                transition_inputs_ok = false;
                continue;
            }
            const auto it = result.unspent.find(input);
            if (it == result.unspent.end()) {
                fail("transition spends unknown or already-spent seal");
                transition_inputs_ok = false;
                continue;
            }
            if (!AddAmount(input_sum, it->second)) fail("transition input amount overflow");
        }

        uint64_t output_sum{0};
        bool transition_outputs_ok{true};
        std::set<Seal> created;
        for (const Assignment& output : transition.outputs) {
            if (output.amount == 0) {
                fail("transition output amount is zero");
                transition_outputs_ok = false;
            }
            if (!AddAmount(output_sum, output.amount)) fail("transition output amount overflow");
            if (!created.insert(output.seal).second) {
                fail("duplicate transition output seal");
                transition_outputs_ok = false;
            }
            if (consumed.count(output.seal) || result.unspent.count(output.seal)) {
                fail("transition output reuses an existing seal");
                transition_outputs_ok = false;
            }
        }

        if (input_sum != output_sum) {
            fail("transition input and output amounts do not balance");
            continue;
        }
        if (!transition_inputs_ok || !transition_outputs_ok) continue;

        for (const Seal& input : transition.inputs) {
            result.unspent.erase(input);
        }
        for (const Assignment& output : transition.outputs) {
            result.unspent.emplace(output.seal, output.amount);
        }
    }

    for (const auto& [seal, amount] : result.unspent) {
        if (!AddAmount(result.current_supply, amount)) fail("current supply overflow");
    }
    if (result.current_supply != genesis.total_supply) fail("current supply does not equal total supply");
    result.unspent_assignments = result.unspent.size();
    result.valid = result.errors.empty();
    return result;
}

std::optional<uint256> DecodeRGBCommitment(const CScript& script)
{
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(script, solutions) != TxoutType::RGB_COMMITMENT ||
        solutions.size() != 1 ||
        solutions[0].size() != 4 + uint256::size()) {
        return std::nullopt;
    }

    uint256 commitment;
    std::reverse_copy(solutions[0].begin() + 4, solutions[0].end(), commitment.begin());
    return commitment;
}

std::optional<std::pair<unsigned int, uint256>> FirstRGBCommitment(const CTransaction& tx)
{
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        if (const auto commitment = DecodeRGBCommitment(tx.vout[i].scriptPubKey)) {
            return std::make_pair(i, *commitment);
        }
    }
    return std::nullopt;
}

bool ValidateFirstRGBAnchor(const CTransaction& tx, const uint256& expected_commitment, std::string& error)
{
    const auto first = FirstRGBCommitment(tx);
    if (!first) {
        error = "missing RGB anchor";
        return false;
    }
    if (first->second != expected_commitment) {
        error = "first RGB anchor does not match expected commitment";
        return false;
    }
    error.clear();
    return true;
}

bool ValidateRGBAnchor(const CTransaction& tx, const uint256& expected_commitment, const std::vector<Transition>& transitions, std::string& error)
{
    if (!ValidateFirstRGBAnchor(tx, expected_commitment, error)) return false;

    std::set<COutPoint> anchor_inputs;
    for (const CTxIn& input : tx.vin) {
        anchor_inputs.insert(input.prevout);
    }

    for (const Transition& transition : transitions) {
        for (const Seal& seal : transition.inputs) {
            if (!anchor_inputs.count(seal.outpoint)) {
                error = "RGB anchor does not close input seal " + seal.outpoint.ToString();
                return false;
            }
        }
        for (const Assignment& assignment : transition.outputs) {
            if (anchor_inputs.count(assignment.seal.outpoint)) {
                error = "RGB anchor closes output seal " + assignment.seal.outpoint.ToString();
                return false;
            }
        }
    }

    error.clear();
    return true;
}

} // namespace rgb
