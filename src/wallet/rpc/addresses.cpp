// Copyright (c) 2011-2022 Blackcoin Core Developers
// Copyright (c) 2011-2022 Blackcoin More Developers
// Copyright (c) 2011-2022 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <consensus/quantum_witness.h>
#include <crypto/mldsa.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/quantum_pool.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/solver.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <limits>
#include <optional>
#include <vector>

namespace wallet {
static UniValue QuantumKeyInfoToJSON(const QuantumKeyInfo& info)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(info.destination));
    result.pushKV("witness_version", QUANTUM_MIGRATION_WITNESS_VERSION);
    result.pushKV("witness_program", HexStr(info.witness_program));
    result.pushKV("public_key", HexStr(info.public_key));
    result.pushKV("timestamp", info.creation_time);
    result.pushKV("encrypted", info.encrypted);
    result.pushKV("stored_in_wallet", true);
    QuantumStakeTierProgram tier;
    if (DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, info.witness_program, tier) && tier.tiered) {
        result.pushKV("tiered", true);
        result.pushKV("tier_state", tier.IsBonded() ? "bonded" : "unbonding");
        result.pushKV("unbonding_blocks", tier.unbonding_blocks);
        result.pushKV("unlock_height", tier.unlock_height);
    } else {
        result.pushKV("tiered", false);
    }
    return result;
}

static UniValue QuantumColdStakeInfoToJSON(const QuantumColdStakeDelegationInfo& info)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(info.destination));
    result.pushKV("witness_version", QUANTUM_COLDSTAKE_WITNESS_VERSION);
    result.pushKV("witness_program", HexStr(info.witness_program));
    result.pushKV("staking_pubkey_hash", info.staker_pubkey_hash.GetHex());
    result.pushKV("owner_pubkey_hash", info.owner_pubkey_hash.GetHex());
    result.pushKV("timestamp", info.creation_time);
    result.pushKV("has_staker_key", info.has_staker_key);
    result.pushKV("has_owner_key", info.has_owner_key);
    result.pushKV("can_stake", info.has_staker_key);
    result.pushKV("can_owner_spend", info.has_owner_key);
    result.pushKV("tiered", info.tiered);
    if (info.tiered) {
        result.pushKV("tier_state", info.unlock_height == 0 ? "bonded" : "unbonding");
        result.pushKV("unbonding_blocks", info.unbonding_blocks);
        result.pushKV("unlock_height", info.unlock_height);
    }
    return result;
}

RPCHelpMan getnewaddress()
{
    return RPCHelpMan{"getnewaddress",
                "\nReturns a new Blackcoin address for receiving payments.\n"
                "If 'label' is specified, it is added to the address book \n"
                "so payments received with the address will be associated with 'label'.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "The label name for the address to be linked to. It can also be set to the empty string \"\" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name."},
                    {"address_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -addresstype"}, "The address type to use. Options are \"legacy\", \"p2sh-segwit\", \"bech32\", and \"bech32m\"."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new Blackcoin address"
                },
                RPCExamples{
                    HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    // Parse the label first so we don't generate a key if there's an error
    const std::string label{LabelFromValue(request.params[0])};

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[1].isNull()) {
        std::optional<OutputType> parsed = ParseOutputType(request.params[1].get_str());
        if (!parsed) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[1].get_str()));
        } else if (parsed.value() == OutputType::BECH32M && pwallet->GetLegacyScriptPubKeyMan()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Legacy wallets cannot provide bech32m addresses");
        } else if (parsed.value() == OutputType::BECH32M) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Taproot addresses (bech32m) are not supported yet");
        }
        output_type = parsed.value();
    }

    auto op_dest = pwallet->GetNewDestination(output_type, label);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }

    return EncodeDestination(*op_dest);
},
    };
}

RPCHelpMan getnewquantumaddress()
{
    return RPCHelpMan{"getnewquantumaddress",
                "\nReturns a new wallet-backed Blackcoin ML-DSA migration address.\n"
                "The ML-DSA private key is stored in the wallet database and included in wallet backups.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "The label name for the address to be linked to."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The new Blackcoin migration address"},
                        {RPCResult::Type::NUM, "witness_version", "The witness version used for quantum migration"},
                        {RPCResult::Type::STR_HEX, "witness_program", "SHA256(public_key)"},
                        {RPCResult::Type::STR_HEX, "public_key", "The ML-DSA-44 public key"},
                        {RPCResult::Type::NUM_TIME, "timestamp", "The key creation time"},
                        {RPCResult::Type::BOOL, "encrypted", "Whether the wallet stores this key encrypted"},
                        {RPCResult::Type::BOOL, "stored_in_wallet", "Whether this key was inserted into the wallet database"},
                        {RPCResult::Type::BOOL, "tiered", "Whether this address uses the tiered staking witness program."},
                        {RPCResult::Type::STR, "tier_state", /*optional=*/true, "Tier state when this is a tiered staking address."},
                        {RPCResult::Type::NUM, "unbonding_blocks", /*optional=*/true, "Bonded unbonding delay in blocks when tiered."},
                        {RPCResult::Type::NUM, "unlock_height", /*optional=*/true, "Unlock height when tiered and unbonding."},
                        {RPCResult::Type::STR, "warning", "Backup warning"},
                    }},
                RPCExamples{
                    HelpExampleCli("getnewquantumaddress", "")
            + HelpExampleRpc("getnewquantumaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    const std::string label{LabelFromValue(request.params[0])};
    auto op_dest = pwallet->GetNewQuantumDestination(label);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(op_dest).original);
    }

    auto info = pwallet->GetQuantumKeyInfo(*op_dest);
    CHECK_NONFATAL(info.has_value());
    UniValue result = QuantumKeyInfoToJSON(*info);
    result.pushKV("warning", "This address is wallet-backed. Back up the wallet after generating new quantum migration addresses.");
    return result;
},
    };
}

RPCHelpMan getnewquantumstakeaddress()
{
    return RPCHelpMan{"getnewquantumstakeaddress",
                "\nReturns a new wallet-backed tiered Blackcoin ML-DSA self-staking address.\n"
                "The wallet stores one normal ML-DSA key and records a bonded 40-byte v16 witness program\n"
                "that commits to the selected unbonding delay. Funds sent to this address keep that tier\n"
                "inside coinstake refreshes and must unbond before ordinary spends.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{"stake-tier"}, "The label name for the address to be linked to."},
                    {"unbonding_blocks", RPCArg::Type::NUM, RPCArg::Default{0}, "Bonded unbonding delay in blocks. Use 0 for Liquid-style 0.25x weight, 9450 for full Vault weight."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The new tiered Blackcoin staking address"},
                        {RPCResult::Type::NUM, "witness_version", "The witness version used for quantum migration"},
                        {RPCResult::Type::STR_HEX, "witness_program", "The 40-byte tiered staking witness program"},
                        {RPCResult::Type::STR_HEX, "public_key", "The ML-DSA-44 public key"},
                        {RPCResult::Type::STR, "tier_state", "The tier state, currently 'bonded' for new staking addresses"},
                        {RPCResult::Type::NUM, "unbonding_blocks", "Bonded unbonding delay in blocks"},
                        {RPCResult::Type::NUM, "unlock_height", "Unlock height, always 0 for newly bonded addresses"},
                        {RPCResult::Type::NUM_TIME, "timestamp", "The key creation time"},
                        {RPCResult::Type::BOOL, "encrypted", "Whether the wallet stores this key encrypted"},
                        {RPCResult::Type::BOOL, "stored_in_wallet", "Whether this key was inserted into the wallet database"},
                        {RPCResult::Type::STR, "warning", "Backup warning"},
                    }},
                RPCExamples{
                    HelpExampleCli("getnewquantumstakeaddress", "\"vault\" 9450")
            + HelpExampleRpc("getnewquantumstakeaddress", "\"vault\", 9450")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::string label{LabelFromValue(request.params[0])};
    const int unbonding_blocks_arg = request.params[1].isNull() ? 0 : request.params[1].getInt<int>();
    if (unbonding_blocks_arg < 0 || unbonding_blocks_arg > std::numeric_limits<uint16_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("unbonding_blocks must be between 0 and %u", std::numeric_limits<uint16_t>::max()));
    }

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    auto op_dest = pwallet->GetNewTieredQuantumDestination(label, static_cast<uint16_t>(unbonding_blocks_arg));
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(op_dest).original);
    }

    auto info = pwallet->GetQuantumKeyInfo(*op_dest);
    CHECK_NONFATAL(info.has_value());
    QuantumStakeTierProgram tier;
    CHECK_NONFATAL(DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, info->witness_program, tier) && tier.IsBonded());

    UniValue result = QuantumKeyInfoToJSON(*info);
    result.pushKV("warning", "This tiered staking address is wallet-backed. Back up the wallet after generating new quantum staking addresses.");
    return result;
},
    };
}

RPCHelpMan listquantumaddresses()
{
    return RPCHelpMan{"listquantumaddresses",
                "\nLists wallet-backed Blackcoin ML-DSA migration addresses.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "address", "The Blackcoin migration address"},
                            {RPCResult::Type::NUM, "witness_version", "The witness version used for quantum migration"},
                            {RPCResult::Type::STR_HEX, "witness_program", "SHA256(public_key)"},
                            {RPCResult::Type::STR_HEX, "public_key", "The ML-DSA-44 public key"},
                            {RPCResult::Type::NUM_TIME, "timestamp", "The key creation time"},
                            {RPCResult::Type::BOOL, "encrypted", "Whether the wallet stores this key encrypted"},
                            {RPCResult::Type::BOOL, "stored_in_wallet", "Whether this key is in the wallet database"},
                            {RPCResult::Type::BOOL, "tiered", "Whether this address uses the tiered staking witness program."},
                            {RPCResult::Type::STR, "tier_state", /*optional=*/true, "Tier state when this is a tiered staking address."},
                            {RPCResult::Type::NUM, "unbonding_blocks", /*optional=*/true, "Bonded unbonding delay in blocks when tiered."},
                            {RPCResult::Type::NUM, "unlock_height", /*optional=*/true, "Unlock height when tiered and unbonding."},
                            {RPCResult::Type::STR, "label", "The address label"},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("listquantumaddresses", "")
            + HelpExampleRpc("listquantumaddresses", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    UniValue result(UniValue::VARR);
    for (const QuantumKeyInfo& info : pwallet->ListQuantumKeyInfos()) {
        UniValue entry = QuantumKeyInfoToJSON(info);
        const auto* address_book_entry = pwallet->FindAddressBookEntry(info.destination);
        entry.pushKV("label", address_book_entry ? address_book_entry->GetLabel() : "");
        result.push_back(std::move(entry));
    }
    return result;
},
    };
}

RPCHelpMan getnewquantumcoldstakingaddress()
{
    return RPCHelpMan{"getnewquantumcoldstakingaddress",
                "\nCreate a wallet-backed Quantum Cold-Stake deposit address.\n"
                "The wallet generates and stores a new owner ML-DSA key. The supplied staking public key\n"
                "may stake the deposit only in coinstake transactions; the owner key can spend normally.\n"
                "The delegation metadata is stored in this wallet so owner spends can be signed later.\n",
                {
                    {"staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Staker/hot-wallet ML-DSA-44 public key."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{"coldstake"}, "Label for the QCS deposit address."},
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Policy preflight options for the intended delegation.", {
                        {"delegation_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Intended new delegation amount. When set, the wallet checks the per-pool cap before generating the address."},
                        {"enforce_pool_cap", RPCArg::Type::BOOL, RPCArg::Default{true}, "Refuse over-cap address creation only when an under-cap alternative exists; otherwise allow bootstrap and report the over-cap projection."},
                        {"unbonding_blocks", RPCArg::Type::NUM, RPCArg::Default{0}, "Bonded unbonding delay in blocks. Use 0 for liquid cold staking, 9450 for 7-day full-weight vault cold staking."},
                    }},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The Quantum Cold-Stake deposit address."},
                        {RPCResult::Type::NUM, "witness_version", "The QCS witness version."},
                        {RPCResult::Type::STR_HEX, "witness_program", "The QCS witness program."},
                        {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                        {RPCResult::Type::STR_HEX, "owner_pubkey_hash", "SHA256(owner_pubkey)."},
                        {RPCResult::Type::NUM_TIME, "timestamp", "Delegation creation timestamp stored in the wallet."},
                        {RPCResult::Type::STR, "owner_quantum_address", "Wallet-backed owner migration address for the generated owner key."},
                        {RPCResult::Type::STR_HEX, "owner_pubkey", "Generated owner ML-DSA public key."},
                        {RPCResult::Type::BOOL, "has_staker_key", "Whether this wallet also has the staking key."},
                        {RPCResult::Type::BOOL, "has_owner_key", "Whether this wallet has the owner key."},
                        {RPCResult::Type::BOOL, "can_stake", "Whether this wallet can use the staker coinstake branch."},
                        {RPCResult::Type::BOOL, "can_owner_spend", "Whether this wallet can use the owner spend branch."},
                        {RPCResult::Type::BOOL, "tiered", "Whether this QCS address uses the tiered staking witness program."},
                        {RPCResult::Type::STR, "tier_state", /*optional=*/true, "Tier state."},
                        {RPCResult::Type::NUM, "unbonding_blocks", /*optional=*/true, "Bonded unbonding delay in blocks."},
                        {RPCResult::Type::NUM, "unlock_height", /*optional=*/true, "Unlock height for unbonding outputs."},
                        {RPCResult::Type::OBJ, "pool_cap_preflight", /*optional=*/true, "per-pool wallet/policy cap preflight result.", {
                            {RPCResult::Type::STR_AMOUNT, "delegation_amount", "Prospective delegation amount checked."},
                            {RPCResult::Type::STR_AMOUNT, "total_coldstake", "Current total cold-stake UTXO value."},
                            {RPCResult::Type::STR_AMOUNT, "operator_value", "Verified value registered for the target operator."},
                            {RPCResult::Type::NUM, "share_bps", "Current verified operator share in basis points."},
                            {RPCResult::Type::BOOL, "would_exceed_cap", "Whether the prospective delegation would exceed the local policy cap."},
                            {RPCResult::Type::BOOL, "enforced", "Whether an over-cap result would be refused."},
                            {RPCResult::Type::BOOL, "cap_filter_unlocked", "Whether the over-cap target was allowed because no under-cap alternative exists."},
                        }},
                        {RPCResult::Type::STR, "warning", "Backup warning."},
                    }},
                RPCExamples{
                    HelpExampleCli("getnewquantumcoldstakingaddress", "\"<staking_pubkey>\"")
            + HelpExampleRpc("getnewquantumcoldstakingaddress", "\"<staking_pubkey>\", \"coldstake\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::vector<unsigned char> staking_pubkey = ParseHexV(request.params[0], "staking_pubkey");
    if (staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }
    const std::string label{LabelFromValue(request.params[1])};

    bool have_pool_preflight{false};
    UniValue pool_preflight(UniValue::VOBJ);
    const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2].get_obj();
    const int unbonding_blocks_arg = options.exists("unbonding_blocks") ? options["unbonding_blocks"].getInt<int>() : 0;
    if (unbonding_blocks_arg < 0 || unbonding_blocks_arg > std::numeric_limits<uint16_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("unbonding_blocks must be between 0 and %u", std::numeric_limits<uint16_t>::max()));
    }
    if (options.exists("delegation_amount")) {
        const CAmount delegation_amount = AmountFromValue(options["delegation_amount"]);
        if (delegation_amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "delegation_amount must be positive");
        }
        const bool enforce_pool_cap = !options.exists("enforce_pool_cap") || options["enforce_pool_cap"].get_bool();
        const uint256 staker_hash = node::QuantumPoolHashPubKey(staking_pubkey);

        LOCK(cs_main);
        const CCoinsViewCache& view = pwallet->chain().getCoinsTip();
        const node::QuantumPoolShare share = node::ComputeQuantumPoolShare(view, staker_hash, node::GetQuantumPoolClaims(staker_hash));
        const bool would_exceed_cap = node::WouldQuantumPoolExceedCap(share.total_coldstake, share.operator_share.verified_value, delegation_amount);
        const bool cap_filter_unlocked = would_exceed_cap && !node::HasQuantumPoolUnderCapCandidate(view, delegation_amount, {staker_hash});

        pool_preflight.pushKV("delegation_amount", ValueFromAmount(delegation_amount));
        pool_preflight.pushKV("total_coldstake", ValueFromAmount(share.total_coldstake));
        pool_preflight.pushKV("operator_value", ValueFromAmount(share.operator_share.verified_value));
        pool_preflight.pushKV("share_bps", node::QuantumPoolShareBps(share.operator_share.verified_value, share.total_coldstake));
        pool_preflight.pushKV("would_exceed_cap", would_exceed_cap);
        pool_preflight.pushKV("enforced", enforce_pool_cap);
        pool_preflight.pushKV("cap_filter_unlocked", cap_filter_unlocked);
        have_pool_preflight = true;

        if (would_exceed_cap && enforce_pool_cap && !cap_filter_unlocked) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Quantum cold-stake pool cap exceeded by this delegation amount");
        }
    }

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    const std::string owner_label = label.empty() ? "coldstake-owner" : label + " owner";
    auto owner_dest = pwallet->GetNewQuantumDestination(owner_label);
    if (!owner_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(owner_dest).original);
    }
    const auto owner_info = pwallet->GetQuantumKeyInfo(*owner_dest);
    CHECK_NONFATAL(owner_info.has_value());

    auto qcs_dest = pwallet->AddQuantumColdStakeDelegation(staking_pubkey, owner_info->public_key, label, GetTime(), /*record_as_receive=*/true, static_cast<uint16_t>(unbonding_blocks_arg), /*tiered=*/unbonding_blocks_arg > 0);
    if (!qcs_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(qcs_dest).original);
    }
    const auto qcs_info = pwallet->GetQuantumColdStakeDelegationInfo(*qcs_dest);
    CHECK_NONFATAL(qcs_info.has_value());

    UniValue result = QuantumColdStakeInfoToJSON(*qcs_info);
    result.pushKV("owner_quantum_address", EncodeDestination(owner_info->destination));
    result.pushKV("owner_pubkey", HexStr(owner_info->public_key));
    if (have_pool_preflight) {
        result.pushKV("pool_cap_preflight", pool_preflight);
    }
    result.pushKV("warning", "Back up the wallet now. The owner ML-DSA key and QCS delegation metadata are required to recover and spend this cold-stake deposit.");
    return result;
},
    };
}

RPCHelpMan importquantumcoldstakingdelegation()
{
    return RPCHelpMan{"importquantumcoldstakingdelegation",
                "\nImport Quantum Cold-Stake delegation metadata for a wallet that holds either the owner\n"
                "or staking ML-DSA key. This does not import private keys; use importquantumkey first if needed.\n",
                {
                    {"owner_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Owner/cold-wallet ML-DSA-44 public key."},
                    {"staking_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Staker/hot-wallet ML-DSA-44 public key."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{"coldstake"}, "Label for the QCS deposit address."},
                    {"timestamp", RPCArg::Type::NUM, RPCArg::Default{0}, "Creation time used for wallet birth time/rescan planning."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The Quantum Cold-Stake deposit address."},
                        {RPCResult::Type::NUM, "witness_version", "The QCS witness version."},
                        {RPCResult::Type::STR_HEX, "witness_program", "The QCS witness program."},
                        {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                        {RPCResult::Type::STR_HEX, "owner_pubkey_hash", "SHA256(owner_pubkey)."},
                        {RPCResult::Type::NUM_TIME, "timestamp", "Delegation creation timestamp stored in the wallet."},
                        {RPCResult::Type::BOOL, "has_staker_key", "Whether this wallet has the staking key."},
                        {RPCResult::Type::BOOL, "has_owner_key", "Whether this wallet has the owner key."},
                        {RPCResult::Type::BOOL, "can_stake", "Whether this wallet can use the staker coinstake branch."},
                        {RPCResult::Type::BOOL, "can_owner_spend", "Whether this wallet can use the owner spend branch."},
                    }},
                RPCExamples{
                    HelpExampleCli("importquantumcoldstakingdelegation", "\"<owner_pubkey>\" \"<staking_pubkey>\"")
            + HelpExampleRpc("importquantumcoldstakingdelegation", "\"<owner_pubkey>\", \"<staking_pubkey>\", \"coldstake\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::vector<unsigned char> owner_pubkey = ParseHexV(request.params[0], "owner_pubkey");
    const std::vector<unsigned char> staking_pubkey = ParseHexV(request.params[1], "staking_pubkey");
    if (owner_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("owner_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }
    if (staking_pubkey.size() != ML_DSA::PUBLICKEY_BYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("staking_pubkey must be exactly %u bytes", ML_DSA::PUBLICKEY_BYTES));
    }
    const std::string label{LabelFromValue(request.params[2])};
    const int64_t timestamp = request.params[3].isNull() ? 0 : request.params[3].getInt<int64_t>();
    if (timestamp < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "timestamp cannot be negative");
    }

    LOCK(pwallet->cs_wallet);
    auto qcs_dest = pwallet->AddQuantumColdStakeDelegation(staking_pubkey, owner_pubkey, label, timestamp);
    if (!qcs_dest) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(qcs_dest).original);
    }
    const auto qcs_info = pwallet->GetQuantumColdStakeDelegationInfo(*qcs_dest);
    CHECK_NONFATAL(qcs_info.has_value());
    return QuantumColdStakeInfoToJSON(*qcs_info);
},
    };
}

RPCHelpMan listquantumcoldstakingdelegations()
{
    return RPCHelpMan{"listquantumcoldstakingdelegations",
                "\nList wallet-known Quantum Cold-Stake delegations.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "address", "The Quantum Cold-Stake deposit address."},
                            {RPCResult::Type::NUM, "witness_version", "The QCS witness version."},
                            {RPCResult::Type::STR_HEX, "witness_program", "The QCS witness program."},
                            {RPCResult::Type::STR_HEX, "staking_pubkey_hash", "SHA256(staking_pubkey)."},
                            {RPCResult::Type::STR_HEX, "owner_pubkey_hash", "SHA256(owner_pubkey)."},
                            {RPCResult::Type::NUM_TIME, "timestamp", "Delegation creation timestamp stored in the wallet."},
                            {RPCResult::Type::BOOL, "has_staker_key", "Whether this wallet has the staking key."},
                            {RPCResult::Type::BOOL, "has_owner_key", "Whether this wallet has the owner key."},
                            {RPCResult::Type::BOOL, "can_stake", "Whether this wallet can use the staker coinstake branch."},
                            {RPCResult::Type::BOOL, "can_owner_spend", "Whether this wallet can use the owner spend branch."},
                            {RPCResult::Type::BOOL, "tiered", "Whether this QCS address uses the tiered staking witness program."},
                            {RPCResult::Type::STR, "tier_state", /*optional=*/true, "Tier state."},
                            {RPCResult::Type::NUM, "unbonding_blocks", /*optional=*/true, "Bonded unbonding delay in blocks."},
                            {RPCResult::Type::NUM, "unlock_height", /*optional=*/true, "Unlock height for unbonding outputs."},
                            {RPCResult::Type::STR, "label", "Address-book label."},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("listquantumcoldstakingdelegations", "")
            + HelpExampleRpc("listquantumcoldstakingdelegations", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);
    UniValue result(UniValue::VARR);
    for (const QuantumColdStakeDelegationInfo& info : pwallet->ListQuantumColdStakeDelegationInfos()) {
        UniValue entry = QuantumColdStakeInfoToJSON(info);
        const auto* address_book_entry = pwallet->FindAddressBookEntry(info.destination);
        entry.pushKV("label", address_book_entry ? address_book_entry->GetLabel() : "");
        result.push_back(std::move(entry));
    }
    return result;
},
    };
}

RPCHelpMan dumpquantumkey()
{
    return RPCHelpMan{"dumpquantumkey",
                "\nReveals the wallet-backed ML-DSA private key for a Blackcoin migration address.\n"
                "Requires an unlocked wallet. Keep the returned private key secret.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet-backed Blackcoin migration address"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The Blackcoin migration address"},
                        {RPCResult::Type::NUM, "witness_version", "The witness version used for quantum migration"},
                        {RPCResult::Type::STR_HEX, "witness_program", "SHA256(public_key)"},
                        {RPCResult::Type::STR_HEX, "public_key", "The ML-DSA-44 public key"},
                        {RPCResult::Type::STR_HEX, "private_key", "The ML-DSA-44 private key"},
                        {RPCResult::Type::STR, "warning", "Backup warning"},
                    }},
                RPCExamples{
                    HelpExampleCli("dumpquantumkey", "\"address\"")
            + HelpExampleRpc("dumpquantumkey", "\"address\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<const CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    std::string error_msg;
    const CTxDestination dest = DecodeDestination(request.params[0].get_str(), error_msg);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg.empty() ? "Invalid address" : error_msg);
    }
    const auto* witness = std::get_if<WitnessUnknown>(&dest);
    if (!witness || !IsQuantumMigrationWitnessProgram(witness->GetWitnessVersion(), witness->GetWitnessProgram())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not a Blackcoin migration address");
    }

    std::vector<unsigned char> public_key;
    CKeyingMaterial private_key;
    bilingual_str error;
    if (!pwallet->GetQuantumKey(witness->GetWitnessProgram(), public_key, private_key, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    std::vector<unsigned char> private_key_bytes(private_key.begin(), private_key.end());
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("witness_version", QUANTUM_MIGRATION_WITNESS_VERSION);
    result.pushKV("witness_program", HexStr(witness->GetWitnessProgram()));
    result.pushKV("public_key", HexStr(public_key));
    result.pushKV("private_key", HexStr(private_key_bytes));
    result.pushKV("warning", "Do not share this key. Anyone with private_key can spend funds sent to this quantum migration address once ML-DSA spends are active.");
    // Wipe the plaintext secret copy from the heap (private_key is a secure-alloc
    // type and self-cleanses; private_key_bytes is a plain vector and must not linger).
    memory_cleanse(private_key_bytes.data(), private_key_bytes.size());
    return result;
},
    };
}

RPCHelpMan getrawchangeaddress()
{
    return RPCHelpMan{"getrawchangeaddress",
                "\nReturns a new Blackcoin address, for receiving change.\n"
                "This is for use with raw transactions, NOT normal use.\n",
                {
                    {"address_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -changetype"}, "The address type to use. Options are \"legacy\", \"p2sh-segwit\", \"bech32\", and \"bech32m\"."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The address"
                },
                RPCExamples{
                    HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    OutputType output_type = pwallet->m_default_change_type.value_or(pwallet->m_default_address_type);
    if (!request.params[0].isNull()) {
        std::optional<OutputType> parsed = ParseOutputType(request.params[0].get_str());
        if (!parsed) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
        } else if (parsed.value() == OutputType::BECH32M && pwallet->GetLegacyScriptPubKeyMan()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Legacy wallets cannot provide bech32m addresses");
        }
        output_type = parsed.value();
    }

    auto op_dest = pwallet->GetNewChangeDestination(output_type);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }
    return EncodeDestination(*op_dest);
},
    };
}


RPCHelpMan setlabel()
{
    return RPCHelpMan{"setlabel",
                "\nSets the label associated with the given address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Blackcoin address to be associated with a label."},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label to assign to the address."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\" \"tabby\"")
            + HelpExampleRpc("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\", \"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Blackcoin address");
    }

    const std::string label{LabelFromValue(request.params[1])};

    if (pwallet->IsMine(dest)) {
        pwallet->SetAddressBook(dest, label, AddressPurpose::RECEIVE);
    } else {
        pwallet->SetAddressBook(dest, label, AddressPurpose::SEND);
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan listaddressgroupings()
{
    return RPCHelpMan{"listaddressgroupings",
                "\nLists groups of addresses which have had their common ownership\n"
                "made public by common use as inputs or as the resulting change\n"
                "in past transactions\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::ARR, "", "",
                        {
                            {RPCResult::Type::ARR_FIXED, "", "",
                            {
                                {RPCResult::Type::STR, "address", "The Blackcoin address"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "The label"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = GetAddressBalances(*pwallet);
    for (const std::set<CTxDestination>& grouping : GetAddressGroupings(*pwallet)) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                if (address_book_entry) {
                    addressInfo.push_back(address_book_entry->GetLabel());
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
},
    };
}

RPCHelpMan addmultisigaddress()
{
    return RPCHelpMan{"addmultisigaddress",
                "\nAdd an nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
                "Each key is a Blackcoin address or hex-encoded public key.\n"
                "This functionality is only intended for use with non-watchonly addresses.\n"
                "See `importaddress` for watchonly p2sh address support.\n"
                "If 'label' is specified, assign address to that label.\n"
                "Note: This command is only compatible with legacy wallets.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys or addresses."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The Blackcoin addresses or hex-encoded public keys",
                        {
                            {"key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Blackcoin address or hex-encoded public key"},
                        },
                        },
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A label to assign the addresses to."},
                    {"address_type", RPCArg::Type::STR, RPCArg::DefaultHint{"set by -addresstype"}, "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The value of the new multisig address"},
                        {RPCResult::Type::STR_HEX, "redeemScript", "The string value of the hex-encoded redemption script"},
                        {RPCResult::Type::STR, "descriptor", "The descriptor for this multisig"},
                        {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Any warnings resulting from the creation of this multisig",
                        {
                            {RPCResult::Type::STR, "", ""},
                        }},
                    }
                },
                RPCExamples{
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    const std::string label{LabelFromValue(request.params[2])};

    int required = request.params[0].getInt<int>();

    // Get the public keys
    const UniValue& keys_or_addrs = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys_or_addrs.size(); ++i) {
        if (IsHex(keys_or_addrs[i].get_str()) && (keys_or_addrs[i].get_str().length() == 66 || keys_or_addrs[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys_or_addrs[i].get_str()));
        } else {
            pubkeys.push_back(AddrToPubKey(spk_man, keys_or_addrs[i].get_str()));
        }
    }

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[3].isNull()) {
        std::optional<OutputType> parsed = ParseOutputType(request.params[3].get_str());
        if (!parsed) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[3].get_str()));
        } else if (parsed.value() == OutputType::BECH32M) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bech32m multisig addresses cannot be created with legacy wallets");
        }
        output_type = parsed.value();
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    CTxDestination dest = AddAndGetMultisigDestination(required, pubkeys, output_type, spk_man, inner);
    pwallet->SetAddressBook(dest, label, AddressPurpose::SEND);

    // Make the descriptor
    std::unique_ptr<Descriptor> descriptor = InferDescriptor(GetScriptForDestination(dest), spk_man);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner));
    result.pushKV("descriptor", descriptor->ToString());

    UniValue warnings(UniValue::VARR);
    if (descriptor->GetOutputType() != output_type) {
        // Only warns if the user has explicitly chosen an address type we cannot generate
        warnings.push_back("Unable to make chosen address type, please ensure no uncompressed public keys are present.");
    }
    PushWarnings(warnings, result);

    return result;
},
    };
}

RPCHelpMan keypoolrefill()
{
    return RPCHelpMan{"keypoolrefill",
                "\nFills the keypool."+
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"newsize", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%u, or as set by -keypool", DEFAULT_KEYPOOL_SIZE)}, "The new keypool size"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (pwallet->IsLegacy() && pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    LOCK(pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].getInt<int>() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].getInt<int>();
    }

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan newkeypool()
{
    return RPCHelpMan{"newkeypool",
                "\nEntirely clears and refills the keypool.\n"
                "WARNING: On non-HD wallets, this will require a new backup immediately, to include the new keys.\n"
                "When restoring a backup of an HD wallet created before the newkeypool command is run, funds received to\n"
                "new addresses may not appear automatically. They have not been lost, but the wallet may not find them.\n"
                "This can be fixed by running the newkeypool command on the backup and then rescanning, so the wallet\n"
                "re-generates the required keys." +
            HELP_REQUIRING_PASSPHRASE,
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            HelpExampleCli("newkeypool", "")
            + HelpExampleRpc("newkeypool", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet, true);
    spk_man.NewKeyPool();

    return UniValue::VNULL;
},
    };
}


class DescribeWalletAddressVisitor
{
public:
    const SigningProvider * const provider;

    void ProcessSubScript(const CScript& subscript, UniValue& obj) const
    {
        // Always present: script type and redeemscript
        std::vector<std::vector<unsigned char>> solutions_data;
        TxoutType which_type = Solver(subscript, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript));

        CTxDestination embedded;
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(detail);
            UniValue wallet_detail = std::visit(*this, embedded);
            subobj.pushKVs(wallet_detail);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
        } else if (which_type == TxoutType::MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                pubkeys.push_back(HexStr(key));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }
    }

    explicit DescribeWalletAddressVisitor(const SigningProvider* _provider) : provider(_provider) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }
    UniValue operator()(const PubKeyDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const PKHash& pkhash) const
    {
        CKeyID keyID{ToKeyID(pkhash)};
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (provider && provider->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const ScriptHash& scripthash) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (provider && provider->GetCScript(ToScriptID(scripthash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (provider && provider->GetPubKey(ToKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (provider && provider->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessV1Taproot& id) const { return UniValue(UniValue::VOBJ); }
    UniValue operator()(const WitnessUnknown& id) const { return UniValue(UniValue::VOBJ); }
};

static UniValue DescribeWalletAddress(const CWallet& wallet, const CTxDestination& dest)
{
    UniValue ret(UniValue::VOBJ);
    UniValue detail = DescribeAddress(dest);
    CScript script = GetScriptForDestination(dest);
    std::unique_ptr<SigningProvider> provider = nullptr;
    provider = wallet.GetSolvingProvider(script);
    ret.pushKVs(detail);
    ret.pushKVs(std::visit(DescribeWalletAddressVisitor(provider.get()), dest));
    return ret;
}

RPCHelpMan getaddressinfo()
{
    return RPCHelpMan{"getaddressinfo",
                "\nReturn information about the given Blackcoin address.\n"
                "Some of the information will only be present if the address is in the active wallet.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Blackcoin address for which to get information."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The Blackcoin address validated."},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded scriptPubKey generated by the address."},
                        {RPCResult::Type::BOOL, "ismine", "If the address is yours."},
                        {RPCResult::Type::BOOL, "iswatchonly", "If the address is watchonly."},
                        {RPCResult::Type::BOOL, "solvable", "If we know how to spend coins sent to this address, ignoring the possible lack of private keys."},
                        {RPCResult::Type::STR, "desc", /*optional=*/true, "A descriptor for spending coins sent to this address (only when solvable)."},
                        {RPCResult::Type::STR, "parent_desc", /*optional=*/true, "The descriptor used to derive this address if this is a descriptor wallet"},
                        {RPCResult::Type::BOOL, "isscript", "If the key is a script."},
                        {RPCResult::Type::BOOL, "ischange", "If the address was used for change output."},
                        {RPCResult::Type::BOOL, "iswitness", "If the address is a witness address."},
                        {RPCResult::Type::NUM, "witness_version", /*optional=*/true, "The version number of the witness program."},
                        {RPCResult::Type::STR_HEX, "witness_program", /*optional=*/true, "The hex value of the witness program."},
                        {RPCResult::Type::BOOL, "isquantummigration", /*optional=*/true, "Whether this is a Blackcoin migration address."},
                        {RPCResult::Type::BOOL, "hasquantumkey", /*optional=*/true, "Whether this wallet contains the ML-DSA key for this migration address."},
                        {RPCResult::Type::STR_HEX, "quantum_public_key", /*optional=*/true, "The wallet ML-DSA-44 public key for this migration address."},
                        {RPCResult::Type::BOOL, "quantum_key_encrypted", /*optional=*/true, "Whether the wallet stores this ML-DSA key encrypted."},
                        {RPCResult::Type::BOOL, "isquantumcoldstake", /*optional=*/true, "Whether this is a Quantum Cold-Stake address."},
                        {RPCResult::Type::BOOL, "hascoldstakemetadata", /*optional=*/true, "Whether this wallet has the QCS delegation metadata for this address."},
                        {RPCResult::Type::STR_HEX, "staking_pubkey_hash", /*optional=*/true, "SHA256(staking_pubkey) for a known QCS delegation."},
                        {RPCResult::Type::STR_HEX, "owner_pubkey_hash", /*optional=*/true, "SHA256(owner_pubkey) for a known QCS delegation."},
                        {RPCResult::Type::BOOL, "has_staker_key", /*optional=*/true, "Whether this wallet has the staking ML-DSA key for this QCS delegation."},
                        {RPCResult::Type::BOOL, "has_owner_key", /*optional=*/true, "Whether this wallet has the owner ML-DSA key for this QCS delegation."},
                        {RPCResult::Type::BOOL, "can_stake", /*optional=*/true, "Whether this wallet can use the QCS staking branch."},
                        {RPCResult::Type::BOOL, "can_owner_spend", /*optional=*/true, "Whether this wallet can use the QCS owner-spend branch."},
                        {RPCResult::Type::STR, "script", /*optional=*/true, "The output script type. Only if isscript is true and the redeemscript is known. Possible\n"
                                                                     "types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash,\n"
                            "witness_v0_scripthash, witness_unknown."},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The redeemscript for the p2sh address."},
                        {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "Array of pubkeys associated with the known redeemscript (only if script is multisig).",
                        {
                            {RPCResult::Type::STR, "pubkey", ""},
                        }},
                        {RPCResult::Type::NUM, "sigsrequired", /*optional=*/true, "The number of signatures required to spend multisig output (only if script is multisig)."},
                        {RPCResult::Type::STR_HEX, "pubkey", /*optional=*/true, "The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH)."},
                        {RPCResult::Type::OBJ, "embedded", /*optional=*/true, "Information about the address embedded in P2SH or P2WSH, if relevant and known.",
                        {
                            {RPCResult::Type::ELISION, "", "Includes all getaddressinfo output fields for the embedded address, excluding metadata (timestamp, hdkeypath, hdseedid)\n"
                            "and relation to the wallet (ismine, iswatchonly)."},
                        }},
                        {RPCResult::Type::BOOL, "iscompressed", /*optional=*/true, "If the pubkey is compressed."},
                        {RPCResult::Type::NUM_TIME, "timestamp", /*optional=*/true, "The creation time of the key, if available, expressed in " + UNIX_EPOCH_TIME + "."},
                        {RPCResult::Type::STR, "hdkeypath", /*optional=*/true, "The HD keypath, if the key is HD and available."},
                        {RPCResult::Type::STR_HEX, "hdseedid", /*optional=*/true, "The Hash160 of the HD seed."},
                        {RPCResult::Type::STR_HEX, "hdmasterfingerprint", /*optional=*/true, "The fingerprint of the master key."},
                        {RPCResult::Type::ARR, "labels", "Array of labels associated with the address. Currently limited to one label but returned\n"
                            "as an array to keep the API stable if multiple labels are enabled in the future.",
                        {
                            {RPCResult::Type::STR, "label name", "Label name (defaults to \"\")."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
                    HelpExampleRpc("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::string error_msg;
    CTxDestination dest = DecodeDestination(request.params[0].get_str(), error_msg);

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        // Set generic error message in case 'DecodeDestination' didn't set it
        if (error_msg.empty()) error_msg = "Invalid address";

        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg);
    }

    UniValue ret(UniValue::VOBJ);

    std::string currentAddress = EncodeDestination(dest);
    ret.pushKV("address", currentAddress);

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.pushKV("scriptPubKey", HexStr(scriptPubKey));

    std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
    const std::optional<QuantumKeyInfo> quantum_info = pwallet->GetQuantumKeyInfo(dest);
    const std::optional<QuantumColdStakeDelegationInfo> qcs_info = pwallet->GetQuantumColdStakeDelegationInfo(dest);

    isminetype mine = pwallet->IsMine(dest);
    ret.pushKV("ismine", bool(mine & ISMINE_SPENDABLE));

    if (provider) {
        auto inferred = InferDescriptor(scriptPubKey, *provider);
        bool solvable = inferred->IsSolvable();
        ret.pushKV("solvable", solvable);
        if (solvable) {
            ret.pushKV("desc", inferred->ToString());
        }
    } else {
        ret.pushKV("solvable", quantum_info.has_value() || qcs_info.has_value());
    }

    const auto& spk_mans = pwallet->GetScriptPubKeyMans(scriptPubKey);
    // In most cases there is only one matching ScriptPubKey manager and we can't resolve ambiguity in a better way
    ScriptPubKeyMan* spk_man{nullptr};
    if (spk_mans.size()) spk_man = *spk_mans.begin();

    DescriptorScriptPubKeyMan* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (desc_spk_man) {
        std::string desc_str;
        if (desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) {
            ret.pushKV("parent_desc", desc_str);
        }
    }

    ret.pushKV("iswatchonly", bool(mine & ISMINE_WATCH_ONLY));

    UniValue detail = DescribeWalletAddress(*pwallet, dest);
    ret.pushKVs(detail);

    if (IsQuantumMigrationDestination(dest)) {
        ret.pushKV("hasquantumkey", quantum_info.has_value());
        if (quantum_info) {
            ret.pushKV("quantum_public_key", HexStr(quantum_info->public_key));
            ret.pushKV("quantum_key_encrypted", quantum_info->encrypted);
            if (!ret.exists("timestamp")) {
                ret.pushKV("timestamp", quantum_info->creation_time);
            }
        }
    } else if (IsQuantumColdStakeDestination(dest)) {
        ret.pushKV("isquantumcoldstake", true);
        ret.pushKV("hascoldstakemetadata", qcs_info.has_value());
        if (qcs_info) {
            ret.pushKV("staking_pubkey_hash", qcs_info->staker_pubkey_hash.GetHex());
            ret.pushKV("owner_pubkey_hash", qcs_info->owner_pubkey_hash.GetHex());
            ret.pushKV("has_staker_key", qcs_info->has_staker_key);
            ret.pushKV("has_owner_key", qcs_info->has_owner_key);
            ret.pushKV("can_stake", qcs_info->has_staker_key);
            ret.pushKV("can_owner_spend", qcs_info->has_owner_key);
            if (!ret.exists("timestamp")) {
                ret.pushKV("timestamp", qcs_info->creation_time);
            }
        } else {
            ret.pushKV("warning", "Quantum cold-stake address metadata is not present in this wallet. Import the delegation metadata before staking or spending this address.");
        }
    }

    ret.pushKV("ischange", ScriptIsChange(*pwallet, scriptPubKey));

    if (spk_man) {
        if (const std::unique_ptr<CKeyMetadata> meta = spk_man->GetMetadata(dest)) {
            ret.pushKV("timestamp", meta->nCreateTime);
            if (meta->has_key_origin) {
                // In legacy wallets hdkeypath has always used an apostrophe for
                // hardened derivation. Perhaps some external tool depends on that.
                ret.pushKV("hdkeypath", WriteHDKeypath(meta->key_origin.path, /*apostrophe=*/!desc_spk_man));
                ret.pushKV("hdseedid", meta->hd_seed_id.GetHex());
                ret.pushKV("hdmasterfingerprint", HexStr(meta->key_origin.fingerprint));
            }
        }
    }

    // Return a `labels` array containing the label associated with the address,
    // equivalent to the `label` field above. Currently only one label can be
    // associated with an address, but we return an array so the API remains
    // stable if we allow multiple labels to be associated with an address in
    // the future.
    UniValue labels(UniValue::VARR);
    const auto* address_book_entry = pwallet->FindAddressBookEntry(dest);
    if (address_book_entry) {
        labels.push_back(address_book_entry->GetLabel());
    }
    ret.pushKV("labels", std::move(labels));

    return ret;
},
    };
}

RPCHelpMan getaddressesbylabel()
{
    return RPCHelpMan{"getaddressesbylabel",
                "\nReturns the list of addresses assigned the specified label.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label."},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "json object with addresses as keys",
                    {
                        {RPCResult::Type::OBJ, "address", "json object with information about address",
                        {
                            {RPCResult::Type::STR, "purpose", "Purpose of address (\"send\" for sending address, \"receive\" for receiving address)"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressesbylabel", "\"tabby\"")
            + HelpExampleRpc("getaddressesbylabel", "\"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    const std::string label{LabelFromValue(request.params[0])};

    // Find all addresses that have the given label
    UniValue ret(UniValue::VOBJ);
    std::set<std::string> addresses;
    pwallet->ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label, bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (_label == label) {
            std::string address = EncodeDestination(_dest);
            // CWallet::m_address_book is not expected to contain duplicate
            // address strings, but build a separate set as a precaution just in
            // case it does.
            bool unique = addresses.emplace(address).second;
            CHECK_NONFATAL(unique);
            // UniValue::pushKV checks if the key exists in O(N)
            // and since duplicate addresses are unexpected (checked with
            // std::set in O(log(N))), UniValue::pushKVEnd is used instead,
            // which currently is O(1).
            UniValue value(UniValue::VOBJ);
            value.pushKV("purpose", _purpose ? PurposeToString(*_purpose) : "unknown");
            ret.pushKVEnd(address, value);
        }
    });

    if (ret.empty()) {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, std::string("No addresses with label " + label));
    }

    return ret;
},
    };
}

RPCHelpMan listlabels()
{
    return RPCHelpMan{"listlabels",
                "\nReturns the list of all labels, or labels that are assigned to addresses with a specific purpose.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address purpose to list labels for ('send','receive'). An empty string is the same as not providing this argument."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "label", "Label name"},
                    }
                },
                RPCExamples{
            "\nList all labels\n"
            + HelpExampleCli("listlabels", "") +
            "\nList labels that have receiving addresses\n"
            + HelpExampleCli("listlabels", "receive") +
            "\nList labels that have sending addresses\n"
            + HelpExampleCli("listlabels", "send") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlabels", "receive")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::optional<AddressPurpose> purpose;
    if (!request.params[0].isNull()) {
        std::string purpose_str = request.params[0].get_str();
        if (!purpose_str.empty()) {
            purpose = PurposeFromString(purpose_str);
            if (!purpose) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid 'purpose' argument, must be a known purpose string, typically 'send', or 'receive'.");
            }
        }
    }

    // Add to a set to sort by label name, then insert into Univalue array
    std::set<std::string> label_set = pwallet->ListAddrBookLabels(purpose);

    UniValue ret(UniValue::VARR);
    for (const std::string& name : label_set) {
        ret.push_back(name);
    }

    return ret;
},
    };
}


#ifdef ENABLE_EXTERNAL_SIGNER
RPCHelpMan walletdisplayaddress()
{
    return RPCHelpMan{
        "walletdisplayaddress",
        "Display address on an external signer for verification.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Blackcoin address to display"},
        },
        RPCResult{
            RPCResult::Type::OBJ,"","",
            {
                {RPCResult::Type::STR, "address", "The address as confirmed by the signer"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;
            CWallet* const pwallet = wallet.get();

            LOCK(pwallet->cs_wallet);

            CTxDestination dest = DecodeDestination(request.params[0].get_str());

            // Make sure the destination is valid
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            if (!pwallet->DisplayAddress(dest)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to display address");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", request.params[0].get_str());
            return result;
        }
    };
}
#endif // ENABLE_EXTERNAL_SIGNER
} // namespace wallet
