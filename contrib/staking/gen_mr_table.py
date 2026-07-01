#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""
Fixed-point staking-weight reference generator.

This is the single source of truth for the three-tier staking-weight curve

    m(r) = 0.25 + 0.75 * sqrt(r),   r = remaining_unbonding_blocks / NV_MAX

represented as an integer multiplier `m_ppm10k` in parts-per-10000 (2500 = 0.25x,
10000 = 1.00x). Floating-point sqrt is NOT bit-reproducible across platforms and
would split consensus. Therefore the *table this script emits* is the
consensus data: production code ships the generated table (preferred) or an
isqrt that reproduces these exact integers, and the unit test asserts the runtime
path matches byte-for-byte.

Consensus constants:
  * NV_MAX                = 9450    # nVaultMaxUnbondingBlocks (7 d @ 64 s spacing)
  * OPERATOR_PPM10K       = 10000   # 30 d Operator tier is FLAT 1.00x (off-curve)
  * LIQUID floor          = 2500    # r = 0
  * rounding              = round-half-up of 10000 * m(r)  (Decimal, prec 60)
  * clamp                 = r in [0, 1]  -> rem in [0, NV_MAX]

Usage:
  gen_mr_table.py                      # human-readable summary + self-consistency
  gen_mr_table.py --emit-header PATH   # write C++ header (full table + tier pts + overflow vectors)
  gen_mr_table.py --emit-json PATH     # write JSON (tier pts + table sha256 + overflow vectors)
  gen_mr_table.py --check PATH         # regen + verify a committed header/json still matches

The overflow vectors are emitted alongside the
table so the C++ unit tests and functional win-rate tests consume the
same canonical numbers.
"""
import argparse
import hashlib
import json
import sys
from decimal import Decimal, getcontext, ROUND_HALF_UP

getcontext().prec = 60

# --- FROZEN consensus constants -------------------------------------------------
NV_MAX = 9450            # remaining-unbonding blocks at Vault max (7 d @ 64 s)
OPERATOR_BLOCKS = 40500  # 30 d @ 64 s — Operator commitment (weight is FLAT, not on curve)
OPERATOR_PPM10K = 10000  # Operator multiplier (flat 1.00x)
LIQUID_PPM10K = 2500     # r = 0 floor (0.25x)
FULL_PPM10K = 10000      # r = 1 ceiling (1.00x)

# pool factor
POOL_OWNER_PPM10K = 10000   # owner-branch / self-stake
POOL_STAKER_PPM10K = 8000   # delegate (staker) branch

# Overflow-edge constants (mainnet)
POS_LIMIT_V2 = (1 << 208) - 1                 # bnTarget worst case ~ 2^208
MAX_MONEY = 20_000_000_000 * 100_000_000      # 2e10 coins * 1e8 sat = 2e18 sat
TWO_256 = 1 << 256


def m_ppm10k(rem_blocks: int) -> int:
    """Canonical integer multiplier for `rem_blocks` of remaining unbonding.
    FROZEN: round-half-up of 10000*(0.25 + 0.75*sqrt(rem/NV_MAX)), r clamped [0,1]."""
    rem = min(max(int(rem_blocks), 0), NV_MAX)
    r = Decimal(rem) / Decimal(NV_MAX)
    m = Decimal("0.25") + Decimal("0.75") * r.sqrt()
    return int((Decimal(10000) * m).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def full_table() -> list[int]:
    return [m_ppm10k(b) for b in range(NV_MAX + 1)]


def table_sha256(table: list[int]) -> str:
    h = hashlib.sha256()
    for v in table:
        h.update(v.to_bytes(2, "little"))
    return h.hexdigest()


def tier_points() -> dict:
    pts = {
        "liquid_0d": 0,
        "vault_1d": 1350,
        "vault_2d": 2700,
        "vault_3p5d": 4725,
        "vault_5d": 6750,
        "vault_7d": 9450,
    }
    return {name: m_ppm10k(b) for name, b in pts.items()}


def overflow_vectors() -> dict:
    """Overflow canonical vectors. Effective weight at full multiplier (m=pool=10000) is
    MAX_MONEY exactly; the kernel compares bnTarget*bnWeight, which is 269 bits and
    MUST be evaluated in a 512-bit intermediate (the naive 256-bit product truncates)."""
    # required per-factor order keeps weight <= MAX_MONEY at every step
    w = MAX_MONEY
    w = (w * FULL_PPM10K) // 10000       # * m
    w = (w * POOL_OWNER_PPM10K) // 10000  # * pool
    assert w == MAX_MONEY, "full-multiplier effective weight must equal MAX_MONEY"
    ref_full = POS_LIMIT_V2 * w           # untruncated 512-bit product (269 bits)
    ref_trunc = ref_full % TWO_256        # what a naive arith_uint256 multiply yields
    return {
        "pos_limit_v2_dec": str(POS_LIMIT_V2),
        "max_money_sat": str(MAX_MONEY),
        "effective_weight_full_mult_sat": str(w),
        "ref_bntarget_times_weight_full_dec": str(ref_full),
        "ref_bntarget_times_weight_full_bits": ref_full.bit_length(),
        "ref_truncated_256_dec": str(ref_trunc),
        "truncation_changes_value": ref_full != ref_trunc,
        "forbidden_fold_bits": (POS_LIMIT_V2 * (MAX_MONEY * 10000)).bit_length(),
    }


def build_manifest() -> dict:
    table = full_table()
    assert table[0] == LIQUID_PPM10K, "liquid floor must be 2500"
    assert table[NV_MAX] == FULL_PPM10K, "vault max must be 10000"
    assert all(table[i] <= table[i + 1] for i in range(len(table) - 1)), "must be monotonic non-decreasing"
    assert min(table) == LIQUID_PPM10K and max(table) == FULL_PPM10K, "bounds [2500,10000]"
    return {
        "_frozen_rule": "m_ppm10k = round_half_up(10000*(0.25 + 0.75*sqrt(rem/NV_MAX))), rem in [0,NV_MAX]",
        "nv_max_blocks": NV_MAX,
        "operator_blocks": OPERATOR_BLOCKS,
        "operator_ppm10k": OPERATOR_PPM10K,
        "liquid_ppm10k": LIQUID_PPM10K,
        "full_ppm10k": FULL_PPM10K,
        "pool_owner_ppm10k": POOL_OWNER_PPM10K,
        "pool_staker_ppm10k": POOL_STAKER_PPM10K,
        "tier_points": tier_points(),
        "table_len": len(table),
        "table_sha256": table_sha256(table),
        "overflow_vectors": overflow_vectors(),
    }


def emit_header(path: str) -> None:
    table = full_table()
    man = build_manifest()
    ov = man["overflow_vectors"]
    tp = man["tier_points"]
    lines = []
    lines.append("// AUTO-GENERATED by contrib/staking/gen_mr_table.py — DO NOT EDIT BY HAND.")
    lines.append("// Regenerate/verify: python3 contrib/staking/gen_mr_table.py --check <thisfile>")
    lines.append("// Staking-weight table (fixed-point, no floats).")
    lines.append("// Frozen rule: " + man["_frozen_rule"])
    lines.append("#ifndef BLACKCOIN_TEST_DATA_STAKING_MR_TABLE_H")
    lines.append("#define BLACKCOIN_TEST_DATA_STAKING_MR_TABLE_H")
    lines.append("#include <array>")
    lines.append("#include <cstdint>")
    lines.append("namespace blackcoin_staking_canonical {")
    lines.append(f"inline constexpr int kNvMaxBlocks = {NV_MAX};")
    lines.append(f"inline constexpr uint16_t kLiquidPpm10k = {LIQUID_PPM10K};")
    lines.append(f"inline constexpr uint16_t kFullPpm10k = {FULL_PPM10K};")
    lines.append(f"inline constexpr uint16_t kOperatorPpm10k = {OPERATOR_PPM10K};")
    lines.append(f"inline constexpr uint16_t kPoolOwnerPpm10k = {POOL_OWNER_PPM10K};")
    lines.append(f"inline constexpr uint16_t kPoolStakerPpm10k = {POOL_STAKER_PPM10K};")
    lines.append("// Tier checkpoints (remaining-unbonding blocks -> m_ppm10k):")
    lines.append(f"inline constexpr uint16_t kTierLiquid0d   = {tp['liquid_0d']};   // rem=0")
    lines.append(f"inline constexpr uint16_t kTierVault1d    = {tp['vault_1d']};   // rem=1350")
    lines.append(f"inline constexpr uint16_t kTierVault2d    = {tp['vault_2d']};   // rem=2700")
    lines.append(f"inline constexpr uint16_t kTierVault3p5d  = {tp['vault_3p5d']};   // rem=4725")
    lines.append(f"inline constexpr uint16_t kTierVault5d    = {tp['vault_5d']};   // rem=6750")
    lines.append(f"inline constexpr uint16_t kTierVault7d    = {tp['vault_7d']};  // rem=9450")
    lines.append("// Overflow-edge test vectors, as decimal strings:")
    lines.append(f'inline constexpr const char* kPosLimitV2Dec = "{ov["pos_limit_v2_dec"]}";')
    lines.append(f'inline constexpr const char* kMaxMoneySat = "{ov["max_money_sat"]}";')
    lines.append(f'inline constexpr const char* kEffWeightFullMultSat = "{ov["effective_weight_full_mult_sat"]}";')
    lines.append(f'inline constexpr const char* kRefBnTargetTimesWeightFull = "{ov["ref_bntarget_times_weight_full_dec"]}";')
    lines.append(f'inline constexpr const char* kRefTruncated256 = "{ov["ref_truncated_256_dec"]}";')
    lines.append(f'inline constexpr const char* kTableSha256 = "{man["table_sha256"]}";')
    lines.append(f"// Full canonical table m_ppm10k[0..{NV_MAX}] (len {len(table)}):")
    lines.append(f"inline constexpr std::array<uint16_t, {len(table)}> kStakingMrPpm10k = {{{{")
    for i in range(0, len(table), 16):
        chunk = ",".join(str(v) for v in table[i:i + 16])
        lines.append("    " + chunk + ",")
    lines.append("}};")
    lines.append("}  // namespace blackcoin_staking_canonical")
    lines.append("#endif")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def emit_json(path: str) -> None:
    man = build_manifest()
    man["full_table"] = full_table()
    with open(path, "w") as f:
        json.dump(man, f, indent=2)
        f.write("\n")


def check(path: str) -> int:
    man = build_manifest()
    with open(path) as f:
        blob = f.read()
    ok = True
    # table hash must appear verbatim in either header or json
    if man["table_sha256"] not in blob:
        print(f"FAIL: committed {path} does not contain current canonical table sha256 {man['table_sha256']}")
        ok = False
    if man["overflow_vectors"]["ref_bntarget_times_weight_full_dec"] not in blob:
        print("FAIL: committed file does not contain current overflow reference product")
        ok = False
    for name, val in man["tier_points"].items():
        if str(val) not in blob:
            print(f"WARN: tier point {name}={val} not found verbatim in {path}")
    print("OK: committed canonical data matches generator." if ok else "MISMATCH — consensus table drift!")
    return 0 if ok else 1


def summary() -> None:
    man = build_manifest()
    print("=== canonical tier ppm10k (frozen round-half-up) ===")
    for name, val in man["tier_points"].items():
        print(f"  {name:12s} -> {val}")
    print(f"  operator (flat) -> {man['operator_ppm10k']}")
    print(f"=== table: len={man['table_len']} sha256={man['table_sha256']}")
    ov = man["overflow_vectors"]
    print("=== overflow edge ===")
    print(f"  ref product bits={ov['ref_bntarget_times_weight_full_bits']} (must be 269, >256)")
    print(f"  naive-256 truncation changes value: {ov['truncation_changes_value']} (must be True)")
    print(f"  forbidden fold bits={ov['forbidden_fold_bits']} (283 — never do this order)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Staking-weight table generator")
    ap.add_argument("--emit-header", metavar="PATH")
    ap.add_argument("--emit-json", metavar="PATH")
    ap.add_argument("--check", metavar="PATH")
    args = ap.parse_args()
    if args.emit_header:
        emit_header(args.emit_header)
        print(f"wrote header {args.emit_header}")
    if args.emit_json:
        emit_json(args.emit_json)
        print(f"wrote json {args.emit_json}")
    if args.check:
        return check(args.check)
    if not (args.emit_header or args.emit_json):
        summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
