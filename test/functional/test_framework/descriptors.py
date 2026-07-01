#!/usr/bin/env python3
# Copyright (c) 2019 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utility functions related to output descriptors"""

import re

from test_framework.address import b58chars
from test_framework.script import hash256

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

MAIN_EXT_PUBLIC = bytes.fromhex("0488b21e")
MAIN_EXT_SECRET = bytes.fromhex("0488ade4")
TEST_EXT_PUBLIC = bytes.fromhex("043587cf")
TEST_EXT_SECRET = bytes.fromhex("04358394")

def descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))

def descsum_check(s, require=True):
    """Verify that the checksum is correct in a descriptor"""
    if not '#' in s:
        return not require
    if s[-9] != '#':
        return False
    if not all(x in CHECKSUM_CHARSET for x in s[-8:]):
        return False
    symbols = descsum_expand(s[:-9]) + [CHECKSUM_CHARSET.find(x) for x in s[-8:]]
    return descsum_polymod(symbols) == 1

def drop_origins(s):
    '''Drop the key origins from a descriptor'''
    desc = re.sub(r'\[.+?\]', '', s)
    if '#' in s:
        desc = desc[:desc.index('#')]
    return descsum_create(desc)


def _base58check_decode(s):
    n = 0
    for c in s:
        n *= 58
        assert c in b58chars
        n += b58chars.index(c)
    payload = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip(b58chars[0]))
    payload = b"\x00" * pad + payload
    assert hash256(payload[:-4])[:4] == payload[-4:]
    return payload[:-4]


def _base58check_encode(payload):
    payload = payload + hash256(payload)[:4]
    value = int.from_bytes(payload, "big")
    result = ""
    while value > 0:
        result = b58chars[value % 58] + result
        value //= 58
    for b in payload:
        if b == 0:
            result = b58chars[0] + result
        else:
            break
    return result


def xkey_to_main_prefix(xkey):
    """Convert inherited regtest tpub/tprv fixtures to this fork's xpub/xprv.

    Blackcoin regtest intentionally uses main extended-key version bytes,
    while many inherited Bitcoin functional tests still embed tpub/tprv
    descriptor vectors. The key material and derivation path stay identical;
    only the version prefix is adapted so descriptor parsing tests remain
    faithful to this fork.
    """
    payload = _base58check_decode(xkey)
    if payload[:4] == TEST_EXT_PUBLIC:
        return _base58check_encode(MAIN_EXT_PUBLIC + payload[4:])
    if payload[:4] == TEST_EXT_SECRET:
        return _base58check_encode(MAIN_EXT_SECRET + payload[4:])
    return xkey


def xkeys_to_main_prefix(desc):
    return re.sub(r"\bt(?:pub|prv)[1-9A-HJ-NP-Za-km-z]+", lambda m: xkey_to_main_prefix(m.group(0)), desc)


def descsum_create_with_main_xkeys(desc):
    return descsum_create(xkeys_to_main_prefix(desc))
