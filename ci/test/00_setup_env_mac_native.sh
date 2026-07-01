#!/usr/bin/env bash
#
# Copyright (c) 2019-present Blackcoin Core Developers
# Copyright (c) 2019-present Blackcoin More Developers
# Copyright (c) 2019-present Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export HOST=x86_64-apple-darwin
# Homebrew's python@3.12 is marked as externally managed (PEP 668).
# Therefore, `--break-system-packages` is needed.
export PIP_PACKAGES="--break-system-packages zmq"
export GOAL="install"
export BITCOIN_CONFIG="--with-gui --with-miniupnpc --with-natpmp --enable-reduce-exports"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
export CCACHE_MAXSIZE=400M
export RUN_FUZZ_TESTS=true
export FUZZ_TESTS_CONFIG="--exclude banman"  # https://github.com/bitcoin/bitcoin/issues/27924

if command -v brew >/dev/null; then
    QT5_PREFIX="$(brew --prefix qt@5 2>/dev/null || true)"
    LIBOQS_PREFIX="$(brew --prefix liboqs 2>/dev/null || true)"
    if [[ -n "$QT5_PREFIX" ]]; then
        export PATH="$QT5_PREFIX/bin:$PATH"
        export PKG_CONFIG_PATH="$QT5_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
    if [[ -n "$LIBOQS_PREFIX" ]]; then
        export PKG_CONFIG_PATH="$LIBOQS_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
fi
