#!/usr/bin/env bash
#
# Copyright (c) 2019-present Blackcoin Core Developers
# Copyright (c) 2019-present Blackcoin More Developers
# Copyright (c) 2019-present Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

set -o errexit; source ./ci/test/00_setup_env.sh
set -o errexit
"./ci/test/02_run_container.sh"
