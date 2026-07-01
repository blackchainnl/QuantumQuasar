// Copyright (c) 2022 Blackcoin Core Developers
// Copyright (c) 2022 Blackcoin More Developers
// Copyright (c) 2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/checks.h>

#include <crypto/mldsa.h>
#include <key.h>
#include <random.h>
#include <util/time.h>
#include <util/translation.h>

#include <memory>

namespace kernel {

util::Result<void> SanityChecks(const Context&)
{
    if (!ECC_InitSanityCheck()) {
        return util::Error{Untranslated("Elliptic curve cryptography sanity check failure. Aborting.")};
    }

    if (!Random_SanityCheck()) {
        return util::Error{Untranslated("OS cryptographic RNG sanity check failure. Aborting.")};
    }

    if (!ML_DSA::SelfTest()) {
        return util::Error{Untranslated("ML-DSA cryptography sanity check failure. Aborting.")};
    }

    if (!ChronoSanityCheck()) {
        return util::Error{Untranslated("Clock epoch mismatch. Aborting.")};
    }

    return {};
}

}
