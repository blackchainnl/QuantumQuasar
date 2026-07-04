// Copyright (c) 2023 Blackcoin Core Developers
// Copyright (c) 2023 Blackcoin More Developers
// Copyright (c) 2023 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_INIT_H
#define BITCOIN_COMMON_INIT_H

#include <util/translation.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

class ArgsManager;

namespace common {
enum class ConfigStatus {
    FAILED,       //!< Failed generically.
    FAILED_WRITE, //!< Failed to write settings.json
    ABORTED,      //!< Aborted by user
};

struct ConfigError {
    ConfigStatus status;
    bilingual_str message{};
    std::vector<std::string> details{};
};

//! Callback function to let the user decide whether to abort loading if
//! settings.json file exists and can't be parsed, or to ignore the error and
//! overwrite the file.
using SettingsAbortFn = std::function<bool(const bilingual_str& message, const std::vector<std::string>& details)>;
using LegacyMigrationPromptFn = std::function<std::string(const std::string& blackcoin_datadir, const std::string& blackmore_datadir)>;
//! Callback reporting first-run legacy datadir migration progress so front
//! ends can show the user that a long copy is running rather than a hang.
//! `phase` is a short human-readable description of the current step and
//! `progress_percent` is 0-100 within that phase (-1 when indeterminate).
using MigrationProgressFn = std::function<void(const std::string& phase, int progress_percent)>;

/* Read config files, and create datadir and settings.json if they don't exist. */
std::optional<ConfigError> InitConfig(ArgsManager& args, SettingsAbortFn settings_abort_fn = nullptr, LegacyMigrationPromptFn legacy_migration_prompt_fn = nullptr, MigrationProgressFn migration_progress_fn = nullptr);
} // namespace common

#endif // BITCOIN_COMMON_INIT_H
