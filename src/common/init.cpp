// Copyright (c) 2023 Blackcoin Core Developers
// Copyright (c) 2023 Blackcoin More Developers
// Copyright (c) 2023 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compat/compat.h>
#include <common/args.h>
#include <common/init.h>
#include <logging.h>
#include <random.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace {

constexpr const char* LEGACY_BLACKMORE_CONF_FILENAME = "blackmore.conf";
constexpr const char* MIGRATION_DONE_FILENAME = ".blackcoin-migration-done";
constexpr const char* MIGRATION_RECOVERY_FILENAME = ".blackcoin-migration-recovery";
constexpr const char* MIGRATION_LOCK_FILENAME = ".lock";
constexpr std::array<const char*, 3> LEGACY_NETWORK_DIRS{"testnet", "signet", "regtest"};

enum class MigrationChoice {
    AUTO,
    BLACKMORE,
    BLACKCOIN,
    NONE,
};

struct LegacySource {
    const char* label;
    fs::path path;
    const char* config_filename;
};

//! Front-end progress sink for the first-run migration; set once by
//! InitConfig before any migration work starts (single-threaded init path).
common::MigrationProgressFn g_migration_progress_fn;

void ReportMigrationProgress(const std::string& phase, int progress_percent)
{
    if (g_migration_progress_fn) g_migration_progress_fn(phase, progress_percent);
}

bool PathExistsNoThrow(const fs::path& path)
{
    try {
        return fs::exists(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsDirectoryNoThrow(const fs::path& path)
{
    try {
        return fs::is_directory(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsRegularFileNoThrow(const fs::path& path)
{
    try {
        return fs::is_regular_file(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsSymlinkNoThrow(const fs::path& path)
{
    try {
        return fs::is_symlink(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool DirectoryHasEntriesNoThrow(const fs::path& path)
{
    try {
        if (!fs::is_directory(path)) return false;
        return fs::directory_iterator(path) != fs::directory_iterator();
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy directory %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

fs::path NormalizedAbsolutePath(const fs::path& path)
{
    return fs::absolute(path).lexically_normal();
}

bool DestinationAllowsLegacyMigration(const fs::path& destination)
{
    if (!PathExistsNoThrow(destination)) return true;
    try {
        return fs::is_directory(destination) && fs::is_empty(destination);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect Blackcoin datadir %s: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

std::vector<fs::path> BlackmoreDataDirCandidates(const fs::path& new_base_path)
{
    std::vector<fs::path> candidates;
    const fs::path normalized_new_base = NormalizedAbsolutePath(new_base_path);

    auto add_candidate = [&](const fs::path& candidate) {
        if (candidate.empty()) return;
        const fs::path normalized = NormalizedAbsolutePath(candidate);
        if (normalized == normalized_new_base) return;
        if (std::find(candidates.begin(), candidates.end(), normalized) == candidates.end()) {
            candidates.push_back(normalized);
        }
    };

    if (!new_base_path.parent_path().empty()) {
        const fs::path sibling_base = new_base_path.parent_path();
        add_candidate(sibling_base / "Blackmore");
        add_candidate(sibling_base / ".blackmore");
    }

    if (const char* home = std::getenv("HOME")) {
        const fs::path home_path{home};
        add_candidate(home_path / ".blackmore");
    }
    if (const char* appdata = std::getenv("APPDATA")) {
        add_candidate(fs::path{appdata} / "Blackmore");
    }

    return candidates;
}

bool HasDataPayload(const fs::path& base_path, const char* primary_config_filename)
{
    if (!PathIsDirectoryNoThrow(base_path)) return false;

    bool has_payload =
        PathExistsNoThrow(base_path / primary_config_filename) ||
        PathExistsNoThrow(base_path / BITCOIN_CONF_FILENAME) ||
        PathExistsNoThrow(base_path / LEGACY_BLACKMORE_CONF_FILENAME) ||
        PathExistsNoThrow(base_path / BITCOIN_SETTINGS_FILENAME) ||
        PathExistsNoThrow(base_path / "wallet.dat") ||
        DirectoryHasEntriesNoThrow(base_path / "wallets") ||
        DirectoryHasEntriesNoThrow(base_path / "blocks") ||
        DirectoryHasEntriesNoThrow(base_path / "chainstate");

    for (const char* network_dir : LEGACY_NETWORK_DIRS) {
        const fs::path legacy_net_path = base_path / network_dir;
        has_payload = has_payload ||
            PathExistsNoThrow(legacy_net_path / "wallet.dat") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "wallets") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "blocks") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "chainstate");
    }
    return has_payload;
}

bool HasMigrationDoneMarker(const fs::path& destination)
{
    return PathIsRegularFileNoThrow(destination / MIGRATION_DONE_FILENAME);
}

std::string UniqueMigrationSuffix(const std::string& label)
{
    static std::atomic<uint64_t> sequence{0};
    FastRandomContext rng;
    const auto wall_ticks = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
#ifdef WIN32
    const uint64_t process_id = static_cast<uint64_t>(GetCurrentProcessId());
#else
    const uint64_t process_id = static_cast<uint64_t>(getpid());
#endif
    return strprintf("%s-%d-%d-%d-%s",
                     label,
                     wall_ticks,
                     process_id,
                     sequence.fetch_add(1),
                     HexStr(rng.randbytes(8)));
}

fs::path UniqueMigrationPath(const fs::path& destination, const std::string& suffix)
{
    fs::path temp = destination;
    temp += "." + UniqueMigrationSuffix(suffix);
    return temp;
}

fs::path MigrationBackupRoot(const fs::path& destination)
{
    fs::path backup_root = destination;
    backup_root += ".backup";
    return backup_root;
}

fs::path MigrationRecoveryPath(const fs::path& destination)
{
    return MigrationBackupRoot(destination) / MIGRATION_RECOVERY_FILENAME;
}

fs::path UniqueBackupPath(const fs::path& destination, const std::string& label)
{
    return MigrationBackupRoot(destination) / fs::PathFromString(UniqueMigrationSuffix(label));
}

bool PathNameStartsWith(const fs::path& path, const std::string& prefix)
{
    return fs::PathToString(path.filename()).rfind(prefix, 0) == 0;
}

void CleanupStaleMigrationTemps(const fs::path& destination)
{
    if (destination.parent_path().empty() || !PathIsDirectoryNoThrow(destination.parent_path())) return;

    const std::string base_name = fs::PathToString(destination.filename());
    std::error_code ec;
    for (fs::directory_iterator it(destination.parent_path(), fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        const fs::path path = it->path();
        if (PathNameStartsWith(path, base_name + ".tmp-") || PathNameStartsWith(path, base_name + ".import-")) {
            std::error_code remove_ec;
            fs::remove_all(path, remove_ec);
            if (remove_ec) {
                LogPrintf("Warning: failed to remove stale migration temp path %s: %s\n",
                          fs::quoted(fs::PathToString(path)),
                          remove_ec.message());
            }
        }
    }
}

void RemoveCopiedLockFiles(const fs::path& root)
{
    std::vector<fs::path> lock_files;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        if (it->path().filename() == MIGRATION_LOCK_FILENAME) {
            lock_files.push_back(it->path());
        }
    }
    for (const fs::path& lock_file : lock_files) {
        std::error_code remove_ec;
        fs::remove(lock_file, remove_ec);
        if (remove_ec) {
            LogPrintf("Warning: failed to remove copied lock file %s: %s\n",
                      fs::quoted(fs::PathToString(lock_file)),
                      remove_ec.message());
        }
    }
}

bool ProbeExistingDirectoryLock(const fs::path& directory)
{
    const fs::path lock_path = directory / MIGRATION_LOCK_FILENAME;
    if (!PathExistsNoThrow(lock_path)) return true;

    auto lock = std::make_unique<fsbridge::FileLock>(lock_path);
    if (!lock->TryLock()) {
        return error("Error while attempting to probe-lock directory %s: %s", fs::PathToString(directory), lock->GetReason());
    }
    return true;
}

bool SourceRootIsCopyable(const fs::path& source)
{
    if (!PathIsDirectoryNoThrow(source)) return false;
    if (!ProbeExistingDirectoryLock(source)) {
        LogPrintf("Warning: skipping legacy datadir migration because %s appears to be in use\n", fs::quoted(fs::PathToString(source)));
        return false;
    }
    return true;
}

std::optional<fs::path> ResolveCopyableSourceRoot(const fs::path& source)
{
    if (!PathIsDirectoryNoThrow(source)) return std::nullopt;

    fs::path resolved_source{source};
    if (PathIsSymlinkNoThrow(source)) {
        std::error_code ec;
        resolved_source = fs::canonical(source, ec);
        if (ec || !PathIsDirectoryNoThrow(resolved_source)) {
            LogPrintf("Warning: refusing legacy datadir migration from broken symlinked source root %s: %s\n",
                      fs::quoted(fs::PathToString(source)),
                      ec ? ec.message() : "target is not a directory");
            return std::nullopt;
        }
        LogPrintf("Blackcoin: legacy datadir source %s is a symlink; migrating resolved target %s\n",
                  fs::quoted(fs::PathToString(source)),
                  fs::quoted(fs::PathToString(resolved_source)));
    }

    if (!SourceRootIsCopyable(resolved_source)) return std::nullopt;
    return resolved_source;
}

bool PathIsRealDirectoryNoThrow(const fs::path& path)
{
    return PathIsDirectoryNoThrow(path) && !PathIsSymlinkNoThrow(path);
}

bool WriteDurableTextFile(const fs::path& path, const std::string& text)
{
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, "wb");
    if (!file) return false;

    const bool wrote_all = std::fwrite(text.data(), 1, text.size(), file) == text.size();
    const bool committed = wrote_all && FileCommit(file);
    const bool closed = std::fclose(file) == 0;
    if (!committed || !closed) return false;

    DirectoryCommit(path.parent_path());
    return true;
}

void RemoveCopiedBlocksDirs(const fs::path& root)
{
    std::vector<fs::path> blocks_dirs;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        if (it->is_directory(ec) && it->path().filename() == "blocks") {
            blocks_dirs.push_back(it->path());
            it.disable_recursion_pending();
        }
    }
    for (const fs::path& blocks_dir : blocks_dirs) {
        std::error_code remove_ec;
        fs::remove_all(blocks_dir, remove_ec);
        if (remove_ec) {
            LogPrintf("Warning: failed to remove migrated blocks directory %s after -blocksdir override: %s\n",
                      fs::quoted(fs::PathToString(blocks_dir)),
                      remove_ec.message());
        }
    }
}

//! Total size of the regular files a migration copy will touch, honoring the
//! same "blocks" directory pruning that the copy itself performs.
uintmax_t ScanCopyPlanBytes(const fs::path& source, bool skip_blocks)
{
    uintmax_t total{0};
    std::error_code ec;
    for (fs::recursive_directory_iterator it(source, fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        if (skip_blocks && it->is_directory(ec) && it->path().filename() == "blocks") {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_regular_file(ec) && !it->is_symlink(ec)) {
            std::error_code size_ec;
            const uintmax_t size = it->file_size(size_ec);
            if (!size_ec) total += size;
        }
    }
    return total;
}

//! Transient per-network state that must not follow a legacy datadir into a
//! new client: serialization formats drift between forks and a stale
//! peers.dat or mempool.dat turns the first post-upgrade start into a hard
//! "corrupt file" error. All of these are safely regenerated from scratch.
bool IsTransientNetworkFile(const fs::path& filename)
{
    static const std::array<const char*, 8> TRANSIENT_FILES{
        "peers.dat", "banlist.dat", "banlist.json", "anchors.dat",
        "mempool.dat", "fee_estimates.dat", "db.log", "debug.log"};
    const std::string name = fs::PathToString(filename);
    for (const char* transient : TRANSIENT_FILES) {
        if (name == transient) return true;
    }
    return false;
}

//! Copy `source` into `destination` file by file so front ends can render
//! progress, skipping any "blocks" subtree when requested instead of copying
//! gigabytes of block files only to delete them again afterwards.
void CopyTreeWithProgress(const fs::path& source, const fs::path& destination, bool skip_blocks, bool skip_transient, const std::string& phase, uintmax_t total_bytes)
{
    uintmax_t copied_bytes{0};
    int last_percent{-1};
    ReportMigrationProgress(phase, total_bytes == 0 ? -1 : 0);

    fs::create_directories(destination);
    std::error_code ec;
    for (fs::recursive_directory_iterator it(source, fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        const fs::path relative = it->path().lexically_relative(source);
        const fs::path target = destination / relative;
        std::error_code type_ec;
        if (skip_blocks && it->is_directory(type_ec) && it->path().filename() == "blocks") {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_symlink(type_ec)) {
            fs::copy_symlink(it->path(), target);
        } else if (it->is_directory(type_ec)) {
            fs::create_directories(target);
        } else if (it->is_regular_file(type_ec)) {
            if (skip_transient && IsTransientNetworkFile(it->path().filename())) {
                LogPrintf("Blackcoin: not migrating transient legacy file %s (it will be regenerated)\n",
                          fs::quoted(fs::PathToString(it->path())));
                continue;
            }
            fs::create_directories(target.parent_path());
            fs::copy_file(it->path(), target, fs::copy_options::skip_existing);
            std::error_code size_ec;
            const uintmax_t size = it->file_size(size_ec);
            if (!size_ec) copied_bytes += size;
            if (total_bytes > 0) {
                const int percent = static_cast<int>(std::min<uintmax_t>(100, (copied_bytes * 100) / total_bytes));
                if (percent != last_percent) {
                    last_percent = percent;
                    ReportMigrationProgress(phase, percent);
                }
            }
        }
        // Other file types (sockets, fifos, devices) are intentionally skipped.
    }
    if (ec) {
        throw std::runtime_error(strprintf("failed while walking %s: %s", fs::PathToString(source), ec.message()));
    }
    ReportMigrationProgress(phase, 100);
}

bool CopyDirectoryTreeVerified(const fs::path& source, const fs::path& destination, const char* verify_config_filename, bool skip_blocks, bool convert_blackmore_config, const std::string& progress_phase)
{
    const fs::path temp_path = UniqueMigrationPath(destination, "tmp");
    try {
        fs::create_directories(destination.parent_path());
        if (PathExistsNoThrow(destination)) {
            LogPrintf("Warning: refusing to copy legacy datadir into existing path %s\n", fs::quoted(fs::PathToString(destination)));
            return false;
        }

        const uintmax_t plan_bytes = ScanCopyPlanBytes(source, skip_blocks);

        // Fail fast with a clear message when the destination volume cannot
        // hold the copy instead of dying deep into a multi-gigabyte transfer.
        std::error_code space_ec;
        const fs::space_info space = fs::space(destination.parent_path(), space_ec);
        constexpr uintmax_t SPACE_MARGIN{512ull * 1024 * 1024};
        if (!space_ec && space.available < plan_bytes + SPACE_MARGIN) {
            throw std::runtime_error(strprintf(
                "not enough free disk space to migrate safely: need about %.1f GB plus working room, only %.1f GB available on the destination volume",
                plan_bytes / 1e9, space.available / 1e9));
        }

        LogPrintf("Blackcoin: %s: copying %.1f MB from %s\n", progress_phase, plan_bytes / 1e6, fs::quoted(fs::PathToString(source)));
        // Only the promoted import filters transient network files; backups
        // stay byte-faithful to the source (minus blocks) for manual recovery.
        CopyTreeWithProgress(source, temp_path, skip_blocks, /*skip_transient=*/convert_blackmore_config, progress_phase, plan_bytes);
        RemoveCopiedLockFiles(temp_path);

        if (convert_blackmore_config) {
            const fs::path legacy_config = temp_path / LEGACY_BLACKMORE_CONF_FILENAME;
            const fs::path blackcoin_config = temp_path / BITCOIN_CONF_FILENAME;
            if (PathExistsNoThrow(legacy_config) && !PathExistsNoThrow(blackcoin_config)) {
                fs::copy_file(legacy_config, blackcoin_config, fs::copy_options::none);
            }
        }

        if (!HasDataPayload(temp_path, verify_config_filename) &&
            !(skip_blocks && HasDataPayload(source, verify_config_filename))) {
            throw std::runtime_error("copied datadir did not contain a recognizable wallet, config, block, or chainstate payload");
        }
        if (!PathIsRealDirectoryNoThrow(temp_path)) {
            throw std::runtime_error("copied datadir root was not a real directory");
        }

        fs::rename(temp_path, destination);
        if (!PathIsRealDirectoryNoThrow(destination)) {
            throw std::runtime_error("migrated datadir root was not a real directory");
        }
        DirectoryCommit(destination.parent_path());
        return true;
    } catch (const std::exception& e) {
        std::error_code ec;
        fs::remove_all(temp_path, ec);
        LogPrintf("Warning: failed to copy legacy datadir %s to %s: %s\n",
                  fs::quoted(fs::PathToString(source)),
                  fs::quoted(fs::PathToString(destination)),
                  e.what());
        return false;
    }
}

bool BackupLegacySource(const fs::path& source, const fs::path& destination, const std::string& label, const char* verify_config_filename)
{
    if (!HasDataPayload(source, verify_config_filename)) return true;
    const std::optional<fs::path> copy_source = ResolveCopyableSourceRoot(source);
    if (!copy_source) return false;

    const fs::path backup_path = UniqueBackupPath(destination, label);
    // Backups exist to protect wallets, configs, and chain databases; the
    // multi-gigabyte blocks directory is never modified by migration (the
    // original source directory is preserved in place), so skip it here
    // instead of doubling the disk cost and copy time of the upgrade.
    const bool copied = CopyDirectoryTreeVerified(*copy_source, backup_path, verify_config_filename, /*skip_blocks=*/true, /*convert_blackmore_config=*/false,
                                                  strprintf("Backing up %s data", label));
    if (!copied) return false;

    LogPrintf("Blackcoin: backed up legacy datadir %s to %s (blocks directory left with the original)\n",
              fs::quoted(fs::PathToString(source)),
              fs::quoted(fs::PathToString(backup_path)));
    return true;
}

bool MoveActiveDestinationAside(const fs::path& destination, const fs::path& moved_path)
{
    if (!HasDataPayload(destination, BITCOIN_CONF_FILENAME)) return false;
    if (!LockDirectory(destination, MIGRATION_LOCK_FILENAME, false)) {
        LogPrintf("Warning: refusing to move active Blackcoin datadir %s because it appears to be in use\n", fs::quoted(fs::PathToString(destination)));
        return false;
    }

    try {
        fs::create_directories(moved_path.parent_path());
        fs::rename(destination, moved_path);
        UnlockDirectory(destination, MIGRATION_LOCK_FILENAME);
        std::error_code ec;
        fs::remove(moved_path / MIGRATION_LOCK_FILENAME, ec);
        DirectoryCommit(destination.parent_path());
        DirectoryCommit(moved_path.parent_path());
        LogPrintf("Blackcoin: moved active legacy datadir %s to %s before selected migration\n",
                  fs::quoted(fs::PathToString(destination)),
                  fs::quoted(fs::PathToString(moved_path)));
        return true;
    } catch (const std::exception& e) {
        UnlockDirectory(destination, MIGRATION_LOCK_FILENAME);
        LogPrintf("Warning: failed to move active Blackcoin datadir %s aside: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

bool WriteMigrationDoneMarker(const fs::path& destination, const std::string& status)
{
    try {
        fs::create_directories(destination);
        const std::string marker_text = "Blackcoin first-run data migration completed.\n" + status + "\n";
        if (!WriteDurableTextFile(destination / MIGRATION_DONE_FILENAME, marker_text)) {
            LogPrintf("Warning: failed to commit Blackcoin migration marker in %s\n", fs::quoted(fs::PathToString(destination)));
            return false;
        }
        DirectoryCommit(destination);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to write Blackcoin migration marker in %s: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

bool WriteRecoveryRecord(const fs::path& destination, const fs::path& moved_path)
{
    try {
        const std::string text = fs::PathToString(moved_path) + "\n";
        if (!WriteDurableTextFile(MigrationRecoveryPath(destination), text)) {
            LogPrintf("Warning: failed to commit Blackcoin migration recovery record under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(destination))));
            return false;
        }
        DirectoryCommit(MigrationBackupRoot(destination));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to write Blackcoin migration recovery record: %s\n", e.what());
        return false;
    }
}

std::optional<fs::path> ReadRecoveryRecord(const fs::path& destination)
{
    const fs::path recovery_path = MigrationRecoveryPath(destination);
    if (!PathIsRegularFileNoThrow(recovery_path)) return std::nullopt;

    try {
        std::ifstream file{recovery_path};
        std::string line;
        std::getline(file, line);
        if (line.empty()) return std::nullopt;
        return fs::PathFromString(line);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to read Blackcoin migration recovery record %s: %s\n",
                  fs::quoted(fs::PathToString(recovery_path)),
                  e.what());
        return std::nullopt;
    }
}

void ClearRecoveryRecord(const fs::path& destination)
{
    std::error_code ec;
    fs::remove(MigrationRecoveryPath(destination), ec);
    DirectoryCommit(MigrationBackupRoot(destination));
}

bool RestoreStrandedActiveBackup(const fs::path& destination)
{
    if (PathExistsNoThrow(destination)) return true;

    const std::optional<fs::path> recovery_path = ReadRecoveryRecord(destination);
    if (!recovery_path) return true;

    if (!PathIsRealDirectoryNoThrow(*recovery_path) || !HasDataPayload(*recovery_path, BITCOIN_CONF_FILENAME)) {
        LogPrintf("Warning: Blackcoin migration recovery record points to missing or invalid backup %s; leaving backups untouched for manual recovery\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return true;
    }

    if (!CopyDirectoryTreeVerified(*recovery_path, destination, BITCOIN_CONF_FILENAME, /*skip_blocks=*/false, /*convert_blackmore_config=*/false,
                                   "Restoring Blackcoin data after an interrupted upgrade")) {
        LogPrintf("Warning: failed to copy stranded original .blackcoin datadir from %s\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }
    if (!PathIsRealDirectoryNoThrow(destination) || !HasDataPayload(destination, BITCOIN_CONF_FILENAME)) {
        LogPrintf("Warning: restored .blackcoin datadir from %s failed post-copy verification\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }

    ClearRecoveryRecord(destination);
    DirectoryCommit(destination.parent_path());
    LogPrintf("Blackcoin: restored stranded original .blackcoin datadir from %s after interrupted migration; backup copy preserved\n",
              fs::quoted(fs::PathToString(*recovery_path)));
    return true;
}

bool CopyLegacyDataDirAtomically(const fs::path& legacy_base_path, const fs::path& destination, bool skip_blocks)
{
    if (!PathExistsNoThrow(legacy_base_path) || !HasDataPayload(legacy_base_path, LEGACY_BLACKMORE_CONF_FILENAME)) return false;
    if (!DestinationAllowsLegacyMigration(destination)) return false;
    const std::optional<fs::path> copy_source = ResolveCopyableSourceRoot(legacy_base_path);
    if (!copy_source) return false;

    const bool copied = CopyDirectoryTreeVerified(*copy_source, destination, LEGACY_BLACKMORE_CONF_FILENAME, skip_blocks, /*convert_blackmore_config=*/true,
                                                  "Importing Blackmore data");
    if (copied) {
        LogPrintf("Blackcoin: completed copy-only legacy datadir migration from %s to %s\n",
                  fs::quoted(fs::PathToString(legacy_base_path)),
                  fs::quoted(fs::PathToString(destination)));
        return true;
    }
    return false;
}

std::optional<LegacySource> FindBlackmoreSource(const fs::path& base_path)
{
    for (const fs::path& candidate : BlackmoreDataDirCandidates(base_path)) {
        if (HasDataPayload(candidate, LEGACY_BLACKMORE_CONF_FILENAME)) {
            return LegacySource{"blackmore", candidate, LEGACY_BLACKMORE_CONF_FILENAME};
        }
    }
    return std::nullopt;
}

MigrationChoice ParseMigrationChoiceValue(const std::string& raw_choice)
{
    const std::string choice = ToLower(raw_choice);
    if (choice == "auto") return MigrationChoice::AUTO;
    if (choice == "blackmore") return MigrationChoice::BLACKMORE;
    if (choice == "blackcoin") return MigrationChoice::BLACKCOIN;
    if (choice == "none") return MigrationChoice::NONE;

    LogPrintf("Warning: unknown -migratewallet value %s; using auto\n", choice);
    return MigrationChoice::AUTO;
}

MigrationChoice ParseMigrationChoice(const ArgsManager& args)
{
    return ParseMigrationChoiceValue(args.GetArg("-migratewallet", "auto"));
}

MigrationChoice ResolveAutoMigrationChoice(bool has_blackcoin, const fs::path& blackcoin_path, const std::optional<LegacySource>& blackmore_source, const common::LegacyMigrationPromptFn& legacy_migration_prompt_fn, bool explicit_choice)
{
    if (blackmore_source && !has_blackcoin) return MigrationChoice::BLACKMORE;
    if (has_blackcoin && !blackmore_source) return MigrationChoice::BLACKCOIN;
    if (!has_blackcoin && !blackmore_source) return MigrationChoice::NONE;

    if (!explicit_choice && legacy_migration_prompt_fn) {
        const MigrationChoice prompted = ParseMigrationChoiceValue(
            legacy_migration_prompt_fn(fs::PathToString(blackcoin_path), fs::PathToString(blackmore_source->path)));
        if (prompted == MigrationChoice::BLACKMORE || prompted == MigrationChoice::BLACKCOIN || prompted == MigrationChoice::NONE) {
            return prompted;
        }
    }

    LogPrintf("Blackcoin: both .blackcoin and .blackmore legacy datadirs were found; keeping the populated .blackcoin datadir by default. The .blackmore datadir will be backed up and preserved. Restart with -migratewallet=blackmore to import it explicitly.\n");
    return MigrationChoice::BLACKCOIN;
}

std::optional<std::string> CommitMigrationMarker(const fs::path& destination, const std::string& status)
{
    if (WriteMigrationDoneMarker(destination, status)) return std::nullopt;
    return "failed to durably write the first-run migration marker";
}

std::optional<std::string> MaybeMigrateLegacyDataDir(ArgsManager& args, const common::LegacyMigrationPromptFn& legacy_migration_prompt_fn)
{
    if (args.IsArgSet("-datadir") || args.IsArgSet("-conf")) return std::nullopt;

    const fs::path base_path = args.GetDataDirBase();
    CleanupStaleMigrationTemps(base_path);
    if (!RestoreStrandedActiveBackup(base_path)) {
        return "failed to restore original .blackcoin datadir after an interrupted migration";
    }
    if (HasMigrationDoneMarker(base_path)) return std::nullopt;

    const bool has_blackcoin = HasDataPayload(base_path, BITCOIN_CONF_FILENAME);
    const std::optional<LegacySource> blackmore_source = FindBlackmoreSource(base_path);

    if (!has_blackcoin && !blackmore_source) {
        return std::nullopt;
    }

    MigrationChoice choice = ParseMigrationChoice(args);
    const bool explicit_choice = args.IsArgSet("-migratewallet");
    if (choice == MigrationChoice::AUTO) {
        choice = ResolveAutoMigrationChoice(has_blackcoin, base_path, blackmore_source, legacy_migration_prompt_fn, explicit_choice);
    }

    if (has_blackcoin && !BackupLegacySource(base_path, base_path, "original-blackcoin", BITCOIN_CONF_FILENAME)) {
        return "failed to preserve a backup of the existing .blackcoin datadir";
    }
    if (blackmore_source && !BackupLegacySource(blackmore_source->path, base_path, blackmore_source->label, blackmore_source->config_filename)) {
        return "failed to preserve a backup of the legacy .blackmore datadir";
    }

    if (choice == MigrationChoice::NONE) {
        LogPrintf("Blackcoin: first-run legacy datadir migration was disabled; backups were preserved under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(base_path))));
        const auto marker_error = CommitMigrationMarker(base_path, "Migration disabled by -migratewallet=none; backups preserved.");
        if (marker_error) return marker_error;
        ClearRecoveryRecord(base_path);
        return std::nullopt;
    }

    if (choice == MigrationChoice::BLACKCOIN) {
        if (has_blackcoin) {
            LogPrintf("Blackcoin: using existing .blackcoin datadir after preserving a backup under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(base_path))));
            const auto marker_error = CommitMigrationMarker(base_path, "Using existing original .blackcoin datadir; backups preserved.");
            if (marker_error) return marker_error;
            ClearRecoveryRecord(base_path);
            return std::nullopt;
        }
        return "-migratewallet=blackcoin was selected but no populated .blackcoin datadir was found";
    }

    if (choice == MigrationChoice::BLACKMORE) {
        if (!blackmore_source) {
            return "-migratewallet=blackmore was selected but no .blackmore datadir was found";
        }

        const fs::path staged_import_path = UniqueMigrationPath(base_path, "import");
        if (!CopyLegacyDataDirAtomically(blackmore_source->path, staged_import_path, args.IsArgSet("-blocksdir"))) {
            return "failed to stage the .blackmore datadir import";
        }

        std::optional<fs::path> moved_active_path;
        if (has_blackcoin) {
            const fs::path moved_path = UniqueBackupPath(base_path, "active-blackcoin");
            if (!WriteRecoveryRecord(base_path, moved_path)) {
                std::error_code ec;
                fs::remove_all(staged_import_path, ec);
                return "failed to write recovery record before replacing the active .blackcoin datadir";
            }
            if (!MoveActiveDestinationAside(base_path, moved_path)) {
                std::error_code ec;
                fs::remove_all(staged_import_path, ec);
                return "failed to move the active .blackcoin datadir aside before selected .blackmore import";
            }
            moved_active_path = moved_path;
        }

        try {
            if (PathExistsNoThrow(base_path)) {
                throw std::runtime_error("active .blackcoin datadir still exists before staged import promotion");
            }
            fs::rename(staged_import_path, base_path);
            if (!PathIsRealDirectoryNoThrow(base_path)) {
                throw std::runtime_error("promoted .blackmore import was not a real directory");
            }
            DirectoryCommit(base_path.parent_path());
            const auto marker_error = CommitMigrationMarker(base_path, "Imported .blackmore datadir into active .blackcoin datadir; backups preserved.");
            if (marker_error) return marker_error;
            ClearRecoveryRecord(base_path);
            return std::nullopt;
        } catch (const std::exception& e) {
            LogPrintf("Warning: failed to promote staged .blackmore datadir import into %s: %s\n",
                      fs::quoted(fs::PathToString(base_path)),
                      e.what());
        }

        if (moved_active_path && !PathExistsNoThrow(base_path)) {
            try {
                fs::rename(*moved_active_path, base_path);
                ClearRecoveryRecord(base_path);
                DirectoryCommit(base_path.parent_path());
                LogPrintf("Blackcoin: restored original .blackcoin datadir after .blackmore migration failed\n");
            } catch (const std::exception& e) {
                LogPrintf("Warning: failed to restore original .blackcoin datadir from %s after .blackmore migration failure: %s\n",
                          fs::quoted(fs::PathToString(*moved_active_path)),
                          e.what());
            }
        }
        std::error_code ec;
        fs::remove_all(staged_import_path, ec);
        return "failed to activate the staged .blackmore datadir import";
    }
    return "unknown first-run migration choice";
}

} // namespace

namespace common {
std::optional<ConfigError> InitConfig(ArgsManager& args, SettingsAbortFn settings_abort_fn, LegacyMigrationPromptFn legacy_migration_prompt_fn, MigrationProgressFn migration_progress_fn)
{
    try {
        g_migration_progress_fn = std::move(migration_progress_fn);
        if (!CheckDataDirOption(args)) {
            return ConfigError{ConfigStatus::FAILED, strprintf(_("Specified data directory \"%s\" does not exist."), args.GetArg("-datadir", ""))};
        }

        if (const auto migration_error = MaybeMigrateLegacyDataDir(args, legacy_migration_prompt_fn)) {
            return ConfigError{ConfigStatus::FAILED, Untranslated(strprintf("Legacy datadir migration failed: %s. Startup aborted to avoid creating or loading the wrong wallet.", *migration_error))};
        }

        // Record original datadir and config paths before parsing the config
        // file. It is possible for the config file to contain a datadir= line
        // that changes the datadir path after it is parsed. This is useful for
        // CLI tools to let them use a different data storage location without
        // needing to pass it every time on the command line. (It is not
        // possible for the config file to cause another configuration to be
        // used, though. Specifying a conf= option in the config file causes a
        // parse error, and specifying a datadir= location containing another
        // blackcoin.conf file just ignores the other file.)
        const fs::path orig_datadir_path{args.GetDataDirBase()};
        const fs::path orig_config_path{AbsPathForConfigVal(args, args.GetPathArg("-conf", BITCOIN_CONF_FILENAME), /*net_specific=*/false)};

        std::string error;
        if (!args.ReadConfigFiles(error, true)) {
            return ConfigError{ConfigStatus::FAILED, strprintf(_("Error reading configuration file: %s"), error)};
        }

        // Check for chain settings (Params() calls are only valid after this clause)
        SelectParams(args.GetChainType());

        // Create datadir if it does not exist.
        const auto base_path{args.GetDataDirBase()};
        if (!fs::exists(base_path)) {
            // When creating a *new* datadir, also create a "wallets" subdirectory,
            // whether or not the wallet is enabled now, so if the wallet is enabled
            // in the future, it will use the "wallets" subdirectory for creating
            // and listing wallets, rather than the top-level directory where
            // wallets could be mixed up with other files. For backwards
            // compatibility, wallet code will use the "wallets" subdirectory only
            // if it already exists, but never create it itself. There is discussion
            // in https://github.com/bitcoin/bitcoin/issues/16220 about ways to
            // change wallet code so it would no longer be necessary to create
            // "wallets" subdirectories here.
            fs::create_directories(base_path / "wallets");
        }
        const auto net_path{args.GetDataDirNet()};
        if (!fs::exists(net_path)) {
            fs::create_directories(net_path / "wallets");
        }

        // Show an error or warning if there is a blackcoin.conf file in the
        // datadir that is being ignored.
        const fs::path base_config_path = base_path / BITCOIN_CONF_FILENAME;
        if (fs::exists(base_config_path) && !fs::equivalent(orig_config_path, base_config_path)) {
            const std::string cli_config_path = args.GetArg("-conf", "");
            const std::string config_source = cli_config_path.empty()
                ? strprintf("data directory %s", fs::quoted(fs::PathToString(orig_datadir_path)))
                : strprintf("command line argument %s", fs::quoted("-conf=" + cli_config_path));
            const std::string error = strprintf(
                "Data directory %1$s contains a %2$s file which is ignored, because a different configuration file "
                "%3$s from %4$s is being used instead. Possible ways to address this would be to:\n"
                "- Delete or rename the %2$s file in data directory %1$s.\n"
                "- Change datadir= or conf= options to specify one configuration file, not two, and use "
                "includeconf= to include any other configuration files.\n"
                "- Set allowignoredconf=1 option to treat this condition as a warning, not an error.",
                fs::quoted(fs::PathToString(base_path)),
                fs::quoted(BITCOIN_CONF_FILENAME),
                fs::quoted(fs::PathToString(orig_config_path)),
                config_source);
            if (args.GetBoolArg("-allowignoredconf", false)) {
                LogPrintf("Warning: %s\n", error);
            } else {
                return ConfigError{ConfigStatus::FAILED, Untranslated(error)};
            }
        }

        // Create settings.json if -nosettings was not specified.
        if (args.GetSettingsPath()) {
            std::vector<std::string> details;
            if (!args.ReadSettingsFile(&details)) {
                const bilingual_str& message = _("Settings file could not be read");
                if (!settings_abort_fn) {
                    return ConfigError{ConfigStatus::FAILED, message, details};
                } else if (settings_abort_fn(message, details)) {
                    return ConfigError{ConfigStatus::ABORTED, message, details};
                } else {
                    details.clear(); // User chose to ignore the error and proceed.
                }
            }
            if (!args.WriteSettingsFile(&details)) {
                const bilingual_str& message = _("Settings file could not be written");
                return ConfigError{ConfigStatus::FAILED_WRITE, message, details};
            }
        }
    } catch (const std::exception& e) {
        return ConfigError{ConfigStatus::FAILED, Untranslated(e.what())};
    }
    return {};
}
} // namespace common
