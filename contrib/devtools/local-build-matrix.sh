#!/usr/bin/env bash
#
# Copyright (c) 2026-present Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: contrib/devtools/local-build-matrix.sh [--target NAME] [--keep-work] [--werror] [--fail-on-warnings]

Run the release build matrix locally inside an Ubuntu 22.04 Docker container.
Each target is built from a clean git archive of HEAD, matching the export that
will be pushed for remote validation.

Targets:
  linux-64-bit
  windows-64-bit
  macos-64-bit
  linux-arm-64-bit

Environment:
  MAKEJOBS=N             parallelism inside the container (default: 4)
  LOCAL_MATRIX_WORK=DIR  log/archive root (default: build/local-matrix-work)
                          also stores per-target depends caches
  LOCAL_MATRIX_ALLOW_DIRTY=1
                         allow testing committed HEAD while the worktree is dirty

Examples:
  contrib/devtools/local-build-matrix.sh --target linux-64-bit
  contrib/devtools/local-build-matrix.sh --target linux-64-bit --werror
  MAKEJOBS=8 contrib/devtools/local-build-matrix.sh --fail-on-warnings
EOF
}

ROOT_DIR="$(git rev-parse --show-toplevel)"
WORK_ROOT="${LOCAL_MATRIX_WORK:-$ROOT_DIR/build/local-matrix-work}"
MAKEJOBS="${MAKEJOBS:-4}"
ALLOW_DIRTY="${LOCAL_MATRIX_ALLOW_DIRTY:-0}"
KEEP_WORK=0
WERROR=0
FAIL_ON_WARNINGS=0
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            [[ $# -ge 2 ]] || { echo "missing target name" >&2; exit 2; }
            TARGETS+=("$2")
            shift 2
            ;;
        --keep-work)
            KEEP_WORK=1
            shift
            ;;
        --werror)
            WERROR=1
            shift
            ;;
        --fail-on-warnings)
            FAIL_ON_WARNINGS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(linux-64-bit windows-64-bit macos-64-bit linux-arm-64-bit)
fi

if [[ "$ALLOW_DIRTY" -ne 1 ]] && [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
    echo "working tree is dirty; commit or stash changes before archive-based matrix validation" >&2
    echo "set LOCAL_MATRIX_ALLOW_DIRTY=1 only when intentionally testing committed HEAD" >&2
    git -C "$ROOT_DIR" status --short >&2
    exit 1
fi

target_vars() {
    local target="$1"
    DEP_OPTS=""
    POSTINSTALL=""
    SDK=""
    GOAL="install"
    case "$target" in
        linux-64-bit)
            HOST="x86_64-pc-linux-gnu"
            PACKAGES="python3"
            CONFIG_OPTS="--enable-sse2 --enable-glibc-back-compat LDFLAGS=-static-libstdc++"
            ;;
        windows-64-bit)
            HOST="x86_64-w64-mingw32"
            PACKAGES="nsis g++-mingw-w64-x86-64 build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git"
            POSTINSTALL="update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix && update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix"
            CONFIG_OPTS="--enable-sse2 LDFLAGS=-static-libgcc"
            ;;
        macos-64-bit)
            HOST="x86_64-apple-darwin"
            PACKAGES="curl bsdmainutils cmake libz-dev python3-setuptools libtinfo5 xorriso zip"
            CONFIG_OPTS="--enable-sse2"
            GOAL="deploy"
            SDK="12.2-12B45b"
            ;;
        linux-arm-64-bit)
            HOST="aarch64-linux-gnu"
            PACKAGES="g++-aarch64-linux-gnu binutils-aarch64-linux-gnu"
            CONFIG_OPTS="--enable-glibc-back-compat LDFLAGS=-static-libstdc++"
            ;;
        *)
            echo "unknown target: $target" >&2
            exit 2
            ;;
    esac
}

scan_warnings() {
    local target="$1"
    local log_file="$2"
    local warnings_file="$WORK_ROOT/logs/$target.warnings"

    grep -nE \
        '(^|[[:space:]])(warning:|Warning:|WARNING:|ld: warning|clang: warning|gcc: warning|warning C[0-9]+|[-[:alnum:]_./]+:[0-9]+:[0-9]+: warning:)' \
        "$log_file" \
        > "$warnings_file.tmp" || true
    grep -nE "ar: .*modifier ignored|command not found|No package '.*' found|Package .* was not found in the pkg-config search path|Perhaps you should add the directory containing" "$log_file" >> "$warnings_file.tmp" || true
    # Keep the warning audit focused on this project's code and link graph.
    # The depends build deliberately compiles pinned third-party sources; their
    # compiler/autotools/libtool chatter is not actionable in Blackcoin source
    # and differs by distro toolchain version.
    grep -vE 'apt-key|debconf: delaying package configuration|WARNING: apt does not have a stable CLI interface|sha256sum: WARNING: [0-9]+ computed checksum|computed checksum did NOT match|update-alternatives: warning: skip creation of|libtool: (install: )?warning: (remember to run|relinking)|configure: WARNING: (dot|doxygen) not found - .*(doxygen|documentation) targets will be skipped|WARNING: QDoc will not be compiled|WARNING: Failure to find: .*/qt5(core|gui|widgets)_metatypes\.json|(\.\./3rdparty/md4c/md4c\.c|access/qnetworkaccessmanager\.cpp|/usr/include/.*/bits/string_fortified\.h|../../include/QtCore/.*/qdatastream\.h):.*warning:|(icccm|ewmh)\.c:[0-9]+:[0-9]+: warning: ISO C90 forbids mixed declarations and code|(\.\./dist/.*db_err\.c|\./db_int\.h):[0-9]+:[0-9]+: warning: .*-Wformat-truncation|configure\.ac:[0-9]+: warning: (The macro `AC_|AC_LIBTOOL_WIN32_DLL)|configure: WARNING: xgettext is required to update qt translations|Package xorg-macros was not found in the pkg-config search path|Perhaps you should add the directory containing `xorg-macros\.pc|No package '\''xorg-macros'\'' found|ar: `u'\'' modifier ignored since `D'\'' is the default' \
        "$warnings_file.tmp" \
        > "$warnings_file" || true
    rm -f "$warnings_file.tmp"

    if [[ -s "$warnings_file" ]]; then
        echo "==> Warnings found for $target; see $warnings_file"
        sed -n '1,120p' "$warnings_file"
        if [[ "$FAIL_ON_WARNINGS" -eq 1 ]]; then
            echo "warning audit failed for $target" >&2
            return 1
        fi
    else
        echo "==> No compiler/linker warnings found for $target"
        rm -f "$warnings_file"
    fi
}

run_target() {
    local target="$1"
    target_vars "$target"

    local archive_dir="$WORK_ROOT/archives"
    local log_dir="$WORK_ROOT/logs"
    local cache_dir="$WORK_ROOT/depends-cache/$target"
    local archive_file="$archive_dir/$target.tar"
    mkdir -p "$archive_dir" "$log_dir" "$cache_dir/built" "$cache_dir/sdk-sources"
    if [[ "$KEEP_WORK" -eq 0 ]]; then
        rm -f "$archive_file" "$log_dir/$target.config.log"
    fi

    echo "==> Preparing clean HEAD archive for $target"
    git -C "$ROOT_DIR" archive --format=tar HEAD > "$archive_file"

    if [[ "$WERROR" -eq 1 ]]; then
        CONFIG_OPTS="$CONFIG_OPTS --enable-werror"
    fi

    echo "==> Running $target in Ubuntu 22.04 Docker"
    docker run --rm --platform linux/amd64 \
        -e DEBIAN_FRONTEND=noninteractive \
        -e MAKEJOBS="$MAKEJOBS" \
        -e HOST="$HOST" \
        -e PACKAGES="$PACKAGES" \
        -e POSTINSTALL="$POSTINSTALL" \
        -e SDK="$SDK" \
        -e DEP_OPTS="$DEP_OPTS" \
        -e CONFIG_OPTS="$CONFIG_OPTS" \
        -e GOAL="$GOAL" \
        -e TARGET="$target" \
        -e KEEP_WORK="$KEEP_WORK" \
        -e SDK_URL="https://bitcoincore.org/depends-sources/sdks" \
        -v "$archive_file:/input/source.tar:ro" \
        -v "$log_dir:/out" \
        -v "$cache_dir:/depends-cache" \
        -w /work \
        ubuntu:22.04 \
        bash -euxo pipefail -c '
            save_debug() {
                local status="$?"
                if [[ "$status" -ne 0 ]]; then
                    cp /work/config.log "/out/$TARGET.config.log" 2>/dev/null || true
                fi
                if [[ "$KEEP_WORK" -eq 1 ]]; then
                    tar -czf "/out/$TARGET-work.tar.gz" -C /work . 2>/dev/null || true
                fi
                exit "$status"
            }
            trap save_debug EXIT

            tar -xf /input/source.tar -C /work

            apt-get update
            apt-get install -y --no-install-recommends \
                ca-certificates make automake cmake curl g++ libtool gperf \
                binutils-gold bsdmainutils pkg-config python3 patch bison git lbzip2 xz-utils libxml2-utils \
                gettext xutils-dev \
                $PACKAGES
            if command -v pkg-config >/dev/null && ! command -v "$HOST-pkg-config" >/dev/null; then
                ln -s "$(command -v pkg-config)" "/usr/local/bin/$HOST-pkg-config"
            fi

            if [[ -n "$POSTINSTALL" ]]; then
                eval "$POSTINSTALL"
            fi

            if [[ -n "$SDK" ]]; then
                mkdir -p /depends-cache/sdk-sources depends/SDKs
                sdk_file="/depends-cache/sdk-sources/Xcode-$SDK-extracted-SDK-with-libcxx-headers.tar.gz"
                if [[ ! -f "$sdk_file" ]]; then
                    curl --location --fail "$SDK_URL/Xcode-$SDK-extracted-SDK-with-libcxx-headers.tar.gz" \
                        -o "$sdk_file"
                fi
                tar -C depends/SDKs -xzf "$sdk_file"
            fi

            make -j "$MAKEJOBS" -C depends HOST="$HOST" \
                BASE_CACHE=/depends-cache/built \
                $DEP_OPTS
            ./autogen.sh
            ./configure --prefix="$(pwd)/depends/$HOST" $CONFIG_OPTS --enable-reduce-exports || { cat config.log; exit 1; }
            make -j "$MAKEJOBS" "$GOAL" || { echo "Build failure. Verbose build follows."; make "$GOAL" V=1; exit 1; }
        ' 2>&1 | tee "$log_dir/$target.log"

    scan_warnings "$target" "$log_dir/$target.log"

    if [[ "$KEEP_WORK" -eq 0 ]]; then
        rm -f "$archive_file"
    fi
}

for target in "${TARGETS[@]}"; do
    run_target "$target"
done

echo "Local build matrix completed successfully."
