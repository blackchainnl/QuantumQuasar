#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: contrib/devtools/open-gui-preview.sh [--reset] [--print-command] [--direct] [--datadir PATH] [--binary PATH] [-- extra qt args...]

Launch the Blackcoin Qt wallet in an isolated offline regtest preview
environment. This is intended for GUI layout/performance review only.

Options:
  --reset          Delete the preview datadir before launching.
  --print-command  Print the command that would be run, then exit.
  --direct         Run the Qt binary directly instead of macOS Launch Services.
  --datadir PATH   Override the preview datadir.
  --binary PATH    Override the Qt binary path.

The launcher always passes regtest/offline flags:
  -regtest -listen=0 -connect=0 -dnsseed=0 -fixedseeds=0
  -upnp=0 -natpmp=0 -listenonion=0 -i2pacceptincoming=0 -discover=0
  -networkactive=0
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

binary="${repo_root}/src/qt/blackcoin-qt"
datadir="${BLACKCOIN_GUI_PREVIEW_DATADIR:-${HOME}/Library/Application Support/Blackcoin-GUI-Preview-Regtest}"
reset=0
print_command=0
direct=0
passthrough=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --reset)
            reset=1
            shift
            ;;
        --print-command)
            print_command=1
            shift
            ;;
        --direct)
            direct=1
            shift
            ;;
        --datadir)
            datadir="$2"
            shift 2
            ;;
        --binary)
            binary="$2"
            shift 2
            ;;
        --)
            shift
            passthrough+=("$@")
            break
            ;;
        *)
            passthrough+=("$1")
            shift
            ;;
    esac
done

if [[ ! -x "${binary}" ]]; then
    echo "Qt binary not found or not executable: ${binary}" >&2
    echo "Build it with: make -C src -j8 qt/blackcoin-qt" >&2
    exit 1
fi

if [[ "${reset}" -eq 1 ]]; then
    case "${datadir}" in
        "${HOME}/Library/Application Support/Blackcoin-GUI-Preview-Regtest"|/tmp/blackcoin-gui-preview*)
            rm -rf "${datadir}"
            ;;
        *)
            echo "Refusing --reset for non-default datadir: ${datadir}" >&2
            exit 1
            ;;
    esac
fi

mkdir -p "${datadir}"
cat > "${datadir}/blackcoin.conf" <<'EOF'
# Offline GUI preview only. Do not use this as a real wallet datadir.
regtest=1
listen=0
connect=0
dnsseed=0
fixedseeds=0
upnp=0
natpmp=0
listenonion=0
i2pacceptincoming=0
discover=0
server=0

[regtest]
listen=0
connect=0
dnsseed=0
fixedseeds=0
server=0
EOF

cmd=(
    "${binary}"
    -regtest
    "-datadir=${datadir}"
    -choosedatadir=0
    -listen=0
    -connect=0
    -dnsseed=0
    -fixedseeds=0
    -upnp=0
    -natpmp=0
    -listenonion=0
    -i2pacceptincoming=0
    -discover=0
    -networkactive=0
    -server=0
    -debug=qt
)

args=("${cmd[@]:1}")

if ((${#passthrough[@]} > 0)); then
    cmd+=("${passthrough[@]}")
fi

printf 'Preview datadir: %s\n' "${datadir}"
printf 'Network mode: regtest, offline, no peers, no listening sockets\n'

if [[ "${print_command}" -eq 1 ]]; then
    printf 'Command:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
    exit 0
fi

if [[ "$(uname -s)" == "Darwin" && "${direct}" -eq 0 ]]; then
    app="${datadir}/Blackcoin GUI Preview.app"
    macos_dir="${app}/Contents/MacOS"
    mkdir -p "${macos_dir}"
    rm -f "${macos_dir}/blackcoin-qt" "${macos_dir}/launcher"
    ln -s "${binary}" "${macos_dir}/blackcoin-qt"
    cat > "${app}/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>blackcoin-qt</string>
    <key>CFBundleIdentifier</key>
    <string>org.blackcoin.blackcoin.preview</string>
    <key>CFBundleName</key>
    <string>Blackcoin GUI Preview</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
EOF

    open -n "${app}" --args "${args[@]}"
    exit 0
fi

exec "${cmd[@]}"
