#!/bin/sh
# Tenzro installer for Linux and macOS (x86_64 and arm64). POSIX sh.
#
#   curl -fsSL https://downloads.tenzro.com/install.sh | sh
#   curl -fsSL https://downloads.tenzro.com/install.sh | sh -s -- --dry-run
#
# What it does, in this order, and stops at the first failure:
#   1. picks the archive for this machine from the release's SHA256SUMS
#   2. verifies SHA256SUMS.sig against the release key embedded below (ECDSA
#      P-256, checked against the published fingerprint) with openssl
#   3. verifies the archive's SHA-256 against that signed list
#   4. unpacks to PREFIX/install/versions/, runs the binary's own hardware
#      self-check and, on Linux, the archive's install gate in dry-run
#   5. links tenzro and tenzro-node into BIN_DIR (default ~/.local/bin)
# Nothing is installed unless 2 and 3 pass. No sudo. No shell file is edited
# unless you say yes (or pass --modify-path).
#
# This script itself is covered by TLS only. Its SHA-256 is published beside it
# (install.sh.sha256). To avoid trusting it, follow the manual steps in
# docs/VERIFY-DOWNLOAD.md.
#
# Options:
#   --version V        refuse unless the release's CLI reports version V
#   --prefix DIR       install under DIR/install (default ~/.tenzro)
#   --bin-dir DIR      where the tenzro and tenzro-node links go (default ~/.local/bin)
#   --target NAME      archive to take, e.g. tenzro-node-linux-x86_64-cpu (default: detected)
#   --from DIR         offline: DIR holds SHA256SUMS, SHA256SUMS.sig and the archive
#   --base-url URL     download site (default https://downloads.tenzro.com)
#   --dry-run          detect, fetch and verify the signed list, change nothing
#   --uninstall        remove what this script installed (keeps ~/.tenzro data)
#   --modify-path      add BIN_DIR to your shell profile without asking
#   --no-modify-path   never touch a shell profile, never ask
#   -h, --help         this text
set -eu

BASE="${TENZRO_DOWNLOAD_BASE:-https://downloads.tenzro.com}"
KEY_FPR="c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d"
PUBKEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3/NYEWx6w1OdV23xU656MhkpzxNM
PAP5jhmCYs7mWBx/W6lVL7cgwsTRlzcNq8iMIyU2lPMsmGNC7nZkxpaTZA==
-----END PUBLIC KEY-----'
MARK_BEGIN="# >>> tenzro >>>"
MARK_END="# <<< tenzro <<<"

# ---------------------------------------------------------------- output
c_acc="" c_dim="" c_bld="" c_off="" e_acc="" e_off=""
if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    if [ -t 1 ]; then c_acc=$(printf '\033[38;5;110m'); c_dim=$(printf '\033[2m'); c_bld=$(printf '\033[1m'); c_off=$(printf '\033[0m'); fi
    if [ -t 2 ]; then e_acc=$(printf '\033[38;5;110m'); e_off=$(printf '\033[0m'); fi
fi
row() { printf '  %s%-11s%s %s\n' "$c_dim" "$1" "$c_off" "$2"; }
say() { printf '%s\n' "$*"; }
note() { printf '  %s\n' "$*" >&2; }
# fail WHAT WHY FIX: every error says what happened, why, and what to do.
fail() {
    printf '\n%serror:%s %s\n' "$e_acc" "$e_off" "$1" >&2
    [ -n "${2:-}" ] && printf '  why:  %s\n' "$2" >&2
    [ -n "${3:-}" ] && printf '  fix:  %s\n' "$3" >&2
    printf '  Nothing was installed or changed on this machine.\n\n' >&2
    exit 1
}

# ---------------------------------------------------------------- arguments
WANT_VERSION="" PREFIX="${TENZRO_HOME:-}" BIN_DIR="${TENZRO_BIN_DIR:-}" TARGET="" FROM="" DRY=0 UNINSTALL=0 PATHMODE=ask
while [ $# -gt 0 ]; do
    case "$1" in
        --version) WANT_VERSION="${2:-}"; shift ;;
        --prefix) PREFIX="${2:-}"; shift ;;
        --bin-dir) BIN_DIR="${2:-}"; shift ;;
        --target) TARGET="${2:-}"; shift ;;
        --from) FROM="${2:-}"; shift ;;
        --base-url) BASE="${2:-}"; shift ;;
        --dry-run) DRY=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --modify-path) PATHMODE=yes ;;
        --no-modify-path) PATHMODE=no ;;
        -h|--help) sed -n '2,36p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown option: $1" "" "run with --help to see the options" ;;
    esac
    [ $# -gt 0 ] && shift
done
[ -n "${HOME:-}" ] || fail "HOME is not set" "the install location is under your home directory" "set HOME, or pass --prefix and --bin-dir"
[ -n "$PREFIX" ] || PREFIX="$HOME/.tenzro"
[ -n "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
INST="$PREFIX/install"
BASE="${BASE%/}"
T0=$(date +%s)

# ---------------------------------------------------------------- PATH profile
profile_file() {
    case "${SHELL:-}" in
        */zsh) echo "$HOME/.zshrc" ;;
        */bash) if [ "$(uname -s)" = Darwin ]; then echo "$HOME/.bash_profile"; else echo "$HOME/.bashrc"; fi ;;
        *) echo "$HOME/.profile" ;;
    esac
}
on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; esac; return 1; }
strip_block() { # strip_block FILE: remove our marked block, keep the rest byte for byte
    [ -f "$1" ] && grep -qF "$MARK_BEGIN" "$1" || return 0
    t=$(mktemp "${TMPDIR:-/tmp}/tenzro-rc.XXXXXX") || return 0
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip{print}' "$1" > "$t" && cat "$t" > "$1"
    rm -f "$t"
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
    removed=0
    for t in tenzro tenzro-node; do
        l="$BIN_DIR/$t"
        if [ -L "$l" ]; then
            case "$(readlink "$l")" in "$INST"/*) rm -f "$l"; row removed "$l"; removed=1 ;; esac
        fi
    done
    if [ -d "$INST" ]; then rm -rf "$INST"; row removed "$INST"; removed=1; fi
    for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
        if [ -f "$f" ] && grep -qF "$MARK_BEGIN" "$f"; then strip_block "$f"; row cleaned "$f"; removed=1; fi
    done
    rmdir "$PREFIX" 2>/dev/null || true
    [ "$removed" = 1 ] || say "Nothing to remove: no Tenzro install found under $PREFIX."
    [ -d "$PREFIX" ] && say "Left in place: $PREFIX (settings and any node data). Delete it yourself if you want it gone."
    exit 0
fi

# ---------------------------------------------------------------- tools
have() { command -v "$1" >/dev/null 2>&1; }
have openssl || fail "openssl was not found" "the download is verified with openssl, and the installer will not continue without checking it" "install it (Debian/Ubuntu: apt-get install openssl; Fedora: dnf install openssl; macOS ships it) and run this again"
have tar || fail "tar was not found" "the release is a .tar.gz archive" "install tar and run this again"
if [ -z "$FROM" ]; then
    have curl || have wget || fail "neither curl nor wget was found" "the installer has to download the release" "install curl (Debian/Ubuntu: apt-get install curl ca-certificates) and run this again"
fi
sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
    else openssl dgst -sha256 -r "$1" | awk '{print $1}'; fi
}

# fetch NAME DEST [progress]: download from BASE, or copy from --from DIR.
fetch() {
    if [ -n "$FROM" ]; then
        [ -f "$FROM/$1" ] || fail "$FROM/$1 is missing" "--from needs the archive, SHA256SUMS and SHA256SUMS.sig in one folder" "download them from $BASE and try again"
        cp "$FROM/$1" "$2"; return 0
    fi
    rc=0
    if have curl; then
        if [ "${3:-}" = progress ] && [ -t 2 ]; then curl -fL --retry 2 --connect-timeout 15 -# -o "$2" "$BASE/$1" || rc=$?
        else curl -fsSL --retry 2 --connect-timeout 15 -o "$2" "$BASE/$1" || rc=$?; fi
    else
        wget -q -O "$2" "$BASE/$1" || rc=$?
    fi
    [ "$rc" = 0 ] && return 0
    why="the request for $BASE/$1 failed (exit $rc)"
    case "$rc" in
        6) why="the name ${BASE#*://} could not be looked up, so this machine has no working DNS or no internet" ;;
        7) why="the connection to $BASE was refused or unreachable" ;;
        22|8) why="the server answered with an error for $BASE/$1 (the file may not exist)" ;;
        28) why="the connection to $BASE timed out" ;;
        35|51|58|60|77) why="the TLS connection to $BASE could not be verified" ;;
    esac
    fail "could not download $1" "$why" "check your connection and run this again. Offline: download the archive, SHA256SUMS and SHA256SUMS.sig on another machine and run: sh install.sh --from <folder>"
}

# ---------------------------------------------------------------- this machine
OS=$(uname -s) ARCH=$(uname -m)
case "$OS" in
    Linux) OSN=linux ;;
    Darwin) OSN=macos ;;
    MINGW*|MSYS*|CYGWIN*) fail "this is Windows" "install.sh is for Linux and macOS" "in PowerShell run: irm https://downloads.tenzro.com/install.ps1 | iex" ;;
    *) fail "unsupported system: $OS" "Tenzro publishes Linux, macOS and Windows builds" "see $BASE for the list" ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCHN=x86_64 ;;
    aarch64|arm64) ARCHN=aarch64 ;;
    *) fail "unsupported CPU: $ARCH" "Tenzro publishes x86_64 and arm64 builds" "see $BASE for the list" ;;
esac
# A terminal running under Rosetta reports x86_64 on an Apple silicon Mac.
if [ "$OSN" = macos ] && [ "$ARCHN" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then ARCHN=aarch64; fi

GPU=none
ORIN=0
if [ "$OSN" = linux ]; then
    if { have nvidia-smi && nvidia-smi -L 2>/dev/null | grep -q '^GPU '; } || [ -e /proc/driver/nvidia/version ]; then GPU=nvidia; fi
    if have ldd && ldd --version 2>&1 | grep -qi musl; then
        fail "this Linux uses musl libc (Alpine, for example)" "the published Linux builds need glibc" "use a glibc distribution (Debian, Ubuntu, Fedora) or run Tenzro in a container based on one"
    fi
    LIBC=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
    ORIN=0; [ "$ARCHN" = aarch64 ] && detect_orin "${TENZRO_FS_ROOT:-}" && ORIN=1
    # A Jetson reaches its GPU through the Tegra driver: no nvidia-smi, no /proc/driver/nvidia.
    [ "$ORIN" = 1 ] && GPU=nvidia
elif [ "$ARCHN" = aarch64 ]; then GPU=metal
fi
HAS_TPM=unknown
if [ "$OSN" = linux ]; then if [ -e /dev/tpmrm0 ]; then HAS_TPM=yes; else HAS_TPM=no; fi
elif [ "$ARCHN" = aarch64 ]; then HAS_TPM=secure-enclave; fi

# pick_pref OS ARCH GPU LIBC ORIN: the build kinds to try, best first, on a machine of this kind.
# On aarch64 Linux the Ubuntu 24.04 builds need glibc 2.39; an older glibc (Raspberry Pi OS or Debian 12 Bookworm,
# 2.36) takes the Bookworm CPU build, which is the only one built against glibc 2.36. A Jetson Orin (ORIN=1)
# takes the Orin CUDA build first, since the general CUDA build carries no sm_87 ONNX Runtime kernels.
# pick_pref begin
detect_orin() {
    for f in "$1/proc/device-tree/compatible" "$1/sys/firmware/devicetree/base/compatible"; do
        [ -r "$f" ] && tr '\0' '\n' < "$f" 2>/dev/null | grep -qx 'nvidia,tegra234' && return 0
    done
    return 1
}
pick_pref() {
    if [ "$1" = linux ] && [ "$3" = nvidia ]; then pp="cuda vulkan cpu"; else pp="cpu metal edge"; fi
    if [ "$1" = linux ] && [ "$2" = aarch64 ]; then
        if [ "$3" = nvidia ] && [ "$5" = 1 ]; then pp="cuda-orin $pp"; fi
        if [ -n "$4" ] && [ "$(printf '%s\n%s\n' 2.39 "$4" | sort -V | head -1)" != 2.39 ]; then pp="cpu-bookworm"; fi
    fi
    echo "$pp"
}
# pick_pref end

# ---------------------------------------------------------------- the signed list
WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; rmdir "$INST/versions" "$INST" "$PREFIX" 2>/dev/null || true; return 0; }
trap cleanup EXIT INT TERM HUP
if [ "$DRY" = 1 ]; then WORK=$(mktemp -d "${TMPDIR:-/tmp}/tenzro-install.XXXXXX")
else mkdir -p "$INST" 2>/dev/null || fail "cannot create $INST" "no permission, or the disk is full" "pass --prefix with a folder you can write to"; WORK=$(mktemp -d "$INST/.work.XXXXXX"); fi

say ""
say "${c_bld}Installing Tenzro${c_off}"
say ""
row machine "$OSN $ARCHN$( [ -n "${LIBC:-}" ] && echo ", glibc $LIBC" ), $( [ "$GPU" = nvidia ] && echo 'NVIDIA GPU' || { [ "$GPU" = metal ] && echo 'Apple silicon' || echo 'no GPU'; } )"

fetch SHA256SUMS "$WORK/SHA256SUMS"
fetch SHA256SUMS.sig "$WORK/SHA256SUMS.sig"
printf '%s\n' "$PUBKEY" > "$WORK/key.pub"
fpr=$(openssl pkey -pubin -in "$WORK/key.pub" -outform DER 2>/dev/null | { if have sha256sum; then sha256sum; elif have shasum; then shasum -a 256; else openssl dgst -sha256 -r; fi; } | awk '{print $1}')
[ "$fpr" = "$KEY_FPR" ] || fail "the release key inside this script is not the published one" "its fingerprint is ${fpr:-unreadable}, expected $KEY_FPR" "download install.sh again from https://downloads.tenzro.com/install.sh; if that does not help, stop and ask"
openssl base64 -d -A -in "$WORK/SHA256SUMS.sig" -out "$WORK/sig.der" 2>/dev/null || fail "SHA256SUMS.sig is not a valid signature file" "it is not base64" "download again; if it keeps failing the release is damaged, stop and ask"
if ! openssl dgst -sha256 -verify "$WORK/key.pub" -signature "$WORK/sig.der" "$WORK/SHA256SUMS" >/dev/null 2>&1; then
    fail "the signature on SHA256SUMS does not verify" "the list of release hashes was not signed by the Tenzro release key (damaged download, or something is altering it in transit)" "do not install from this source. Try again from another network, or follow docs/VERIFY-DOWNLOAD.md"
fi
row signature "verified, release key ${KEY_FPR%"${KEY_FPR#????????}"}"

# pick the archive
names=$(awk '{n=$2; sub(/^\*/,"",n); print n}' "$WORK/SHA256SUMS")
if [ -n "$TARGET" ]; then
    NAME="${TARGET%.tar.gz}"
    echo "$names" | grep -qx "$NAME.tar.gz" || fail "$NAME is not in this release" "the signed list holds: $(echo "$names" | tr '\n' ' ')" "pick one of those with --target"
else
    cands=$(echo "$names" | grep "^tenzro-node-$OSN-$ARCHN-.*\.tar\.gz$" | sed 's/\.tar\.gz$//' || true)
    NAME=""
    pref=$(pick_pref "$OSN" "$ARCHN" "$GPU" "${LIBC:-}" "$ORIN")
    for p in $pref; do
        if echo "$cands" | grep -qx "tenzro-node-$OSN-$ARCHN-$p"; then NAME="tenzro-node-$OSN-$ARCHN-$p"; break; fi
    done
    if [ -z "$NAME" ] && [ "$pref" = cpu-bookworm ]; then
        fail "no build in this release fits glibc $LIBC on aarch64" "the aarch64 builds need glibc 2.39 (Ubuntu 24.04, Debian 13, Raspberry Pi OS Trixie) and this release publishes no Debian 12 build; this machine has glibc $LIBC" "use Raspberry Pi OS Trixie, Ubuntu 24.04 or newer, or a container based on one"
    fi
    if [ -z "$NAME" ]; then
        if [ -n "$cands" ]; then
            fail "this release has no build that fits this machine" "for $OSN $ARCHN it publishes only: $(echo "$cands" | sed 's/^tenzro-node-//' | tr '\n' ' ') and that needs hardware this machine does not report (an NVIDIA GPU)" "use a machine with the matching GPU, build from source (README, Build from Source), or ask for a CPU build of this platform"
        fi
        fail "this release has no build for $OSN $ARCHN" "the signed list holds: $(echo "$names" | sed 's/^tenzro-node-//; s/\.\(tar\.gz\|zip\)$//' | tr '\n' ' ')" "use a supported machine, or build from source (README, Build from Source)"
    fi
fi
WANT=$(awk -v f="$NAME.tar.gz" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' "$WORK/SHA256SUMS")
[ -n "$WANT" ] || fail "$NAME.tar.gz is not listed in the signed SHA256SUMS" "" "pick a listed archive with --target"
row build "$NAME"
if [ "$OSN" = linux ] && [ "$GPU" = nvidia ] && [ "${NAME##*-}" = cpu ]; then
    note "note: an NVIDIA GPU is present, but this release's $ARCHN Linux build is CPU-only; it runs, the GPU is not used."
fi

# glibc floor, from matrix.json when it is reachable. Advisory: matrix.json is not signed.
if [ "$OSN" = linux ] && [ -n "${LIBC:-}" ] && [ -z "$FROM" ]; then
    if fetch matrix.json "$WORK/matrix.json" 2>/dev/null; then
        floor=$(awk -v a="$NAME" '$0 ~ "\"artifact\": \""a"\""{f=1} f && /glibc_floor/{gsub(/[^0-9.]/,"",$0); print; exit}' "$WORK/matrix.json" 2>/dev/null || true)
        if [ -n "$floor" ] && [ "$(printf '%s\n%s\n' "$floor" "$LIBC" | sort -V | head -1)" != "$floor" ]; then
            fail "this system's glibc is too old" "$NAME needs glibc $floor or newer and this machine has $LIBC" "use Ubuntu 24.04 or newer, Debian 13 or newer, Fedora 40 or newer, or a container based on one"
        fi
    fi
fi

if [ "$DRY" = 1 ]; then
    row install "would go to $INST/versions/$NAME-${WANT%"${WANT#????????????}"} and link into $BIN_DIR"
    say ""; say "Dry run: the signed list verified; the archive was not downloaded and nothing was changed."; say ""
    exit 0
fi

# ---------------------------------------------------------------- the archive
VDIR="$INST/versions/$NAME-${WANT%"${WANT#????????????}"}"
if [ -d "$VDIR/bin" ]; then
    row archive "already installed, nothing to download"
    CLIV=$("$VDIR/bin/tenzro" --version 2>/dev/null | awk '{print $NF}')
    [ -n "$CLIV" ] || CLIV="(unknown version)"
else
    say "  ${c_dim}downloading $NAME.tar.gz${c_off}"
    fetch "$NAME.tar.gz" "$WORK/a.tar.gz" progress
    GOT=$(sha256_of "$WORK/a.tar.gz")
    [ "$GOT" = "$WANT" ] || fail "the archive does not match the signed list" "$NAME.tar.gz hashes to $GOT; the signed SHA256SUMS lists $WANT (truncated or altered download)" "the file was discarded. Run this again; if it repeats, stop and ask"
    row checksum "verified, sha256 ${WANT%"${WANT#????????????}"}"
    if tar -tzf "$WORK/a.tar.gz" 2>/dev/null | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
        fail "the archive has unsafe paths" "an entry would be written outside the install folder" "do not use it; stop and ask"
    fi
    mkdir "$WORK/x"
    tar -xzf "$WORK/a.tar.gz" -C "$WORK/x" 2>/dev/null || fail "the archive could not be unpacked" "tar failed (the disk may be full)" "free some space under $PREFIX and run this again"
    rm -f "$WORK/a.tar.gz"
    [ -x "$WORK/x/$NAME/bin/tenzro" ] && [ -x "$WORK/x/$NAME/bin/tenzro-node" ] || fail "the archive does not contain bin/tenzro and bin/tenzro-node" "unexpected layout" "stop and ask"

    X="$WORK/x/$NAME"
    # Never run a file that is not an executable for this system: a shell would try to read it as a script.
    for b in tenzro tenzro-node; do
        magic=$(dd if="$X/bin/$b" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
        case "$OSN:$magic" in
            linux:7f454c46|macos:cffaedfe|macos:cafebabe) ;;
            *) fail "this build is not for this system" "$NAME/bin/$b is not a $OS executable" "use a build for $OSN $ARCHN (omit --target to let the installer choose)" ;;
        esac
        if [ "$OSN" = linux ]; then
            em=$(dd if="$X/bin/$b" bs=1 skip=18 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
            case "$ARCHN:$em" in x86_64:3e00|aarch64:b700) ;;
                *) fail "this build is for another CPU" "$NAME/bin/$b is not a $ARCHN executable" "use a build for $OSN $ARCHN (omit --target to let the installer choose)" ;;
            esac
        fi
    done
    out=$("$X/bin/tenzro" --version 2>&1) && rc=0 || rc=$?
    if [ "$rc" != 0 ]; then
        case "$out" in
            *GLIBC_*) fail "the binary needs a newer glibc than this system has" "$(echo "$out" | head -1)" "use Ubuntu 24.04 or newer, Debian 13 or newer, Fedora 40 or newer, or a container based on one" ;;
            *) fail "the downloaded binary does not run on this machine" "$(echo "$out" | head -1)" "check that this is the right CPU and operating system; use --target to choose another build" ;;
        esac
    fi
    CLIV=$(echo "$out" | awk '{print $NF}')
    if [ -n "$WANT_VERSION" ] && [ "$CLIV" != "$WANT_VERSION" ]; then
        fail "this release is version $CLIV, you asked for $WANT_VERSION" "downloads.tenzro.com serves the current release only" "install without --version, or fetch the archive of $WANT_VERSION yourself and use --from"
    fi
    hw=$("$X/bin/tenzro-node" hardware 2>/dev/null) && hrc=0 || hrc=$?
    hb=$(echo "$hw" | sed -n 's/^build: //p' | head -1); hg=$(echo "$hw" | sed -n 's/^gpus: //p' | head -1); hs=$(echo "$hw" | sed -n 's/^startup: //p' | head -1)
    if [ "$hrc" = 0 ] && [ "$hs" = ok ]; then
        row self-check "build $hb, $hg GPU(s), startup ok"
    elif [ "$OSN" = linux ]; then
        fail "the node would not start on this machine" "its own hardware check said: $(echo "$hw" | tr '\n' ' ')" "run \`$X/bin/tenzro-node hardware\` for detail"
    else
        note "note: the hardware self-check did not finish ($(echo "$hw" | tr '\n' ' ')); the CLI is installed anyway."
    fi
    # The archive's own install gate (Linux), in dry-run, when its tools are present.
    if [ "$OSN" = linux ] && [ -f "$X/tenzro-node-install" ]; then
        role=cpu; case "${NAME##*-}" in cuda|vulkan) role=gpu ;; edge) role=edge ;; esac
        if have bash && have file && have readelf; then
            if g=$(bash "$X/tenzro-node-install" --dry-run --role "$role" "$X" 2>&1); then row gate "accepted for the $role role"
            else fail "the install gate refused this build" "$(echo "$g" | grep REFUSED | head -2 | tr '\n' ' ')" "choose another build with --target, or stop and ask"; fi
        else
            row gate "skipped (needs bash, file and binutils: apt-get install file binutils)"
        fi
    fi
    mkdir -p "$INST/versions"
    mv "$X" "$VDIR"
    row install "$VDIR"
fi

# ---------------------------------------------------------------- links
ln -sfn "versions/$(basename "$VDIR")" "$INST/current"
mkdir -p "$BIN_DIR" 2>/dev/null || fail "cannot create $BIN_DIR" "no permission" "pass --bin-dir with a folder you can write to"
for t in tenzro tenzro-node; do
    l="$BIN_DIR/$t"
    if [ -e "$l" ] || [ -L "$l" ]; then
        if [ -L "$l" ]; then case "$(readlink "$l")" in "$INST"/*) ;; *) fail "$l already points somewhere else ($(readlink "$l"))" "it was not made by this installer, so it was not replaced" "remove it yourself, or use --bin-dir" ;; esac
        else fail "$l already exists and is not a link" "it was not made by this installer, so it was not replaced" "move it away, or use --bin-dir"; fi
    fi
    ln -sfn "$INST/current/bin/$t" "$l"
done
row linked "$BIN_DIR/tenzro, $BIN_DIR/tenzro-node"
# keep this and the previous version only
( cd "$INST/versions" && ls -t | tail -n +3 | while read -r old; do [ "$old" != "$(basename "$VDIR")" ] && rm -rf "./$old"; done ) 2>/dev/null || true

# ---------------------------------------------------------------- PATH
NEED_SOURCE=0
if ! on_path "$BIN_DIR"; then
    rcf=$(profile_file)
    line="export PATH=\"$BIN_DIR:\$PATH\""
    do_it=0
    case "$PATHMODE" in
        yes) do_it=1 ;;
        ask)
            if [ -t 1 ] && ( : </dev/tty ) 2>/dev/null; then
                printf '\n  %s is not on your PATH. Add it to %s? [Y/n] ' "$BIN_DIR" "$rcf" >/dev/tty
                read -r ans </dev/tty || ans=n
                case "$ans" in ""|y|Y|yes|YES) do_it=1 ;; esac
            fi ;;
    esac
    if [ "$do_it" = 1 ]; then
        strip_block "$rcf"
        { printf '\n%s\n%s\n%s\n' "$MARK_BEGIN" "$line" "$MARK_END"; } >> "$rcf"
        row path "added to $rcf (open a new terminal, or run: . $rcf)"
        NEED_SOURCE=1
    else
        row path "$BIN_DIR is not on your PATH"
        NEED_SOURCE=2
    fi
fi
if have tenzro && [ "$(command -v tenzro)" != "$BIN_DIR/tenzro" ] && on_path "$BIN_DIR"; then
    note "note: another tenzro at $(command -v tenzro) comes first on your PATH; use $BIN_DIR/tenzro or remove the other."
fi

# ---------------------------------------------------------------- welcome
say ""
say "${c_bld}Tenzro $CLIV is installed${c_off} (${c_dim}$(( $(date +%s) - T0 ))s${c_off})"
say ""
case $NEED_SOURCE in
    2) say "Add it to this terminal, then start:"; say ""; say "    ${c_acc}export PATH=\"$BIN_DIR:\$PATH\" && tenzro${c_off}" ;;
    1) say "Open a new terminal, or run \`. $(profile_file)\`, then start:"; say ""; say "    ${c_acc}tenzro${c_off}" ;;
    *) say "Open a terminal and run:"; say ""; say "    ${c_acc}tenzro${c_off}" ;;
esac
say ""
say "${c_dim}The first time, it takes you through setup; after that it opens the console. \`tenzro --help\` lists everything.${c_off}"
case "$HAS_TPM" in
    no) say "${c_dim}This machine has no TPM 2.0: you can still use the CLI and join with a passkey. Running a node or \`tenzro dev\` needs a TPM 2.0, or a Mac with a Secure Enclave.${c_off}" ;;
esac
if [ -z "$FROM" ] && have curl && ! curl -s -m 4 -o /dev/null https://rpc.tenzro.com 2>/dev/null; then
    say "${c_dim}The public network (rpc.tenzro.com) is not reachable from here right now, so commands that talk to it will say so. Local use does not need it.${c_off}"
fi
say ""
say "${c_dim}Update: run this installer again. Remove: sh install.sh --uninstall${c_off}"
say ""
exit 0
