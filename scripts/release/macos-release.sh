#!/bin/bash
# The Apple side of the macOS release in one place.
#
#   macos-release.sh doctor
#       Which inputs are present (Xcode tools, the two Developer ID certificates, the notary profile).
#       Prints names only, never a secret. Exit 0.
#   macos-release.sh setup
#       Checks the Xcode tools, finds or helps create the Developer ID Application and Developer ID
#       Installer certificates (the request is made here; the private key goes into the login keychain
#       and its temporary file is wiped), stores the notary credentials with
#       `xcrun notarytool store-credentials` (it prompts; nothing secret passes through this script's
#       arguments, environment, log or files) and writes the three TENZRO_MACOS_* names to
#       $TENZRO_MACOS_CONFIG (default ~/.config/tenzro/macos-release.env, outside the repository).
#   macos-release.sh release [--require-signed] <other-arch-archive> [ref] [dist-dir] [out-dir]
#       build-macos.sh (this Mac's archive; Developer ID + hardened runtime when the identity is set),
#       build-pkg.sh with the other architecture's archive (signs, notarises, staples when set), then
#       the checks: codesign --verify on the programs in this Mac's archive, pkgutil/spctl on the
#       package, stapler validate. Any failed check exits non-zero. With no credentials it ends at the
#       unsigned package and lists what is missing; --require-signed makes that an error (exit 3).
#
# TENZRO_MACOS_DRY_RUN=1 prints every command that would run instead of running it (works on Linux).
# TENZRO_MACOS_ENTITLEMENTS=<plist> passes an entitlements file to codesign for the programs; none
# is passed by default (Secure Enclave blob keys are not known to need one; unverified on a Mac).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
config=${TENZRO_MACOS_CONFIG:-$HOME/.config/tenzro/macos-release.env}
dry=${TENZRO_MACOS_DRY_RUN:-}

say() { printf '%s\n' "$*"; }
run() {
    if [ -n "$dry" ]; then printf 'DRY %s\n' "$*"; return 0; fi
    "$@"
}
load_config() {
    if [ -f "$config" ]; then
        # shellcheck disable=SC1090
        . "$config"
    fi
}
need_mac() {
    if [ -z "$dry" ] && [ "$(uname -s)" != Darwin ]; then
        say "REFUSING: this runs on macOS (set TENZRO_MACOS_DRY_RUN=1 to see the steps)" >&2
        exit 1
    fi
}
find_identity() { # kind: "Developer ID Application" | "Developer ID Installer"
    if [ -n "$dry" ] || ! command -v security >/dev/null 2>&1; then return 0; fi
    security find-identity -v 2>/dev/null | sed -n "s/.*\"\\($1:[^\"]*\\)\".*/\\1/p" | head -n 1
}
have_xcode() { [ -n "$dry" ] || { xcode-select -p >/dev/null 2>&1 && command -v xcrun >/dev/null 2>&1; }; }
have_profile() { # a notarytool profile answers a history call
    [ -n "${TENZRO_MACOS_NOTARY_PROFILE:-}" ] || return 1
    [ -n "$dry" ] || xcrun notarytool history --keychain-profile "$TENZRO_MACOS_NOTARY_PROFILE" >/dev/null 2>&1
}

missing=()
w=
inputs() {
    load_config
    missing=()
    if have_xcode; then say "ok       Xcode command line tools"; else say "MISSING  Xcode command line tools (xcode-select --install)"; missing+=(xcode); fi
    if [ -n "${TENZRO_MACOS_SIGN_IDENTITY:-}" ]; then say "ok       TENZRO_MACOS_SIGN_IDENTITY=$TENZRO_MACOS_SIGN_IDENTITY"; else say "MISSING  TENZRO_MACOS_SIGN_IDENTITY (Developer ID Application)"; missing+=(sign); fi
    if [ -n "${TENZRO_MACOS_INSTALLER_IDENTITY:-}" ]; then say "ok       TENZRO_MACOS_INSTALLER_IDENTITY=$TENZRO_MACOS_INSTALLER_IDENTITY"; else say "MISSING  TENZRO_MACOS_INSTALLER_IDENTITY (Developer ID Installer)"; missing+=(installer); fi
    if have_profile; then say "ok       TENZRO_MACOS_NOTARY_PROFILE=$TENZRO_MACOS_NOTARY_PROFILE"; else say "MISSING  TENZRO_MACOS_NOTARY_PROFILE (a notarytool keychain profile that answers)"; missing+=(notary); fi
}

cmd_doctor() { inputs; say "config file: $config ($([ -f "$config" ] && echo present || echo absent))"; }

make_identity() { # kind, file stem
    local kind=$1 stem=$2 found w
    found=$(find_identity "$kind")
    if [ -n "$found" ]; then say "found $kind: $found" >&2; printf '%s' "$found"; return 0; fi
    say "no $kind certificate in the keychain: making a request for one" >&2
    w=$(mktemp -d "${TMPDIR:-/tmp}/tzcsr.XXXXXX"); chmod 700 "$w"
    local email name
    read -r -p "Apple ID email for the request: " email
    name="Tenzro $kind"
    run openssl req -new -newkey rsa:2048 -nodes -keyout "$w/$stem.key" -out "$w/$stem.csr" -subj "/emailAddress=$email/CN=$name" >&2
    run security import "$w/$stem.key" -k "$HOME/Library/Keychains/login.keychain-db" -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/pkgbuild >&2
    if [ -z "$dry" ]; then rm -P "$w/$stem.key" 2>/dev/null || rm -f "$w/$stem.key"; fi
    say "Upload $w/$stem.csr at https://developer.apple.com/account/resources/certificates/add as a \"$kind\" certificate, download the .cer." >&2
    local cer
    read -r -p "Path of the downloaded $kind .cer: " cer
    run security import "$cer" -k "$HOME/Library/Keychains/login.keychain-db" >&2
    rm -rf "$w"
    find_identity "$kind"
}

cmd_setup() {
    need_mac
    have_xcode || { say "REFUSING: install the Xcode command line tools first: xcode-select --install" >&2; exit 1; }
    local app inst profile
    app=$(make_identity "Developer ID Application" app)
    inst=$(make_identity "Developer ID Installer" installer)
    if [ -z "$dry" ] && { [ -z "$app" ] || [ -z "$inst" ]; }; then
        say "REFUSING: a certificate is still missing after the import" >&2; exit 1
    fi
    read -r -p "Notary profile name [tenzro-notary]: " profile
    profile=${profile:-tenzro-notary}
    # No credential flags: notarytool asks for them itself, so nothing secret passes through here.
    run xcrun notarytool store-credentials "$profile"
    if [ -n "$dry" ]; then say "DRY would write $config"; return 0; fi
    mkdir -p "$(dirname "$config")"
    (umask 077; { printf 'TENZRO_MACOS_SIGN_IDENTITY=%q\n' "$app"; printf 'TENZRO_MACOS_INSTALLER_IDENTITY=%q\n' "$inst"; printf 'TENZRO_MACOS_NOTARY_PROFILE=%q\n' "$profile"; } > "$config")
    say "wrote $config (names only)"
}

cmd_release() {
    local require=""
    if [ "${1:-}" = --require-signed ]; then require=1; shift; fi
    local other=${1:?usage: macos-release.sh release [--require-signed] <other-arch-archive> [ref] [dist-dir] [out-dir]}
    local ref=${2:-HEAD} dist=${3:-$HOME/dist} out=${4:-$HOME/dist/pkg}
    need_mac
    inputs >&2
    export TENZRO_MACOS_SIGN_IDENTITY=${TENZRO_MACOS_SIGN_IDENTITY:-}
    export TENZRO_MACOS_INSTALLER_IDENTITY=${TENZRO_MACOS_INSTALLER_IDENTITY:-}
    export TENZRO_MACOS_NOTARY_PROFILE=${TENZRO_MACOS_NOTARY_PROFILE:-}
    local signed=1; [ "${#missing[@]}" -eq 0 ] || signed=""
    if [ -z "$signed" ] && [ -n "$require" ]; then say "REFUSING: --require-signed and inputs are missing" >&2; exit 3; fi
    # A notary profile that does not answer is dropped so the package step does not refuse on it.
    case " ${missing[*]:-} " in *" notary "*) export TENZRO_MACOS_NOTARY_PROFILE= ;; esac
    if [ -n "${TENZRO_MACOS_ENTITLEMENTS:-}" ]; then
        [ -n "$dry" ] || [ -f "$TENZRO_MACOS_ENTITLEMENTS" ] || { say "REFUSING: TENZRO_MACOS_ENTITLEMENTS names no file" >&2; exit 1; }
        export TENZRO_MACOS_CODESIGN_ENTITLEMENTS=$TENZRO_MACOS_ENTITLEMENTS
    fi
    run bash "$here/build-macos.sh" "$ref" "$dist"
    local arch flavour
    case "$(uname -m)" in x86_64) arch=x86_64 flavour=cpu ;; *) arch=aarch64 flavour=metal ;; esac
    local mine=$dist/tenzro-node-macos-$arch-$flavour.tar.gz
    local arm=$mine x86=$other
    [ "$arch" = aarch64 ] || { arm=$other; x86=$mine; }
    run bash "$repo/packaging/macos/build-pkg.sh" "$arm" "$x86" "$out"
    # Checks: any failure exits non-zero.
    w=$(mktemp -d "${TMPDIR:-/tmp}/tzverify.XXXXXX"); trap 'rm -rf "$w"' EXIT
    run tar -xzf "$mine" -C "$w"
    local b
    for b in tenzro-node tenzro; do
        run codesign --verify --strict --verbose=2 "$w/tenzro-node-macos-$arch-$flavour/bin/$b"
    done
    local pkgs=("$out"/tenzro-*-macos.pkg)
    if [ -n "$signed" ]; then
        run pkgutil --check-signature "${pkgs[@]}"
        run spctl -a -t install -vv "${pkgs[@]}"
        run xcrun stapler validate "${pkgs[@]}"
        say "RELEASE ok: signed, notarised, stapled, verified"
    else
        say "RELEASE unsigned package built; to sign and notarise run: macos-release.sh setup"
        say "missing: ${missing[*]}"
    fi
}

case "${1:-}" in
    doctor) shift; cmd_doctor "$@" ;;
    setup) shift; cmd_setup "$@" ;;
    release) shift; cmd_release "$@" ;;
    *) say "usage: macos-release.sh doctor | setup | release [--require-signed] <other-arch-archive> [ref] [dist-dir] [out-dir]" >&2; exit 2 ;;
esac
