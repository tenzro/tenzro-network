#!/bin/bash
# Dry-run test of macos-release.sh; runs on Linux (no Mac, no credentials, nothing is signed).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
s=$here/macos-release.sh
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
export TENZRO_MACOS_DRY_RUN=1 TENZRO_MACOS_CONFIG=$t/none.env
fail() { echo "FAIL: $*" >&2; exit 1; }

# doctor without anything: names the four missing inputs, exits 0, prints no secret
out=$(bash "$s" doctor)
for k in SIGN_IDENTITY INSTALLER_IDENTITY NOTARY_PROFILE; do
    grep -q "ok .*$k" <<<"$out" && fail "doctor claims $k present"
done
[ "$(grep -c '^MISSING' <<<"$out")" -eq 3 ] || fail "doctor should list three missing inputs (the dry run counts Xcode as present): $out"

# release without credentials ends at the unsigned package and says what is missing
out=$(bash "$s" release /x/other.tar.gz HEAD /x/dist /x/out)
grep -q 'DRY bash .*build-macos.sh HEAD /x/dist' <<<"$out" || fail "no build-macos step"
grep -q 'DRY bash .*build-pkg.sh .*/x/out' <<<"$out" || fail "no build-pkg step"
grep -q 'RELEASE unsigned package built' <<<"$out" || fail "not reported unsigned"
grep -q 'DRY spctl' <<<"$out" && fail "spctl ran without a signature"
# --require-signed refuses without credentials
set +e; bash "$s" release --require-signed /x/o.tar.gz >/dev/null 2>&1; rc=$?; set -e
[ "$rc" -eq 3 ] || fail "--require-signed should exit 3, got $rc"

# with the three names: the full sequence, in order
printf 'TENZRO_MACOS_SIGN_IDENTITY=%q\nTENZRO_MACOS_INSTALLER_IDENTITY=%q\nTENZRO_MACOS_NOTARY_PROFILE=%q\n' \
    "Developer ID Application: T (X)" "Developer ID Installer: T (X)" p > "$t/full.env"
out=$(TENZRO_MACOS_CONFIG=$t/full.env bash "$s" release /x/other.tar.gz HEAD /x/dist /x/out)
seq=$(grep -oE 'build-macos.sh|build-pkg.sh|codesign --verify|pkgutil --check-signature|spctl -a -t install|stapler validate|RELEASE ok' <<<"$out" | tr '\n' ' ')
[ "$seq" = "build-macos.sh build-pkg.sh codesign --verify codesign --verify pkgutil --check-signature spctl -a -t install stapler validate RELEASE ok " ] || fail "sequence: $seq"

# setup: store-credentials takes no credential argument, the config holds names only
out=$(printf 'a@b.c\n/x/app.cer\na@b.c\n/x/inst.cer\nprof\n' | bash "$s" setup)
grep -q 'DRY xcrun notarytool store-credentials prof$' <<<"$out" || fail "store-credentials has arguments"
grep -qiE 'password|--key|--apple-id' <<<"$out" && fail "a credential flag appears"
echo "macos-release dry-run: ok"
