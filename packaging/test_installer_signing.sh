#!/usr/bin/env bash
# Code signing is a switch: off until a signing identity exists. Runs anywhere: the macOS and
# Windows tools the builders call are replaced by stubs that record what they were asked to do.
#
#   bash packaging/test_installer_signing.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "FAIL: $*"; fail=1; }

mkdir -p "$tmp/bin"
stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$tmp/bin/$1"; chmod +x "$tmp/bin/$1"; }
# macOS tools
stub uname 'echo Darwin'
stub otool ':'
stub shasum 'shift 2; sha256sum "$@"'
stub ditto 'mkdir -p "$2"; cp -R "$1/." "$2/"'
stub pkgbuild 'for a; do :; done; case "$a" in *.pkg) : > "$a";; *.plist) echo "<plist/>" > "$a";; esac'
stub productbuild 'echo "$*" >> "$TEST_LOG"; for a; do :; done; : > "$a"'
stub pkgutil 'echo "Status: ${FAKE_PKG_STATUS:-no signature}"'
stub xcrun 'echo "xcrun $*" >> "$TEST_LOG"'
# Windows machine reached over ssh/scp
stub ssh 'for a; do :; done; echo "$a" >> "$TEST_LOG"'
stub scp 'for a; do :; done; case "$a" in *:*) ;; *) [ -d "$a" ] || : > "$a";; esac'
export PATH="$tmp/bin:$PATH"

# Two release archives of the shape build-pkg.sh repackages, Tenzro Control included.
for n in tenzro-node-macos-aarch64-metal tenzro-node-macos-x86_64-cpu; do
    mkdir -p "$tmp/a/$n/bin" "$tmp/a/$n/control/Tenzro Control.app/Contents/MacOS"
    : > "$tmp/a/$n/bin/tenzro"; : > "$tmp/a/$n/bin/tenzro-node"
    : > "$tmp/a/$n/control/Tenzro Control.app/Contents/MacOS/TenzroControl"
    tar -czf "$tmp/$n.tar.gz" -C "$tmp/a" "$n"
done
pkg() { TEST_LOG=$tmp/pkg.log TENZRO_VERSION=9.9.9 bash "$here/macos/build-pkg.sh" \
    "$tmp/tenzro-node-macos-aarch64-metal.tar.gz" "$tmp/tenzro-node-macos-x86_64-cpu.tar.gz" "$tmp/out" 2>&1; }
id="Developer ID Installer: Test"

: > "$tmp/pkg.log"; out=$(pkg); rc=$?
[[ $rc == 0 && $out == *"unsigned: TENZRO_MACOS_INSTALLER_IDENTITY is not set"* ]] || bad "an unsigned package is not built and reported as unsigned: $out"
grep -q -- '--sign' "$tmp/pkg.log" && bad "productbuild was asked to sign with no identity set"

: > "$tmp/pkg.log"; out=$(TENZRO_MACOS_INSTALLER_IDENTITY="$id" FAKE_PKG_STATUS="signed by a developer certificate issued by Apple for distribution" pkg); rc=$?
[[ $rc == 0 && $out == *"signed by $id"* ]] || bad "a package with an identity is not reported as signed: $out"
grep -q -- "--sign $id --timestamp" "$tmp/pkg.log" || bad "productbuild was not asked to sign with a timestamp: $(cat "$tmp/pkg.log")"
grep -q 'notarytool' "$tmp/pkg.log" && bad "the package was notarised with no notary profile set"

out=$(TENZRO_MACOS_INSTALLER_IDENTITY="$id" pkg); rc=$?
[[ $rc != 0 && $out == *"REFUSING:"*"did not come out signed"* ]] || bad "a package that is not signed after signing was accepted: $out"
[ -e "$tmp/out/tenzro-9.9.9-macos.pkg" ] && bad "the unsigned leftover of a failed signing was kept"

out=$(TENZRO_MACOS_NOTARY_PROFILE=tenzro pkg); rc=$?
[[ $rc != 0 && $out == *"REFUSING: notarising needs a signed package"* ]] || bad "notarising an unsigned package was not refused: $out"
[ -e "$tmp/out/tenzro-9.9.9-macos.pkg" ] && bad "the package of a refused notarisation was kept"

: > "$tmp/pkg.log"; out=$(TENZRO_MACOS_INSTALLER_IDENTITY="$id" TENZRO_MACOS_NOTARY_PROFILE=tenzro FAKE_PKG_STATUS="signed by a developer certificate issued by Apple for distribution" pkg); rc=$?
[[ $rc == 0 && $out == *"notarised and stapled"* ]] || bad "a signed package with a notary profile is not reported as notarised: $out"
grep -q 'xcrun notarytool submit .*tenzro-9.9.9-macos.pkg --keychain-profile tenzro --wait' "$tmp/pkg.log" || bad "the package was not submitted to notarytool: $(cat "$tmp/pkg.log")"
grep -q 'xcrun stapler staple' "$tmp/pkg.log" || bad "the notarisation was not stapled"

# The MSI: build-msi.sh hands the switch to build-msi.ps1 on the Windows machine, over ssh,
# which carries no environment.
mkdir -p "$tmp/dist"; : > "$tmp/dist/tenzro-node-windows-x86_64-cuda.zip"
msi() { TEST_LOG=$tmp/msi.log TZ_WIN_HOST=win TZ_VERSION=9.9.9 bash "$here/windows/build-msi.sh" "$tmp/dist" "$tmp/msiout" 2>&1; }
thumb=0123456789ABCDEF0123456789ABCDEF01234567
: > "$tmp/msi.log"; out=$(msi); rc=$?
call=$(grep 'build-msi.ps1' "$tmp/msi.log")
[[ $rc == 0 && $call == *"-File "* ]] || bad "the unsigned MSI build did not run: $out"
[[ $call == *TENZRO_WINDOWS_SIGN_CERT* ]] && bad "the MSI build was handed a certificate with none set: $call"

: > "$tmp/msi.log"; out=$(TENZRO_WINDOWS_SIGN_CERT=$thumb TENZRO_WINDOWS_TIMESTAMP_URL=http://ts.example msi); rc=$?
call=$(grep 'build-msi.ps1' "$tmp/msi.log")
[[ $rc == 0 && $call == *"\$env:TENZRO_WINDOWS_SIGN_CERT='$thumb'; \$env:TENZRO_WINDOWS_TIMESTAMP_URL='http://ts.example'; & "* ]] \
    || bad "the certificate is not handed to the MSI build over ssh: $call"

: > "$tmp/msi.log"; out=$(TENZRO_WINDOWS_SIGN_CERT=$thumb msi); rc=$?
[[ $rc != 0 && $out == *"without a TENZRO_WINDOWS_TIMESTAMP_URL"* ]] || bad "a signature without a timestamp was not refused: $out"
grep -q 'build-msi.ps1' "$tmp/msi.log" && bad "the MSI build ran although the timestamp was missing"

: > "$tmp/msi.log"; out=$(TENZRO_WINDOWS_SIGN_CERT="x'; Remove-Item C:\\ -Recurse; '" TENZRO_WINDOWS_TIMESTAMP_URL=http://ts.example msi); rc=$?
[[ $rc != 0 && $out == *"not a certificate thumbprint"* ]] || bad "a value that is not a thumbprint was not refused: $out"
grep -q 'build-msi.ps1' "$tmp/msi.log" && bad "the MSI build ran with a value that is not a thumbprint"

# The PowerShell side: the MSI and, in the release build, the programs are signed with SHA-256
# and a timestamp, each signature is checked against the certificate, and it says when it is off.
for f in "$here/windows/build-msi.ps1" "$repo/scripts/release/build-windows.ps1"; do
    ps=$(tr -d '\r' < "$f")
    [[ $ps == *"/fd SHA256 /tr \$env:TENZRO_WINDOWS_TIMESTAMP_URL /td SHA256"* ]] || bad "$f does not sign with SHA-256 and a timestamp"
    [[ $ps == *"Get-AuthenticodeSignature"* && $ps == *"SignerCertificate.Thumbprint -ne"* ]] || bad "$f does not check the signatures it made"
    [[ $ps == *'"TENZRO_WINDOWS_SIGN_CERT is set without TENZRO_WINDOWS_TIMESTAMP_URL"'* ]] || bad "$f signs without a timestamp"
    [[ $ps == *'"unsigned: TENZRO_WINDOWS_SIGN_CERT is not set"'* ]] || bad "$f does not say when signing is off"
done
rel=$(tr -d '\r' < "$repo/scripts/release/build-windows.ps1")
before=${rel%%\$epoch = *}
[[ $before == *"Invoke-CodeSign @("* && $before == *'control\TenzroControl.exe'* ]] \
    || bad "the release build does not sign the programs and Tenzro Control before the archive is made"

[ $fail = 0 ] && echo "ok: code signing is off until an identity is set, and checked when it is on"
exit $fail
