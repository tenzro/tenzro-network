#!/bin/bash
# Build one macOS installer package from the two signed macOS release archives,
# repackaging the exact bytes. macOS only (pkgbuild, productbuild, otool).
#
#   build-pkg.sh <tenzro-node-macos-aarch64-metal.tar.gz> <tenzro-node-macos-x86_64-cpu.tar.gz | none> <out-dir>
#
# With "none" for the Intel archive the package is for Apple silicon only (macOS 27 runs on Apple silicon only,
# and the Intel archive can follow): its distribution offers the Metal build and refuses Intel Macs.
#
# One tenzro-<version>-macos.pkg holds both payloads and installs the one that
# matches the Mac (Apple silicon: Metal build; Intel: CPU build).
# Environment: TENZRO_VERSION (default: the version of the node), PUBLIC_COMMIT, RELEASE_COMMIT.
#
# Signing turns on once an identity exists, and is off until then:
#   TENZRO_MACOS_INSTALLER_IDENTITY  a "Developer ID Installer" identity in the keychain. Set, the
#                             package is signed with a secure timestamp and its signature is checked
#                             before the script reports success; unset, it is unsigned and says so.
#   TENZRO_MACOS_NOTARY_PROFILE  a notarytool keychain profile: the signed package is notarised and
#                             stapled.
# The programs inside are the exact bytes of the release archives, which the macOS release build
# signs with Developer ID before their digests are taken (scripts/release/build-macos.sh), so the
# release digests hold for them.
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "REFUSING: pkgbuild and productbuild only run on macOS" >&2; exit 1; }
arm=${1:?usage: build-pkg.sh <aarch64-metal.tar.gz> <x86_64-cpu.tar.gz> <out-dir>}
x86=${2:?}; out=${3:?}
arm_only=0; [ "$x86" = none ] && arm_only=1
here=$(cd "$(dirname "$0")" && pwd)
pk=$(cd "$here/.." && pwd); repo=$(cd "$pk/.." && pwd)
mkdir -p "$out"; out=$(cd "$out" && pwd)
version=${TENZRO_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/tenzro-node/Cargo.toml" | head -1)}
release_commit=${RELEASE_COMMIT:-unknown}; public_commit=${PUBLIC_COMMIT:-unknown}
packaging_commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
w=$(mktemp -d "${TMPDIR:-/tmp}/tzpkg.XXXXXX"); trap 'rm -rf "$w"' EXIT
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

stage() { # archive flavour id
    local archive=$1 flavour=$2 id=$3 name src root
    name=$(basename "$archive" .tar.gz)
    mkdir -p "$w/x-$flavour"; tar -xzf "$archive" -C "$w/x-$flavour"
    src=$w/x-$flavour/$name
    [ -f "$src/bin/tenzro" ] && [ -f "$src/bin/tenzro-node" ] || { echo "REFUSING: $archive lacks the programs" >&2; exit 1; }
    root=$w/root-$flavour
    mkdir -p "$root/usr/local/lib/tenzro/bin" "$root/usr/local/lib/tenzro/share/doc" "$root/usr/local/bin" "$root/Applications/Tenzro.app/Contents/MacOS"
    install -m755 "$src/bin/tenzro" "$src/bin/tenzro-node" "$root/usr/local/lib/tenzro/bin/"
    # The network profile, found by the node at <bin dir>/../share/network.
    if [ -d "$src/share" ]; then cp -a "$src/share/." "$root/usr/local/lib/tenzro/share/"; fi
    install -m755 "$pk/common/tenzro-check" "$root/usr/local/lib/tenzro/bin/tenzro-check"
    install -m755 "$here/tenzro-uninstall" "$root/usr/local/lib/tenzro/bin/tenzro-uninstall"
    for b in tenzro tenzro-node tenzro-check tenzro-uninstall; do ln -s "../lib/tenzro/bin/$b" "$root/usr/local/bin/$b"; done
    install -m644 "$repo/LICENSE" "$repo/NOTICE" "$pk/common/FIRST-RUN.txt" "$root/usr/local/lib/tenzro/share/doc/"
    cat > "$root/usr/local/lib/tenzro/PACKAGE-INFO" <<EOF
package=$id
version=$version
flavour=$flavour
architecture=$(echo "$name" | cut -d- -f4)
source_archive=$(basename "$archive")
source_archive_sha256=$(sha "$archive")
release_commit=$release_commit
public_source_commit=$public_commit
packaging_commit=$packaging_commit
EOF
    install -m755 "$here/app/Tenzro" "$root/Applications/Tenzro.app/Contents/MacOS/Tenzro"
    [ -d "$src/control/Tenzro Control.app" ] || { echo "REFUSING: $archive has no control/Tenzro Control.app" >&2; exit 1; }
    ditto "$src/control/Tenzro Control.app" "$root/Applications/Tenzro Control.app"
    sed "s/@VERSION@/$version/g" "$here/app/Info.plist" > "$root/Applications/Tenzro.app/Contents/Info.plist"
    # Minimum macOS version the programs were built for.
    otool -l "$src/bin/tenzro-node" | awk '/LC_BUILD_VERSION/ {f=1} f && /minos/ {print $2; exit}' > "$w/minos-$flavour"
    mkdir -p "$w/components"
    pkgbuild --analyze --root "$root" "$w/$flavour.plist" >/dev/null
    # No bundle relocation: the launcher must land in /Applications.
    i=0; while /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$w/$flavour.plist" >/dev/null 2>&1; do i=$((i + 1)); done
    pkgbuild --root "$root" --component-plist "$w/$flavour.plist" --identifier "$id" --version "$version" \
        --scripts "$here/scripts" --install-location / --ownership recommended "$w/components/tenzro-$flavour.pkg" >/dev/null
}
stage "$arm" metal com.tenzro.node.metal
[ "$arm_only" = 1 ] || stage "$x86" cpu com.tenzro.node.cpu

if [ "$arm_only" = 1 ]; then minos=$(cat "$w/minos-metal"); else minos=$(printf '%s\n%s\n' "$(cat "$w/minos-metal")" "$(cat "$w/minos-cpu")" | sort -V | head -1); fi
minos=${minos:-11.0}
mkdir -p "$w/resources"
cp "$here/resources/welcome.html" "$here/resources/conclusion.html" "$w/resources/"
cp "$repo/LICENSE" "$w/resources/license.txt"
tmpl=$here/distribution.xml.in; [ "$arm_only" = 1 ] && tmpl=$here/distribution-arm64.xml.in
sed "s/@VERSION@/$version/g; s/@MINOS@/$minos/g" "$tmpl" > "$w/distribution.xml"
pkg=$out/tenzro-$version-macos.pkg
sign=()
[ -z "${TENZRO_MACOS_INSTALLER_IDENTITY:-}" ] || sign=(--sign "$TENZRO_MACOS_INSTALLER_IDENTITY" --timestamp)
productbuild --distribution "$w/distribution.xml" --resources "$w/resources" --package-path "$w/components" ${sign[@]+"${sign[@]}"} "$pkg" >/dev/null
if [ ${#sign[@]} -eq 0 ]; then
    [ -z "${TENZRO_MACOS_NOTARY_PROFILE:-}" ] || { rm -f "$pkg"; echo "REFUSING: notarising needs a signed package (TENZRO_MACOS_INSTALLER_IDENTITY)" >&2; exit 1; }
    echo "built $pkg (minimum macOS $minos), unsigned: TENZRO_MACOS_INSTALLER_IDENTITY is not set"
    exit 0
fi
pkgutil --check-signature "$pkg" | grep -q 'Status: signed' \
    || { rm -f "$pkg"; echo "REFUSING: $pkg did not come out signed by $TENZRO_MACOS_INSTALLER_IDENTITY" >&2; exit 1; }
if [ -n "${TENZRO_MACOS_NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$pkg" --keychain-profile "$TENZRO_MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$pkg"
    echo "built $pkg (minimum macOS $minos), signed by $TENZRO_MACOS_INSTALLER_IDENTITY, notarised and stapled"
else
    echo "built $pkg (minimum macOS $minos), signed by $TENZRO_MACOS_INSTALLER_IDENTITY"
fi
