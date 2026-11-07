#!/bin/bash
# Build one macOS installer package from the two signed macOS release archives,
# repackaging the exact bytes. macOS only (pkgbuild, productbuild, otool).
#
#   build-pkg.sh <tenzro-node-macos-aarch64-metal.tar.gz> <tenzro-node-macos-x86_64-cpu.tar.gz> <out-dir>
#
# One tenzro-<version>-macos.pkg holds both payloads and installs the one that
# matches the Mac (Apple silicon: Metal build; Intel: CPU build). It is unsigned.
# Environment: TENZRO_VERSION (default: the workspace version), PUBLIC_COMMIT, RELEASE_COMMIT.
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "REFUSING: pkgbuild and productbuild only run on macOS" >&2; exit 1; }
arm=${1:?usage: build-pkg.sh <aarch64-metal.tar.gz> <x86_64-cpu.tar.gz> <out-dir>}
x86=${2:?}; out=${3:?}
here=$(cd "$(dirname "$0")" && pwd)
pk=$(cd "$here/.." && pwd); repo=$(cd "$pk/.." && pwd)
mkdir -p "$out"; out=$(cd "$out" && pwd)
version=${TENZRO_VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)}
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
stage "$x86" cpu com.tenzro.node.cpu

minos=$(printf '%s\n%s\n' "$(cat "$w/minos-metal")" "$(cat "$w/minos-cpu")" | sort -V | head -1)
minos=${minos:-11.0}
mkdir -p "$w/resources"
cp "$here/resources/welcome.html" "$here/resources/conclusion.html" "$w/resources/"
cp "$repo/LICENSE" "$w/resources/license.txt"
sed "s/@VERSION@/$version/g; s/@MINOS@/$minos/g" "$here/distribution.xml.in" > "$w/distribution.xml"
productbuild --distribution "$w/distribution.xml" --resources "$w/resources" --package-path "$w/components" "$out/tenzro-$version-macos.pkg" >/dev/null
echo "built $out/tenzro-$version-macos.pkg (minimum macOS $minos)"
