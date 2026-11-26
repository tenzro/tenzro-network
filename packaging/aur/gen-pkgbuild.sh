#!/usr/bin/env bash
# The AUR packages for a release, for the community catalogue: tenzro-bin (the node and the
# terminal app) and tenzro-control-bin (Tenzro Control, the desktop app), both from the release's
# Linux cpu archives, checked against the release's SHA256SUMS.
#
#   gen-pkgbuild.sh <dist-dir> <version> <download-url-of-the-release> <out-dir>
#
# Writes <out-dir>/tenzro-bin/ and <out-dir>/tenzro-control-bin/, each with its PKGBUILD and the
# .SRCINFO the AUR reads. makepkg checks each archive against the digest written here.
set -euo pipefail
dist=$(cd "${1:?usage: gen-pkgbuild.sh <dist-dir> <version> <download-url> <out-dir>}" && pwd)
ver=${2:?}; base=${3:?}; out=${4:?}
base=${base%/}
digest() {
    local s; s=$(awk -v f="$1" '$2==f {print $1}' "$dist/SHA256SUMS")
    [ -n "$s" ] || { echo "REFUSING: $dist/SHA256SUMS does not list $1" >&2; exit 1; }
    echo "$s"
}
x86=tenzro-node-linux-x86_64-cpu; arm=tenzro-node-linux-aarch64-cpu
x86_sha=$(digest "$x86.tar.gz"); arm_sha=$(digest "$arm.tar.gz")

# pkgbuild <name> <description> <depends> <conflicts/provides name> <package() body>
pkgbuild() {
    local name=$1 desc=$2 depends=$3 provides=$4 body=$5 dir=$out/$1
    mkdir -p "$dir"
    cat > "$dir/PKGBUILD" <<EOF
# Maintainer: Tenzro Network <eng@tenzro.com>
pkgname=$name
pkgver=$ver
pkgrel=1
pkgdesc="$desc"
arch=('x86_64' 'aarch64')
url="https://tenzro.com"
license=('Apache-2.0')
depends=($depends)
provides=('$provides')
conflicts=('$provides')
options=('!strip' '!debug')
source_x86_64=("$base/$x86.tar.gz")
source_aarch64=("$base/$arm.tar.gz")
sha256sums_x86_64=('$x86_sha')
sha256sums_aarch64=('$arm_sha')

package() {
  local src="\$srcdir/tenzro-node-linux-\$CARCH-cpu"
$body
}
EOF
    {
        echo "pkgbase = $name"
        echo "	pkgdesc = $desc"
        echo "	pkgver = $ver"
        echo "	pkgrel = 1"
        echo "	url = https://tenzro.com"
        echo "	arch = x86_64"
        echo "	arch = aarch64"
        echo "	license = Apache-2.0"
        for d in $depends; do echo "	depends = ${d//\'/}"; done
        echo "	provides = $provides"
        echo "	conflicts = $provides"
        echo "	options = !strip"
        echo "	options = !debug"
        echo "	source_x86_64 = $base/$x86.tar.gz"
        echo "	sha256sums_x86_64 = $x86_sha"
        echo "	source_aarch64 = $base/$arm.tar.gz"
        echo "	sha256sums_aarch64 = $arm_sha"
        echo
        echo "pkgname = $name"
    } > "$dir/.SRCINFO"
    echo "$dir/PKGBUILD"
}

# The binaries find their network profile at <bin dir>/../share/network.
pkgbuild tenzro-bin "Run a Tenzro node, with the tenzro terminal app" "'glibc' 'gcc-libs'" tenzro '  install -d "$pkgdir/usr/lib/tenzro" "$pkgdir/usr/bin"
  cp -a "$src/bin" "$src/share" "$pkgdir/usr/lib/tenzro/"
  install -Dm755 "$src/tenzro-node-install" "$pkgdir/usr/bin/tenzro-node-install"
  ln -s ../lib/tenzro/bin/tenzro "$pkgdir/usr/bin/tenzro"
  ln -s ../lib/tenzro/bin/tenzro-node "$pkgdir/usr/bin/tenzro-node"'
pkgbuild tenzro-control-bin "Set up and run a Tenzro node from the desktop" "'gtk4' 'libadwaita' 'tenzro'" tenzro-control '  install -Dm755 "$src/control/tenzro-control" "$pkgdir/usr/bin/tenzro-control"
  install -Dm644 "$src/control/com.tenzro.Control.desktop" "$pkgdir/usr/share/applications/com.tenzro.Control.desktop"
  install -Dm644 "$src/control/com.tenzro.Control.metainfo.xml" "$pkgdir/usr/share/metainfo/com.tenzro.Control.metainfo.xml"
  install -Dm644 "$src/control/com.tenzro.Control.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/com.tenzro.Control.svg"'
