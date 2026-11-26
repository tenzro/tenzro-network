#!/usr/bin/env bash
# Build every installer package from a release dist directory.
#
#   make-packages.sh <dist-dir> [out-dir]
#
# <dist-dir> holds the signed archives and SHA256SUMS. Packages go to <out-dir>
# (default: ../packages beside <dist-dir>), never into <dist-dir>. Nothing in
# <dist-dir> is changed. Each package repackages the exact bytes of an archive.
#
#   Linux    .deb and .rpm for every linux cpu and cuda archive present (build-linux.sh;
#            the rpm needs podman or docker for rpmbuild, see linux/build-rpm-image.sh), and
#            tenzro-control's .deb and .rpm from the control/ folder of each cpu archive
#            (apps/tenzro-control/linux/packaging/build-packages.sh)
#   Windows  the .msi from the windows cuda zip (windows/build-msi.sh; needs the Windows
#            build host: WINDOWS_BUILD=0 skips it)
#   macOS    the .pkg: pkgbuild only runs on macOS. On a Mac it is built here; elsewhere
#            take the artifact of the "Release macOS" workflow run with build=pkg and put it
#            in <out-dir>, or pass MACOS_PKG=<file> to copy it in.
#
# Then packages.json is written (gen-packages-json.sh). Fold the result into the signed
# manifest as packaging/README-FOLD.txt describes.
set -euo pipefail
dist=$(cd "${1:?usage: make-packages.sh <dist-dir> [out-dir]}" && pwd)
out=${2:-$dist/../packages}
mkdir -p "$out"; out=$(cd "$out" && pwd)
[ "$out" != "$dist" ] || { echo "REFUSING: packages never go into the dist directory" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$dist/SHA256SUMS" ] || { echo "REFUSING: $dist/SHA256SUMS missing" >&2; exit 1; }
( cd "$dist" && sha256sum -c --quiet SHA256SUMS ) || { echo "REFUSING: the archives do not match SHA256SUMS" >&2; exit 1; }

for a in tenzro-node-linux-x86_64-cpu tenzro-node-linux-aarch64-cpu tenzro-node-linux-x86_64-cuda tenzro-node-linux-aarch64-cuda; do
    if [ -f "$dist/$a.tar.gz" ]; then "$here/linux/build-linux.sh" "$dist/$a.tar.gz" "$out"; else echo "skipped $a (no archive)"; fi
done
for a in tenzro-node-linux-x86_64-cpu tenzro-node-linux-aarch64-cpu; do
    if [ -f "$dist/$a.tar.gz" ]; then "$here/../apps/tenzro-control/linux/packaging/build-packages.sh" "$dist/$a.tar.gz" "$out"; fi
done

if [ -f "$dist/tenzro-node-windows-x86_64-cuda.zip" ] && [ "${WINDOWS_BUILD:-1}" != 0 ]; then
    "$here/windows/build-msi.sh" "$dist" "$out"
else
    echo "skipped the Windows MSI"
fi

if [ "$(uname -s)" = Darwin ] && [ -f "$dist/tenzro-node-macos-aarch64-metal.tar.gz" ] && [ -f "$dist/tenzro-node-macos-x86_64-cpu.tar.gz" ]; then
    "$here/macos/build-pkg.sh" "$dist/tenzro-node-macos-aarch64-metal.tar.gz" "$dist/tenzro-node-macos-x86_64-cpu.tar.gz" "$out"
elif [ -n "${MACOS_PKG:-}" ]; then
    cp "$MACOS_PKG" "$out/"
else
    ls "$out"/tenzro-*-macos.pkg >/dev/null 2>&1 || echo "no macOS pkg: build it with the release-macos workflow (build=pkg) and pass MACOS_PKG=<file>"
fi

"$here/gen-packages-json.sh" "$dist" "$out"
# The digests of the packages that were built; a kind that was skipped is not an error. The list is
# written whole or not at all: a package whose digest fails leaves none behind.
( cd "$out" && shopt -s nullglob && pkgs=(tenzro-*.deb tenzro-*.rpm tenzro-*.msi tenzro-*.pkg) \
    && [ ${#pkgs[@]} -gt 0 ] && rm -f SHA256SUMS.packages && sha256sum "${pkgs[@]}" > SHA256SUMS.packages.part \
    && mv SHA256SUMS.packages.part SHA256SUMS.packages && cat SHA256SUMS.packages ) \
    || { rm -f "$out/SHA256SUMS.packages.part"; echo "REFUSING: no package was built, or one could not be read for its digest" >&2; exit 1; }
