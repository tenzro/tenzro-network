#!/usr/bin/env bash
# The release's package sources, after make-packages.sh: our apt and dnf repositories, our
# Android app source, the Homebrew formula and cask, the winget manifests, the AUR and Nix
# packages, and the browser app's static files.
#
#   make-sources.sh <dist-dir> <packages-dir> <version> <out-dir>
#
# Files are fetched from downloads.tenzro.com (TENZRO_DOWNLOADS overrides it). The repositories
# and the Android app source are signed only with their keys set (TENZRO_REPO_KEY, see
# repos/make-repos.sh; TENZRO_FDROID_KEYSTORE, see android/make-app-source.sh); without them they
# are built for checking and this script ends with exit 3 after making everything else.
set -euo pipefail
dist=$(cd "${1:?usage: make-sources.sh <dist-dir> <packages-dir> <version> <out-dir>}" && pwd)
pkgs=$(cd "${2:?}" && pwd)
ver=${3:?}; out=${4:?}
here=$(cd "$(dirname "$0")" && pwd)
base=${TENZRO_DOWNLOADS:-https://downloads.tenzro.com}
mkdir -p "$out"

"$here/homebrew/gen-formula.sh" "$dist" "$ver" "$base" "$out/homebrew-tap"
shopt -s nullglob
msis=("$pkgs"/tenzro-*-windows*.msi)
if [ ${#msis[@]} -eq 1 ]; then
    "$here/winget/gen-manifests.sh" "${msis[0]}" "$ver" "$base/$(basename "${msis[0]}")" "$out/winget"
else
    echo "skipped winget (${#msis[@]} Windows installers in $pkgs, one expected)"
fi
"$here/aur/gen-pkgbuild.sh" "$dist" "$ver" "$base" "$out/aur"
"$here/nix/gen-packages.sh" "$dist" "$ver" "$base" "$out/nix"
mkdir -p "$out/web"
"$here/../apps/tenzro-control/tools/web-bundle.sh" "$ver" "$out/web" > "$out/web/SHA256SUMS.web"
unsigned=0
apks=("$pkgs"/tenzro-control-*.apk)
if [ ${#apks[@]} -eq 1 ]; then
    "$here/android/make-app-source.sh" "${apks[0]}" "$out/android" || { rc=$?; [ $rc = 3 ] || exit $rc; unsigned=1; }
else
    echo "skipped the Android app source (${#apks[@]} Tenzro Control APKs in $pkgs, one expected)"
fi
"$here/repos/make-repos.sh" "$pkgs" "$out/repos" || { rc=$?; [ $rc = 3 ] || exit $rc; unsigned=1; }
[ $unsigned = 0 ] || exit 3
