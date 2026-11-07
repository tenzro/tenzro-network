#!/usr/bin/env bash
# Install, check, remove, reinstall and upgrade a package in clean containers.
#
#   run-container-tests.sh <pkg-dir> <archive.tar.gz> <image> [expect-refused|expect-ready|expect-not-ready]
#
# <pkg-dir> holds the package built from <archive> (and optionally a revision 2 of it,
# tenzro-*-2.*, for the upgrade step, and other/ with the other flavour's package for
# the conflict step). The archive supplies the expected sha256 of the binaries.
set -euo pipefail
pkgdir=$(cd "$1" && pwd); archive=$2; image=$3; mode=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
ctr=${CONTAINER:-$(command -v podman || command -v docker)}
name=$(basename "$archive" .tar.gz); flavour=${name##*-}
# BIN_SHAS="<node sha256> <cli sha256>" replaces reading the archive (for a host that only has the packages).
if [ -n "${BIN_SHAS:-}" ]; then
    nsha=${BIN_SHAS%% *}; csha=${BIN_SHAS##* }
else
    w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
    tar -xzf "$archive" -C "$w" "$name/bin/tenzro" "$name/bin/tenzro-node"
    nsha=$(sha256sum "$w/$name/bin/tenzro-node" | cut -d' ' -f1); csha=$(sha256sum "$w/$name/bin/tenzro" | cut -d' ' -f1)
fi
case "$image" in *debian*|*ubuntu*) ext=deb ;; *) ext=rpm ;; esac
f1=$(ls "$pkgdir"/tenzro-$flavour[_-]*-1[._]*.$ext | head -1)
f2=$(ls "$pkgdir"/tenzro-$flavour[_-]*-2[._]*.$ext 2>/dev/null | head -1 || true)
fo=$(ls "$pkgdir"/other/*.$ext 2>/dev/null | head -1 || true)
args=(-e PKG_NAME=tenzro-$flavour -e PKG_FILE=/pkgs/$(basename "$f1") -e EXPECT_NODE_SHA=$nsha -e EXPECT_CLI_SHA=$csha)
mounts=(-v "$pkgdir:/pkgs:ro" -v "$here/test-inside.sh:/test-inside.sh:ro")
[ -n "$f2" ] && args+=(-e PKG_FILE_NEXT=/pkgs/$(basename "$f2"))
[ -n "$fo" ] && args+=(-e OTHER_FILE=/pkgs/other/$(basename "$fo"))
case "$mode" in
    expect-refused) args+=(-e EXPECT_REFUSED=1) ;;
    expect-ready) args+=(-e EXPECT_GATE=READY) ;;
    expect-not-ready) args+=(-e "EXPECT_GATE=NOT READY") ;;
esac
[ "$flavour" = cuda ] && args+=(-e EXPECT_MISSING_CUDA=1)
exec "$ctr" run --rm "${args[@]}" "${mounts[@]}" "$image" bash /test-inside.sh
