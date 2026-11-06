#!/bin/bash
# Build the macOS release artifact of tenzro-node and the CLI for this Mac's
# architecture: cargo only, from a committed ref, --locked, with the toolchain
# pinned in rust-toolchain.toml.
#   Apple silicon  tenzro-node-macos-aarch64-metal  (Metal, linked by the
#                  aarch64-apple target itself)
#   Intel          tenzro-node-macos-x86_64-cpu     (CPU build: the Metal
#                  backend is switched off, so an Intel Mac never runs models
#                  on a GPU path the node does not treat as one)
#
# Usage: scripts/release/build-macos.sh [ref] [dist-dir]
set -euo pipefail

REF=${1:-HEAD}
DIST=${2:-$HOME/dist}
case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) arch=aarch64 flavour=metal ;;
    Darwin/x86_64) arch=x86_64 flavour=cpu; export GGML_METAL=OFF ;;
    *) echo "REFUSING: not a Mac"; exit 1 ;;
esac
target=$arch-apple-darwin

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
. scripts/release/lib.sh
commit=$(git rev-parse --verify "$REF^{commit}")
epoch=$(release_epoch "$commit")
rustc --version | grep -q " $(release_rust) " || { echo "REFUSING: rustc is not the pinned $(release_rust)"; exit 1; }

name=tenzro-node-macos-$arch-$flavour
src=$(mktemp -d)
stage=$(mktemp -d)/$name
trap 'rm -rf "$src" "$(dirname "$stage")"' EXIT
git archive --format=tar "$commit" | tar -x -C "$src"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target-release/macos}
(cd "$src" && RUSTFLAGS="--remap-path-prefix=$src=." \
    cargo build --release --locked --target "$target" -p tenzro-node -p tenzro-cli)
out=$CARGO_TARGET_DIR/$target/release
mkdir -p "$stage/bin"
install -m755 "$out/tenzro-node" "$stage/bin/tenzro-node"
install -m755 "$out/tenzro" "$stage/bin/tenzro"
mach=arm64; [ "$arch" = x86_64 ] && mach=x86_64
file "$stage/bin/tenzro-node" | grep -q "$mach" || { echo "REFUSING: not an $mach Mach-O"; exit 1; }
if [ "$flavour" = metal ]; then
    grep -qa ggml_metal "$stage/bin/tenzro-node" || { echo "REFUSING: no Metal backend linked"; exit 1; }
else
    ! grep -qa ggml_metal_init "$stage/bin/tenzro-node" || { echo "REFUSING: Metal backend linked into a cpu build"; exit 1; }
fi
# The Swift runtime is linked by @rpath; without an rpath to /usr/lib/swift the
# binary aborts at load on every Mac.
for bin in "$stage/bin/tenzro-node" "$stage/bin/tenzro"; do
    if otool -L "$bin" | grep -q '@rpath/libswift' && ! otool -l "$bin" | grep -q 'path /usr/lib/swift '; then
        echo "REFUSING: $(basename "$bin") links the Swift runtime without an rpath to /usr/lib/swift"; exit 1
    fi
    "$bin" --version >/dev/null || { echo "REFUSING: $(basename "$bin") does not start"; exit 1; }
done

mkdir -p "$DIST"
# bsdtar has no --sort; entries are added in sorted order by name instead.
find "$(dirname "$stage")" -exec touch -h -t "$(date -r "$epoch" +%Y%m%d%H%M.%S)" {} +
(cd "$(dirname "$stage")" && find "$name" | sort | tar --uid 0 --gid 0 -cf - -n -T - | gzip -9n > "$DIST/$name.tar.gz")
release_buildenv "$DIST/$name.buildenv.json" "$name" "$commit" "$flavour" "$target" "" ""
echo "BUILD OK: $DIST/$name.tar.gz"
