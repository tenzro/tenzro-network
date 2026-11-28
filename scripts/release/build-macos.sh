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
# The node reaches the Secure Enclave through a CryptoKit shim built for macOS 14 (the first release with the
# surface it uses), so the binaries say macOS 14 is their floor: an older Mac is refused cleanly at launch.
# macOS 27 runs Apple silicon only; the Intel archive serves the Intel Macs on macOS 14 to 26.
export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-14.0}
# ONNX Runtime from the pinned library (packaging/onnxruntime.tsv), checked by hash; nothing is fetched by the
# build. Intel macOS has no prebuilt runtime and loads one at run time, so it links none.
if [ "$target" = aarch64-apple-darwin ]; then
    python3 "$src/scripts/release/fetch-onnxruntime.py" --target "$target" --link-at "$src/.onnxruntime/host" >/dev/null
fi
(cd "$src" && CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS="--remap-path-prefix=$src=." \
    cargo build --release --locked --target "$target" -p tenzro-node -p tenzro-cli)
out=$CARGO_TARGET_DIR/$target/release
mkdir -p "$stage/bin"
install -m755 "$out/tenzro-node" "$stage/bin/tenzro-node"
install -m755 "$out/tenzro" "$stage/bin/tenzro"
# Debug symbols to a dSYM bundle, shipped separately; the binaries keep their function names.
dbg=$(dirname "$stage")/$name-debug
mkdir -p "$dbg"
for b in tenzro-node tenzro; do dsymutil "$stage/bin/$b" -o "$dbg/$b.dSYM" && strip -S "$stage/bin/$b"; done
release_network_profile "$src" "$stage"
release_console "$src" "$stage"
# The app uses the glass button styles of the macOS 26 SDK where the system has them (and runs from
# macOS 14), so it is built with Xcode 26 or newer. A runner whose default Xcode is older has the
# newer ones installed beside it: use the newest.
if [ -z "${DEVELOPER_DIR:-}" ]; then
  xc=$(ls -d /Applications/Xcode_2[6-9]*.app 2>/dev/null | sort -V | tail -n 1)
  if [ -n "$xc" ]; then DEVELOPER_DIR="$xc/Contents/Developer"; export DEVELOPER_DIR; fi
fi
echo "Xcode: $(xcode-select -p) (SDK $(xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo unknown))"
# Tenzro Control, the desktop app the installer puts in /Applications, for the
# same processor.
app=$(sh "$src/apps/tenzro-control/apple/bundle.sh" "$([ "$arch" = x86_64 ] && echo macos-x86_64 || echo macos)" | tail -n 1)
mkdir -p "$stage/control"
ditto "$app" "$stage/control/Tenzro Control.app"
mach=arm64; [ "$arch" = x86_64 ] && mach=x86_64
# Developer ID signing with the hardened runtime, when this Mac holds the
# release identity (TENZRO_MACOS_SIGN_IDENTITY, a codesign identity name).
# Without it the binaries keep their ad-hoc signatures.
if [ -n "${TENZRO_MACOS_SIGN_IDENTITY:-}" ]; then
    for b in "$stage/bin/tenzro-node" "$stage/bin/tenzro" "$stage/control/Tenzro Control.app"; do
        codesign --force --options runtime --timestamp ${TENZRO_MACOS_CODESIGN_ENTITLEMENTS:+--entitlements "$TENZRO_MACOS_CODESIGN_ENTITLEMENTS"} --sign "$TENZRO_MACOS_SIGN_IDENTITY" "$b"
        codesign --verify --strict "$b"
    done
else
    echo "not Developer ID signed: TENZRO_MACOS_SIGN_IDENTITY is not set"
fi
for bin in "$stage/bin/tenzro-node" "$stage/control/Tenzro Control.app/Contents/MacOS/TenzroControl"; do
    file "$bin" | grep -q "$mach" || { echo "REFUSING: $(basename "$bin") is not an $mach Mach-O"; exit 1; }
done
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
(cd "$(dirname "$stage")" && find "$name-debug" | sort | tar --uid 0 --gid 0 -cf - -n -T - | gzip -9n > "$DIST/$name-debug.tar.gz")
release_buildenv "$DIST/$name.buildenv.json" "$name" "$commit" "$flavour" "$target" "" ""
echo "BUILD OK: $DIST/$name.tar.gz"
