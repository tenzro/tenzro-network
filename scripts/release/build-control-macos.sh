#!/bin/bash
# Build the macOS release of Tenzro Control (the desktop app) for this Mac's
# architecture: Tenzro Control.app and a .dmg, signed with the Developer ID
# identity named in tauri.conf.json, plus SHA256SUMS and a buildenv record.
#
# The source is a `git archive` of a committed ref; npm ci and cargo --locked
# take every dependency from the lockfiles, with the toolchain pinned in
# rust-toolchain.toml. The build links tenzro-node and is heavy: run it on a
# Mac build host, not on a workstation in use. The Developer ID certificate
# must be in that host's login keychain; nothing here reads a key.
#
# Notarisation, when wanted, runs after the build against the .dmg:
#   xcrun notarytool submit <dmg> --keychain-profile <profile> --wait
#   xcrun stapler staple <dmg>
#
# Usage: scripts/release/build-control-macos.sh [ref] [dist-dir]
#   JOBS  cargo jobs (default 4)
set -euo pipefail
cd "$(dirname "$0")/../.."
repo=$(pwd)
. scripts/release/lib.sh

REF=${1:-HEAD}
DIST=${2:-dist/control}
export CARGO_BUILD_JOBS=${JOBS:-4} CARGO_INCREMENTAL=0
case "$(uname -m)" in
    arm64) arch=aarch64 ;;
    x86_64) arch=x86_64 ;;
    *) echo "REFUSING: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
rustc --version | grep -q " $(release_rust) " || { echo "REFUSING: rustc is not the pinned $(release_rust)"; exit 1; }
node --version | grep -q '^v22\.' || { echo "REFUSING: Node 22 is required"; exit 1; }

commit=$(git rev-parse --verify "$REF^{commit}")
export SOURCE_DATE_EPOCH=$(release_epoch "$commit")
version=$(git show "$commit:apps/tenzro-control/src-tauri/tauri.conf.json" | jq -r .version)
name="tenzro-control-macos-$arch-$version"
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git archive --format=tar "$commit" | tar -x -C "$src"

cd "$src/apps/tenzro-control"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target-release/control-macos}
npm ci --no-audit --no-fund
npm test
RUSTFLAGS="--remap-path-prefix=$src=." npx tauri build --ci --bundles app,dmg -- --locked

bundle=$CARGO_TARGET_DIR/release/bundle
app="$bundle/macos/Tenzro Control.app"
codesign --verify --deep --strict "$app" || { echo "REFUSING: the app is not validly signed"; exit 1; }
mkdir -p "$repo/$DIST"
out=$(cd "$repo/$DIST" && pwd)
cp "$bundle"/dmg/*.dmg "$out/$name.dmg"
ditto -c -k --keepParent "$app" "$out/$name.app.zip"
(cd "$out" && shasum -a 256 "$name.dmg" "$name.app.zip" > "$name.SHA256SUMS")
cd "$repo"
jq -n --arg artifact "$name" --arg commit "$commit" --arg version "$version" --arg rust "$(release_rust)" \
    --arg cargo_lock "$(git show "$commit:apps/tenzro-control/src-tauri/Cargo.lock" | release_sha256)" \
    --arg npm_lock "$(git show "$commit:apps/tenzro-control/package-lock.json" | release_sha256)" \
    --arg builder "$(uname -s)-$(uname -m)" --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{artifact: $artifact, commit: $commit, version: $version, rust: $rust,
      cargo_lock_sha256: $cargo_lock, npm_lock_sha256: $npm_lock, builder: $builder,
      built: $built, locked: true}' > "$out/$name.buildenv.json"
echo "BUILD OK:"; cat "$out/$name.SHA256SUMS"
