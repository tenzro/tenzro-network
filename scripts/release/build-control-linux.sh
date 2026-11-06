#!/bin/bash
# Build the Linux release of Tenzro Control (the desktop app) on a Linux build
# host of the target architecture, in the pinned image of Dockerfile.control:
# a .deb and an .rpm, plus SHA256SUMS and a buildenv record beside them.
#
# The source is a `git archive` of a committed ref, never the working tree.
# npm ci and cargo --locked take every dependency from the lockfiles, the
# commit time is SOURCE_DATE_EPOCH, and the workspace .cargo/config.toml remaps
# the build paths, so a second build of the same commit can be compared byte
# for byte (the sums of the app binary are recorded for that).
#
# Usage: scripts/release/build-control-linux.sh [ref] [dist-dir]
#   JOBS  cargo jobs (default 8)
#   MEM   container memory cap (default 16g)
set -euo pipefail
cd "$(dirname "$0")/../.."
. scripts/release/lib.sh

REF=${1:-HEAD}
DIST=${2:-dist/control}
JOBS=${JOBS:-8}
MEM=${MEM:-16g}
CT=$(release_container)

commit=$(git rev-parse "$REF^{commit}")
stamp=$(git rev-parse --short=10 "$commit")
epoch=$(release_epoch "$commit")
version=$(git show "$commit:apps/tenzro-control/src-tauri/tauri.conf.json" | jq -r .version)
case "$(uname -m)" in
    x86_64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) echo "REFUSING: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
name="tenzro-control-linux-$arch-$version"

ctx=$(mktemp -d)
image="tenzro-control:$arch-$stamp"
cleanup() { rm -rf "$ctx"; [ -n "${cid:-}" ] && $CT rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git archive --format=tar "$commit" | tar -x -C "$ctx"

echo "target: $name  ref: $stamp  ($JOBS jobs, memory cap $MEM, $CT)"
started=$(date +%s)
limits=(--memory "$MEM")
[ "$CT" = docker ] && limits=(--memory "$MEM" --memory-swap "$MEM")
$CT build "${limits[@]}" --file "$ctx/scripts/release/Dockerfile.control" --tag "$image" \
    --build-arg "CARGO_BUILD_JOBS=$JOBS" --build-arg "SOURCE_DATE_EPOCH=$epoch" "$ctx"

mkdir -p "$DIST"
out=$(cd "$DIST" && pwd)
cid=$($CT create "$image")
$CT cp "$cid:/out/." "$out/"
mv "$out/tenzro-control" "$out/$name.bin"
(cd "$out" && sha256sum ./*.deb ./*.rpm "$name.bin" | sed 's| \./| |' > SHA256SUMS)
jq -n --arg artifact "$name" --arg commit "$commit" --arg version "$version" \
    --arg rust "$(release_rust)" --arg image "$image" \
    --arg cargo_lock "$(git show "$commit:apps/tenzro-control/src-tauri/Cargo.lock" | release_sha256)" \
    --arg npm_lock "$(git show "$commit:apps/tenzro-control/package-lock.json" | release_sha256)" \
    --arg builder "$(uname -s)-$(uname -m)" --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{artifact: $artifact, commit: $commit, version: $version, rust: $rust,
      cargo_lock_sha256: $cargo_lock, npm_lock_sha256: $npm_lock, container_image: $image,
      builder: $builder, built: $built, locked: true}' > "$out/$name.buildenv.json"
echo "built in $(( $(date +%s) - started ))s:"
cat "$out/SHA256SUMS"
