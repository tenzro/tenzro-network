#!/bin/bash
# Build the container image of one Linux release archive. Nothing is compiled:
# the image carries the archive's own binaries (and, for cuda, its ONNX Runtime
# libraries) on a base image pinned by digest, so it ships exactly what the
# archive ships. The archive must already be in the dist directory, written by
# build-linux.sh, which runs this script at its end.
#
#   cpu     Ubuntu 24.04, the base of the CPU build's own Dockerfile
#   vulkan  the same, with the Vulkan loader and the Mesa Vulkan drivers
#   cuda    the CUDA runtime image that Dockerfile.cuda runs on
#
# The image runs as uid 10001, keeps everything on the /data/tenzro volume,
# checks itself with the node's own /health endpoint, and refuses to start
# without the host TPM (/dev/tpmrm0) and the node's service credential.
#
# Tags: tenzro-node:launch-<commit>-<flavour>-<amd64|arm64> and
# tenzro-node:launch-<flavour>-<amd64|arm64>. The image is saved beside the
# archive as tenzro-node-image-linux-<arch>-<flavour>.tar with a .image.json
# record; publishing (multi-arch manifests per tag, registry push) is a later
# release step. This script never pushes.
#
# Usage: scripts/release/build-image.sh <x86_64|aarch64> <cpu|cuda|vulkan> [dist-dir]
set -euo pipefail

ARCH=${1:?usage: build-image.sh <x86_64|aarch64> <cpu|cuda|vulkan> [dist-dir]}
FLAVOUR=${2:?usage: build-image.sh <x86_64|aarch64> <cpu|cuda|vulkan> [dist-dir]}
DIST=${3:-$HOME/dist}
RELEASE=launch

case "$ARCH" in x86_64) platform=amd64 ;; aarch64) platform=arm64 ;; *) echo "REFUSING: unknown arch $ARCH"; exit 1 ;; esac
case "$FLAVOUR" in cpu|cuda|vulkan) ;; *) echo "REFUSING: unknown flavour $FLAVOUR"; exit 1 ;; esac
# The base image's package installs run natively; no emulation.
[ "$(uname -m)" = "$ARCH" ] || { echo "REFUSING: build host is $(uname -m), not $ARCH"; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
. "$repo/scripts/release/lib.sh"
CT=$(release_container)

name="tenzro-node-linux-$ARCH-$FLAVOUR"
archive="$DIST/$name.tar.gz"
[ -f "$archive" ] && [ -f "$DIST/$name.buildenv.json" ] || { echo "REFUSING: $archive or its .buildenv.json is missing"; exit 1; }
commit=$(jq -r .commit "$DIST/$name.buildenv.json")
[ "$(jq -r .flavour "$DIST/$name.buildenv.json")" = "$FLAVOUR" ] || { echo "REFUSING: $name.buildenv.json is not a $FLAVOUR build"; exit 1; }
short=${commit:0:8}

# Base images: the same pinned digests the release builds use.
ubuntu=$(sed -n 's/^FROM \([^ ]*ubuntu:24.04@sha256:[0-9a-f]*\).*/\1/p' "$repo/Dockerfile" | tail -1)
cuda=$(sed -n 's/^FROM \([^ ]*cuda:[^ ]*runtime[^ ]*@sha256:[0-9a-f]*\).*/\1/p' "$repo/Dockerfile.cuda" | head -1)
case "$FLAVOUR" in
    cpu)    base=$ubuntu; packages="libssl3t64 libstdc++6" ;;
    vulkan) base=$ubuntu; packages="libssl3t64 libstdc++6 libvulkan1 mesa-vulkan-drivers" ;;
    cuda)   base=$cuda;   packages="libssl3t64" ;;
esac
[ -n "$base" ] || { echo "REFUSING: no pinned base image found for $FLAVOUR"; exit 1; }

ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
tar -xzf "$archive" -C "$ctx"
mv "$ctx/$name" "$ctx/archive"
mkdir -p "$ctx/archive/lib"
# Only the shared libraries the node loads go into the image.
find "$ctx/archive/lib" -mindepth 1 -maxdepth 1 ! -name 'libonnxruntime*' -exec rm -rf {} +
cp "$repo/scripts/release/image/Dockerfile" "$repo/scripts/release/image/entrypoint.sh" "$ctx/"

tag="tenzro-node:$RELEASE-$short-$FLAVOUR-$platform"
moving="tenzro-node:$RELEASE-$FLAVOUR-$platform"
format=(); [ "${CT%% *}" = podman ] && format=(--format docker)   # keeps HEALTHCHECK
echo "image: $tag from $name ($base)"
$CT build "${format[@]}" --platform "linux/$platform" --file "$ctx/Dockerfile" \
    --build-arg "BASE=$base" --build-arg "PACKAGES=$packages" \
    --build-arg "FLAVOUR=$FLAVOUR" --build-arg "COMMIT=$commit" --build-arg "VERSION=$RELEASE" \
    --tag "$tag" --tag "$moving" "$ctx"

# --- prove the image: same binaries, unprivileged, refuses without a TPM ---
for bin in tenzro-node tenzro; do
    want=$(release_sha256 < "$ctx/archive/bin/$bin")
    got=$($CT run --rm --network none --entrypoint sha256sum "$tag" "/usr/local/bin/$bin" | cut -d' ' -f1)
    [ "$want" = "$got" ] || { echo "REFUSING: /usr/local/bin/$bin in the image is not the archive's"; exit 1; }
done
uid=$($CT run --rm --network none --entrypoint id "$tag" -u)
[ "$uid" = 10001 ] || { echo "REFUSING: the image runs as uid $uid, not 10001"; exit 1; }
$CT run --rm --network none "$tag" --version
set +e
out=$($CT run --rm --network none "$tag" 2>&1); rc=$?
set -e
[ $rc = 78 ] && echo "$out" | grep -q "no TPM" \
    || { echo "REFUSING: without /dev/tpmrm0 the image did not refuse (exit $rc): $out"; exit 1; }
echo "without a TPM: $(echo "$out" | head -1)"
$CT image inspect --format '{{json .Config.Healthcheck}}' "$tag" | grep -q '/health' \
    || { echo "REFUSING: the image has no health check"; exit 1; }

out="$DIST/tenzro-node-image-linux-$ARCH-$FLAVOUR.tar"
rm -f "$out"
if [ "${CT%% *}" = podman ]; then
    $CT save --format docker-archive -o "$out" "$tag" "$moving"
else
    $CT save -o "$out" "$tag" "$moving"
fi
id=$($CT image inspect --format '{{.Id}}' "$tag")
jq -n --arg image "$tag" --arg moving "$moving" --arg id "$id" --arg commit "$commit" \
    --arg flavour "$FLAVOUR" --arg platform "linux/$platform" --arg base "$base" \
    --arg archive "$(basename "$archive")" --arg archive_sha256 "$(release_sha256 < "$archive")" \
    --arg file "$(basename "$out")" --arg sha256 "$(release_sha256 < "$out")" \
    '{image: $image, tags: [$image, $moving], id: $id, commit: $commit, flavour: $flavour,
      platform: $platform, base: $base, archive: $archive, archive_sha256: $archive_sha256,
      file: $file, sha256: $sha256}' > "${out%.tar}.image.json"
echo "IMAGE OK: $out"
