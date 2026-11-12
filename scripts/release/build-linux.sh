#!/bin/bash
# Build the Linux release artifacts of tenzro-node and the CLI on a Linux build
# host of the target architecture with podman or docker. No GPU is needed for
# any of them.
#
#   cpu   Dockerfile        (Ubuntu 24.04, glibc 2.39 floor)
#   cuda  Dockerfile.cuda   (Ubuntu 24.04, CUDA 13, glibc 2.39 floor); it also
#                           compiles ONNX Runtime with the CUDA and TensorRT
#                           providers for the host architecture
#   edge  Dockerfile with NODE_BUILD=edge (aarch64 only): the light build for
#         the edge tier, no model engines, the edge profile; the CLI as for cpu
#   vulkan Dockerfile.vulkan (Ubuntu 24.04, glibc 2.39 floor); llama.cpp's
#                           Vulkan backend for AMD, Intel and NVIDIA GPUs,
#                           linked against the Vulkan loader (libvulkan.so.1)
#
# x86_64 artifacts build on an x86_64 host, aarch64 artifacts on an aarch64 host.
#
# The source is a `git archive` of a committed ref, never the working tree, and
# every cargo invocation is --locked with the toolchain from rust-toolchain.toml.
# The glibc a binary links against is part of the deliverable, which is why the
# build runs in a pinned image rather than on the host.
#
# Width is bounded by memory, not cores: the ggml-cuda flash-attention kernels
# peak around 2 GB per translation unit. JOBS and MEM (container memory cap,
# default 24g) bound the build. The ONNX Runtime CUDA kernels compiled for the
# CUDA image take far more per unit, so ORT_JOBS defaults to one job per 8 GB (two jobs peaked at 13 GB with all six x86_64 architectures)
# of the cap.
#
# After the archive, the script builds its container image with
# scripts/release/build-image.sh (from the archive's binaries; IMAGE=0 skips).
#
# Usage: scripts/release/build-linux.sh <x86_64|aarch64> <cpu|cuda|vulkan|edge> [ref] [dist-dir]
set -euo pipefail

ARCH=${1:?usage: build-linux.sh <x86_64|aarch64> <cpu|cuda|vulkan|edge> [ref] [dist-dir]}
FLAVOUR=${2:?usage: build-linux.sh <x86_64|aarch64> <cpu|cuda|vulkan|edge> [ref] [dist-dir]}
REF=${3:-HEAD}
DIST=${4:-$HOME/dist}
MEM=${MEM:-24g}
# The BuildKit image a docker host builds in, by digest.
BUILDKIT_IMAGE=docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5
mem_gb=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 / 1024 ))
JOBS=${JOBS:-$(( mem_gb / 2 < $(nproc) ? mem_gb / 2 : $(nproc) ))}
[ "$JOBS" -ge 1 ] || JOBS=1
cap_gb=$(numfmt --from=iec "${MEM^^}" | awk '{print int($1 / 1073741824)}')
ORT_JOBS=${ORT_JOBS:-$(( cap_gb / 8 ))}
[ "$ORT_JOBS" -ge 1 ] || ORT_JOBS=1

case "$ARCH/$FLAVOUR" in
    x86_64/cpu|x86_64/cuda|x86_64/vulkan|aarch64/cpu|aarch64/cuda|aarch64/vulkan|aarch64/edge) ;;
    *) echo "REFUSING: unknown target $ARCH/$FLAVOUR"; exit 1 ;;
esac
[ "$(uname -m)" = "$ARCH" ] || { echo "REFUSING: build host is $(uname -m), not $ARCH"; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
. scripts/release/lib.sh
CT=$(release_container)

commit=$(git rev-parse --verify "$REF^{commit}")
stamp=$(git rev-parse --short "$commit")
epoch=$(release_epoch "$commit")
name="tenzro-node-linux-$ARCH-$FLAVOUR"
features=""
case "$FLAVOUR" in cpu) ;; edge) features="light (no default features, edge profile)" ;; *) features="tenzro-node/$FLAVOUR" ;; esac

ctx=$(mktemp -d)
stage=$(mktemp -d)/$name
mkdir -p "$stage/bin"
cleanup() { rm -rf "$ctx" "$(dirname "$stage")" ${dbg:+$(dirname "$dbg")}; [ -n "${cid:-}" ] && $CT rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git archive --format=tar "$commit" | tar -x -C "$ctx"

echo "target: $name  ref: $stamp  ($JOBS jobs, memory cap $MEM, $CT)"
started=$(date +%s)

file=Dockerfile; case "$FLAVOUR" in cpu|edge) ;; *) file=Dockerfile.$FLAVOUR ;; esac
node_build=standard; [ "$FLAVOUR" = edge ] && node_build=edge
image="tenzro-node:$FLAVOUR-$ARCH-$stamp"
if [ "$CT" = docker ]; then
    # Docker's BuildKit takes no per-build memory cap, so the build runs in a
    # container builder capped at MEM and JOBS cores, at the lowest CPU weight.
    builder="tenzro-release-$MEM-$JOBS"
    docker buildx inspect "$builder" >/dev/null 2>&1 || docker buildx create --name "$builder" \
        --driver docker-container \
        --driver-opt "image=$BUILDKIT_IMAGE" \
        --driver-opt "memory=$MEM,memory-swap=$MEM,cpu-quota=$(( JOBS * 100000 )),cpu-period=100000,cpu-shares=2" >/dev/null
    limits=(--builder "$builder" --load)
else
    limits=(--memory "$MEM")
fi
$CT build "${limits[@]}" --file "$ctx/$file" --tag "$image" \
    --build-arg "CARGO_BUILD_JOBS=$JOBS" --build-arg "ORT_JOBS=$ORT_JOBS" --build-arg "NODE_BUILD=$node_build" --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    ${ORT_CUDA_ARCHITECTURES:+--build-arg "ORT_CUDA_ARCHITECTURES=$ORT_CUDA_ARCHITECTURES"} "$ctx"
cid=$($CT create "$image")
$CT cp "$cid:/usr/local/bin/tenzro-node" "$stage/bin/tenzro-node"
$CT cp "$cid:/usr/local/bin/tenzro-cli" "$stage/bin/tenzro"
# Split debug information (build-id matched), packed beside the archive, never inside it.
dbg=$(mktemp -d)/$name-debug
mkdir -p "$dbg"
$CT cp "$cid:/usr/local/share/tenzro-debug/." "$dbg/"
# The installer travels with the archive it installs.
install -m 755 "$ctx/scripts/release/tenzro-node-install" "$stage/tenzro-node-install"
release_network_profile "$ctx" "$stage"
if [ "$FLAVOUR" = cuda ]; then
    mkdir -p "$stage/lib"
    # ONNX Runtime and its providers, symlinks kept; stdout carries only the tar.
    $CT run --rm --entrypoint /bin/sh "$image" -c 'cd /usr/local/lib && tar -c libonnxruntime*' \
        | tar -x -C "$stage/lib"
fi
echo "built in $(( ($(date +%s) - started) / 60 )) min"

# --- prove the flavour: a DONE marker is not proof ---------------------------
node="$stage/bin/tenzro-node"
want=x86-64; [ "$ARCH" = aarch64 ] && want=aarch64
file "$node" | grep -q "$want" || { echo "REFUSING: not a $ARCH ELF"; exit 1; }
if [ "$FLAVOUR" = cuda ]; then
    grep -qa ggml_cuda_init "$node" || { echo "REFUSING: no ggml_cuda symbols in a cuda build"; exit 1; }
    for lib in libonnxruntime.so.1 libonnxruntime_providers_shared.so libonnxruntime_providers_cuda.so; do
        [ -e "$stage/lib/$lib" ] || { echo "REFUSING: lib/$lib missing from a cuda build"; exit 1; }
    done
else
    ! grep -qa ggml_cuda_init "$node" || { echo "REFUSING: ggml_cuda symbols in a $FLAVOUR build"; exit 1; }
fi
if [ "$FLAVOUR" = vulkan ]; then
    grep -qa 'ggml_vulkan:' "$node" || { echo "REFUSING: no Vulkan backend in a vulkan build"; exit 1; }
    readelf -d "$node" | grep -q 'NEEDED.*\[libvulkan\.so\.1\]' \
        || { echo "REFUSING: a vulkan build that does not link the Vulkan loader"; exit 1; }
else
    ! grep -qa 'ggml_vulkan:' "$node" || { echo "REFUSING: the Vulkan backend in a $FLAVOUR build"; exit 1; }
fi
! grep -qa ggml_cuda_init "$stage/bin/tenzro" || { echo "REFUSING: the CLI carries the CUDA backend"; exit 1; }
! grep -qa 'ggml_vulkan:' "$stage/bin/tenzro" || { echo "REFUSING: the CLI carries the Vulkan backend"; exit 1; }
# A load-time dependency on the GPU driver would stop the binary before it can
# refuse on a host without a GPU; the driver is resolved at runtime instead.
for bin in "$stage/bin/tenzro-node" "$stage/bin/tenzro"; do
    if readelf -d "$bin" | grep -q 'NEEDED.*\[libcuda\.so'; then
        echo "REFUSING: $(basename "$bin") links the CUDA driver library"; exit 1
    fi
done
if [ "$FLAVOUR" = edge ]; then
    ! grep -qa ggml_init "$node" || { echo "REFUSING: the model engines in an edge build"; exit 1; }
    # Built on the target architecture, so its own check runs here.
    "$node" hardware 2>/dev/null | grep -qx "build: light" || { echo "REFUSING: an edge build that does not report the light build"; exit 1; }
fi
echo "glibc floor: $(objdump -T "$node" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"

mkdir -p "$DIST"
release_pack "$stage" "$DIST/$name.tar.gz" "$epoch"
for b in tenzro-node tenzro; do readelf -n "$stage/bin/$b" | grep -i "build id" | sed "s/^ */$b /" >> "$dbg/BUILD-IDS.txt"; done
release_pack "$dbg" "$DIST/$name-debug.tar.gz" "$epoch"
release_buildenv "$DIST/$name.buildenv.json" "$name" "$commit" "$FLAVOUR" "$ARCH-unknown-linux-gnu" \
    "$features" "$image@$($CT image inspect --format '{{.Id}}' "$image")"
echo "BUILD OK: $DIST/$name.tar.gz"

# The container image of this archive, from its binaries (IMAGE=0 skips it).
# An edge archive has none: edge machines run the archive itself.
[ "${IMAGE:-1}" = 0 ] || [ "$FLAVOUR" = edge ] || bash scripts/release/build-image.sh "$ARCH" "$FLAVOUR" "$DIST"
