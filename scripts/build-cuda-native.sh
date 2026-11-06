#!/bin/bash
# Build tenzro-node with real CUDA support natively on a Linux host that has
# the CUDA toolkit installed (x86_64 or aarch64, discrete or unified memory).
#
# The C and C++ compilers are the system gcc (llama-cpp-sys-2's CMake cache
# records /usr/bin/cc and /usr/bin/c++ beside nvcc). Do not export CC=clang: aws-lc-sys then configures
# through a CMake path that requires Go, which the host does not have, and the
# build dies before reaching this workspace.
#
# CMAKE_CUDA_ARCHITECTURES / CUDAARCHS must be UNSET. ggml picks its own
# architecture list; setting one produces a binary that serves every layer on
# the CPU while the build reports success.
#
# The build runs in its own bounded systemd unit, never in the invoking shell:
#
#   * On a host where user.slice is capped (a memory.high on the user slice), a build
#     in a shell is throttled and thrashes instead of failing, and looks like a
#     hang for hours.
#   * Unbounded, a link step across every core once exhausted RAM into a swap
#     livelock that needed a physical power-cycle, with nothing OOM-logged. On a
#     machine with no out-of-band console that is an outage.
#   * Unified-memory GPU allocations are invisible to cgroups, so the model the
#     node is serving is not counted against the bound. The script therefore also
#     refuses to start without real headroom, measured, not assumed.
#
# ONNX Runtime. The `cuda` feature also enables ONNX Runtime's CUDA and
# TensorRT providers. On x86_64 ort downloads a CUDA 12 ONNX Runtime unless
# ORT_LIB_LOCATION is set. On aarch64 no CUDA download exists (ort would
# quietly fetch a CPU-only one), so ORT_LIB_LOCATION is REQUIRED there: the
# install prefix of a CUDA-enabled ONNX Runtime (lib/libonnxruntime.so plus
# lib/libonnxruntime_providers_cuda.so and _shared.so), for example the prefix
# Dockerfile.cuda's ort-cuda stage produces. The binary links it dynamically
# with an rpath to $ORT_LIB_LOCATION/lib. Either way, the node refuses to start
# on an NVIDIA machine if its ONNX Runtime lacks the CUDA provider.
#
# Knobs (all optional): TENZRO_BUILD_MIN_AVAILABLE_GB (default 48),
# TENZRO_BUILD_MEMORY_HIGH / TENZRO_BUILD_MEMORY_MAX (36G / 40G),
# CARGO_BUILD_JOBS (8), ORT_LIB_LOCATION (required on aarch64).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${ORT_LIB_LOCATION:-}" ] && [ "$(uname -m)" != "x86_64" ]; then
    echo "REFUSING: set ORT_LIB_LOCATION to a CUDA-enabled ONNX Runtime prefix; on $(uname -m) ort has no CUDA download and would link a CPU-only ONNX Runtime." >&2
    exit 1
fi
if [ -n "${ORT_LIB_LOCATION:-}" ] && [ ! -f "${ORT_LIB_LOCATION}/lib/libonnxruntime_providers_cuda.so" ]; then
    echo "REFUSING: ${ORT_LIB_LOCATION}/lib has no libonnxruntime_providers_cuda.so, so it is not a CUDA ONNX Runtime." >&2
    exit 1
fi

if [ -z "${TENZRO_BUILD_BOUNDED:-}" ]; then
    avail=$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)
    need=${TENZRO_BUILD_MIN_AVAILABLE_GB:-48}
    if [ "$avail" -lt "$need" ]; then
        echo "REFUSING: ${avail} GiB available, and a CUDA build of tenzro-node needs ${need} GiB of headroom." >&2
        exit 1
    fi
    unit="tenzro-build-$(date +%Y%m%d-%H%M%S)"
    echo "building in transient unit ${unit} (MemoryMax ${TENZRO_BUILD_MEMORY_MAX:-40G}, ${avail} GiB available)"
    exec sudo -n systemd-run --unit="$unit" --wait --collect --pipe --quiet \
        --uid="$(id -u)" --gid="$(id -g)" \
        -p MemoryHigh="${TENZRO_BUILD_MEMORY_HIGH:-36G}" \
        -p MemoryMax="${TENZRO_BUILD_MEMORY_MAX:-40G}" \
        -p CPUWeight=20 -p IOWeight=20 -p Nice=10 \
        -E HOME="$HOME" -E TENZRO_BUILD_BOUNDED=1 \
        -E CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" \
        -E ORT_LIB_LOCATION="${ORT_LIB_LOCATION:-}" \
        --working-directory="$REPO" \
        /bin/bash "$REPO/scripts/build-cuda-native.sh"
fi

export PATH=/usr/local/cuda/bin:$HOME/.cargo/bin:$PATH
unset CC CXX CUDAHOSTCXX
unset CMAKE_CUDA_ARCHITECTURES CUDAARCHS
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}
if [ -n "${ORT_LIB_LOCATION:-}" ]; then
    export ORT_SKIP_DOWNLOAD=1
    # ort-sys 2.0.0-rc.11 and later link the prefix statically unless asked for the dynamic link, which searches
    # only the directory it is given: the lib/ of the prefix, as ORT_LIB_PATH (read before ORT_LIB_LOCATION).
    export ORT_PREFER_DYNAMIC_LINK=1
    export ORT_LIB_PATH="${ORT_LIB_LOCATION}/lib"
    export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-rpath,${ORT_LIB_LOCATION}/lib"
else
    unset ORT_LIB_LOCATION
fi

cd "$REPO"
echo "=== HEAD ==="
git log --oneline -1
echo "=== nvcc ==="
nvcc --version | tail -2
echo "=== building (release, cuda) ==="
date -u +%H:%M:%S
cargo build --release --locked -p tenzro-node --features tenzro-node/cuda
date -u +%H:%M:%S

# The only honest check. `nm -D` gives false negatives on stripped release
# binaries and returns 0 even for working CUDA builds.
n=$(strings target/release/tenzro-node | grep -c ggml_cuda || true)
echo "=== ggml_cuda symbols: ${n} (0 = CPU-only, hundreds = real CUDA) ==="
if [ "$n" -eq 0 ]; then
    echo "CPU-ONLY BINARY: the build succeeded but would serve every layer on the CPU." >&2
    exit 1
fi

# ONNX Runtime: a linked CUDA prefix, or the downloaded CUDA provider libraries
# placed beside the binary. Ship everything this lists with the binary.
if [ -n "${ORT_LIB_LOCATION:-}" ]; then
    if ! ldd target/release/tenzro-node | grep -q "${ORT_LIB_LOCATION}/lib/libonnxruntime"; then
        echo "ONNX RUNTIME NOT LINKED from ${ORT_LIB_LOCATION}/lib." >&2
        exit 1
    fi
    echo "=== ONNX Runtime: ${ORT_LIB_LOCATION}/lib (install it at the same path on the target) ==="
else
    if [ ! -e target/release/libonnxruntime_providers_cuda.so ]; then
        echo "CPU-ONLY ONNX RUNTIME: no libonnxruntime_providers_cuda.so beside the binary." >&2
        exit 1
    fi
    echo "=== ONNX Runtime providers (ship beside the binary): ==="
    ls -1 target/release/libonnxruntime_providers_*.so
fi
echo "=== BUILD OK ==="
