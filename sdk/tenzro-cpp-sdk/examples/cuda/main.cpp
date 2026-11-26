// CUDA-aware application integration sketch.
//
// Builds CPU-only by default (no CUDA toolkit needed). With -DTENZRO_HAVE_CUDA
// and cuda_runtime.h available, it also queries device properties through the
// CUDA runtime API (compile with nvcc or link cudart).
//
// STATUS: the Tenzro client calls are tested against a live dev node. The
// nvidia-smi / CUDA runtime paths were NOT run on real GPU hardware by the
// author (the build host had no NVIDIA GPU or driver) - treat as unverified.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <tenzro/client.hpp>

#ifdef TENZRO_HAVE_CUDA
#include <cuda_runtime.h>
#endif

// "Doctor"-style GPU check. UNVERIFIED on real hardware.
// Returns true if nvidia-smi ran and listed at least one GPU.
static bool gpu_doctor() {
    FILE* p = popen("nvidia-smi --query-gpu=name,driver_version,compute_cap --format=csv,noheader 2>/dev/null", "r");
    if (!p) { std::puts("[doctor] cannot spawn nvidia-smi"); return false; }
    char line[256]; int n = 0;
    while (std::fgets(line, sizeof line, p)) { std::printf("[doctor] gpu: %s", line); n++; }
    int rc = pclose(p);
    if (rc != 0 || n == 0) { std::puts("[doctor] nvidia-smi unavailable or no GPU found (CPU-only mode)"); return false; }
    // compute_cap (e.g. "8.9") should map to one of the SM targets listed in docs/gpu-provider.md.
#ifdef TENZRO_HAVE_CUDA
    int count = 0;
    if (cudaGetDeviceCount(&count) == cudaSuccess)
        for (int i = 0; i < count; i++) {
            cudaDeviceProp pr; cudaGetDeviceProperties(&pr, i);
            std::printf("[doctor] cuda dev %d: %s sm_%d%d\n", i, pr.name, pr.major, pr.minor);
        }
#endif
    return true;
}

int main(int argc, char** argv) {
    const char* env = std::getenv("TENZRO_RPC_URL");
    std::string endpoint = argc > 1 ? argv[1] : (env ? env : "http://127.0.0.1:28545");

    bool has_gpu = gpu_doctor();

    // Integration point: before advertising GPU capacity, confirm you are on
    // the intended chain and the node is healthy.
    tenzro::Client c(endpoint, 13380);
    if (!c.valid()) { std::fprintf(stderr, "bad endpoint\n"); return 2; }
    auto st = c.status();
    if (!st) { std::fprintf(stderr, "node check failed: %s\n", st.error().message.c_str()); return 1; }
    std::printf("node healthy=%d block=%llu; gpu_present=%d\n", st.value().healthy,
                (unsigned long long)st.value().block_number, (int)has_gpu);
    return 0;
}
