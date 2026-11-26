# GPU Provider Kit (documentation)

For people serving models on NVIDIA GPUs alongside a Tenzro node. This is documentation and one example, not a separate SDK: CUDA is a compute API, and the Tenzro client here only talks JSON-RPC.

## CUDA compute capabilities in Tenzro builds

As provided by the Tenzro project (stated, not re-derived or re-verified here):

| Build | SM targets |
|---|---|
| x86_64 | 80; 86; 89; 90; 100; 120 |
| aarch64 | 90; 110; 121 |
| aarch64, Jetson Orin build | adds 87 |

To find your card's capability: `nvidia-smi --query-gpu=name,compute_cap --format=csv` (the `compute_cap` field needs a reasonably recent driver) and check that the value (e.g. `8.9` = 89) appears in the table for your architecture. A GPU whose capability is not listed may not run the shipped binaries.

## Driver, CUDA, cuDNN, TensorRT

**Unverified:** I did not check current NVIDIA vendor pages against the SM list above, and I am not asserting exact minimum versions. General points that are widely documented but should be confirmed on NVIDIA's pages before relying on them:

- The driver must be new enough for the CUDA toolkit used to build the binaries, and for newer architectures (the 100/110/120/121 targets are recent) you will generally need a recent driver and CUDA 12.x or later toolkit.
- cuDNN and TensorRT builds are tied to specific CUDA major versions; match them to the toolkit the Tenzro build used.
- Jetson devices use JetPack-provided drivers and libraries rather than the desktop driver.

Ask the Tenzro release notes for the exact toolkit/cuDNN/TensorRT versions of a given build.

## Example: `examples/cuda/main.cpp`

Shows the integration point: run a GPU check, then use `tenzro::Client` to confirm chain id and node health before advertising capacity.

- Builds CPU-only by default (`tenzro_cuda_sample` target). Add `-DTENZRO_HAVE_CUDA` and link `cudart` to include a device-property query.
- `gpu_doctor()` wraps `nvidia-smi --query-gpu=name,driver_version,compute_cap`.

**Test status:** the CPU-only build was compiled and run on a host with no NVIDIA GPU or driver; it printed "nvidia-smi unavailable ... CPU-only mode", then the live-node status check succeeded. `gpu_doctor`'s success path and the `TENZRO_HAVE_CUDA` path were **never run on real GPU hardware** and are unverified.
