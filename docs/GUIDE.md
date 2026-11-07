# Tenzro Network — Local Run Guide

Build and run a Tenzro node, the CLI, and the desktop app from source. Covers Linux, macOS, and Docker, plus a troubleshooting catalog for the most common build failures.

Tenzro is an open network for the machine economy: machines from small edge devices to the largest GPU servers sell AI work, and agents and apps buy it, under one identity model and one payment rail. Which part you run depends on your machine:

| You have | Build | Start with |
|---|---|---|
| A small, embedded or edge device (Raspberry Pi, Jetson-class module, mini PC, NAS, gateway) | `scripts/build-tier.sh edge` (the light build, no model engines) | §4.2 and [NODE.md, Node tiers](NODE.md#node-tiers) |
| A CPU server or workstation | `cargo build --release -p tenzro-node` (the standard build) | §4.1 to §4.3 |
| One or more GPUs | `scripts/build-tier.sh provider cuda` (or another backend, §3.2) | §4.3 and §4.9 |
| A server to validate on | `scripts/build-tier.sh validator` | §4.1 and §4.8 |

`--tier auto` (the default) sizes the node's storage and threads to the machine it finds; [NODE.md](NODE.md#resource-presets) lists the presets.

The network opens in phases: a preview, then a testnet, then the stages governance decides on the way to mainnet. A preview chain can be reset and carries test tokens.

---

## 0. Quickstart (public endpoints)

If you only want to *use* a model — send a prompt to a provider that already
serves it, with no node and no weights — call a provider's public RPC through
one of the SDKs (TypeScript, Python or Rust) instead of running the full node
CLI.

| SDK | Install | Source and reference |
| --- | --- | --- |
| TypeScript | `npm install tenzro-sdk` (and `@tenzro/device-key` where a TPM or Secure Enclave signs) | `sdk/tenzro-ts-sdk`, [README](../sdk/tenzro-ts-sdk/README.md), [API.md](../sdk/tenzro-ts-sdk/API.md) |
| Python | not yet published to PyPI; install from this repository (`pip install ./sdk/tenzro-py`) until it ships | `sdk/tenzro-py`, [README](../sdk/tenzro-py/README.md) |
| Rust | `cargo add tenzro-sdk` | `sdk/tenzro-sdk`, [README](../sdk/tenzro-sdk/README.md), docs.rs |

Each SDK defaults to the preview network (chain id 13380, `https://rpc.tenzro.com`)
and finds the staked RPC operators on chain; each also takes one endpoint,
such as the local chain `tenzro dev` serves (chain id 1337, `http://127.0.0.1:8545`).
The snippets below are written against what each SDK's current published
registry version actually exposes (TypeScript `tenzro-sdk` 0.7.0, Rust
`tenzro-sdk` 0.7.0): a client built from an endpoint and chain id, not the
newer network-auto-discovery helper (`connectToNetwork` / `connect_to_network`),
which lands in a later registry release; building from this repository gets
that helper today.

```typescript
import pkg from "tenzro-sdk";
const { TenzroClient } = pkg;
const preview = new TenzroClient({ endpoint: "https://rpc.tenzro.com", chainId: 13380 });
const local = new TenzroClient({ endpoint: "http://127.0.0.1:8545", chainId: 1337 });
console.log(await local.getChainId(), await local.getBalance("0x<32-byte account address>"));
```

```python
# from source until the package is published (see the Install row above)
from tenzro import NetworkRpcClient, RpcClient
preview = NetworkRpcClient.connect()
local = RpcClient("http://127.0.0.1:8545")
print(int(local.eth_chain_id(), 16), local.get_balance(["0x<32-byte account address>"]))
```

```rust
let preview = tenzro_sdk::TenzroClient::new("https://rpc.tenzro.com").await?;
let local = tenzro_sdk::TenzroClient::new("http://127.0.0.1:8545").await?;
println!("{} {}", local.get_chain_id().await?, local.get_balance(address).await?);
```

Every method the node serves has a named binding in each SDK and is also
reachable by name through the gateway; see [SURFACES.md](SURFACES.md). The SDK
never signs with a software key: transactions are signed by the machine's TPM
or Secure Enclave, or by a passkey in a browser.

## Quickstart: a local developer chain

`tenzro dev` starts a single-validator chain on your machine for building
against Tenzro: quarter-second rounds, one-minute epochs, chain id 1337, the
full JSON-RPC on `127.0.0.1:8545`, and your accounts funded at genesis.

```bash
tenzro dev                                 # a new chain under ~/.tenzro/dev
tenzro dev --fund 0x<passkey account>      # also fund an account you hold with a passkey
tenzro wallet balance                      # in another terminal: the funded client account
```

Every key is held by the machine's hardware, as on the network: the
validator and node identity keys in the TPM (Linux, Windows) or the Secure
Enclave (macOS), and the funded client account in the CLI's own hardware key
(namespace `client`, the account the other commands sign with). Nothing is
generated in software or written to a file. On a machine with neither a TPM
nor a Secure Enclave, `tenzro dev` refuses and says so; it never falls back to
a software key. Each funded account starts with 1,000,000 TNZO.

The chain lives in its data directory (`--data-dir`, default
`~/.tenzro/dev`): run `tenzro dev` again to resume it, or remove the directory
to start over. It dials no one and no one dials it. `tenzro-node --dev --fund
<address>` is the same chain without the CLI.

## Building on the network

Every application on Tenzro uses the same open surfaces, with no privileged builder: managed model access, agent harnesses, secure agent deployments and billing of your own are all built from the pieces below.

- **Nodes and RPC.** Use the public endpoints, run your own node (§4), or serve RPC to your own tenants as an RPC provider ([ACCESS.md](ACCESS.md), [RPC.md](RPC.md)).
- **SDKs.** TypeScript (`sdk/tenzro-ts-sdk`), Python (`sdk/tenzro-py`) and Rust (`sdk/tenzro-sdk`) cover identity, wallets, models, inference, payments, settlement and agents. Agent harnesses connect over MCP, either to the full tool list at `/mcp` or to `search` and `call` at `/mcp/compact` ([CODE-GENERATING-HARNESSES.md](CODE-GENERATING-HARNESSES.md), [MCP.md](MCP.md)).
- **Terms and payments.** A delegated agent acts only within Terms its human (passkey) or machine root signed: assets, limits, tools and counterparties ([AGENT_ACCOUNTS.md](AGENT_ACCOUNTS.md)). It pays over x402, MPP, AP2 or ACP, in TNZO or in a stablecoin ([architecture/machine-payments.md](architecture/machine-payments.md)).
- **Taking payments.** Any identity can be a payee: price a service, accept the assets you list, and divide one payment between several payees with a split rule, each paid directly. Settlements can name the app, agent and tool behind a payment, and their creators earn from it ([ECONOMICS.md](ECONOMICS.md), [TOKENOMICS.md](TOKENOMICS.md)).
- **Records and attestation.** Every tool call through a node is a signed record, packs export with an EU AI Act profile and verify offline, trained models carry provenance receipts, and private weights are released only to attested environments ([AGENT_TRUST.md](AGENT_TRUST.md), [AI.md](AI.md)).
- **Covering users' fees.** A user needs no TNZO, key or account when your app sponsors its calls: a delegated agent you fund from your own account pays the provider for each call, within Terms that name the provider's node and the models you cover ([SPONSORED-INFERENCE.md](SPONSORED-INFERENCE.md)).
- **NVIDIA OpenShell.** The SDKs turn an OpenShell sandbox policy into Terms, keep credentials under those Terms and verify sandbox session records offline ([OPENSHELL.md](OPENSHELL.md)).

## Prebuilt binaries

Every release publishes the node and the CLI as the archives below, and the
release page lists exactly the archives of that release. Each archive is a CPU
build or a GPU build, and both are official; nobody has to build from source.
A build that is not in the table (a CPU build for Linux aarch64 or Windows,
a Vulkan build, the light edge build) is built from source with the matching
script in `scripts/release/`; see [light-build.md](operations/light-build.md)
for the light tier.

| Platform | CPU build | GPU build |
|---|---|---|
| Linux x86_64 | `tenzro-node-linux-x86_64-cpu.tar.gz` | `tenzro-node-linux-x86_64-cuda.tar.gz` (NVIDIA) |
| Linux aarch64 | | `tenzro-node-linux-aarch64-cuda.tar.gz` (NVIDIA) |
| Windows x86_64 | | `tenzro-node-windows-x86_64-cuda.zip` (NVIDIA) |
| macOS Apple silicon | | `tenzro-node-macos-aarch64-metal.tar.gz` |
| macOS Intel | `tenzro-node-macos-x86_64-cpu.tar.gz` | |

Each archive holds `bin/tenzro-node` and `bin/tenzro`. A Linux CUDA archive
also holds `lib/` (ONNX Runtime with its CUDA providers); keep it beside
`bin/`. The NVIDIA driver and the CUDA 13 runtime come from your machine.

**Checking a build on this machine.** `bin/tenzro-node hardware` prints what
the binary was built for (`build:`), the GPUs it can drive (`gpus:`), the
ONNX Runtime execution providers it will use (`onnx:`) and whether the node
would start here (`startup:`), then exits, non-zero when it would refuse.
`scripts/release/tenzro-node-install --dry-run <archive>` in the repository
runs that check together with the archive checks (CUDA backend in the binary,
ONNX Runtime and its CUDA provider in `lib/`) and refuses a CPU build for a
GPU machine; without `--dry-run` it then installs the node and the CLI.

**Choosing CPU or CUDA.** Take the CPU build unless the machine will serve
GPU-tier models. The CPU build runs a validator, an RPC node, a storage or
light node, and serves CPU-tier models (6 GiB of weights or less); it refuses
a larger model and names the GPU build. The CUDA build refuses to start on a
machine with no usable NVIDIA GPU or driver and names the CPU build. Neither
falls back silently to the other. Validators do not need a GPU.

**Verifying a download.** Each release carries `SHA256SUMS` and its signature
`SHA256SUMS.sig`. Check both before installing:

```bash
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing        # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

On Windows, compare `(Get-FileHash -Algorithm SHA256 .\tenzro-node-windows-x86_64-cuda.zip).Hash`
with the line in `SHA256SUMS`. `matrix.json` in the release records how each
archive was built (commit, toolchain, features, lockfile digest), so you can
rebuild it and compare. The full procedure, where the public key comes from and the Windows signing status are in [VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md).

The rest of this guide covers the full `tenzro` node CLI — running a node,
downloading weights, and serving models yourself. If you only want to try the
network without building anything, point any Tenzro CLI build at the public
endpoints:

```bash
# Install the CLI (requires Rust toolchain — see §2)
cargo install --git https://github.com/tenzro/tenzro-network --bin tenzro

# Or use a prebuilt binary from a release (see "Prebuilt binaries" below),
# after verifying the download (VERIFY-DOWNLOAD.md)

# Talk to the public network
export TENZRO_RPC_URL=https://rpc.tenzro.com

tenzro setup                             # guided setup — join, provide, validate, or bootstrap a network
# or go straight in:
tenzro join --name "Alice"               # provisions DID + permissionless wallet
tenzro wallet balance
tenzro model list
tenzro chat
```

To earn from network demand instead of just consuming it, run a node and
become a provider in one command — see §4.3.

Every account signs with a P-256 key and an ML-DSA-65 key together, and the
network requires both legs. A new account's first transaction enrols the
hardware's ML-DSA-65 key (the SDKs' `sendEnrolling` / `send_enrolling` do this on
the first send; to do it on its own, `tenzro pq-hybrid enroll`); until then the
account signs nothing else. See
[PQ-AND-AI-SAFETY.md](PQ-AND-AI-SAFETY.md).

Public endpoints:

| Service | URL |
|---------|-----|
| JSON-RPC | `https://rpc.tenzro.com` |
| Web API | `https://api.tenzro.com` |
| MCP | `https://mcp.tenzro.com/mcp` |
| A2A | `https://a2a.tenzro.com` |

Continue below if you want to run a node locally.

---

## 1. System Requirements to build from source

This guide is for building and running from source. To install a released binary instead of building, see [HARDWARE-COVERAGE.md](HARDWARE-COVERAGE.md) for the requirements of the release archive itself — the toolchain requirements below (for `cargo build`) are not the same as what a built binary needs to run.

To install a release archive or package (no build):

| Resource | Requirement |
|----------|-------------|
| OS | Linux x86_64 or aarch64 with glibc 2.39 or newer (Ubuntu 24.04, Debian 13, Fedora 40); macOS (Apple silicon or Intel); Windows x86_64 (CUDA build) |
| Disk | Space for the archive plus the node data directory |
| Network | Open outbound 443 |

The glibc 2.39 floor is the highest `GLIBC_` symbol version in the released Linux binaries. Debian 12 and Ubuntu 22.04 are below it.

To build from source:

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | x86-64-v3 (Haswell 2013+, Zen 1+) or aarch64 | 8+ cores |
| RAM | 8 GB free during build | 16 GB |
| Disk | 20 GB for `target/` | 50 GB (multi-profile + models) |
| OS (build toolchain) | Linux (glibc 2.31+), macOS 12+ | Ubuntu 22.04 / macOS 14+ |
| Network | Open outbound 443 (crates.io, Hugging Face) | — |
| Hardware key store | TPM 2.0 (Linux, Windows) or Secure Enclave (macOS), required to run a node | — |

**A hardware key store is required.** `tenzro-node` refuses to start on a machine with no TPM 2.0 or Secure Enclave, or whose identity key does not open: it exits non-zero with a message naming what is missing. There is no keyless or software-key mode. A machine with no TPM of its own, such as a Raspberry Pi, keeps its identity key in another machine's TPM: that machine runs `tenzro-node tpm serve`, and the small one runs `tenzro-node tpm key-holder`, approved by the operator's passkey, and starts with `--tpm-key-holder` ([NODE.md](NODE.md#raspberry-pi-and-other-edge-devices)). Building needs no TPM; running does.

**GPU / accelerator (optional, for local inference):** enabled per cargo feature on `tenzro-node`, one backend per build — `cuda` (NVIDIA), `rocm` (AMD), `metal` (Apple), `vulkan` (any NVIDIA/AMD/Intel/ARM GPU), `sycl` (Intel GPU, needs oneAPI DPC++), `opencl`, `webgpu`, `musa` (Moore Threads), `cann` (Huawei Ascend NPU), `openvino` (Intel CPU/GPU/NPU), `zdnn` (IBM Z Telum), `blas` (accelerated CPU). A node with no backend feature runs CPU-only. See §3.2 and `docs/AI.md` §2.7 for the full matrix.

---

## 2. Toolchain Installation

The authoritative reference is the `Dockerfile`. Install the same toolchain locally.

### 2.1 Linux (Debian / Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
  pkg-config \
  libssl-dev \
  libclang-dev \
  clang \
  cmake \
  protobuf-compiler \
  build-essential \
  curl

# Force clang for C/C++ — required by llama-cpp-sys-2
export CC=clang
export CXX=clang++
```

Add the exports to `~/.bashrc` or `~/.zshrc` to persist them.

### 2.2 Linux (Fedora / RHEL)

```bash
sudo dnf install -y \
  pkg-config openssl-devel clang clang-devel \
  cmake protobuf-compiler gcc-c++ make curl
export CC=clang CXX=clang++
```

### 2.3 Linux (Arch)

```bash
sudo pacman -S --needed \
  pkgconf openssl clang cmake protobuf base-devel curl
export CC=clang CXX=clang++
```

### 2.4 macOS

```bash
# Xcode command line tools (provides Apple Clang)
xcode-select --install

# Homebrew deps
brew install cmake protobuf pkg-config

# OpenSSL — use Homebrew's if system is old
brew install openssl@3
# export OPENSSL_DIR=$(brew --prefix openssl@3)   # only if linker can't find it
```

Apple Clang is used by default; do not override `CC`/`CXX` on macOS.

### 2.5 Rust

The workspace pins `stable` via `rust-toolchain.toml`. Install via `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# rustup will auto-install the toolchain components on first cargo call
# (rustfmt, clippy, and platform targets from rust-toolchain.toml)
```

Verify:

```bash
rustc --version          # 1.82.0+ stable
cargo --version
clang --version          # Linux only
cmake --version          # >= 3.21
protoc --version         # >= libprotoc 3.12
```

---

## 3. Clone and Build

```bash
git clone https://github.com/tenzro/tenzro-network.git
cd tenzro-network

# Recommended: build only node + CLI
cargo build --release -p tenzro-node -p tenzro-cli

# Binaries land at:
#   ./target/release/tenzro-node
#   ./target/release/tenzro       (CLI; binary name is "tenzro", not "tenzro-cli")
```

**First build takes 10–30 minutes** depending on CPU/RAM. Subsequent incremental builds are seconds.

### 3.1 Build the full workspace (optional)

```bash
cargo build            # debug, all 32 crates
cargo test --workspace # full test suite
cargo clippy --workspace --all-targets -- -D warnings
```

### 3.2 GPU / accelerator inference (optional)

llama.cpp provides every backend; a build enables one via a `tenzro-node` feature flag. Pick the one that matches your hardware — a build with no backend feature is CPU-only.

| Feature | Hardware | Build requirement |
|---------|----------|-------------------|
| `cuda` | NVIDIA GPU | CUDA Toolkit 12+ |
| `cuda-no-vmm` | NVIDIA GPU (no virtual-memory management) | CUDA Toolkit 12+ |
| `rocm` | AMD GPU | ROCm 6+ (gfx90a/gfx942/gfx1100/gfx1201) |
| `metal` | Apple Silicon GPU | macOS + Xcode (auto-links on macOS ARM64) |
| `vulkan` | any NVIDIA/AMD/Intel/ARM GPU | Vulkan SDK + `glslc` |
| `sycl` | Intel GPU | oneAPI DPC++ (`CC=icx CXX=icpx`) |
| `opencl` | OpenCL GPU | OpenCL ICD loader |
| `webgpu` | WebGPU device | Dawn/wgpu |
| `musa` | Moore Threads GPU | MUSA Toolkit |
| `cann` | Huawei Ascend NPU | CANN Toolkit |
| `openvino` | Intel CPU/GPU/NPU | OpenVINO runtime (device via `GGML_OPENVINO_DEVICE`) |
| `zdnn` | IBM Z Telum accelerator | zDNN library |
| `blas` | accelerated CPU | OpenBLAS/MKL |

```bash
# NVIDIA CUDA
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/cuda

# AMD ROCm
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/rocm

# Intel GPU via SYCL (oneAPI compiler required)
CC=icx CXX=icpx cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/sycl

# Cross-platform Vulkan
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/vulkan

# Apple Metal auto-links on macOS ARM64 — no flag needed
```

The runtime reports the compiled set and the active backend at startup via `HardwareInfo` (`compiled_backends` / `active_backend`).

Prebuilt releases (archives and container images) come in these flavours only: Linux x86_64 and aarch64 as `cpu`, `cuda` and `vulkan`; macOS Apple silicon as `metal` and Intel as `cpu`; Windows as `cpu`, `cuda` and `vulkan`. Every other feature in the table, `rocm` included, is a source build: there is no prebuilt ROCm archive or image. On an AMD GPU, either run the `vulkan` release or build `--features tenzro-node/rocm` (or `Dockerfile.rocm`) yourself. See `docs/AI.md` §2.7 and `deploy/validator-deployment.md`.

> The `.cargo/config.toml` sets `CMAKE_ARGS="-DGGML_NATIVE=OFF"` to prevent Apple Clang breakage. On Linux, override with `CMAKE_ARGS="-DGGML_NATIVE=ON"` for max CPU SIMD detection.

---

## 4. Running a Node

### 4.1 Validator (default)

```bash
./target/release/tenzro-node \
  --roles validator \
  --data-dir ./data
```

Ports opened on the node:

| Port | Service | Scope |
|------|---------|-------|
| 9000 | Tenzro network transport (TCP + QUIC); works outbound-only behind NAT | all interfaces |
| 8545 | JSON-RPC | loopback only |
| 8080 | Web verification API — also serves Prometheus `/metrics` | loopback only |
| 3001 | MCP server | loopback only |
| 3002 | A2A server | loopback only |

The node runs confined: its HTTP listeners bind loopback and the node refuses to start with any of them bound elsewhere. It speaks to peers only over the network transport and publishes no address of its own. Serving RPC to the public is your decision, made outside the node: put your own reverse proxy in front of the loopback listener and pass its public https URL as `--external-rpc-addr`.

### 4.2 Light client / user node

```bash
./target/release/tenzro-node --roles light --data-dir ./data
```

On a small machine, use the light build: `scripts/build-tier.sh edge` (add
`--cpu cortex-a76` for a Raspberry Pi 5, `--cpu cortex-a72` for a Pi 4,
`--size` for the smallest binary). It carries identity, payments, agents, RPC,
MCP, A2A, storage and chain following, forwards inference calls to providers
on the network, and refuses the `ai`, `compute` and `tee` roles at startup.
Sizes, memory and the glibc note for Raspberry Pi OS are in
[NODE.md](NODE.md#node-tiers).

### 4.3 Model provider

```bash
./target/release/tenzro-node --roles ai --data-dir ./data
```

Then become a network provider in one command:

```bash
tenzro join --provider
```

Against the running local node this provisions an identity and wallet,
detects your hardware (CPU, RAM, GPUs, TEE), checks the wallet holds the
compute bond minimum in force (`compute_bond.min_tnzo`, set by governance,
read from `tenzro_computeBondParams`), posts it, registers you as
a model provider with default per-token pricing, and downloads + serves the
largest catalog model that fits the machine.

Fund the wallet with a transfer from an account that holds
TNZO before running `tenzro join --provider`; it stops and says so when the
balance is below the bond.

Addresses may be given in either form the node prints — 32-byte hex
(`0x1ac72f09…`) or base58 (`3F5YuHJUov…`, what the wallet displays). Both are
accepted everywhere an `address` parameter is taken. Your node advertises its
capacity on the provider gossip topic automatically; inference demand routes
to you and settles in TNZO. Use `--rpc <url>` to target a node you operate
remotely.

To serve a model without announcing it to the network, register it with
`tenzro model serve <id> --private` (or set the whole node private with
`tenzro visibility set private`) — the model answers local callers only,
sends no announcements or heartbeats, and never appears in provider
discovery. Distributing private weights to other nodes as encrypted shards
(`tenzro model seal` / `install-sealed`) is covered in
`docs/operators/OPERATOR_GUIDE.md` §17.

To download and run a specific model yourself, without the one-command
`--provider` flow:

```bash
# Download the weights: peer-first over the network (BLAKE3-verified),
# falling back to HuggingFace. --source pins one path.
tenzro model download qwen3-4b
tenzro model download qwen3-4b --source network

# Serve it. If it does not fit one machine, the node auto-forms a LAN
# pipeline cluster from cluster-willing providers on your local segment.
tenzro model serve qwen3-4b --rpc http://127.0.0.1:8545

# Chat against your local copy.
tenzro chat qwen3-4b
```

### 4.4 Generative media

A node renders images, video and audio with the media models it loads, in
process on its native engine:

```bash
tenzro model load-media-model --model-id z-image-turbo
tenzro media-gen catalog
tenzro media-gen render --model z-image-turbo --kind text2image \
  --params ./render.json --out ./render.png
```

`render.json` is a `MediaGenParams` object with a `seed`, for example
`{"prompt": "a plaster studio room at dawn", "width": 1024, "height": 1024,
"steps": 8, "guidance_scale": 0.0, "seed": 7}`. The answer carries the signed
receipt over the output's SHA-256 and perceptual fingerprint, and the price the
node metered it at. Most catalog models are permissively licensed;
`qwen-image-flash` carries the NVIDIA Open Model License and the node refuses to
load it unless it was started with `--accept-license nvidia-open-model`.

### 4.5 Verify it's running

```bash
curl http://localhost:8080/health
curl http://localhost:8080/status
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### 4.6 Shutdown, restart, and upgrade

Ctrl+C or `kill -TERM <pid>`. The node drains pending RPC requests, flushes RocksDB with fsync, and persists agent/swarm state before exit.

**Your identity is in hardware.** A node's P-256 keys live inside its TPM 2.0 or
Secure Enclave. Its Ed25519, ML-DSA-65 and X25519 keys, which that
hardware cannot hold, are derived from a TPM or enclave key at the moment they
sign and wiped afterwards; `tenzro-node init` only prints their public halves
for genesis. The data directory holds chain state and public records, never
keys. On Linux the TPM root is usable only with a fresh signature, made inside
the TPM, by the machine's attestation key (`tenzro-node tpm provision` makes
it; `[tpm] root_authorization_handle` names it), which is checked against the
TPM's endorsement key before the root is used, and only while the machine's
secure-boot state (PCR 7) is the one the root was made in; no secret is stored. A node on a machine without that hardware does not
start: it exits with a message naming the missing TPM, and there is no keyless
mode to fall back to. The iroh endpoint key is fresh at every start; the
machine's signed endpoint record and signed announcements vouch for it. A voting validator whose
hardware key is missing fails loudly rather than mint a new one, so a swapped
disk can never silently fork your identity or double-sign.

**Provision the TPM once.** On Linux, run `tenzro-node tpm provision` once per
machine (and once per `hardware_key_namespace`), as a user that can open
`/dev/tpmrm0`, before the first start. It makes three keys persistent in the
TPM's endorsement hierarchy: the storage root (`0x81018000`), the machine
attestation key (`0x81018001`) and the node identity key (`0x81018100`, or the
namespace's own slot after it). It is idempotent, and because these keys are
derived from the chip's endorsement seed, provisioning again after a reinstall
gives back the same identity. The node only reads these handles: it refuses
to start until they exist and never creates a primary key itself. Its other
TPM keys are generated inside the TPM under the storage root; their
TPM-wrapped blobs (useless on any other chip) are kept in
`~/.local/state/tenzro/device-keys` (or `TENZRO_DEVICE_KEY_DIR`). Machine
attestation also needs the platform's endorsement key at `0x81010020`.

The node sends TPM commands through the kernel resource manager
(`/dev/tpmrm0`), one at a time on a dedicated thread, and shares the chip
politely with other processes. The `[tpm]` table bounds that use:

```toml
[tpm]
call_timeout_secs = 10   # a command that takes longer fails with an error
signs_per_second = 30    # sustained TPM signatures
quotes_per_second = 2    # sustained quotes and key certifications
```

**To upgrade, replace the binary — never the data directory.** Stop the node,
swap in the new `tenzro-node`, and start it again pointing at the same
`--data-dir`. Identity, wallets, staking position, and chain state all carry
across untouched:

```bash
kill -TERM <pid>                   # graceful stop
cp tenzro-node /usr/local/bin/     # install the new binary
tenzro-node --roles ... --data-dir <same-dir> --genesis <same-genesis>
```

Never `rm -rf` the data directory as part of an upgrade — that discards the keys
that *are* the node's identity. The key files are small and are the only thing
that cannot be regenerated, so back the directory up before any risky operation.

### 4.7 Bootstrap a local or sovereign network

`tenzro setup` walks through every participation path interactively — join the
public network (consume / provide / validate), create your own network, or join
an existing private one. Every prompt has a matching flag for non-interactive
use.

Create a self-contained network on your own hardware:

```bash
tenzro setup --path local --network-name lab --yes
```

This derives the validator's keys from the machine's hardware root (its TPM
2.0 or Secure Enclave; your passkey controls the operator account but never holds the key), assembles a schema-v1 `genesis.toml`
with your node as the founding validator plus a funded account, and writes
a service unit (launchd plist on macOS, systemd unit on Linux) into the data
directory. It then prints three things:

1. The founding start command, serving the relay role so peers need no inbound port:
   `tenzro-node --roles validator,ai --data-dir <data> --genesis <genesis.toml> --relay-listen 127.0.0.1:3340 --relay-url <url>`
2. A copy hint for distributing `genesis.toml` to other machines
3. The exact join command for each peer, naming the founding machine by its identity:
   `tenzro-node --roles ai --genesis <genesis.toml> --data-dir <dir> --boot-nodes did:tenzro:machine:<id>@<relay url>`

Join an existing private network instead:

```bash
tenzro setup --path private --genesis ./genesis.toml \
  --bootstrap /ip4/10.0.0.5/tcp/9000/p2p/12D3Koo...
```

Choosing the validator role in the private path prints your `[[validators]]`
genesis stanza so the network operator can add you before their next genesis
cut.

A node that serves another bonded role (`rpc`, `storage`, `ai`...) refuses to
boot until its operator account holds that role's stake. On a running chain the
operator bonds it with `tenzro stake bond`; a new chain's bootstrap nodes have
theirs bonded by the genesis:

```toml
[[role_stakes]]
address = "0x<operator account, 32 bytes>"
role = "storage"
capacity = { terabytes = 4 }        # for a role whose bond scales; omit otherwise
# stake = 10000                     # whole TNZO; omitted, the bond the governed stake.* parameters require
```

The stake is allocated at genesis to the role-stake vault and counts toward the
fixed supply, which genesis allocates once; the genesis state root commits to
every entry.

Useful flags: `--path {network,local,private}`, `--mode {consume,provide,validate}`,
`--network-name`, `--chain-id`, `--data-dir`, `--stake`, `--bootstrap`,
`--genesis`, `--name`, `--rpc`, `--yes` (accept all defaults, no prompts).

### 4.8 Joining an existing network as a validator — what to expect

Any machine can join and follow the chain without anyone's approval. Becoming
a voting validator can need one: while the governed parameter
`validator.admission_approval` is 1, as it is during the preview, a new
validator registers only from an account that an enacted `ApproveValidators`
proposal named. Governance sets it to 0 to open admission. The machine needs a TPM 2.0
(or, on macOS, a Secure Enclave), provisioned once with
`tenzro-node tpm provision` (§4.6), or its key held in another machine's TPM
through a key holder (`--tpm-key-holder`; see [NODE.md](NODE.md#raspberry-pi-and-other-edge-devices) for its
limits): a node with none of these refuses to start. The
flow, and the behaviors that surprise first-time operators:

1. **You join as a non-voting (verify-only) node first.** Start with the
   network's `genesis.toml`; its validators are your boot identities (add more
   with `--boot-nodes did:tenzro:machine:<id>@<relay url>`). Until you hold
   enough stake and are admitted at an epoch boundary you validate and sync but
   do not propose — this is normal, not an error.

2. **A freshly-joined node can sit at block 0 on an idle chain — that is
   expected, not a stuck node.** The chain suppresses empty blocks: with no
   transactions the leader only mints on a long heartbeat (default 10 min). Join
   while the chain is idle and your node shows `peer_count ≥ 1` but
   `block_height 0` until the next real block, then catches up automatically.
   Send any transaction (or wait for the heartbeat) and it advances to the tip.
   A node at height 0 *with peers* is not broken.

3. **Run the exact same binary and genesis as the network.** State is
   deterministic — every node must compute byte-identical state for the same
   blocks. A different binary or an edited genesis yields a different state root
   and your blocks are rejected ("message validation rejected"). Persistent
   rejections mean your genesis or node version does not match the network's.

4. **Becoming a voting validator.** Fund your validator account with a
   validator self-stake plus gas from an account that holds TNZO, then
   self-register: `tenzro setup --mode validate` writes a unit that boots with
   `--validator-self-stake` (the node registers itself with its own keys once
   the account is funded), or run `tenzro validator register --self-stake 10000`
   (amounts on `tenzro stake` and `tenzro validator` are TNZO: `10000` or
   `10000 TNZO`; wei needs its suffix, `250000000000000000wei`). While
   admission approval is on, the account must first be named in an enacted
   `ApproveValidators` proposal, or registration is refused. You are
   admitted to the active set at the next epoch boundary after a short
   activation delay. Registering below the minimum self-stake, or with a zero
   balance, is rejected.

5. **Identity and wallets are persistent — run the node as a service.** Your
   keys are derived from the machine's hardware on demand (§4.6), so a service
   restarts with no console once its TPM root credential is provisioned. Run under systemd with automatic restart so a
   crash, OOM, or reboot returns on the same identity. Never wipe the data
   directory to "reset" — that discards the only unregenerable material (the
   list is in section 9.8, which also gives the supported recovery for a
   corrupt chain database).

6. **Provider resources are gated; you choose how.** If you run provider roles
   (`ai`, `storage`), access is controlled — see
   [`ACCESS.md`](ACCESS.md): on-demand (pay-per-use, open to the network),
   subscription (DIDs your access policy names), and rental (capacity funded
   up front). Visibility
   (public/private) controls *discovery*, not access.

7. **Benign startup noise.** Peer-discovery relay publish warnings and "inbound
   block-sync request during bootstrap window" lines appear while the node is
   still attaching subscribers; they are not failures.

### 4.9 Becoming an operator: every role, its bond and what checks it

Every service on the network is open to anyone who bonds for it. There is no
list to be added to: an account bonds stake for a role with a signed `Stake`
transaction (`tenzro stake bond`), the bond sits in the role-stake vault in
consensus, and a node configured with a bonded role refuses to boot until its
operator account holds that bond. The validator role bonds through
`RegisterValidator` instead. Read any account's bonds with `tenzro stake info`
(`tenzro_getRoleStakes`).

| Role (`--role`) | What you run | Bond | Checked by | Slashed for |
|---|---|---|---|---|
| `validator` | A node ordering blocks and signing checkpoints | 10,000 TNZO (`RegisterValidator`) | Checkpoint certificates | Equivocation |
| `rpc` | A node carrying tenant traffic and issuing tenant access | 100,000 TNZO | SLA probes, and of its published https endpoint (`eth_chainId`) | An unavailable SLA verdict |
| `tee` | A node with a hardware TEE serving attested work | 10,000 TNZO | SLA probes | An unavailable SLA verdict |
| `ai` | A node serving models from the catalog | 1,000 TNZO | SLA probes | An unavailable SLA verdict |
| `compute` | A node renting accelerators | 500 TNZO floor, per card class | SLA probes | An unavailable SLA verdict |
| `storage` | A node holding storage claims | 100 TNZO per terabyte, 100 floor | SLA probes | An unavailable SLA verdict |
| `attestor` | A payment rail confirming settlement legs; reserve attestations for reserve-backed tokens; with a declared bridge signer, a seat on bridge committees | 100,000 TNZO | Payee disputes; committee draws | An evidenced dispute; signing two deliveries with one nonce, or a handover to a committee the chain did not draw |
| `catalog` | Model catalog entries signed by your key (no node needed) | 1,000 TNZO | Catalog faults anyone files | An upheld catalog fault: an entry pinning bytes its source does not hold |
| `wallet` | A passkey wallet on your own domain (no node needed) | 1,000 TNZO | Validators fetching your domain's provider document | An unavailable SLA verdict |
| `edge` | A relay every node may connect through, at the URL your bond publishes (`tenzro stake endpoint --role edge --url https://...`) | 10,000 TNZO | Validators fetching your relay's signed record at `<url>/identity` | An unavailable SLA verdict |

The amounts are set by governance. Each is a governed parameter (`stake.rpc_tnzo`,
`stake.wallet_tnzo`, ..., in whole TNZO); the table shows the genesis values, and
`tenzro_getNetworkParams` returns the values in force and any change pending. An
enacted vote applies at the next epoch, and a raise waits out the tightening grace
window first, so a bond that met the old amount keeps serving while its owner tops
it up; once the raise applies, a bond below it stops serving the role.

`archive`, `bootstrap`, `fullnode`, `light` and `micro` take no bond:
they claim no work for anyone else and carry no counterparty risk.

Each SLA-probed bond is named `did:tenzro:role:<role>:<account hex>`
(`sla_subject` in `tenzro_getRoleStakes`). Validators probe it every ten
minutes and attest each hourly epoch's outcome; once two thirds of bonded
stake agree, an unavailable verdict takes the governed penalty
(`sla.unavailable.penalty_gwei`) from the bond into the insurance pool. A
node-run role answers probes as the hardware identity registered on chain for
its operator account, so register that identity before bonding.

The path for every role is the same: bond, serve, get probed.

```bash
# 1. Bond (signed with the account's hardware key)
tenzro stake bond --role storage --amount 400 --terabytes 4
# 2. Serve: start the node with the role
tenzro-node --roles storage
# 3. Check the bond and the subject validators probe
tenzro stake info --address <operator account>
```

#### Wallet provider

A wallet provider serves passkey wallets on its own relying-party domain.
Users link a credential from any domain to their keystore and it works whether
or not the provider is bonded; a bond lets wallets show credentials from that
domain as coming from a staked provider.

1. Serve the provider document at `https://<your domain>/.well-known/tenzro-provider`,
   over HTTPS, without a redirect, under 16 KiB:

   ```json
   { "accounts": ["0x<the 32-byte bonding account, hex>"] }
   ```

2. Bond for the domain. The domain is your WebAuthn RP ID: a lowercase DNS
   name. It stays fixed until the stake is fully withdrawn.

   ```bash
   tenzro stake bond --role wallet --amount 1000 --domain wallet.example
   ```

3. Validators fetch the document every probe round. Once two thirds of bonded
   stake attest an epoch in which it named your account, the domain shows as
   staked:

   ```bash
   tenzro stake wallet-provider wallet.example   # tenzro_getWalletProvider
   ```

   A wallet reads the same answer with `client.staking.walletProvider(rpId)`
   (TS), `client.staking().wallet_provider(rp_id)` (Rust) or
   `get_wallet_provider` (Python SDK and MCP). It counts the latest frozen verdict from the last three closed
   epochs. An epoch in which the document is unreachable or stops naming the
   account is an unavailable verdict, which takes the SLA penalty from the bond.

Building the wallet itself takes the SDK alone; no other provider is involved
and none can sign for your users. With the TypeScript SDK (`tenzro-sdk`):

1. Register a passkey on your domain with WebAuthn. Take its key with
   `rawP256(publicKey)` and its model and sync flags with
   `registrationFacts(authenticatorData)`; these form the `KeystoreAnchor`
   of a new account or the `KeystoreCredential` of a linked one.
2. Build a change with `KeystoreClient.prepare(account, op)`, have the
   account's passkeys approve it with `approve(update, signer)` and a passkey
   being linked prove possession with `prove(update, signer)`, each signer a
   WebAuthn passkey. A flow that drives WebAuthn itself asks the passkey to
   sign `passkeyChallenge(digest)`, where `digest` is
   `keystoreDigest(chain_id, account, previous_commitment, op)` over the
   update's fields. A change names the chain it is for (`prepare` takes the
   node's `eth_chainId`); a chain refuses a change approved for another.
3. Send it with `KeystoreClient.send`: from the account itself once it holds a
   balance, or from your own account as its sponsor before then. The
   authority is in the approvals; as a sponsor you pay and cannot change
   anything.
4. Offer recovery the user chooses, all off until they turn it on: a
   hardware recovery key or another device as recovery signers
   (`set_recovery`), a second passkey for every change (`set_policy` with
   `two_credentials`), and the one-time recovery code: `generateRecoveryCode()`
   in the user's browser, `recoveryCodeCommitment(chainId, account, code)` in
   `set_recovery_code`, and the code handed to the user to keep. To recover, the user's new passkey is
   bound to the code with `recoveryCodeClaim` in `claim_recovery_code`, sent
   by an account other than the locked one, then revealed in
   `recover_with_code` once the claim has aged.
5. Show every pending recovery and let any linked passkey cancel it
   (`cancel_recovery`) during its wait.

The Rust (`tenzro-sdk`) and Python (`tenzro`) SDKs offer the same encoding,
digest and recovery code helpers, checked against one shared vector.

---

## 5. Using the CLI

```bash
# Install binary to PATH (optional)
cargo install --path crates/tenzro-cli

# Or run directly
./target/release/tenzro --help

# Guided setup — join, provide, validate, or bootstrap a network (see §4.7)
tenzro setup

# Join the network (provisions identity + permissionless wallet + hardware profile)
tenzro join --name "Alice"

# Join AND become an inference provider (bond + register + pricing + model
# pull + serve, all automatic — requires a running local node, see §4.3)
tenzro join --provider

# Mint a DPoP-bound bearer JWT for authenticated RPC/MCP access
tenzro auth onboard-human --display-name "Alice"

# Check balance
tenzro wallet balance

# List models
tenzro model list

# Chat (local llama.cpp + RPC fallback)
tenzro chat

# Interactive mode launches automatically when invoked without a subcommand on a TTY
tenzro
```

The CLI talks to `http://localhost:8545` by default. Point at the public network with `--rpc-url https://rpc.tenzro.com`.

---

## 6. Configuration File (optional)

Create `~/.tenzro/config.toml` or pass with `--config path.toml`:

```toml
data_dir = "/var/lib/tenzro"
role = "validator"
log_level = "info"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000,/ip4/0.0.0.0/udp/9000/quic-v1"

[iroh]
# Boot identities: omit to join through the genesis validators; set machine
# identities here or via --boot-nodes for a private deployment.
# boot = ["did:tenzro:machine:<id>@https://relay.example.org"]

[rpc]
addr = "127.0.0.1:8545"

[mcp]
addr = "127.0.0.1:3001"
auth = "tiered"          # tiered | false | full

[a2a]
addr = "127.0.0.1:3002"
```

CLI flags override config file values.

### Running the relay role

A relay lets nodes with no inbound port reach each other: it forwards their
end-to-end encrypted QUIC and serves your node's signed endpoint record at
`/identity`, the door new nodes join the network through. The node never
exposes itself: the relay listener binds loopback like every other listener
(a non-loopback bind is refused at startup), speaks plain HTTP, and you put
your own TLS-terminating reverse proxy in front of it.

1. Start the node with the role:
   `tenzro-node ... --relay-listen 127.0.0.1:3340 --relay-url https://relay.example.org`
   (the URL must be `https` on a public host; it is signed into your record).
2. Terminate TLS for that host on your proxy and forward every path to
   `127.0.0.1:3340`, passing WebSocket upgrades through (`/relay` upgrades to
   a WebSocket). No other port is needed.
3. Peers join with `--boot-nodes did:tenzro:machine:<your id>@https://relay.example.org`
   (`tenzro_iroh_getInfo` shows your `machine_did`).

Behind a terminating proxy the relay authenticates each client with a signed
challenge over the WebSocket rather than with TLS keying material, which only
exists when TLS ends at the relay itself. The relay runs no QUIC address
discovery service, so clients learn nothing about their public address from
it; they probe its latency over HTTPS and upgrade to direct paths where their
own networks allow.

A private node (every hideable capability set private with
`tenzro_setNodeVisibility`) shares its endpoint record only with its
counterparties: its boot identities and the identities in
`[iroh] counterparties`. Set `[iroh] relay_only = true` on it to bind no IP
socket at all.

---

## 7. Docker

To run a node in a container, use the release images (`tenzro-node:launch-cpu`,
`-cuda`, `-vulkan`); [Run a node in Docker](DOCKER.md) covers the TPM, GPU,
ports and volumes.

To build in a known-good environment when local toolchain issues persist, the
release Dockerfiles are the canonical build environment: `Dockerfile` (CPU),
`Dockerfile.cuda` and `Dockerfile.vulkan`. `scripts/release/build-linux.sh
<x86_64|aarch64> <cpu|cuda|vulkan>` builds a release archive with them and the
image from that archive.

---

## 8. Control App (optional)

```bash
cd apps/tenzro-control
npm install
npm run tauri dev
```

Requires Node.js 20+ and the Tauri CLI (`cargo install tauri-cli` or `npm i -g @tauri-apps/cli`).

---

## 9. Troubleshooting

### 9.1 `cc-rs: command did not execute successfully (status code exit status: 1)` while building `librocksdb-sys`

**Most common cause: OOM killed during parallel C++ compile.** RocksDB, revm, and llama-cpp each allocate 500 MB–1 GB per translation unit. On machines with < 16 GB RAM, `cargo` default `-j$(nproc)` triggers the OOM killer.

**Check:**
```bash
dmesg | tail -50 | grep -iE "killed process|out of memory"
```

**Fix:**
```bash
CARGO_BUILD_JOBS=2 cargo build --release -p tenzro-node -p tenzro-cli
# or
cargo build --release -p tenzro-node -p tenzro-cli -j 2
```

Add 4–8 GB of swap for safety:
```bash
sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
```

**Other causes for the same error:**

1. **GCC too old.** Needs ≥ 7 for C++17. Check `g++ --version`. Install `g++-11` or use clang:
   ```bash
   export CC=clang CXX=clang++
   cargo clean -p librocksdb-sys
   cargo build
   ```
2. **Mixed toolchain** (e.g., `CC=gcc` but `CXX=clang++`). Unset both and re-export matching pair.
3. **Missing `libclang-dev`** (Linux). Install via package manager.

### 9.2 `llama-cpp-sys-2` build fails with cmake errors

- **macOS Apple Silicon**: ensure `.cargo/config.toml` has `CMAKE_ARGS="-DGGML_NATIVE=OFF"` (it does by default). Do not set `target-cpu=native` globally.
- **Linux with old cmake**: needs cmake ≥ 3.21. Install from Kitware APT repo or `pip install cmake`.
- **GPU feature enabled without driver**: remove the `--features tenzro-model/cuda` (or rocm/vulkan) and retry CPU-only.

### 9.3 `ld: library not found for -lssl` / `error: failed to run custom build command for openssl-sys`

**Linux:**
```bash
sudo apt-get install -y libssl-dev pkg-config
```

**macOS:**
```bash
brew install openssl@3
export OPENSSL_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
```

### 9.4 `error: linker 'cc' not found`

Missing C toolchain.
```bash
# Debian/Ubuntu
sudo apt-get install -y build-essential
# Fedora
sudo dnf groupinstall -y "Development Tools"
# macOS
xcode-select --install
```

### 9.5 `SIGILL` / `Illegal instruction` at startup on older x86_64 CPUs

`.cargo/config.toml:22` sets `target-cpu=x86-64-v3` (AVX2 required). If your CPU is pre-Haswell (Intel) or pre-Zen (AMD):

```bash
# Check for AVX2 support
grep -o avx2 /proc/cpuinfo | head -1
```

If empty, remove the `rustflags` line for your target from `.cargo/config.toml` or override:

```bash
RUSTFLAGS="-C target-cpu=x86-64" cargo build --release -p tenzro-node
```

### 9.6 `error: failed to open: /tmp/.../CACHEDIR.TAG: Permission denied`

Running `cargo` as root after building as a user (or vice versa). Clean and rebuild as the correct user:

```bash
sudo chown -R "$USER:$USER" target/ ~/.cargo
```

### 9.7 Port already in use

```
Error: Address already in use (os error 98) — 127.0.0.1:8545
```

Another process holds the port. Find and stop it:

```bash
# Linux
sudo ss -tlnp | grep 8545
sudo fuser -k 8545/tcp

# macOS
lsof -i :8545
```

Or override via flags: `--rpc-addr 127.0.0.1:8546 --mcp-addr 127.0.0.1:3011 --a2a-addr 127.0.0.1:3012`.

### 9.8 RocksDB corruption after crash / kill -9

The node repairs its write-ahead log on open. A store damaged beyond that (a
bad disk, a partial overwrite) is detected and refused: the node does not start
and does not serve the damaged data, and the other validators carry on. The
start fails with

```
Failed to load genesis block: RocksDB error: Corruption: block checksum mismatch
```

The node does not repair this by itself. Recover it by replacing the chain
database; do not wipe the whole data directory.

What the data directory holds that peers cannot give back:

| Path under the data directory | What it is |
|---|---|
| `consensus/` | A validator's record of the checkpoints it has signed. It stops the validator signing two different checkpoints for one index across restarts, so it stays in place and is never deleted. |
| `wallets/`, `contacts.json` | The node's wallet records and contacts. |
| `credentials/`, `access.toml` | The operator's own credentials and access policy. |

Identity keys are not in the data directory: they are derived from the
machine's hardware root (or the TPM of the machine it delegates to), so a
machine returns with the same identity. The chain database is recoverable from
peers: `db/`, `epoch-snapshots/` and `epoch-proof/`.

1. Stop the node.
2. Copy the files in the table above to a safe place (`cp -a`), then move the
   whole data directory aside as a further backup (`mv ./data ./data.backup`).
3. Create a new data directory and put back from the backup only `consensus/`,
   `wallets/`, `contacts.json`, `credentials/` and `access.toml`; leave out
   `db/`, `epoch-snapshots/` and `epoch-proof/`.
4. Start the node with `--state-sync-from ENDPOINT_ID` naming one or more
   healthy peers (see [NODE.md](NODE.md)), and wait until it has synced and
   reports the network's finalized height.

Finalized blocks are fsync'd on the peers, so the sync restores the state.

### 9.9 `tenzro join` hangs

Check the node is running and reachable:
```bash
curl http://localhost:8080/status
```

Point the CLI at the public network if your local node is not ready:
```bash
tenzro --rpc-url https://rpc.tenzro.com join --name "Alice"
```

### 9.10 Peer discovery: "no peers connected" for > 60 s

- Ensure outbound UDP for the iroh endpoint is not blocked by firewall.
- Check `tenzro_iroh_getInfo`: `relays` lists the relays admitted by their operators' records and `boot_peers` the boot identities resolved. An empty `relays` means no boot entry named a relay whose record verified.
- Pass boot identities via `--boot-nodes did:tenzro:machine:<id>@<relay url>` or `[iroh] boot`.
- Check logs: `RUST_LOG=iroh=debug,tenzro_iroh=debug,tenzro_network=debug ./target/release/tenzro-node ...`

### 9.11 macOS: "killed: 9" on first run of downloaded binary

Gatekeeper quarantine. Remove the attribute:

```bash
xattr -d com.apple.quarantine ./target/release/tenzro-node
xattr -d com.apple.quarantine ./target/release/tenzro
```

### 9.12 A gated model download is refused

Model weights are content-addressed: each artifact is identified by its BLAKE3 hash and a `tenzro://blob/<hash>` URI. A download is peer-first: the node fetches from other nodes over the iroh blob transport when a peer holds the artifact, and from Hugging Face Hub otherwise. Weights their origin gates behind a licence need the operator to accept that licence first; the node then fetches them from other nodes, and those nodes serve them only to a node whose hardware-signed endpoint record lists the same licence. Accept it when starting the node:

```bash
tenzro-node --accept-license <licence id>
```

A refusal naming no network source means no node that accepted the licence holds the weights yet. An operator who has their own Hugging Face account, with access to the gated repository, can also let their node fetch such weights from the origin with that account's access token. The token is the operator's own: the network ships none, and a node without one still serves every open model and fetches gated ones from peers. Set it on the node's machine; it is sealed to that machine's TPM or Secure Enclave and only the sealed envelope is written to disk:

```bash
tenzro-node credentials set huggingface < token.txt   # or paste it and press Enter
tenzro-node credentials status
tenzro-node credentials clear huggingface
```

A sealed token is used first. Operators without a TPM or Secure Enclave, or who keep secrets outside the node, can set `TENZRO_HUGGINGFACE_CREDENTIAL` in the node's environment or `huggingface_credential` in its configuration file instead (the environment wins over the file); the token is then stored unsealed at the operator's own risk, and the node logs one warning saying so. Restart the node after a change. The token is sent only as the authorization header of a gated download from the origin (and dropped on a redirect to another host); it is never logged, sent over RPC, gossiped, written to the chain or put in a receipt, and weights fetched with it are not offered to other nodes. The node never reads a token from the Hugging Face libraries' own environment variables.

Every model a node downloads or serves is recorded in its trust ledger as a content-addressed manifest (per-file SHA-256 and BLAKE3, with a BLAKE3 Merkle root). A manifest is verified when independent origins agree on it: the model creator, the Hugging Face Hub commit, and the storage providers that hold it (`tenzro_getModelProvenance` shows which). Before weights load they are checked against the hashes in the model's catalog entry and the verified manifest; a mismatch fails the load, and a model no verified manifest lists loads with its provenance reported as `unverified`. See [TRUST.md](TRUST.md).

### 9.13 Slow first build, no visible progress

`cargo` prints a line per crate but silences C++ compile progress. Watch RAM and CPU instead:

```bash
watch -n 1 'free -h && nproc && ps -eo pid,rss,comm --sort=-rss | head -20'
```

A cold build compiles 32 workspace crates plus hundreds of dependencies and takes 20 minutes or more on a laptop.

### 9.14 Clean rebuild when everything is wedged

```bash
cargo clean
rm -rf ~/.cargo/registry/cache
rm -rf ~/.cargo/git/db
CARGO_BUILD_JOBS=2 cargo build --release -p tenzro-node -p tenzro-cli
```

---

## 10. Running Tests

```bash
# Full workspace
cargo test --workspace

# One crate
cargo test -p tenzro-consensus

# One test by name
cargo test -p tenzro-wallet --test integration_test

# With logs visible
RUST_LOG=debug cargo test -p tenzro-node -- --nocapture
```

---

## 11. Development Loop

```bash
# Fast type-check (no codegen)
cargo check --workspace

# Format
cargo fmt --all

# Lint (zero warnings policy)
cargo clippy --workspace --all-targets -- -D warnings

# Run with logs
RUST_LOG=tenzro_node=debug,tenzro_consensus=info \
  cargo run --bin tenzro-node -- --roles validator --data-dir ./data
```

---

## 12. Useful Environment Variables

| Variable | Effect |
|----------|--------|
| `CARGO_BUILD_JOBS=N` | Limit parallel compile jobs (RAM-starved systems) |
| `CC` / `CXX` | C/C++ compiler override (use `clang`/`clang++` on Linux) |
| `CMAKE_ARGS` | Pass flags to llama.cpp cmake (e.g., `-DGGML_NATIVE=ON`) |
| `RUST_LOG` | Tracing filter (e.g., `debug`, `tenzro_consensus=trace`) |
| `RUST_BACKTRACE=1` | Print backtrace on panic |
| `TENZRO_MCP_AUTH` | `tiered` (default) / `false` / `full` |
| `TENZRO_BEARER_JWT` / `TENZRO_DPOP_PROOF` | An access token and a DPoP proof the SDKs forward when no credential is configured |
| `OPENSSL_DIR` | OpenSSL install path (macOS with Homebrew) |

---

## 13. Monitoring & Observability

### 13.1 Prometheus metrics

The node exposes Prometheus-compatible metrics on the verification API port
(8080), at the root path so a standard scraper finds them:

```bash
curl http://localhost:8080/metrics
```

Metric families include `tenzro_consensus_*` (current view, high-QC view,
finalized height, view timeouts, equivocation evidence), `tenzro_network_*`
(peers connected, gossip publish/accept/reject counts, dial rate-limit
rejections, mesh size, address migrations), `tenzro_mempool_*` (size,
admitted, rejected), plus `tenzro_block_height`, `tenzro_peer_count`,
`tenzro_inference_requests_total`, and `tenzro_settlements_total`.

Wire to Prometheus by scraping `http://<node>:8080/metrics`.

### 13.2 Health checks

```bash
curl http://localhost:8080/health     # liveness — always 200 if process is up
curl http://localhost:8080/status     # readiness — block height, peer count, role
```

### 13.3 Log filtering

The `tracing` crate is configured via `RUST_LOG`. Common filters:

```bash
RUST_LOG=info                                            # default
RUST_LOG=tenzro_consensus=debug                          # focus consensus
RUST_LOG=tenzro_network=trace,tenzro_iroh=debug          # debug peer issues
RUST_LOG=warn,tenzro_node::rpc=info                      # quiet, but RPC visible
```

Logs go to stderr in human-readable format. Pipe to `jq` for structured filtering once `--log-format json` is enabled.

---

## 14. Security Considerations

### 14.1 Key material

- The wallet is permissionless and no custody is held: every private key lives in the holder's own hardware — a passkey (WebAuthn) for a human, a TPM 2.0 or Apple Secure Enclave for a node — and never leaves it, so neither the network nor any file holds the secret. No key is ever written to disk, placed in configuration or an environment variable, or sent in an RPC. The hardware root is the wallet; losing it is unrecoverable, so guard it accordingly.

### 14.2 RPC exposure

The JSON-RPC server binds `127.0.0.1:8545`, and the node refuses a non-loopback bind. Exposing it through your own reverse proxy puts every open and owner-proof method on the network; state changes without their own proof need a node administrator. The listener answers only to its own host names (`http_surface.allowed_hosts`) and gives no CORS grant unless `cors_allowed_origins` lists the origin. If you expose RPC:

- For your own access to the node prefer Tenzro remote access over `tenzro/shell`, which needs no inbound port.
- Front with a reverse proxy that enforces auth, and list it in `http_surface.trusted_proxies` so its `X-Forwarded-For` is believed.
- Publish its URL with `--external-rpc-addr https://...`; the node refuses a loopback, private, CGNAT or link-local URL.
- Enable MCP-tier authentication (`TENZRO_MCP_AUTH=full`) for MCP server access.

### 14.3 Validator hygiene

- Run validators on dedicated hosts, not shared developer machines.
- Use TEE-attested hardware where possible — TEE validators receive a 1.5× multiplier on their reputation-weighted leader-selection draw and significantly stronger protection against key extraction.
- Monitor `tenzro_consensus_equivocation_evidence{kind="vote"}` and `{kind="proposal"}` — any non-zero value indicates a misconfigured or compromised validator (10% slash penalty applies).

### 14.4 Reporting vulnerabilities

Email security findings to `eng@tenzro.com` or use GitHub private vulnerability reporting on the affected repository. Do not file public issues for unpatched vulnerabilities. The policy is [SECURITY.md](../SECURITY.md).

---

## 15. Getting Help

- **Docs**: https://tenzro.com/docs
- **Issues**: https://github.com/tenzro/tenzro-network/issues
- **Specification**: [`SPECIFICATION.md`](SPECIFICATION.md)

When filing a build-failure issue, attach:

1. `rustc -V && cargo -V && cmake --version && clang --version && protoc --version`
2. `uname -a` (Linux) or `sw_vers` (macOS)
3. Full output of the failing command (not a screenshot — the real error is usually above the `cc-rs:` line)
4. `free -h` and `dmesg | tail -50` if the build was killed
