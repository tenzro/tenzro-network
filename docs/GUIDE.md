# Tenzro Network — Local Run Guide

Build and run a full Tenzro node, the CLI, and the desktop app from source. Covers Linux, macOS, and Docker, plus a troubleshooting catalog for the most common build failures.

---

## 0. Quickstart (Live Testnet)

If you only want to *use* a model — send a prompt to a provider that already
serves it, with no node and no weights — the simplest path is the Tenzro Labs
client, not the full node CLI:

```bash
npm install -g @tenzro/labs-cli
tzlabs model list --serving
tzlabs login tnz_...
tzlabs chat qwen3-4b "explain content addressing in one line"
```

The rest of this guide covers the full `tenzro` node CLI — running a node,
downloading weights, and serving models yourself. If you only want to try the
network without building anything, point any Tenzro CLI build at the public
testnet:

```bash
# Install the CLI (requires Rust toolchain — see §2)
cargo install --git https://github.com/tenzro/tenzro-network --bin tenzro

# Or use a pre-built binary from a release tag (when available)
# https://github.com/tenzro/tenzro-network/releases

# Talk to the live testnet
export TENZRO_RPC_URL=https://rpc.tenzro.xyz

tenzro setup                             # guided setup — join, provide, validate, or bootstrap a network
# or go straight in:
tenzro join --name "Alice"               # provisions DID + MPC wallet
tenzro faucet                            # request testnet TNZO
tenzro wallet balance
tenzro model list
tenzro chat
```

To earn from network demand instead of just consuming it, run a node and
become a provider in one command — see §4.3.

Live testnet endpoints:

| Service | URL |
|---------|-----|
| JSON-RPC | `https://rpc.tenzro.xyz` |
| Web API | `https://api.tenzro.xyz` |
| Faucet | `https://api.tenzro.xyz/faucet` |
| MCP | `https://mcp.tenzro.xyz/mcp` |
| A2A | `https://a2a.tenzro.xyz` |

Continue below if you want to run a node locally.

---

## 1. System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | x86-64-v3 (Haswell 2013+, Zen 1+) or aarch64 | 8+ cores |
| RAM | 8 GB free during build | 16 GB |
| Disk | 20 GB for `target/` | 50 GB (multi-profile + models) |
| OS | Linux (glibc 2.31+), macOS 12+ | Ubuntu 22.04 / macOS 14+ |
| Network | Open outbound 443 (crates.io, Hugging Face) | — |

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

The runtime reports the compiled set and the active backend at startup via `HardwareInfo` (`compiled_backends` / `active_backend`). Prebuilt container images cover CUDA, ROCm, and Vulkan — see `docs/AI.md` §2.7 and `deploy/validator-deployment.md`.

> The `.cargo/config.toml` sets `CMAKE_ARGS="-DGGML_NATIVE=OFF"` to prevent Apple Clang breakage. On Linux, override with `CMAKE_ARGS="-DGGML_NATIVE=ON"` for max CPU SIMD detection.

---

## 4. Running a Node

### 4.1 Validator (default)

```bash
./target/release/tenzro-node \
  --roles validator \
  --data-dir ./data \
  --listen-addr /ip4/0.0.0.0/tcp/9000
```

Ports opened on the node:

| Port | Service | Scope |
|------|---------|-------|
| 9000 | libp2p P2P (TCP + QUIC) | 0.0.0.0 |
| 8545 | JSON-RPC | 0.0.0.0 (default) |
| 8080 | Web verification API — also serves Prometheus `/metrics` | 0.0.0.0 |
| 3001 | MCP server | 0.0.0.0 |
| 3002 | A2A server | 0.0.0.0 |
| 3003–3008 | Ecosystem MCP servers (Solana, Ethereum, Canton, LayerZero, Chainlink, Li.Fi) | 0.0.0.0 |

Restrict RPC to loopback with `--rpc-addr 127.0.0.1:8545`. The default binds to all interfaces; expose only behind a reverse proxy or firewall.

### 4.2 Light client / user node

```bash
./target/release/tenzro-node --roles light --data-dir ./data
```

### 4.3 Model provider

```bash
./target/release/tenzro-node --roles ai --data-dir ./data
```

Then become a network provider in one command:

```bash
tenzro join --provider
```

Against the running local node this provisions an identity and wallet,
detects your hardware (CPU, RAM, GPUs, TEE), funds the wallet from the
testnet faucet if needed, posts the 1,000 TNZO compute bond, registers you as
a model provider with default per-token pricing, and downloads + serves the
largest catalog model that fits the machine.

The faucet grants up to 20,000 TNZO per request — enough to cover a validator
self-stake (10,000 TNZO) plus the gas to post it, so a permissionless node can
faucet once and self-register as a voting validator the same day (it also
covers the smaller 1,000 TNZO model-provider bond). Operators running their own
testnet set the grant with `TENZRO_FAUCET_DISPENSE_AMOUNT` (clamped to the
20,000 TNZO ceiling).

Addresses may be given in either form the node prints — 32-byte hex
(`0x1ac72f09…`) or base58 (`3F5YuHJUov…`, what the wallet displays). Both are
accepted everywhere an `address` parameter is taken. Your node advertises its
capacity on the provider gossip topic automatically; inference demand routes
to you and settles in TNZO. Use `--rpc <url>` to target a node you operate
remotely.

To serve a model without announcing it to the network, register it with
`tenzro model serve <id> --private` — the model answers local callers only,
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

### 4.4 Media worker

Generative image and video jobs are rendered by a separate worker process. The
node holds the queue, prices the work, and verifies the receipt; the renderer is
Python because that is where `diffusers` lives, and it never loads into the node.

```bash
pip install -e integrations/media_gen

# One-time: mint the worker's signing key (or set TENZRO_MEDIA_GEN_SEED)
tenzro-media-gen --url http://127.0.0.1:8545 keygen

# Enroll and render until interrupted
tenzro-media-gen --url http://127.0.0.1:8545 serve \
  --worker-did did:tenzro:machine:<uuid> \
  --worker-address <32-byte hex> \
  --model z-image-turbo \
  --gpu-vram-gb 24
```

`--model` names a model held whole and repeats. `--expert
<model_id>:<high_noise|low_noise>` names one half of a model whose denoising
schedule divides at a timestep boundary, which is how a machine that cannot hold
the whole model still earns on it — the two halves exchange a single intermediate
latent through the content-addressed store, and payment divides by the step counts
each side signed.

Declared VRAM is what requesters route against, so `--gpu-vram-gb` should be
honest: a claim the machine cannot finish costs the worker the job. Most catalog
models are permissively licensed; `qwen-image-flash` carries the NVIDIA Open Model
License and the node refuses to enroll a worker for it unless it was started with
`--accept-license nvidia-open-model`.

To post work rather than render it:

```bash
tenzro-media-gen catalog

tenzro-media-gen quote --kind text2image \
  --prompt "a plaster studio room at dawn" \
  --width 1024 --height 1024 --steps 8

tenzro-media-gen post --kind text2image --model z-image-turbo \
  --prompt "a plaster studio room at dawn" \
  --width 1024 --height 1024 --steps 8 \
  --requester-did did:tenzro:human:<uuid> \
  --requester-address <32-byte hex> \
  --max-price <attoTNZO>

tenzro-media-gen get <job_id>
tenzro-media-gen receipt <job_id>
tenzro-media-gen fetch <job_id> -o ./render.png
```

`quote` prices the job before it is queued and takes no model, because the unit is
the pixel-step (`width × height × steps × frames`) — cost is known in full at post
time regardless of which model renders it. `--max-price` is a ceiling the node
checks at admission, not after a worker claims. `receipt` returns the worker's
signature over the output's content hash, so the bytes `fetch` returns can be
checked against what was paid for.

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

**Your identity and wallets are persistent.** A node's autonomous identity — the
validator keyset (Ed25519 + ML-DSA-65 + BLS12-381) and its ERC-8004 system key —
and every wallet live under the data directory (`<data-dir>/validator_key`,
`validator_pq_key`, `validator_bls_key`, `validator_erc8004_system_key`, and
`wallets/`), alongside the libp2p peer identity. On restart the node **loads**
these files; it never regenerates them. A voting validator that finds a key
missing fails loudly rather than mint a new one, so a mis-mounted or empty volume
can never silently fork your identity or double-sign.

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

This generates the full validator keyset (Ed25519 + ML-DSA-65 + BLS12-381),
assembles a schema-v1 `genesis.toml` with your node as the founding validator
plus a funded account and faucet, persists the libp2p peer identity, and writes
a service unit (launchd plist on macOS, systemd unit on Linux) into the data
directory. It then prints three things:

1. The founding start command:
   `tenzro-node --roles validator,ai --data-dir <data> --genesis <genesis.toml>`
2. A copy hint for distributing `genesis.toml` to other machines
3. The exact join command for each peer, including your LAN address and peer id:
   `tenzro-node --roles ai --genesis <genesis.toml> --data-dir <dir> --boot-nodes /ip4/<LAN_IP>/tcp/9000/p2p/<PEER_ID>`

Join an existing private network instead:

```bash
tenzro setup --path private --genesis ./genesis.toml \
  --bootstrap /ip4/10.0.0.5/tcp/9000/p2p/12D3Koo...
```

Choosing the validator role in the private path prints your `[[validators]]`
genesis stanza so the network operator can add you before their next genesis
cut.

Useful flags: `--path {network,local,private}`, `--mode {consume,provide,validate}`,
`--network-name`, `--chain-id`, `--data-dir`, `--stake`, `--bootstrap`,
`--genesis`, `--name`, `--rpc`, `--yes` (accept all defaults, no prompts).

### 4.8 Brokering Canton access (optional)

Everything above runs on protocol resources — no credential beyond your own
identity. Canton is different: the ledger sits outside Tenzro, and the node
reaches it with credentials you supply. That makes it an operator-brokered
resource, and it is the one surface where callers need an API key.

The bridge is off unless you turn it on, and it is configured per Canton
network. `devnet` and `mainnet` each read their own variable group, and a
network counts as served only when its `LEDGER_API_HOST` is set:

| Variable | Purpose |
|---|---|
| `CANTON_ENABLED=true` | Master switch. Unset or `false` and the Canton surface stays off. |
| `CANTON_DEFAULT_NETWORK=devnet` | Which network a request resolves to when the caller names none. |
| `CANTON_<NET>_LEDGER_API_HOST` | JSON Ledger API hostname. Its presence declares you serve that network. |
| `CANTON_<NET>_LEDGER_API_PORT` | The JSON Ledger API port serving `/v2/...`, not the gRPC Ledger API port. Defaults to `7575`. Use `443` for a TLS-fronted participant. |
| `CANTON_<NET>_TLS` | `true` to dial over TLS. Defaults to `false`. |
| `CANTON_<NET>_OAUTH_TOKEN_URL` | OAuth2 client-credentials token endpoint. |
| `CANTON_<NET>_OAUTH_CLIENT_ID` | OAuth2 client id. |
| `CANTON_<NET>_OAUTH_CLIENT_SECRET` | OAuth2 client secret. |
| `CANTON_<NET>_OAUTH_AUDIENCE` | Audience the participant expects. |
| `CANTON_<NET>_OAUTH_SCOPE` | Defaults to `daml_ledger_api`. |
| `CANTON_<NET>_JWT_TOKEN` | Static bearer token, honoured only when the OAuth group is absent. |

`<NET>` is `DEVNET` or `MAINNET`. The four `OAUTH_*` values are
all-or-nothing: if any one is missing the grant is dropped and the node
talks to the participant unauthenticated.

Callers pick a network with the `canton_network` request parameter over
JSON-RPC, or the `X-Canton-Network` header on the Canton MCP server.
Resolution order is explicit selector, then the key's sole authorized
network, then `CANTON_DEFAULT_NETWORK`.

You mint keys with `tenzro_createApiKey` (admin-token-gated, so set
`TENZRO_ADMIN_TOKEN` first) and hand them out yourself. Each key carries a
tier that bounds its request budget over a sliding 60-second window:

| Tier | Requests/min | Writes |
|---|---|---|
| `free` | 60 | refused |
| `standard` | 600 | allowed |
| `priority` | 6,000 | allowed |

A request with no key, an unknown key, or a key lacking the `canton` scope
returns `-32004`. Exceeding the budget returns `-32005` with
`retry_after_ms`, `requests_per_minute`, and `tier`. Tenant keys act as the
party bound to the key and are confined to the networks it lists; operator
admin-token requests skip the key gate, reach the participant's own parties,
and can allocate parties, upload DARs, and grant rights.

API keys gate operator-brokered resources only. Publishing to the
marketplace registry — agents, skills, workflows, MCP servers — is
permissionless: you set your own TNZO price or offer it free, and no
operator approves the listing. See [`api-keys.md`](api-keys.md) for the full
reference.

### 4.9 Joining an existing network as a validator — what to expect

Joining is permissionless — no one approves you. The flow, and the behaviours
that surprise first-time operators:

1. **You join as a non-voting (verify-only) node first.** Start with the
   network's `genesis.toml` and at least one `--boot-nodes` peer. Until you hold
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

4. **Becoming a voting validator.** Fund your validator account (on testnet the
   faucet grants up to 20,000 TNZO — a validator self-stake plus gas), then
   self-register: boot with `--validator-self-stake <wei>` (the node registers
   itself with its own keys) or run `tenzro validator register`. You are
   admitted to the active set at the next epoch boundary after a short
   activation delay. Registering below the minimum self-stake, or with a zero
   balance, is rejected.

5. **Identity and wallets are persistent — run the node as a service.** Your
   keyset and wallets live in the data directory, not the binary (§4.6). With a
   TPM, keys are sealed to it and unseal non-interactively at boot, so a service
   restarts with no console. Run under systemd with automatic restart so a
   crash, OOM, or reboot returns on the same identity. Never wipe the data
   directory to "reset" — that discards the only unregenerable material.

6. **Provider resources are gated; you choose how.** If you run provider roles
   (`ai`, `storage`, `database`, `cloud`), access is controlled — see
   [`ACCESS.md`](ACCESS.md): on-demand (pay-per-use, open to the network),
   subscription (an API key you issue), and rental (a service key). Visibility
   (public/private) controls *discovery*, not access.

7. **Benign startup noise.** Peer-discovery relay publish warnings and "inbound
   block-sync request during bootstrap window" lines appear while the node is
   still attaching subscribers; they are not failures.

---

## 5. Using the CLI

```bash
# Install binary to PATH (optional)
cargo install --path crates/tenzro-cli

# Or run directly
./target/release/tenzro --help

# Guided setup — join, provide, validate, or bootstrap a network (see §4.7)
tenzro setup

# Join the network (provisions identity + MPC wallet + hardware profile)
tenzro join --name "Alice"

# Join AND become an inference provider (bond + register + pricing + model
# pull + serve, all automatic — requires a running local node, see §4.3)
tenzro join --provider

# Mint a DPoP-bound bearer JWT for authenticated RPC/MCP access
tenzro auth onboard-human --display-name "Alice"

# Request testnet TNZO from the faucet
tenzro faucet

# Check balance
tenzro wallet balance

# List models
tenzro model list

# Chat (local llama.cpp + RPC fallback)
tenzro chat

# Deploy a static site or single-page app (see docs/HOSTING.md)
tenzro site deploy --name my-app --owner-did did:tenzro:... --dir ./dist --did-envelope <hex>

# Interactive mode launches automatically when invoked without a subcommand on a TTY
tenzro
```

The CLI talks to `http://localhost:8545` by default. Point at the live testnet with `--rpc-url https://rpc.tenzro.xyz`.

---

## 6. Configuration File (optional)

Create `~/.tenzro/config.toml` or pass with `--config path.toml`:

```toml
data_dir = "/var/lib/tenzro"
role = "validator"
log_level = "info"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000,/ip4/0.0.0.0/udp/9000/quic-v1"
# Bootstrap peers: omit to resolve the network bootstrap name tenzro.xyz
# (SRV _tenzro-boot._tcp + TXT _tenzro-id._tcp records) automatically; set
# explicit multiaddrs here or via --boot-nodes for a private deployment.

[rpc]
addr = "0.0.0.0:8545"

[mcp]
addr = "0.0.0.0:3001"
auth = "tiered"          # tiered | false | full

[a2a]
addr = "0.0.0.0:3002"
```

CLI flags override config file values.

---

## 7. Docker (known-good environment)

If local toolchain issues persist, the Dockerfile is the canonical build environment.

```bash
# Build
docker build -t tenzro-node .

# Run
docker run --rm -it \
  -p 9000:9000 -p 8545:8545 -p 8080:8080 -p 3001:3001 -p 3002:3002 \
  -v tenzro-data:/data/tenzro \
  tenzro-node --roles validator --data-dir /data/tenzro

# Compose (includes Prometheus + Grafana)
docker compose up
```

---

## 8. Desktop App (optional)

```bash
cd apps/tenzro-desktop
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
Error: Address already in use (os error 98) — 0.0.0.0:8545
```

Another process holds the port. Find and stop it:

```bash
# Linux
sudo ss -tlnp | grep 8545
sudo fuser -k 8545/tcp

# macOS
lsof -i :8545
```

Or override via flags: `--rpc-addr 127.0.0.1:8546 --mcp-addr 0.0.0.0:3011 --a2a-addr 0.0.0.0:3012`.

### 9.8 RocksDB corruption after crash / kill -9

The node auto-repairs WAL on open, but on rare catastrophic crashes:

```bash
# Back up state, then wipe
mv ./data ./data.backup
./target/release/tenzro-node --roles validator --data-dir ./data
```

Finalized blocks are fsync'd so re-syncing recovers state.

### 9.9 `tenzro join` hangs / faucet fails

Check the node is running and reachable:
```bash
curl http://localhost:8080/status
```

Point CLI at the live testnet if local node is not ready:
```bash
tenzro --rpc-url https://rpc.tenzro.xyz join --name "Alice"
tenzro --rpc-url https://rpc.tenzro.xyz faucet
```

### 9.10 libp2p peer discovery: "no peers connected" for > 60 s

- Ensure outbound UDP + TCP on port 9000 is not blocked by firewall.
- Verify bootstrap DNS resolves: `dig SRV _tenzro-boot._tcp.tenzro.xyz` — the node uses this by default when no boot nodes are configured. Each SRV target needs a matching `dig TXT _tenzro-id._tcp.<target>` carrying `peer_id=<base58>`; a target missing that record is skipped.
- Or pass explicit boot nodes via `--boot-nodes` or config file.
- Check logs: `RUST_LOG=libp2p=debug,tenzro_network=debug ./target/release/tenzro-node ...`

### 9.11 macOS: "killed: 9" on first run of downloaded binary

Gatekeeper quarantine. Remove the attribute:

```bash
xattr -d com.apple.quarantine ./target/release/tenzro-node
xattr -d com.apple.quarantine ./target/release/tenzro
```

### 9.12 Model download fails with 401 / 403 from Hugging Face

Model weights are content-addressed: each artifact is identified by its BLAKE3 hash and a `tenzro://blob/<hash>` URI. A download is peer-first — the node fetches from other nodes over the iroh blob transport when a peer holds the artifact, and falls back to Hugging Face Hub otherwise. When a peer serves the weights, no HF token is needed. The fallback path still hits Hugging Face, and gated models there require a token:

```bash
export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx
tenzro model download gemma3-270m
```

Every downloaded artifact is verified against its recorded BLAKE3 hash before it loads (`tenzro_getModelHash` / `tenzro_listModelHashes` expose the registry). A hash mismatch fails the load — the node never serves weights it can't verify. The first node to record a model's hash pins it network-wide (first-recorder-wins); subsequent downloads verify against that pin.

### 9.13 Slow first build, no visible progress

`cargo` prints a line per crate but silences C++ compile progress. Watch RAM and CPU instead:

```bash
watch -n 1 'free -h && nproc && ps -eo pid,rss,comm --sort=-rss | head -20'
```

A cold build compiles 32 workspace crates plus hundreds of dependencies and may take 20+ minutes on a laptop.

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
| `TENZRO_ADMIN_TOKEN` | Operator secret gating admin RPCs (key minting, Canton party/DAR/IDP operations). Unset = fail-closed |
| `TENZRO_API_KEY` | Client-side key the CLI and SDKs send as `X-Tenzro-Api-Key` |
| `TENZRO_CANTON_NETWORK` | Default Canton network for the CLI and Python clients (§4.8) |
| `CANTON_ENABLED` / `CANTON_<NET>_*` | Canton bridge configuration, per network (§4.8) |
| `TENZRO_SIMULATE_TDX` etc. | Enable TEE simulation when no hardware available |
| `HF_TOKEN` | Hugging Face auth for gated model downloads |
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
admitted, rejected), `tenzro_workflow_*` (workflows by status, approvals,
obligations, Canton mirrors), plus `tenzro_block_height`, `tenzro_peer_count`,
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
RUST_LOG=tenzro_network=trace,libp2p=debug               # debug peer issues
RUST_LOG=warn,tenzro_node::rpc=info                      # quiet, but RPC visible
```

Logs go to stderr in human-readable format. Pipe to `jq` for structured filtering once `--log-format json` is enabled.

---

## 14. Security Considerations

### 14.1 Key material

- The MPC wallet keystore at `~/.tenzro/keystore/` is encrypted with Argon2id-derived AES-256-GCM. The keystore password protects all signing keys; loss is unrecoverable.
- Set restrictive permissions: `chmod 700 ~/.tenzro && chmod 600 ~/.tenzro/keystore/*`.
- Never commit `~/.tenzro/`, `data/`, or any `.toml` containing private keys.

### 14.2 RPC exposure

By default the JSON-RPC server binds to `0.0.0.0:8545`. Exposing RPC to the public internet without authentication is dangerous: clients can drain wallets, submit transactions, and call privileged methods. If you do not need it externally, restrict it to loopback (`--rpc-addr 127.0.0.1:8545`). If you must expose RPC:

- Bind to a VPN/Tailscale interface, not `0.0.0.0`.
- Front with a reverse proxy that enforces auth (the testnet uses Caddy).
- Enable MCP-tier authentication (`TENZRO_MCP_AUTH=full`) for MCP server access.

### 14.3 Validator hygiene

- Run validators on dedicated hosts, not shared developer machines.
- Use TEE-attested hardware where possible — TEE validators receive a 1.5× multiplier on their reputation-weighted leader-selection draw and significantly stronger protection against key extraction.
- Monitor `tenzro_consensus_equivocation_evidence{kind="vote"}` and `{kind="proposal"}` — any non-zero value indicates a misconfigured or compromised validator (10% slash penalty applies).

### 14.4 Reporting vulnerabilities

Email security findings to `security@tenzro.com`. Do not file public issues for unpatched vulnerabilities. A public security policy is published at `SECURITY.md` in the protocol repository.

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
