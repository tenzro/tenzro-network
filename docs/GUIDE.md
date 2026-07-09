# Tenzro Network — Local Run Guide

Build and run a full Tenzro node, the CLI, and the desktop app from source. Covers Linux, macOS, and Docker, plus a troubleshooting catalog for the most common build failures.

---

## 0. Quickstart (Live Testnet)

If you only want to try the network without building anything, point any Tenzro CLI build at the public testnet:

```bash
# Install the CLI (requires Rust toolchain — see §2)
cargo install --git https://github.com/tenzro/tenzro-network --bin tenzro

# Or use a pre-built binary from a release tag (when available)
# https://github.com/tenzro/tenzro-network/releases

# Talk to the live testnet
export TENZRO_RPC_URL=https://rpc.tenzro.network

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
| JSON-RPC | `https://rpc.tenzro.network` |
| Web API | `https://api.tenzro.network` |
| Faucet | `https://api.tenzro.network/faucet` |
| MCP | `https://mcp.tenzro.network/mcp` |
| A2A | `https://a2a.tenzro.network` |

Continue below if you want to run a node locally.

---

## 1. System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | x86-64-v3 (Haswell 2013+, Zen 1+) or aarch64 | 8+ cores |
| RAM | 8 GB free during build | 16 GB |
| Disk | 20 GB for `target/` | 50 GB (multi-profile + models) |
| OS | Linux (glibc 2.31+), macOS 12+ | Ubuntu 22.04 / macOS 14+ |
| Network | Open outbound 443 (Hugging Face, Cloud Build) | — |

**GPU (optional, for local inference):** NVIDIA (CUDA 12+), AMD (ROCm 6+), Intel/Apple (Vulkan/Metal auto-detected).

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
cargo build            # debug, all 25 crates
cargo test --workspace # full test suite
cargo clippy --workspace --all-targets -- -D warnings
```

### 3.2 GPU-accelerated inference (optional)

Enable one of the feature flags on `tenzro-model`:

```bash
# NVIDIA CUDA (data-center + consumer)
cargo build --release -p tenzro-node --features tenzro-model/cuda

# AMD ROCm
cargo build --release -p tenzro-node --features tenzro-model/rocm

# Cross-platform Vulkan (NVIDIA/AMD/Intel/ARM)
cargo build --release -p tenzro-node --features tenzro-model/vulkan

# Apple Metal auto-links on macOS ARM64 — no flag needed
```

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
| 8080 | Web verification API | 0.0.0.0 |
| 3001 | MCP server | 0.0.0.0 |
| 3002 | A2A server | 0.0.0.0 |
| 3003–3008 | Ecosystem MCP servers (Solana, Ethereum, Canton, LayerZero, Chainlink, Li.Fi) | 0.0.0.0 |
| 9090 | Prometheus `/metrics` | 0.0.0.0 |

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
testnet faucet if needed, posts the 100 TNZO compute bond, registers you as
a model provider with default per-token pricing, and downloads + serves the
largest catalog model that fits the machine. Your node advertises its
capacity on the provider gossip topic automatically; inference demand routes
to you and settles in TNZO. Use `--rpc <url>` to target a node you operate
remotely.

### 4.4 Verify it's running

```bash
curl http://localhost:8080/health
curl http://localhost:8080/status
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### 4.5 Graceful shutdown

Ctrl+C or `kill -TERM <pid>`. The node drains pending RPC requests, flushes RocksDB with fsync, and persists agent/swarm state before exit.

---

## 5. Using the CLI

```bash
# Install binary to PATH (optional)
cargo install --path crates/tenzro-cli

# Or run directly
./target/release/tenzro --help

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

# Interactive mode launches automatically when invoked without a subcommand on a TTY
tenzro
```

The CLI talks to `http://localhost:8545` by default. Point at the live testnet with `--rpc-url https://rpc.tenzro.network`.

---

## 6. Configuration File (optional)

Create `~/.tenzro/config.toml` or pass with `--config path.toml`:

```toml
data_dir = "/var/lib/tenzro"
role = "validator"
log_level = "info"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000,/ip4/0.0.0.0/udp/9000/quic-v1"
# Bootstrap peers: omit to use the public testnet seeds; override with your own multiaddrs
# for a private deployment.

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
tenzro --rpc-url https://rpc.tenzro.network join --name "Alice"
tenzro --rpc-url https://rpc.tenzro.network faucet
```

### 9.10 libp2p peer discovery: "no peers connected" for > 60 s

- Ensure outbound UDP + TCP on port 9000 is not blocked by firewall.
- Pass explicit boot nodes via `--boot-nodes` or config file.
- Check logs: `RUST_LOG=libp2p=debug,tenzro_network=debug ./target/release/tenzro-node ...`

### 9.11 macOS: "killed: 9" on first run of downloaded binary

Gatekeeper quarantine. Remove the attribute:

```bash
xattr -d com.apple.quarantine ./target/release/tenzro-node
xattr -d com.apple.quarantine ./target/release/tenzro
```

### 9.12 Model download fails with 401 / 403 from Hugging Face

Gated models require an HF token:

```bash
export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx
tenzro model download gemma3-270m
```

### 9.13 Slow first build, no visible progress

`cargo` prints a line per crate but silences C++ compile progress. Watch RAM and CPU instead:

```bash
watch -n 1 'free -h && nproc && ps -eo pid,rss,comm --sort=-rss | head -20'
```

A cold build compiles 25 workspace crates plus hundreds of dependencies and may take 20+ minutes on a laptop.

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
| `TENZRO_SIMULATE_TDX` etc. | Enable TEE simulation when no hardware available |
| `HF_TOKEN` | Hugging Face auth for gated model downloads |
| `OPENSSL_DIR` | OpenSSL install path (macOS with Homebrew) |

---

## 13. Monitoring & Observability

### 13.1 Prometheus metrics

The node exposes Prometheus-compatible metrics on port 9090:

```bash
curl http://localhost:9090/metrics
```

Metric families include `tenzro_consensus_*` (rounds, votes, view changes), `tenzro_network_*` (peers, gossip throughput), `tenzro_rpc_*` (request rates, latencies), `tenzro_storage_*` (RocksDB stats), and `tenzro_mempool_*` (pending tx counts).

Wire to Prometheus by scraping `http://<node>:9090/metrics`. A reference Grafana dashboard ships with `docker compose up`.

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
- Monitor `tenzro_consensus_equivocation_total` — any non-zero value indicates a misconfigured or compromised validator (10% slash penalty applies).

### 14.4 Reporting vulnerabilities

Email security findings to `security@tenzro.com`. Do not file public issues for unpatched vulnerabilities. A public security policy is published at `SECURITY.md` in the protocol repository.

---

## 15. Getting Help

- **Docs**: https://tenzro.com/docs
- **Issues**: https://github.com/tenzro/tenzro-network/issues
- **Specification**: [`SPECIFICATION.md`](SPECIFICATION.md)
- **Foundation**: [`FOUNDATION.md`](FOUNDATION.md)

When filing a build-failure issue, attach:

1. `rustc -V && cargo -V && cmake --version && clang --version && protoc --version`
2. `uname -a` (Linux) or `sw_vers` (macOS)
3. Full output of the failing command (not a screenshot — the real error is usually above the `cc-rs:` line)
4. `free -h` and `dmesg | tail -50` if the build was killed
