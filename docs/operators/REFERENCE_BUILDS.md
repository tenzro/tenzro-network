# Tenzro Reference Builds — Multi-Platform Targets

Tenzro Network is a single Rust workspace, but the participating-node story
spans server, mobile, and embedded form factors. This document defines the
**three node classes**, the **target triples** they cross-compile to, and the
**iroh transport story** that makes mobile + embedded participation possible
without running the full validator stack.

Phase C3 (#221) is the reference set: anyone wanting to bring up a Tenzro
endpoint on iOS / Android / Raspberry Pi / ESP32 follows these instructions.

---

## 1. Node Classes

| Class                   | Form factor                                  | Crates included                                                                                       | Iroh role                          | Consensus | Storage    |
|-------------------------|----------------------------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------|-----------|------------|
| **Full Node**           | Cloud VM, dedicated server, Raspberry Pi 5   | All 21 crates (full `tenzro-node` binary)                                                             | Endpoint + iroh-blobs publisher    | Yes (if `--role validator`) | RocksDB    |
| **Light Client**        | Desktop app, iOS, Android                    | `tenzro-types` + `tenzro-crypto` + `tenzro-wallet` + `tenzro-iroh` + `tenzro-identity` + RPC client   | Endpoint + iroh-blobs consumer     | No (RPC reads + tenzro:// fetches)  | None (in-memory) |
| **Embedded Agent**      | ESP32, FreeRTOS micro, RasPi Zero            | `tenzro-types` (no_std subset) + `tenzro-iroh` (endpoint + blobs only)                                | Endpoint + iroh-blobs publisher    | No                                  | None             |

The iroh endpoint, content-addressed `tenzro://` URI scheme, and the same
TDIP-anchored Pkarr discovery (Phase C2, #220) are present on **every class** —
that is the unifying transport layer. What changes by class is which crates
above iroh are present.

---

## 2. Target Triples

### 2.1 Full Node

| Platform          | Triple                          | Notes                                       |
|-------------------|---------------------------------|---------------------------------------------|
| Linux x86_64      | `x86_64-unknown-linux-gnu`      | GKE testnet validators, Cloud Build images  |
| Linux aarch64     | `aarch64-unknown-linux-gnu`     | RasPi 5 (8 GB), AWS Graviton                |
| macOS x86_64      | `x86_64-apple-darwin`           | Developer machines                          |
| macOS aarch64     | `aarch64-apple-darwin`          | Developer machines (Apple Silicon)          |

Already pinned in `rust-toolchain.toml`. Build via:

```bash
cargo build --release --bin tenzro-node \
  --target aarch64-unknown-linux-gnu
```

### 2.2 Light Client

| Platform          | Triple                              | Binding mechanism                  |
|-------------------|-------------------------------------|------------------------------------|
| iOS (arm64)       | `aarch64-apple-ios`                 | UniFFI → Swift Package             |
| iOS Simulator     | `aarch64-apple-ios-sim`             | UniFFI → Swift Package             |
| Android (arm64)   | `aarch64-linux-android`             | UniFFI → Kotlin (via jnigen)       |
| Android (armv7)   | `armv7-linux-androideabi`           | UniFFI → Kotlin (legacy ARMv7 devices) |
| Android (x86_64)  | `x86_64-linux-android`              | UniFFI → emulator                  |

The light-client crate exposes a minimal API surface — wallet create / import,
identity resolve, `tenzro://` fetch, RPC client — bound via UniFFI. The Rust
library is statically linked into the platform-native app (Swift XCFramework
on iOS, AAR on Android).

### 2.3 Embedded Agent

| Platform          | Triple                              | RAM minimum  |
|-------------------|-------------------------------------|--------------|
| ESP32 (Xtensa)    | `xtensa-esp32-none-elf`             | 4 MiB Flash / 2 MiB RAM (per iroh's published support matrix) |
| ESP32-S3 / -C3    | `riscv32imc-esp-espidf` / similar   | 4 MiB Flash / 4 MiB RAM |
| RasPi Pico W      | `thumbv6m-none-eabi` (+ rp2040)     | n/a (transport only; no iroh data plane) |

Iroh itself supports `FreeRTOS` and runs on the ESP32 Flash/RAM envelope above
(verified by the n0 team, see iroh's compatibility page). The Tenzro embedded-
agent build is **iroh endpoint + iroh-blobs only** — no consensus, no
RocksDB, no VM. The agent publishes sensor data as content-addressed blobs
under its `did:tenzro:machine:...` identity; full nodes resolve those blobs
via the shared Pkarr relay.

---

## 3. Build Profiles by Class

### 3.1 Full Node (cloud / RasPi 5)

```bash
# RasPi 5 (8 GB) cross-build from a Linux x86_64 dev host
rustup target add aarch64-unknown-linux-gnu
cargo build --release --bin tenzro-node \
  --target aarch64-unknown-linux-gnu

# Native build on RasPi 5 (Ubuntu 24.04 LTS aarch64)
sudo apt install -y build-essential pkg-config libssl-dev clang
cargo build --release --bin tenzro-node
```

Memory budget: 4 GB RSS steady-state for a validator (per K8s manifest
`resources.limits.memory: 6Gi`). RasPi 4 (4 GB) is **not** sufficient as a
validator — use it as `--role light-client` only.

### 3.2 Light Client (iOS / Android via UniFFI)

A dedicated FFI crate (`crates/tenzro-mobile-ffi`) exposes the light-client
API. It depends on `tenzro-types`, `tenzro-crypto`, `tenzro-wallet`,
`tenzro-identity`, and `tenzro-iroh` — but **not** `tenzro-node`,
`tenzro-vm`, or `tenzro-storage` (those bring in RocksDB and tokio's full
multi-threaded runtime, which inflate the binary).

The crate is shipped as:

- **iOS:** `Tenzro.xcframework` (Swift Package Manager consumable)
- **Android:** `tenzro-aar` (Gradle consumable)

Build workflow (illustrative, lives in `tools/mobile-build/` once Phase C3
ships):

```bash
# iOS XCFramework
cargo install cargo-lipo  # one-time
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo lipo --release -p tenzro-mobile-ffi
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libtenzro_mobile.a \
  -library target/universal/release/libtenzro_mobile.a \
  -output Tenzro.xcframework

# Android AAR
cargo install cargo-ndk  # one-time
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o ./jniLibs build --release -p tenzro-mobile-ffi
# Wrap with Kotlin bindings via uniffi-bindgen → publish AAR
```

The mobile-ffi crate and the build harness ship in a follow-up — this
document fixes the contract.

### 3.3 Embedded Agent (ESP32 via esp-idf)

ESP32 builds use the `esp-idf-template` toolchain (`espup install`,
`cargo +esp`). The Tenzro embedded crate (`crates/tenzro-embedded`) is
`no_std` and depends only on:

- `tenzro-types` (no_std subset — primitives, no I/O)
- `iroh` configured with `default-features = false`, `features = ["embedded"]`
- `iroh-blobs` configured for the in-memory store

Build workflow (illustrative):

```bash
# One-time toolchain setup
cargo install espup
espup install

# Build
. ~/export-esp.sh
cargo +esp build --release -p tenzro-embedded \
  --target xtensa-esp32-none-elf
```

The embedded agent uses its own Ed25519 keypair (provisioned via the device's
secure element or eFuse). The same `derive_iroh_secret_key_from_ed25519`
helper from `tenzro-iroh::tdip` anchors its iroh `EndpointId` to its DID, so
the device is discoverable through the Tenzro Pkarr relay exactly like a
server-class node.

---

## 4. Iroh Discovery Across Form Factors

All three node classes share **one Pkarr relay endpoint**
(`pkarr.tenzro.network/pkarr`, Phase C2 #220). This means:

- A user's phone (light client) resolves a sensor's iroh `EndpointId` via the
  same relay a cloud validator uses to publish its address.
- An ESP32 agent registers its `EndpointId` against its DID and is reachable
  by name (DID) from anywhere — no NAT punching, no manual port forwarding
  required, because the iroh stack handles relay fallback transparently.
- A validator's iroh endpoint and its libp2p endpoint serve different planes
  (data vs. control); both are discoverable but through different paths
  (iroh via Pkarr; libp2p via Kademlia + bootnodes).

This is the unifying model: **same identity key, same iroh transport,
different surface area above it**.

---

## 5. Verification Matrix

When the FFI and embedded crates ship in follow-up phases, the matrix below
becomes the smoke-test checklist. For Phase C3 the rows are documented
contracts; for Phase D and beyond they become CI jobs.

| Class            | Target                     | Smoke test                                                      | Status (2026-05-17) |
|------------------|----------------------------|-----------------------------------------------------------------|---------------------|
| Full node        | `x86_64-unknown-linux-gnu` | `cargo test -p tenzro-node`                                     | PASS (CI)           |
| Full node        | `aarch64-unknown-linux-gnu`| Cross-build + run on RasPi 5 (`tenzro-node --role light-client`)| Documented          |
| Full node        | `aarch64-apple-darwin`     | `cargo test -p tenzro-node` (dev machine)                       | PASS                |
| Light client     | `aarch64-apple-ios`        | `cargo build -p tenzro-mobile-ffi --target …`                   | Pending (crate TBD) |
| Light client     | `aarch64-linux-android`    | `cargo ndk … build -p tenzro-mobile-ffi`                        | Pending (crate TBD) |
| Embedded agent   | `xtensa-esp32-none-elf`    | `cargo +esp build -p tenzro-embedded`                           | Pending (crate TBD) |

---

## 6. Why this layering matters

The three classes correspond to the **three identity classes** in TDIP:

- **Human (delegated)** → light-client form factor (phone, desktop). The user
  signs from their device; the wallet talks to a remote `tenzro-node` for RPC
  reads.
- **Human (validator/operator)** → full-node form factor (cloud / RasPi 5).
  The operator hosts a node that participates in consensus, serves models, or
  provides TEE attestation.
- **Autonomous agent** → embedded form factor (ESP32 sensor, robot,
  industrial controller). The agent owns its own DID and key; it publishes
  attestations and observations as content-addressed blobs through its own
  iroh endpoint.

Phase C3 closes the gap between "the protocol works on cloud servers" and
"any device that can run Rust can participate." The mobile and embedded
crates land in follow-up tasks; this document is the contract those crates
implement against.
