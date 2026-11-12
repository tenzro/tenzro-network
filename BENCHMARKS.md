# Tenzro Network — Criterion Benchmark Baselines

Captured 2026-05-20 on Darwin 24.1.0, opt-level=3 release build (default workspace profile). Numbers are criterion's reported `[low estimate, mean, high estimate]` over the criterion-default sample protocol (100 samples for most groups; 50 for the slower batch settlements and 20 for the slowest RocksDB write-batches) after a 3s warm-up.

These baselines exist so future changes to hot paths can be regression-checked with `cargo bench -p <crate> -- <function_name>`. They are **not** SLA targets — they're a starting line.

## How to reproduce

```bash
# Single bench function
cargo bench -p tenzro-token -- tnzo_balance_of

# Whole crate
cargo bench -p tenzro-token

# Whole workspace (long — ~5-10 min wall clock)
cargo bench --workspace
```

The CI workflow (`.github/workflows/ci.yml`, `benches` job) runs `cargo check --workspace --benches`. Full bench runs are not gated in CI — they're operator-triggered.

## tenzro-iroh — `tenzro://` URI parsing

`TenzroUri::parse` is on every cross-node fetch path (iroh-blobs DA, gradient store, sealed shards, agent memory). Sub-200ns budget across the variants below.

| Function | Mean |
|---|---|
| `tenzro_uri_parse/blob` | 85.5 ns |
| `tenzro_uri_parse/blob_with_hint` | 111.8 ns |
| `tenzro_uri_parse/node` | 47.7 ns |
| `tenzro_uri_parse/did` | 48.5 ns |
| `tenzro_uri_parse/model` | 112.3 ns |
| `tenzro_uri_parse/memory` | 80.5 ns |
| `tenzro_uri_parse/receipt` | 117.2 ns |

## tenzro-identity — TDIP DID parsing + registry resolution

DID parse is on every payment / message-routing / delegation-enforcement hot path. Targets sub-100ns for parse, sub-1µs for resolve+enforce.

| Function | Mean |
|---|---|
| `did_parse/human` | 21.0 ns |
| `did_parse/machine_delegated` | 73.3 ns |
| `did_parse/machine_autonomous` | 49.6 ns |
| `registry_resolve/hit_machine_did` | 342.3 ns |

## tenzro-token — TNZO balance, transfer, adaptive burn

`balance_of` is the single most-called function on the chain (every transfer, every query, every gas check).

| Function | Mean |
|---|---|
| `tnzo_balance_of/hit` | 19.0 ns |
| `tnzo_balance_of/miss` | 16.5 ns |
| `adaptive_burn/compute_recommendation_inside_band` | 2.04 ns |

## tenzro-storage — RocksDB

The 5k-key prefix-scan exercises the registry-hydration path consumed by every manager that boots from `CF_*` (models, agents, escrows, settlements, …).

| Function | Mean |
|---|---|
| `rocksdb_put/256B_value` | 3.48 µs |
| `rocksdb_get/hit_256B` | 591.3 ns |
| `rocksdb_write_batch/10` | 11.51 µs |
| `rocksdb_write_batch/100` | 91.06 µs |
| `rocksdb_write_batch/1000` | 838.1 µs |
| `rocksdb_write_batch_sync/10` | 53.82 µs |
| `rocksdb_write_batch_sync/100` | 197.9 µs |
| `rocksdb_prefix_scan/5k_matching` | 690.3 µs |
| `memory_store/put_256B` | 2.46 µs |
| `memory_store/get_hit_256B` | 91.3 ns |

## tenzro-wallet — Nonce manager

| Function | Mean |
|---|---|
| `nonce_manager/next_nonce_single_address` | 20.47 ns |

## tenzro-model — Pricing + provider reputation

These are pure-function paths on every inference request (router consults pricing + reputation before dispatch).

| Function | Mean |
|---|---|
| `provider_manager_record_success/in_memory` | 52.41 ns |
| `provider_manager_get_reputation/hit` | 21.60 ns |
| `provider_manager_get_reputation/miss` | 18.54 ns |

## tenzro-crypto — Signing + verification + hashing + AEAD

Hot paths consumed by every consensus vote (Ed25519), every transaction hash (Keccak-256), every TEE wrap (AES-256-GCM).

| Function | Mean |
|---|---|
| `key_generation/ed25519_keygen` | 12.00 µs |
| `key_generation/secp256k1_keygen` | 35.01 µs |
| `signing/ed25519_sign` | 12.30 µs |
| `signing/secp256k1_sign` | 37.27 µs |
| `verification/ed25519_verify` | 32.37 µs |
| `verification/secp256k1_verify` | 56.13 µs |
| `hashing/sha256/32` | 190.1 ns |
| `hashing/sha256/256` | 915.1 ns |
| `hashing/sha256/1024` | 3.09 µs |
| `hashing/sha256/4096` | 12.17 µs |
| `hashing/keccak256/32` | 232.3 ns |
| `hashing/keccak256/256` | 449.3 ns |
| `hashing/keccak256/1024` | 1.78 µs |
| `hashing/keccak256/4096` | 6.83 µs |
| `encryption/aes256gcm_encrypt_1kb` | 8.32 µs |
| `encryption/aes256gcm_decrypt_1kb` | 7.54 µs |

## tenzro-consensus

Consensus latency and throughput are measured by the network emulator runs in `crates/tenzro-consensus/src/harness/gates.rs` (one `GATE {json}` line per criterion), not by micro-benchmarks.

## tenzro-payments — MPP + x402 protocol primitives

`mpp_credential_verification` is the HTTP-402 happy path — Ed25519 verification over the canonical preimage.

| Function | Mean |
|---|---|
| `mpp_challenge_creation/create_challenge` | 3.33 µs |
| `mpp_credential_verification/verify_credential` | 173.1 ns |
| `credential_parsing/parse_from_json` | 31.36 µs |
| `credential_parsing/parse_mpp_challenge` | 415.3 ns |
| `payment_gateway_routing/route_challenge_creation` | 3.15 µs |
| `payment_gateway_routing/challenge_store_operations` | 553.6 ns |

## tenzro-vm — EVM execution + state adapter + gas estimation

`evm_execution/*` covers single revm dispatch.

| Function | Mean |
|---|---|
| `evm_execution/simple_transfer` | 32.42 µs |
| `evm_execution/contract_call` | 36.19 µs |
| `state_adapter/get_set_balance` | 280.1 ns |
| `state_adapter/get_set_storage` | 578.6 ns |
| `gas_estimation/estimate_transfer` | 474.0 ps |
| `gas_estimation/estimate_call/32` | 2.50 ns |
| `gas_estimation/estimate_call/256` | 2.56 ns |
| `gas_estimation/estimate_call/1024` | 2.67 ns |
| `gas_estimation/estimate_call/4096` | 2.61 ns |
| `gas_estimation/estimate_deployment/32` | 454.2 ps |
| `gas_estimation/estimate_deployment/256` | 460.3 ps |
| `gas_estimation/estimate_deployment/1024` | 411.8 ps |
| `gas_estimation/estimate_deployment/4096` | 441.2 ps |

## When to re-run

- Before a release: full sweep, paste the new table here, diff against the prior baseline.
- After touching any function listed above: run that single bench (`cargo bench -p <crate> -- <function_name>`) and confirm no >10% regression.
- After a Rust toolchain upgrade: full sweep, since codegen changes can shift numbers ±5% without touching our code.

Do **not** treat criterion noise as a regression unless it's outside the reported confidence interval **and** reproducible across two runs.
