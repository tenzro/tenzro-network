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
cargo bench --workspace --exclude tenzro-desktop
```

CI runs `cargo check --workspace --exclude tenzro-desktop --benches` on every PR (see `.github/workflows/ci.yml` → `benches` job). Full bench runs are not gated in CI — they're operator-triggered.

## tenzro-iroh — `tenzro://` URI parsing

`TenzroUri::parse` is on every cross-node fetch path (iroh-blobs DA, gradient store, sealed shards, agent memory). Sub-200ns budget across all 9 variants.

| Function | Mean |
|---|---|
| `tenzro_uri_parse/blob` | 85.5 ns |
| `tenzro_uri_parse/blob_with_hint` | 111.8 ns |
| `tenzro_uri_parse/node` | 47.7 ns |
| `tenzro_uri_parse/did` | 48.5 ns |
| `tenzro_uri_parse/model` | 112.3 ns |
| `tenzro_uri_parse/gradient` | 128.9 ns |
| `tenzro_uri_parse/shard` | 150.4 ns |
| `tenzro_uri_parse/manifest` | 89.5 ns |
| `tenzro_uri_parse/memory` | 80.5 ns |
| `tenzro_uri_parse/receipt` | 117.2 ns |
| `tenzro_uri_display_roundtrip/blob_gradient_model` | 598.6 ns |

## tenzro-identity — TDIP DID parsing + registry resolution

DID parse is on every payment / message-routing / delegation-enforcement hot path. Targets sub-100ns for parse, sub-1µs for resolve+enforce.

| Function | Mean |
|---|---|
| `did_parse/human` | 21.0 ns |
| `did_parse/machine_delegated` | 73.3 ns |
| `did_parse/machine_autonomous` | 49.6 ns |
| `did_generate/human_new` | 660.8 ns |
| `did_generate/autonomous_machine_new` | 665.7 ns |
| `registry_resolve/hit_machine_did` | 342.3 ns |
| `enforce_operation/payment_within_scope` | 355.4 ns |

## tenzro-token — TNZO balance, transfer, adaptive burn

`balance_of` is the single most-called function on the chain (every transfer, every query, every gas check).

| Function | Mean |
|---|---|
| `tnzo_balance_of/hit` | 19.0 ns |
| `tnzo_balance_of/miss` | 16.5 ns |
| `tnzo_transfer/1_tnzo_known_recipient` | 387.0 ns |
| `adaptive_burn/compute_recommendation_inside_band` | 2.04 ns |

## tenzro-bridge — Message signing + codec

Bridge messages are signed Ed25519 (default) or Secp256k1 (LayerZero/CCIP compat), JSON-encoded for gossip + adapter dispatch.

| Function | Mean |
|---|---|
| `message_format/new_token_transfer_256b_payload` | 971.8 ns |
| `message_format_sign/ed25519` | 22.20 µs |
| `message_format_sign/secp256k1` | 68.26 µs |
| `message_format_verify/ed25519` | 30.44 µs |
| `message_format_codec/encode_json` | 1.91 µs |
| `message_format_codec/decode_json` | 4.23 µs |

## tenzro-training — Outer-gradient hashing + aggregation

`compute_payload_hash` (SHA-256 over a full safetensors payload) is the per-trainer-per-round cost; aggregation is the per-syncer-per-round cost.

| Function | Mean |
|---|---|
| `training_payload_hash/sha256_4MiB` | 11.36 ms |
| `training_state_root/16_fragments_8_trainers` | 12.95 µs |
| `training_run_root/64_rounds_merkle` | 25.27 µs |
| `training_aggregate/mean_8_trainers_4096_dim` | 21.79 µs |

## tenzro-storage — RocksDB + Merkle Patricia Trie

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
| `merkle_trie_insert/10` | 791.9 ns |
| `merkle_trie_insert/100` | 6.95 µs |
| `merkle_trie_insert/1000` | 94.31 µs |
| `merkle_trie_proof/generate_proof` | 37.56 ns |
| `merkle_trie_proof/verify_proof` | 2.96 ns |

## tenzro-wallet — Smart-account hashing + keystore KDF

`keystore_store_shares` is dominated by Argon2id (64 MiB memory, 3 iterations, parallelism 4) — intentionally slow to harden against offline brute-force.

| Function | Mean |
|---|---|
| `user_op_hash/eip712_v0_8` | 4.01 µs |
| `nonce_manager/next_nonce_single_address` | 20.47 ns |
| `wallet_provision/frost_2of3_plus_mldsa65_plus_bls` | 470.0 µs |
| `keystore_store_shares/argon2id_64MB_3iter_p4` | 102.2 ms |

## tenzro-model — Pricing + provider reputation

These are pure-function paths on every inference request (router consults pricing + reputation before dispatch).

| Function | Mean |
|---|---|
| `pricing_calculate_cost/per_token_512in_256out` | 1.01 ns |
| `pricing_calculate_price/dynamic_7b_50pct_load_no_market` | 17.27 ns |
| `pricing_calculate_price/dynamic_7b_50pct_load_with_market` | 86.62 ns |
| `provider_manager_record_success/in_memory` | 52.41 ns |
| `provider_manager_get_reputation/hit` | 21.60 ns |
| `provider_manager_get_reputation/miss` | 18.54 ns |

## tenzro-crypto — Signing + verification + hashing + AEAD

Hot paths consumed by every consensus vote (Ed25519), every bridge message (Ed25519/Secp256k1), every transaction hash (Keccak-256), every TEE wrap (AES-256-GCM).

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

## tenzro-consensus — HotStuff-2 voting, QC formation, leader selection

`vote_collection/add_votes/N` is the cost of admitting N quorum-bound votes — each vote is hybrid (Ed25519+ML-DSA-65) verified plus BLS-verified. `qc_formation/form_qc/N` includes BLS aggregation. `equivocation_detection` is the per-vote double-vote check.

| Function | Mean |
|---|---|
| `vote_collection/add_votes/10` | 11.90 ms |
| `vote_collection/add_votes/50` | 63.09 ms |
| `vote_collection/add_votes/100` | 130.23 ms |
| `vote_verification/single_vote_verify_and_add` | 813.2 µs |
| `qc_formation/form_qc/4` | 2.55 ms |
| `qc_formation/form_qc/10` | 5.97 ms |
| `qc_formation/form_qc/50` | 28.31 ms |
| `leader_selection/round_robin` | 677.7 ps |
| `leader_selection/reputation` | 4.46 µs |
| `equivocation_detection/clean_check` | 466.0 ns |
| `equivocation_detection/with_equivocation` | 1.33 µs |
| `equivocation_detection/check_after_100_votes` | 206.7 ns |
| `mempool/add_transaction` | 684.8 µs |
| `mempool/select_transactions_100` | 261.5 µs |
| `epoch_manager/create_epoch_manager` | 2.45 ms |

## tenzro-payments — MPP + x402 protocol primitives

`mpp_credential_verification` is the HTTP-402 happy path — Ed25519 verification over the canonical preimage.

| Function | Mean |
|---|---|
| `mpp_challenge_creation/create_challenge` | 3.33 µs |
| `mpp_credential_verification/verify_credential` | 173.1 ns |
| `x402_payload_creation/create_payload` | 68.48 ns |
| `credential_parsing/parse_from_json` | 31.36 µs |
| `credential_parsing/parse_from_base64` | 34.93 µs |
| `credential_parsing/parse_mpp_challenge` | 415.3 ns |
| `payment_gateway_routing/route_challenge_creation` | 3.15 µs |
| `payment_gateway_routing/challenge_store_operations` | 553.6 ns |

## tenzro-settlement — Settlement engine + escrow + channels + fees

`immediate_settlement/single_settlement` and `batch_settlement/batch/N` measure the in-memory async path including provider-signature verification. `micropayment_channel/open_100_updates_close` exercises the full channel lifecycle with 100 signed state updates.

| Function | Mean |
|---|---|
| `immediate_settlement/single_settlement` | 162.3 µs |
| `batch_settlement/batch/10` | 1.49 ms |
| `batch_settlement/batch/50` | 5.87 ms |
| `batch_settlement/batch/100` | 7.25 ms |
| `escrow_create_release/create_and_release` | 33.27 µs |
| `micropayment_channel/open_100_updates_close` | 4.46 ms |
| `fee_calculation/collect_fee` | 968.2 ns |
| `fee_calculation/fee_for_amount/1000` | 2.40 ns |
| `fee_calculation/fee_for_amount/1000000` | 2.44 ns |
| `fee_calculation/fee_for_amount/1000000000` | 2.44 ns |

## tenzro-vm — EVM execution + state adapter + gas estimation

`compute_state_root` is the Merkle-Patricia-Trie commit on every block. `evm_execution/*` covers single revm dispatch.

| Function | Mean |
|---|---|
| `evm_execution/simple_transfer` | 32.42 µs |
| `evm_execution/contract_call` | 36.19 µs |
| `state_adapter/get_set_balance` | 280.1 ns |
| `state_adapter/get_set_storage` | 578.6 ns |
| `state_adapter/compute_state_root` | 1.58 ms |
| `gas_estimation/estimate_transfer` | 474.0 ps |
| `gas_estimation/estimate_call/32` | 2.50 ns |
| `gas_estimation/estimate_call/256` | 2.56 ns |
| `gas_estimation/estimate_call/1024` | 2.67 ns |
| `gas_estimation/estimate_call/4096` | 2.61 ns |
| `gas_estimation/estimate_deployment/32` | 454.2 ps |
| `gas_estimation/estimate_deployment/256` | 460.3 ps |
| `gas_estimation/estimate_deployment/1024` | 411.8 ps |
| `gas_estimation/estimate_deployment/4096` | 441.2 ps |

## tenzro-zk — Plonky3 STARK prove + verify

Pinned testnet config: `log_blowup=1, num_queries=64, query_pow=16, commit_pow=8`. AIR sizes differ across circuits (inference is the largest trace). Prove is multi-millisecond CPU; verify is sub-millisecond — the asymmetry is exactly what the on-chain `ZK_VERIFY` precompile relies on (it never re-proves, only checks the recorded commitment).

| Function | Mean |
|---|---|
| `plonky3_prove/inference_air` | 50.46 ms |
| `plonky3_verify/inference_air` | 961.3 µs |
| `plonky3_prove/settlement_air` | 10.29 ms |
| `plonky3_verify/settlement_air` | 937.7 µs |
| `plonky3_prove/identity_air` | 5.83 ms |
| `plonky3_verify/identity_air` | 938.0 µs |
| `plonky3_verify_envelope/inference` | 1.03 ms |

## When to re-run

- Before a release: full sweep, paste the new table here, diff against the prior baseline.
- After touching any function listed above: run that single bench (`cargo bench -p <crate> -- <function_name>`) and confirm no >10% regression.
- After a Rust toolchain upgrade: full sweep, since codegen changes can shift numbers ±5% without touching our code.

Do **not** treat criterion noise as a regression unless it's outside the reported confidence interval **and** reproducible across two runs.
