# tenzro-training

Protocol-only Rust crate for **Tenzro Train** — decentralized, verifiable, multi-modal foundation-model training over Decoupled DiLoCo.

## What this crate is

`tenzro-training` is the **Rust protocol layer** of Tenzro Train. It owns:

- **Aggregation rules** (`aggregation` module) — `Mean`, `TrimmedMean`, `CoordinateMedian`, `Krum`. All four are implemented and unit-tested; tier policy admits `Mean` on the Open tier and all four on Verified + Confidential.
- **Outer optimizer** (`outer_optimizer` module) — Nesterov SGD state used between outer rounds, plus adaptive learning rate: `gradient_agreement` computes pairwise cosine agreement across submitted outer gradients and `AdaptiveLrConfig` scales the outer step accordingly.
- **Gradient quantization** (`quantization` module) — blockwise symmetric Int8 (4× smaller than f32) and Int4 (~8×) codecs for outer-gradient payloads, byte-identical to the Python implementation in `tenzro_trainer.quantization`. Per-block 4-byte LE f32 scale followed by clamped integer codes; `GradientQuantization::None` is raw little-endian f32.
- **Witness committee** (`committee` module) — k-of-N committee selection over chain entropy for multi-syncer round finalization.
- **Confidential-tier sealed shards** (`confidential` module) — `SealedDatasetManifest` / `SealedShardEnvelope` validation, manifest hash binding, enrollment attestation checks.
- **Gossip codecs** (`gossip` module) — typed encode/decode for the `tenzro/training` and `tenzro/training/syncer` topics.
- **Payload store** (`payload_store` module) — `GradientPayloadStore` trait (SHA-256 protocol hash) with an in-memory implementation; the iroh-blobs adapter lives in `tenzro-iroh`.
- **On-chain commitments** (`commitments` module) — per-round `state_root`, per-run `run_root`, and the canonical signing bytes for `SyncRound` messages. Run roots are SHA-256 Merkle commitments domain-prefixed with `tenzro/train/run-root`.
- **Syncer runtime** (`runtime` module) — `TrainingRuntime`, `FragmentBuffer`, `SyncerState`. Owns the K-of-M acceptance window, grace-period (τ) handling, streaming-shard admission (`active_shard = round % num_shards`), pipeline-stage admission, and write-through persistence to `CF_TRAINING_RUNS` / `CF_TRAINING_RECEIPTS`.
- **Protocol types** (re-exported from `tenzro_types::training`) — `TrainingTaskSpec`, `OuterGradient`, `SyncRound`, `TrainingReceipt`, `TrainingTier`, `AggregationRule`, `ArchitectureSpec`, `TrainingModality`, `SyncStrategy`, `GradientQuantization`, `PipelineConfig`, `PipelineAssignment`.

## What this crate is NOT

**It does not own the inner training loop.** No tensor library lives in this crate. No Candle, no Burn, no tch-rs, no llama.cpp.

The inner training loop — forward/backward, optimizer step, FSDP sharding — is the responsibility of the **Python reference trainer** at `integrations/trainer/` (PyTorch FSDP2 + Hivemind + safetensors). The two layers communicate over JSON-RPC (`tenzro_training_*` namespace exposed by `tenzro-node`) plus the gossip topics:

- `tenzro/training` — outer gradient submissions, fragment payloads
- `tenzro/training/syncer` — syncer status, round transitions, finality

This split mirrors how every production decentralized training run in 2026 (Prime Intellect's INTELLECT-1/2/3, Nous Research's Hermes 4.3 on Psyche/DisTrO, OpenDiLoCo) structures its stack: Python + PyTorch for the inner loop, a typed protocol crate for orchestration. See `AI.md` §7.7.1 for the full rationale.

When the protocol layer needs to "train," it dispatches to the Python reference trainer over JSON-RPC and ingests the resulting `OuterGradient` / safetensors payload. Aggregation operates over already-decoded `ndarray` views of those payloads.

## Scope

| Dimension | Supported |
|---|---|
| Modality | Timeseries (TimesFM-class 200M), language (`transformers`), vision (`timm`) |
| Trust tier | `Open` (stake bonding), `Verified` (TEE attestation), `Confidential` (TEE-resident data via sealed shards) |
| Aggregation | `Mean` (all tiers); `TrimmedMean`, `CoordinateMedian`, `Krum` (Verified + Confidential) |
| Sync strategy | `Full` (every fragment every round) or `Streaming { num_shards }` (one shard per round, arXiv 2501.18512) |
| Quantization | `None`, `Int8 { block_size }` (4×), `Int4 { block_size }` (~8×) |
| Pipeline groups | `PipelineConfig { num_stages }` — a group of trainers jointly holds one replica; quorum counts distinct groups (arXiv 2506.21263) |
| Inner optimizer | Task-selectable in the Python trainer: `muon` / `adamw` / `sgd` (arXiv 2505.23725) |
| Reference hyperparams | M=8, K=6, F=12, H=24, AdamW lr=3e-4 inner, Nesterov SGD lr=0.7 mom=0.9 outer |

## Public API surface

```rust
pub use aggregation::{
    aggregator_for, Aggregator, CoordinateMedianAggregator, KrumAggregator,
    MeanAggregator, TrimmedMeanAggregator,
};
pub use commitments::{compute_run_root, compute_state_root, sync_round_signing_bytes};
pub use committee::{
    committee_seed, is_in_committee, recommended_committee_size, select_witness_committee,
};
pub use confidential::{
    compute_manifest_hash, compute_shard_ciphertext_hash, parse_tee_dataset_ref,
    validate_confidential_enrollment, verify_manifest_binding, verify_shard_ciphertext,
    InMemorySealedShardStore, SealedManifestStore, SealedShardStore,
};
pub use error::{Result, TrainingError};
pub use gossip::{
    decode_for_topic, encode_install_sealed_manifest, encode_outer_gradient, encode_sync_round,
    TrainingGossipMessage, TRAINING_SYNCER_TOPIC, TRAINING_TOPIC,
};
pub use outer_optimizer::{
    gradient_agreement, AdaptiveLrConfig, NesterovSgdConfig, NesterovSgdState,
};
pub use payload_store::{
    compute_payload_hash, verify_payload, GradientPayloadStore, InMemoryGradientStore,
};
pub use quantization::{dequantize, encoded_len, quantize};
pub use runtime::{
    min_tier_for_rule, validate_aggregation_for_tier, FragmentBuffer, SyncerState, TrainingRuntime,
};

pub use tenzro_types::training::{
    AggregationRule, ArchitectureSpec, FragmentQuorumStatus, GradientQuantization, OuterGradient,
    PipelineAssignment, PipelineConfig, SealedDatasetManifest, SealedShardEnvelope, SyncRound,
    SyncStrategy, TrainingAttestation, TrainingModality, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};
```

## Integration points

- **`tenzro-types::training`** — type definitions (no logic). Lives in `tenzro-types` so RPC, storage, network, token, CLI, and the Python reference trainer can talk about training without circular dependencies.
- **`tenzro-node`** — exposes the `tenzro_training_*` JSON-RPC namespace (9 methods: `postTask`, `listRuns`, `getRun`, `getReceipt`, `enrollTrainer`, `submitOuterGradient`, `finalizeRound`, `installSealedManifest`, `getSealedManifest`) and persists to RocksDB column families `CF_TRAINING_RUNS`, `CF_TRAINING_RECEIPTS`, and `CF_TRAINING_MANIFESTS`.
- **`tenzro-cli`** — `tenzro train` subcommand group (`post-task`, `list-runs`, `get-run`, `get-receipt`, `enroll-trainer`, `submit-gradient`, `finalize-round`, `install-sealed-manifest`, `get-sealed-manifest`).
- **`tenzro-vm`** — `TRAINING_VERIFY` precompile at `0x1008` for on-chain receipt verification.
- **`integrations/trainer/`** — Python reference trainer.

## Tests

```bash
cargo test -p tenzro-training
```

## Further reading

- [`AI.md`](../../AI.md) — full whitepaper
- [Tenzro Train docs](https://tenzro.com/docs/tenzro-train) — developer reference
- [Tenzro Train whitepaper](https://tenzro.com/whitepapers/tenzro-train) — architecture and phasing

## License

Apache-2.0
