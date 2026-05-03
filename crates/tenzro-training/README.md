# tenzro-training

Protocol-only Rust crate for **Tenzro Train** — decentralized, verifiable, multi-modal foundation-model training over Decoupled DiLoCo.

## What this crate is

`tenzro-training` is the **Rust protocol layer** of Tenzro Train. It owns:

- **Aggregation rules** (`aggregation` module) — `Mean`, `TrimmedMean`, `CoordinateMedian`, `Krum`. All four are implemented and unit-tested. Phase 1 only exposes `Mean` via tier policy; the rest light up in Phase 2.
- **Outer optimizer** (`outer_optimizer` module) — Nesterov SGD state used between outer rounds.
- **On-chain commitments** (`commitments` module) — per-round `state_root`, per-run `run_root`, and the canonical signing bytes for `SyncRound` messages. Run roots are SHA-256 Merkle commitments domain-prefixed with `tenzro/train/run-root/v1`.
- **Syncer runtime** (`runtime` module) — `TrainingRuntime`, `FragmentBuffer`, `SyncerState`. Owns the K-of-M acceptance window, grace-period (τ) handling, and write-through persistence to `CF_TRAINING_RUNS` / `CF_TRAINING_RECEIPTS`.
- **Protocol types** (re-exported from `tenzro_types::training`) — `TrainingTaskSpec`, `OuterGradient`, `SyncRound`, `TrainingReceipt`, `TrainingTier`, `AggregationRule`, `ArchitectureSpec`, `TrainingModality`.

## What this crate is NOT

**It does not own the inner training loop.** No tensor library lives in this crate. No Candle, no Burn, no tch-rs, no llama.cpp.

The inner training loop — forward/backward, optimizer step, FSDP sharding — is the responsibility of the **Python reference trainer** at `integrations/trainer/` (PyTorch FSDP2 + Hivemind + safetensors). The two layers communicate over JSON-RPC (`tenzro_training_*` namespace exposed by `tenzro-node`) plus the gossip topics:

- `tenzro/training/1.0.0` — outer gradient submissions, fragment payloads
- `tenzro/training/syncer/1.0.0` — syncer status, round transitions, finality

This split mirrors how every production decentralized training run in 2026 (Prime Intellect's INTELLECT-1/2/3, Nous Research's Hermes 4.3 on Psyche/DisTrO, OpenDiLoCo) structures its stack: Python + PyTorch for the inner loop, a typed protocol crate for orchestration. See `TRAIN.md` §7.1 for the full rationale.

When the protocol layer needs to "train," it dispatches to the Python reference trainer over JSON-RPC and ingests the resulting `OuterGradient` / safetensors payload. Aggregation operates over already-decoded `ndarray` views of those payloads.

## Phase 1 scope

| Dimension | Phase 1 | Roadmap |
|---|---|---|
| Modality | Timeseries (TimesFM-class 200M) | Language, vision, multimodal |
| Trust tier | `Open` (stake bonding) | `Verified` (TEE attestation), `Confidential` (TEE-resident data) |
| Aggregation | `Mean` | `TrimmedMean`, `CoordinateMedian`, `Krum` |
| Reference hyperparams | M=8, K=6, F=12, H=24, AdamW lr=3e-4 inner, Nesterov SGD lr=0.7 mom=0.9 outer | — |

## Public API surface

```rust
pub use aggregation::{
    aggregator_for, Aggregator, CoordinateMedianAggregator, KrumAggregator,
    MeanAggregator, TrimmedMeanAggregator,
};
pub use commitments::{compute_run_root, compute_state_root, sync_round_signing_bytes};
pub use error::{Result, TrainingError};
pub use outer_optimizer::{NesterovSgdConfig, NesterovSgdState};
pub use runtime::{FragmentBuffer, SyncerState, TrainingRuntime};

pub use tenzro_types::training::{
    AggregationRule, ArchitectureSpec, FragmentQuorumStatus, OuterGradient, SyncRound,
    TrainingAttestation, TrainingModality, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};
```

## Integration points

- **`tenzro-types::training`** — type definitions (no logic). Lives in `tenzro-types` so RPC, storage, network, token, CLI, and the Python reference trainer can talk about training without circular dependencies.
- **`tenzro-node`** — exposes the `tenzro_training_*` JSON-RPC namespace (7 methods: `postTask`, `listRuns`, `getRun`, `getReceipt`, `enrollTrainer`, `submitOuterGradient`, `finalizeRound`) and persists to RocksDB column families `CF_TRAINING_RUNS` and `CF_TRAINING_RECEIPTS`.
- **`tenzro-cli`** — `tenzro train` subcommand group (`post-task`, `list-runs`, `get-run`, `get-receipt`, `enroll-trainer`, `submit-gradient`, `finalize-round`).
- **`tenzro-vm`** — `TRAINING_VERIFY` precompile at `0x1008` for on-chain receipt verification.
- **`integrations/trainer/`** — Python reference trainer.

## Tests

```bash
cargo test -p tenzro-training
```

## Further reading

- [`TRAIN.md`](../../TRAIN.md) — full whitepaper
- [Tenzro Train docs](https://tenzro.com/docs/tenzro-train) — developer reference
- [Tenzro Train whitepaper](https://tenzro.com/whitepapers/tenzro-train) — architecture and phasing

## License

Apache-2.0
