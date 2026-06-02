# tenzro-trainer

**Tenzro Train Phase 1 reference trainer.** Python implementation of the inner
training loop for Decoupled DiLoCo, paired with the Rust protocol layer in
[`crates/tenzro-training/`](../../crates/tenzro-training).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       tenzro-trainer (Python)                    │
│                                                                  │
│   ┌──────────────┐   ┌────────────────┐   ┌─────────────────┐  │
│   │   adapters   │   │   inner_loop   │   │  outer_gradient │  │
│   │              │   │                │   │                 │  │
│   │ - timeseries │──▶│  H × SGD step  │──▶│  Δθ = θ' − θ₀   │  │
│   │ - language   │   │  on local data │   │  per fragment   │  │
│   │ - vision     │   │  (PyTorch)     │   │  (safetensors)  │  │
│   └──────────────┘   └────────────────┘   └────────┬────────┘  │
│                                                     │            │
│                                            ┌────────▼────────┐  │
│                                            │   rpc_bridge    │  │
│                                            │ JSON-RPC client │  │
│                                            └────────┬────────┘  │
└─────────────────────────────────────────────────────┼───────────┘
                                                      │
                                                      ▼ JSON-RPC
                            ┌──────────────────────────────────┐
                            │  tenzro-node  (Rust)             │
                            │                                  │
                            │  - tenzro_training_enrollTrainer │
                            │  - tenzro_training_submit…       │
                            │  - tenzro_training_finalizeRound │
                            └──────────────────────────────────┘
```

## Phase 1 scope

- **Modalities:** timeseries (TimesFM-class 200M models), language (Qwen 3 0.6B
  default via `transformers.AutoModelForCausalLM`; swap to any catalog LM via
  `architecture.metadata.hf_repo`), and vision (`timm` ViT-B/16 default; swap
  via `architecture.metadata.timm_model`). All share the same outer-gradient
  + RPC plumbing.
- **Trust tier:** Open (no TEE attestation). Trust comes from stake bonding +
  redundant fragment assignment + Mean aggregation across K-of-M trainers.
- **Aggregation:** the *Rust* syncer applies `AggregationRule::Mean` to the
  outer gradients submitted by all enrolled trainers. The Python trainer never
  sees other trainers' gradients — it only ever produces its own and submits
  the safetensors hash.

## Quickstart

```bash
# Install (editable) — choose the modality you need
cd integrations/trainer
pip install -e '.[timeseries]'

# Train one round of a posted task
tenzro-trainer run \
    --rpc-url http://localhost:8545 \
    --task-id task-timesfm-202604 \
    --trainer-did did:tenzro:machine:trainer-7 \
    --shard-uri ipfs://Qm…/shard-3.parquet \
    --modality timeseries
```

## Module layout

| Module | Purpose |
|---|---|
| `tenzro_trainer.types` | Python mirrors of `tenzro_types::training` (dataclasses serializable to the same JSON the Rust syncer expects). |
| `tenzro_trainer.rpc_bridge` | Thin JSON-RPC 2.0 client over `requests`. Handles `enrollTrainer`, `submitOuterGradient`, `finalizeRound`. |
| `tenzro_trainer.gradient` | Outer-gradient packaging: per-fragment safetensors blobs + SHA-256 + signing helpers (Ed25519 via PyNaCl). |
| `tenzro_trainer.inner_loop` | Generic H-step inner SGD driver. Modality adapters provide a `step()` callable. |
| `tenzro_trainer.adapters.*` | Modality-specific model + dataset wiring. |
| `tenzro_trainer.cli` | `tenzro-trainer enroll | run | submit-gradient | finalize-round` |

## Why split Rust + Python

The Rust protocol layer in `tenzro-training` owns aggregation, commitments,
signatures, persistence, and the syncer state machine — all bandwidth- and
correctness-sensitive concerns where the broader Tenzro stack already
provides hardened primitives (BLS signatures, Merkle commitments, RocksDB
write-through, libp2p gossip, JSON-RPC). **No tensor library lives in the
Rust workspace** — no Candle, no Burn, no tch-rs, no llama.cpp.

The Python trainer owns the part that needs PyTorch: model definition,
forward / backward, optimizer steps, FSDP2 sharding, and shard ingestion.
Hivemind (when installed) provides the all-reduce primitives for in-fragment
data parallelism among co-located trainers; the cross-fragment outer-gradient
exchange is *not* Hivemind, it goes over the Rust syncer + the
`tenzro/training/*` gossipsub topics.

Per-modality inner loops use the SOTA Python library for the modality:
`transformers` / native PyTorch for language, `gluonts` / native PyTorch for
timeseries, `timm` for vision. Outer gradients are packaged as safetensors
fragments with SHA-256 hashes and Ed25519 signatures.

See `TRAIN.md` §7.1 and `crates/tenzro-training/src/lib.rs` for the full split
rationale.
