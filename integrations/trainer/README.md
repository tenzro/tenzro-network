# tenzro-trainer

**Tenzro Train reference trainer.** Python implementation of the inner
training loop with decoupled outer aggregation, paired with the Rust protocol layer in
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

## Scope

- **Modalities:** timeseries (TimesFM-class 200M models), language (Qwen 3 0.6B
  default via `transformers.AutoModelForCausalLM`; swap to any catalog LM via
  `architecture.metadata.hf_repo`), and vision (`timm` ViT-B/16 default; swap
  via `architecture.metadata.timm_model`). All share the same outer-gradient
  + RPC plumbing.
- **Trust tiers:** Open (stake bonding + redundant fragment assignment),
  Verified (TEE attestation at enrollment), and Confidential (TEE-resident
  data — `tenzro_trainer.confidential` unwraps sealed dataset shards inside
  the trainer's enclave via HPKE RFC 9180 + AES-256-GCM).
- **Aggregation:** the *Rust* syncer applies the task's `AggregationRule`
  (Mean and LoraAlternating on Open — LoraAlternating is the alternating-freeze
  rule for LoRA/QLoRA adapter runs; Mean / LoraAlternating / TrimmedMean /
  CoordinateMedian / Krum on Verified + Confidential) to the outer gradients
  submitted by all enrolled trainers.
  The Python trainer never sees other trainers' gradients — it only ever
  produces its own and submits the safetensors hash.
- **Objectives:** `Supervised` (default H-step SGD) or `RlPostTraining` — a
  GRPO inner loop for Language tasks. Per step the trainer samples a
  `group_size` rollout group from one shard prompt (the shard is a plain-text
  prompt list, one per line), scores completions with the sponsor-referenced
  reward callable (`reward_ref = "py:<module.path>:<callable>"`), computes
  group-relative advantages, and takes one optimizer step on the clipped
  surrogate with a k3 KL penalty against the sampling-time policy. No value
  model, no frozen reference copy; the outer-gradient contract is unchanged.
- **Inner optimizer:** selectable per task via `architecture.metadata.inner_optimizer`
  (`muon` / `adamw` / `sgd`, default `adamw`). Muon orthogonalizes 2D weight
  updates with Newton-Schulz iteration and falls back to AdamW for 1D,
  embedding, and head parameters.
- **Communication efficiency:** blockwise symmetric gradient quantization
  (`GradientQuantization`: Int8 4×, Int4 ~8× smaller than f32 — the codec in
  `tenzro_trainer.quantization` is byte-identical to the Rust implementation),
  streaming synchronization (one parameter shard per round when the task uses
  `SyncStrategy::Streaming`), and delayed outer-update application
  (`OuterUpdateScheduler` applies round r's update during round r+1 so
  communication overlaps computation).
- **Hardware acceleration:** under `torchrun` the language adapter shards the
  model with FSDP2 (per-parameter DTensor sharding, bf16 compute / fp32
  gradient reduction) — every rank runs the loop, only rank 0 speaks JSON-RPC,
  each rank samples distinct batches. Attention uses FlashAttention-2 when
  `flash_attn` + CUDA are present (SDPA otherwise; override via
  `architecture.metadata.attn_implementation`), and
  `architecture.metadata.fp8: true` opts eligible linear layers into torchao
  FP8 training on compute-capability ≥ 8.9 GPUs (`pip install
  'tenzro-trainer[fp8]'`). QLoRA (`lora.quantize: "nf4"`) is single-process
  only — bitsandbytes 4-bit parameters are not DTensor-compatible.

## Quickstart

```bash
# Install (editable) — choose the modality you need
cd integrations/trainer
pip install -e '.[timeseries]'

# Publish a dataset shard into the network's content-addressed blob store
# (iroh-blobs, BLAKE3-verified on transfer) and train against it. The
# trainer fetches tenzro:// shards through the local node's
# tenzro_iroh_fetchBlob RPC and caches them under ~/.cache/tenzro-trainer.
tenzro iroh publish --file shard-3.parquet
# → tenzro://blob/<blake3-hash>

tenzro-trainer run \
    --rpc-url http://localhost:8545 \
    --task-id task-timesfm-202604 \
    --trainer-did did:tenzro:machine:trainer-7 \
    --shard-uri tenzro://blob/<blake3-hash>

# Also supported: ipfs:// and ar:// (via HTTP gateways, override with
# TENZRO_IPFS_GATEWAY / TENZRO_ARWEAVE_GATEWAY), plain http(s)://, and
# file:// / bare local paths.

# Multi-GPU host: same command under torchrun. The language adapter shards
# the model with FSDP2; only rank 0 speaks JSON-RPC to the node.
torchrun --nproc-per-node 8 -m tenzro_trainer.cli run \
    --task-id task-qwen-202607 \
    --trainer-did did:tenzro:machine:trainer-7 \
    --shard-uri file:///data/shard.jsonl
```

The invocation above is the direct developer path. In production the trainer is
not launched by hand: a node with `[training] enabled = true` runs an
auto-provisioning daemon that discovers active runs and spawns one trainer
subprocess per run (deriving the trainer identity from the node key, supervising
restarts with exponential backoff). Operators pull the separate trainer image
built from `Dockerfile.trainer` — the base node image ships without this
package to stay lean. See `../../docs/AI.md` §7.7.5 for the daemon config,
identity derivation, crash policy, and the `tenzro_getTrainerDaemonStatus` RPC.

## Module layout

| Module | Purpose |
|---|---|
| `tenzro_trainer.types` | Python mirrors of `tenzro_types::training` (dataclasses serializable to the same JSON the Rust syncer expects). |
| `tenzro_trainer.rpc_bridge` | Thin JSON-RPC 2.0 client over `requests`. Handles `enrollTrainer`, `submitOuterGradient`, `finalizeRound`. |
| `tenzro_trainer.gradient` | Outer-gradient packaging: per-fragment safetensors blobs + SHA-256 + signing helpers (Ed25519 via PyNaCl). |
| `tenzro_trainer.inner_loop` | Generic H-step inner driver plus `OuterUpdateScheduler` (delayed outer-update application), partial-state load/apply for streaming shards, and state snapshots. |
| `tenzro_trainer.rl` | GRPO RL post-training inner loop: `RolloutAdapter` protocol, `load_reward`, group-relative advantages, clipped surrogate + k3 KL loss, `run_rl_inner_loop` (same `(pre, post, report)` contract as the supervised driver). |
| `tenzro_trainer.muon` | Muon inner optimizer — Newton-Schulz orthogonalization of 2D weight updates, AdamW fallback for 1D / embedding / head parameters. DTensor-aware: sharded gradients gather for Newton-Schulz, momentum stays sharded, the update distributes back. |
| `tenzro_trainer.distributed` | torchrun detection (`DistContext`), FSDP2 sharding (`shard_model_fsdp2`), and DTensor helpers (`full_tensor`, `copy_into`, `add_into`) used by the inner loop and Muon. |
| `tenzro_trainer.accel` | Attention-kernel selection (FlashAttention-2 / SDPA) and torchao FP8 conversion for the language adapter. |
| `tenzro_trainer.quantization` | Blockwise symmetric Int8/Int4 gradient codec, byte-identical to the Rust `tenzro_training::quantization` implementation. |
| `tenzro_trainer.shards` | Shard URI resolution: `tenzro://` via the local node's iroh blob store (native), `ipfs://` / `ar://` via HTTP gateways, `http(s)://` direct, `file://` / bare paths passthrough. Remote fetches cached under `~/.cache/tenzro-trainer/shards`; vision ImageFolder tarballs unpacked on arrival. |
| `tenzro_trainer.confidential` | Confidential-tier sealed-shard unwrap: HPKE RFC 9180 base-mode key unwrap + AES-256-GCM shard decryption, run inside the trainer's TEE enclave. |
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

Per-modality inner loops use the leading Python library for the modality:
`transformers` / native PyTorch for language, `gluonts` / native PyTorch for
timeseries, `timm` for vision. Outer gradients are packaged as safetensors
fragments with SHA-256 hashes and Ed25519 signatures.

See `AI.md` §7.7.1 and `crates/tenzro-training/src/lib.rs` for the full split
rationale.
