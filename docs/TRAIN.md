# Tenzro Train

**Decentralized, Verifiable, Multi-Modal Foundation Model Training on Tenzro Network**

---

## Abstract

Tenzro Train is a protocol for training foundation models — language, timeseries, vision, and multimodal — across a permissionless network of independently operated compute providers. It adapts the Decoupled DiLoCo training algorithm (DeepMind, 2025) to a trustless setting by combining attested execution (TEE), Byzantine-robust gradient aggregation, and on-chain settlement to produce **verifiable training receipts**: cryptographically auditable records of who trained what, on which data, with what compute, settled in TNZO.

Where Decoupled DiLoCo's original setting assumes a single trusted operator running M chips inside a hyperscaler datacenter, Tenzro Train relaxes that assumption: learners are stake-bonded providers anywhere on the network, the syncer's correctness is enforced by attestation and fraud proofs, and the entire training run is reproducible from the ledger. The same protocol trains a 7B language model, a 200M timeseries foundation model, or a vision encoder — what differs is the data adapter and the loss function, not the coordination layer.

This document describes the protocol, the trust model, the economic design, and the implementation path within the existing Tenzro Network architecture.

---

## 1. Motivation

Foundation model training today is concentrated in a handful of hyperscalers, for two reasons that are coupled but distinct:

1. **Compute density** — synchronous SGD over thousands of accelerators requires high-bandwidth interconnects.
2. **Data gravity** — proprietary datasets sit inside organizational boundaries.

Decoupled DiLoCo addresses (1) by reducing inter-worker bandwidth by approximately two orders of magnitude relative to elastic data-parallel training, making cross-region (and ultimately cross-organization) training feasible. It does not address (2): in DeepMind's setting, learners are operated by the same entity that owns the data, and worker faults are hardware failures, not adversarial behavior.

Tenzro Train completes the picture: learners can be operated by independent parties, data can remain with its owner via TEE-resident execution, and the resulting model is settled on-chain with cryptographic provenance. This unlocks two distinct markets:

- **Commodity-compute training** — providers monetize idle GPUs, CPUs, or specialized accelerators by joining training runs and earning TNZO per accepted gradient.
- **Privacy-preserving training** — data owners contract with the network to train on their data without ever releasing it in cleartext, paying for compute in TNZO and receiving a verifiable model artifact.

Both markets apply equally to language models, timeseries models, vision models, and multimodal architectures. The protocol is modality-agnostic; modality enters only through the data adapter.

---

## 2. Background: Decoupled DiLoCo

DiLoCo (Distributed Low-Communication training) reduces synchronization bandwidth by performing many local SGD steps on each worker before exchanging parameter updates. Decoupled DiLoCo extends this with three further changes that matter for our setting:

1. **Asynchronous learners.** M learners train independently. None waits for any other.
2. **Centralized syncer.** A coordinator holds the global parameter state. After every H inner SGD steps a learner sends its outer gradient (param delta) to the syncer; the syncer applies a fragment-wise outer optimizer (Nesterov-momentum SGD in the paper) and ships the updated fragment back.
3. **Fragment-wise quorum.** Parameters are partitioned into P fragments. The syncer accepts an outer gradient for fragment j as soon as K of M learners have submitted; stragglers are absorbed via an adaptive grace window τ.

The reported result: at 1.2M-chip scale with 1-year MTBF per chip, Decoupled DiLoCo achieves 88% goodput versus 58% for elastic data-parallel, with no correctness loss versus synchronous baseline. Bandwidth between learners and syncer is approximately two orders of magnitude lower than elastic data-parallel.

What the paper does not provide and Tenzro Train must supply:

- **Trustless syncer.** The single syncer is a censorship and forgery surface in a permissionless network.
- **Adversarial gradient defense.** A malicious learner can submit poisoned outer gradients.
- **Verifiable execution.** A learner can claim to have trained on its assigned shard while actually replaying a checkpoint.
- **Data confidentiality.** Owners may not be willing to release training data in cleartext.
- **Settlement.** Compensation must be enforceable across organizational boundaries.

Each of these maps to existing Tenzro Network infrastructure.

---

## 3. Architecture

### 3.1 Roles

Tenzro Train introduces three new role specializations, layered on top of existing Tenzro provider roles:

- **Trainer** — a `ModelProvider` that has additionally staked the `TrainerCapability` and registered one or more `ArchitectureSpec` entries describing the model families it can train (e.g., `transformer-decoder/7B`, `timesfm/200M`, `vit-b/16`).
- **Syncer** — a stake-bonded validator-class node elected per training run, responsible for outer-optimizer state and fragment aggregation. Runs inside an attested TEE.
- **Sponsor** — the party initiating a training run. Posts a `TrainingTask` on-chain, escrows TNZO for rewards, and supplies the dataset reference (cleartext, encrypted, or TEE-sealed).

### 3.2 Training Run Lifecycle

```
                ┌──────────────────────────────────────────────────┐
                │ 1. Sponsor posts TrainingTask                    │
                │    - architecture, fragment plan, H, M, K, P, τ  │
                │    - dataset reference + access policy           │
                │    - reward budget (escrowed in TNZO)            │
                └─────────────────────┬────────────────────────────┘
                                      │
                ┌─────────────────────▼────────────────────────────┐
                │ 2. Syncer election                               │
                │    - VRF-weighted by stake among eligible nodes  │
                │    - elected syncer publishes TEE attestation    │
                └─────────────────────┬────────────────────────────┘
                                      │
                ┌─────────────────────▼────────────────────────────┐
                │ 3. Trainer enrollment                            │
                │    - trainers stake, post TEE attestation,       │
                │      receive shard assignment from syncer        │
                └─────────────────────┬────────────────────────────┘
                                      │
                ┌─────────────────────▼────────────────────────────┐
                │ 4. Training rounds (repeated until convergence)  │
                │    - each trainer runs H inner SGD steps         │
                │    - submits outer gradient to syncer            │
                │    - syncer aggregates K-of-M, publishes root    │
                │    - state root committed on-chain each round    │
                └─────────────────────┬────────────────────────────┘
                                      │
                ┌─────────────────────▼────────────────────────────┐
                │ 5. Finalization                                  │
                │    - final model hash committed on-chain         │
                │    - reward distribution per accepted gradient   │
                │    - training receipt sealed (NFT-style)         │
                └──────────────────────────────────────────────────┘
```

### 3.3 Trust Model

Tenzro Train does **not** require trainers to run inside a TEE. TEEs are one tool among several, and demanding them universally would lock out the long tail of GPU operators that make a permissionless network worth building. Instead, the protocol exposes three trust tiers — selected by the sponsor at task posting — and combines complementary defenses (stake, redundancy, robust aggregation, fraud proofs) so that strong end-to-end guarantees are reachable in every tier.

#### Three trust tiers

| Tier | Trainer hardware | Trust comes from | Typical use |
|---|---|---|---|
| **Open** | Any GPU (or CPU). No TEE required. | Stake bonding, Byzantine-robust aggregation, redundant fragment assignment, syncer fraud proofs. | Public-data foundation runs; the default tier. |
| **Verified** | Any GPU; trainer also posts a TEE attestation per round. | All of the above, plus attestation binding {program hash, data shard hash, model hash, DID}. | Provenance-sensitive runs (regulated industries, model-card claims). Higher reward weight. |
| **Confidential** | TEE'd CPU and/or TEE'd GPU (NVIDIA H100/B200 CC). | Same as Verified, plus the data is sealed to the enclave; the host OS never sees cleartext. | Private datasets (medical, financial, proprietary). |

Sponsors pay for what they use: Open is the cheap default, Verified adds an attestation premium, Confidential adds a hardware-scarcity premium. A trainer can opt into a higher tier than the task requires (and earn more); a trainer cannot satisfy a task by claiming a tier they don't operate in.

#### Defenses (always on)

**Stake bonding.** Every trainer escrows TNZO before being assigned fragments. Misbehavior — invalid signatures, missed deadlines, divergent outputs under redundant assignment, or losing a fraud-proof challenge — is slashed proportionally.

**Byzantine-robust aggregation.** A trainer might submit a numerically valid but adversarially crafted gradient (e.g., to insert a backdoor). The syncer applies one of:
- **Trimmed mean** — discard the top and bottom α% of gradients per parameter, mean the rest.
- **Coordinate-wise median** — robust to up to f < M/2 Byzantine learners.
- **Krum / Multi-Krum** — pick the gradient(s) with the lowest sum-of-distances to nearest neighbors.

The aggregation rule is committed in the `TrainingTask` and verified by all observers.

**Redundant assignment.** For high-value runs, the same data shard can be assigned to two or three independent trainers. The syncer compares their outer gradients; statistically significant divergence triggers slashing of the outliers. This is the protocol's primary defense against single-trainer malice in the Open tier — and works without any TEE.

**Syncer correctness via fraud proofs.** The syncer publishes per-round state roots on-chain. Any observer (a non-elected validator, a competing trainer, or the sponsor) can challenge a state root by submitting a fraud proof: a re-aggregation of the round's input gradients showing the posted root is incorrect. A successful challenge slashes the syncer's stake and re-runs the round.

This is the optimistic-rollup pattern applied to training. We chose it over running aggregation directly inside HotStuff-2 consensus because outer optimization is computationally heavier than typical block production and would saturate the validator set.

#### Where TEE is non-negotiable

Even though training itself is TEE-optional, Tenzro Network uses TEEs everywhere a key, identity, or verification authority is at stake — that is unchanged here:

- **Trainer keys.** Stake-bonding signatures, weight-update signatures, and payout addresses live in the operator's MPC wallet, whose key shares are TEE-sealed (`tenzro-tee` + `tenzro-wallet`). This holds for Open-tier trainers too.
- **Syncer election and signing.** The elected syncer signs round receipts with a key sealed inside its TEE; sponsors and observers verify those signatures against the syncer's attestation report. The syncer is always TEE'd; trainers may not be.
- **Confidential-tier data sealing.** Dataset symmetric keys, when used, are sealed to the trainer's enclave; cleartext never reaches the host OS.
- **Receipt minting.** The on-chain training receipt commits the syncer's TEE attestation chain alongside the merkle root of accepted gradients, so verifiers downstream can audit the syncer's identity even if individual trainers were Open-tier.

In short: **training compute is TEE-optional; key custody and verification are TEE-mandatory** — and the latter already runs in Tenzro today.

### 3.4 Data Confidentiality

Three modes, selected by the sponsor at task posting and aligned with the trust tiers above:

- **Public** (Open or Verified tier) — dataset is referenced by content hash (IPFS, Arweave, HTTP). Trainers download cleartext.
- **Encrypted-at-rest** (Verified or Confidential tier) — dataset is AES-GCM-encrypted; the symmetric key is sealed to the trainer's TEE attestation. The TEE decrypts only inside the enclave; the host OS never sees cleartext. Requires the trainer to be in Verified or Confidential tier.
- **TEE-resident** (Confidential tier only) — data never leaves the data owner's environment. Training runs inside a TEE colocated with the data; only outer gradients leave. This requires the trainer's hardware to be physically located with the data owner, or remote attestation over a confidential channel.

The protocol is the same across modes; only the data adapter and tier-eligibility check change.

---

## 4. Multi-Modal Support

The training protocol is agnostic to what the model's parameters represent. A modality is defined by four interfaces a trainer must implement:

```rust
trait ModalityAdapter {
    type Sample;
    type Batch;

    /// Hash the data shard for attestation binding.
    fn shard_hash(&self, shard: &DataShard) -> Hash;

    /// Decode raw bytes into training samples (tokens, windows, patches, ...).
    fn decode(&self, bytes: &[u8]) -> Vec<Self::Sample>;

    /// Assemble samples into a training batch with the right shape.
    fn collate(&self, samples: Vec<Self::Sample>) -> Self::Batch;

    /// Compute the loss given model output and batch.
    fn loss(&self, output: ModelOutput, batch: Self::Batch) -> Tensor;
}
```

Tenzro Train ships reference adapters for the modalities below. Sponsors can register additional adapters by publishing the adapter code's hash on-chain alongside their `TrainingTask`.

### 4.1 Language

- **Architectures**: decoder-only transformer (Llama-style), MoE (Mixtral-style), state-space (Mamba).
- **Sample type**: token sequences (BPE/SentencePiece).
- **Loss**: causal cross-entropy.
- **Validation**: perplexity on held-out, downstream eval suites (MMLU, HumanEval, BBH).
- **Fragment partitioning**: per transformer block, with embedding and unembedding as their own fragments.

### 4.2 Timeseries

This is the most underserved modality and arguably the strongest fit for Tenzro Train's economic model.

- **Architectures**:
  - **TimesFM-style** — decoder transformer over patched timeseries, autoregressive forecasting.
  - **Chronos-style** — quantize timeseries into tokens, train a language model on them.
  - **Moirai-style** — masked encoder for any-frequency forecasting.
  - **Temporal Fusion Transformer** — interpretable attention with static covariates.
  - **N-BEATS / NHITS** — pure MLP backbones with basis decomposition.
  - **State-space models** — Mamba-style continuous-time dynamics.
- **Sample type**: `(history_window, future_window, covariates, frequency)` tuples.
- **Loss**: pinball/quantile loss (probabilistic forecasting), MASE, or MSE depending on task.
- **Validation**: MASE, sMAPE, CRPS on held-out windows; rolling-origin evaluation.
- **Fragment partitioning**: same as transformer for TimesFM/Chronos/Moirai; per-block for TFT; per-stack for N-BEATS.

Why timeseries fits Tenzro especially well:

1. **Model size.** Frontier timeseries foundation models (TimesFM 200M, Chronos T5-small 60M, Moirai-base 91M) are 1-3 orders of magnitude smaller than frontier LLMs. They train on consumer GPUs and even CPUs. This opens the trainer market to ordinary participants, not just datacenter operators.

2. **Data privacy.** Timeseries datasets are dominated by privately owned data: financial tick data, energy consumption, IoT sensor streams, healthcare vitals, supply-chain logistics, in-game telemetry. The TEE-resident mode is a direct value-prop, not a hypothetical one.

3. **On-chain consumers.** Tenzro Network already has DeFi rails, oracles, and RWA tokenization. A trained forecasting model can be deployed as an inference endpoint that on-chain contracts consume directly — pricing oracles, risk models, automated market makers. The training-to-deployment loop closes inside the network.

4. **Greenfield.** Foundation timeseries models are nascent (TimesFM, Chronos, Moirai all 2024). There is no incumbent monopoly to displace; first-mover positioning is realistic.

### 4.3 Vision

- **Architectures**: ViT, ConvNeXt, diffusion U-Nets.
- **Sample type**: image patches with positional encoding.
- **Loss**: cross-entropy (classification), contrastive (CLIP-style), denoising score matching (diffusion).
- **Fragment partitioning**: per transformer block (ViT), per stage (ConvNeXt), per resolution level (U-Net).

### 4.4 Multimodal

CLIP-style dual encoders, audio (Whisper-style), and video extend naturally. The adapter implements a per-modality decode path; the model contains separately-named parameter groups; fragment partitioning treats each tower as an independent set of fragments.

### 4.5 Heterogeneous Trainers

Different trainers may have different hardware (e.g., A100 vs. consumer 4090 vs. CPU-only). Decoupled DiLoCo's quorum-based design handles this naturally: slower trainers fall behind in vector-clock order but their late submissions are absorbed by τ. Sponsors can also tier trainers by `min_throughput` requirements in the `TrainingTask`, which the syncer enforces at enrollment.

---

## 5. Bandwidth and Throughput

For a model of P parameters partitioned into F fragments with H inner steps per outer round:

- **Per-round trainer→syncer bandwidth**: P × F⁻¹ × dtype_size per fragment update, sent F times per round if the trainer participates in all fragments. For a 7B model at FP16 with F=24: ~580 MB/round per trainer.
- **Per-round syncer→trainer bandwidth**: same.
- **Wall-clock per round**: dominated by inner training time. For H=24 inner steps on a 7B model on a single A100, ~minutes; the network transfer is comfortably amortized.

Public-internet feasibility:

| Model size | F | Per-fragment xfer (FP16) | At 100 Mbps | At 1 Gbps |
|---|---|---|---|---|
| 200M | 12 | 33 MB | 2.6s | 0.3s |
| 1B | 24 | 83 MB | 6.6s | 0.7s |
| 7B | 24 | 580 MB | 46s | 4.6s |
| 70B | 48 | 2.9 GB | 232s | 23s |

For 200M-1B models (covering all current frontier timeseries foundation models), public-internet trainers are entirely viable. For 7B+ language models, geographic clustering or compressed gradients (INT8 or top-k sparsification) become attractive.

---

## 6. Economics

### 6.1 Reward Distribution

Sponsor escrows `R` TNZO per `TrainingTask`. After each round in which a trainer's outer gradient is included in the syncer's aggregation, the trainer accrues `R / (rounds × M_per_round)` TNZO. Rewards are distributed at training-run finalization.

### 6.2 Slashing Conditions

- **Failed TEE attestation** → trainer's stake is slashed proportional to rounds completed.
- **Divergent gradient on redundant assignment** → outlier trainer slashed, model state rolled back to last unanimous round.
- **Syncer fraud proof accepted** → syncer's stake fully slashed, run paused for re-election.
- **Sponsor abandonment** → escrow forfeited to participating trainers.

### 6.3 Network Commission

Tenzro Network takes a configurable commission (default 5%) on the training reward pool, accruing to the treasury for protocol development and validator rewards. This matches the existing AI inference and TEE service fee model.

### 6.4 Verifiable Training Receipts

At finalization, the syncer publishes a `TrainingReceipt` on-chain containing:
- Final model parameter hash
- Sponsor DID, syncer DID, list of contributing trainer DIDs with their per-round contribution counts
- Reward distribution
- Per-round state roots (Merkle-rooted into a single training-run hash)
- TEE attestation chain
- Architecture spec, hyperparameters, dataset reference

The receipt is mintable as an NFT (using `tenzro-vm`'s NFT factory) and represents proof-of-training for the resulting model. This is the artifact that distinguishes Tenzro Train from any centralized training service: every step is auditable, every contributor is named, and the model's lineage is permanent on-chain.

---

## 7. Implementation Path

### 7.1 Architecture: Rust protocol + Python reference trainer

Tenzro Train splits cleanly into two layers — a Rust **protocol layer** that owns coordination, settlement, and verification, and a Python **inner-training reference** that owns the actual gradient computation. This mirrors the split shipped by every production decentralized training project in 2026 (Prime Intellect's `protocol` + `prime`/`prime-RL`; Nous Research's Psyche network + custom Torchitan).

**Why this split:** PyTorch's training ecosystem (FSDP2, DTensor, torch.compile, Hivemind, transformers, gluonts, timm, and per-architecture implementations of TimesFM/Chronos/Moirai/Llama/ViT) is irreplaceable for inner training in 2026. Rust ML frameworks (Candle, Burn, tch-rs) are excellent for inference and protocol code but no production decentralized training run picks them as the inner trainer — the per-modality library coverage isn't there. llama.cpp's `finetune` is LoRA-only, LLaMA-architecture-only, and does not cover timeseries or vision. Rather than reimplement the PyTorch ecosystem in Rust, Tenzro Train uses Rust for what Rust is best at (deterministic protocol code, on-chain commitments, signature verification, gossip topics) and delegates inner training to the existing Python tooling.

#### New Rust Crate: `tenzro-training`

Pure-Rust crate, no networking, no consensus dependencies, **no tensor library**. Defines:

- `OuterGradient`, `Fragment`, `LearnerVectorClock`, `SyncRound` types
- `Aggregator` trait with implementations: `MeanAggregator`, `TrimmedMeanAggregator`, `CoordinateMedianAggregator`, `KrumAggregator` (operating over `ndarray` views of safetensors-decoded tensors)
- `OuterOptimizer` trait with `NesterovSgd` reference implementation
- `TrainingTaskSpec` — the on-chain task description
- `TrainingReceipt` — the on-chain finalization artifact
- `TrainingTier` enum: `Open` / `Verified` / `Confidential`

The crate intentionally does **not** define a `ModalityAdapter` in Rust. Modality-specific decoding, batching, and loss computation live entirely in the Python reference trainer where the SOTA libraries already exist.

#### New Integration: `integrations/trainer/`

Python reference trainer that implements the inner training loop for each modality. Built on:

- **PyTorch FSDP2** — intra-node sharding (matches OpenDiLoCo / Prime Intellect's stack)
- **Hivemind** — DHT-based inter-worker coordination metadata (the published OpenDiLoCo reference uses Hivemind; we adopt it directly to avoid reinventing peer discovery)
- **safetensors** — fragment serialization on the wire (TEE-friendly, deterministic, no pickle)
- **Per-modality libraries** — `transformers` for language, `gluonts` + native PyTorch for timeseries (TimesFM, Chronos, Moirai), `timm` + native PyTorch for vision

The Python trainer is a thin agent that:

1. Authenticates with its TDIP DID + MPC wallet (via the Tenzro JSON-RPC).
2. Subscribes to the `tenzro/training` gossip topic.
3. On task assignment, downloads the dataset shard, runs H inner SGD steps with the appropriate inner optimizer, and emits its outer gradient as a safetensors blob.
4. Submits the safetensors blob + signature to the Rust syncer over JSON-RPC (`tenzro_training_submitOuterGradient`).
5. Listens for round-completion events on `tenzro/training/syncer` and pulls updated fragments back from the syncer.

The trainer can run anywhere Python + PyTorch run, including inside a TEE (Verified / Confidential tiers). The Rust syncer never touches a tensor; it only verifies signatures, runs the chosen aggregation rule over decoded `ndarray` views, applies the outer optimizer, and commits the result on-chain.

### 7.2 Extensions to Existing Crates

- **`tenzro-types`** — add `TrainingTask`, `OuterGradient`, `TrainingReceipt`, `ArchitectureSpec`, `TrainingTier` types.
- **`tenzro-storage`** — add `CF_TRAINING_RUNS`, `CF_TRAINING_RECEIPTS` column families.
- **`tenzro-network`** — add gossipsub topic `tenzro/training` for outer gradient broadcast and `tenzro/training/syncer` for syncer state roots.
- **`tenzro-token`** — add `TrainerCapability` to staking; add `SyncerCapability` for elected syncers.
- **`tenzro-vm`** — add precompile `0x1008` (TRAINING_VERIFY) for fraud-proof verification on-chain. Phase 1 ships the precompile shell; Phase 2 lights up full re-aggregation verification.
- **`tenzro-node`** — RPC namespace `tenzro_training_*`: `postTrainingTask`, `enrollTrainer`, `submitOuterGradient`, `getTrainingRun`, `getTrainingReceipt`, `challengeStateRoot`.
- **`tenzro-cli`** — `tenzro train` subcommand: `post`, `enroll`, `status`, `claim-rewards`, `verify-receipt`.
- **`tenzro-agent-kit`** — reference templates: `language-trainer`, `timeseries-trainer`, `vision-trainer` agents that wrap the Python reference trainer and auto-enroll in matching tasks.

### 7.3 Dependencies

- **Rust protocol layer** — only `ndarray` and `safetensors` for parsing tensors at the aggregation step. No tensor library in the Rust workspace.
- **Python reference trainer** — PyTorch (FSDP2 / DTensor / safetensors / torch.compile), Hivemind for inter-worker coordination, plus per-modality libraries: `transformers`, `gluonts`, `timm`.
- **Tensor serialization on the wire** — `safetensors` (no Python pickle, deterministic bytes, TEE-friendly).

### 7.4 Phased Delivery

**Phase 1: Single-modality MVP (timeseries)**
- 200M-parameter TimesFM-style model
- 4-8 trainers, single-region
- TEE attestation + simple mean aggregation (no Byzantine defense yet)
- On-chain task posting + reward distribution
- Goal: prove the protocol end-to-end on the smallest interesting model

**Phase 2: Byzantine-robust aggregation**
- Add trimmed mean, coordinate median, Krum
- Add redundant assignment + divergence-triggered slashing
- Goal: harden against adversarial trainers

**Phase 3: Multi-region + larger models**
- 1B-7B language models
- Cross-region trainers
- Compressed gradients (INT8, top-k)
- Goal: scale up

**Phase 4: Multi-modal**
- Vision adapters
- Multimodal (CLIP-style) adapters
- Sponsor-defined custom adapters
- Goal: full modality coverage

**Phase 5: TEE-resident data mode**
- Encrypted-at-rest data flow
- TEE-resident training with sealed data
- Goal: enable privacy-preserving training as a product

---

## 8. Comparison with Existing Approaches

| Approach | Permissionless | Verifiable | Privacy | Multi-modal | Settlement |
|---|---|---|---|---|---|
| Centralized DC training (OpenAI, Anthropic) | No | No | No | Yes | Off-chain |
| Decoupled DiLoCo (DeepMind, original) | No | No | No | Yes (in principle) | N/A |
| Federated learning (FedAvg, etc.) | Partial | No | Partial | Yes | None |
| Bittensor | Yes | Partial (via consensus) | No | Limited | TAO |
| Akash + custom orchestration | Yes | No | No | Yes | AKT |
| **Tenzro Train** | **Yes** | **Yes (TEE + fraud proofs + receipts)** | **Yes (TEE-resident mode)** | **Yes** | **TNZO, on-chain** |

Tenzro Train's distinctive combination is verifiability + privacy + multi-modal in a single protocol with native on-chain settlement. No existing system covers all four.

---

## 9. Open Questions

- **Convergence under adversarial gradient floors.** Byzantine-robust aggregators (especially coordinate median) may slow convergence relative to mean aggregation. Quantifying the cost is required before recommending a default.
- **Optimal F (fragment count).** Higher F means smaller per-fragment transfers but more coordination overhead. The sweet spot is model- and bandwidth-dependent.
- **Syncer state size.** For a 70B model with full optimizer state (Adam: 3× param size), the syncer holds ~840 GB. This argues for sharded syncers (multiple elected nodes each owning a fragment range) for the largest models. Single-syncer suffices for the 1B-class models we expect to train first.
- **Cross-modality fragment-aware scheduling.** A trainer with limited memory may want to participate only in some fragments. The protocol allows this; the economics need to ensure such participation is fairly rewarded.
- **Long-running run resumability.** A training run may take days or weeks. Trainers join and leave continuously. Decoupled DiLoCo handles this natively via vector clocks; we need to confirm the on-chain commitment cadence doesn't become a cost bottleneck. State roots every N rounds (rather than every round) is the obvious lever.

---

## 10. Conclusion

Tenzro Train is a tractable extension of the existing Tenzro Network. The training algorithm (Decoupled DiLoCo) is published and proven. The trust primitives (TEE attestation, stake slashing, fraud proofs) already exist in production. The economic rails (TNZO escrow, micropayments, receipt minting) are operational. What's left is the integration work: a new crate, extensions to a handful of existing crates, and reference adapters for the modalities we want to support first.

The protocol is the same whether we're training a 200M timeseries forecaster or a 7B language model. The first product to ship should be the timeseries one — smaller models, underserved market, immediate on-chain consumers, strongest privacy story. Language models follow. Vision and multimodal extend naturally from there.

The result is a network where any participant with compute can earn TNZO by training models, any data owner can train on private data without releasing it, and any consumer of the resulting models can verify their full provenance from the ledger. That is a credible alternative to centralized model training, and it fits inside Tenzro Network without rearchitecting anything that already works.

---

## Appendix A: Reference Hyperparameters

For initial timeseries MVP (Phase 1):

| Parameter | Value |
|---|---|
| Model | TimesFM-style decoder, 200M params |
| M (trainers) | 8 |
| K (quorum) | 6 |
| F (fragments) | 12 |
| H (inner steps) | 24 |
| τ (grace window) | 2 inner-step durations |
| Inner optimizer | AdamW, lr=3e-4 |
| Outer optimizer | Nesterov SGD, lr=0.7, momentum=0.9 |
| Aggregation | Trimmed mean (α=12.5%) |
| TEE attestation refresh | Per round |
| State root commitment | Per round |

For Phase 3 language scaling:

| Parameter | Value |
|---|---|
| Model | Llama-style decoder, 7B params |
| M (trainers) | 32 |
| K (quorum) | 24 |
| F (fragments) | 24 |
| H (inner steps) | 24 |
| Gradient compression | INT8 with stochastic rounding |
| State root commitment | Every 4 rounds |

---

## Appendix B: Related Work

- Douillard et al., *Decoupled DiLoCo: A New Frontier for Resilient Distributed AI Training*, DeepMind, 2025.
- Douillard et al., *DiLoCo: Distributed Low-Communication Training of Language Models*, 2023.
- Das et al., *TimesFM: A decoder-only foundation model for time-series forecasting*, Google, 2024.
- Ansari et al., *Chronos: Learning the Language of Time Series*, Amazon, 2024.
- Woo et al., *Moirai: A Time Series Foundation Model for Universal Forecasting*, Salesforce, 2024.
- Blanchard et al., *Krum: Machine Learning with Adversaries*, NeurIPS 2017.
- Yin et al., *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates*, ICML 2018.
- Costan & Devadas, *Intel SGX Explained*, IACR ePrint 2016/086.
- AMD, *SEV-SNP: Strengthening VM Isolation with Integrity Protection and More*, 2020.
