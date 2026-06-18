# Tenzro AI

**Decentralized, verifiable AI inference and training on Tenzro Network**

---

## Abstract

Tenzro AI is the protocol surface that makes intelligence a network resource — discovered, compensated, attested, and settled in TNZO. The same network providers serve dense single-replica inference, sharded Mixture-of-Experts serving for frontier-scale models, speculative decoding via Multi-Token Prediction, multi-modal inference across seven ONNX runtimes plus the llama.cpp language path, TEE-confidential inference, recurrent-depth reasoning (Cortex), and Decoupled-DiLoCo decentralized training.

None of these are silos. Compute providers serving an MoE expert shard are the same providers that serve a dense Qwen 3.5 27B chat completion. The TDIP identity that pays a per-token bill on inference is the same identity that sponsors a training run. The reputation a provider earns serving inference is the reputation that admits them to a training witness committee. The protocol layer underwrites all of it with one consensus, one settlement asset, and one identity model.

This document describes the inference surface, the MoE serving primitives, MTP wiring, multi-modal coverage, the confidential-execution path, Cortex, and Tenzro Train.

---

## 1. Decentralized AI infrastructure — design

The protocol layer treats AI compute as a coordinated resource. Three properties matter:

1. **Provider unity.** A single provider registration covers every modality and every role. A provider declares its capacities through one `ProviderCapacity` record (`max_concurrent_requests`, `requests_per_second`, `max_batch_size`, `mtp_enabled`, `drafter_vram_gb`, `moe_holdings`, `moe_roles`, `iroh_endpoint_id`). The inference router consults the same record regardless of whether the request is dense chat, an MoE expert batch, a forecast call, or an embedding lookup.
2. **One settlement substrate.** Inference settles per call, per token, or through a micropayment channel — every path uses the same TDIP-bound `IdentityPaymentBinder`, the same delegation scope checks, and the same network commission.
3. **Verifiability is co-designed with execution.** Plonky3 STARK proofs over the KoalaBear field cover inference output commitments; TEE attestation chains cover confidential inference; both anchor through on-chain commitment registries.

The crates that implement this:

- `tenzro-model` — catalog, registry, inference router, provider manager, MoE shard view, MoE dispatch planner, ONNX runtimes (forecast / vision / text-embed / segmentation / detection / audio / video)
- `tenzro-cortex` — recurrent-depth reasoning sidecar
- `tenzro-training` — Decoupled DiLoCo protocol layer (syncer, aggregators, receipts, on-chain commitments)
- `integrations/trainer/` — Python reference trainer (PyTorch FSDP2, Hivemind, safetensors)

---

## 2. Inference

### 2.1 Provider model

A node runs as a model provider with `--role model_provider`, registers each model it can serve through `tenzro_serveModel` (or `tenzro model serve` on the CLI), and the registration writes through to `CF_MODEL_SERVICES`. The provider's TDIP identity is bound at registration; payments route to its MPC wallet.

Provider economics:

- **Reputation tracking** mutates on success (+1, saturating at 1000) and on failure (−5, saturating at 0). The asymmetry against failure is intentional. `record_success` is gated to "settled-success only" so providers cannot game reputation without taking a real payment.
- **Bonding** is optional for the Open trust tier; mandatory for the Verified and Confidential tiers. A bonded provider's stake is slashable on misbehavior (invalid receipts, repeated SLA breach, withheld results).
- **Pricing** is provider-set. The catalog publishes a recommended pricing per model; providers may quote above or below. The router picks per the caller's strategy.

### 2.2 Routing strategies

`InferenceRouter::route()` is modality-aware. It reads the model's modality from the registry, picks the matching runtime, and dispatches a typed `InferencePayload` (Chat / Forecast / VisionEmbed / VisionSimilarity / TextEmbed / Segment / Detect / Transcribe / VideoEmbed). The strategy is one of:

- **`LowestPrice`** — cheapest matching provider
- **`LowestLatency`** — provider with the lowest moving-window latency
- **`HighestReputation`** — highest reputation among capable providers
- **`Random`** — uniformly random capable provider
- **`WeightedScore`** (default) — weighted composite of price / latency / reputation
- **`ReasoningDepth`** — Cortex-aware: prefer providers whose advertised max loop count meets or exceeds the caller's target depth

Additional filters compose with the strategy: an MTP filter when `params.custom["draft_n"]` is set, an MoE filter when expert routing is required.

### 2.3 Chat surface

Language inference is exposed five ways over one runtime:

- `tenzro_chat` and `tenzro_chatCompletion` JSON-RPC (the canonical Tenzro chat shape, with `params.custom["draft_n"]` for MTP and `params.custom["chat_session"]` for the persisted session id)
- `tenzro_chatStream` JSON-RPC streaming variant
- `POST /v1/chat/completions` — OpenAI-compatible HTTP endpoint (handler: `handle_openai_chat_completions`)
- `POST /api/paid/chat/completions` — HTTP 402-gated variant for x402 / MPP / AP2 payment binding
- `POST /chat-stream` — Anthropic-style SSE endpoint (handler: `handle_chat_stream_rich`)
- MCP `chat_completion` tool, A2A `inference` skill, CLI `tenzro chat`

Each surface is a thin wrapper over the same router and runtime — the model and provider are the same underneath.

### 2.4 Multi-Token Prediction

Speculative decoding lets a target model generate multiple tokens per inference step using a smaller drafter. **MTP** is the jointly-trained variant — an auxiliary head that shares hidden state with the target and produces tokens consistent with the target's distribution.

Tenzro wires MTP through the full path:

- **Catalog metadata.** Each `HfModelEntry` declares its paired drafter (`drafter_id`), the speculation flavour (`mtp_kind: DraftMtp` for joint MTP heads, `Generic` for classical drafter pairing), and the recommended starting `draft_n`.
- **Provider capacity.** `ProviderCapacity.mtp_enabled` advertises drafter co-load. `ProviderCapacity.drafter_vram_gb` advertises the VRAM headroom reserved for the drafter.
- **Router filter.** When the request carries `params.custom["draft_n"]`, the router filters to MTP-capable providers; when no MTP-capable provider exists for the model, the router falls back to standard autoregressive providers so the caller can degrade.
- **Runtime.** The MTP variant of llama.cpp consumes the joint head via the vendored `llama-cpp-rs` `MtpSpeculative` wrapper. `generate_speculative` accepts the longest matching prefix on each step.

Shipped in the catalog with `mtp_kind: DraftMtp`: DeepSeek V3 (native MTP head), DeepSeek V4 Pro / Flash, GLM 5.2, Gemma 4 (E2B / E4B / 12B / 26B-A4B / 31B), Qwen 3.5 every size (0.8B / 2B / 4B / 9B / 27B / 35B-A3B / 122B-A10B / 397B-A17B), Qwen 3.6 27B and 35B-A3B. For dense models without a joint head, classical two-model speculative decoding (`MtpKind::Generic`) is wired through the same path.

---

## 3. Mixture-of-Experts serving

MoE architectures activate a small subset of expert FFNs per token. Total parameter count can sit at 122B / 397B / 685B / 1T while the active path is only 3–37B — generation-time compute scales with the active path. Tenzro serves MoE in two modes that share the same provider population.

### 3.1 Full-replica mode

A provider whose hardware fits the entire model holds it and serves single-peer inference exactly like a dense model. Gemma 4 26B-A4B, Qwen 3.5 35B-A3B, Qwen 3.6 35B-A3B, Kimi K2.5, DeepSeek V3 on a single H200-class node.

### 3.2 Decentralized expert-shard mode

For models too large for any single provider, providers declare which subset of expert weights they hold via `ProviderCapacity.moe_holdings` — a list of `MoeExpertHolding { model_id, layer, expert, residency, committed_tps }`. Residency is `Warm` (VRAM-resident), `Cold` (disk only), or `Evicting`.

A dispatch planner (`plan_dispatch`) aggregates per-token top-k routing decisions into per-holder batches. Each batch carries the tokens whose top-k landed on the same `(expert, holder)` tuple. The batch is dispatched directly over the holder's iroh QUIC endpoint when available, or the OpenAI-compatible HTTP endpoint otherwise.

The shard view (`MoeShardView`) is a derived view over the existing `ProviderManager` — the compute providers serving MoE shards are the same network providers that serve dense models. The view is built from a borrowed slice of providers and pinned to one `model_id`. Stale providers (non-`Active`) and providers with no MoE roles declared are filtered out at view construction.

### 3.3 Pipeline roles

MoE pipeline roles are typed on `ProviderCapacity.moe_roles: Vec<MoeProviderRole>`. A provider can declare more than one role; the router picks the matching role per request.

- `Replica` — holds the full model; serves single-peer inference. Default.
- `Router` — runs the gating step and fans out batched expert calls.
- `ExpertHolder` — holds one or more experts declared in `moe_holdings`.
- `PrefillDecode` — runs both prefill and decode phases co-located.
- `Prefill` — prefill phase only; hands off KV cache to a `Decode` peer over iroh.
- `Decode` — decode phase only; consumes KV cache from a `Prefill` peer over iroh.

### 3.4 Replication policy

`ReplicationPolicy` defaults:

- `min_replication: 2` — every active expert must be held by at least 2 distinct providers
- `max_replication: 8` — ceiling on hot-expert replication
- `hot_threshold_tps: 1_000` — committed TPS above which an expert is considered hot

The view exposes `under_replicated(policy)` and `hot_experts(policy)` so a scheduler or governance layer can act on under-served or over-loaded experts.

### 3.5 RPCs

- `tenzro_moeShardMap` — live shard map: per-expert holder list, replication factor, under-replicated experts, hot experts, role counts
- `tenzro_moePlanDispatch` — given a list of per-token routing decisions, returns the per-holder batch plan plus token-level assignment so the caller can reassemble per-token outputs
- `tenzro_moeReplicationPolicy` — current policy snapshot
- `tenzro_moeCatalogShape` — catalog-side MoE topology for a model: `num_experts`, `experts_per_token`, `shared_experts`, `params_per_expert_x10`

### 3.6 Catalog coverage

Catalog entries that declare a `moe: Some(MoeShape { ... })` topology:

| Family | Catalog id | num_experts | top-k | shared |
|---|---|---:|---:|---:|
| Qwen 3 | `qwen3-30b-a3b` | 128 | 8 | 0 |
| Qwen 3 Coder | `qwen3-coder-30b-a3b` | 128 | 8 | 0 |
| Qwen 3.5 | `qwen3.5-35b-a3b`, `qwen3.5-122b-a10b`, `qwen3.5-397b-a17b` | 128 | 8 | 0 |
| Qwen 3.5 MTP | every Qwen 3.5 MoE size has a paired `-mtp` entry | 128 | 8 | 0 |
| Qwen 3.6 | `qwen3.6-35b-a3b`, `qwen3.6-35b-a3b-mtp` | 128 | 8 | 0 |
| Gemma 4 | `gemma4-26b-a4b`, `gemma4-26b-a4b-qat`, `gemma4-26b-a4b-mtp-draft` | 128 | 4 | 1 |
| DiffusionGemma | `diffusiongemma-26b-a4b` | 128 | 4 | 1 |
| Kimi | `kimi-k2-instruct`, `kimi-k2.5`, `kimi-k2.6`, `kimi-k2.7-code` | 384 | 8 | 1 |
| MiniMax | `minimax-m1-40b`, `minimax-m3` | 32 | 2 | 0 |
| DeepSeek | `deepseek-v3-0324`, `deepseek-v4-flash`, `deepseek-v4-pro` | 256 / 256 / 512 | 8 | 1 |
| GLM | `glm-5`, `glm-5.1`, `glm-5.2` | 160 | 8 | 1 |
| Nemotron Nano | `nemotron-nano-30b-a3b` | 16 | 4 | 0 |
| OpenAI | `gpt-oss-120b` | 128 | 4 | 0 |

---

## 4. Multi-modal serving

The catalog covers seven ONNX runtimes plus the llama.cpp language path. All entries pass through `ModelRegistry::register_model()` which enforces the license tier from the `LicenseTier` enum:

- **`Permissive`** (Apache-2.0, MIT, BSD-2/3) — loaded by default, no friction
- **`Attribution`** (CC-BY-4.0) — loaded by default, attribution string is logged
- **`CommercialCustom`** (DINOv3, SAM, Gemma) — bespoke commercial-OK licenses; refuse without explicit per-family acceptance
- **`NonCommercial`** (CC-BY-NC, OpenRAIL-M, etc.) — refused unless explicit opt-in

| Modality | Catalog families | RPC | RPC alias |
|---|---|---|---|
| Forecast | TimesFM 2.5 200M | `tenzro_forecast` | |
| Vision embedding | CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2 | `tenzro_imageEmbed` | `tenzro_visionEmbed` |
| Text embedding | Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0 | `tenzro_textEmbed` | `tenzro_embed` |
| Segmentation (point/box) | SAM 2 base/large, EdgeSAM, MobileSAM | `tenzro_segment` | |
| Segmentation (text-promptable) | SAM 3 / 3.1 | `tenzro_textSegment` | |
| Detection | RF-DETR n/s/m/b/l/2xl (90-class COCO), D-FINE n/s/m/l/x (80-class) | `tenzro_detect` | |
| Audio ASR | Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash | `tenzro_transcribe` | |
| Video | Vision-fallback encoder over uniformly-sampled frames | `tenzro_videoEmbed` | |

Each modality has a dedicated runtime in `tenzro-model` with model-specific preprocessing (mel-spectrogram for ASR, ImageNet / CLIP / SigLIP normalization for vision, BPE tokenization for text-embed). The runtime dispatch hides the per-family ABI differences (SAM 1 vs SAM 2 decoder, RF-DETR vs D-FINE post-processing, Parakeet RNN-T vs Canary NeMo Conformer-AED).

---

## 5. Confidential inference

Some inference paths require that the model weights, the input, or the output stay inside a hardware-attested enclave.

The model provider runs the inference inside an Intel TDX / AMD SEV-SNP / AWS Nitro Enclave / NVIDIA GPU Confidential Computing / Intel Tiber-attested enclave. The result is signed with an enclave-bound signing key whose attestation chain validates through one of the five vendors' root CAs. The signature anchors through the `TEE_VERIFY` precompile on-chain.

Three use-cases:

- **Model-weight confidentiality.** A provider serving a model under a license that prohibits weight extraction can run the inference inside the enclave so neither the request nor the inference path leaks the weights.
- **Input/output confidentiality.** An institutional caller (a bank requesting a NAV calculation, an asset manager pricing a bond) wraps the request and the response in HPKE envelopes sealed to the enclave's public key.
- **Hybrid ZK-in-TEE.** The enclave produces the witness, runs the Plonky3 prover inside, and signs the commitment with a PQ-hybrid composite signer (Ed25519 + ML-DSA-65 or secp256k1 + ML-DSA-65). The relying party can verify the ZK proof, the TEE attestation, or both.

---

## 6. Cortex

`tenzro-cortex` is a recurrent-depth-transformer reasoning lane exposed as a separate compute resource. Where standard chat inference produces one output token per step, Cortex workers re-feed hidden state through a recurrent depth dimension. Each loop costs additional compute and trades depth for quality.

The Tenzro Cortex surface:

- Runs as a separate Python sidecar that the node discovers via `tenzro/cortex` gossipsub advertisements
- Carries signed receipts per inference (commitments to weights hash, runtime hash, loops used, worker DID)
- Carries a TEE attestation chain matching the inference attestation surface
- Bills `price_per_loop * loops_used` on top of base token fees

Cortex is the path for reasoning workloads where the caller is willing to pay for verifiable depth (planning, formal verification of a contract clause, multi-step financial reasoning) rather than the linear-token economy of standard chat. The `RoutingStrategy::ReasoningDepth` filter routes a request to a Cortex worker whose advertised `max_loops` meets or exceeds the caller's target.

---

## 7. Tenzro Train

The rest of this document describes the protocol layer for decentralized training. The split between Rust protocol (`tenzro-training`) and Python reference trainer (`integrations/trainer/`) keeps the protocol layer free of tensor library churn while letting the per-modality adapters track frontier model architectures without protocol changes.

The training surface below preserves the original Tenzro Train design verbatim, renumbered to fit this document.

---

### 7.1 Motivation

Foundation model training today is concentrated in a handful of hyperscalers, for two reasons that are coupled but distinct:

1. **Compute density** — synchronous SGD over thousands of accelerators requires high-bandwidth interconnects.
2. **Data gravity** — proprietary datasets sit inside organizational boundaries.

Decoupled DiLoCo addresses (1) by reducing inter-worker bandwidth by approximately two orders of magnitude relative to elastic data-parallel training, making cross-region (and ultimately cross-organization) training feasible. It does not address (2): in DeepMind's setting, learners are operated by the same entity that owns the data, and worker faults are hardware failures, not adversarial behavior.

Tenzro Train completes the picture: learners can be operated by independent parties, data can remain with its owner via TEE-resident execution, and the resulting model is settled on-chain with cryptographic provenance. This unlocks two distinct markets:

- **Commodity-compute training** — providers monetize idle GPUs, CPUs, or specialized accelerators by joining training runs and earning TNZO per accepted gradient.
- **Privacy-preserving training** — data owners contract with the network to train on their data without ever releasing it in cleartext, paying for compute in TNZO and receiving a verifiable model artifact.

Both markets apply equally to language models, timeseries models, vision models, and multimodal architectures. The protocol is modality-agnostic; modality enters only through the data adapter.

---

### 7.2 Background: Decoupled DiLoCo

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

### 7.3 Architecture

#### 7.3.1 Roles

Tenzro Train introduces three new role specializations, layered on top of existing Tenzro provider roles:

- **Trainer** — a `ModelProvider` that has additionally staked the `TrainerCapability` and registered one or more `ArchitectureSpec` entries describing the model families it can train (e.g., `transformer-decoder/7B`, `timesfm/200M`, `vit-b/16`).
- **Syncer** — a stake-bonded validator-class node elected per training run, responsible for outer-optimizer state and fragment aggregation. Runs inside an attested TEE.
- **Sponsor** — the party initiating a training run. Posts a `TrainingTask` on-chain, escrows TNZO for rewards, and supplies the dataset reference (cleartext, encrypted, or TEE-sealed).

#### 7.3.2 Training Run Lifecycle

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

#### 7.3.3 Trust Model

Tenzro Train does **not** require trainers to run inside a TEE. TEEs are one tool among several, and demanding them universally would lock out the long tail of GPU operators that make a permissionless network worth building. Instead, the protocol exposes three trust tiers — selected by the sponsor at task posting — and combines complementary defenses (stake, redundancy, robust aggregation, fraud proofs) so that strong guarantees are reachable in every tier.

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

#### 7.3.4 Data Confidentiality

Three modes, selected by the sponsor at task posting and aligned with the trust tiers above:

- **Public** (Open or Verified tier) — dataset is referenced by content hash (IPFS, Arweave, HTTP). Trainers download cleartext.
- **Encrypted-at-rest** (Verified or Confidential tier) — dataset is AES-GCM-encrypted; the symmetric key is sealed to the trainer's TEE attestation. The TEE decrypts only inside the enclave; the host OS never sees cleartext. Requires the trainer to be in Verified or Confidential tier.
- **TEE-resident** (Confidential tier only) — data never leaves the data owner's environment. Training runs inside a TEE colocated with the data; only outer gradients leave. This requires the trainer's hardware to be physically located with the data owner, or remote attestation over a confidential channel.

The protocol is the same across modes; only the data adapter and tier-eligibility check change.

---

### 7.4 Multi-Modal Support

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

#### 7.4.1 Language

- **Architectures**: decoder-only transformer (Qwen 3 / 3.5 / 3.6 / Gemma 3 / 4 / Mistral / Phi 3 / DeepSeek V3 / Granite), MoE (Qwen 3.5-MoE / 3.6-MoE / Mixtral-style), state-space (Mamba).
- **Sample type**: token sequences (BPE/SentencePiece).
- **Loss**: causal cross-entropy.
- **Validation**: perplexity on held-out, downstream eval suites (MMLU, HumanEval, BBH).
- **Fragment partitioning**: per transformer block, with embedding and unembedding as their own fragments.

#### 7.4.2 Timeseries

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

#### 7.4.3 Vision

- **Architectures**: ViT, ConvNeXt, diffusion U-Nets.
- **Sample type**: image patches with positional encoding.
- **Loss**: cross-entropy (classification), contrastive (CLIP-style), denoising score matching (diffusion).
- **Fragment partitioning**: per transformer block (ViT), per stage (ConvNeXt), per resolution level (U-Net).

#### 7.4.4 Multimodal

CLIP-style dual encoders, audio (Whisper-style), and video extend naturally. The adapter implements a per-modality decode path; the model contains separately-named parameter groups; fragment partitioning treats each tower as an independent set of fragments.

#### 7.4.5 Heterogeneous Trainers

Different trainers may have different hardware (e.g., A100 vs. consumer 4090 vs. CPU-only). Decoupled DiLoCo's quorum-based design handles this naturally: slower trainers fall behind in vector-clock order but their late submissions are absorbed by τ. Sponsors can also tier trainers by `min_throughput` requirements in the `TrainingTask`, which the syncer enforces at enrollment.

---

### 7.5 Bandwidth and Throughput

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

### 7.6 Economics

#### 7.6.1 Reward Distribution

Sponsor escrows `R` TNZO per `TrainingTask`. After each round in which a trainer's outer gradient is included in the syncer's aggregation, the trainer accrues `R / (rounds × M_per_round)` TNZO. Rewards are distributed at training-run finalization.

#### 7.6.2 Slashing Conditions

- **Failed TEE attestation** → trainer's stake is slashed proportional to rounds completed.
- **Divergent gradient on redundant assignment** → outlier trainer slashed, model state rolled back to last unanimous round.
- **Syncer fraud proof accepted** → syncer's stake fully slashed, run paused for re-election.
- **Sponsor abandonment** → escrow forfeited to participating trainers.

#### 7.6.3 Network Commission

Tenzro Network takes a configurable commission (default 5%) on the training reward pool, accruing to the treasury for protocol development and validator rewards. This matches the existing AI inference and TEE service fee model.

#### 7.6.4 Verifiable Training Receipts

At finalization, the syncer publishes a `TrainingReceipt` on-chain containing:
- Final model parameter hash
- Sponsor DID, syncer DID, list of contributing trainer DIDs with their per-round contribution counts
- Reward distribution
- Per-round state roots (Merkle-rooted into a single training-run hash)
- TEE attestation chain
- Architecture spec, hyperparameters, dataset reference

The receipt is mintable as an NFT (using `tenzro-vm`'s NFT factory) and represents proof-of-training for the resulting model. This is the artifact that distinguishes Tenzro Train from any centralized training service: every step is auditable, every contributor is named, and the model's lineage is permanent on-chain.

---

### 7.7 Implementation Path

#### 7.7.1 Architecture: Rust protocol + Python reference trainer

Tenzro Train splits cleanly into two layers — a Rust **protocol layer** that owns coordination, settlement, and verification, and a Python **inner-training reference** that owns the actual gradient computation. This mirrors the split adopted by every production decentralized training project in 2026 (Prime Intellect, Nous Research, OpenDiLoCo).

**Why this split:** PyTorch's training ecosystem (FSDP2, DTensor, torch.compile, Hivemind, transformers, gluonts, timm, and per-architecture implementations of TimesFM/Chronos/Moirai/Llama/ViT) is irreplaceable for inner training in 2026. Rust ML frameworks (Candle, Burn, tch-rs) are excellent for inference and protocol code but no production decentralized training run picks them as the inner trainer — the per-modality library coverage isn't there. llama.cpp's `finetune` is LoRA-only, LLaMA-architecture-only, and does not cover timeseries or vision. Rather than reimplement the PyTorch ecosystem in Rust, Tenzro Train uses Rust for what Rust is best at (deterministic protocol code, on-chain commitments, signature verification, gossip topics) and delegates inner training to the existing Python tooling.

#### New Rust Crate: `tenzro-training`

Pure-Rust crate, no networking, no consensus dependencies, **no tensor library**. Defines:

- `OuterGradient`, `Fragment`, `LearnerVectorClock`, `SyncRound` types
- `Aggregator` trait with implementations: `MeanAggregator`, `TrimmedMeanAggregator`, `CoordinateMedianAggregator`, `KrumAggregator` (operating over `ndarray` views of safetensors-decoded tensors)
- `OuterOptimizer` trait with `NesterovSgd` reference implementation
- `TrainingTaskSpec` — the on-chain task description
- `TrainingReceipt` — the on-chain finalization artifact
- `TrainingTier` enum: `Open` / `Verified` / `Confidential`

The crate intentionally does **not** define a `ModalityAdapter` in Rust. Modality-specific decoding, batching, and loss computation live entirely in the Python reference trainer where the frontier libraries already exist.

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

#### 7.7.2 Extensions to Existing Crates

- **`tenzro-types`** — add `TrainingTask`, `OuterGradient`, `TrainingReceipt`, `ArchitectureSpec`, `TrainingTier` types.
- **`tenzro-storage`** — add `CF_TRAINING_RUNS`, `CF_TRAINING_RECEIPTS` column families.
- **`tenzro-network`** — add gossipsub topic `tenzro/training` for outer gradient broadcast and `tenzro/training/syncer` for syncer state roots.
- **`tenzro-token`** — add `TrainerCapability` to staking; add `SyncerCapability` for elected syncers.
- **`tenzro-vm`** — add precompile `0x1008` (TRAINING_VERIFY) for fraud-proof verification on-chain. Phase 1 ships the precompile shell; Phase 2 lights up full re-aggregation verification.
- **`tenzro-node`** — RPC namespace `tenzro_training_*`: `postTrainingTask`, `enrollTrainer`, `submitOuterGradient`, `getTrainingRun`, `getTrainingReceipt`, `challengeStateRoot`.
- **`tenzro-cli`** — `tenzro train` subcommand: `post`, `enroll`, `status`, `claim-rewards`, `verify-receipt`.
- **`tenzro-agent-kit`** — reference templates: `language-trainer`, `timeseries-trainer`, `vision-trainer` agents that wrap the Python reference trainer and auto-enroll in matching tasks.

#### 7.7.3 Dependencies

- **Rust protocol layer** — only `ndarray` and `safetensors` for parsing tensors at the aggregation step. No tensor library in the Rust workspace.
- **Python reference trainer** — PyTorch (FSDP2 / DTensor / safetensors / torch.compile), Hivemind for inter-worker coordination, plus per-modality libraries: `transformers`, `gluonts`, `timm`.
- **Tensor serialization on the wire** — `safetensors` (no Python pickle, deterministic bytes, TEE-friendly).

#### 7.7.4 Phased Delivery

**Phase 1: Single-modality MVP (timeseries)**
- 200M-parameter TimesFM-style model
- 4-8 trainers, single-region
- TEE attestation + simple mean aggregation (no Byzantine defense yet)
- On-chain task posting + reward distribution
- Goal: prove the protocol on the smallest interesting model

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

### 7.8 Comparison with Existing Approaches

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

### 7.9 Open Questions

- **Convergence under adversarial gradient floors.** Byzantine-robust aggregators (especially coordinate median) may slow convergence relative to mean aggregation. Quantifying the cost is required before recommending a default.
- **Optimal F (fragment count).** Higher F means smaller per-fragment transfers but more coordination overhead. The sweet spot is model- and bandwidth-dependent.
- **Syncer state size.** For a 70B model with full optimizer state (Adam: 3× param size), the syncer holds ~840 GB. This argues for sharded syncers (multiple elected nodes each owning a fragment range) for the largest models. Single-syncer suffices for the 1B-class models we expect to train first.
- **Cross-modality fragment-aware scheduling.** A trainer with limited memory may want to participate only in some fragments. The protocol allows this; the economics need to ensure such participation is fairly rewarded.
- **Long-running run resumability.** A training run may take days or weeks. Trainers join and leave continuously. Decoupled DiLoCo handles this natively via vector clocks; we need to confirm the on-chain commitment cadence doesn't become a cost bottleneck. State roots every N rounds (rather than every round) is the obvious lever.

---

### 7.10 Conclusion

Tenzro Train is a tractable extension of the existing Tenzro Network. The training algorithm (Decoupled DiLoCo) is published and proven. The trust primitives (TEE attestation, stake slashing, fraud proofs) already exist in production. The economic rails (TNZO escrow, micropayments, receipt minting) are operational. What's left is the integration work: a new crate, extensions to a handful of existing crates, and reference adapters for the modalities we want to support first.

The protocol is the same whether we're training a 200M timeseries forecaster or a 7B language model. The first product to release should be the timeseries one — smaller models, underserved market, immediate on-chain consumers, strongest privacy story. Language models follow. Vision and multimodal extend naturally from there.

The result is a network where any participant with compute can earn TNZO by training models, any data owner can train on private data without releasing it, and any consumer of the resulting models can verify their full provenance from the ledger. That is a credible alternative to centralized model training, and it fits inside Tenzro Network without rearchitecting anything that already works.

---

### 7.A Reference hyperparameters

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
| Model | Qwen 3.5-style decoder (any catalog-member LM family swappable — Qwen 3 / 3.5 / 3.6, Gemma 3 / 4, Mistral, Phi 3, DeepSeek V3, Granite), 7B params |
| M (trainers) | 32 |
| K (quorum) | 24 |
| F (fragments) | 24 |
| H (inner steps) | 24 |
| Gradient compression | INT8 with stochastic rounding |
| State root commitment | Every 4 rounds |

---

### 7.B Related work

- Douillard et al., *Decoupled DiLoCo: A New Frontier for Resilient Distributed AI Training*, DeepMind, 2025.
- Douillard et al., *DiLoCo: Distributed Low-Communication Training of Language Models*, 2023.
- Das et al., *TimesFM: A decoder-only foundation model for time-series forecasting*, Google, 2024.
- Ansari et al., *Chronos: Learning the Language of Time Series*, Amazon, 2024.
- Woo et al., *Moirai: A Time Series Foundation Model for Universal Forecasting*, Salesforce, 2024.
- Blanchard et al., *Krum: Machine Learning with Adversaries*, NeurIPS 2017.
- Yin et al., *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates*, ICML 2018.
- Costan & Devadas, *Intel SGX Explained*, IACR ePrint 2016/086.
- AMD, *SEV-SNP: Strengthening VM Isolation with Integrity Protection and More*, 2020.

