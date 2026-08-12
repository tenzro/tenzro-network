# tenzro-model

AI model registry, inference routing, and provider management for Tenzro Network.

## Overview

The `tenzro-model` crate provides the core infrastructure for managing AI models and inference providers on Tenzro Network. It enables a decentralized marketplace for AI inference services with intelligent routing, dynamic pricing, provider management, and durable catalog persistence.

## Features

### Model Registry

- Central catalog of all AI models available on the network with durable RocksDB persistence
- Model registration with metadata, pricing, and verification
- Search and filter models by modality, category, price, capabilities
- Model status tracking and lifecycle management
- SHA-256 checksum verification for downloaded models
- Write-through persistence to CF_MODELS under `info:<model_id>` prefix; full hydration on node restart

### Provider Management

- Register and manage inference providers
- Track provider performance metrics (latency, success rate, uptime)
- Health monitoring with heartbeat mechanism and circuit breaker integration
- Provider ranking and scoring
- TEE provider tracking
- Authenticated gossip announcements: model and provider registrations are Ed25519-signed and verified on ingest; a model announcement advertises `weights_sha256` (a streaming SHA-256 of the served on-disk weights) inside the signed payload so consumers can detect weight substitution

### Inference Routing

- Multiple routing strategies:
  - Lowest price
  - Lowest latency
  - Highest reputation
  - Weighted score (balanced approach)
  - Random
- Circuit breaker pattern for fault tolerance
- Automatic failover on provider failure
- TEE requirement support
- Preferred provider lists

### Pricing Engine

- Calculate inference costs based on:
  - Per-token pricing (input/output tokens)
  - Per-request pricing
  - Per-compute-time pricing
  - Dynamic market-based pricing
- Cost estimation before execution
- Market price tracking and analysis
- Price range queries across providers

### Model Library

- Curated model discovery and browsing
- Organize models by category:
  - Text Generation
  - Vision
  - Audio
  - Embedding
  - Multimodal
  - Code
  - And more...
- Featured and trending models
- Model ratings and download tracking
- Compatibility checking (VRAM, RAM requirements)

### Download Manager

- Content-addressed, peer-first model distribution: weights are identified by their BLAKE3 hash and a `tenzro://blob/<hash>` URI
- `HfArtifactDownloader` fetches peer-first through a pluggable `BlobFetcher` (the node wires `IrohBlobFetcher` over the iroh blob transport), falling back to HuggingFace Hub when no peer holds the artifact; downloaded weights are opportunistically re-published into the local blob store so the next node can fetch from this one
- `BlobFetcher` has two publish paths: `publish(Bytes)` for callers holding bytes, and `publish_file(&Path)` for artifacts already on disk. Model weights are multi-gigabyte, so the download side always takes `publish_file`, which the iroh adapter services by referencing the file in place rather than copying it or reading it into memory
- Progress tracking with speed estimation
- Pause, resume, and cancel downloads
- Verify-before-load: every artifact is checked against its recorded BLAKE3 hash before it loads — a mismatch fails the load
- Concurrent download management
- Storage path management
- `HfArtifactDownloader` supports both `ArtifactSpec::SingleFile { filename, extension }` (single-file ONNX) and `ArtifactSpec::Bundle { files, dir_name }` (multi-file ONNX encoder/decoder/joiner). Tmp-dir-rename atomic finalization. `HfDownloader` is the GGUF-oriented downloader with size-tolerant `verify_download`, used by LLM callers (CLI, RPC).

### Content-Addressed Model Registry

`ModelHashRegistry` binds every model artifact to its BLAKE3 hash. `ModelInfo` carries `blake3_hash: Option<[u8; 32]>`, `tenzro_uri: Option<String>` (the `tenzro://blob/<hash>` locator), and `peer_hints: Vec<PeerHintRecord>` (nodes known to hold the artifact). The registry is **first-recorder-wins**: the first node to record a model's hash pins it network-wide, and every subsequent download verifies against that pin. Records write through to `CF_MODEL_HASHES` and hydrate on startup (`ModelHashRegistry::with_storage`). `compute_model_manifest_hash()` folds a multi-file bundle into one manifest hash; `blake3_of_bytes()` / `ModelFileRecord::from_bytes()` are the single-file primitives. Surfaced through `tenzro_getModelHash` / `tenzro_listModelHashes` / `tenzro_recordModelHash` / `tenzro_overrideModelHash`.

### Multi-Modal Inference Runtimes

Feature-gated ONNX runtimes covering 7 modalities. Each runtime caches sessions, dispatches via `spawn_blocking`, and uses `parking_lot::Mutex<Session>` to satisfy ORT's non-concurrent contract.

- **`TimeseriesRuntime`** — `ForecastModel` trait + `GenericForecast` ORT implementation. Supports `[1, context_len] -> [1, horizon]` and quantile output `[1, horizon, n_quantiles]`. Powers TimesFM 2.5 200M.
- **`VisionRuntime`** — `ImageEncoder` trait + `GenericImageEncoder`. PNG/JPEG/WebP decode via the `image` crate, Lanczos3 resize, configurable normalization (CLIP / ImageNet / SigLIP), accepts `[1, D]` and `[1, 1, D]` outputs. Optional L2-normalize. `cosine_similarity` helper for image-text similarity. Catalog: CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2.
- **`TextEmbeddingRuntime`** — text-only encoder. Tokenizer loaded from HF `tokenizer.json` via the `tokenizers` crate. Optional dim truncation + re-normalization for Matryoshka models. fp32 / q8 / q4 activation paths. Catalog: Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka 768/512/256/128, BGE-M3, Snowflake Arctic Embed L v2.0.
- **`SegmentationRuntime`** — two-pass encoder/decoder runtime. `SamFamily::{Sam1, Sam2}` dispatches the two ABIs: SAM 1 (6-input decoder + `orig_im_size` + longest-side pad to 1024 + raw 0–255 SAM mean/std) and SAM 2 (7-input decoder + `high_res_feats_0/1` + bilinear resize + ImageNet norm). Encoder caches per-image embedding; decoder takes embedding + prompts (points/boxes) → masks. API: `segment(model_id, image_bytes, Vec<SegmentPrompt>)`. Catalog: SAM 2 base/large, EdgeSAM, MobileSAM. SAM 3 / 3.1 are text-promptable with a 14-input box-output decoder, incompatible with the point/box `Segmenter` trait, exposed through the separate `TextSegmentationRuntime`.
- **`DetectionRuntime`** — `DetrFamily::{RfDetr, DFine}` dispatches two NMS-free DETR-family ABIs: RF-DETR (single input, ImageNet norm, raw `labels` logits + cxcywh-normalized `dets`, client does sigmoid + top-1 + cxcywh→xyxy + scale, **90-class** COCO) and D-FINE (2 inputs incl. `orig_target_sizes` int64, pixel scale-to-[0,1] only, post-sigmoid sorted outputs in xyxy pixels, **80-class**). API: `detect(model_id, image_bytes, score_threshold) -> Vec<Detection>` with `{bbox, label_id, score}`. Catalog: RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x.
- **`AudioRuntime`** — ASR. Two ORT-backed `Transcriber` implementations cover the catalog: `MoonshineTranscriber` (raw 16 kHz waveform input, encoder + merged-decoder autoregressive loop with `use_cache_branch` KV-cache, SentencePiece detokenization) and `WhisperTranscriber` (80- or 128-mel log-spectrogram input via Slaney filterbank + Hanning STFT, encoder + merged-decoder autoregressive loop with `use_cache_branch` KV-cache, BPE detokenization, language/SOT/transcribe/no-timestamps prompt prefix). `WhisperFamily::{DistilEn, DistilLargeV3, LargeV3Turbo}` selects mel count and multilingual prompt behavior. Two further implementations cover the NeMo families: `ParakeetTranscriber` (Token-and-Duration Transducer — encoder, prediction network, and joint network run as three sessions with RNN-T joint decoding) and `CanaryTranscriber` (Conformer attention-encoder-decoder, four languages). Audio decode: `hound` for WAV, `symphonia` for MP3/FLAC/OGG; `rubato` sinc resampler to 16 kHz mono. Catalog: Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash.
- **`VideoRuntime`** — frame extraction (shell-out to `ffmpeg`) + per-frame embedding via vision encoder fallback (DINOv3/SigLIP2 mean-pooled across frames), evenly spaced across the clip or at a fixed stride when the request carries `frame_stride`. The video catalog advertises the V-JEPA 2 family (ViT-L and ViT-H under MIT, ViT-g under Apache-2.0, all `Permissive`) as reference clip encoders; the upstream repos publish safetensors only, so `load_video_model` registers the `VisionFallbackVideoEncoder` rather than an ONNX graph. VideoMAE v1/v2 and V-JEPA 2.1 stay off the catalog on license grounds.

### Distributed MoE Execution

Mixture-of-Experts models run distributed across holders with three cooperating modules:

- **`moe_shard`** — `MoeShardView` maps `ExpertId` → `ExpertHolder` assignments under a `ReplicationPolicy` (per-expert replica counts, VRAM-aware placement).
- **`moe_router`** — `plan_dispatch(routing, shard_view)` turns per-token top-k gating decisions (`TokenRouting` of `TokenSlot`s) into a `DispatchPlan` of per-holder `ExpertBatch`es, grouping tokens by destination so each holder receives one sub-batch per expert it hosts.
- **`moe_exec`** — `MoeExpertRuntime` hosts the actual weights: `ExpertFfn` (gate/up/down projections, SwiGLU) and `GatingNetwork` (router linear + softmax top-k), both loaded from safetensors — a local file path or a `tenzro://blob/<hash>` URI fetched over iroh-blobs. A forward pass gates locally, fans `ExpertExecuteRequest` sub-batches out to remote holders, executes local experts in-process, and `combine_expert_outputs` merges the gate-weighted expert outputs back into token order.

**Expert compute backends.** The `Y = X·Wᵀ` projection math sits behind an `ExpertCompute` trait so the same forward path runs on whatever hardware a holder has. `CpuCompute` is always present — an `ndarray` f32 dense path plus, when the CPU reports the target features at runtime (`is_x86_feature_detected!`), an AVX-512-VNNI Q8_0 dot path. GPU backends compile only under cargo features and never enter a default build: `moe-cuda` (cudarc cuBLAS grouped-GEMM on NVIDIA) and `moe-wgpu` (a cross-vendor WGSL kernel over wgpu); `moe-gpu` is the umbrella that turns on both device probes. A holder advertises `moe_gpu` in its capacity so the router can bias expert placement toward GPU holders.

**Expert quantization.** Projections can be stored block-quantized to cut the safetensors footprint and the bytes moved between holders: `Q8_0` (32-weight blocks, ~1 byte/weight), `Q4_K` (256-weight super-blocks, ~4.5 bpw), and `Q6_K` (256-weight super-blocks, ~6.6 bpw). The GGUF-compatible codecs live in `moe_quant`. `ExpertQuantPlan::q4_k_m()` is the balanced default — gate/up projections in Q4_K, the down projection in Q6_K — and quantized rows are dequantized one at a time on the compute path. The `quant` parameter on `tenzro_moePrepareExperts` selects the plan at prepare time.

**Residency tiers.** A holder can advertise more experts than fit in memory. The runtime keeps a byte-bounded memory-tier LRU (`ResidencyConfig::memory_budget_bytes`, auto-sized to 60% of Linux `MemAvailable`, else a 4 GiB fallback, tunable via `with_memory_budget` / `with_disk_dir`) over a disk tier at `{data_dir}/moe_experts/` that spills raw safetensors (atomic temp-write + rename) and decodes them back on demand. Readahead promotes disk-tier experts a forward is about to select before the batch arrives. `tenzro_moeExpertStatus` reports each expert's tier (`Warm` in memory / `Cold` on disk) and byte footprint.

**Cross-holder overlap.** When the hidden dimension is a multiple of 32, the router may send Q8_0-compressed activation blocks instead of f32 rows (`ExpertExecuteRequest::compressed`, materialized carrier-agnostically via `materialize_hidden`). Backup redispatch (`ExpertBatch::backups`, warm-holder-first) covers a slow or missing holder, and `MoeCombiner` accumulates holder responses as they arrive off a `FuturesUnordered` stream — `MoeCombiner::finish` fails if any expected contribution never arrives, so a dropped holder surfaces as an error rather than a silently-wrong sum.

The node layer exposes planning RPCs (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`) and execution RPCs (`tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moePrepareExperts`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`); cross-holder transport is the `tenzro/moe` iroh ALPN with HTTP fallback. Catalog entries carry a `MoeShape` describing expert count, top-k, and per-expert dimensions.

### ONNX Execution Providers

All ONNX runtimes build sessions through one shared `onnx_session::build_onnx_session()`, which registers hardware execution providers before falling back to CPU. The `onnx-tensorrt` / `onnx-cuda` / `onnx-coreml` cargo features compile in the corresponding providers; default priority is TensorRT → CUDA → CoreML → CPU. The `TENZRO_ONNX_EP` environment variable overrides the priority as a comma-separated list (`tensorrt`, `cuda`, `coreml`, `cpu` — `cpu` terminates the list). A provider that fails to register logs a warning and falls through to the next rather than erroring.

### Modality-Aware Inference Routing

`InferenceRouter::route()` reads `model.modality` from the registry and dispatches a typed `InferencePayload` enum (`Chat | Forecast | VisionEmbed | VisionSimilarity | TextEmbed | Segment | Detect | Transcribe | VideoEmbed`) to the correct runtime handle. Pricing/latency/reputation strategies apply per-modality with independent provider pools.

### Intent Routing and Per-Query Difficulty

Model selection and provider selection are two tiers. `MetaRouter` (`meta_router`) takes a `RouteIntent` — a use case, a per-request cost cap, and a quality floor — and resolves it to a concrete `model_id`; `InferenceRouter` then picks the operator deployment for that model. The meta-router owns use-case→modality mapping, candidate discovery over `ModelRegistry`, quality-tier resolution, budget pre-filtering, usage-stat scoring, and the cross-model fallback order. Three independent ceilings apply: the per-request `Budget` enforced at discovery, a per-DID rolling-window cap through a `BudgetGate`, and a hard wallet-balance ceiling read through a `BalanceProvider` so no model priced above what the payer can settle is ever selected.

Declared metadata says nothing about whether a *specific* prompt needs the expensive model, so `difficulty` supplies the measured signal. Prompts are embedded through a `PromptEmbedder` (backed by `TextEmbeddingRuntime`) and grouped by an online sequential k-means map that grows on demand — no training corpus and no offline fit step. Each model accrues per-cluster outcome counters from real serving results, so a model's strength is a measured property per prompt neighbourhood. A newly registered model starts at the neutral prior with an optimism bonus so it stays explorable, and earns its per-cluster error rates from observations. Both the cluster map and the per-model counters write through to `CF_MODELS` and hydrate on startup.

### Latency-Tail Estimation

Hedging and steering read the tail of a provider's latency distribution, not its mean — racing a backup request at the mean fires far too many hedges. `LatencyTail` tracks a chosen quantile with a streaming five-marker estimator: O(1) memory and O(1) per observation, no stored history and no windowing, converging to the true quantile of the running stream. Every field serializes, so the estimate survives a restart alongside the rest of `ProviderMetrics`.

### Inference Commitments (TOPLOC)

During generation the provider records, per output token, the top-k raw logits (token id and value) that produced the sample. The canonical serialization of those records is the commitment blob, domain-tagged `tenzro/inference/toploc`; its SHA-256 rides on inference results and receipts. A verifier holding the prompt, the output tokens, and the same weights re-executes the sequence as one prefill — far cheaper than the original decode — reads the logits at each output position, and fuzzy-compares them against the committed records. Exact float equality is not required: kernels differ across accelerators, drivers, and batch shapes, so verification tolerates bounded index churn (`MIN_INDEX_OVERLAP`) and bounded logit drift (`MAX_MEAN_LOGIT_DELTA`) per step, and requires `MIN_PASSING_STEP_FRACTION` of steps to pass overall. `DEFAULT_COMMITMENT_K` is 16, capped at `MAX_COMMITMENT_K`.

### SLA Probes

`SlaManager::issue_probe` gives validators a liveness challenge for staked providers that cannot be selectively targeted. The validator generates a VRF proof over `epoch || round || provider_did` with its own Ed25519-compatible VRF key and folds the 64-byte output into a per-provider challenge nonce, so anyone holding the validator's VRF public key can confirm the nonce matches the tuple — no grinding, and no forging a challenge after the response was sampled. Providers reply with an Ed25519 signature over the canonical payload. Misses, signature failures, and past-deadline responses increment the bond's failure count through `ProviderSlashingCallback::record_probe_miss`; crossing the threshold calls `slash_provider_bond`. The crate owns the protocol types, the VRF derivation, and the fault detector; transport is wired at the node layer.

### Provenance and Jurisdiction Receipts

`provenance` signs a statement binding an inference result to the model, weights hash, and serving key. `jurisdiction` mirrors it for locality: a request may pin `parameters.custom["jurisdiction"]` to ISO 3166-1 alpha-2 country codes and bloc tokens, the router hard-filters to providers whose declared `JurisdictionClaim` satisfies the pin, and the serving node returns a signed `JurisdictionReceipt` binding the claim to the exact request and response byte hashes. A receipt is an attestation-bound claim, not a geolocation proof: the signature proves which key and — through `attestation_hash` — which enclave made the claim, and reputation and slashing punish false declarations. Both modules expose a pluggable signer trait, an in-process Ed25519 implementation, and offline verification helpers.

### LAN Clustering — Layer-Wise Pipeline Parallelism

When no single member fits a model, the `cluster` module places it across machines on the same LAN as a layer-wise pipeline. The model is described by a `ModelShape { layers, hidden_dim, total_vram_gb }`; candidate members are a `ClusterMember` array carrying per-member VRAM, backend, and `MemberReachability`.

- `single_box_fit(model, members)` returns the lone member that fits the whole model, if any.
- `should_cluster(model, members, user_forced)` returns a `FitDecision` — `RunLocal`, `ClusterRequired`, or `ClusterForced` — with `forms_cluster()` telling the caller whether to assemble a pipeline.
- `assign_layers(total_layers, members)` partitions the layers into contiguous per-member stages by **VRAM-weighted largest-remainder** apportionment, returning `HashMap<Address, PipelineStage { start_layer, end_layer }>`.
- `order_stages(head, members, probes, activation_bytes)` orders the stages greedily by nearest-neighbour link cost and emits a `NetworkGate { ordered, excluded }`; the reachability gate drops any member without a `data_plane_eligible` link.

Only the boundary activation crosses the wire between adjacent stages — `hidden_dim × ACTIVATION_DTYPE_BYTES` per token, fp16 (`ModelShape::activation_bytes_per_token`). Members must share one runtime build commit (`LLAMA_CPP_COMMIT`); mixed backends across members are supported. The planner is a pure function of its inputs and reads no node state — the whole planning path is exposed via `tenzro_clusterPlan`.

The `ModelShape` does not have to be supplied by the caller: `gguf_shape::read_model_shape(path)` parses just the GGUF metadata header (no tensor load) to pull `<arch>.block_count` and `<arch>.embedding_length`, deriving `total_vram_gb` from the file size. This lets the serving path size a model and decide whether to cluster without first loading it — see `tenzro-node`'s serve runtime, which folds this shape, the local `NodeProfile`, and gossip-discovered members into the planner and, when a cluster forms, drives the per-stage ggml `rpc-server` pipeline over the authenticated cluster tunnel (NETWORK.md).

### Hardware Self-Profile

`detect_node_profile()` builds this node's `NodeProfile` from the linked runtime's device API: build commit, CPU architecture, OS, the detected compute devices (enumerated through the runtime's ggml backend-device list), and the derived serving capacity (GB), backend, and capability key. The profile feeds both single-box fit and cluster planning and is published over `tenzro_nodeProfile`.

### Provider Reputation (+1 / −5 asymmetric)

`ProviderManager::record_success(addr, latency)` and `record_failure(addr)`
mutate `InferenceProvider.reputation` in-place with **+1 on success / −5 on
failure** (saturating, ceiling **1000**, floor **0**) and write through to
RocksDB via `persist_provider`. Flaky providers drift down quickly and the
score is durable across node restarts.

The score is read by:
- `calculate_score()` — used by the `WeightedScore` and `Reputation` routing strategies
- `tenzro_getProviderReputation { provider }` RPC
- `tenzro reputation get --provider <addr>` CLI

### Usage Tracking

`InferenceRouter::with_usage_tracker(Arc<UsageTracker>)` attaches a usage tracker; on every successful inference the router calls `tracker.record_usage(UsageRecord::new(model_id, provider, input_tokens, output_tokens, bytes_in, bytes_out, cost, latency_ms))`. `bytes_in` / `bytes_out` are measured at the HTTP boundary (request body length sent to the provider; response body length received from the provider) and aggregated alongside token counts on `ModelUsageStats`, `ProviderUsageStats`, and `GlobalUsageStats` (`total_bytes_in` / `total_bytes_out` / `total_bytes()`). The tracker maintains per-model, per-provider, and global aggregates plus a bounded ring of recent records, all persisted to CF_MODELS under the `usage:` prefix when constructed via `with_storage()`. Surfaced through `tenzro_listInferenceUsage`.

The router keys each record on the `request_id` of the inference it served, via `UsageRecord::with_record_id`, so a caller holding only the id it was handed can read the record back with `UsageTracker::get_record(&id)`. That read checks the in-memory ring newest-first, then falls back to storage: the ring is bounded and is not rehydrated on restart, whereas the per-record row survives one. Inference records are DA-offloaded, so the storage path resolves the envelope's pointer through the configured `DaBackend` and verifies the payload commitment before decoding. `get_record` returns `None` for an unknown id rather than a zeroed record. Surfaced through `tenzro_getGeneration` and `GET /v1/generation`.

### Streaming Inference with Per-Token Billing

`InferenceRouter` supports streamed token emission via `tenzro_chatStream`.
When the caller supplies an optional `channel_id`, each emitted token
attaches a signed micropayment-channel state-update so the provider gets
billed per token rather than per request. CLI:

```bash
tenzro inference stream <model_id> "<message>" --channel <channel_id>
```

The channel must be opened beforehand with the provider as payee
(see `tenzro-settlement` README → "Micropayment Channels"). If the
channel is omitted, the stream still works — billing falls back to a
single end-of-stream settlement charge.

### License-Tier Gating

`ModelRegistry::register_model()` enforces a 4-level license tier centrally:

- **Permissive** (Apache 2.0, MIT, BSD) — load freely
- **Attribution** (CC-BY-4.0) — load + log attribution
- **CommercialCustom** (DINOv3, SAM, Gemma terms) — require explicit `--accept-license <id>` per family
- **NonCommercial** (e.g. CC-BY-NC-4.0) — refuse without `--accept-non-commercial`

### Model Runtime

- Local model inference via `llama.cpp` bindings (`llama-cpp-2` crate)
- GPU / accelerator backends (one per build, via cargo feature — see "GPU Acceleration" below): CUDA, ROCm, Metal, Vulkan, SYCL, OpenCL, WebGPU, MUSA, CANN, OpenVINO, zDNN, BLAS
- Chat interface with session history
- Streaming and batch inference
- Hardware detection and capability reporting
- **Multi-Token Prediction (MTP) speculative decoding** — the runtime keeps a `loaded_drafters` map alongside `loaded_models`; when a drafter is loaded for a target and the request carries `draft_n`, generation runs real speculative decoding: the drafter proposes a block of candidate tokens, the target verifies them in one batched decode, and the accepted prefix advances the stream. Serving a model auto-loads its paired drafter from the catalog's `drafter_id` (downloaded in the background if absent); a drafter problem never fails the serve. `ModelError::MtpUnavailable` is returned only when `draft_n` is requested with no drafter loaded for that target.
- **In-process multimodal projector (`mtmd` feature)** — a model whose catalog entry names a multimodal projector loads it alongside the text weights into an `MtmdContext`. Image and audio attachments become `MtmdBitmap`s placed at the media marker inside the prompt, and the projector interleaves encoded media chunks with text tokens during prefill, so a vision-capable GGUF is served in-process without a separate encoder service. The projector owns its own prefill path rather than sharing the batch scheduler; built without the feature, multimodal requests are refused instead of silently dropping the attachment.

### Continuous Batching

`batching` holds one long-lived `llama_context` per model with a fixed pool of KV-cache sequence slots and interleaves every in-flight request into a single `llama_decode` per step, so throughput scales with the number of active sequences instead of serializing decodes behind one mutex. One dedicated OS thread per model owns the model and its context together. Each iteration admits waiting requests into free slots, prefills their prompts requesting logits only at the last position, extends each running sequence by its last sampled token, decodes the interleaved batch once, then samples per sequence from its own logits index with its own sampler so repetition state stays per-request. A sequence finishes on an end-of-generation token, one of its stop sequences, its position ceiling, or when a streaming caller drops the receiver. Stop sequences match over decoded text rather than token ids, so a multi-token delimiter still matches and is trimmed before the text is streamed.

### External Serving Engines

A provider fronting its accelerators with a dedicated serving engine registers it against a `model_id` through `external_engine` instead of loading a local GGUF. `ExternalEngineKind` records which engine sits behind the endpoint (`Vllm`, `Sglang`, `LlamaServer`, `OpenAiCompatible`); all of them speak the same OpenAI `/v1/chat/completions` wire contract, so `ModelRuntime` maps `ChatMessage` / `GenerationConfig` / `InferenceResult` onto that endpoint and routes chat and generate for that model over HTTP.

## Usage Examples

### Registering a Model

```rust
use tenzro_model::registry::ModelRegistry;
use tenzro_types::model::{ModelInfo, ModelModality};
use tenzro_types::primitives::Address;

let registry = ModelRegistry::new();

let model = ModelInfo::new(
    "gpt-4".to_string(),
    "GPT-4".to_string(),
    "1.0.0".to_string(),
    ModelModality::Text,
    Address::zero(),
)
.with_description("Advanced language model".to_string());

registry.register_model(model)?;
```

### Routing an Inference Request

```rust
use tenzro_model::routing::{InferenceRouter, RoutingConfig, RoutingStrategy};
use tenzro_model::provider::ProviderManager;
use tenzro_types::model::InferenceRequest;
use std::sync::Arc;

let provider_manager = Arc::new(ProviderManager::new());
let config = RoutingConfig::new()
    .with_strategy(RoutingStrategy::WeightedScore)
    .with_tee_required(true);

let router = InferenceRouter::with_config(provider_manager, config);

// Route request to best provider
let provider_address = router.route_request(&request)?;
```

### Calculating Pricing

```rust
use tenzro_model::pricing::PricingEngine;
use tenzro_types::model::{PricingConfig, InferenceMetadata};

let engine = PricingEngine::new();

// Calculate actual cost
let cost = engine.calculate_cost(&pricing_config, &metadata)?;

// Estimate cost before execution
let estimated = engine.estimate_cost(&pricing_config, 100, 50)?;
```

### Managing Downloads

```rust
use tenzro_model::download::DownloadManager;
use std::path::PathBuf;

let storage_path = PathBuf::from("/models");
let manager = DownloadManager::new(storage_path);

// Start download
manager.start_download(
    "gemma4-9b".to_string(),
    "https://example.com/gemma4-9b.bin".to_string(),
    7_000_000_000, // 7GB
    Some("abc123...".to_string()), // checksum
).await?;

// Check progress
if let Some(task) = manager.get_download_status("gemma4-9b") {
    println!("Progress: {:.1}%", task.progress * 100.0);
}

// Verify checksum
manager.verify_checksum("gemma4-9b").await?;
```

### Downloading a model

A model can be fetched from either source class: the centralized HuggingFace
Hub, or the set of verified network providers that hold the blob at its content
hash (BLAKE3, checked over the whole transfer, plus the canonical SHA-256).
`SourcePolicy` selects between them — `Auto` tries verified providers first and
falls back to HuggingFace, `Network` fetches only from verified providers and
never contacts HuggingFace, and `HuggingFace` streams only from the Hub.

```rust
use tenzro_model::{get_model_by_id, HfDownloader, DownloadProgress, DownloadState, SourcePolicy};
use std::path::PathBuf;

let downloader = HfDownloader::new(PathBuf::from("/models"));
let entry = get_model_by_id("qwen3.5-0.8b").expect("model in catalog");

let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(DownloadProgress {
    model_id: entry.id.clone(),
    status: DownloadState::Pending,
    progress_percent: 0.0,
    downloaded_bytes: 0,
    total_bytes: entry.size_bytes,
});

// Network-first with a HuggingFace fallback; pass SourcePolicy::Network to
// require a verified provider and never contact HuggingFace.
let path = downloader
    .download_model(&entry, None, SourcePolicy::Auto, progress_tx)
    .await?;
```

### Browsing the Model Library

```rust
use tenzro_model::library::{ModelLibrary, CategoryType};

let library = ModelLibrary::new();

// Get all text generation models
let text_models = library.get_models_by_category(CategoryType::TextGeneration);

// Get trending models
let trending = library.get_trending_models();

// Search models
let results = library.search("gpt");

// Check compatibility
let compatible = library.check_compatibility("large-model", 24, 64)?;
```

### Local Inference with GPU Acceleration

```rust
use tenzro_model::runtime::{ModelRuntime, GenerationConfig};

let runtime = ModelRuntime::new()?;

// Load model (GPU auto-selected)
runtime.load_model("path/to/model.gguf", None).await?;

// Generate text
let config = GenerationConfig::default()
    .with_max_tokens(100)
    .with_temperature(0.7);

let response = runtime.generate("Tell me a story", config).await?;
println!("{}", response.text);
```

## Architecture

The crate is organized into several key modules:

- `registry`: Model catalog and metadata management with durable persistence
- `provider`: Inference provider registration, metrics, and health monitoring
- `routing`: Request routing with multiple strategies and circuit breakers
- `meta_router`: Intent → `model_id` resolution with budget, quality floor, and balance ceilings
- `difficulty`: Per-query difficulty estimation over online prompt clusters
- `latency`: Streaming quantile estimator for provider latency tails
- `pricing`: Cost calculation and market analysis
- `library`: Model discovery and browsing
- `download`: Model download management
- `batching`: Continuous batching engine — one context per model, interleaved decode
- `external_engine`: OpenAI-compatible external serving-engine backend
- `toploc`: Top-k logit inference commitments and fuzzy re-execution verification
- `sla`: VRF-driven liveness probes and provider fault detection
- `provenance` / `jurisdiction`: Signed inference provenance and locality receipts
- `provisioning`: Hardware-aware model provisioning recommendations and peer discovery
- `gguf_shape`: GGUF metadata-header parse for layer count, hidden dim, and size
- `hf_download`: peer-first artifact downloader (`BlobFetcher` → iroh blobs, HuggingFace Hub fallback)
- `model_hash`: `ModelHashRegistry` — BLAKE3 content addressing, first-recorder-wins, verify-before-load, `CF_MODEL_HASHES` persistence
- `runtime`: Local inference via llama.cpp with GPU acceleration and MTP speculative decoding
- `moe_shard`: Expert → holder shard maps and replication policy
- `moe_router`: Token-to-expert dispatch planning
- `moe_exec`: Expert FFN + gating network execution from safetensors
- `moe_extract`: Per-expert and per-layer-router tensor slicing straight out of an upstream safetensors checkpoint over HTTP Range requests, re-serialized into the blob shape `moe_exec` accepts
- `moe_receipt`: Signed `ExpertExecutionReceipt` per remote expert execution, binding the input carrier hash to a top-k activation commitment over the output rows
- `moe_quant`: GGUF-compatible Q8_0 / Q4_K / Q6_K block codecs for expert projections
- `sealed`: Encrypted shard distribution for private models — AES-256-GCM content key wrapped per recipient with X25519 envelope encryption, signed `SealedModelManifest`
- `onnx_session`: Shared ONNX session builder with hardware execution providers
- `usage`: Usage tracking and statistics
- `load`: Load tracking and concurrency management
- `catalog`: Static catalogs for HuggingFace plus ONNX vision, forecast, text-embedding, segmentation, detection, audio, and video models, and the generative-media catalog
- `error`: Error types and handling

## Text-generation catalog

`HfModelEntry` + `get_model_catalog()` / `get_model_by_id()` describe the GGUF text-generation models a provider may serve — Qwen, Gemma, Mistral, Phi, DeepSeek, Granite, GLM, Kimi, muse-glimmer, and the rest of the open families. Each entry carries the HuggingFace repo and filename, quantization, size, minimum RAM, `ModelArchitecture`, license and `license_tier`, per-family sampling defaults (temperature, top-p, min-p), a `ReasoningPolicy`, an optional `mmproj` projector, and — for speculative decoding — `drafter_id` / `mtp_kind` / `mtp_default_draft_n`.

Reasoning is resolved universally by `ReasoningPolicy::for_family` and a total-params size gate: `resolve_enable_thinking()` maps `Auto` to thinking-ON only when the model's total parameter count is at least `thinking_safe_min_b`, so small hybrid models (e.g. `qwen3.5-0.8b`) serve thinking-off and answer directly while `qwen3.6` and channel-format reasoners like muse-glimmer keep reasoning. Vision-capable text-generation families carry an `mmproj` projector (Gemma 4, Kimi K3, muse-glimmer-30b, Qwen3-VL, Ornith, Inkling) and are served through the in-process `mtmd` path above.

MoE entries additionally carry a `MoeShape` (expert count, top-k, per-expert dimensions) and a safetensors repo resolved through `moe_safetensors_repo(id)`, so the same model is reachable two ways: whole-model serving from the GGUF, or distributed expert extraction from the safetensors. Kimi K3 is the extreme of that split — 2.8T total parameters with 104B active over 896 routed experts, 93 layers, 1M context, and a multimodal encoder. Its smallest quantization exceeds any single machine, so whole-model serving means a pipeline cluster and a lone host runs it as distributed expert extraction instead.

## ONNX catalogs

In addition to the dynamic model registry, `tenzro-model` provides static catalogs of verified ONNX-exported models per modality for direct runtime registration.

- **Vision** — `OnnxVisionEntry` + `get_vision_catalog()`: CLIP ViT-B/32 + ViT-L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16. Each entry carries `input_size`, `embedding_dim`, and a normalization key (CLIP / ImageNet / SigLIP).
- **Timeseries forecast** — `OnnxForecastEntry` + `get_forecast_catalog()`: TimesFM 2.5 200M.
- **Text embedding** — `OnnxTextEmbeddingEntry` + `get_text_embedding_catalog()`: Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, Snowflake Arctic Embed L v2.0.
- **Segmentation** — `OnnxSegmentationEntry` + `get_segmentation_catalog()`: SAM 2 base/large, EdgeSAM, MobileSAM.
- **Detection** — `OnnxDetectionEntry` + `get_detection_catalog()`: RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x.
- **Audio** — `OnnxAudioEntry` + `get_audio_catalog()`: Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT-v3, Canary-1B-Flash.
- **Video** — `OnnxVideoEntry` + `get_video_catalog()`: V-JEPA 2 ViT-L/256, ViT-H/256, ViT-g/384.

All entries carry `license_tier: Permissive | Attribution | CommercialCustom | NonCommercial`, enforced centrally in `ModelRegistry::register_model()`.

Catalogs feed feature-gated runtimes (`VisionRuntime`, `TimeseriesRuntime`, `TextEmbeddingRuntime`, `SegmentationRuntime`, `DetectionRuntime`, `AudioRuntime`, `VideoRuntime`) that wrap ORT sessions for direct inference.

## Generative-media catalog

`MediaGenModelEntry` + `get_media_gen_catalog()` / `get_media_gen_model_by_id()` describe the image and video pipelines a media worker may serve. These are not ONNX single files: each entry is a multi-folder HuggingFace repository (transformer + text encoder + VAE + scheduler) loaded whole by `diffusers`, so the entry names a `pipeline_class` rather than an `hf_filename`.

| Entry | Kinds | Split |
|---|---|---|
| `qwen-image` | text2image | — |
| `qwen-image-flash` | text2image | — |
| `qwen-image-edit` | image2image | — |
| `z-image-turbo` | text2image | — |
| `flux2-klein-4b` | text2image | — |
| `wan2.2-t2v-a14b` | text2video | yes |
| `wan2.2-i2v-a14b` | image2video | yes |
| `wan2.2-ti2v-5b` | text2video, image2video | — |

Membership requires that the repo is ungated, that `model_index.json` names a real diffusers pipeline class, and that the output is an image or a video. Entries whose `expert_pair` is set split denoising at a timestep boundary, so two workers holding one expert each can serve a job neither could serve alone; `min_vram_gb_per_expert` is what one half needs against `min_vram_gb` for the whole.

Media-gen weights are loaded by the Python worker in `integrations/media_gen/`, never by the node, so `license_tier` here is held at worker enrollment rather than at model load — a capability naming a model whose terms the node was not started with is refused. `custom_license_id()` maps an entry's license text to the id `--accept-license` takes.

## Durable Catalog Persistence

When initialized with `ModelRegistry::with_storage(storage)`, the registry persists all `ModelInfo` records (including optional `vision_parameters` / `audio_parameters` / `video_parameters` / `timeseries_parameters` sidecars) to CF_MODELS under the `info:<model_id>` prefix. This coexists with node-level served-model markers (written under raw keys by `tenzro-node`).

Write-through happens on:
- `register_model`
- `update_model`
- `deactivate_model`
- `remove_model`

On startup, hydration restores the full catalog so models survive node restarts without re-registration.

## GPU Acceleration

llama.cpp includes every ggml backend; each is exposed as a cargo feature that sets the matching `GGML_<X>` cmake define on the vendored `llama-cpp-sys-2` build. A build enables one backend; a build with no backend feature is CPU-only. These features are forwarded through `tenzro-node` (`--features tenzro-node/<name>`).

- **cuda** — NVIDIA CUDA (datacenter: A100/H100/B200; consumer: RTX 3090/4090)
- **cuda-no-vmm** — NVIDIA CUDA without virtual memory (older drivers/embedded)
- **rocm** — AMD ROCm (datacenter: MI300X; consumer: RX 7900 XTX)
- **metal** — Apple Metal (auto-linked on macOS ARM64 regardless)
- **vulkan** — Cross-platform GPU (NVIDIA, AMD, Intel Arc, ARM Mali/Adreno)
- **sycl** — Intel GPU via oneAPI DPC++ (build with `CC=icx CXX=icpx`)
- **opencl** — OpenCL GPU
- **webgpu** — WebGPU device
- **musa** — Moore Threads GPU (MUSA Toolkit)
- **cann** — Huawei Ascend NPU (CANN Toolkit)
- **openvino** — Intel CPU/GPU/NPU (device selected at runtime via `GGML_OPENVINO_DEVICE`)
- **zdnn** — IBM Z Telum accelerator
- **blas** — accelerated CPU (OpenBLAS/MKL)

`HardwareInfo::detect()` reports the compiled set (`compiled_backends`) and the resolved `active_backend` string at startup.

## Integration with Tenzro Network

This crate integrates with:

- `tenzro-types`: Core type definitions for models, providers, and requests
- `tenzro-network`: P2P networking for provider discovery
- `tenzro-settlement`: Payment settlement for inference services
- `tenzro-tee`: Trusted execution environment verification
- `tenzro-storage`: RocksDB persistence for catalog durability

## Performance Considerations

- Uses `DashMap` for lock-free concurrent access to registries
- Circuit breaker pattern prevents cascading failures
- Market data uses bounded history for memory efficiency
- Provider metrics updated asynchronously
- Download manager limits concurrent operations

## Testing

Unit tests cover registry, routing, pricing, downloads, multi-modal runtimes, MoE dispatch and execution, license-tier gating, usage tracking, and persistence.

```bash
cargo test -p tenzro-model
```

## License

Apache-2.0.
