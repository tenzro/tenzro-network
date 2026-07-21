# tenzro-model

AI model registry, inference routing, and provider management for Tenzro Network.

## Overview

The `tenzro-model` crate provides the core infrastructure for managing AI models and inference providers on Tenzro Network. It enables a decentralized marketplace for AI inference services with intelligent routing, dynamic pricing, comprehensive provider management, and durable catalog persistence.

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
- **`AudioRuntime`** — ASR. Two ORT-backed `Transcriber` implementations cover the catalog: `MoonshineTranscriber` (raw 16 kHz waveform input, encoder + merged-decoder autoregressive loop with `use_cache_branch` KV-cache, SentencePiece detokenization) and `WhisperTranscriber` (80- or 128-mel log-spectrogram input via Slaney filterbank + Hanning STFT, encoder + merged-decoder autoregressive loop with `use_cache_branch` KV-cache, BPE detokenization, language/SOT/transcribe/no-timestamps prompt prefix). `WhisperFamily::{DistilEn, DistilLargeV3, LargeV3Turbo}` selects mel count and multilingual prompt behavior. Audio decode: `hound` for WAV, `symphonia` for MP3/FLAC/OGG; `rubato` sinc resampler to 16 kHz mono. Catalog: Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo.
- **`VideoRuntime`** — frame extraction (shell-out to `ffmpeg`) + per-frame embedding via vision encoder fallback (DINOv3/SigLIP2 mean-pooled across frames). Native video catalog (`get_video_catalog()`) returns empty — no permissive ONNX-shippable encoder-only video model exists in the 2026 OSS landscape; runtime scaffolding ships ready for future entries.

### Distributed MoE Execution

Mixture-of-Experts models run distributed across holders with three cooperating modules:

- **`moe_shard`** — `MoeShardView` maps `ExpertId` → `ExpertHolder` assignments under a `ReplicationPolicy` (per-expert replica counts, VRAM-aware placement).
- **`moe_router`** — `plan_dispatch(routing, shard_view)` turns per-token top-k gating decisions (`TokenRouting` of `TokenSlot`s) into a `DispatchPlan` of per-holder `ExpertBatch`es, grouping tokens by destination so each holder receives one sub-batch per expert it hosts.
- **`moe_exec`** — `MoeExpertRuntime` hosts the actual weights: `ExpertFfn` (gate/up/down projections, SwiGLU) and `GatingNetwork` (router linear + softmax top-k), both loaded from safetensors — a local file path or a `tenzro://blob/<hash>` URI fetched over iroh-blobs. A forward pass gates locally, fans `ExpertExecuteRequest` sub-batches out to remote holders, executes local experts in-process, and `combine_expert_outputs` merges the gate-weighted expert outputs back into token order.

**Expert compute backends.** The `Y = X·Wᵀ` projection math sits behind an `ExpertCompute` trait so the same forward path runs on whatever hardware a holder has. `CpuCompute` is always present — an `ndarray` f32 dense path plus, when the CPU reports the target features at runtime (`is_x86_feature_detected!`), an AVX-512-VNNI Q8_0 dot path. GPU backends compile only under cargo features and never enter a default build: `moe-cuda` (cudarc cuBLAS grouped-GEMM on NVIDIA) and `moe-wgpu` (a cross-vendor WGSL kernel over wgpu); `moe-gpu` is the umbrella that turns on both device probes. A holder advertises `moe_gpu` in its capacity so the router can bias expert placement toward GPU holders.

**Expert quantization.** Projections can be stored block-quantized to cut the safetensors footprint and the bytes moved between holders: `Q8_0` (32-weight blocks, ~1 byte/weight), `Q4_K` (256-weight super-blocks, ~4.5 bpw), and `Q6_K` (256-weight super-blocks, ~6.6 bpw). The GGUF-compatible codecs live in `moe_quant`. `ExpertQuantPlan::q4_k_m()` is the balanced default — gate/up projections in Q4_K, the down projection in Q6_K — and quantized rows are dequantized one at a time on the compute path. The `quant` parameter on `tenzro_moePrepareExperts` selects the plan at prepare time.

**Residency tiers.** A holder can advertise more experts than fit in memory. The runtime keeps a byte-bounded memory-tier LRU (`ResidencyConfig::memory_budget_bytes`, auto-sized to 60% of Linux `MemAvailable`, else a 4 GiB fallback, tunable via `with_memory_budget` / `with_disk_dir`) over a disk tier at `{data_dir}/moe_experts/` that spills raw safetensors (atomic temp-write + rename) and decodes them back on demand. Readahead promotes disk-tier experts a forward is about to select before the batch arrives. `tenzro_moeExpertStatus` reports each expert's tier (`Warm` in memory / `Cold` on disk) and byte footprint.

**Cross-holder overlap.** When the hidden dimension is a multiple of 32, the router may send Q8_0-compressed activation blocks instead of f32 rows (`ExpertExecuteRequest::compressed`, materialized carrier-agnostically via `materialize_hidden`). Backup redispatch (`ExpertBatch::backups`, warm-holder-first) covers a slow or missing holder, and `MoeCombiner` accumulates holder responses as they arrive off a `FuturesUnordered` stream — `MoeCombiner::finish` fails if any expected contribution never lands, so a dropped holder surfaces as an error rather than a silently-wrong sum.

The node layer exposes planning RPCs (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`) and execution RPCs (`tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moePrepareExperts`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`); cross-holder transport is the `tenzro/moe` iroh ALPN with HTTP fallback. Catalog entries carry a `MoeShape` describing expert count, top-k, and per-expert dimensions.

### ONNX Execution Providers

All ONNX runtimes build sessions through one shared `onnx_session::build_onnx_session()`, which registers hardware execution providers before falling back to CPU. The `onnx-tensorrt` / `onnx-cuda` / `onnx-coreml` cargo features compile in the corresponding providers; default priority is TensorRT → CUDA → CoreML → CPU. The `TENZRO_ONNX_EP` environment variable overrides the priority as a comma-separated list (`tensorrt`, `cuda`, `coreml`, `cpu` — `cpu` terminates the list). A provider that fails to register logs a warning and falls through to the next rather than erroring.

### Modality-Aware Inference Routing

`InferenceRouter::route()` reads `model.modality` from the registry and dispatches a typed `InferencePayload` enum (`Chat | Forecast | VisionEmbed | VisionSimilarity | TextEmbed | Segment | Detect | Transcribe | VideoEmbed`) to the correct runtime handle. Pricing/latency/reputation strategies apply per-modality with independent provider pools.

### LAN Clustering — Layer-Wise Pipeline Parallelism

When no single member fits a model, the `cluster` module places it across machines on the same LAN as a layer-wise pipeline. The model is described by a `ModelShape { layers, hidden_dim, total_vram_gb }`; candidate members are a `ClusterMember` array carrying per-member VRAM, backend, and `MemberReachability`.

- `single_box_fit(model, members)` returns the lone member that fits the whole model, if any.
- `should_cluster(model, members, user_forced)` returns a `FitDecision` — `RunLocal`, `ClusterRequired`, or `ClusterForced` — with `forms_cluster()` telling the caller whether to assemble a pipeline.
- `assign_layers(total_layers, members)` partitions the layers into contiguous per-member stages by **VRAM-weighted largest-remainder** apportionment, returning `HashMap<Address, PipelineStage { start_layer, end_layer }>`.
- `order_stages(head, members, probes, activation_bytes)` orders the stages greedily by nearest-neighbour link cost and emits a `NetworkGate { ordered, excluded }`; the reachability gate drops any member without a `data_plane_eligible` link.

Only the boundary activation crosses the wire between adjacent stages — `hidden_dim × ACTIVATION_DTYPE_BYTES` per token, fp16 (`ModelShape::activation_bytes_per_token`). Members must share one runtime build commit (`LLAMA_CPP_COMMIT`); mixed backends across members are supported. The planner is a pure function of its inputs and reads no node state — exposed end-to-end via `tenzro_clusterPlan`.

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

### Downloading from HuggingFace

```rust
use tenzro_model::hf_download::{HfDownloader, DownloadProgress};
use std::path::PathBuf;

let downloader = HfDownloader::new(PathBuf::from("/models"));

// Download a model from the Tenzro catalog
let handle = downloader.download_model(
    "unsloth/Qwen3.5-0.8B-GGUF",
    Some("Qwen3.5-0.8B-Q4_K_M.gguf".to_string()),
).await?;

// Monitor progress
loop {
    let progress = downloader.get_progress(&handle).await?;
    match progress.state {
        DownloadState::Downloading { bytes_downloaded, total_bytes } => {
            println!("Downloaded {} / {} bytes", bytes_downloaded, total_bytes.unwrap_or(0));
        },
        DownloadState::Completed => break,
        DownloadState::Failed(e) => return Err(e.into()),
        _ => {}
    }
}
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
- `pricing`: Cost calculation and market analysis
- `library`: Model discovery and browsing
- `download`: Model download management
- `hf_download`: peer-first artifact downloader (`BlobFetcher` → iroh blobs, HuggingFace Hub fallback)
- `model_hash`: `ModelHashRegistry` — BLAKE3 content addressing, first-recorder-wins, verify-before-load, `CF_MODEL_HASHES` persistence
- `runtime`: Local inference via llama.cpp with GPU acceleration and MTP speculative decoding
- `moe_shard`: Expert → holder shard maps and replication policy
- `moe_router`: Token-to-expert dispatch planning
- `moe_exec`: Expert FFN + gating network execution from safetensors
- `onnx_session`: Shared ONNX session builder with hardware execution providers
- `usage`: Usage tracking and statistics
- `load`: Load tracking and concurrency management
- `catalog`: Static catalogs for HuggingFace plus ONNX vision, forecast, text-embedding, segmentation, detection, audio, and video models
- `error`: Error types and handling

## ONNX catalogs

In addition to the dynamic model registry, `tenzro-model` ships static catalogs of verified ONNX-exported models per modality for direct runtime registration.

- **Vision** — `OnnxVisionEntry` + `get_vision_catalog()`: CLIP ViT-B/32 + ViT-L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16. Each entry carries `input_size`, `embedding_dim`, and a normalization key (CLIP / ImageNet / SigLIP).
- **Timeseries forecast** — `OnnxForecastEntry` + `get_forecast_catalog()`: TimesFM 2.5 200M.
- **Text embedding** — `OnnxTextEmbeddingEntry` + `get_text_embedding_catalog()`: Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, Snowflake Arctic Embed L v2.0.
- **Segmentation** — `OnnxSegmentationEntry` + `get_segmentation_catalog()`: SAM 2 base/large, EdgeSAM, MobileSAM.
- **Detection** — `OnnxDetectionEntry` + `get_detection_catalog()`: RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x.
- **Audio** — `OnnxAudioEntry` + `get_audio_catalog()`: Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT-v3, Canary-1B-Flash.
- **Video** — `OnnxVideoEntry` + `get_video_catalog()`: empty scaffold (awaiting permissive ONNX-shippable encoder).

All entries carry `license_tier: Permissive | Attribution | CommercialCustom | NonCommercial`, enforced centrally in `ModelRegistry::register_model()`.

Catalogs feed feature-gated runtimes (`VisionRuntime`, `TimeseriesRuntime`, `TextEmbeddingRuntime`, `SegmentationRuntime`, `DetectionRuntime`, `AudioRuntime`, `VideoRuntime`) that wrap ORT sessions for direct inference.

## Durable Catalog Persistence

When initialized with `ModelRegistry::with_storage(storage)`, the registry persists all `ModelInfo` records (including optional `vision_parameters` / `audio_parameters` / `video_parameters` / `timeseries_parameters` sidecars) to CF_MODELS under the `info:<model_id>` prefix. This coexists with node-level served-model markers (written under raw keys by `tenzro-node`).

Write-through happens on:
- `register_model`
- `update_model`
- `deactivate_model`
- `remove_model`

On startup, hydration restores the full catalog so models survive node restarts without re-registration.

## GPU Acceleration

llama.cpp ships every ggml backend; each is exposed as a cargo feature that sets the matching `GGML_<X>` cmake define on the vendored `llama-cpp-sys-2` build. A build enables one backend; a build with no backend feature is CPU-only. These features are forwarded through `tenzro-node` (`--features tenzro-node/<name>`).

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

MIT or Apache-2.0
