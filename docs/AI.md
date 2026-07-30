# Tenzro AI

**Decentralized, verifiable AI inference and training on Tenzro Network**

---

## Abstract

Tenzro AI is the protocol surface that makes intelligence a network resource — discovered, compensated, attested, and settled in TNZO. It is the open infrastructure for self-owned AI: any open model, any size, on hardware you and your peers own. The same network providers serve dense single-replica inference, sharded Mixture-of-Experts serving for frontier-scale models, speculative decoding via Multi-Token Prediction, multi-modal inference across seven ONNX runtimes plus the llama.cpp language path, TEE-confidential inference, recurrent-depth reasoning (Cortex), diffusion image and video generation including split-expert rendering across two accelerators, and decoupled-outer-aggregation decentralized training.

None of these are silos. Compute providers serving an MoE expert shard are the same providers that serve a dense Qwen 3.5 27B chat completion. The TDIP identity that pays a per-token bill on inference is the same identity that sponsors a training run. The reputation a provider earns serving inference is the reputation that admits them to a training witness committee. The protocol layer underwrites all of it with one consensus, one settlement asset, and one identity model.

This document describes the inference surface, the MoE serving primitives, MTP wiring, multi-modal coverage, the confidential-execution path, Cortex, Tenzro Train, and Tenzro Media Gen.

### Verified on the live network

The following paths have been exercised from request through settlement against live network nodes, using the network's own registry and node machinery — no external orchestration:

- **Decentralized MoE serving.** Registry-native expert extraction turns a catalog MoE entry into per-expert and gate blobs addressed by `tenzro://blob/` URI. Independent nodes each load a subset of those experts into their own memory, so the full model is assembled across distributed memory that no single node holds. A router node runs the gating step and dispatches per-token expert batches to the holders — local when the expert is resident, over the holder's iroh QUIC endpoint otherwise — and combines the returned hidden states into a single forward pass. Cross-node expert loads, the distributed forward pass, and finite outputs were all confirmed.
- **Decentralized MoE-aware training.** The reference trainer auto-detects the MoE backbone (expert and router parameter groups, auxiliary load-balancing loss) and attaches an alternating low-rank (LoRA) adapter under the `LoraAlternating` aggregation rule, which freezes one adapter factor per round. Independent trainers run their inner loops, sign gradient fragments, and submit them to the syncer; the syncer reaches cross-node quorum, aggregates per coordinate, produces the aggregated state root, records it on-chain via the round-finalize path, and advances the run to the next round. A genuine multi-trainer quorum finalize was confirmed.
- **Confidential-tier attestation on confidential-compute hardware.** The TEE attestation path was exercised on both an Intel TDX node and an AMD SEV-SNP node, reading evidence from the `/dev/tdx-guest` and `/dev/sev-guest` devices rather than a simulated device. This is the trust primitive the Verified and Confidential training tiers and confidential inference bind to.
- **Supporting surface.** The provider registry, `tenzro://blob/` addressing, cross-node blob fetch over iroh, gradient-fragment submission, and on-chain round finalization were all verified in the same runs.

---

## 1. Decentralized AI infrastructure — design

The protocol layer treats AI compute as a coordinated resource. Three properties matter:

1. **Provider unity.** A single provider registration covers every modality and every role. A provider declares its capacities through one `ProviderCapacity` record (`max_concurrent_requests`, `requests_per_second`, `max_batch_size`, `mtp_enabled`, `drafter_vram_gb`, `moe_holdings`, `moe_roles`, `iroh_endpoint_id`). The inference router consults the same record regardless of whether the request is dense chat, an MoE expert batch, a forecast call, or an embedding lookup. The same `serves_ai()` role that lets a node serve a model also lets it rent out spare compute by the epoch — backed by the same stake. See [`docs/COMPUTE.md`](COMPUTE.md).
2. **One settlement substrate.** Inference settles per call, per token, or through a micropayment channel — every path uses the same TDIP-bound `IdentityPaymentBinder`, the same delegation scope checks, and the same network commission.
3. **Verifiability is co-designed with execution.** Plonky3 STARK proofs over the KoalaBear field cover inference output commitments; TEE attestation chains cover confidential inference; both anchor through on-chain commitment registries.

The crates that implement this:

- `tenzro-model` — catalog, registry, inference router, provider manager, MoE shard view, MoE dispatch planner, ONNX runtimes (forecast / vision / text-embed / segmentation / detection / audio / video)
- `tenzro-cortex` — recurrent-depth reasoning sidecar
- `tenzro-training` — decoupled outer-aggregation protocol layer (syncer, aggregators, receipts, on-chain commitments)
- `integrations/trainer/` — Python reference trainer (PyTorch FSDP2, Hivemind, safetensors)
- `tenzro-media-gen` — generative media protocol layer (job queue, worker registry, pricing, payment split, commitments, output store)
- `integrations/media_gen/` — Python reference media worker (HuggingFace `diffusers`)

---

## 2. Inference

### 2.1 Provider model

A node runs as a model provider with `--roles ai`, registers each model it can serve through `tenzro_serveModel` (or `tenzro model serve` on the CLI), and the registration writes through to `CF_MODEL_SERVICES`. The provider's TDIP identity is bound at registration; payments route to its MPC wallet.

Registration and provider announcements are authenticated over gossip. Each announcement on `tenzro/models` and `tenzro/providers` is Ed25519-signed by the node's key over a canonical preimage of its routable fields and carries the signing public key; consumers verify on ingest and drop anything unsigned or tampered. A model announcement also advertises `weights_sha256` — a streaming SHA-256 of the served on-disk weights — inside the signed payload, so a consumer can detect weight substitution before routing inference to that provider.

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

### 2.3 Tail-latency hedging and failover

Once the strategy picks a primary provider, the router guards against the slow tail by hedging. It selects the next-best provider as a hedge target and starts the primary request immediately; if the primary has not answered by a short delay, the router dispatches the same request to the hedge target and returns whichever answers first, dropping the loser. Inference through the router is stateless, so a hedge is a safe duplicate — only the winning response bills the consumer and credits provider reputation.

- **Hedge delay.** Derived from the primary's observed **p95 tail latency**, clamped to `[hedge_delay_floor_ms, hedge_delay_ceiling_ms]` (defaults 40 ms / 500 ms). Each provider keeps a streaming `LatencyTail` estimator (the P² algorithm of Jain & Chlamtac — constant memory, no stored samples) so the p95 tracks live without a sliding window. A provider with no latency history hedges at the midpoint of that band. Racing at the primary's own p95 means a healthy primary has replied 19 times out of 20 by the delay, so a still-pending request is a genuine tail case — the pattern from Dean & Barroso's "The Tail at Scale", which keys hedging on the tail rather than the mean.
- **Hedge cap.** At most one hedge per request; hedges never nest.
- **Circuit-breaker respect.** A provider whose breaker is Open (quarantined after repeated failures) is never chosen as a hedge target.
- **Opt-out.** A caller that needs strict single-dispatch semantics sets `params.custom["no_hedge"] = "1"`.
- **Failover.** When both the primary and the hedge fail, the router excludes both and retries with the next-best providers up to `max_retries`, matching the existing single-dispatch failover path.

Counters are exposed over `tenzro_getRouterMetrics`: `requests` (total routed), `hedges_dispatched` (primary still pending past the delay), `hedges_won` (hedge answered before its primary), and `deadline_exceeded` (requests abandoned because the whole-request wall-clock deadline elapsed before any provider succeeded). A high `hedges_won / hedges_dispatched` ratio means hedging is rescuing tail requests; a high `hedges_dispatched / requests` ratio means primaries are routinely slow; a rising `deadline_exceeded` means providers are missing the caller's deadline outright.

### 2.4 Chat surface

Language inference is exposed six ways over one runtime:

- `tenzro_chat` and `tenzro_chatCompletion` JSON-RPC (the canonical Tenzro chat shape, with `params.custom["draft_n"]` for MTP and `params.custom["chat_session"]` for the persisted session id)
- `tenzro_chatStream` JSON-RPC streaming variant
- `POST /v1/chat/completions` — OpenAI-compatible HTTP endpoint (handler: `handle_openai_chat_completions`)
- `POST /v1/responses` — the Responses shape over the same handler (handler: `handle_openai_responses`, translation in `openai_responses.rs`)
- `POST /api/paid/chat/completions` — HTTP 402-gated variant for x402 / MPP / AP2 payment binding
- `POST /chat-stream` — Anthropic-style SSE endpoint (handler: `handle_chat_stream_rich`)
- MCP `chat_completion` tool, A2A `inference` skill, CLI `tenzro chat`

Each surface is a thin wrapper over the same router and runtime — the model and provider are the same underneath.

### 2.5 Multi-Token Prediction

Speculative decoding lets a target model generate multiple tokens per inference step using a smaller drafter. **MTP** is the jointly-trained variant — an auxiliary head that shares hidden state with the target and produces tokens consistent with the target's distribution.

Tenzro wires MTP through the full path:

- **Catalog metadata.** Each `HfModelEntry` declares its paired drafter (`drafter_id`), the speculation flavour (`mtp_kind: DraftMtp` for joint MTP heads, `Generic` for classical drafter pairing), and the recommended starting `draft_n`.
- **Provider capacity.** `ProviderCapacity.mtp_enabled` advertises drafter co-load. `ProviderCapacity.drafter_vram_gb` advertises the VRAM headroom reserved for the drafter.
- **Router filter.** When the request carries `params.custom["draft_n"]`, the router filters to MTP-capable providers; when no MTP-capable provider exists for the model, the router falls back to standard autoregressive providers so the caller can degrade.
- **Runtime.** The MTP variant of llama.cpp consumes the joint head via the vendored `llama-cpp-rs` `MtpSpeculative` wrapper. `generate_speculative` accepts the longest matching prefix on each step.
- **Drafter auto-load.** `tenzro_serveModel` reads the catalog entry's `drafter_id` and loads the paired drafter automatically. If the drafter GGUF is on disk it loads inline; otherwise a background download starts and the drafter attaches when it completes — the target serves non-speculatively in the meantime. The serve response carries an `mtp` field reporting the outcome: `none` (entry declares no MTP), `inline` (single-file MTP model, the draft head lives inside the target GGUF), `drafter_loaded`, `drafter_downloading`, `drafter_load_failed`, `drafter_unavailable`, or `disabled` (caller passed `"load_drafter": false`). A drafter problem never fails the serve. `tenzro_stopModel` unloads the drafter with its target, and the drafter is re-attached on node restart when the served model is restored.

Listed in the catalog with `mtp_kind: DraftMtp`: DeepSeek V3 (native MTP head), DeepSeek V4 Pro / Flash, GLM 5.2, Gemma 4 (E2B / E4B / 12B / 26B-A4B / 31B), Qwen 3.5 every size (0.8B / 2B / 4B / 9B / 27B / 35B-A3B / 122B-A10B / 397B-A17B), Qwen 3.6 27B and 35B-A3B. For dense models without a joint head, classical two-model speculative decoding (`MtpKind::Generic`) is wired through the same path.

### 2.6 Per-model serving profile

The catalog is the single source of truth for serving behaviour. Each `HfModelEntry` carries a `serving: ServingProfile` (temperature, top_p, top_k, min_p, `jinja_required`, `reasoning_default`) stamped from the model author's recommended values (Unsloth per-family guidance) by a single post-construction pass keyed on family + architecture — the per-family knowledge lives in one `ServingProfile::for_family` function rather than being duplicated across the struct literals. Clients consume the profile two ways: the `tenzro_modelMetadata` RPC returns it (alongside `drafter_id`, `mtp_kind`, MoE shape, and multimodal/`mmproj` flags) so any client can render or apply the recommended config, and the local serving sidecar stamps each on-disk GGUF's preset section with the profile's samplers, `--jinja`, speculative (`spec-type`), and MoE-offload (`n-cpu-moe`) flags. Request-level parameters override the profile; the profile is the default, not a ceiling.

### 2.7 Hardware backends

A provider can serve inference on whatever accelerator it has. llama.cpp's ggml runtime provides a backend for every major vendor; Tenzro exposes each one as a cargo feature on `tenzro-model` that forwards to the corresponding `GGML_<X>` cmake define at build time. A node compiled with a backend feature detects the device at runtime and reports it through `HardwareInfo` (`compiled_backends` + `active_backend`), logged when the llama backend initialises. The default build (`cluster-serving`) is CPU-only plus the ggml RPC backend for LAN layer-pipeline serving.

| Hardware | Backend | Cargo feature | Build-time requirement |
|---|---|---|---|
| NVIDIA (datacenter + consumer) | CUDA | `cuda` | CUDA Toolkit |
| NVIDIA (older drivers / no VMM) | CUDA | `cuda-no-vmm` | CUDA Toolkit |
| AMD (Instinct + Radeon) | HIP / ROCm | `rocm` | ROCm + hipcc |
| Apple Silicon | Metal | auto-linked (macOS ARM64); `metal` to force | Xcode toolchain |
| Intel Arc / Battlemage / Data Center GPU Max / Xe | SYCL | `sycl` | oneAPI DPC++ (`icx`/`icpx`) |
| Intel CPU / GPU / NPU | OpenVINO | `openvino` | OpenVINO runtime; device via `GGML_OPENVINO_DEVICE` (`CPU`/`GPU`/`NPU`) |
| NVIDIA / AMD / Intel Arc / ARM Mali / Adreno | Vulkan | `vulkan` | Vulkan headers + loader + `glslc` |
| Qualcomm Adreno / ARM Mali | OpenCL | `opencl` | OpenCL 3.0 headers + ICD |
| Moore Threads MTT S-series | MUSA | `musa` | MUSA toolkit |
| Huawei Ascend 910 / 310 NPU | CANN | `cann` | Ascend CANN toolkit |
| Cross-vendor GPU (Dawn) | WebGPU | `webgpu` | Dawn |
| IBM Z Telum | zDNN | `zdnn` | zDNN library |
| CPU (BLAS-accelerated) | BLAS | `blas` | OpenBLAS / Intel MKL / Apple Accelerate |
| CPU (fallback) | — | none | — |

**Build recipes.** Pass the backend feature to `tenzro-node` at build time:

```bash
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/cuda
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/rocm
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/vulkan
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/sycl
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/openvino
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/opencl
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/musa
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/cann
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/webgpu
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/zdnn
cargo build --release -p tenzro-node -p tenzro-cli --features tenzro-node/blas
```

SYCL additionally needs the oneAPI DPC++ compiler selected as the C/C++ compiler (`CC=icx CXX=icpx`). OpenVINO picks its device at runtime from `GGML_OPENVINO_DEVICE` (defaults to `CPU`); the node reports the selected device in `active_backend`.

**Container images.** Three prebuilt Dockerfile variants cover the widest-reach backends. The base `Dockerfile` is the CPU image.

| Backend | Dockerfile | Run flags |
|---|---|---|
| CUDA | `Dockerfile.cuda` | `--gpus all` |
| ROCm / HIP | `Dockerfile.rocm` | `--device /dev/kfd --device /dev/dri --group-add video` |
| Vulkan (cross-vendor) | `Dockerfile.vulkan` | `--device /dev/dri -v /usr/share/vulkan/icd.d:/usr/share/vulkan/icd.d:ro` |

Backends without a prebuilt image (SYCL, OpenVINO, OpenCL, MUSA, CANN, WebGPU, zDNN, BLAS) build from the base `Dockerfile` template with the vendor toolchain layered into the builder stage and the matching `--features tenzro-node/<x>` flag.

The non-LLM modalities (forecast / vision / text-embed / segmentation / detection / ASR / video) run on ONNX Runtime and fall back to CPU under every GPU image; the `onnx-cuda`, `onnx-tensorrt`, and `onnx-coreml` features link the corresponding ONNX Runtime execution provider where available.

---

## 3. Mixture-of-Experts serving

MoE architectures activate a small subset of expert FFNs per token. Total parameter count can sit at 122B / 397B / 685B / 1T while the active path is only 3–37B — generation-time compute scales with the active path. Tenzro serves MoE in two modes that share the same provider population.

### 3.1 Full-replica mode

A provider whose hardware fits the entire model holds it and serves single-peer inference exactly like a dense model. Gemma 4 26B-A4B, Qwen 3.5 35B-A3B, Qwen 3.6 35B-A3B, Kimi K2.5, DeepSeek V3 on a single H200-class node.

### 3.2 Decentralized expert-shard mode

For models too large for any single provider, providers declare which subset of expert weights they hold via `ProviderCapacity.moe_holdings` — a list of `MoeExpertHolding { model_id, layer, expert, residency, committed_tps }`. Residency is `Warm` (memory-resident), `Cold` (on the holder's disk tier, decoded on demand), or `Evicting`. Each holder derives this residency from its own `MoeExpertRuntime` tier state (§3.6) rather than a static declaration, so the shard map reflects what is actually loaded at query time.

A dispatch planner (`plan_dispatch`) aggregates per-token top-k routing decisions into per-holder batches. Each batch carries the tokens whose top-k resolved to the same `(expert, holder)` tuple. The batch is dispatched directly over the holder's iroh QUIC endpoint when available, or the OpenAI-compatible HTTP endpoint otherwise.

Three mechanisms overlap and harden the cross-holder fan-out:

- **Q8_0 activation compression.** Batch hidden states cross the `tenzro/moe` wire as GGUF Q8_0 blocks (`ExpertExecuteRequest::compressed`) — one f16 scale plus 32 int8 values per 32-wide block, ~4× smaller than raw f32 at ~0.4% error. Compression engages only when `d_model % 32 == 0`; otherwise the request stays dense. The holder's `execute()` path is carrier-agnostic: `materialize_hidden()` yields f32 rows whether the request arrived compressed or dense.
- **Backup redispatch.** The planner records every reachable holder for an expert in warm-first order. The primary is carried inline on the batch; the remaining holders become `ExpertBatch::backups`. When a holder fails at the transport level or returns a holder-side error, the router redispatches the same token batch to the next standby before failing the batch.
- **Pipelined combine.** The router folds each holder response into a `MoeCombiner` the moment it arrives (fed from a `FuturesUnordered` stream), overlapping the gate-weighted gather with still-in-flight batches instead of blocking on the slowest holder. `MoeCombiner::finish` verifies every gate-selected `(expert, token)` contribution arrived.

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

### 3.5 LAN clustering: layer-wise pipeline parallelism

The expert-shard mode above splits a model across providers over the WAN. A single provider can also split a model across machines on its own local segment — several boxes that, jointly, hold a model none of them fits alone. To the wider network the cluster is one logical provider (`ProviderCapacity.lan_cluster: Option<LanCluster>`); internally the head fans the model across members over the LAN.

The split is a layer-wise pipeline: the model's transformer layers are partitioned into contiguous ranges, one range per member, and a token flows head → member → member, each executing its range and forwarding only the boundary activation to the next. This is the deliberate choice for commodity local networks — pipeline parallelism moves only `hidden_dim × dtype_bytes` per token between members (fp16 activations regardless of weight quant), so it tolerates ordinary Ethernet/Wi-Fi RTTs. Expert-parallel all-to-all and tensor-parallel row-splits need NVLink/RDMA fabrics and collapse on a LAN.

Because there is one GGUF on the head and the members are device executors, members may mix backends (CUDA, Metal, Vulkan, HIP, SYCL, CPU) in one pipeline, and quantization is not per-member. The one hard requirement is a shared llama.cpp build commit across all members — the RPC wire protocol has no version negotiation.

Orchestration is deterministic; nothing in the placement path runs a model or makes a generative decision. `tenzro-model`'s `cluster` module decides:

- **Fit policy** (`single_box_fit` / `should_cluster`) — a cluster is only worth forming when no single member can hold the model. The default fit policy is run-local, advise-only: if a single member fits, it serves alone and clustering is advised but not forced.
- **Layer assignment** (`assign_layers`) — largest-remainder, VRAM-weighted bin-packing of layers into contiguous `PipelineStage { start_layer, end_layer }` ranges, floored at one layer per admitted member. More memory earns proportionally more layers.
- **Hardware gate** (`hardware_gate`) — per-member admission: can the member load its range on its backend, and does its build commit match the cluster's. Rejections carry a typed `RejectReason` (`CommitMismatch`, `NotDataPlaneReachable`, `InsufficientVram`).
- **Network gate / stage ordering** (`order_stages`) — a greedy nearest-neighbour chain over a probed latency/bandwidth matrix (`LinkProbe { rtt_ms, bandwidth_gbps }`), admitting only data-plane-reachable members. Members reachable only via relay or behind symmetric NAT are excluded — the relay budget carries a handful of tokens at most, never per-token pipeline traffic.

Members are discovered from the runtime ggml device API (`list_llama_ggml_backend_devices()`), normalized into a `NodeProfile { llama_commit, cpu_arch, os, devices }`, and offered as `ClusterMember` candidates over local discovery (see NETWORK.md, mDNS / `LocalPeerSet`). Two members fed identical inputs compute the identical plan with no coordinator round.

**From plan to running pipeline.** The deterministic plan above becomes a live pipeline in `tenzro-node`'s cluster-serving runtime. A node can act as the cluster **head**, a **member**, or both, and the runtime stays dormant until a plan activates it — a node that neither heads nor joins a cluster pays nothing.

- **Member.** A member never exposes its ggml `rpc-server` socket on the network; the RPC wire protocol is unauthenticated and unsafe on an open network. Instead it subscribes to the authenticated libp2p cluster-tunnel overlay (see NETWORK.md) and, for each session a head opens, spawns a loopback `rpc-server` and splices the tunnel byte stream to that socket. One request-response pair is full-duplex: frames in, socket bytes out, return bytes piggybacked on the acknowledgement.
- **Head.** The head consumes the plan's ordered stages. For each it opens a tunnel session to the member, binds a loopback TCP listener, bridges the accepted connection to the session, and registers `127.0.0.1:<port>` as a ggml RPC backend device. With every member registered in pipeline order it loads the single GGUF, selecting those devices with the plan's `--tensor-split` proportions so the runtime's proportional device-fill reproduces the assigned contiguous layer ranges. The loaded model is exposed to the inference path as one logical provider.
- **Failover.** A dropped stage surfaces as a ggml load/decode failure; the serving path tears down the half-open sessions, asks the planner for a fresh plan over the still-reachable members, and reloads. Re-planning is deterministic, so two heads fed the same surviving-member set converge on the same replacement with no coordination round.

**Auto-discovery.** Clustering does not require the caller to hand-supply members. An AI-serving node that is willing to join LAN clusters advertises a `ClusterProfile { llama_commit, backend, cap_key }` on its provider announcement (see NETWORK.md); nodes that omit it are never auto-clustered. When `tenzro_serveModel` is called with a `model_shape` but no explicit `cluster_members`, the head gathers candidates from gossip — itself (serving the first stage locally) plus every provider that advertised a `ClusterProfile` — and feeds them to the same fit policy and planner. A peer also seen on the local mDNS segment is treated as `LocalDirect` regardless of its announced WAN tier; the planner's hardware gate and stage ordering drop commit-mismatched, VRAM-starved, or non-data-plane-reachable candidates. Passing `force_single: true` opts out and forces a single-box load; passing explicit `cluster_members` overrides auto-discovery.

### 3.6 Expert-host execution

The dispatch planner in §3.2 decides *where* each token batch goes; the expert-host execution runtime carries the tensors there and runs the math.

Every node embeds a `MoeExpertRuntime` (`tenzro-model::moe_exec`). An expert holder loads expert FFN weights (`ExpertFfn`, gate/up/down projections with SwiGLU activation) and gating networks (`GatingNetwork`) from safetensors payloads, keyed by `(model_id, layer, expert)`.

The gating network supports both router families in the catalog. Qwen-layout checkpoints use softmax top-k routing. DeepSeek-layout checkpoints (DeepSeek V3/V4, Kimi K2/K3) use sigmoid scoring with a per-expert selection bias: experts are *selected* by `sigmoid(score) + bias` but *weighted* by the raw sigmoid scores, renormalized to sum 1 and scaled by the checkpoint's routed scaling factor. The gate blob is self-describing — the presence of a `router.bias` tensor switches the sigmoid path on, and `routed_scaling_factor` / `shared_experts` ride in the blob's `__metadata__` — so a holder loads either family with the same call. When the checkpoint declares a fused shared-expert FFN, the router appends it as one extra weight-1.0 slot per token at index `num_experts`; the distributed layer treats it as a normal expert for announcement, holding, dispatch, and settlement.

The runtime holds experts in two tiers under a byte budget, so a holder can advertise more experts than fit in memory:

- **Memory tier.** A byte-bounded LRU keyed by `(model_id, layer, expert)`. Each admitted expert is charged its decoded footprint against `ResidencyConfig.memory_budget_bytes`. When the budget is exceeded the least-recently-used expert is evicted; a single oversized expert still stays servable rather than being rejected.
- **Disk tier.** On load, the raw safetensors blob is written to `<data_dir>/moe_experts/` (atomic temp-write then rename). An evicted expert drops from memory but remains indexed on disk, so it is decoded back on demand instead of being re-fetched over the network.
- **Auto budget.** With `ResidencyConfig::auto()` the budget is read from the host — 60% of Linux `MemAvailable` — falling back to 4 GiB off-Linux. Nodes set an explicit budget with `with_memory_budget(bytes)`.
- **Readahead.** Before a distributed forward dispatches, the coordinating node promotes the disk-tier experts named by the current routing decision back into memory (`readahead`), so the experts a batch is about to hit are warm when the batch arrives.

A holder can lower an expert's resident footprint by loading it block-quantized instead of dense. Each of the three projections is independently either dense f32 or GGUF k-quant: Q8_0 (block width 32), Q4_K, or Q6_K (block width 256). A quantized projection is stored as a flat `U8` safetensors tensor carrying `"<name>.quant"` (`q8_0` / `q4_k` / `q6_k`) and `"<name>.shape"` (`"rows,cols"`) in the blob's `__metadata__`; `ExpertFfn::from_safetensors` reads those back and keeps the projection in its quantized form. The SwiGLU forward dequantizes one weight row at a time into a scratch buffer, so the resident charge against the byte budget is the quantized size, not the dense size — a Q4_K expert costs ~4 bits/weight instead of 32, so roughly 8× more experts stay warm in the same budget. The GGUF `Q4_K_M` convention (`ExpertQuantPlan::q4_k_m`) keeps `gate`/`up` at Q4_K and `down` at Q6_K, since down-projection error dominates output quality. Projections whose column width is not a multiple of the kind's block width are left dense.

`resolve` serves a memory hit directly (touching its LRU position) and, on a disk hit, decodes the blob, admits it to memory, and re-runs eviction. `status` reports both tiers — per-expert `tier` (`memory` / `disk`), the coarsest projection `quant` tag when quantized, plus `memory_bytes`, `memory_budget_bytes`, `memory_experts`, and `disk_experts`.

The runtime also carries cumulative residency counters so an operator can see whether a node's memory budget matches the model it serves: `evicted_to_disk` (experts spilled to the disk tier under LRU pressure), `evicted_dropped` (experts dropped entirely because no disk tier is configured — these must be re-fetched from a peer holder before serving again), and `admissions_over_budget` (a single expert larger than the whole budget was admitted anyway, keeping it servable while resident bytes exceed the ceiling). A rising `evicted_dropped` on a node without a disk tier, or a non-zero `admissions_over_budget`, signals the budget is too small for the assigned shard and the holder is thrashing network fetches or overcommitting memory.

A distributed layer forward (`tenzro_moeForward`) runs in three steps on the coordinating node:

1. **Gate.** The local gating network routes each token's hidden state to its top-k experts (`route_batch`).
2. **Dispatch.** Routing decisions feed the §3.2 planner, which groups tokens into per-holder batches. Each batch is an `ExpertExecuteRequest` — hidden states as base64-encoded little-endian f32 rows — sent over a three-tier transport: local execution when this node holds the expert, the holder's iroh QUIC endpoint (`tenzro/moe` ALPN, methods `moe/execute` and `moe/status`) when one is advertised, or the holder's HTTP endpoint otherwise.
3. **Combine.** Per-expert outputs come back as `ExpertExecuteResponse` rows and are recombined per token, weighted by the gate probabilities (`combine_expert_outputs`).

The wire format is identical across all three tiers, so a holder can serve LAN peers, WAN peers, and its own local router with one code path.

**Failover.** Holder failures are handled inside the forward, not surfaced to the caller. Each batch first walks its planned holder set — primary, then each standby in the planner's warm-first order — retiring any holder that fails at the transport level or returns an execution error. When a batch exhausts every known holder, the coordinating node replans: the affected (expert, token) pairs are re-dispatched against a rebuilt shard view that excludes every provider that already failed, while contributions already gathered stay in the combiner. Replanning is bounded at two rounds per forward. Each holder failure records a reputation penalty against that provider and the winning holder's latency feeds its serving metrics, so repeat offenders sink in future dispatch plans.

By default the forward is fail-closed: tokens still unservable after the replan budget fail the request. Passing `allow_partial: true` instead drops the unservable (expert, token) contributions, renormalizes each affected token's surviving expert outputs by their gate weights, and reports the dropped slots in the response's `missing` field (`[{layer, expert, tokens}]`) alongside a `replans` count — the distributed analogue of serving with a reduced top-k under partial outages.

**Throughput metering.** Every expert holder meters its aggregate expert-forward throughput (tokens served per second over a rolling minute) and stamps the measurement onto each advertised holding as `committed_tps`, so the dispatch planner ranks holders by observed serving capacity rather than self-declared numbers.

**Execution receipts.** Every remote expert execution is signed. The holder computes an activation commitment over its output rows — for each token, the top-k features by absolute value (k = 8 by default), hashed under a dedicated domain tag — and signs `(model_id, layer, expert, token_indices, input_carrier_hash, commitment_hash)` with the same Ed25519 key that signs its provider announcements. The input carrier hash covers the exact bytes the router sent (including the Q8_0-compressed hidden-state carrier when that leg is in use), so both sides hash identical bytes and the binding survives the lossy transport encoding. The router verifies each receipt inline before accepting a batch: it recomputes the activation commitment from the returned outputs, checks the signature, the provider binding, and token-set equality. A response with a missing, mismatched, or unverifiable receipt is treated exactly like a transport failure — the holder is retired for the batch, takes the reputation penalty, and the standby/replan path takes over. Local self-execution attaches no receipt and is never settled. A holder without a signing key on disk serves receiptless and is rejected by remote routers, matching the fail-closed provider-announcement policy.

**Settlement.** After a forward completes, the router settles the remote expert work per holder in the background — response latency never waits on settlement. Each holder is paid at its own advertised per-input-token price with its minimum-price floor; the network's inference commission is deducted, and the holder's reputation is credited with the net amount through the settled-success path — the only path that raises a provider's score, so reputation tracks paid, receipt-verified work rather than mere liveness. The settlement engine records an audit entry whose proof bytes are the concatenated activation-commitment hashes from that forward's signed receipts, and the usage tracker meters the per-model, per-holder token counts.

**Sampled receipt store and disputes.** Roughly one in 64 verified batches is persisted in full — the exact request carrier, the complete activation-commitment rows, and the holder's signed receipt. Sampling is keyed off the commitment hash itself, so a holder cannot predict which of its batches will be retained. Any node holding its own copy of the disputed expert can re-execute the stored request and compare its output rows against the committed sketch: per-row index overlap and relative feature delta must clear fixed thresholds. An upheld dispute is a fraud proof against the signed receipt and hits the holder with the quarantine-grade reputation penalty.

### 3.7 RPCs

Planning and topology:

- `tenzro_moeShardMap` — live shard map: per-expert holder list, replication factor, under-replicated experts, hot experts, role counts
- `tenzro_moePlanDispatch` — given a list of per-token routing decisions, returns the per-holder batch plan plus token-level assignment so the caller can reassemble per-token outputs
- `tenzro_moeReplicationPolicy` — current policy snapshot
- `tenzro_moeCatalogShape` — catalog-side MoE topology for a model: `num_experts`, `experts_per_token`, `shared_experts`, `params_per_expert_x10`
- `tenzro_modelMetadata` — full catalog metadata for a model: `serving` profile (samplers, jinja, reasoning), `multimodal` + `mmproj_filename`, `drafter_id` / `mtp_kind` / `mtp_default_draft_n`, MoE `moe` shape, and `architecture`. The read API over the catalog's single source of truth, consumed by the CLI and SDKs.

Execution:

- `tenzro_moeExpertLoad` / `tenzro_moeExpertUnload` — load or unload one expert FFN's safetensors weights for `(model_id, layer, expert)`
- `tenzro_moeGateLoad` / `tenzro_moeGateUnload` — load or unload a layer's gating network
- `tenzro_moeExpertStatus` — resident experts and gates on this node: per-expert tier (`memory` / `disk`) and footprint, plus `memory_bytes` / `memory_budget_bytes` / `memory_experts` / `disk_experts`
- `tenzro_moeRoute` — run the local gating network over a batch of hidden states, returning per-token top-k expert assignments
- `tenzro_moeExecute` — run a batch of tokens through one locally-resident expert FFN
- `tenzro_moeForward` — the full distributed layer forward: gate → plan → dispatch to holders (local / iroh / HTTP) → combine, with bounded in-flight failover around failed holders; `allow_partial: true` degrades unservable tokens to a gate-weight-renormalized partial combine reported under `missing`, and the response's `replans` counts failover rounds. Every remote batch is receipt-verified inline and settled per holder in the background
- `tenzro_moeListReceipts` — summaries of the sampled execution receipts this router has persisted: model, expert, token count, holder, commitment hash, storage key; optional `model_id` filter and `limit`
- `tenzro_moeDisputeReceipt` — re-execute a stored receipt's exact request carrier against this node's own copy of the expert and compare the output rows to the committed activation sketch; an upheld dispute applies the quarantine-grade reputation penalty to the receipt's signer

Weight preparation:

- `tenzro_moePrepareExperts` — extract per-expert (and optionally gate) safetensors blobs for a catalog MoE model directly from its original checkpoint using HTTP-Range tensor fetches (only the requested tensors cross the wire, never whole shards), publish each blob into the iroh blob store, and return a background job id. An optional `quant` param re-encodes each expert blob before publish: a preset string (`"q4_k_m"`, or a uniform `"q8_0"` / `"q4_k"` / `"q6_k"`) or a per-projection object (`{ "gate": "q4_k", "up": "q4_k", "down": "q6_k" }`, any projection omitted stays dense). Prepared quantized blobs are self-describing, so a holder loads them at their reduced footprint with no extra flags.
- `tenzro_moePrepareStatus` — progress snapshot for a prepare job: completed experts, each blob's `quant` tag when quantized, and the resulting `tenzro://blob/` URIs, which feed `tenzro_moeExpertLoad` / `tenzro_moeGateLoad` on any node

The extractor understands two checkpoint layouts, selected by the entry's architecture. The Qwen layout (`Qwen3MoeForCausalLM`) has routed experts and a softmax router on every MoE layer. The DeepSeek layout (`DeepseekV3ForCausalLM` — DeepSeek and Kimi families) shares the routed-expert tensor pattern and adds three things the extractor carries through: the router selection bias (`e_score_correction_bias`, packed into the gate blob as `router.bias`), the fused shared-expert FFN (prepared as one extra expert slot at index `num_experts`, requested like any other expert id), and dense-first-k layers — the extractor fetches the checkpoint's `config.json` at open, requires `first_k_dense_replace` / `routed_scaling_factor` / `n_shared_experts` to be present, refuses expert extraction on the dense layers with a clear error, and stamps the scaling factor and shared-expert count into the gate blob's `__metadata__` so the loading node needs no side-channel configuration.

### 3.8 Catalog coverage

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
| Kimi K3 | `kimi-k3` | 896 | 16 | 2 |
| MiniMax | `minimax-m1-40b`, `minimax-m3` | 32 | 2 | 0 |
| DeepSeek | `deepseek-v3-0324`, `deepseek-v4-flash`, `deepseek-v4-pro` | 256 / 256 / 512 | 8 | 1 |
| GLM | `glm-5`, `glm-5.1`, `glm-5.2` | 160 | 8 | 1 |
| Nemotron Nano | `nemotron-nano-30b-a3b` | 16 | 4 | 0 |
| OpenAI | `gpt-oss-120b` | 128 | 4 | 0 |

Per-expert extraction (`tenzro_moePrepareExperts`) additionally needs a safetensors checkpoint source mapped in `moe_safetensors_repo`. Currently mapped: `qwen3-30b-a3b`, `deepseek-v3-0324`, `deepseek-v4-flash`, `deepseek-v4-pro`, `kimi-k2-instruct`, `kimi-k2.6`, and `kimi-k3`. The mapping is independent of `hf_repo`, so an entry can serve both paths: `kimi-k3` extracts experts from `moonshotai/Kimi-K3` while its whole-model artifact is the `UD-IQ1_S` quant in `unsloth/Kimi-K3-GGUF`. At 594GB for the smallest quant, that whole-model path is a pipeline cluster rather than a single host.

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
| Text embedding | Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0, ModernBERT-embed base/large (8192-context RoPE encoder) | `tenzro_textEmbed` | `tenzro_embed` |
| Segmentation (point/box) | SAM 2 base/large, EdgeSAM, MobileSAM | `tenzro_segment` | |
| Segmentation (text-promptable) | SAM 3 / 3.1 | `tenzro_textSegment` | |
| Detection | RF-DETR n/s/m/b/l/2xl (90-class COCO), D-FINE n/s/m/l/x (80-class) | `tenzro_detect` | |
| Audio ASR | Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash | `tenzro_transcribe` | |
| Video | Vision-fallback encoder over uniformly-sampled frames | `tenzro_videoEmbed` | |

Each modality has a dedicated runtime in `tenzro-model` with model-specific preprocessing (mel-spectrogram for ASR, ImageNet / CLIP / SigLIP normalization for vision, BPE tokenization for text-embed). The runtime dispatch hides the per-family ABI differences (SAM 1 vs SAM 2 decoder, RF-DETR vs D-FINE post-processing, Parakeet RNN-T vs Canary NeMo Conformer-AED).

**Serving embeddings — local or network.** `tenzro_loadTextEmbeddingModel` with just `{ model_id }` (a catalog id) fetches the ONNX graph, its `model.onnx_data` external-data sidecar when the export has one (Qwen3-Embedding, EmbeddingGemma, BGE-M3 do; ModernBERT-embed is self-contained), and the tokenizer from HuggingFace as a co-located bundle onto the persistent models directory, then registers the encoder — pooling family and dimensions come from the catalog entry. Passing explicit `path` + `tokenizer_path` + `family` instead loads a self-hosted file already on disk. Once loaded, `tenzro_textEmbed` serves from the local runtime handle; when the model is not loaded on this node, the router dispatches to a remote provider serving it. The same choice a node makes for language models and blobs applies to embeddings: run it locally or use the network. CLI: `tenzro embed-text {catalog,load,unload,list,run}`.

**OpenAI-compatible endpoint.** `POST /v1/embeddings` (handler: `handle_openai_embeddings`) serves any loaded encoder in the OpenAI wire shape — `input` as a string or array, optional `dimensions` for Matryoshka truncation, response `{ object, data: [{ object, index, embedding }], model, usage }`. It sits on the same router as `/v1/chat/completions` and is HTTP 402-gated when a payment gate is configured, open otherwise. The ORT encoder path does not meter tokens, so `usage` reports 0.

**OpenAI-compatible transcription endpoint.** `POST /v1/audio/transcriptions` (handler: `handle_openai_transcriptions`) serves any loaded transcriber over `multipart/form-data` in the OpenAI wire shape — a `file` part carrying the audio and a `model` part naming the catalog entry, with `language`, `temperature`, `timestamp_granularities` and `response_format` alongside. All five OpenAI response formats are served: `json`, `text`, `verbose_json` (segment list with `start` / `end` / `text`), and the `srt` / `vtt` subtitle bodies rendered from the runtime's segment time ranges. Requesting a format that renders time ranges makes the runtime emit them regardless of `timestamp_granularities`. The body ceiling on this route is 128 MiB rather than the 2 MiB that governs JSON bodies, since a limit sized for chat would reject an ordinary audio file. Word-level granularity, a non-empty `prompt`, and unknown form fields are refused by name rather than dropped. Wire details in [`chat-api.md`](chat-api.md#audio-transcriptions).

**Tenzro-namespaced endpoints for the modalities no vendor covers.** Forecasting, detection, segmentation and clip embedding have no OpenAI path to be compatible with, so they sit under `/v1/tenzro/…` rather than occupying a vendor name the vendor may later define differently:

| Route | Handler | Body | Response |
|---|---|---|---|
| `POST /v1/tenzro/forecasts` | `handle_openai_forecasts` | `model`, `history` (oldest first), `horizon`, optional `quantiles` + `frequency_seconds` | `{ object: "forecast", point, quantiles, quantile_levels, generation_time_ms }` |
| `POST /v1/tenzro/detections` | `handle_openai_detections` | `model`, `image_base64`, optional `score_threshold` (default `0.25`) | `{ object: "detection", detections, generation_time_ms }` |
| `POST /v1/tenzro/segmentations` | `handle_openai_segmentations` | `model`, `image_base64`, exactly one of `prompts` (geometric) or `text_prompt` (open-vocabulary), optional `box_prompt` + `score_threshold` | `{ object: "segmentation", masks: [{ score, mask_base64 }], generation_time_ms }` |
| `POST /v1/tenzro/video/embeddings` | `handle_openai_video_embeddings` | `model`, `video_base64`, optional `normalize` + `frame_stride` | `{ object: "video_embedding", embedding, dim, frames_consumed, generation_time_ms }` |

Three details follow from the modalities rather than from the wire shape. `prompts` and `text_prompt` are mutually exclusive because they select different runtimes holding different models under different ids — sending both is refused rather than resolved, since the route cannot pick for the caller. Masks travel base64-encoded: a 1024² mask as a JSON integer array is roughly 3 MB of text for one artifact, and no vendor standard governs the noun. Clip embedding is its own route rather than another `input` on `/v1/embeddings` because a clip returns one vector plus a frame count, and the vendor's `data[]` shape has no field to report how much of the clip was consumed. All four carry a base64 payload or a long series, so they sit on the 64 MiB media ceiling. When the named runtime holds nothing under that id, the error names both the RPC that loads one and the RPC that lists what is loaded. Wire details in [`chat-api.md`](chat-api.md#forecasts).

**Execution providers.** All ONNX runtimes share one session builder that registers hardware execution providers before falling back to CPU. The `onnx-tensorrt`, `onnx-cuda`, and `onnx-coreml` cargo features compile in the corresponding providers; the default registration priority is TensorRT → CUDA → CoreML, restricted to whichever features are compiled in. The `TENZRO_ONNX_EP` environment variable overrides the priority as a comma-separated list drawn from `tensorrt`, `cuda`, `coreml`, `cpu` (`cpu` terminates the list). A provider that fails to register logs a warning and falls through to the next — a GPU-featured binary on a machine without the matching driver still serves on CPU. The CUDA container image and GPU model-serving setup are covered in [`deploy/validator-deployment.md`](../deploy/validator-deployment.md).

### 4.1 Vision-language GGUFs (mmproj)

Natively-multimodal chat models (the Gemma 4 family, Kimi K3) run on the same llama.cpp language path as models that serve text alone, but accept image input. Two files load for these: the language GGUF plus a separate **multimodal projector** (mmproj) that encodes images into the model's embedding space. The catalog carries this on `HfModelEntry::mmproj` (`Some(MmprojSpec { filename })`); the projector lives in the model's own `hf_repo`, so only the filename is stored. The post-construction catalog pass stamps `mmproj-F16.gguf` onto every Gemma 4 language model (the tiny speculative `-mtp-draft` entries take no image input and stay `None`). The downloader fetches the projector alongside the model into `<models_dir>/<id>.mmproj.gguf`.

The runtime loads it in-process rather than shelling out to a server binary. `ModelRuntime::load_projector` runs at model load: it resolves `<id>.mmproj.gguf` (checking both the flat storage directory and the per-model directory a gguf-split set uses), initializes an `MtmdContext` against the already-loaded `LlamaModel`, and records the model id in a lock-free set that `ModelRuntime::supports_media` probes. A projector-carrying model is pinned to the serial serving path, because encoding an attachment and prefilling it are one unit and cannot interleave with a batched decode. When the projector is declared but absent on disk, or fails to initialize, the load logs a warning and the model serves text — `supports_media` returns false and an attachment is refused by name rather than silently dropped.

`ModelRuntime::generate_chat_multimodal` is the generation path: it renders the chat prompt, places one media marker per attachment in the last user turn when the caller sent none, encodes each image into an `MtmdBitmap`, and prefills the interleaved text-and-image chunks before sampling. Attachments bind positionally — the nth image in traversal order is the nth marker in the prompt. Four surfaces reach it: `tenzro_chat` in its rich shape (streaming and not), the OpenAI-compatible `/v1/chat/completions` `image_url` content part, the MCP `chat_completion` tool, and `tenzro chat`'s `/image <path>` REPL command. The simple `tenzro_chat` shape and the web `/chat` route carry a bare text message with no field an attachment could ride on, so both serve text regardless of the model's projector. The `mtmd` cargo feature on `tenzro-model` compiles the path in and is on by default; a build without it refuses an attachment and names the feature to rebuild with.

### 4.2 Sharded (gguf-split) downloads

Frontier-scale GGUFs (Kimi K2, Kimi K3, DeepSeek V3, GLM 5, MiniMax M3, the largest Qwen 3.5 MoE quants) are published as `gguf-split` sets where the catalog `hf_filename` points at the first shard (`...-00001-of-000NN.gguf`). The downloader detects this pattern, enumerates all `NN` shards from the self-describing suffix, and downloads them into a per-model directory (`<models_dir>/<id>/`) preserving their original filenames — llama.cpp only auto-continues a split set when every shard sits in one directory under its split name. `model_path`/`is_downloaded`/`downloaded_size`/`delete_model` all recognize the per-model-directory layout; single-file models keep the flat `<id>.gguf` form.

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

This section describes the protocol layer for decentralized training. The split between Rust protocol (`tenzro-training`) and Python reference trainer (`integrations/trainer/`) keeps the protocol layer free of tensor library churn while letting the per-modality adapters track frontier model architectures without protocol changes.

The training surface below preserves the original Tenzro Train design verbatim, renumbered to fit this document.

---

### 7.1 Motivation

Foundation model training today is concentrated in a handful of hyperscalers, for two reasons that are coupled but distinct:

1. **Compute density** — synchronous SGD over thousands of accelerators requires high-bandwidth interconnects.
2. **Data gravity** — proprietary datasets sit inside organizational boundaries.

Low-communication outer aggregation addresses (1) by reducing inter-worker bandwidth by approximately two orders of magnitude relative to elastic data-parallel training, making cross-region (and ultimately cross-organization) training feasible. It does not address (2): in the standard low-communication setting, learners are operated by the same entity that owns the data, and worker faults are hardware failures, not adversarial behavior.

Tenzro Train completes the picture: learners can be operated by independent parties, data can remain with its owner via TEE-resident execution, and the resulting model is settled on-chain with cryptographic provenance. This unlocks two distinct markets:

- **Commodity-compute training** — providers monetize idle GPUs, CPUs, or specialized accelerators by joining training runs and earning TNZO per accepted gradient.
- **Privacy-preserving training** — data owners contract with the network to train on their data without ever releasing it in cleartext, paying for compute in TNZO and receiving a verifiable model artifact.

Both markets apply equally to language models, timeseries models, vision models, and multimodal architectures. The protocol is modality-agnostic; modality enters only through the data adapter.

---

### 7.2 Background: Decoupled Outer Aggregation

Low-communication training reduces synchronization bandwidth by performing many local SGD steps on each worker before exchanging parameter updates. Decoupled outer aggregation extends this with three further changes that matter for our setting:

1. **Asynchronous learners.** M learners train independently. None waits for any other.
2. **Centralized syncer.** A coordinator holds the global parameter state. After every H inner SGD steps a learner sends its outer gradient (param delta) to the syncer; the syncer applies a fragment-wise outer optimizer (Nesterov-momentum SGD) and returns the updated fragment.
3. **Fragment-wise quorum.** Parameters are partitioned into P fragments. The syncer accepts an outer gradient for fragment j as soon as K of M learners have submitted; stragglers are absorbed via an adaptive grace window τ.

Reported results at large chip scale with realistic per-chip MTBF show substantially higher goodput than elastic data-parallel, with no correctness loss versus a synchronous baseline. Bandwidth between learners and syncer is approximately two orders of magnitude lower than elastic data-parallel.

What the base technique does not provide and Tenzro Train must supply:

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

**Gradient norm clipping.** The task carries an optional `clip_l2_norm` cap. Before aggregation the syncer scales any accepted outer gradient whose global L2 norm exceeds the cap back down to exactly the cap; smaller gradients pass through untouched. This bounds the influence a single trainer — honest or adversarial — can exert on the aggregate in one round, independent of the aggregation rule, and is the cheapest first line of defense against a runaway or crafted gradient. The Python reference trainer honors the identical cap when producing its local outer gradient, so an honest trainer is never clipped at the syncer; a gradient the syncer has to clip is one whose producer ignored the budget.

**Gradient signature binding.** Every `OuterGradient` carries the trainer's Ed25519 signature over a domain-separated encoding of its own fields. At accept time the syncer checks that the signing public key equals the declared `trainer_address` and that the signature verifies over that encoding; the Python reference trainer produces a byte-identical encoding when it signs. A submission with a mismatched key or a tampered payload is rejected before it can be buffered, so a trainer cannot forge a contribution under another trainer's identity.

**Slash-and-evict on rejected contribution.** A submission that deviates from the task spec the trainer enrolled under — bad signature, wrong quantization, out-of-stage fragment, missing attestation at a tier that requires it, or a malformed / hash-mismatched payload — is not merely dropped: the trainer is evicted from the run for the remainder of the run and its bond is slashed. The same applies post-aggregation to a buffered gradient the syncer had to clip (it exceeded the round's norm budget) or whose cosine agreement with the round aggregate fell below the run's floor. Benign timing or scope races an honest trainer can lose — a straggler submitting for a stale round, or for a fragment outside the current active shard — are dropped but never slashed. Eviction is terminal within a run; there is no down-weighted reputation and no rehabilitation, so an evicted trainer must re-enroll in a future run to participate again.

**Byzantine-robust aggregation.** A trainer might submit a numerically valid but adversarially crafted gradient (e.g., to insert a backdoor). The syncer applies one of:
- **Trimmed mean** — discard the top and bottom α% of gradients per parameter, mean the rest.
- **Coordinate-wise median** — robust to up to f < M/2 Byzantine learners.
- **Krum / Multi-Krum** — pick the gradient(s) with the lowest sum-of-distances to nearest neighbors.

The aggregation rule is committed in the `TrainingTask` and verified by all observers.

**LoRA / QLoRA runs.** When the task trains low-rank adapters rather than the full model, only the adapter matrices carry gradient and the outer gradient transmits just those matrices — the frozen base (4-bit NF4 for QLoRA) is never in the delta. The naive fix of meaning both factors independently is wrong: the useful update is the product `B·A`, and the mean of the products is not the product of the means. The `LoraAlternating` rule handles this by freezing one of the two factors each round (`round % 2`) and syncing only the other, so within a round every contributor submits the same single factor and a plain per-coordinate mean is correct. The reference trainer's language adapter enables this via `architecture.metadata.lora`; the alternating freeze lives in the trainer, so the syncer never needs the rank and applies the same `MeanAggregator` it uses for a full fine-tune. `LoraAlternating` is admissible at the Open tier.

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

- **Public** (Open or Verified tier) — dataset is referenced by content hash. The native path is the network's own blob store: shards published as `tenzro://blob/<hash>` (iroh-blobs, BLAKE3-verified on transfer), fetched by the trainer through the local node's `tenzro_iroh_fetchBlob` RPC. IPFS, Arweave, and plain HTTP are supported alternatives resolved through gateways. Trainers download cleartext.
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

Tenzro Train provides reference adapters for the modalities below. Sponsors can register additional adapters by publishing the adapter code's hash on-chain alongside their `TrainingTask`.

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

Different trainers may have different hardware (e.g., A100 vs. consumer 4090 vs. CPU-only). The quorum-based outer-aggregation design handles this naturally: slower trainers fall behind in vector-clock order but their late submissions are absorbed by τ. Sponsors can also tier trainers by `min_throughput` requirements in the `TrainingTask`, which the syncer enforces at enrollment.

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

For 200M-1B models (covering all current frontier timeseries foundation models), public-internet trainers are entirely viable at raw f32. For 7B+ language models the protocol carries five communication-efficiency mechanisms, each declared on the `TrainingTaskSpec` and enforced by the syncer:

- **Gradient quantization** (`quantization: GradientQuantization`). Blockwise symmetric compression of the outer-gradient payload: `Int8 { block_size }` stores a 4-byte little-endian f32 scale per block (`scale = max_abs / 127`) followed by one `i8` code per value — 4× smaller than f32; `Int4 { block_size }` uses `scale = max_abs / 7` with codes packed two per byte (low nibble first) — ~8× smaller. `None` is raw little-endian f32. The syncer rejects submissions whose declared quantization differs from the task's, so every trainer and every aggregation round shares one wire format. The Python trainer encodes and decodes the identical format.
- **Streaming synchronization** (`sync_strategy: SyncStrategy::Streaming { num_shards }`). Instead of synchronizing every fragment every round, fragments are partitioned into contiguous shards and each round synchronizes one shard (`active_shard = round % num_shards`). Per-round transfer drops by `num_shards`× and outer sync overlaps inner compute on the fragments that are not active. The syncer rejects submissions for inactive shards so per-fragment quorum accounting stays scoped. `Full` synchronizes everything every round.
- **Delayed application** (`delayed_apply: bool`). The aggregate computed at round *r* is applied by trainers at round *r+1*, overlapping the outer synchronization with the next inner-step window instead of stalling on it.
- **Adaptive outer learning rate** (`AdaptiveLrConfig` on the outer optimizer). The syncer computes the pairwise cosine agreement of submitted outer gradients (`gradient_agreement`) and scales the Nesterov outer step accordingly (`NesterovSgdState::step_with_agreement`) — high agreement earns a larger step, disagreement shrinks it.
- **Pipeline-parallel trainer groups** (`pipeline: Option<PipelineConfig { num_stages }>`). Trainers enroll as `(group_id, stage)` pairs; a group of `num_stages` trainers jointly holds one model replica, each stage owning the contiguous fragment slice `stage = fragment × num_stages / fragment_count`. Quorum counts distinct **groups** per fragment, so no single trainer needs to fit the whole model.

On the inner-loop side, the Python reference trainer supports **Muon** (momentum orthogonalized by Newton-Schulz) as the inner optimizer: matrix parameters take the Muon update, non-matrix parameters fall back to AdamW inside the same optimizer. As an inner optimizer for low-communication training, Muon converges with fewer outer synchronizations than AdamW at equal quality.

#### Multi-GPU sharding and hardware acceleration

The reference trainer scales from one GPU to a multi-GPU host with no configuration. Launched under `torchrun` (`RANK` / `WORLD_SIZE` in the environment), the language adapter shards the model with **FSDP2** (`torch.distributed.fsdp.fully_shard`) — per-parameter DTensor sharding with bf16 compute and fp32 gradient reduction (`MixedPrecisionPolicy`). Each block of the decoder stack is sharded individually so parameter prefetch overlaps compute, then the root module. Single-process runs skip sharding entirely; `tenzro_trainer.distributed.DistContext.detect()` returns a disabled context whenever `RANK` is absent or `WORLD_SIZE` is 1.

Under torchrun, every rank runs the full training loop (the FSDP2 collectives require all ranks to reach every gather at the same point), but only rank 0 speaks JSON-RPC to the node — the syncer sees one trainer per DID, not one per process. Each rank seeds its data sampler with its rank, so data-parallel width translates into distinct batches. Snapshot, load, and delta application in the inner loop are DTensor-aware: `snapshot_state` gathers full tensors (a collective), `load_partial_state` / `apply_state_delta` distribute full tensors back into the local shards. The Muon step gathers each sharded gradient to run Newton-Schulz on the full matrix, keeps the momentum buffer sharded, and distributes the orthogonalized update back.

Two further acceleration knobs, both automatic with metadata overrides:

- **Attention kernel.** The language adapter requests **FlashAttention-2** when the `flash_attn` package is importable and an accelerator is present, PyTorch SDPA otherwise. Override with `architecture.metadata.attn_implementation`. `flash-attn` is deliberately not a pip extra — it needs a CUDA (or ROCm) toolchain at install time, so GPU operators install it directly (`pip install flash-attn --no-build-isolation`) and the adapter picks it up. On AMD, the `flash_attn` package is the ROCm Composable-Kernel/Triton build; when it imports, transformers dispatches the ROCm kernel behind the same `flash_attention_2` request.
- **FP8 training.** Setting `architecture.metadata.fp8: true` converts eligible linear layers to FP8 via torchao `convert_to_float8_training` on Ada/Hopper-class GPUs (compute capability ≥ 8.9). Embedding and head modules are skipped, as are linear layers whose dimensions are not multiples of 16 (an FP8 kernel requirement). Absent a capable GPU or torchao (`pip install 'tenzro-trainer[fp8]'`), the request degrades to a logged no-op. torchao rowwise FP8 is treated as CUDA-only here — on a ROCm build the compute-capability tuple has HIP semantics and does not map to the ≥ 8.9 gate, so FP8 degrades to a logged no-op on AMD (MI300-class FP8 needs a different code path).

One constraint: QLoRA (`lora.quantize: "nf4"`) cannot be combined with FSDP2 sharding — bitsandbytes 4-bit parameters are not DTensor-compatible. Run QLoRA single-process, or drop `quantize` for multi-process LoRA.

**AMD ROCm.** *(Unverified on AMD hardware in this fleet — the reference path is coded and documented but has not been exercised on a physical AMD GPU here.)* PyTorch's HIP build reuses the `torch.cuda` namespace, so `torch.cuda.is_available()` returns True on AMD data-center (MI300X, 192 GB) and RDNA3/3.5/4 GPUs; the adapter discriminates the backend on `torch.version.hip`. Two install steps cannot be expressed as pip constraints and must be run manually on the ROCm host:

1. **ROCm torch wheel** — `pip install torch --index-url https://download.pytorch.org/whl/rocm6.3` (match the host's ROCm version).
2. **Patched bitsandbytes** — stock bitsandbytes ≤ 0.49.2 has a 4-bit NF4 dequant NaN bug on ROCm. Install the ROCm pre-release wheel with `pip` (not `uv`):
   ```
   pip install --force-reinstall --no-cache-dir --no-deps \
     "https://github.com/bitsandbytes-foundation/bitsandbytes/releases/download/continuous-release_main/bitsandbytes-1.33.7.preview-py3-none-manylinux_2_24_x86_64.whl"
   ```
   (swap `x86_64` → `aarch64` on ARM hosts, or use `bitsandbytes>=0.49.1`). The language adapter logs a warning when QLoRA is requested on ROCm with a NaN-prone bitsandbytes version.

The `tenzro-trainer[amd]` extra pulls the ROCm-safe language stack (transformers/peft/tokenizers); torchao FP8 is deliberately excluded from it (CUDA-only rowwise path). AMD GPUs otherwise run bf16/fp16 + SDPA (or ROCm FlashAttention when installed).

#### Measured inner-loop throughput

The transfer figures above are analytical; the inner-loop rate is measured. Running the timeseries reference adapter — a 3.19M-parameter patch transformer (`d_model=256`, 4 layers, 4 heads) matching the Phase 1 lead modality — through the real forward/backward/optimizer path on a single-core commodity CPU (no GPU), with 20 warmup steps discarded and 200 steps timed:

| Config | Hardware | Batch | Samples/s | Steps/s |
|---|---|---|---|---|
| timeseries reference (3.19M params) | 1× CPU core (n1-highcpu-8, Cascade Lake) | 8 | 177 | 22.2 |

A "sample" is one `context_patches × patch_size` forecasting window (16 × 32 = 512 points of context). The measurement covers the inner training compute only; model construction and shard load are excluded. Reproduce with:

```bash
tenzro-trainer-bench --steps 200 --warmup 20 --batch-size 8
```

The harness lives in `tenzro_trainer.benchmark` and drives the same `run_inner_loop` a real training round uses, so the number tracks the adapter as it evolves. GPU and larger-model figures move up from this floor; this CPU rate is the reproducible baseline any operator can confirm on their own hardware.

#### Measured LoRA fine-tune

The same harness runs a real PEFT LoRA fine-tune of a decoder-only LM. The base is frozen; PEFT injects low-rank adapter matrices at the attention projections; only those matrices carry gradient through the real forward/backward/optimizer path. Because only the adapters are trainable, the per-round outer gradient a trainer transmits is the serialized adapter delta alone — orders of magnitude smaller than a full-model gradient. The measurement below wraps a small Qwen3-family config built locally (no model-weight download, so it reproduces in CI), with 5 warmup steps discarded and 40 steps timed on a single commodity CPU core:

| Config | Hardware | Batch × Seq | Trainable | Delta/round | Samples/s | Steps/s |
|---|---|---|---|---|---|---|
| Qwen3-family LoRA (r=16) | 1× CPU core (n1-highcpu-8, Cascade Lake) | 4 × 128 | 196,608 (3.99%) | 790,816 B | 39.7 | 9.92 |

"Trainable" is the LoRA-adapter parameter count and its share of the base (the frozen base is excluded); "Delta/round" is the serialized safetensors bytes a trainer sends per round — exactly the adapter matrices, never the frozen base. At r=16 the trainer transmits ~0.77 MB per round regardless of base size, which is the point of the LoRA path: the per-round communication is set by the adapter rank, not the model. The measurement covers inner training compute only. Reproduce with:

```bash
tenzro-trainer-bench --modality language --steps 40 --warmup 5 \
  --batch-size 4 --seq-len 128 --lora-rank 16
```

Pass `--hf-repo Qwen/Qwen3-0.6B` (or any catalog member) to fine-tune the real pretrained backbone instead of the local config; the code path — PEFT `get_peft_model`, frozen base, adapter-only snapshot — is identical.

---

### 7.6 Economics

#### 7.6.1 Reward Distribution

Sponsor escrows `R` TNZO per `TrainingTask`. After each round in which a trainer's outer gradient is included in the syncer's aggregation, the trainer accrues `R / (rounds × M_per_round)` TNZO. Rewards are distributed at training-run finalization.

#### 7.6.2 Slashing Conditions

- **Rejected contribution** → a submission that deviates from the enrolled task spec (bad signature, wrong quantization, out-of-stage fragment, missing required attestation, malformed payload), or a buffered gradient over the round's norm budget or below the agreement floor, slashes the trainer's bond and evicts it from the run. Terminal for the run.
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

Tenzro Train splits cleanly into two layers — a Rust **protocol layer** that owns coordination, settlement, and verification, and a Python **inner-training reference** that owns the actual gradient computation. This mirrors the split adopted by production decentralized training projects in 2026.

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

- **PyTorch FSDP2** — intra-node sharding
- **Hivemind** — DHT-based inter-worker coordination metadata (adopted directly to avoid reinventing peer discovery)
- **safetensors** — fragment serialization on the wire (TEE-friendly, deterministic, no pickle)
- **Per-modality libraries** — `transformers` for language, `gluonts` + native PyTorch for timeseries (TimesFM, Chronos, Moirai), `timm` + native PyTorch for vision

The Python trainer is a thin agent that:

1. Authenticates with its TDIP DID + MPC wallet (via the Tenzro JSON-RPC).
2. Subscribes to the `tenzro/training` gossip topic.
3. On task assignment, resolves the dataset shard URI (`tenzro://blob/<hash>` natively through the local node's `tenzro_iroh_fetchBlob` RPC, with `ipfs://` / `ar://` / `http(s)://` as gateway-resolved alternatives and `file://` passthrough; remote fetches cache under `~/.cache/tenzro-trainer/shards`), then runs the inner loop the task's `objective` selects: H supervised SGD steps for `Supervised`, or H GRPO steps for `RlPostTraining` (Language modality only — per step, sample a `group_size` rollout group from one shard prompt, score with the sponsor's `py:<module>:<callable>` reward, take one optimizer step on the clipped surrogate with a k3 KL penalty against the sampling-time policy). Either way it emits its outer gradient as a safetensors blob — the outer contract is objective-agnostic.
4. Submits the safetensors blob + signature to the Rust syncer over JSON-RPC (`tenzro_training_submitOuterGradient`).
5. Listens for round-completion events on `tenzro/training/syncer` and pulls updated fragments back from the syncer.

The trainer can run anywhere Python + PyTorch run, including inside a TEE (Verified / Confidential tiers). The Rust syncer never touches a tensor; it only verifies signatures, runs the chosen aggregation rule over decoded `ndarray` views, applies the outer optimizer, and commits the result on-chain.

#### 7.7.2 Extensions to Existing Crates

- **`tenzro-types`** — add `TrainingTask`, `OuterGradient`, `TrainingReceipt`, `ArchitectureSpec`, `TrainingTier` types.
- **`tenzro-storage`** — add `CF_TRAINING_RUNS`, `CF_TRAINING_RECEIPTS` column families.
- **`tenzro-network`** — add gossipsub topic `tenzro/training` for outer gradient broadcast and `tenzro/training/syncer` for syncer state roots.
- **`tenzro-token`** — add `TrainerCapability` to staking; add `SyncerCapability` for elected syncers.
- **`tenzro-vm`** — add precompile `0x1008` (TRAINING_VERIFY) for fraud-proof verification on-chain. Phase 1 defines the precompile shell; Phase 2 adds full re-aggregation verification.
- **`tenzro-node`** — RPC namespace `tenzro_training_*`: `postTrainingTask`, `enrollTrainer`, `submitOuterGradient`, `getTrainingRun`, `getTrainingReceipt`, `challengeStateRoot`.
- **`tenzro-cli`** — `tenzro train` subcommand: `post`, `enroll`, `status`, `claim-rewards`, `verify-receipt`.
- **`tenzro-agent-kit`** — reference templates: `language-trainer`, `timeseries-trainer`, `vision-trainer` agents that wrap the Python reference trainer and auto-enroll in matching tasks.

#### 7.7.3 Dependencies

- **Rust protocol layer** — only `ndarray` and `safetensors` for parsing tensors at the aggregation step. No tensor library in the Rust workspace.
- **Python reference trainer** — PyTorch (FSDP2 / DTensor / safetensors / torch.compile), Hivemind for inter-worker coordination, plus per-modality libraries: `transformers`, `gluonts`, `timm`.
- **Tensor serialization on the wire** — `safetensors` (no Python pickle, deterministic bytes, TEE-friendly).

#### 7.7.4 Phased Delivery

**Phase 1: Single modality (timeseries)**
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
- Quantized gradients (blockwise INT8 / INT4), streaming synchronization, delayed application, adaptive outer LR, pipeline-parallel trainer groups (see §7.5)
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

#### 7.7.5 Running a trainer node

Operators do not launch trainer subprocesses by hand. A node with training
enabled runs an auto-provisioning daemon that discovers active runs from the
local `tenzro-training` runtime and manages a Python trainer subprocess per
run.

**Enabling.** The daemon is off by default. Turn it on in the node config:

```toml
[training]
enabled = true
```

With only `enabled = true`, the daemon resolves the Python interpreter in
order: `python_executable`, then `<venv_path>/bin/python`, then
`$TENZRO_TRAINING_VENV_PATH/bin/python`, then `python3` / `python` on `PATH` —
and requires the `tenzro_trainer` package to be importable. If no such
interpreter is found, the daemon logs a warning and stays disabled; the node
otherwise runs normally. This is why the base node image contains no Python
trainer runtime (see below) — a validator, RPC provider, or light client never
carries the multi-GB PyTorch dependency unless it opts into training.

**Task discovery.** On each poll tick the daemon lists runs from the runtime
and provisions a trainer for every run in `Enrolling` or `Training` status, up
to `max_concurrent_trainers`. Additional eligible runs wait for a free slot.
There is no manual assignment step.

**Trainer identity.** The trainer's Ed25519 signing key is derived
deterministically from the node's TDIP validator seed via HKDF-SHA256 under a
dedicated domain label, materialised once to `<data_dir>/trainer/trainer.seed`
(mode `0600`), and passed to the trainer as `--seed-file`. The DID is
`did:tenzro:machine:trainer:<node-address>`. Deriving from the node seed means
no second secret to manage and stable reward attribution across restarts. If
the node identity key is unavailable, the trainer falls back to an ephemeral
key (reward attribution is then unstable, but Open-tier training still
proceeds).

**Crash policy.** Trainers are supervised with exponential-backoff restart. A
trainer that exits (crash or non-zero status) is evicted and respawned no
sooner than `backoff_base_ms * 2^(retries-1)`, capped at `backoff_max_ms`.
After `max_restarts` consecutive restarts for the same run, the daemon stops
respawning it until the run's state changes or the node restarts — so a
permanently-broken trainer cannot pin a subprocess slot in a tight loop.

**Config reference (`[training]`):**

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master enable for the daemon. |
| `python_executable` | — | Explicit interpreter path (highest priority). |
| `venv_path` | — | Virtualenv root; daemon uses `<venv_path>/bin/python`. |
| `max_concurrent_trainers` | `1` | Cap on concurrent trainer subprocesses. |
| `poll_interval_secs` | `30` | Seconds between reconcile ticks. |
| `backoff_base_ms` | `2000` | Base restart backoff. |
| `backoff_max_ms` | `300000` | Restart backoff ceiling. |
| `max_restarts` | `8` | Consecutive restarts per run before giving up. |
| `trainer_extra_args` | `[]` | Extra CLI args appended to every trainer invocation. |

**Status.** The JSON-RPC method `tenzro_getTrainerDaemonStatus` reports whether
the daemon is running, the derived `trainer_did`, the live trainer count, and
`max_concurrent_trainers`. When the daemon is disabled it returns
`{ "running": false, "live_trainers": 0 }`.

**Trainer image.** Because the base node image carries no Python trainer, a
separate opt-in image bundles the reference trainer venv on top of the base
node image, built from `Dockerfile.trainer`. The node binary is identical to
the base; the image sets `TENZRO_TRAINING_VENV_PATH` so the daemon resolves the
interpreter with no extra node config beyond `[training] enabled = true`. The
`TRAINER_EXTRAS` build arg selects the pip extras (default:
`language,vision,timeseries,confidential`). Operators who run training pull this
image; everyone else runs the lean base image.

---

### 7.8 Comparison with Existing Approaches

| Approach | Permissionless | Verifiable | Privacy | Multi-modal | Settlement |
|---|---|---|---|---|---|
| Centralized DC training (OpenAI, Anthropic) | No | No | No | Yes | Off-chain |
| Low-communication outer aggregation (single-operator) | No | No | No | Yes (in principle) | N/A |
| Federated learning (FedAvg, etc.) | Partial | No | Partial | Yes | None |
| Incentivized subnet training | Yes | Partial (via consensus) | No | Limited | Subnet token |
| Rented-compute + custom orchestration | Yes | No | No | Yes | Compute token |
| **Tenzro Train** | **Yes** | **Yes (TEE + fraud proofs + receipts)** | **Yes (TEE-resident mode)** | **Yes** | **TNZO, on-chain** |

Tenzro Train's distinctive combination is verifiability + privacy + multi-modal in a single protocol with native on-chain settlement. No existing system covers all four.

---

### 7.9 Open Questions

- **Convergence under adversarial gradient floors.** Byzantine-robust aggregators (especially coordinate median) may slow convergence relative to mean aggregation. Quantifying the cost is required before recommending a default.
- **Optimal F (fragment count).** Higher F means smaller per-fragment transfers but more coordination overhead. The sweet spot is model- and bandwidth-dependent.
- **Syncer state size.** For a 70B model with full optimizer state (Adam: 3× param size), the syncer holds ~840 GB. This argues for sharded syncers (multiple elected nodes each owning a fragment range) for the largest models. Single-syncer suffices for the 1B-class models we expect to train first.
- **Cross-modality fragment-aware scheduling.** A trainer with limited memory may want to participate only in some fragments. The protocol allows this; the economics need to ensure such participation is fairly rewarded.
- **Long-running run resumability.** A training run may take days or weeks. Trainers join and leave continuously. The outer-aggregation design handles this natively via vector clocks; we need to confirm the on-chain commitment cadence doesn't become a cost bottleneck. State roots every N rounds (rather than every round) is the obvious lever.

---

### 7.10 Conclusion

Tenzro Train is a tractable extension of the existing Tenzro Network. The training algorithm (decoupled outer aggregation) is published and proven. The trust primitives (TEE attestation, stake slashing, fraud proofs) already exist in production. The economic rails (TNZO escrow, micropayments, receipt minting) are operational. What's left is the integration work: a new crate, extensions to a handful of existing crates, and reference adapters for the modalities we want to support first.

The protocol is the same whether we're training a 200M timeseries forecaster or a 7B language model. The first product to release should be the timeseries one — smaller models, underserved market, immediate on-chain consumers, strongest privacy story. Language models follow. Vision and multimodal extend naturally from there.

The result is a network where any participant with compute can earn TNZO by training models, any data owner can train on private data without releasing it, and any consumer of the resulting models can verify their full provenance from the ledger. That is a credible alternative to centralized model training, and it fits inside Tenzro Network without rearchitecting anything that already works.

---

### 7.A Reference hyperparameters

For the initial timeseries run (Phase 1):

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
| Gradient compression | `Int8 { block_size: 256 }` blockwise symmetric |
| Sync strategy | `Streaming { num_shards: 4 }` |
| Delayed application | enabled |
| State root commitment | Every 4 rounds |

---

### 7.B Related work

- Das et al., *TimesFM: A decoder-only foundation model for time-series forecasting*, Google, 2024.
- Ansari et al., *Chronos: Learning the Language of Time Series*, Amazon, 2024.
- Woo et al., *Moirai: A Time Series Foundation Model for Universal Forecasting*, Salesforce, 2024.
- Blanchard et al., *Krum: Machine Learning with Adversaries*, NeurIPS 2017.
- Yin et al., *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates*, ICML 2018.
- Costan & Devadas, *Intel SGX Explained*, IACR ePrint 2016/086.
- AMD, *SEV-SNP: Strengthening VM Isolation with Integrity Protection and More*, 2020.

---

## 8. Tenzro Media Gen

Diffusion image and video generation as a network resource. A requester posts a job with a price ceiling; a worker claims it, renders it, publishes the output, and signs a receipt over what it produced. The same TDIP identity, staking bond, reputation, and settlement asset that underwrite inference and training underwrite this too — a media worker is a provider registration with a different capability record.

### 8.1 Rust protocol, Python worker

The split mirrors Tenzro Train:

- **`tenzro-media-gen` (Rust)** — the job queue, the worker registry, the pricing function, the payment split, the three signing preimages, the output-store trait, persistence, and the gossip envelope. No tensor library enters the Rust workspace.
- **`integrations/media_gen/` (Python)** — the denoising loop and nothing else. Pipeline construction, scheduler manipulation, VAE decode, and video muxing over HuggingFace `diffusers`.

The worker never decides what a job is worth, who else is working on it, or whether its own receipt is acceptable. `diffusers` carries a maintained implementation of every pipeline class in the catalog, including the timestep-boundary dispatch that split-expert rendering depends on; reimplementing that in Rust would mean tracking upstream model releases in a second language for no protocol benefit.

### 8.2 Job kinds

`MediaGenKind` has four values, spelled on the wire as `text2image`, `image2image`, `text2video`, `image2video`. The image-conditioned kinds bind the conditioning image's hash into the job id, so the job commits to the exact bytes it was conditioned on. Video kinds carry a frame count and fps; image kinds reject both.

`MediaGenParams` carries the prompt, an optional negative prompt, width, height, step count, guidance scale, optional seed, optional frame count and fps, an optional conditioning-image hash, and an opaque `metadata` map. Admission bounds: `MAX_MEDIA_GEN_DIMENSION = 8192`, `MAX_MEDIA_GEN_STEPS = 500`, `MAX_MEDIA_GEN_FRAMES = 3600`, `MAX_MEDIA_GEN_PROMPT_BYTES = 8192`.

### 8.3 Catalog

Read by workers at enrollment through `tenzro_mediaGen_listCatalog`. Each row names the HuggingFace repo, the `diffusers` pipeline class, the kinds it serves, default and maximum resolutions, default step count and guidance scale, frame count and fps for video, a VRAM floor, and — for split models — the expert pair.

| ID | Repo | Pipeline class | Kinds | Default w×h | Steps | Guidance | Frames / fps | VRAM | Expert pair |
|---|---|---|---|---|---|---|---|---|---|
| `qwen-image` | `Qwen/Qwen-Image` | `QwenImagePipeline` | text2image | 1328 × 1328 | 50 | 4.0 | — | 48 GB | — |
| `qwen-image-flash` | `nvidia/Qwen-Image-Flash` | `QwenImagePipeline` | text2image | 1024 × 1024 | 4 | 1.0 | — | 48 GB | — |
| `qwen-image-edit` | `Qwen/Qwen-Image-Edit-2511` | `QwenImageEditPlusPipeline` | image2image | 1328 × 1328 | 40 | 4.0 | — | 48 GB | — |
| `z-image-turbo` | `Tongyi-MAI/Z-Image-Turbo` | `ZImagePipeline` | text2image | 1024 × 1024 | 9 | 0.0 | — | 16 GB | — |
| `flux2-klein-4b` | `black-forest-labs/FLUX.2-klein-4B` | `Flux2KleinPipeline` | text2image, image2image | 1024 × 1024 | 4 | 1.0 | — | 12 GB | — |
| `wan2.2-t2v-a14b` | `Wan-AI/Wan2.2-T2V-A14B-Diffusers` | `WanPipeline` | text2video | 1280 × 720 | 40 | 4.0 | 81 / 16 | 80 GB | 48 GB each |
| `wan2.2-i2v-a14b` | `Wan-AI/Wan2.2-I2V-A14B-Diffusers` | `WanImageToVideoPipeline` | image2video | 1280 × 720 | 40 | 3.5 | 81 / 16 | 80 GB | 48 GB each |
| `wan2.2-ti2v-5b` | `Wan-AI/Wan2.2-TI2V-5B-Diffusers` | `WanPipeline` | text2video, image2video | 1280 × 704 | 50 | 5.0 | 121 / 24 | 24 GB | — |

Rows with an image-conditioned kind resolve to a sibling pipeline class where the family provides one — `WanPipeline` becomes `WanImageToVideoPipeline` for an `image2video` job against `wan2.2-ti2v-5b`, while a class that already covers image input keeps it.

`qwen-image-flash` is `qwen-image` distilled onto a four-step trajectory with guidance disabled — the same 20.4B transformer and the same VRAM floor, one twelfth of the pixel-steps, so it quotes at one twelfth of the price. It is the one row not under a permissive license: the NVIDIA Open Model License puts it in the `CommercialCustom` tier, and a worker naming it must enroll on a node started with `--accept-license nvidia-open-model`. Every other row is admitted by default. The check runs at `tenzro_mediaGen_enrollWorker` rather than at load, because the node never loads media-gen weights — the Python worker does — so enrollment is the only point at which the protocol sees what an operator is about to serve.

### 8.4 Split-expert rendering

Two distinct model shapes are called mixture-of-experts in the generative-media literature. Only one of them is a distribution primitive.

**Token-routed MoE** — a learned router selects experts per token inside every forward pass. Splitting it across machines means a round trip per layer per token. This is the shape §3 addresses for language models, where the dispatch planner amortizes it; it is not what the media catalog carries.

**Timestep-boundary expert pairs** — two transformers trained for different noise regimes, one for the high-noise prefix of the schedule and one for the low-noise remainder. There is no learned router: a fixed noise threshold decides which expert owns a step. Wan 2.2 A14B is this shape. Exactly one intermediate latent crosses between the two halves, once per job.

That single handoff is what makes it a distribution primitive. One expert needs 48 GB where the whole model needs 80, so two commodity accelerators render what one could not, and the coordination cost is one blob transfer rather than one per layer.

**The boundary is a noise level, not a step index.** A step belongs to the high-noise expert while

```
t >= boundary_ratio × scheduler.config.num_train_timesteps
```

Timesteps descend through the schedule, so that set is always a prefix and one integer index splits it. `boundary_ratio` is a fraction of the scheduler's *training* timestep count — for Wan 2.2 A14B, `0.875` of 1000. A 40-step job and a 100-step job therefore split at the same noise level and at different indices, which is why the protocol records `steps_completed` from the worker rather than assuming a fixed fraction.

**Loading one half.** Both transformer slots are optional in the `diffusers` Wan pipeline, and every internal read falls back to the other slot when one is unset. A worker holding the high-noise expert loads it into `transformer` and leaves `transformer_2` unset; a low-noise holder does the reverse. The low-noise worker resumes the schedule with `scheduler.set_begin_index(boundary_index)`.

**Assignment.** `MediaGenWorkerCapability` carries `supported_models` (models the worker serves whole) and `expert_holdings` (individual halves, for models it cannot). A worker with the VRAM for both halves lists the model in `supported_models`, and claims each half separately anyway — the protocol makes no exception for co-location, which keeps the signed step counts and the payment split identical whether the two halves run on one machine or two.

### 8.5 Pricing and the payment split

The work unit is the pixel-step: `width × height × steps × frames`, with frames defaulting to 1 for image kinds. A quote is `base_fee + per_pixel_step × pixel_steps`, with `DEFAULT_BASE_FEE = 1 × 10¹⁵` attoTNZO and `DEFAULT_PER_PIXEL_STEP = 1 × 10⁹` attoTNZO. A job whose ceiling falls below the quote is rejected at admission rather than claimed and abandoned.

A non-split job pays the single worker `10_000` basis points. A split job pays proportionally to the schedule each half actually rendered:

```
high_bps = steps_completed × 10_000 / total_steps
low_bps  = 10_000 − high_bps
```

`steps_completed` comes from the signed handoff, not from either worker's later claim. Overstating a half would take a forged Ed25519 signature over the handoff preimage.

The money moves when the receipt is accepted, not before: `tenzro_mediaGen_submitReceipt` runs the runtime's validation first, and settles only against a receipt the runtime sealed. The requester is debited `price_paid` and no more — the 5% network commission is carved out of that amount rather than added on top, so the charge matches the price the worker sealed and the requester was quoted against. What remains is divided by the basis points above; integer division leaves at most one attoTNZO per worker unallocated, and that dust goes to the last share so the parts sum to the remainder exactly. The commission reaches the treasury at a derived address, so an operator cannot redirect it.

The full debit is checked before any of it moves, so a requester who cannot cover the job does not pay one expert and strand the other. A transfer that fails after that check leaves the job completed and short-paid rather than unwinding what already moved: the render happened and the receipt is valid, so the shortfall is the requester's to make good. Every leg that could not be paid is written as an unpaid marker for retry and named in the JSON-RPC error (`-32023`). The response carries a `settlement` block — `price_paid`, `commission_wei`, and one payout per assignment — which the CLI prints and the Python worker logs against its own DID.

### 8.6 Commitments

Three SHA-256 preimages under three distinct domain tags:

| Tag | Binds |
|---|---|
| `tenzro/media-gen/job-id` | requester DID and address, model ID, kind, every parameter, price ceiling, creation timestamp |
| `tenzro/media-gen/handoff` | job ID, handing-off worker DID and address, latent hash, latent byte length, `steps_completed`, handoff timestamp |
| `tenzro/media-gen/receipt` | job ID, the executed task spec, worker DID and address, output hash, output MIME, output byte length, seed used, generation time, price paid, completion timestamp |

Distinct tags keep a handoff signature from being replayed as a receipt signature. Encoding rules: integers big-endian at their declared width, `Timestamp` as two's-complement i64 milliseconds, `f32` as the IEEE-754 big-endian bit pattern, variable-length fields prefixed with a big-endian u32 byte count, `Option` as a presence byte then the value. Raw 32-byte hashes embed bare; addresses are length-prefixed. `metadata` is excluded from every preimage — a map has no canonical ordering across encoders, so binding it would make the digest encoder-dependent.

The job id is the digest of its own contents, so a spec carrying someone else's id still hashes to what it actually says. `tenzro_mediaGen_getReceipt` returns the signature alongside the receipt; the Python and Rust implementations recompute the same preimages, and `integrations/media_gen/tests/` pins the field order against the same fixture values the Rust suite uses.

### 8.7 Payload store

Three payload kinds share one content-addressed store: the rendered output, the intermediate latent on a split job, and the requester's conditioning image. All three are addressed by `tenzro://blob/`, fetched over the node's iroh endpoint, and verified on read.

`Hash` is SHA-256 — the canonical Tenzro hash, and what the commitments bind. iroh-blobs indexes by BLAKE3. `tenzro_mediaGen_publishOutput` therefore returns both: `output_hash` for the commitment and `locator` for the fetch. A worker that publishes a latent records the SHA-256 in the handoff it signs; its partner fetches by locator and verifies the SHA-256 before resuming, so iroh-blobs' own BLAKE3 verification and the protocol's hash check are independent.

### 8.8 Lifecycle

```
postJob → claimJob → markRunning → render
                                     ├─ recordHandoff   (high-noise half of a split job)
                                     └─ submitReceipt   (whole job, or low-noise half)
```

`failJob` is terminal: a failed job does not requeue. A worker waiting on a split partner waits a bounded interval and then fails the job explicitly rather than abandoning it. `cancelJob` is the requester's path, valid until a worker has claimed.

Job status is `pending` | `claimed` | `running` | `completed` | `failed` | `cancelled`. Expert role is `high_noise` | `low_noise`.

### 8.9 Surfaces

Eighteen JSON-RPC methods under `tenzro_mediaGen_`:

| Group | Methods |
|---|---|
| Discovery | `listCatalog`, `quote`, `listWorkers` |
| Requester | `postJob`, `listJobs`, `getJob`, `cancelJob`, `getReceipt`, `fetchOutput`, `fetchInput` |
| Worker | `enrollWorker`, `claimJob`, `markRunning`, `failJob`, `publishOutput`, `recordHandoff`, `submitReceipt`, `fetchLatent` |

The same surface is reachable through the CLI (`tenzro media-gen …`), the MCP server, and the A2A `media-gen` skill. Job, worker, and receipt events broadcast on the `tenzro/media-gen` gossip topic.

**OpenAI-compatible endpoint.** `POST /v1/images/generations` (handler: `handle_openai_images_generations`) projects text-to-image onto the OpenAI wire shape so an unmodified OpenAI SDK client reaches the queue. It posts a job through the same `post_job` / `post_split_job` admission the RPC uses — the split decision is read from the catalog, and `job_id` is derived by the runtime from the spec — announces it on `tenzro/media-gen`, polls to a terminal status under a bounded deadline, then fetches the bytes and returns them as `data[0].b64_json` alongside a `tenzro` block carrying the receipt (`output_hash`, `seed_used`, `worker_did`, `generation_time_ms`, `price_paid`). `requester_did` and `requester_address` are required request extensions: the queue binds every job to the identity that posted it, and an HTTP request carries no authenticated Tenzro principal to infer one from. A render that outruns `wait_seconds` (default and cap 300) returns HTTP 504 naming the `job_id` — the work continues and the caller polls `tenzro_mediaGen_getJob` then `tenzro_mediaGen_fetchOutput`. Wire details in [`chat-api.md`](chat-api.md#image-generations).

**Image edits.** `POST /v1/images/edits` (handler: `handle_openai_images_edits`) is the image-to-image route, `multipart/form-data` per the vendor shape. Reference frames arrive under `image`, `image[]` or `images[]`; a `mask` part is accepted for inpainting pipelines. It shares the admission, announcement, terminal-wait and receipt path with generations, so a caller reads the result identically. The kind is fixed by the route — image-to-image whatever the body says — because letting a field override it would reach a pipeline the route was not priced for. Vendor controls the pipelines have no home for (`background`, `output_compression`, `input_fidelity`, `partial_images`, `quality`, `style`) are refused by name with the reason, rather than accepted and quietly ignored: a caller is never billed for a render that dropped an instruction it was given. Wire details in [`chat-api.md`](chat-api.md#image-edits).

**Video renders.** `POST /v1/videos` (handler: `handle_openai_videos_create`) is a job resource rather than a synchronous call, matching the vendor's video surface — a render that takes minutes has no business holding a connection open for them. The POST admits the job and returns it immediately at `status: "queued"`; the caller polls `GET /v1/videos/{video_id}` and collects the clip from `GET /v1/videos/{video_id}/content`. Both GETs stay ungated even when a payment gate governs generation: they are the back half of a render already priced and charged on the POST, and gating them would bill twice for one artifact. An `input_reference` part selects `Image2Video`, its absence `Text2Video` — again, no field names the kind. `seconds` is converted to a frame count against the pipeline's frame rate, since that is what a diffusion schedule is denominated in; a catalog entry declaring neither an fps nor a default frame count cannot yield a frame budget and the request is refused. The job resource maps queue status onto the vendor vocabulary (`Pending` / `Claimed` → `queued`, `Running` → `in_progress`, `Completed` → `completed`, `Failed` / `Cancelled` → `failed`) with a coarse `progress` that reads the split handoff, and carries the receipt fields under `tenzro` once one exists. Asking for the bytes before completion returns HTTP 409 naming the current status: an SDK client writes any 2xx body straight to a file, and a zero-length clip is harder to diagnose than a status code saying what to wait for. Wire details in [`chat-api.md`](chat-api.md#video-renders).

The Python worker's own CLI (`tenzro-media-gen`) covers both sides: `catalog`, `quote`, `post`, `jobs`, `get`, `cancel`, `receipt`, `fetch` for requesters, and `keygen`, `enroll`, `serve`, `workers` for operators. The requester surface installs without torch. See [`integrations/media_gen/README.md`](../integrations/media_gen/README.md).

