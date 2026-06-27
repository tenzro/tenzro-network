//! RFC-0007: Adaptive Execution Upgrade — Runtime types
//!
//! Phase 1 (Metadata Foundation): type annotations, manifest fields, and HTTP API
//! for the Tenzro adaptive execution runtime. No streaming/MoE runtime logic yet.
//!
//! # Backward Compatibility
//!
//! All new fields on existing wire messages use `#[serde(default)]`.
//! Old nodes that do not emit these fields will be treated as
//! `artifact_completeness = FULL_ONLY` with `execution_support.local_full = true`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// High-level classification of a model by architecture and parameter scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelClass {
    #[default]
    SmallDense,
    MidDense,
    LargeDense,
    SmallMoe,
    LargeMoe,
    FrontierMoe,
}

/// How a model session should be executed end-to-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionMode {
    /// Full weights loaded locally, inference executed locally.
    #[default]
    LocalFull,
    /// Full weights loaded on a remote node; client sends prompt, receives response.
    RemoteFull,
    /// Weights streamed to local memory layer-by-layer during inference.
    LocalStreamed,
    /// Remote node uses layer streaming; client receives streamed tokens.
    RemoteStreamed,
    /// MoE router local; expert shards distributed across a local cluster.
    HybridMoeLocal,
    /// MoE router local; expert shards distributed across a regional mesh.
    HybridMoeRegional,
    /// Runtime selects the best mode automatically.
    Auto,
}

/// Which artifact types are present for a model, determining execution modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactCompleteness {
    /// Only full-weight artifacts — supports LOCAL_FULL / REMOTE_FULL only.
    #[default]
    FullOnly,
    /// Full weights + streaming shards — all non-MoE modes supported.
    StreamingReady,
    /// Full weights + expert shards — MoE hybrid modes supported.
    MoeReady,
    /// All artifact types present — any execution mode supported.
    FullyAdaptive,
}

/// Fine-grained type of a single downloadable artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ArtifactType {
    #[default]
    FullWeights,
    StreamingShard,
    ExpertShard,
    KvProfile,
    Tokenizer,
    BackendBundle,
    QuantVariant,
}


/// KV-cache compression profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KVProfile {
    /// Raw FP16/BF16 KV cache.
    #[default]
    KvRaw,
    /// INT8-quantised KV cache.
    KvInt8,
    /// Mixed-precision KV cache (attention heads split).
    KvMixed,
    /// Paged KV cache for variable sequence lengths.
    KvPaged,
}

/// Role a node plays in a distributed inference execution plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerRole {
    /// Runs the full model on a single node.
    #[default]
    FullWorker,
    /// Streams layer shards during inference.
    StreamingWorker,
    /// Hosts expert shards in a MoE configuration.
    ExpertWorker,
    /// Handles prefill phase of prompt processing.
    PrefillWorker,
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Which execution modes a node is capable of serving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSupport {
    /// Node can load full model weights and run inference locally.
    #[serde(default = "default_true")]
    pub local_full: bool,
    /// Node can accept remote inference requests for a full model.
    #[serde(default = "default_true")]
    pub remote_full: bool,
    /// Node can stream model layers for local inference.
    #[serde(default)]
    pub local_streamed: bool,
    /// Node can serve remote inference with layer streaming.
    #[serde(default)]
    pub remote_streamed: bool,
    /// Node can participate as local MoE expert coordinator.
    #[serde(default)]
    pub hybrid_moe_local: bool,
    /// Node can participate in regional MoE mesh.
    #[serde(default)]
    pub hybrid_moe_regional: bool,
}

impl Default for ExecutionSupport {
    fn default() -> Self {
        Self {
            local_full: true,
            remote_full: true,
            local_streamed: false,
            remote_streamed: false,
            hybrid_moe_local: false,
            hybrid_moe_regional: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Internal topology metadata for MoE and large-scale models.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelTopology {
    /// Total number of experts (for MoE models).
    #[serde(default)]
    pub num_experts: u32,
    /// Number of experts activated per token.
    #[serde(default)]
    pub active_experts: u32,
    /// Total number of transformer layers.
    #[serde(default)]
    pub num_layers: u32,
    /// Hidden dimension size.
    #[serde(default)]
    pub hidden_dim: u32,
    /// Number of attention heads.
    #[serde(default)]
    pub attention_heads: u32,
}

/// Hardware and network constraints for scheduling inference.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlacementConstraints {
    /// Minimum VRAM required (GB).
    #[serde(default)]
    pub min_vram_gb: u32,
    /// Minimum system RAM required (GB).
    #[serde(default)]
    pub min_ram_gb: u32,
    /// Must be scheduled on a GPU-enabled node.
    #[serde(default)]
    pub requires_gpu: bool,
    /// Must be scheduled on a TEE-enabled node.
    #[serde(default)]
    pub requires_tee: bool,
    /// Preferred geographic regions (e.g. "us-central1").
    #[serde(default)]
    pub preferred_regions: Vec<String>,
}

/// Routing preferences for inference request dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// Prefer local execution if a capable node is available.
    #[serde(default = "default_true")]
    pub prefer_local: bool,
    /// Maximum allowed hop count for distributed inference.
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    /// Only route to attestation-verified providers.
    #[serde(default)]
    pub require_attestation: bool,
    /// Fall back to remote execution if local is unavailable.
    #[serde(default = "default_true")]
    pub fallback_to_remote: bool,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            prefer_local: true,
            max_hops: 3,
            require_attestation: false,
            fallback_to_remote: true,
        }
    }
}

fn default_max_hops() -> u32 {
    3
}

/// Client-specified execution requirements for an inference session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredExecution {
    /// Minimum acceptable execution mode.
    #[serde(default)]
    pub min_mode: ExecutionMode,
    /// Preferred execution mode.
    #[serde(default)]
    pub preferred_mode: ExecutionMode,
    /// Whether the node may fall back to a less capable mode.
    #[serde(default = "default_true")]
    pub allow_fallback: bool,
}

/// Runtime capabilities declared by a provider node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeSupport {
    /// Execution modes this node can serve.
    #[serde(default)]
    pub supported_modes: Vec<ExecutionMode>,
    /// Inference backend identifiers (e.g. "llama.cpp", "vllm", "ggml").
    #[serde(default)]
    pub supported_backends: Vec<String>,
    /// Maximum supported context length in tokens.
    #[serde(default)]
    pub max_context_len: u32,
    /// Maximum request batch size.
    #[serde(default)]
    pub max_batch_size: u32,
    /// Whether this node has a verified TEE enclave.
    #[serde(default)]
    pub tee_capable: bool,
}

/// TEE trust provenance for a provider or inference session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustProfile {
    /// TEE vendor identifier (e.g. "intel-tdx", "amd-sev-snp", "aws-nitro").
    #[serde(default)]
    pub tee_vendor: String,
    /// Attestation verification level (e.g. "none", "simulated", "hardware").
    #[serde(default)]
    pub attestation_level: String,
    /// Whether the attestation has been cryptographically verified.
    #[serde(default)]
    pub verified: bool,
}

/// Network topology metadata for a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeNetworkProfile {
    /// Cloud region or datacenter identifier.
    #[serde(default)]
    pub region: String,
    /// Available upstream bandwidth in Mbps.
    #[serde(default)]
    pub bandwidth_mbps: u32,
    /// Median latency to known peers in milliseconds.
    #[serde(default)]
    pub latency_ms_to_peers: u32,
    /// Sustained connectivity tier this node has *earned* through observed
    /// reachability, not a self-asserted flag: `direct` (a public address has
    /// held across repeated confirmation), `relay_only` (reachable solely via
    /// a circuit relay — usable but latency-added and resource-limited), or
    /// `unreachable`. Empty string means the announcing node did not report a
    /// tier; consumers should treat that as the weakest tier for routing.
    /// Request routers prefer `direct` providers and treat `relay_only` as a
    /// fallback.
    #[serde(default)]
    pub reachability: String,
}

/// LAN-cluster serving profile for a provider node.
///
/// Carries exactly the facts a head needs to admit this node as a pipeline
/// member that the rest of the announcement does not already supply: the
/// llama.cpp build commit (the ggml RPC wire protocol has no version
/// negotiation, so every member must match) and the serving device's
/// backend and capability key. The head reaches the member's loopback
/// `rpc-server` over the authenticated libp2p cluster tunnel keyed by the
/// announcement's `peer_id`, so no serving socket is advertised. A node only
/// emits this when it is willing to join LAN clusters; absence means
/// "single-box serving only" and the node will not be auto-clustered.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterProfile {
    /// llama.cpp build commit this node links against. Members must match.
    #[serde(default)]
    pub llama_commit: String,
    /// Backend the serving device runs on (`cuda`, `metal`, `vulkan`,
    /// `rocm`, `cpu`, …) — lower-case ggml family name.
    #[serde(default)]
    pub backend: String,
    /// Capability key of the serving device (CUDA compute capability, AMD
    /// gfx target, Apple chip family, or CPU arch when serving on CPU).
    #[serde(default)]
    pub cap_key: String,
}

/// Descriptor for a single downloadable model artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Unique artifact identifier.
    #[serde(default)]
    pub artifact_id: String,
    /// Type of this artifact.
    #[serde(default)]
    pub artifact_type: ArtifactType,
    /// Size in bytes.
    #[serde(default)]
    pub size_bytes: u64,
    /// SHA-256 hex digest of the artifact file.
    #[serde(default)]
    pub sha256: String,
    /// Download URL (HTTPS or ipfs://).
    #[serde(default)]
    pub url: String,
    /// Completeness classification of the full artifact set.
    #[serde(default)]
    pub completeness: ArtifactCompleteness,
}

// ---------------------------------------------------------------------------
// Capability resolver types
// ---------------------------------------------------------------------------

/// A resolved execution plan for a model inference session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Unique plan identifier.
    pub plan_id: String,
    /// Model being executed.
    pub model_id: String,
    /// Provider peer ID selected for this plan.
    pub provider_id: String,
    /// Selected execution mode.
    pub execution_mode: ExecutionMode,
    /// Estimated end-to-end latency in milliseconds.
    #[serde(default)]
    pub estimated_latency_ms: u32,
    /// KV-cache profile to use.
    #[serde(default)]
    pub kv_profile: KVProfile,
    /// Placement constraints applied.
    #[serde(default)]
    pub constraints: PlacementConstraints,
    /// Trust profile of the selected provider.
    #[serde(default)]
    pub trust_profile: TrustProfile,
}

/// Receipt emitted after a completed inference session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Session or request identifier this receipt covers.
    pub session_id: String,
    /// Model that was executed.
    pub model_id: String,
    /// Provider that served the request.
    pub provider_id: String,
    /// Execution mode actually used.
    pub mode: ExecutionMode,
    /// Number of prompt tokens processed.
    #[serde(default)]
    pub prompt_tokens: u32,
    /// Number of completion tokens generated.
    #[serde(default)]
    pub completion_tokens: u32,
    /// Number of expert activations (MoE only).
    #[serde(default)]
    pub expert_calls: u32,
    /// Number of layer shard loads (streaming only).
    #[serde(default)]
    pub streamed_layer_loads: u32,
    /// KV-cache profile identifier used.
    #[serde(default)]
    pub kv_profile_id: String,
    /// KV-cache memory resident duration in milliseconds.
    #[serde(default)]
    pub kv_memory_ms: u64,
    /// Whether the session ran in an attested TEE.
    #[serde(default)]
    pub attested: bool,
    /// Reference to the attestation report (if attested).
    #[serde(default)]
    pub attestation_ref: String,
    /// SHA-256 of the raw output bytes.
    #[serde(default)]
    pub output_hash: String,
    /// Unix timestamp (ms) when receipt was created.
    pub created_unix_ms: i64,
}

/// Result of capability resolution for a model + client requirements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityResolution {
    /// Model being resolved.
    pub model_id: String,
    /// Selected provider peer ID.
    pub resolved_provider: String,
    /// The execution plan chosen.
    pub execution_plan: ExecutionPlan,
    /// Alternative plans (sorted by estimated latency).
    #[serde(default)]
    pub alternatives: Vec<ExecutionPlan>,
}
