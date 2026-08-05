//! Model runtime for loading and running GGUF models with llama.cpp.
//!
//! Uses `llama-cpp-2` crate (safe Rust bindings to llama.cpp) for inference.
//! Adapts to whatever hardware is available on the provider's machine:
//!
//! - **Metal** — Apple Silicon GPU (auto-linked on macOS ARM64, no feature flag needed)
//! - **CUDA** — NVIDIA GPUs: datacenter (A100/H100/B200) and consumer (RTX 3090/4090)
//! - **ROCm** — AMD GPUs: datacenter (MI300X) and consumer (RX 7900 XTX)
//! - **Vulkan** — cross-platform GPU (NVIDIA, AMD, Intel Arc, ARM Mali/Adreno)
//! - **CPU** — always available as fallback (with OpenMP parallelization)
//!
//! Compile with the appropriate feature flag for your hardware:
//! ```sh
//! cargo build --features cuda    # NVIDIA
//! cargo build --features rocm    # AMD
//! cargo build --features vulkan  # Universal GPU (Intel/AMD/NVIDIA/ARM)
//! cargo build                    # CPU + Metal (auto on macOS ARM64)
//! ```
//!
//! llama.cpp auto-detects model architecture from GGUF metadata
//! (Llama, Qwen, Gemma, Mistral, Phi, etc.).

use std::num::NonZeroU32;
use std::path::Path;
#[cfg(feature = "mtmd")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Global singleton for the llama.cpp backend — can only be initialized once per process.
static LLAMA_BACKEND: OnceLock<Arc<LlamaBackend>> = OnceLock::new();

use crate::batching::{BatchEngine, BatchPrompt, BatchRequest};
use crate::catalog::{MtpKind, get_model_by_id};
use crate::error::{ModelError, Result};
use crate::external_engine::ExternalEngine;

use llama_cpp_2::context::LlamaContext;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::{LlamaModelParams, LlamaSplitMode};
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
#[cfg(feature = "mtmd")]
use llama_cpp_2::mtmd::{
    MtmdBitmap, MtmdContext, MtmdContextParams, MtmdInputText, mtmd_default_marker,
};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::speculative::{MtpSpeculative, MtpSpeculativeParams};
use llama_cpp_2::token::LlamaToken;

/// Hardware backend information detected at runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    /// Which compute backends were compiled in
    pub compiled_backends: Vec<String>,
    /// Whether GPU offload is available at runtime
    pub gpu_offload: bool,
    /// CPU architecture (x86_64, aarch64, etc.)
    pub cpu_arch: String,
    /// Operating system
    pub os: String,
    /// Active backend description
    pub active_backend: String,
}

impl HardwareInfo {
    /// Detect which backends were compiled in and what's available at runtime
    fn detect(gpu_offload: bool) -> Self {
        let mut compiled_backends = Vec::new();

        // CPU is always available
        compiled_backends.push("cpu".to_string());

        // Check compile-time feature flags
        if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            compiled_backends.push("metal".to_string());
        }
        if cfg!(feature = "cuda") {
            compiled_backends.push("cuda".to_string());
        }
        if cfg!(feature = "cuda-no-vmm") {
            compiled_backends.push("cuda-no-vmm".to_string());
        }
        if cfg!(feature = "rocm") {
            compiled_backends.push("rocm".to_string());
        }
        if cfg!(feature = "vulkan") {
            compiled_backends.push("vulkan".to_string());
        }
        if cfg!(feature = "metal") {
            // Explicit metal feature (in addition to auto-link)
            if !compiled_backends.contains(&"metal".to_string()) {
                compiled_backends.push("metal".to_string());
            }
        }
        if cfg!(feature = "sycl") {
            compiled_backends.push("sycl".to_string());
        }
        if cfg!(feature = "openvino") {
            compiled_backends.push("openvino".to_string());
        }
        if cfg!(feature = "opencl") {
            compiled_backends.push("opencl".to_string());
        }
        if cfg!(feature = "musa") {
            compiled_backends.push("musa".to_string());
        }
        if cfg!(feature = "cann") {
            compiled_backends.push("cann".to_string());
        }
        if cfg!(feature = "webgpu") {
            compiled_backends.push("webgpu".to_string());
        }
        if cfg!(feature = "blas") {
            compiled_backends.push("blas".to_string());
        }
        if cfg!(feature = "zdnn") {
            compiled_backends.push("zdnn".to_string());
        }

        // Determine what's actually active. GPU/NPU backends are checked
        // ahead of CPU-acceleration backends (blas / openvino-CPU / zdnn),
        // which apply whether or not GPU offload was requested.
        let active_backend = if gpu_offload {
            if cfg!(feature = "cuda") || cfg!(feature = "cuda-no-vmm") {
                "CUDA (NVIDIA GPU)".to_string()
            } else if cfg!(feature = "rocm") {
                "ROCm (AMD GPU)".to_string()
            } else if cfg!(feature = "sycl") {
                "SYCL (Intel GPU)".to_string()
            } else if cfg!(feature = "musa") {
                "MUSA (Moore Threads GPU)".to_string()
            } else if cfg!(feature = "cann") {
                "CANN (Huawei Ascend NPU)".to_string()
            } else if cfg!(feature = "openvino") {
                // Device (CPU / GPU / NPU) is picked at runtime via GGML_OPENVINO_DEVICE.
                format!(
                    "OpenVINO (Intel {})",
                    std::env::var("GGML_OPENVINO_DEVICE").unwrap_or_else(|_| "CPU".to_string())
                )
            } else if cfg!(feature = "opencl") {
                "OpenCL (GPU)".to_string()
            } else if cfg!(feature = "vulkan") {
                "Vulkan (GPU)".to_string()
            } else if cfg!(feature = "webgpu") {
                "WebGPU (GPU)".to_string()
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "Metal (Apple GPU)".to_string()
            } else {
                "GPU (unknown backend)".to_string()
            }
        } else if cfg!(feature = "openvino") {
            format!(
                "OpenVINO (Intel {})",
                std::env::var("GGML_OPENVINO_DEVICE").unwrap_or_else(|_| "CPU".to_string())
            )
        } else if cfg!(feature = "zdnn") {
            "zDNN (IBM Z Telum accelerator)".to_string()
        } else if cfg!(feature = "blas") {
            "CPU + BLAS".to_string()
        } else {
            "CPU".to_string()
        };

        Self {
            compiled_backends,
            gpu_offload,
            cpu_arch: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            active_backend,
        }
    }
}

/// Configuration for text generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationConfig {
    pub temperature: f64,
    pub top_p: f64,
    pub max_tokens: u32,
    pub repeat_penalty: f32,
    pub repeat_last_n: usize,
    pub seed: u64,
    /// Top-k truncation. `None` leaves the candidate set untruncated by rank,
    /// which is what the nucleus (`top_p`) stage alone does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Minimum-probability floor relative to the most likely token. `None`
    /// disables the stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_p: Option<f64>,
    /// Per-occurrence logit penalty. `0.0` disables it.
    #[serde(default)]
    pub frequency_penalty: f32,
    /// Flat logit penalty for any token already present. `0.0` disables it.
    #[serde(default)]
    pub presence_penalty: f32,
    /// Stop sequences. Generation halts as soon as the decoded text ends with
    /// one of these, and the matched suffix is trimmed from the returned text
    /// so the caller never sees the delimiter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// Optional speculative-decoding draft count (1..=6). When `Some(n)`,
    /// the runtime is asked to use the target model's paired drafter
    /// (`HfModelEntry.drafter_id` + `mtp_kind`) and propose `n` tokens
    /// per verification round (llama.cpp `--spec-draft-n-max`). When
    /// `None`, the runtime falls back to single-token autoregressive
    /// sampling. The drafter must be loaded alongside the target;
    /// otherwise the runtime returns `ModelError::MtpUnavailable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_n: Option<u8>,
    /// Optional TOPLOC commitment width (1..=64). When `Some(k)`, the
    /// autoregressive path records the top-k raw logits for every
    /// generated token and returns the commitment blob on
    /// [`InferenceResult::commitment`]. Only the single-token sampling
    /// path produces commitments — speculative decoding, external
    /// engines, and the batch engine leave it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_k: Option<u8>,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.9,
            max_tokens: 512,
            repeat_penalty: 1.1,
            repeat_last_n: 64,
            seed: 42,
            top_k: None,
            min_p: None,
            frequency_penalty: 0.0,
            presence_penalty: 0.0,
            stop: Vec::new(),
            draft_n: None,
            commitment_k: None,
        }
    }
}

/// Assemble the llama.cpp sampler chain for a request.
///
/// Stage order mirrors llama.cpp's own default (penalties before truncation,
/// truncation before the distribution draw). The optional `top_k` and `min_p`
/// stages are omitted entirely when unset rather than passed a neutral value,
/// so a request that does not ask for them samples exactly as it did before
/// those knobs existed.
fn build_sampler_chain(config: &GenerationConfig) -> LlamaSampler {
    build_sampler_chain_with_grammar(config, None)
}

/// [`build_sampler_chain`] with an optional grammar stage in front.
///
/// The grammar goes first so it masks the tokens that would spell a malformed
/// tool call before any truncation or temperature stage sees the
/// distribution — constraining after a truncation stage has already discarded
/// candidates can leave nothing legal to draw from.
///
/// `None` reproduces [`build_sampler_chain`] exactly, which is what every
/// non-tool path passes.
fn build_sampler_chain_with_grammar(
    config: &GenerationConfig,
    grammar: Option<LlamaSampler>,
) -> LlamaSampler {
    let mut stages = Vec::new();
    if let Some(g) = grammar {
        stages.push(g);
    }
    stages.push(LlamaSampler::penalties(
        config.repeat_last_n as i32,
        config.repeat_penalty,
        config.frequency_penalty,
        config.presence_penalty,
    ));
    if let Some(k) = config.top_k {
        stages.push(LlamaSampler::top_k(k as i32));
    }
    stages.push(LlamaSampler::temp(config.temperature as f32));
    stages.push(LlamaSampler::top_p(config.top_p as f32, 1));
    if let Some(p) = config.min_p {
        stages.push(LlamaSampler::min_p(p as f32, 1));
    }
    stages.push(LlamaSampler::dist(config.seed as u32));
    LlamaSampler::chain_simple(stages)
}

/// Byte length of the longest stop sequence that `text` ends with, or `None`
/// when no stop sequence matched. The caller truncates by that many bytes so
/// the delimiter never reaches the client.
fn matched_stop_len(text: &str, stop: &[String]) -> Option<usize> {
    stop.iter()
        .filter(|s| !s.is_empty() && text.ends_with(s.as_str()))
        .map(|s| s.len())
        .max()
}

/// Accumulates decoded token pieces, detects stop sequences, and — when the
/// caller is streaming — releases bytes only once they can no longer turn out
/// to be the leading part of a stop sequence.
///
/// A stop sequence may span several tokens, so the last `hold` bytes are kept
/// back until either more text disambiguates them or generation ends. With no
/// stop sequences configured `hold` is zero and every piece is released the
/// moment it is decoded.
pub(crate) struct StopStream {
    text: String,
    emitted: usize,
    hold: usize,
    stop: Vec<String>,
    hit: bool,
}

impl StopStream {
    pub(crate) fn new(stop: Vec<String>) -> Self {
        let hold = stop
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        Self {
            text: String::new(),
            emitted: 0,
            hold,
            stop,
            hit: false,
        }
    }

    /// Absorb one decoded piece. Returns `false` when the stream receiver has
    /// been dropped, which the generation loops treat as "stop generating".
    pub(crate) fn push(
        &mut self,
        piece: &str,
        tx: Option<&tokio::sync::mpsc::Sender<String>>,
    ) -> bool {
        self.text.push_str(piece);
        if let Some(n) = matched_stop_len(&self.text, &self.stop) {
            self.text.truncate(self.text.len() - n);
            self.emitted = self.emitted.min(self.text.len());
            self.hit = true;
        }
        self.release(tx)
    }

    fn release(&mut self, tx: Option<&tokio::sync::mpsc::Sender<String>>) -> bool {
        let Some(tx) = tx else { return true };
        let mut boundary = if self.hit {
            self.text.len()
        } else {
            self.text.len().saturating_sub(self.hold)
        };
        while boundary > self.emitted && !self.text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        if boundary <= self.emitted {
            return true;
        }
        let chunk = self.text[self.emitted..boundary].to_string();
        self.emitted = boundary;
        tx.blocking_send(chunk).is_ok()
    }

    pub(crate) fn hit_stop(&self) -> bool {
        self.hit
    }

    /// Release anything still held back and hand over the accumulated text.
    pub(crate) fn finish(mut self, tx: Option<&tokio::sync::mpsc::Sender<String>>) -> String {
        self.hit = true;
        self.release(tx);
        self.text
    }
}

/// Why generation stopped, as the engine observed it.
///
/// A configured stop sequence is trimmed out of the returned text, so a caller
/// inspecting only [`InferenceResult::text`] cannot tell `StopSequence` from
/// `Eos`. This field is how that distinction reaches the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The model emitted an end-of-generation token.
    Eos,
    /// The token budget in [`GenerationConfig::max_tokens`] was exhausted.
    Length,
    /// Decoded text ended with one of [`GenerationConfig::stop`].
    StopSequence,
}

impl StopReason {
    /// Termination cause for a loop that ran to completion: a stop sequence
    /// wins over an exhausted budget, since the sequence is what halted
    /// decoding.
    fn from_loop(hit_stop: bool, output_tokens: u32, max_tokens: u32) -> Self {
        if hit_stop {
            Self::StopSequence
        } else if output_tokens >= max_tokens {
            Self::Length
        } else {
            Self::Eos
        }
    }

    /// Wire spelling, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eos => "eos",
            Self::Length => "length",
            Self::StopSequence => "stop_sequence",
        }
    }
}

/// Result from running inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    pub text: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub generation_time_ms: u64,
    pub tokens_per_second: f64,
    /// Engine-observed termination cause, reported beside the token counts
    /// because the text alone cannot distinguish a trimmed stop sequence from
    /// an end-of-generation token.
    pub stop_reason: StopReason,
    /// TOPLOC commitment blob, present when the request set
    /// [`GenerationConfig::commitment_k`] and the single-token
    /// autoregressive path served it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<crate::toploc::InferenceCommitment>,
}

/// A chat message with role and content (for chat template formatting)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Tool definition passed into [`ModelRuntime::generate_chat_with_tools`].
///
/// Mirrors the rich-shape `ToolSchema` used at the RPC layer but stays
/// in the inference crate to avoid pulling RPC types into runtime code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input. Must be a JSON object.
    pub input_schema: serde_json::Value,
}

/// A tool invocation extracted from model output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCall {
    /// Caller-assigned (or model-emitted) call id; we synthesize one if the
    /// model didn't supply it.
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// Result of a tool-aware chat generation. Carries the same per-token
/// stats as [`InferenceResult`] plus extracted tool calls and the
/// stop reason inferred from the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatWithToolsResult {
    /// Free-text portion of the model's reply (with tool-call markers
    /// stripped).
    pub text: String,
    /// Tool calls extracted from the raw output, in emission order.
    pub tool_calls: Vec<ToolCall>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub generation_time_ms: u64,
    pub tokens_per_second: f64,
    /// Why generation stopped: `"end_turn"`, `"tool_use"`, `"max_tokens"`,
    /// `"stop_sequence"`. Mirrors the spec's `stop_reason` enum.
    pub stop_reason: String,
    /// TOPLOC top-k logit commitment, when the caller requested one via
    /// [`GenerationConfig::commitment_k`] and the single-token serial
    /// path served the request. `None` for external engines, the batch
    /// engine, and speculative decoding.
    pub commitment: Option<crate::toploc::InferenceCommitment>,
}

/// The literal that marks where an attachment binds in a multimodal prompt.
///
/// A caller that assembles its own prompt writes one of these per attachment,
/// in the position the attachment belongs, and mtmd substitutes the encoded
/// embeddings there. Callers that place none get one per attachment prepended
/// to the last user turn.
///
/// Built without the `mtmd` feature the value is unused — multimodal requests
/// are refused before a prompt is assembled — but the literal has to exist for
/// prompt-rendering code to compile unconditionally.
pub fn media_marker() -> &'static str {
    #[cfg(feature = "mtmd")]
    {
        mtmd_default_marker()
    }
    #[cfg(not(feature = "mtmd"))]
    {
        "<__media__>"
    }
}

/// Maximum context length we allow to prevent OOM on consumer hardware.
const MAX_CONTEXT_LENGTH: u32 = 131_072;

/// Default context length used when no catalog entry is available.
const DEFAULT_CONTEXT_LENGTH: u32 = 8192;

use crate::memory_budget::{LOAD_HEADROOM_DEN, LOAD_HEADROOM_NUM};

/// Maximum number of concurrent requests (in flight + waiting) permitted per
/// loaded model. llama.cpp serializes decode on a single model context, so
/// requests queue behind the one holding the lock. Past this bound we shed
/// load with `ModelError::QueueFull` rather than letting the queue grow
/// unbounded and time every caller out under a thundering herd.
const MAX_INFLIGHT_PER_MODEL: usize = 64;

/// Node bound on a model's warm-prefix radix tree. Once a model's advertised
/// [`tenzro_types::PrefixCacheSummary`] reaches this many nodes the tree is
/// reset to the latest prompt's path, so the summary tracks recent traffic
/// and the announcement stays compact instead of accreting stale prefixes.
const MAX_WARM_PREFIX_NODES: usize = 256;

/// Internal representation of a loaded model
struct LoadedModel {
    /// Multimodal projector for a model whose catalog entry declares an
    /// `mmproj` — Gemma 4's SigLIP tower, Kimi K3's MoonViT-3d. `None` for a
    /// text-only model, and for a multimodal one whose projector file has not
    /// been downloaded, which serves text-only.
    ///
    /// Declared ahead of `model` so it is dropped first: the mtmd context
    /// holds a raw `llama_model *` into the text model and must be torn down
    /// before the model it points at.
    #[cfg(feature = "mtmd")]
    projector: Option<MtmdContext>,
    model: LlamaModel,
    backend: Arc<LlamaBackend>,
    /// Configured context length from catalog (capped at MAX_CONTEXT_LENGTH)
    context_length: u32,
}

// SAFETY: LlamaModel is Send + Sync per llama-cpp-2 docs.
// LlamaBackend is Send + Sync.
unsafe impl Send for LoadedModel {}
unsafe impl Sync for LoadedModel {}

/// How a loaded model serves requests.
///
/// A plain text GGUF is served through a continuous-batching [`BatchEngine`]
/// that owns the `LlamaModel` on a dedicated scheduler thread and interleaves
/// every in-flight sequence into one decode per step — the throughput path. A
/// model that carries a Multi-Token-Prediction drafter, a multimodal
/// projector, or one split across a LAN pipeline cluster, is served through
/// the serial single-context path (`Serial`): speculative decoding runs two
/// contexts that can't share the batch scheduler, mtmd owns its own prefill
/// sequence per request, and a clustered pipeline threads boundary activations
/// across devices per request. The variant is chosen once at load time from
/// the catalog's `mtp_kind` and `mmproj` (and the clustered entry point) and
/// never changes.
enum LoadedEntry {
    Batched(BatchEngine),
    Serial(Arc<tokio::sync::Mutex<LoadedModel>>),
}

/// A loaded Multi-Token-Prediction drafter, keyed under the target's
/// `model_id` (not the drafter's own id). The drafter is a same-
/// architecture sidecar GGUF (e.g.
/// `unsloth/gemma-4-12b-it-GGUF/MTP/mtp-gemma-4-12B-it.gguf`) loaded
/// once per target and reused across every speculative generation
/// against that target. Held in a separate map so the existing
/// `load_model` / `unload_model` API surface for targets stays the
/// same; drafters are loaded by [`ModelRuntime::load_drafter`].
struct LoadedDrafter {
    model: LlamaModel,
    /// Echo of [`LoadedModel::backend`] so we can construct a draft
    /// context without re-resolving the backend.
    backend: Arc<LlamaBackend>,
    /// Context length to use for the draft model's context. Same
    /// catalog-aware cap as the target.
    context_length: u32,
}

unsafe impl Send for LoadedDrafter {}
unsafe impl Sync for LoadedDrafter {}

/// Model runtime -- loads and runs GGUF models for inference via llama.cpp.
///
/// Adapts to the provider's hardware automatically. The GPU/NPU backend is
/// selected at compile time via a cargo feature; the CPU path is always
/// available as fallback:
/// - Metal GPU on macOS ARM64 (auto-detected)
/// - CUDA on NVIDIA GPUs (`--features cuda`, or `cuda-no-vmm` for older drivers)
/// - ROCm/HIP on AMD GPUs (`--features rocm`)
/// - SYCL on Intel GPUs (`--features sycl`, needs the oneAPI DPC++ toolchain)
/// - OpenVINO on Intel CPU/GPU/NPU (`--features openvino`; device picked at
///   runtime via the `GGML_OPENVINO_DEVICE` env var — `CPU` / `GPU` / `NPU`)
/// - Vulkan on any cross-vendor GPU (`--features vulkan`)
/// - OpenCL on Adreno / Mali (`--features opencl`)
/// - MUSA on Moore Threads GPUs (`--features musa`)
/// - CANN on Huawei Ascend NPUs (`--features cann`)
/// - WebGPU via Dawn (`--features webgpu`)
/// - zDNN on IBM Z Telum (`--features zdnn`)
/// - BLAS CPU acceleration (`--features blas`)
/// - CPU fallback (always available)
pub struct ModelRuntime {
    loaded_models: Arc<DashMap<String, Arc<LoadedEntry>>>,
    /// Per-target Multi-Token-Prediction drafter. Key is the TARGET's
    /// `model_id` (not the drafter's). When a target is paired with a
    /// drafter in the catalog (`HfModelEntry.drafter_id` +
    /// `mtp_kind: DraftMtp`), call [`Self::load_drafter`] alongside
    /// [`Self::load_model`] to make speculative decoding available
    /// for that target.
    loaded_drafters: Arc<DashMap<String, Arc<tokio::sync::Mutex<LoadedDrafter>>>>,
    /// Models served through an external OpenAI-compatible engine (vLLM /
    /// SGLang / llama-server) instead of the in-process llama.cpp runtime.
    /// Keyed by our catalog `model_id`. When a model is registered here,
    /// generate/chat requests route to the external endpoint; the model is
    /// never loaded into a local context. External engines and local
    /// `loaded_models` are mutually exclusive per `model_id`.
    external_engines: Arc<DashMap<String, ExternalEngine>>,
    /// Per-model count of requests currently in flight or waiting on the
    /// model mutex. Gates admission at [`MAX_INFLIGHT_PER_MODEL`] so an
    /// overloaded model sheds load instead of queueing unboundedly.
    inflight: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Radix-tree summary of the prompt prefixes each loaded model currently
    /// holds warm in its KV cache, built from recently-served prompts. The
    /// node projects this onto the provider announcement's
    /// [`tenzro_types::PrefixCacheSummary`] so prefix-affinity routing can
    /// prefer this provider for a matching prompt. Keyed by `model_id`.
    warm_prefixes: Arc<DashMap<String, tenzro_types::PrefixCacheSummary>>,
    /// Model ids whose multimodal projector loaded, so they accept image or
    /// audio attachments. Held beside `loaded_models` rather than read out of
    /// `LoadedModel` so [`Self::supports_media`] is a lock-free probe — a
    /// discovery call must not queue behind an in-flight generation holding the
    /// model mutex.
    media_capable: Arc<dashmap::DashSet<String>>,
    backend: Arc<LlamaBackend>,
    hardware: HardwareInfo,
}

/// RAII guard that decrements a model's in-flight counter on drop, so the
/// slot is released whether generation succeeds, errors, or the task is
/// cancelled (client disconnect).
struct InflightGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for ModelRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRuntime {
    pub fn new() -> Self {
        let backend = LLAMA_BACKEND
            .get_or_init(|| {
                let b = LlamaBackend::init().expect("Failed to initialize llama.cpp backend");
                Arc::new(b)
            })
            .clone();

        let has_gpu = backend.supports_gpu_offload();
        let hardware = HardwareInfo::detect(has_gpu);

        info!(
            "llama.cpp backend initialized — {} on {}/{} (compiled backends: {})",
            hardware.active_backend,
            hardware.os,
            hardware.cpu_arch,
            hardware.compiled_backends.join(", "),
        );

        Self {
            loaded_models: Arc::new(DashMap::new()),
            loaded_drafters: Arc::new(DashMap::new()),
            external_engines: Arc::new(DashMap::new()),
            inflight: Arc::new(DashMap::new()),
            warm_prefixes: Arc::new(DashMap::new()),
            media_capable: Arc::new(dashmap::DashSet::new()),
            backend,
            hardware,
        }
    }

    /// Record that `model_id` just served `prompt`, folding its prefix runs
    /// into the model's warm-prefix radix tree. The KV cache holds the most
    /// recent prompts warm; this records the shared prefix so the node can
    /// advertise it. Bounded per model by [`MAX_WARM_PREFIX_NODES`]: once the
    /// tree reaches the bound it is reset to just this prompt's path, so the
    /// summary tracks recent traffic rather than growing without limit.
    pub fn record_warm_prompt(&self, model_id: &str, prompt: &[u8]) {
        let mut entry = self.warm_prefixes.entry(model_id.to_string()).or_default();
        if entry.nodes.len() >= MAX_WARM_PREFIX_NODES {
            *entry.value_mut() = tenzro_types::PrefixCacheSummary::from_warm_prompt(prompt);
        } else {
            entry.insert_warm_prompt(prompt);
        }
    }

    /// Current warm-prefix summary for `model_id`, or an empty summary when
    /// the model has served nothing yet. The node reads this each heartbeat
    /// to refresh the advertised [`tenzro_types::PrefixCacheSummary`].
    pub fn warm_prefix_summary(&self, model_id: &str) -> tenzro_types::PrefixCacheSummary {
        self.warm_prefixes
            .get(model_id)
            .map(|e| e.value().clone())
            .unwrap_or_default()
    }

    /// Merge every loaded model's warm-prefix summary into one, so a single
    /// provider entry (which serves under one address across its models) can
    /// advertise the union of prefixes it holds warm. Each model's tree is
    /// concatenated with its `parent` indices remapped into the merged index
    /// space, so the combined tree stays a valid multi-root radix forest that
    /// the router walks from `parent == None` down. Distinct models rarely
    /// share prompt prefixes, so in practice this is a set of independent
    /// roots — one per model's hot prompt.
    pub fn merged_warm_prefix_summary(&self) -> tenzro_types::PrefixCacheSummary {
        let mut merged = tenzro_types::PrefixCacheSummary::default();
        for entry in self.warm_prefixes.iter() {
            let base = merged.nodes.len() as u32;
            for node in &entry.value().nodes {
                merged.nodes.push(tenzro_types::PrefixCacheNode {
                    parent: node.parent.map(|p| p + base),
                    run_hash: node.run_hash,
                    run_len: node.run_len,
                });
            }
            merged.warm_token_total = merged
                .warm_token_total
                .saturating_add(entry.value().warm_token_total);
            if merged.nodes.len() >= MAX_WARM_PREFIX_NODES {
                merged.nodes.truncate(MAX_WARM_PREFIX_NODES);
                break;
            }
        }
        merged
    }

    /// Reserve an in-flight slot for `model_id`, returning an RAII guard that
    /// releases the slot on drop. Returns `ModelError::QueueFull` when the
    /// per-model bound is already reached so the caller sheds load instead of
    /// queueing behind a saturated model context.
    fn acquire_inflight(&self, model_id: &str) -> Result<InflightGuard> {
        let counter = self
            .inflight
            .entry(model_id.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .value()
            .clone();
        // Reserve optimistically, then roll back if we exceeded the bound.
        let prior = counter.fetch_add(1, Ordering::SeqCst);
        if prior >= MAX_INFLIGHT_PER_MODEL {
            counter.fetch_sub(1, Ordering::SeqCst);
            return Err(ModelError::QueueFull {
                model_id: model_id.to_string(),
                waiting: prior,
                max: MAX_INFLIGHT_PER_MODEL,
            });
        }
        Ok(InflightGuard { counter })
    }

    /// Get detected hardware information for this runtime.
    ///
    /// Reports which compute backends were compiled in, whether GPU offload
    /// is available, and what backend is actively being used.
    pub fn hardware_info(&self) -> &HardwareInfo {
        &self.hardware
    }

    /// Budget key for the speculative drafter paired with `target_model_id`.
    ///
    /// A drafter is a second GGUF resident alongside its target, so it needs
    /// its own commitment. Sharing the target's key would make each load
    /// overwrite the other's claim.
    fn drafter_budget_key(target_model_id: &str) -> String {
        format!("drafter:{target_model_id}")
    }

    /// Load-time memory admission check.
    ///
    /// Claims `file_len × headroom` in the [`Tier::Resident`] pool of the
    /// process-wide [`memory_budget`](crate::memory_budget). Language models
    /// stay loaded to answer requests, so they are resident by definition.
    ///
    /// This charges against a declared ledger rather than against free system
    /// memory. Reading free memory is unsafe here for two reasons: it counts
    /// the space RocksDB's block cache will grow into as available, and two
    /// concurrent loads both observe the same free bytes and both admit
    /// themselves. The budget's admission is an atomic check-and-commit, so
    /// neither happens.
    ///
    /// The commitment is released by [`unload_model`](Self::unload_model).
    /// `TENZRO_SKIP_MODEL_ADMISSION=1` bypasses the check for operators who
    /// pin memory out-of-band.
    fn check_memory_admission(model_id: &str, file_len: u64) -> Result<()> {
        if std::env::var("TENZRO_SKIP_MODEL_ADMISSION").as_deref() == Ok("1") {
            return Ok(());
        }

        let required = crate::memory_budget::MemoryBudget::with_headroom(file_len);
        crate::memory_budget::global()
            .admit(model_id, crate::memory_budget::Tier::Resident, required)
            .map_err(|denied| ModelError::InsufficientMemory {
                model_id: model_id.to_string(),
                required_mb: denied.requested_bytes / 1_048_576,
                available_mb: denied.tier_available_bytes / 1_048_576,
            })
    }

    /// Detected local hardware, probed once per process. Detection shells
    /// out to vendor tools (`nvidia-smi` / `rocm-smi`), so callers must be
    /// on a blocking thread — both load paths run inside `spawn_blocking`.
    fn local_hardware() -> &'static tenzro_types::HardwareCapabilities {
        static HW: OnceLock<tenzro_types::HardwareCapabilities> = OnceLock::new();
        HW.get_or_init(tenzro_types::HardwareCapabilities::detect)
    }

    /// Operator ceiling on the served context window, from `TENZRO_MAX_CONTEXT`.
    ///
    /// The catalog's `context_length` is the model's capability, not a
    /// statement about the machine serving it. `tenzro_serveModel` passes that
    /// figure straight through, and the batching engine turns it into one
    /// context of `n_ctx` tokens — so a 131072-token catalog entry asks for a
    /// KV cache far larger than a consumer card's whole VRAM, and the load
    /// fails on device allocation rather than serving a shorter window.
    ///
    /// Memory admission (`check_memory_admission`) does not catch this: it
    /// sizes against the GGUF file, which covers the weights and a fixed
    /// headroom margin, not a KV cache that scales with the context.
    ///
    /// Unset means "trust the catalog", preserving the previous behaviour on
    /// hosts with the VRAM to back it.
    fn operator_context_cap() -> Option<u32> {
        std::env::var("TENZRO_MAX_CONTEXT")
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    }

    /// Number of transformer layers to offload to the GPU for a model of
    /// the given on-disk size.
    ///
    /// `1000` means "offload everything" (llama.cpp clamps to the model's
    /// layer count). The budget only deviates from full offload when
    /// detection has positively established that discrete VRAM cannot hold
    /// the whole model:
    ///
    /// - undetected hardware or a unified-memory pool (Apple Silicon) →
    ///   full offload; [`check_memory_admission`](Self::check_memory_admission)
    ///   is the RAM gate there;
    /// - detected CPU-only host → 0, skipping pointless offload attempts;
    /// - model plus KV/activation headroom fits in total VRAM → full offload;
    /// - otherwise → proportional layer count from the GGUF header, so the
    ///   layers that fit ride the GPU and the remainder stays in system RAM
    ///   instead of the load failing on device allocation.
    fn gpu_layer_budget(gguf_path: &Path, file_len: u64) -> u32 {
        let hw = Self::local_hardware();
        if !hw.detected || hw.interconnect == tenzro_types::Interconnect::UnifiedMemory {
            return 1000;
        }
        if hw.vram_gb == 0 {
            return 0;
        }
        let need_gb = (file_len as f32 / 1_073_741_824.0)
            * (LOAD_HEADROOM_NUM as f32 / LOAD_HEADROOM_DEN as f32);
        let vram_gb = hw.vram_gb as f32;
        if need_gb <= vram_gb {
            return 1000;
        }
        match crate::gguf_shape::read_model_shape(gguf_path) {
            Ok(shape) if shape.layers > 0 => {
                let layers = ((shape.layers as f32 * vram_gb / need_gb) as u32).min(shape.layers);
                warn!(
                    "Partial GPU offload for {}: {:.1} GiB needed vs {} GiB VRAM — {}/{} layers on GPU",
                    gguf_path.display(),
                    need_gb,
                    hw.vram_gb,
                    layers,
                    shape.layers,
                );
                layers
            }
            _ => {
                warn!(
                    "Could not read GGUF layer count from {}; requesting full GPU offload",
                    gguf_path.display()
                );
                1000
            }
        }
    }

    /// Load a GGUF model into memory.
    ///
    /// llama.cpp auto-detects the model architecture from GGUF metadata.
    /// GPU layers are offloaded automatically when Metal/CUDA is available.
    ///
    /// Convenience overload: uses the model's trained context length capped
    /// at [`DEFAULT_CONTEXT_LENGTH`]. To use the full catalog context length,
    /// call [`load_model_with_context`] instead.
    pub async fn load_model(&self, model_id: &str, gguf_path: &Path) -> Result<()> {
        self.load_model_with_context(model_id, gguf_path, None)
            .await
    }

    /// Load a GGUF model into memory with a specified context length.
    ///
    /// If `context_length` is `Some(n)`, the context window is set to
    /// `min(n, model_trained_ctx, MAX_CONTEXT_LENGTH)`.
    /// If `None`, falls back to `min(model_trained_ctx, DEFAULT_CONTEXT_LENGTH)`.
    ///
    /// This allows catalog-aware callers to pass the model's full context
    /// length (e.g. 131072 for Qwen 3 8B) while still capping at a safe
    /// maximum to prevent OOM.
    pub async fn load_model_with_context(
        &self,
        model_id: &str,
        gguf_path: &Path,
        context_length: Option<u32>,
    ) -> Result<()> {
        if self.is_loaded(model_id) {
            info!("Model {} already loaded", model_id);
            return Ok(());
        }

        // Admission control: refuse to load a model that won't fit in memory
        // rather than let llama.cpp OOM-kill the process mid-load. Uses the
        // GGUF file size (≈ resident weight footprint) plus a headroom margin
        // for the KV cache and activation buffers.
        let file_len = std::fs::metadata(gguf_path)?.len();
        Self::check_memory_admission(model_id, file_len)?;
        // Everything from here to the registration below can fail through `?`.
        // The guard hands the commitment back on any such path, so a failed
        // load does not permanently shrink the resident tier.
        let admission = crate::memory_budget::AdmissionGuard::new(model_id);

        info!("Loading model {} from {}", model_id, gguf_path.display());
        let start = Instant::now();

        let gguf_path_owned = gguf_path.to_path_buf();
        let model_id_owned = model_id.to_string();
        let backend = self.backend.clone();

        let loaded = tokio::task::spawn_blocking(move || {
            // GPU offload sized against detected VRAM — full offload when the
            // model fits (or the pool is unified / undetected), a proportional
            // layer count when it doesn't.
            let n_gpu_layers = Self::gpu_layer_budget(&gguf_path_owned, file_len);
            let model_params = LlamaModelParams::default().with_n_gpu_layers(n_gpu_layers);

            let model = LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params)
                .map_err(|e| {
                    ModelError::Other(format!(
                        "Failed to load GGUF model '{}': {}",
                        model_id_owned, e
                    ))
                })?;

            // Determine context length:
            // - If caller provides a context_length, use it (capped at MAX_CONTEXT_LENGTH
            //   and the model's trained context)
            // - Otherwise default to DEFAULT_CONTEXT_LENGTH (safe default)
            let trained_ctx = model.n_ctx_train();
            let effective_ctx = match context_length {
                Some(requested) => trained_ctx.min(requested).min(MAX_CONTEXT_LENGTH),
                None => trained_ctx.min(DEFAULT_CONTEXT_LENGTH),
            };
            let effective_ctx = Self::operator_context_cap()
                .map_or(effective_ctx, |cap| effective_ctx.min(cap.max(1)));

            info!(
                "Model {} loaded: {} params, {} layers, trained_context={}, effective_context={}",
                model_id_owned,
                model.n_params(),
                model.n_layer(),
                trained_ctx,
                effective_ctx,
            );

            #[cfg(feature = "mtmd")]
            let projector = Self::load_projector(&model_id_owned, &gguf_path_owned, &model);

            Ok::<LoadedModel, ModelError>(LoadedModel {
                #[cfg(feature = "mtmd")]
                projector,
                model,
                backend,
                context_length: effective_ctx,
            })
        })
        .await
        .map_err(|e| ModelError::Other(format!("Task join error: {}", e)))??;

        let elapsed = start.elapsed();
        info!("Model {} loaded in {:.2}s", model_id, elapsed.as_secs_f64(),);

        // A model paired with a Multi-Token-Prediction drafter is served on the
        // serial single-context path: speculative decoding runs the target and
        // drafter as two contexts that can't share one batch scheduler. So is a
        // model that loaded a multimodal projector — mtmd interleaves image and
        // audio embeddings into its own prefill sequence, which the batch
        // scheduler has no way to express. Every other text model is served
        // through the continuous-batching engine.
        let wants_drafter = get_model_by_id(model_id)
            .map(|e| e.mtp_kind != MtpKind::None)
            .unwrap_or(false);

        #[cfg(feature = "mtmd")]
        let has_projector = loaded.projector.is_some();
        #[cfg(not(feature = "mtmd"))]
        let has_projector = false;

        let entry = if wants_drafter || has_projector {
            LoadedEntry::Serial(Arc::new(tokio::sync::Mutex::new(loaded)))
        } else {
            let LoadedModel {
                model,
                backend,
                context_length,
                ..
            } = loaded;
            let engine = BatchEngine::spawn(model_id.to_string(), model, backend, context_length)?;
            LoadedEntry::Batched(engine)
        };

        if has_projector {
            self.media_capable.insert(model_id.to_string());
        }
        self.loaded_models
            .insert(model_id.to_string(), Arc::new(entry));
        // Registered: `unload_model` now owns releasing this commitment.
        admission.commit();

        Ok(())
    }

    /// Load a GGUF model split across a set of ggml RPC devices, in pipeline
    /// order, for LAN cluster serving.
    ///
    /// `device_indices` are ggml backend-registry indices (one per pipeline
    /// stage, in order) as returned by the cluster runtime's device resolver,
    /// and `tensor_split` carries the per-stage proportions (the planner's
    /// per-stage layer counts) so llama.cpp's layer split reproduces exactly
    /// the assigned ranges. `split_mode` is forced to `Layer` — pipeline
    /// parallelism is the only mode where solely boundary activations cross the
    /// wire, which is what the LAN tunnel is sized for.
    pub async fn load_model_clustered(
        &self,
        model_id: &str,
        gguf_path: &Path,
        context_length: Option<u32>,
        device_indices: Vec<usize>,
        tensor_split: Vec<f32>,
    ) -> Result<()> {
        if self.is_loaded(model_id) {
            info!("Model {} already loaded", model_id);
            return Ok(());
        }
        if device_indices.is_empty() {
            return Err(ModelError::Other(format!(
                "clustered load of '{}' requires at least one device",
                model_id
            )));
        }

        info!(
            "Loading model {} clustered across {} devices from {}",
            model_id,
            device_indices.len(),
            gguf_path.display()
        );
        let start = Instant::now();

        let gguf_path_owned = gguf_path.to_path_buf();
        let model_id_owned = model_id.to_string();
        let backend = self.backend.clone();

        let loaded = tokio::task::spawn_blocking(move || {
            let model_params = LlamaModelParams::default()
                .with_n_gpu_layers(1000)
                .with_split_mode(LlamaSplitMode::Layer)
                .with_devices(&device_indices)
                .map_err(|e| {
                    ModelError::Other(format!(
                        "clustered load of '{}': device selection failed: {}",
                        model_id_owned, e
                    ))
                })?
                .with_tensor_split(&tensor_split);

            let model = LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params)
                .map_err(|e| {
                    ModelError::Other(format!(
                        "Failed to load clustered GGUF model '{}': {}",
                        model_id_owned, e
                    ))
                })?;

            let trained_ctx = model.n_ctx_train();
            let effective_ctx = match context_length {
                Some(requested) => trained_ctx.min(requested).min(MAX_CONTEXT_LENGTH),
                None => trained_ctx.min(DEFAULT_CONTEXT_LENGTH),
            };

            info!(
                "Model {} loaded (clustered): {} params, {} layers, effective_context={}",
                model_id_owned,
                model.n_params(),
                model.n_layer(),
                effective_ctx,
            );

            // Kimi K3 is both the largest clustered target and a multimodal
            // one, so the projector is resolved on the clustered path too. It
            // stays resident on the rank that owns the context; only the text
            // model's layers are split across devices.
            #[cfg(feature = "mtmd")]
            let projector = Self::load_projector(&model_id_owned, &gguf_path_owned, &model);

            Ok::<LoadedModel, ModelError>(LoadedModel {
                #[cfg(feature = "mtmd")]
                projector,
                model,
                backend,
                context_length: effective_ctx,
            })
        })
        .await
        .map_err(|e| ModelError::Other(format!("Task join error: {}", e)))??;

        info!(
            "Model {} loaded clustered in {:.2}s",
            model_id,
            start.elapsed().as_secs_f64(),
        );

        // A clustered pipeline threads boundary activations across devices per
        // request — served on the serial single-context path, not the batch
        // engine.
        #[cfg(feature = "mtmd")]
        if loaded.projector.is_some() {
            self.media_capable.insert(model_id.to_string());
        }
        self.loaded_models.insert(
            model_id.to_string(),
            Arc::new(LoadedEntry::Serial(Arc::new(tokio::sync::Mutex::new(
                loaded,
            )))),
        );

        Ok(())
    }

    /// Resolve and load a model's multimodal projector, if it declares one.
    ///
    /// The projector is the `mmproj` GGUF the artifact downloader stores flat
    /// as `<storage>/<id>.mmproj.gguf` alongside the weights. A catalog entry
    /// with no `mmproj`, or one whose projector has not been downloaded,
    /// returns `None` and the model serves text-only.
    #[cfg(feature = "mtmd")]
    fn load_projector(model_id: &str, gguf_path: &Path, model: &LlamaModel) -> Option<MtmdContext> {
        get_model_by_id(model_id)?.mmproj.as_ref()?;

        let path = Self::projector_path(model_id, gguf_path)?;
        let path_str = path.to_str()?;

        let params = MtmdContextParams {
            use_gpu: true,
            print_timings: false,
            n_threads: std::thread::available_parallelism()
                .map(|n| n.get() as i32)
                .unwrap_or(4),
            media_marker: std::ffi::CString::new(mtmd_default_marker()).ok()?,
        };

        match MtmdContext::init_from_file(path_str, model, &params) {
            Ok(ctx) => {
                info!(
                    "Model {} projector loaded from {}: vision={}, audio={}",
                    model_id,
                    path.display(),
                    ctx.support_vision(),
                    ctx.support_audio(),
                );
                Some(ctx)
            }
            Err(e) => {
                warn!(
                    "Model {} declares a projector at {} but loading it failed ({}) — serving text-only",
                    model_id,
                    path.display(),
                    e,
                );
                None
            }
        }
    }

    /// Locate a downloaded projector for `model_id` given the path its weights
    /// were loaded from. Single-file weights sit directly in the storage
    /// directory; a gguf-split set sits one level deeper in `<storage>/<id>/`.
    /// The projector is flat in the storage directory either way, so both
    /// layouts are checked.
    #[cfg(feature = "mtmd")]
    fn projector_path(model_id: &str, gguf_path: &Path) -> Option<PathBuf> {
        let filename = format!("{}.mmproj.gguf", model_id);
        let parent = gguf_path.parent()?;

        let flat = parent.join(&filename);
        if flat.is_file() {
            return Some(flat);
        }
        let nested = parent.parent()?.join(&filename);
        if nested.is_file() {
            return Some(nested);
        }
        None
    }

    /// Whether a loaded model can accept image or audio input — its catalog
    /// entry declares an `mmproj` and that projector loaded successfully.
    pub fn supports_media(&self, model_id: &str) -> bool {
        self.media_capable.contains(model_id)
    }

    /// Unload a model from memory.
    pub async fn unload_model(&self, model_id: &str) -> Result<()> {
        // An externally-served model has no local context — drop the routing
        // registration and we're done.
        if self.external_engines.remove(model_id).is_some() {
            info!("Unregistered external engine for model: {}", model_id);
            return Ok(());
        }
        self.media_capable.remove(model_id);
        if let Some((_, entry)) = self.loaded_models.remove(model_id) {
            match entry.as_ref() {
                LoadedEntry::Batched(engine) => {
                    // Stop the scheduler thread and join it, which drops the
                    // owned model + context. In-flight requests receive an
                    // error on their result channel.
                    engine.shutdown();
                }
                LoadedEntry::Serial(model_mutex) => {
                    // Acquire the mutex to wait for any in-progress generation
                    // to finish before dropping the llama.cpp model context.
                    // Without this, the model stays in memory until the
                    // generation task completes, causing OOM when loading
                    // another model.
                    let _lock = model_mutex.lock().await;
                    drop(_lock);
                }
            }
            drop(entry);
            // Return the claim to the resident tier only after the context is
            // actually gone. Releasing earlier would let a concurrent load be
            // admitted against space this model has not yet freed.
            crate::memory_budget::global().release(model_id);
            info!("Unloaded model: {} (llama.cpp context freed)", model_id);
        } else {
            warn!("Model {} was not loaded", model_id);
        }
        Ok(())
    }

    /// Check if a model is currently served — either loaded into a local
    /// llama.cpp context or routed to a registered external engine.
    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.loaded_models.contains_key(model_id) || self.external_engines.contains_key(model_id)
    }

    /// List all currently served model IDs (local + external).
    pub fn list_loaded(&self) -> Vec<String> {
        self.loaded_models
            .iter()
            .map(|entry| entry.key().clone())
            .chain(self.external_engines.iter().map(|e| e.key().clone()))
            .collect()
    }

    /// Register an external OpenAI-compatible engine as the backend for
    /// `model_id`. Probes `/health` first so a misconfigured endpoint fails
    /// the serve call rather than surfacing on the first inference. Refuses to
    /// register over a model that is already loaded into a local context —
    /// unload it first.
    pub async fn register_external_engine(
        &self,
        model_id: &str,
        engine: ExternalEngine,
    ) -> Result<()> {
        if self.loaded_models.contains_key(model_id) {
            return Err(ModelError::Other(format!(
                "`{}` is already served through the local runtime; unload it before \
                 registering an external engine",
                model_id
            )));
        }
        engine.health().await?;
        info!(
            model_id = %model_id,
            engine = engine.kind().as_str(),
            base_url = engine.base_url(),
            "Registered external inference engine",
        );
        self.external_engines.insert(model_id.to_string(), engine);
        Ok(())
    }

    /// If `model_id` is served through an external engine, return
    /// `(kind, base_url, upstream_model)` for endpoint listing. `None` for
    /// locally-loaded or absent models.
    pub fn external_engine_info(&self, model_id: &str) -> Option<(String, String, String)> {
        self.external_engines.get(model_id).map(|e| {
            let engine = e.value();
            (
                engine.kind().as_str().to_string(),
                engine.base_url().to_string(),
                engine.upstream_model().to_string(),
            )
        })
    }

    /// Load a Multi-Token-Prediction drafter GGUF and bind it to an
    /// already-loaded target.
    ///
    /// The drafter is a same-architecture sidecar (e.g.
    /// `unsloth/gemma-4-12b-it-GGUF/MTP/mtp-gemma-4-12B-it.gguf`).
    /// `target_model_id` must already be in the runtime via
    /// [`Self::load_model`]; the drafter is then keyed under the
    /// target's id so subsequent generations against that target with
    /// `GenerationConfig.draft_n = Some(n)` will use the speculative
    /// path.
    ///
    /// `context_length` matches the target's effective context window
    /// when `None` (recommended). The catalog-driven loader in
    /// `tenzro-node` reads `HfModelEntry.context_length` for both
    /// target and drafter and passes them through here.
    pub async fn load_drafter(
        &self,
        target_model_id: &str,
        drafter_gguf_path: &Path,
        context_length: Option<u32>,
    ) -> Result<()> {
        match self.loaded_models.get(target_model_id) {
            None => {
                return Err(ModelError::Other(format!(
                    "Cannot load drafter for `{}`: target model is not loaded",
                    target_model_id
                )));
            }
            Some(entry) => {
                if matches!(entry.as_ref(), LoadedEntry::Batched(_)) {
                    // Speculative decoding needs the target on the serial
                    // two-context path. A batched target has no drafter pairing
                    // in the catalog, so this is only reachable on a catalog
                    // mismatch — refuse rather than silently ignore.
                    return Err(ModelError::Other(format!(
                        "Cannot load drafter for `{}`: target is served through the \
                         continuous-batching engine, which has no speculative path",
                        target_model_id
                    )));
                }
            }
        }
        if self.loaded_drafters.contains_key(target_model_id) {
            info!("Drafter for {} already loaded", target_model_id);
            return Ok(());
        }

        let file_len = std::fs::metadata(drafter_gguf_path)?.len();
        // Keyed separately from the target. Admitting under `target_model_id`
        // would *replace* the target's own commitment with the drafter's much
        // smaller one, silently handing back memory the target still holds.
        Self::check_memory_admission(&Self::drafter_budget_key(target_model_id), file_len)?;
        let admission =
            crate::memory_budget::AdmissionGuard::new(Self::drafter_budget_key(target_model_id));

        info!(
            "Loading MTP drafter for {} from {}",
            target_model_id,
            drafter_gguf_path.display()
        );
        let start = Instant::now();

        let gguf_path_owned = drafter_gguf_path.to_path_buf();
        let target_id_owned = target_model_id.to_string();
        let backend = self.backend.clone();

        let loaded = tokio::task::spawn_blocking(move || {
            let n_gpu_layers = Self::gpu_layer_budget(&gguf_path_owned, file_len);
            let model_params = LlamaModelParams::default().with_n_gpu_layers(n_gpu_layers);
            let model = LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params)
                .map_err(|e| {
                    ModelError::Other(format!(
                        "Failed to load MTP drafter for target '{}': {}",
                        target_id_owned, e
                    ))
                })?;
            let trained_ctx = model.n_ctx_train();
            let effective_ctx = match context_length {
                Some(requested) => trained_ctx.min(requested).min(MAX_CONTEXT_LENGTH),
                None => trained_ctx.min(DEFAULT_CONTEXT_LENGTH),
            };
            Ok::<LoadedDrafter, ModelError>(LoadedDrafter {
                model,
                backend,
                context_length: effective_ctx,
            })
        })
        .await
        .map_err(|e| ModelError::Other(format!("Task join error: {}", e)))??;

        let elapsed = start.elapsed();
        info!(
            "MTP drafter for {} loaded in {:.2}s",
            target_model_id,
            elapsed.as_secs_f64(),
        );

        self.loaded_drafters.insert(
            target_model_id.to_string(),
            Arc::new(tokio::sync::Mutex::new(loaded)),
        );
        // Registered: `unload_drafter` now owns releasing this commitment.
        admission.commit();
        Ok(())
    }

    /// Unload the MTP drafter paired with `target_model_id`.
    pub async fn unload_drafter(&self, target_model_id: &str) -> Result<()> {
        if let Some((_, drafter_arc)) = self.loaded_drafters.remove(target_model_id) {
            let _lock = drafter_arc.lock().await;
            drop(_lock);
            drop(drafter_arc);
            crate::memory_budget::global().release(&Self::drafter_budget_key(target_model_id));
            info!("Unloaded MTP drafter for {}", target_model_id);
        }
        Ok(())
    }

    /// Whether a Multi-Token-Prediction drafter is currently loaded for
    /// the given target. Drives the speculative seam in the generation
    /// loop and the inference router's mtp_enabled filter.
    pub fn has_drafter(&self, target_model_id: &str) -> bool {
        self.loaded_drafters.contains_key(target_model_id)
    }

    /// Re-execute a committed inference as a single prefill and compare
    /// the recomputed logits against the commitment (TOPLOC check).
    ///
    /// The verifier must hold the same model weights the provider used.
    /// The prompt is tokenized exactly as the generation path tokenizes
    /// it (`AddBos::Always`); the committed output tokens are appended
    /// and the whole sequence is decoded in one batch, which is roughly
    /// two orders of magnitude cheaper than the original token-by-token
    /// decode.
    pub async fn verify_inference_commitment(
        &self,
        model_id: &str,
        prompt: &str,
        commitment: crate::toploc::InferenceCommitment,
    ) -> Result<crate::toploc::VerificationOutcome> {
        if self.external_engines.contains_key(model_id) {
            return Err(ModelError::InferenceError(
                "model is served through an external engine, which does not expose logits; \
                 commitment verification requires locally loaded weights"
                    .to_string(),
            ));
        }
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();
        let _guard = self.acquire_inflight(model_id)?;
        match entry.as_ref() {
            LoadedEntry::Batched(_) => Err(ModelError::InferenceError(
                "commitment verification requires the model loaded in serial mode".to_string(),
            )),
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                let prompt = prompt.to_string();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    Self::verify_commitment_sync(&loaded, &prompt, &commitment)
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Verification task error: {}", e)))?
            }
        }
    }

    fn verify_commitment_sync(
        loaded: &LoadedModel,
        prompt: &str,
        commitment: &crate::toploc::InferenceCommitment,
    ) -> Result<crate::toploc::VerificationOutcome> {
        if commitment.steps.is_empty() {
            return Ok(crate::toploc::verify_commitment(commitment, &[]));
        }

        let prompt_tokens = loaded
            .model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {}", e)))?;
        if prompt_tokens.len() != commitment.prompt_tokens as usize {
            return Err(ModelError::InferenceError(format!(
                "prompt tokenizes to {} tokens but the commitment declares {} — \
                 different tokenizer or altered prompt",
                prompt_tokens.len(),
                commitment.prompt_tokens,
            )));
        }

        let prompt_len = prompt_tokens.len();
        let steps = commitment.steps.len();
        // Step j's logits come from sequence position prompt_len - 1 + j,
        // so the batch feeds the prompt plus all output tokens except the
        // last one.
        let total = prompt_len + steps - 1;

        let n_ctx = NonZeroU32::new(loaded.context_length)
            .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());
        if total as u32 > n_ctx.get() {
            return Err(ModelError::InferenceError(format!(
                "committed sequence needs {} positions but the context holds {}",
                total,
                n_ctx.get(),
            )));
        }

        let ctx_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx));
        let mut ctx = loaded
            .model
            .new_context(&loaded.backend, ctx_params)
            .map_err(|e| ModelError::Other(format!("Failed to create context: {}", e)))?;

        // The sequence to replay is the prompt followed by every committed
        // output token but the last.
        let mut seq: Vec<LlamaToken> = Vec::with_capacity(total);
        seq.extend_from_slice(&prompt_tokens);
        seq.extend(
            commitment.steps[..steps - 1]
                .iter()
                .map(|step| LlamaToken(step.token_id as i32)),
        );

        let k = commitment.k as usize;
        let first_logits_pos = prompt_len - 1;

        // Chunked for the same reason as `prefill_in_batches` — a committed
        // sequence longer than `n_batch` would abort the process rather than
        // fail the verification. The rows are read back inside the loop
        // instead of after it because `output_ids` is refilled by every
        // decode, so a row is only addressable until the next one runs.
        let n_batch = (ctx.n_batch() as usize).max(1);
        let mut batch = LlamaBatch::new(n_batch.min(seq.len()), 1);
        let mut recomputed: Vec<Vec<crate::toploc::TopKEntry>> = Vec::with_capacity(steps);

        let mut start = 0usize;
        while start < seq.len() {
            let end = (start + n_batch).min(seq.len());
            batch.clear();
            for (offset, token) in seq[start..end].iter().enumerate() {
                let pos = start + offset;
                batch
                    .add(*token, pos as i32, &[0], pos >= first_logits_pos)
                    .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;
            }
            ctx.decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Verification prefill failed: {}", e)))?;

            for pos in start.max(first_logits_pos)..end {
                recomputed.push(crate::toploc::top_k_from_logits(
                    ctx.get_logits_ith((pos - start) as i32),
                    k,
                ));
            }
            start = end;
        }

        Ok(crate::toploc::verify_commitment(commitment, &recomputed))
    }

    /// Submit a prompt to a model's continuous-batching engine and await its
    /// terminal result, optionally streaming token pieces through `token_tx`.
    ///
    /// The `_guard` in-flight reservation is held for the whole await so a
    /// cancelled caller (client disconnect) releases its slot — and, when
    /// streaming, dropping `token_tx`'s receiver signals the scheduler to free
    /// the sequence early.
    async fn run_batched(
        engine: &BatchEngine,
        prompt: BatchPrompt,
        config: &GenerationConfig,
        token_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        engine.submit(BatchRequest {
            prompt,
            config: config.clone(),
            token_tx,
            result_tx,
        })?;
        result_rx
            .await
            .map_err(|_| ModelError::Other("batch engine dropped the request".into()))?
    }

    /// Generate text from a raw prompt string.
    pub async fn generate(
        &self,
        model_id: &str,
        prompt: &str,
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        // External engine takes priority: the model is served off-box, so
        // there is no local context. A raw prompt maps to a single user turn.
        // Clone the engine and drop the DashMap guard before any `.await`.
        let external = self
            .external_engines
            .get(model_id)
            .map(|e| e.value().clone());
        if let Some(engine) = external {
            let _guard = self.acquire_inflight(model_id)?;
            let messages = [ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }];
            return engine.chat(&messages, config).await;
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.acquire_inflight(model_id)?;

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(engine, BatchPrompt::Raw(prompt.to_string()), config, None).await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                let prompt = prompt.to_string();
                let config = config.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    Self::generate_sync(&loaded, &prompt, &config)
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Generate text from structured chat messages.
    ///
    /// Uses the model's built-in chat template (read from GGUF metadata) to
    /// format the prompt correctly for each architecture (Gemma uses
    /// `<start_of_turn>`, Qwen uses `<|im_start|>`, etc.).
    pub async fn generate_chat(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        let external = self
            .external_engines
            .get(model_id)
            .map(|e| e.value().clone());
        if let Some(engine) = external {
            let _guard = self.acquire_inflight(model_id)?;
            return engine.chat(messages, config).await;
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        // Record the served prompt as warm — its prefix stays in the KV cache
        // and is now advertisable for prefix-affinity routing. Hashed over the
        // same user-content bytes the requesting router hashes from
        // `InferenceRequest.input`, so both sides agree on the prefix.
        self.record_warm_prompt(model_id, &warm_prompt_bytes(messages));

        let _guard = self.acquire_inflight(model_id)?;

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(engine, BatchPrompt::Chat(messages.to_vec()), config, None).await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                let messages = messages.to_vec();
                let config = config.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let prompt = render_chat_prompt(&loaded.model, &messages)?;
                    Self::generate_sync(&loaded, &prompt, &config)
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Generate a chat completion with tool-use awareness.
    ///
    /// Tool schemas are inlined into the system prompt (since GGUF chat
    /// templates don't carry a uniform tool slot across model families).
    /// After generation, the raw output is scanned for template-specific
    /// tool-call markers (Qwen3 `<tool_call>...</tool_call>`, Llama 3
    /// `<|python_tag|>{...}`, Mistral `[TOOL_CALLS]...`, plus a generic
    /// JSON fallback). Extracted calls are returned as structured
    /// [`ToolCall`] values; the surrounding free text is returned with
    /// markers stripped.
    ///
    /// `stop_reason` follows the rich-shape spec:
    /// - `"tool_use"` — at least one tool call was extracted.
    /// - `"max_tokens"` — output_tokens reached `config.max_tokens`.
    /// - `"end_turn"` — clean EOG with no tool calls.
    pub async fn generate_chat_with_tools(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<ChatWithToolsResult> {
        // Resolve the backend: external engine, or a local `LoadedEntry`.
        let external = self
            .external_engines
            .get(model_id)
            .map(|e| e.value().clone());
        let entry = if external.is_some() {
            None
        } else {
            Some(
                self.loaded_models
                    .get(model_id)
                    .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
                    .value()
                    .clone(),
            )
        };

        let _guard = self.acquire_inflight(model_id)?;
        let messages = messages.to_vec();
        let tools = tools.to_vec();
        let config = config.clone();

        // Two ways to tell a model about tools, preferred in this order:
        //
        // 1. The model's own chat template, which renders them in the format
        //    it was tuned on and hands back a GBNF grammar compiled from their
        //    schemas. Sampling constrained to that grammar cannot spell a
        //    malformed call — see `crate::tool_grammar`.
        // 2. Failing that, a system preamble of our own wording, parsed back
        //    out of free text on a best-effort basis.
        //
        // Only the serial path takes route 1 so far: the batching engine
        // renders its own prompts and owns one long-lived context and sampler,
        // so a per-request grammar does not thread through it without changing
        // how that engine is built. The preamble it already used is unchanged,
        // so nothing regresses by not having been converted yet.
        let preamble_messages = || {
            let mut m = messages.clone();
            inject_tools_preamble(&mut m, &tools);
            m
        };

        let inner = if let Some(engine) = external {
            // A remote engine is given the tool schemas over its own wire
            // format; the preamble is all this side controls.
            engine.chat(&preamble_messages(), &config).await?
        } else {
            match entry
                .as_ref()
                .expect("local entry present when not external")
                .as_ref()
            {
                LoadedEntry::Batched(engine) => {
                    Self::run_batched(
                        engine,
                        BatchPrompt::Chat(preamble_messages()),
                        &config,
                        None,
                    )
                    .await?
                }
                LoadedEntry::Serial(model_mutex) => {
                    let model_mutex = model_mutex.clone();
                    let config = config.clone();
                    let messages = messages.clone();
                    let tools = tools.clone();
                    tokio::task::spawn_blocking(move || {
                        let loaded = model_mutex.blocking_lock();
                        match crate::tool_grammar::native_tool_prompt(
                            &loaded.model,
                            &messages,
                            &tools,
                        ) {
                            Some((prompt, grammar)) => {
                                // Stop sequences the template asks for are
                                // additive to the caller's own.
                                let config = match grammar.as_ref() {
                                    Some(g) if !g.additional_stops.is_empty() => {
                                        let mut c = config.clone();
                                        c.stop.extend(g.additional_stops.iter().cloned());
                                        c
                                    }
                                    _ => config,
                                };
                                Self::generate_sync_with_grammar(
                                    &loaded,
                                    &prompt,
                                    &config,
                                    grammar.as_ref(),
                                )
                            }
                            None => {
                                let mut messages = messages;
                                inject_tools_preamble(&mut messages, &tools);
                                let prompt = render_chat_prompt(&loaded.model, &messages)?;
                                Self::generate_sync(&loaded, &prompt, &config)
                            }
                        }
                    })
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))??
                }
            }
        };

        // Parse tool-call markers from the raw output.
        let (clean_text, tool_calls) = extract_tool_calls(&inner.text);

        // A tool call outranks the engine's own cause: the turn ends because
        // control passes to the caller's tool, whatever halted decoding.
        let stop_reason = if !tool_calls.is_empty() {
            "tool_use".to_string()
        } else {
            match inner.stop_reason {
                StopReason::Length => "max_tokens".to_string(),
                StopReason::StopSequence => "stop_sequence".to_string(),
                StopReason::Eos => "end_turn".to_string(),
            }
        };

        Ok(ChatWithToolsResult {
            text: clean_text,
            tool_calls,
            input_tokens: inner.input_tokens,
            output_tokens: inner.output_tokens,
            generation_time_ms: inner.generation_time_ms,
            tokens_per_second: inner.tokens_per_second,
            stop_reason,
            commitment: inner.commitment,
        })
    }

    /// Stream text generation token-by-token from structured chat messages.
    ///
    /// Each generated token piece is sent through the `token_tx` channel as it's
    /// produced. The final `InferenceResult` (with aggregated stats) is returned
    /// when generation finishes.
    pub async fn generate_chat_stream(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
        token_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<InferenceResult> {
        let external = self
            .external_engines
            .get(model_id)
            .map(|e| e.value().clone());
        if let Some(engine) = external {
            let _guard = self.acquire_inflight(model_id)?;
            return engine.chat_stream(messages, config, token_tx).await;
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        // Record the served prompt as warm for prefix-affinity advertisement,
        // same as the non-streaming chat path.
        self.record_warm_prompt(model_id, &warm_prompt_bytes(messages));

        let _guard = self.acquire_inflight(model_id)?;

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(
                    engine,
                    BatchPrompt::Chat(messages.to_vec()),
                    config,
                    Some(token_tx),
                )
                .await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                // Look up the drafter only when the caller asked for speculative
                // decoding. Avoids holding an extra lock on the happy path.
                let drafter_mutex = if config.draft_n.is_some() {
                    self.loaded_drafters
                        .get(model_id)
                        .map(|d| d.value().clone())
                } else {
                    None
                };
                let messages = messages.to_vec();
                let config = config.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let drafter_guard = drafter_mutex.as_ref().map(|d| d.blocking_lock());
                    let prompt = render_chat_prompt(&loaded.model, &messages)?;
                    Self::generate_sync_streaming(
                        &loaded,
                        drafter_guard.as_deref(),
                        &prompt,
                        &config,
                        Some(&token_tx),
                        // Plain chat streaming carries no tools.
                        None,
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Generate a chat completion with image or audio attachments.
    ///
    /// Requires a model whose catalog entry declares an `mmproj` and whose
    /// projector loaded — [`Self::supports_media`] is the check. `media` carries
    /// the raw encoded bytes of each attachment: PNG / JPEG / WebP for images,
    /// and WAV / MP3 / FLAC when the projector has an audio tower. The format is
    /// identified from the bytes, so the caller does not declare it.
    ///
    /// Attachments bind to [`media_marker`] occurrences in the prompt, in
    /// order. A caller that wants precise placement writes the markers into
    /// message content itself; a caller that writes none gets one per
    /// attachment prepended to the last user turn.
    ///
    /// `tools` behaves exactly as in [`Self::generate_chat_with_tools`] — the
    /// schemas go into the system turn and any tool call the model emits is
    /// extracted from the output — so a vision request can drive tools. An empty
    /// `media` slice is an ordinary chat request and is forwarded as one.
    pub async fn generate_chat_multimodal(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        media: &[Vec<u8>],
        tools: &[ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<ChatWithToolsResult> {
        if media.is_empty() {
            return self
                .generate_chat_with_tools(model_id, messages, tools, config)
                .await;
        }

        if self.external_engines.contains_key(model_id) {
            return Err(ModelError::InferenceError(format!(
                "model {} is served by an external engine, which carries no multimodal path",
                model_id,
            )));
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.acquire_inflight(model_id)?;

        // No warm-prompt record: the prefix a multimodal request leaves in the KV
        // cache holds media embeddings, so text-prefix affinity would mis-route.

        match entry.as_ref() {
            LoadedEntry::Batched(_) => Err(ModelError::InferenceError(format!(
                "model {} is served text-only — it declares no projector, or its \
                 projector failed to load. Check ModelRuntime::supports_media before \
                 sending attachments.",
                model_id,
            ))),
            LoadedEntry::Serial(model_mutex) => {
                #[cfg(feature = "mtmd")]
                {
                    let model_mutex = model_mutex.clone();
                    let mut messages = messages.to_vec();
                    let media = media.to_vec();
                    let config = config.clone();
                    inject_tools_preamble(&mut messages, tools);
                    Self::place_media_markers(&mut messages, media.len())?;
                    let inner = tokio::task::spawn_blocking(move || {
                        let loaded = model_mutex.blocking_lock();
                        let prompt = render_chat_prompt(&loaded.model, &messages)?;
                        Self::generate_sync_multimodal(&loaded, &prompt, &media, &config)
                    })
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))??;

                    let (clean_text, tool_calls) = extract_tool_calls(&inner.text);
                    let stop_reason = if !tool_calls.is_empty() {
                        "tool_use".to_string()
                    } else {
                        match inner.stop_reason {
                            StopReason::Length => "max_tokens".to_string(),
                            StopReason::StopSequence => "stop_sequence".to_string(),
                            StopReason::Eos => "end_turn".to_string(),
                        }
                    };
                    Ok(ChatWithToolsResult {
                        text: clean_text,
                        tool_calls,
                        input_tokens: inner.input_tokens,
                        output_tokens: inner.output_tokens,
                        generation_time_ms: inner.generation_time_ms,
                        tokens_per_second: inner.tokens_per_second,
                        stop_reason,
                        commitment: inner.commitment,
                    })
                }
                #[cfg(not(feature = "mtmd"))]
                {
                    let _ = (model_mutex, tools);
                    Err(ModelError::InferenceError(
                        "this node was built without the mtmd feature, so it serves \
                         text only. Rebuild tenzro-model with --features mtmd."
                            .to_string(),
                    ))
                }
            }
        }
    }

    /// Stream text generation token-by-token from a raw prompt.
    ///
    /// Each generated token piece is sent through the `token_tx` channel as it's
    /// produced. The final `InferenceResult` (with aggregated stats) is returned
    /// when generation finishes.
    pub async fn generate_stream(
        &self,
        model_id: &str,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<InferenceResult> {
        let external = self
            .external_engines
            .get(model_id)
            .map(|e| e.value().clone());
        if let Some(engine) = external {
            let _guard = self.acquire_inflight(model_id)?;
            let messages = [ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }];
            return engine.chat_stream(&messages, config, token_tx).await;
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.acquire_inflight(model_id)?;

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(
                    engine,
                    BatchPrompt::Raw(prompt.to_string()),
                    config,
                    Some(token_tx),
                )
                .await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                let drafter_mutex = if config.draft_n.is_some() {
                    self.loaded_drafters
                        .get(model_id)
                        .map(|d| d.value().clone())
                } else {
                    None
                };
                let prompt = prompt.to_string();
                let config = config.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let drafter_guard = drafter_mutex.as_ref().map(|d| d.blocking_lock());
                    Self::generate_sync_streaming(
                        &loaded,
                        drafter_guard.as_deref(),
                        &prompt,
                        &config,
                        Some(&token_tx),
                        // Plain chat streaming carries no tools.
                        None,
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Prefill `tokens` into `ctx`, submitting at most `n_batch` of them per
    /// `llama_decode` call, and return the batch row the first sample reads
    /// its logits from.
    ///
    /// `n_batch` is llama.cpp's *logical* batch cap — "logical maximum batch
    /// size that can be submitted to llama_decode" (`llama.h`) — and going
    /// over it is not a recoverable error. `llama_context::decode` opens with
    /// `GGML_ASSERT(n_tokens_all <= cparams.n_batch)`, and a failed
    /// `GGML_ASSERT` calls `abort()`: a prompt one token past the cap does not
    /// fail the request, it takes the whole node process down, mid-response,
    /// for every other tenant it was serving. The cap defaults to 2048
    /// independently of `n_ctx`, so a 128k-context model still aborts on the
    /// 2049th prompt token unless the prompt is split. Splitting into
    /// `n_ubatch`-sized micro-batches happens inside llama.cpp and needs
    /// nothing from us; this loop is only about the logical cap, and mirrors
    /// upstream's own prefill loops (`tools/perplexity`, `examples/passkey`,
    /// `tools/server`) and `batching.rs`.
    ///
    /// Only the final token requests logits, so the returned row is an index
    /// into the *last* decode call's batch rather than a position in the
    /// prompt: `output_ids` is refilled per decode and translates a batch
    /// index, not a sequence position. Returning it keeps that distinction
    /// with the loop that knows the chunk boundaries instead of leaving each
    /// caller to re-derive it.
    fn prefill_in_batches(ctx: &mut LlamaContext, tokens: &[LlamaToken]) -> Result<i32> {
        let n_batch = (ctx.n_batch() as usize).max(1);
        let last = tokens.len() - 1;
        let mut batch = LlamaBatch::new(n_batch.min(tokens.len()), 1);

        let mut start = 0usize;
        while start < tokens.len() {
            let end = (start + n_batch).min(tokens.len());
            batch.clear();
            for (offset, token) in tokens[start..end].iter().enumerate() {
                let pos = start + offset;
                batch
                    .add(*token, pos as i32, &[0], pos == last)
                    .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;
            }
            ctx.decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Prompt decode failed: {}", e)))?;
            start = end;
        }

        // Row of the last token within the final chunk.
        Ok((tokens.len() - 1 - (start - batch.n_tokens() as usize)) as i32)
    }

    /// Synchronous text generation using llama.cpp.
    ///
    /// Convenience wrapper for callers that don't have a drafter ref
    /// in scope. Falls through to `generate_sync_streaming` with
    /// `drafter = None` and `token_tx = None`.
    fn generate_sync(
        loaded: &LoadedModel,
        prompt: &str,
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        Self::generate_sync_streaming(loaded, None, prompt, config, None, None)
    }

    /// [`Self::generate_sync`] with sampling constrained to a tool grammar.
    ///
    /// Used by the tool-aware path when the model's own template supplied one;
    /// everything else calls [`Self::generate_sync`] and is unaffected.
    fn generate_sync_with_grammar(
        loaded: &LoadedModel,
        prompt: &str,
        config: &GenerationConfig,
        grammar: Option<&crate::tool_grammar::ToolGrammar>,
    ) -> Result<InferenceResult> {
        Self::generate_sync_streaming(loaded, None, prompt, config, None, grammar)
    }

    /// Core synchronous generation loop, optionally streaming each
    /// token and optionally running speculative decoding when an MTP
    /// drafter is provided.
    fn generate_sync_streaming(
        loaded: &LoadedModel,
        drafter: Option<&LoadedDrafter>,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        tool_grammar: Option<&crate::tool_grammar::ToolGrammar>,
    ) -> Result<InferenceResult> {
        // MTP / speculative-decoding seam. When the caller passes
        // `draft_n: Some(n)`:
        //   - If a drafter is loaded for this target, run the
        //     speculative path via `MtpSpeculative`.
        //   - If no drafter is loaded, return `MtpUnavailable` with a
        //     reason that tells the caller to load the drafter first
        //     (or unset draft_n for single-token sampling).
        //
        // The binding comes from the vendored `llama-cpp-rs` branch
        // `mtp-speculative-decoding` (DINOZYAVIER/llama-cpp-rs PR
        // #1027). When upstream merges, drop the [patch.crates-io]
        // block at the workspace root and this seam stays unchanged.
        // A tool grammar outranks speculative decoding. The drafter proposes
        // tokens the target then accepts or rejects, and the acceptance test
        // does not consult the grammar — a draft could carry the sequence past
        // a point the grammar forbids, which is the one guarantee this path
        // exists to provide. Declining the drafter costs throughput on a turn
        // that is about to call a tool; letting it through would cost the
        // constraint.
        if tool_grammar.is_some() && config.draft_n.is_some() {
            debug!("tool grammar present — running this turn without the MTP drafter");
        } else if let Some(n) = config.draft_n {
            let Some(drafter) = drafter else {
                return Err(ModelError::MtpUnavailable {
                    reason: format!(
                        "draft_n={} requested but no MTP drafter is loaded for this target. \
                         Call ModelRuntime::load_drafter(target_id, drafter.gguf) before \
                         submitting speculative requests, or unset draft_n to use \
                         single-token sampling.",
                        n,
                    ),
                });
            };
            return Self::generate_speculative(loaded, drafter, prompt, config, token_tx, n);
        }

        let start = Instant::now();

        // Tokenize input
        let tokens_list = loaded
            .model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {}", e)))?;

        // A zero-length token stream would leave the prompt batch empty and
        // make `llama_decode` fail with an opaque `n_tokens == 0`. Surface a
        // clear error instead of that internal panic-adjacent message.
        if tokens_list.is_empty() {
            return Err(ModelError::InferenceError(
                "prompt tokenized to zero tokens".to_string(),
            ));
        }

        let input_tokens = tokens_list.len() as u32;

        // Use the context length determined at load time (catalog-aware or default)
        let n_ctx = NonZeroU32::new(loaded.context_length)
            .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());

        // Create a fresh context for this generation
        let ctx_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx));
        let mut ctx = loaded
            .model
            .new_context(&loaded.backend, ctx_params)
            .map_err(|e| ModelError::Other(format!("Failed to create context: {}", e)))?;

        // Prefill the prompt, in `n_batch`-sized decode calls.
        let n_past = tokens_list.len() as i32;
        let first_logits = Self::prefill_in_batches(&mut ctx, &tokens_list)?;

        // The prefill asked for logits on its last token only, so that row is
        // where the first sample reads from.
        Self::decode_loop(
            loaded,
            &mut ctx,
            n_past,
            input_tokens,
            config,
            token_tx,
            Some(first_logits),
            start,
            tool_grammar,
        )
    }

    /// Autoregressive decode loop, shared by the text and multimodal prefill
    /// paths. The caller has already created the context, run the prefill, and
    /// advanced the sequence to `n_past`.
    ///
    /// `first_logits` is the batch row the first sample reads its logits from,
    /// or `None` when the prefill left no readable row. The text path prefills
    /// through `LlamaContext::decode`, which records which rows carry logits, so
    /// it passes the last prompt row. The multimodal path prefills through
    /// `mtmd_helper_eval_chunks`, which decodes on the raw C context and so
    /// leaves that record empty — reading it would trip the bounds assertion in
    /// `get_logits_ith`. That path passes `None`, and the first token is sampled
    /// via the raw `-1` index (last logits row), which the sampler accepts
    /// without the assertion. Every subsequent step decodes a one-token batch
    /// through `decode`, so from the second token on both paths read row 0 and
    /// TOPLOC records normally.
    ///
    /// `input_tokens` is the prompt size reported in the result and bound into
    /// the TOPLOC commitment; it counts media tokens on the multimodal path.
    #[allow(clippy::too_many_arguments)]
    fn decode_loop(
        loaded: &LoadedModel,
        ctx: &mut LlamaContext,
        n_past: i32,
        input_tokens: u32,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        first_logits: Option<i32>,
        start: Instant,
        tool_grammar: Option<&crate::tool_grammar::ToolGrammar>,
    ) -> Result<InferenceResult> {
        let n_ctx_val = ctx.n_ctx() as i32;
        let total_needed = n_past + config.max_tokens as i32;
        if total_needed > n_ctx_val {
            warn!(
                "Requested {} tokens but context is {} -- output will be truncated",
                total_needed, n_ctx_val
            );
        }

        let mut sampler = build_sampler_chain_with_grammar(
            config,
            tool_grammar.and_then(|g| g.sampler(&loaded.model)),
        );

        let mut n_cur = n_past;
        let mut output_tokens: u32 = 0;
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut stream = StopStream::new(config.stop.clone());
        let mut batch = LlamaBatch::new(1, 1);

        // Row the current step reads logits from. `None` means "not readable",
        // which only happens for the first step after a multimodal prefill.
        let mut logits_row = first_logits;

        // TOPLOC commitment collection: one top-k logit record per
        // generated token, read from the raw logits the sampler chain
        // sees (the chain works on a copied token-data array, so the
        // row is unmodified).
        let commitment_k = config
            .commitment_k
            .map(|k| k.clamp(1, crate::toploc::MAX_COMMITMENT_K) as usize);
        let mut commitment_steps: Vec<crate::toploc::StepRecord> = Vec::new();

        let max_pos = n_ctx_val.min(n_past + config.max_tokens as i32);

        while n_cur < max_pos {
            let step_top_k = commitment_k
                .zip(logits_row)
                .map(|(k, row)| crate::toploc::top_k_from_logits(ctx.get_logits_ith(row), k));

            // Sample next token. `-1` is llama.cpp's "last logits row", the only
            // way to reach the row a multimodal prefill left behind.
            let token = sampler.sample(&*ctx, logits_row.unwrap_or(-1));
            sampler.accept(token);

            // Check for end of generation
            if loaded.model.is_eog_token(token) {
                break;
            }

            if let Some(top_k) = step_top_k {
                commitment_steps.push(crate::toploc::StepRecord {
                    token_id: token.0 as u32,
                    top_k,
                });
            }

            // Decode token to text
            match loaded.model.token_to_piece(token, &mut decoder, true, None) {
                Ok(piece) => {
                    // If the receiver is dropped, stop generating
                    if !stream.push(&piece, token_tx) {
                        output_tokens += 1;
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to decode token {}: {}", token.0, e);
                }
            }

            output_tokens += 1;

            if stream.hit_stop() {
                break;
            }

            // Prepare next batch with the sampled token
            batch.clear();
            batch
                .add(token, n_cur, &[0], true)
                .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;

            // Decode the new token
            ctx.decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Decode failed: {}", e)))?;

            // A one-token batch puts the only logits row at 0, and going
            // through `decode` records it as readable.
            logits_row = Some(0);
            n_cur += 1;
        }

        // Read before `finish` consumes the stream — `finish` sets `hit`
        // unconditionally to release held bytes.
        let stop_reason =
            StopReason::from_loop(stream.hit_stop(), output_tokens, config.max_tokens);
        let output_text = stream.finish(token_tx);

        let elapsed = start.elapsed();
        let generation_time_ms = elapsed.as_millis() as u64;
        let tokens_per_second = if generation_time_ms > 0 {
            (output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
        } else {
            0.0
        };

        let commitment = commitment_k
            .filter(|_| !commitment_steps.is_empty())
            .map(|k| crate::toploc::InferenceCommitment {
                k: k as u8,
                prompt_tokens: input_tokens,
                steps: commitment_steps,
            });

        Ok(InferenceResult {
            text: output_text,
            input_tokens,
            output_tokens,
            generation_time_ms,
            tokens_per_second,
            stop_reason,
            commitment,
        })
    }

    /// Give the rendered prompt one media marker per attachment.
    ///
    /// mtmd binds attachments to markers positionally, so the count has to
    /// match. A caller that placed its own markers is left alone; a caller that
    /// placed none gets them prepended to the last user turn, which is what a
    /// chat client sending images followed by a question means. A partial count
    /// is a caller bug, not something to paper over.
    #[cfg(feature = "mtmd")]
    fn place_media_markers(messages: &mut [ChatMessage], count: usize) -> Result<()> {
        let marker = media_marker();
        let placed: usize = messages
            .iter()
            .map(|m| m.content.matches(marker).count())
            .sum();

        if placed == count {
            return Ok(());
        }
        if placed != 0 {
            return Err(ModelError::InferenceError(format!(
                "prompt carries {} media marker(s) but {} attachment(s) were supplied — \
                 place one marker per attachment, or none at all to have them prepended \
                 to the last user turn",
                placed, count,
            )));
        }

        let last_user = messages
            .iter_mut()
            .rev()
            .find(|m| m.role == "user")
            .ok_or_else(|| {
                ModelError::InferenceError(
                    "multimodal request has no user turn to attach media to".to_string(),
                )
            })?;

        let markers = vec![marker; count].join("\n");
        last_user.content = format!("{}\n{}", markers, last_user.content);
        Ok(())
    }

    /// Synchronous multimodal generation: decode the attachments, interleave
    /// their embeddings into the prefill at the marker positions, then run the
    /// shared decode loop.
    #[cfg(feature = "mtmd")]
    fn generate_sync_multimodal(
        loaded: &LoadedModel,
        prompt: &str,
        media: &[Vec<u8>],
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        let start = Instant::now();

        let projector = loaded.projector.as_ref().ok_or_else(|| {
            ModelError::InferenceError(
                "model has no multimodal projector loaded — it serves text only".to_string(),
            )
        })?;

        // mtmd identifies image versus audio from the bytes. Refuse a modality
        // the projector has no tower for here, where the error can name the
        // attachment, rather than letting tokenize fail on the whole batch.
        let mut bitmaps = Vec::with_capacity(media.len());
        for (i, bytes) in media.iter().enumerate() {
            let bitmap = MtmdBitmap::from_buffer(projector, bytes).map_err(|e| {
                ModelError::InferenceError(format!("attachment {} could not be decoded: {}", i, e))
            })?;
            let (kind, supported) = if bitmap.is_audio() {
                ("audio", projector.support_audio())
            } else {
                ("an image", projector.support_vision())
            };
            if !supported {
                return Err(ModelError::InferenceError(format!(
                    "attachment {} is {}, which this projector has no tower for",
                    i, kind,
                )));
            }
            bitmaps.push(bitmap);
        }
        let bitmap_refs: Vec<&MtmdBitmap> = bitmaps.iter().collect();

        let chunks = projector
            .tokenize(
                MtmdInputText {
                    text: prompt.to_string(),
                    add_special: true,
                    parse_special: true,
                },
                &bitmap_refs,
            )
            .map_err(|e| {
                ModelError::InferenceError(format!("multimodal tokenization failed: {}", e))
            })?;

        let input_tokens = chunks.total_tokens() as u32;
        if input_tokens == 0 {
            return Err(ModelError::InferenceError(
                "prompt tokenized to zero tokens".to_string(),
            ));
        }

        let n_ctx = NonZeroU32::new(loaded.context_length)
            .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());
        let ctx_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx));
        let mut ctx = loaded
            .model
            .new_context(&loaded.backend, ctx_params)
            .map_err(|e| ModelError::Other(format!("Failed to create context: {}", e)))?;

        // Prefill. Text chunks go through llama_decode; image and audio chunks
        // are encoded by the projector and their embeddings decoded in place, in
        // the order the markers appeared.
        let n_batch = ctx.n_batch() as i32;
        let n_past = chunks
            .eval_chunks(projector, &ctx, 0, 0, n_batch, true)
            .map_err(|e| ModelError::InferenceError(format!("multimodal prefill failed: {}", e)))?;

        // `first_logits: None` — this prefill ran on the raw context, so no row
        // is recorded as readable and the first sample must use the `-1` index.
        Self::decode_loop(
            loaded,
            &mut ctx,
            n_past,
            input_tokens,
            config,
            None,
            None,
            start,
            // The multimodal prefill path does not carry a tool grammar.
            None,
        )
    }

    /// Speculative-decoding generation loop using llama.cpp's MTP
    /// helper. The target's catalog entry must declare
    /// `mtp_kind: MtpKind::DraftMtp`; the drafter is the
    /// jointly-trained MTP head sidecar GGUF (e.g. Gemma 4's
    /// `mtp-gemma-4-12B-it.gguf`).
    ///
    /// Loop shape per llama.cpp `common_speculative` semantics:
    /// 1. Tokenize prompt and prefill the target context.
    /// 2. Initialize `MtpSpeculative::begin(prompt)`.
    /// 3. Sample one token from the target to seed `id_last`.
    /// 4. Loop:
    ///    a. Ask the drafter for up to `n_max` candidate tokens
    ///    after `id_last`.
    ///    b. Batch-decode the candidates on the target.
    ///    c. Compare each candidate against the target's sample
    ///    and accept the longest matching prefix.
    ///    d. Notify the drafter how many were accepted.
    ///    e. Emit accepted tokens (+ the next target token) and
    ///    update `n_past` / `id_last`.
    ///
    /// Generation stops on EOG or `max_tokens`. Errors surface as
    /// `ModelError::MtpUnavailable` so the caller can degrade to
    /// single-token sampling by unsetting `draft_n`.
    fn generate_speculative(
        loaded: &LoadedModel,
        drafter: &LoadedDrafter,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        draft_n: u8,
    ) -> Result<InferenceResult> {
        let start = Instant::now();

        // Tokenize prompt
        let tokens_list = loaded
            .model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {}", e)))?;
        if tokens_list.is_empty() {
            return Err(ModelError::InferenceError(
                "prompt tokenized to zero tokens".to_string(),
            ));
        }
        let input_tokens = tokens_list.len() as u32;

        let n_ctx_target = NonZeroU32::new(loaded.context_length)
            .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());
        let n_ctx_draft = NonZeroU32::new(drafter.context_length)
            .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());

        // Build target + draft contexts.
        let target_ctx = loaded
            .model
            .new_context(
                &loaded.backend,
                LlamaContextParams::default().with_n_ctx(Some(n_ctx_target)),
            )
            .map_err(|e| {
                ModelError::Other(format!(
                    "Failed to create target context for speculative decoding: {}",
                    e
                ))
            })?;
        let draft_ctx = drafter
            .model
            .new_context(
                &drafter.backend,
                LlamaContextParams::default().with_n_ctx(Some(n_ctx_draft)),
            )
            .map_err(|e| {
                ModelError::Other(format!(
                    "Failed to create draft context for speculative decoding: {}",
                    e
                ))
            })?;

        // Build the MTP speculative helper. `n_max` caps draft length;
        // Unsloth's recommendation is 2 to start, callers may pass
        // 1..=6.
        let mut spec = MtpSpeculative::new(
            target_ctx,
            draft_ctx,
            MtpSpeculativeParams {
                n_max: draft_n as i32,
                n_min: 0,
                p_min: 0.0,
            },
        )
        .map_err(|e| ModelError::MtpUnavailable {
            reason: format!("MtpSpeculative init failed: {}", e),
        })?;

        // Begin a new generation with the prompt tokens.
        spec.begin(&tokens_list)
            .map_err(|e| ModelError::MtpUnavailable {
                reason: format!("MtpSpeculative begin failed: {}", e),
            })?;

        // Prefill the target context with the prompt, in `n_batch`-sized
        // decode calls.
        let prompt_logits_row = Self::prefill_in_batches(spec.target_context_mut(), &tokens_list)?;

        // Reused by every speculative step below, which carries at most
        // `draft_n` candidates — or one token when the drafter declines. The
        // prompt no longer sizes this batch: it is prefilled separately, in
        // `n_batch`-sized calls.
        let mut batch = LlamaBatch::new((draft_n as usize).max(1), 1);

        // Same chain as the single-token path. The drafter only PROPOSES
        // tokens; the target's sampler decides which are kept.
        let mut sampler = build_sampler_chain(config);

        let mut n_cur = tokens_list.len() as i32;
        let mut output_tokens: u32 = 0;
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut stream = StopStream::new(config.stop.clone());
        let max_pos =
            (n_ctx_target.get() as i32).min(input_tokens as i32 + config.max_tokens as i32);

        // Seed `id_last` by sampling one token from the target. The
        // drafter conditions its draft on this token.
        let mut id_last = sampler.sample(spec.target_context_mut(), prompt_logits_row);
        sampler.accept(id_last);

        // Emit the seed token.
        if loaded.model.is_eog_token(id_last) {
            return Ok(InferenceResult {
                text: stream.finish(token_tx),
                input_tokens,
                output_tokens,
                generation_time_ms: start.elapsed().as_millis() as u64,
                tokens_per_second: 0.0,
                stop_reason: StopReason::Eos,
                commitment: None,
            });
        }
        let mut seed_open = true;
        match loaded
            .model
            .token_to_piece(id_last, &mut decoder, true, None)
        {
            Ok(piece) => {
                // Receiver dropped, or the seed token already completed a stop
                // sequence — either way there is nothing further to generate.
                seed_open = stream.push(&piece, token_tx) && !stream.hit_stop();
            }
            Err(e) => warn!("Failed to decode seed token {}: {}", id_last.0, e),
        }
        output_tokens += 1;
        n_cur += 1;
        if !seed_open {
            let stop_reason =
                StopReason::from_loop(stream.hit_stop(), output_tokens, config.max_tokens);
            return Ok(InferenceResult {
                text: stream.finish(token_tx),
                input_tokens,
                output_tokens,
                generation_time_ms: start.elapsed().as_millis() as u64,
                tokens_per_second: 0.0,
                stop_reason,
                commitment: None,
            });
        }

        // Speculative loop.
        let mut prompt_so_far: Vec<llama_cpp_2::token::LlamaToken> = tokens_list.clone();
        prompt_so_far.push(id_last);

        while n_cur < max_pos && !loaded.model.is_eog_token(id_last) {
            // 1. Ask the drafter for candidates.
            let drafts = match spec.draft(n_cur, id_last, &prompt_so_far) {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "Speculative draft failed at n_past={}: {} — falling back to single-token sample",
                        n_cur, e
                    );
                    Vec::new()
                }
            };

            if drafts.is_empty() {
                // No draft produced — fall back to a single-token
                // sample on the target. This keeps the loop making
                // progress when the drafter refuses (low confidence,
                // edge of context, etc.).
                batch.clear();
                batch
                    .add(id_last, n_cur, &[0], true)
                    .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;
                spec.target_context_mut()
                    .decode(&mut batch)
                    .map_err(|e| ModelError::Other(format!("Decode failed: {}", e)))?;
                let next = sampler.sample(spec.target_context_mut(), batch.n_tokens() - 1);
                sampler.accept(next);
                if loaded.model.is_eog_token(next) {
                    break;
                }
                let mut open = true;
                if let Ok(piece) = loaded.model.token_to_piece(next, &mut decoder, true, None) {
                    open = stream.push(&piece, token_tx) && !stream.hit_stop();
                }
                output_tokens += 1;
                n_cur += 1;
                if !open {
                    break;
                }
                prompt_so_far.push(next);
                id_last = next;
                continue;
            }

            // 2. Batch-decode the draft candidates on the target.
            //    We add `id_last` first at position n_cur-1 so the
            //    target has a logit slot for the FIRST draft slot.
            //    Actually llama.cpp's pattern: we decoded id_last in
            //    the previous turn, so its logits sit at the last
            //    slot. For each draft token we add it to the batch
            //    and ask the target to produce logits at THAT slot
            //    so we can decide accept/reject by comparing the
            //    target's sample with the draft.
            batch.clear();
            for (i, draft_tok) in drafts.iter().enumerate() {
                let pos = n_cur + i as i32;
                batch
                    .add(*draft_tok, pos, &[0], true)
                    .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;
            }
            spec.target_context_mut().decode(&mut batch).map_err(|e| {
                ModelError::Other(format!("Target speculative decode failed: {}", e))
            })?;

            // 3. Accept / reject by comparing target samples to drafts.
            let mut n_accepted: u16 = 0;
            for (i, draft_tok) in drafts.iter().enumerate() {
                let logit_idx = i as i32;
                let target_sample = sampler.sample(spec.target_context_mut(), logit_idx);
                sampler.accept(target_sample);
                if target_sample == *draft_tok {
                    n_accepted += 1;
                    id_last = target_sample;
                    prompt_so_far.push(target_sample);
                    if loaded.model.is_eog_token(target_sample) {
                        break;
                    }
                    let mut open = true;
                    if let Ok(piece) =
                        loaded
                            .model
                            .token_to_piece(target_sample, &mut decoder, true, None)
                    {
                        open = stream.push(&piece, token_tx) && !stream.hit_stop();
                    }
                    output_tokens += 1;
                    if !open {
                        // Receiver dropped, or a stop sequence completed.
                        spec.accept(n_accepted)
                            .map_err(|e| ModelError::MtpUnavailable {
                                reason: format!("MtpSpeculative accept failed: {}", e),
                            })?;
                        let stop_reason = StopReason::from_loop(
                            stream.hit_stop(),
                            output_tokens,
                            config.max_tokens,
                        );
                        return Ok(InferenceResult {
                            text: stream.finish(token_tx),
                            input_tokens,
                            output_tokens,
                            generation_time_ms: start.elapsed().as_millis() as u64,
                            tokens_per_second: 0.0,
                            stop_reason,
                            commitment: None,
                        });
                    }
                } else {
                    // First rejection — keep the target's sample as
                    // the next id_last and stop accepting drafts.
                    id_last = target_sample;
                    prompt_so_far.push(target_sample);
                    if loaded.model.is_eog_token(target_sample) {
                        break;
                    }
                    let mut open = true;
                    if let Ok(piece) =
                        loaded
                            .model
                            .token_to_piece(target_sample, &mut decoder, true, None)
                    {
                        open = stream.push(&piece, token_tx) && !stream.hit_stop();
                    }
                    output_tokens += 1;
                    if !open {
                        spec.accept(n_accepted)
                            .map_err(|e| ModelError::MtpUnavailable {
                                reason: format!("MtpSpeculative accept failed: {}", e),
                            })?;
                        let stop_reason = StopReason::from_loop(
                            stream.hit_stop(),
                            output_tokens,
                            config.max_tokens,
                        );
                        return Ok(InferenceResult {
                            text: stream.finish(token_tx),
                            input_tokens,
                            output_tokens,
                            generation_time_ms: start.elapsed().as_millis() as u64,
                            tokens_per_second: 0.0,
                            stop_reason,
                            commitment: None,
                        });
                    }
                    break;
                }
            }

            // 4. Tell the drafter how many were accepted so it can
            //    advance its own KV cache.
            spec.accept(n_accepted)
                .map_err(|e| ModelError::MtpUnavailable {
                    reason: format!("MtpSpeculative accept failed: {}", e),
                })?;

            // 5. Advance n_cur by accepted + 1 (the extra sampled token).
            n_cur += n_accepted as i32 + 1;

            if loaded.model.is_eog_token(id_last) {
                break;
            }
        }

        let elapsed = start.elapsed();
        let generation_time_ms = elapsed.as_millis() as u64;
        let tokens_per_second = if generation_time_ms > 0 {
            (output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
        } else {
            0.0
        };
        let stop_reason =
            StopReason::from_loop(stream.hit_stop(), output_tokens, config.max_tokens);
        Ok(InferenceResult {
            text: stream.finish(token_tx),
            input_tokens,
            output_tokens,
            generation_time_ms,
            tokens_per_second,
            stop_reason,
            commitment: None,
        })
    }
}

/// Flatten a chat message list into the byte sequence used to fingerprint a
/// warm prefix. This is the user-visible prompt content in message order
/// (`content` fields joined by newline), NOT the model's rendered chat
/// template — the requesting router hashes the same content bytes from
/// `InferenceRequest.input`, so hashing the content (not the template) is what
/// lets the two sides agree on a shared prefix regardless of model family.
/// For the common single-user-message forward path this equals
/// `InferenceRequest.input` exactly.
fn warm_prompt_bytes(messages: &[ChatMessage]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(m.content.as_bytes());
    }
    out
}

/// Apply the model's chat template to a message list, producing the flat
/// prompt string the serial generation path decodes. Mirrors the batched
/// scheduler's `render_prompt` so both serving modes template identically.
fn render_chat_prompt(model: &LlamaModel, messages: &[ChatMessage]) -> Result<String> {
    let llama_messages: Vec<LlamaChatMessage> = messages
        .iter()
        .map(|m| {
            LlamaChatMessage::new(m.role.clone(), m.content.clone())
                .map_err(|e| ModelError::Other(format!("Invalid chat message: {}", e)))
        })
        .collect::<Result<Vec<_>>>()?;

    // First choice: the GGUF's embedded chat template, rendered by
    // llama.cpp's minja engine. Some modern templates (Qwen3's 4.9 KB
    // Jinja with tool/reasoning branches) render to an empty string on
    // this llama.cpp build instead of erroring — minja returns success
    // with a zero-length body. An empty prompt tokenizes to zero tokens
    // and `llama_decode` then fails with `n_tokens == 0`. Treat an
    // empty/whitespace render as a miss and fall back to ChatML.
    if let Ok(tmpl) = model.chat_template(None)
        && let Ok(rendered) = model.apply_chat_template(&tmpl, &llama_messages, true)
    {
        if !rendered.trim().is_empty() {
            return Ok(rendered);
        }
        warn!("GGUF chat template rendered empty; falling back to ChatML");
    }

    Ok(render_chatml_prompt(messages))
}

/// Family-agnostic ChatML fallback used when the model's embedded GGUF
/// template is absent or renders empty. ChatML (`<|im_start|>role\n…
/// <|im_end|>`) is the format Qwen, Yi, and most modern instruct models
/// were trained on; the special tokens are in their vocab, so tokenizing
/// this string with `parse_special = true` recovers the intended token
/// stream. Ends with the assistant open turn so generation continues.
pub(crate) fn render_chatml_prompt(messages: &[ChatMessage]) -> String {
    let mut out = String::new();
    for m in messages {
        out.push_str("<|im_start|>");
        out.push_str(&m.role);
        out.push('\n');
        out.push_str(&m.content);
        out.push_str("<|im_end|>\n");
    }
    out.push_str("<|im_start|>assistant\n");
    out
}

/// Render a list of tool schemas into a system-prompt preamble that
/// generalizes across model families. We use Anthropic-style XML-ish
/// framing since most modern instruction-tuned models (Qwen, Llama,
/// Mistral, Gemma) have seen tool prompts in training and adapt to it.
fn render_tools_preamble(tools: &[ToolDefinition]) -> String {
    let mut out = String::new();
    // The instruction is written as a worked example rather than as a
    // `<tool_call>...</tool_call>` schematic on purpose. Models copy what they
    // are shown between the tags, ellipsis included: given the schematic form,
    // Qwen 3.6 emits `<tool_call>...\n{"name": ...}\n</tool_call>` — correct
    // JSON preceded by a literal `...`, which fails to parse and silently
    // costs the caller the entire tool call. Showing one concrete call leaves
    // nothing to copy but the shape.
    out.push_str(
        "You have access to the following tools. To call a tool, write a \
         single JSON object between a <tool_call> tag and a </tool_call> \
         tag, like this:\n\n\
         <tool_call>\n\
         {\"name\": \"example_tool\", \"input\": {\"first_argument\": \"a value\"}}\n\
         </tool_call>\n\n\
         Put nothing but that JSON object between the tags. Only call a tool \
         when needed.\n\n\
         <tools>\n",
    );
    for t in tools {
        out.push_str("  <tool>\n");
        out.push_str(&format!("    <name>{}</name>\n", t.name));
        if let Some(desc) = &t.description {
            out.push_str(&format!("    <description>{}</description>\n", desc));
        }
        out.push_str("    <input_schema>\n");
        out.push_str(&serde_json::to_string(&t.input_schema).unwrap_or_else(|_| "{}".to_string()));
        out.push_str("\n    </input_schema>\n");
        out.push_str("  </tool>\n");
    }
    out.push_str("</tools>");
    out
}

/// Put the tool preamble in front of the conversation.
///
/// An existing system message absorbs the preamble so the model still sees a
/// single system turn; otherwise a synthetic one is inserted at the head. An
/// empty tool list leaves the conversation untouched.
fn inject_tools_preamble(messages: &mut Vec<ChatMessage>, tools: &[ToolDefinition]) {
    if tools.is_empty() {
        return;
    }
    let preamble = render_tools_preamble(tools);
    match messages.first_mut() {
        Some(first) if first.role == "system" => {
            first.content = format!("{}\n\n{}", first.content, preamble);
        }
        _ => messages.insert(
            0,
            ChatMessage {
                role: "system".to_string(),
                content: preamble,
            },
        ),
    }
}

/// Scan raw model output for tool-call markers and return
/// `(clean_text, tool_calls)` with all markers stripped from the text.
///
/// Recognized formats (in priority order):
/// - `<tool_call>{json}</tool_call>` — Qwen 3, our preamble's canonical form
/// - `<|python_tag|>{json}<|eom_id|>` or `<|python_tag|>{json}` — Llama 3.x
/// - `[TOOL_CALLS] [{json}, ...]` — Mistral/Mixtral function-calling
/// - Bare top-level JSON object with `{"name":..., "input":...}` — fallback
///   (only consumed if it spans the entire trimmed output).
pub(crate) fn extract_tool_calls(raw: &str) -> (String, Vec<ToolCall>) {
    let mut calls: Vec<ToolCall> = Vec::new();
    let mut text = raw.to_string();

    // ── Qwen 3 / canonical: <tool_call>...</tool_call> ────────────────
    while let Some(start) = text.find("<tool_call>") {
        let after_open = start + "<tool_call>".len();
        let Some(rel_end) = text[after_open..].find("</tool_call>") else {
            break;
        };
        let end = after_open + rel_end;
        let close_end = end + "</tool_call>".len();

        // Parse from the first `{` rather than from the start of the body.
        // Models routinely put a few stray characters after the opening tag —
        // a copied `...` placeholder, a stray `json` fence, a newline and a
        // word — and dropping the call over that loses the whole turn even
        // though the JSON that follows is exactly right. The object still has
        // to parse, so this widens what is tolerated, not what is accepted.
        let body = text[after_open..end].trim();
        let json = body.find('{').map(|i| &body[i..]).unwrap_or(body);
        if let Some(call) = parse_tool_call_json(json)
            .or_else(|| repair_key_separators(json).and_then(|r| parse_tool_call_json(&r)))
            .or_else(|| parse_xml_tool_call_body(body))
            .or_else(|| parse_tool_call_lenient(body))
        {
            calls.push(call);
        }
        text.replace_range(start..close_end, "");
    }

    // ── Anthropic-shaped: <tool_use id="…" name="…">{json}</tool_use> ─
    //
    // Not a format any local model is trained on — it is the shape an agent's
    // own system prompt and prior turns put in front of the model, and models
    // imitate their context. `qwen3.6-35b-a3b-mtp` reaches for it mid-session
    // once earlier assistant turns carrying tool calls are in the history,
    // even when the template taught it `<function=…>`. Unread, the turn looks
    // to the caller like the model declining to act.
    //
    // The tool name is an attribute rather than a JSON field here, so the
    // whole body is the argument object.
    while let Some(start) = text.find("<tool_use ") {
        let Some(rel_gt) = text[start..].find('>') else {
            break;
        };
        let open_end = start + rel_gt + 1;
        let Some(rel_end) = text[open_end..].find("</tool_use>") else {
            break;
        };
        let end = open_end + rel_end;
        let close_end = end + "</tool_use>".len();

        let attrs = &text[start..open_end];
        if let Some(name) = xml_attr(attrs, "name") {
            let body = text[open_end..end].trim();
            let json = body.find('{').map(|i| &body[i..]).unwrap_or(body);
            let input = find_balanced_close(json, 0, '{', '}')
                .and_then(|close| serde_json::from_str(&json[..=close]).ok())
                .unwrap_or_else(|| serde_json::json!({}));
            calls.push(ToolCall {
                id: xml_attr(attrs, "id")
                    .unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4().simple())),
                name,
                input,
            });
        }
        text.replace_range(start..close_end, "");
    }

    // ── Llama 3.x: <|python_tag|>{json}(<|eom_id|>|<|eot_id|>|EOS) ────
    while let Some(start) = text.find("<|python_tag|>") {
        let after_open = start + "<|python_tag|>".len();
        // Terminate at the next Llama special token or end-of-string.
        let candidates = ["<|eom_id|>", "<|eot_id|>"];
        let term = candidates
            .iter()
            .filter_map(|t| text[after_open..].find(t).map(|i| (i, t.len())))
            .min_by_key(|(i, _)| *i);
        let (body, close_end) = match term {
            Some((rel, term_len)) => (
                text[after_open..after_open + rel].trim().to_string(),
                after_open + rel + term_len,
            ),
            None => (text[after_open..].trim().to_string(), text.len()),
        };
        if let Some(call) = parse_tool_call_json(&body) {
            calls.push(call);
        }
        text.replace_range(start..close_end, "");
    }

    // ── Mistral/Mixtral: [TOOL_CALLS] [{...}, ...] ───────────────────
    if let Some(start) = text.find("[TOOL_CALLS]") {
        let after = start + "[TOOL_CALLS]".len();
        // Find the JSON array immediately after the marker.
        let rest = &text[after..];
        let trimmed_offset = rest.len() - rest.trim_start().len();
        let array_start_abs = after + trimmed_offset;
        if let Some(end_abs) = find_balanced_close(&text, array_start_abs, '[', ']') {
            let body = &text[array_start_abs..=end_abs];
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body)
                && let Some(arr) = v.as_array()
            {
                for item in arr {
                    if let Some(call) = parse_tool_call_value(item) {
                        calls.push(call);
                    }
                }
            }
            text.replace_range(start..=end_abs, "");
        }
    }

    // ── Bare JSON object fallback ────────────────────────────────────
    // Only fire if (a) we haven't already extracted any calls and (b) the
    // entire trimmed output parses as a `{name, input}` object. This
    // avoids stealing free-text replies that just happen to contain `{`.
    if calls.is_empty() {
        let trimmed = text.trim();
        if trimmed.starts_with('{')
            && trimmed.ends_with('}')
            && let Some(call) = parse_tool_call_json(trimmed)
        {
            calls.push(call);
            text.clear();
        }
    }

    (text.trim().to_string(), calls)
}

/// Parse a single tool-call JSON object. Accepts both
/// `{"name":..., "input":...}` (our canonical form, also Qwen) and
/// `{"name":..., "arguments":...}` (Mistral/OpenAI-style).
/// Value of a double-quoted XML attribute in an opening tag, e.g. `name` in
/// `<tool_use id="x" name="bash">`.
///
/// Deliberately minimal: these tags come from a model imitating its own
/// context, not from an XML document, so there are no namespaces, entities or
/// single-quoted forms to honour — and treating the input as XML would invite
/// a parser where a `find` will do.
fn xml_attr(tag: &str, attr: &str) -> Option<String> {
    let pat = format!("{attr}=\"");
    let start = tag.find(&pat)? + pat.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    let value = &rest[..end];
    (!value.is_empty()).then(|| value.to_string())
}

/// Recover a tool call from a `<tool_call>` body that is not valid JSON, by
/// anchoring on the field names instead of the punctuation between them.
///
/// This is the last of four attempts, and it exists because the first three
/// were each written for one observed corruption and the model kept producing
/// a new one. From `qwen3.6-35b-a3b-mtp`, on three prompts differing only in
/// how many tools were offered and how long the system prompt was:
///
/// ```text
/// {"name">"read_file", "input": {"path": "src/parser.rs"}}   // `>` for `:`
/// {"name": "read_file",\n{"input": {"path": "src/parser.rs"}}  // stray `{`
/// {"name">"read_file"</name><arg_key>path</arg_key>…          // XML bleed
/// ```
///
/// Every one names the function and its arguments unambiguously and differs
/// only in the punctuation joining them, so keying on `"name"` and `"input"`
/// and reading the balanced object that follows recovers all three and does
/// not need editing for the fourth. The argument object still has to parse as
/// JSON — models corrupt the joins between fields far more readily than the
/// values inside them — so this widens which wrappers are tolerated, not what
/// counts as a valid call.
///
/// Only ever applied inside a `<tool_call>` span, which this model emits when
/// it is calling a tool and not otherwise, so the looser matching cannot
/// promote ordinary prose into a call.
fn parse_tool_call_lenient(body: &str) -> Option<ToolCall> {
    /// Byte offset just past `"field"`, searched outside of nothing in
    /// particular — the body is already known not to be valid JSON.
    fn field_end(hay: &str, field: &str) -> Option<usize> {
        let pat = format!("\"{}\"", field);
        hay.find(&pat).map(|i| i + pat.len())
    }

    /// Skip whitespace and any separator the model might have used.
    fn skip_separator(hay: &str, mut i: usize) -> usize {
        for (off, c) in hay[i..].char_indices() {
            if c.is_whitespace() || c == ':' || c == '>' || c == '=' || c == ',' {
                continue;
            }
            return i + off;
        }
        i = hay.len();
        i
    }

    let name_at = skip_separator(body, field_end(body, "name")?);
    let rest = &body[name_at..];
    if !rest.starts_with('"') {
        return None;
    }
    let mut name = String::new();
    let mut escaped = false;
    for c in rest[1..].chars() {
        if escaped {
            name.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            break;
        } else {
            name.push(c);
        }
    }
    if name.is_empty() {
        return None;
    }

    let input = ["input", "arguments", "parameters"]
        .iter()
        .find_map(|field| {
            let at = skip_separator(body, field_end(body, field)?);
            let open = body[at..].find('{')? + at;
            let close = find_balanced_close(body, open, '{', '}')?;
            serde_json::from_str::<serde_json::Value>(&body[open..=close]).ok()
        })
        .unwrap_or_else(|| serde_json::json!({}));

    Some(ToolCall {
        id: format!("toolu_{}", uuid::Uuid::new_v4().simple()),
        name,
        input,
    })
}

/// Repair `"key">value` back to `"key":value` in a tool-call body.
///
/// Models trained to emit XML tool calls leak the habit into JSON when a
/// preamble asks for JSON instead. Qwen 3.6 writes
///
/// ```text
/// {"name">"read_file", "input": {"path": "src/parser.rs"}}
/// ```
///
/// — one wrong character, `>` where the key separator belongs, and everything
/// else exactly right. Left alone it costs the whole call and stalls the
/// agent, which is a poor trade for a defect this small.
///
/// The substitution is made only where a colon is the sole legal character:
/// directly after a string that opened in key position (first member of an
/// object, or just past a comma), never inside a string. That keeps a value
/// like `{"html": "<a href=\"x\">"}` untouched. Returns `None` when there was
/// nothing to repair, so the caller can tell a repair from a no-op, and the
/// result still has to parse — this widens what is recovered, not what is
/// accepted.
fn repair_key_separators(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut repaired = false;

    // Last structural character seen outside a string; a key may start only
    // after `{` or `,`.
    let mut prev_structural = '\0';
    let mut chars = s.char_indices().peekable();

    while let Some((_, c)) = chars.next() {
        if c != '"' {
            if !c.is_whitespace() {
                prev_structural = c;
            }
            out.push(c);
            continue;
        }

        // Copy the string literal verbatim, honouring escapes.
        let in_key_position = prev_structural == '{' || prev_structural == ',';
        out.push('"');
        let mut escaped = false;
        for (_, sc) in chars.by_ref() {
            out.push(sc);
            if escaped {
                escaped = false;
            } else if sc == '\\' {
                escaped = true;
            } else if sc == '"' {
                break;
            }
        }

        if !in_key_position {
            prev_structural = '"';
            continue;
        }

        // Whitespace, then the separator.
        while let Some((_, w)) = chars.peek() {
            if w.is_whitespace() {
                out.push(*w);
                chars.next();
            } else {
                break;
            }
        }
        match chars.peek() {
            Some((_, '>')) => {
                out.push(':');
                chars.next();
                repaired = true;
                prev_structural = ':';
            }
            _ => prev_structural = '"',
        }
    }

    repaired.then_some(out)
}

/// Parse the XML argument dialect that some instruct models emit inside a
/// `<tool_call>` span instead of a JSON object.
///
/// Qwen 3.6 and the GLM-4.5/4.6 family are trained to write arguments as
/// `<arg_key>k</arg_key><arg_value>v</arg_value>` pairs, and Qwen 3 Coder as
/// `<parameter=k>v</parameter>`. Told in a system preamble to emit JSON
/// instead, they blend the two — the observed output for the tools preamble is
///
/// ```text
/// <tool_call>
/// {"name">"read_file"</name>
/// <arg_key>path</arg_key><arg_value>"src/parser.rs"</arg_value>
/// </tool_call>
/// ```
///
/// which is neither valid JSON nor clean XML, but names the function and every
/// argument unambiguously. Upstream llama.cpp treats these as first-class
/// dialects rather than errors (`common/chat-auto-parser.h` enumerates
/// `<arg_key>` and `<param=` among its name/argument delimiters), and so do we:
/// the alternative is discarding a call the model got right in substance and
/// stalling the agent loop.
///
/// Returns `None` unless both a name and at least one delimiter were found, so
/// prose that merely mentions the tags cannot masquerade as a call.
fn parse_xml_tool_call_body(body: &str) -> Option<ToolCall> {
    /// Text between the first `open` and the following `close`, plus the
    /// offset just past `close`.
    fn between<'a>(hay: &'a str, from: usize, open: &str, close: &str) -> Option<(&'a str, usize)> {
        let s = hay[from..].find(open)? + from + open.len();
        let e = hay[s..].find(close)? + s;
        Some((&hay[s..e], e + close.len()))
    }

    let mut input = serde_json::Map::new();

    // `<arg_key>k</arg_key> <arg_value>v</arg_value>` pairs.
    let mut cursor = 0usize;
    while let Some((key, after_key)) = between(body, cursor, "<arg_key>", "</arg_key>") {
        let Some((value, after_value)) = between(body, after_key, "<arg_value>", "</arg_value>")
        else {
            break;
        };
        input.insert(key.trim().to_string(), xml_arg_value(value));
        cursor = after_value;
    }

    // `<parameter=k>v</parameter>` pairs.
    let mut cursor = 0usize;
    while let Some((key, after_key)) = between(body, cursor, "<parameter=", ">") {
        let Some((value, after_value)) = between(body, after_key, "", "</parameter>") else {
            break;
        };
        input.insert(key.trim().to_string(), xml_arg_value(value));
        cursor = after_value;
    }

    // The name sits ahead of the first argument delimiter. Prefer the last
    // quoted string there — in `{"name">"read_file"</name>` that is the value
    // rather than the `"name"` label — and fall back to the last bare word,
    // which is the shape GLM's own `<tool_call>fn_name` header uses.
    let head_end = ["<arg_key>", "<parameter=", "<arg_value>"]
        .iter()
        .filter_map(|d| body.find(d))
        .min()
        .unwrap_or(body.len());
    let head = &body[..head_end];

    let quoted: Vec<&str> = head.split('"').skip(1).step_by(2).collect();
    let name = quoted
        .iter()
        .rev()
        .find(|s| !s.trim().is_empty() && *s != &"name")
        .map(|s| s.trim().to_string())
        .or_else(|| {
            head.rsplit(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
                .find(|w| !w.is_empty() && *w != "name")
                .map(|w| w.to_string())
        })?;

    if input.is_empty() && head_end == body.len() {
        return None;
    }

    Some(ToolCall {
        id: format!("toolu_{}", uuid::Uuid::new_v4().simple()),
        name,
        input: serde_json::Value::Object(input),
    })
}

/// Coerce one XML-carried argument value. JSON first, so `3`, `true` and
/// `{"a":1}` keep their types and a quoted `"src/parser.rs"` loses its quotes;
/// anything else is the literal text.
fn xml_arg_value(raw: &str) -> serde_json::Value {
    let t = raw.trim();
    serde_json::from_str::<serde_json::Value>(t)
        .unwrap_or_else(|_| serde_json::Value::String(t.to_string()))
}

fn parse_tool_call_json(body: &str) -> Option<ToolCall> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    parse_tool_call_value(&v)
}

fn parse_tool_call_value(v: &serde_json::Value) -> Option<ToolCall> {
    let obj = v.as_object()?;
    let name = obj.get("name")?.as_str()?.to_string();
    let input = obj
        .get("input")
        .or_else(|| obj.get("arguments"))
        .or_else(|| obj.get("parameters"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    // Some models nest arguments as a JSON-encoded string.
    let input = if let Some(s) = input.as_str() {
        serde_json::from_str::<serde_json::Value>(s)
            .unwrap_or(serde_json::Value::String(s.to_string()))
    } else {
        input
    };
    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4().simple()));
    Some(ToolCall { id, name, input })
}

/// Find the index of the closing bracket that balances the opener at
/// `start`. Naïve scanner — does not honor strings/escapes inside JSON,
/// which is fine because we feed it the slice that begins at the opener
/// and bail if `serde_json` later fails.
fn find_balanced_close(text: &str, start: usize, open: char, close: char) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(start)? != &(open as u8) {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        let c = b as char;
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_config_default() {
        let config = GenerationConfig::default();
        assert!((config.temperature - 0.7).abs() < f64::EPSILON);
        assert_eq!(config.max_tokens, 512);
    }

    #[test]
    fn test_chat_message() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "Hello".to_string(),
        };
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello");
    }

    #[test]
    fn chatml_fallback_renders_turns_and_open_assistant() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: "be terse".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "hi".to_string(),
            },
        ];
        let rendered = render_chatml_prompt(&messages);
        assert_eq!(
            rendered,
            "<|im_start|>system\nbe terse<|im_end|>\n\
             <|im_start|>user\nhi<|im_end|>\n\
             <|im_start|>assistant\n"
        );
        assert!(!rendered.trim().is_empty());
    }

    #[test]
    fn extract_json_body_in_tool_call_tags() {
        let raw = "Sure thing.\n<tool_call>\n{\"name\": \"get_weather\", \"input\": {\"city\": \"Tokyo\"}}\n</tool_call>\nAnything else?";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].input["city"], "Tokyo");
        assert!(!text.contains("<tool_call>"));
        assert!(text.contains("Sure thing"));
        assert!(text.contains("Anything else"));
    }

    /// Junk between the opening tag and the JSON.
    ///
    /// Any model shown a `<tool_call>...</tool_call>` schematic may copy the
    /// ellipsis in ahead of an otherwise perfect call — first seen on a Qwen
    /// 3.6 build, but it is a property of the instruction, not of that model.
    /// The preamble no longer invites it; the tolerance stays because a stray
    /// token before the body must not cost the whole call.
    #[test]
    fn extract_tool_call_with_junk_before_the_json() {
        let raw = "<tool_call>...\n{\"name\": \"get_weather\", \"input\": {\"city\": \"Tokyo\"}}\n</tool_call>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].input["city"], "Tokyo");
        assert!(!text.contains("<tool_call>"));
    }

    /// The preamble is what the model imitates, so it must not contain a
    /// `<tool_call>` span whose body is anything but a valid JSON object.
    #[test]
    fn tools_preamble_shows_only_parseable_tool_call_bodies() {
        let preamble = render_tools_preamble(&[ToolDefinition {
            name: "get_weather".to_string(),
            description: Some("Get current weather".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
        }]);

        let (_text, calls) = extract_tool_calls(&preamble);
        assert_eq!(
            calls.len(),
            1,
            "the worked example in the preamble must itself parse as a tool call"
        );
        assert_eq!(calls[0].name, "example_tool");
    }

    /// The `<arg_key>`/`<arg_value>` argument dialect, blended into JSON.
    ///
    /// Trained into the GLM-4.5/4.6 family and reachable from any model
    /// carrying those tokens. This sample came from a Qwen 3.6 build told to
    /// emit JSON instead, which produced a hybrid of the two: neither valid
    /// JSON nor clean XML, but unambiguous as a call.
    #[test]
    fn extract_arg_key_value_dialect() {
        let raw = "<think>\n\n</think>\n\n<tool_call>\n{\"name\">\"read_file\"</name>\n\
                   <arg_key>path</arg_key><arg_value>\"src/parser.rs\"</arg_value>\n</tool_call>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].input["path"], "src/parser.rs");
        assert!(!text.contains("<tool_call>"));
        assert!(!text.contains("arg_key"));
    }

    #[test]
    fn extract_xml_tool_call_typed_and_multi_arg() {
        let raw = "<tool_call>edit_file\n\
                   <arg_key>path</arg_key><arg_value>src/lib.rs</arg_value>\n\
                   <arg_key>count</arg_key><arg_value>3</arg_value>\n\
                   <arg_key>dry</arg_key><arg_value>true</arg_value>\n</tool_call>";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "edit_file");
        // Unquoted text stays a string; JSON scalars keep their type.
        assert_eq!(calls[0].input["path"], "src/lib.rs");
        assert_eq!(calls[0].input["count"], 3);
        assert_eq!(calls[0].input["dry"], true);
    }

    #[test]
    fn extract_function_parameter_dialect() {
        let raw = "<tool_call>\n<function=read_file>\n<parameter=path>src/parser.rs</parameter>\n</function>\n</tool_call>";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].input["path"], "src/parser.rs");
    }

    /// Prose that merely mentions the tags is not a call — the XML fallback
    /// must not manufacture one out of a bare `<tool_call>` span.
    #[test]
    fn xml_fallback_does_not_invent_calls_from_prose() {
        let raw = "<tool_call>I was going to call a tool but changed my mind.</tool_call>";
        let (_text, calls) = extract_tool_calls(raw);
        assert!(calls.is_empty(), "got {:?}", calls);
    }

    /// One wrong character: `>` where the key separator belongs.
    ///
    /// The failure mode of a model that carries XML tool tokens being asked
    /// for JSON — the tag habit leaks into the separator. Sampled from a Qwen
    /// 3.6 build; nothing about the repair is specific to it.
    #[test]
    fn extract_tool_call_with_angle_bracket_key_separator() {
        let raw = "<think>\n\n</think>\n\n<tool_call>\n\
                   {\"name\">\"read_file\", \"input\": {\"path\": \"src/parser.rs\"}}\n</tool_call>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].input["path"], "src/parser.rs");
        assert!(!text.contains("<tool_call>"));
    }

    /// The repair must not reach inside string values — a `">` that is part of
    /// markup being passed as an argument has to survive intact.
    #[test]
    fn key_separator_repair_leaves_string_values_alone() {
        let body = "{\"name\">\"write\", \"input\": {\"html\": \"<a href=\\\"x\\\">link</a>\"}}";
        let repaired = repair_key_separators(body).expect("the name separator needs repair");
        let call = parse_tool_call_json(&repaired).expect("repaired body must parse");
        assert_eq!(call.name, "write");
        assert_eq!(call.input["html"], "<a href=\"x\">link</a>");
    }

    #[test]
    fn key_separator_repair_is_none_when_nothing_is_broken() {
        assert!(repair_key_separators("{\"name\": \"ok\", \"input\": {}}").is_none());
    }

    /// A stray `{` opens a second object where the first should have
    /// continued.
    ///
    /// Longer tool arrays and longer system prompts make this likelier in any
    /// model; this sample is from a 9-tool, 1.5 KB-system prompt on a Qwen 3.6
    /// build.
    #[test]
    fn extract_tool_call_with_stray_brace_before_input() {
        let raw = "<think>\n\n</think>\n\n<tool_call>\n\
                   {\"name\": \"read_file\",\n{\"input\": {\"path\": \"src/parser.rs\"}}\n</tool_call>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read_file");
        assert_eq!(calls[0].input["path"], "src/parser.rs");
        assert!(!text.contains("<tool_call>"));
    }

    /// A call naming a function but carrying no argument object is still a
    /// call — some tools take none — and must come back with empty input
    /// rather than being dropped.
    #[test]
    fn lenient_parse_allows_argumentless_call() {
        let (_text, calls) =
            extract_tool_calls("<tool_call>\n{\"name\" \"list_dir\"\n</tool_call>");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "list_dir");
        assert_eq!(calls[0].input, serde_json::json!({}));
    }

    /// Without a `"name"` field there is nothing to dispatch, so the lenient
    /// pass must decline rather than invent one.
    #[test]
    fn lenient_parse_declines_without_a_name_field() {
        assert!(parse_tool_call_lenient("{\"input\": {\"path\": \"x\"}}").is_none());
        assert!(parse_tool_call_lenient("just some prose").is_none());
    }

    /// The `<tool_use name="…">` tag of the Anthropic wire format.
    ///
    /// No local model is trained on this — it is the shape an agent's own
    /// system prompt and prior assistant turns are written in, and models
    /// imitate their context. It is therefore reachable from *any* model
    /// driven by an agent that formats history this way, which is why it is
    /// parsed rather than treated as one model's quirk. Sampled several turns
    /// into an agent session on a Qwen 3.6 build.
    #[test]
    fn extract_tool_use_tag_dialect() {
        let raw = "Now verifying the fix by running the test:\
                   <tool_use id=\"toolu_5e14f83b\" name=\"bash\">\
                   {\"command\":\"cargo test 2>&1\"}\n</tool_use>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "bash");
        assert_eq!(calls[0].input["command"], "cargo test 2>&1");
        // The id the model supplied is kept: the caller correlates its result
        // by it, and minting a fresh one would break that pairing.
        assert_eq!(calls[0].id, "toolu_5e14f83b");
        assert!(!text.contains("<tool_use"));
        assert!(text.contains("Now verifying"));
    }

    /// The same tag with the trailing brace dropped. Because the tool name is
    /// an attribute rather than a JSON field, the call stays dispatchable even
    /// when the argument object does not parse.
    #[test]
    fn tool_use_tag_survives_a_truncated_body() {
        let raw = "<tool_use id=\"toolu_48f06e31\" name=\"bash\">\
                   {\"command\":\"cargo test\"</command></tool_use>";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "bash");
        assert_eq!(calls[0].input, serde_json::json!({}));
    }

    /// A tag with no `name` names no tool, so there is nothing to dispatch.
    /// The markers still come out of the text.
    #[test]
    fn tool_use_tag_without_a_name_is_not_a_call() {
        let (text, calls) = extract_tool_calls("<tool_use id=\"x\">{}</tool_use>");
        assert!(calls.is_empty(), "got {:?}", calls);
        assert!(!text.contains("<tool_use"));
    }

    #[test]
    fn xml_attr_reads_only_the_named_attribute() {
        let tag = "<tool_use id=\"toolu_1\" name=\"read_file\">";
        assert_eq!(xml_attr(tag, "id").as_deref(), Some("toolu_1"));
        assert_eq!(xml_attr(tag, "name").as_deref(), Some("read_file"));
        assert_eq!(xml_attr(tag, "missing"), None);
        // An empty value is no value.
        assert_eq!(xml_attr("<tool_use name=\"\">", "name"), None);
    }

    #[test]
    fn extract_multiple_tool_call_tags() {
        let raw = "ok <tool_call>{\"name\":\"a\",\"input\":{}}</tool_call> mid <tool_call>{\"name\":\"b\",\"input\":{\"x\":1}}</tool_call> end";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "a");
        assert_eq!(calls[1].name, "b");
        assert_eq!(calls[1].input["x"], 1);
    }

    #[test]
    fn extract_llama_python_tag() {
        let raw = "Let me check.<|python_tag|>{\"name\": \"search\", \"parameters\": {\"q\": \"rust\"}}<|eom_id|>";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "search");
        assert_eq!(calls[0].input["q"], "rust");
        assert!(!text.contains("<|python_tag|>"));
        assert!(!text.contains("<|eom_id|>"));
    }

    #[test]
    fn extract_llama_python_tag_no_terminator() {
        let raw = "<|python_tag|>{\"name\":\"f\",\"input\":{}}";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "f");
        assert_eq!(text, "");
    }

    #[test]
    fn extract_bracketed_tool_calls_array() {
        let raw = "[TOOL_CALLS] [{\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}}, {\"name\":\"mul\",\"arguments\":{\"x\":3}}]";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "add");
        assert_eq!(calls[0].input["a"], 1);
        assert_eq!(calls[1].name, "mul");
    }

    #[test]
    fn extract_mistral_arguments_as_string() {
        // Some Mistral variants emit arguments as a JSON-encoded string.
        let raw = "[TOOL_CALLS] [{\"name\":\"f\",\"arguments\":\"{\\\"k\\\":42}\"}]";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].input["k"], 42);
    }

    #[test]
    fn extract_bare_json_fallback() {
        let raw = "  {\"name\":\"do_thing\",\"input\":{\"id\":\"abc\"}}  ";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "do_thing");
        assert_eq!(text, "");
    }

    #[test]
    fn bare_json_inside_prose_is_not_a_tool_call() {
        // We only consume bare JSON when the whole output is the JSON.
        let raw = "Sure: {\"name\":\"foo\",\"input\":{}} — that's the answer.";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 0);
        assert!(text.contains("Sure:"));
    }

    #[test]
    fn no_tool_calls_passes_through() {
        let raw = "Just a normal answer.";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 0);
        assert_eq!(text, "Just a normal answer.");
    }

    #[test]
    fn malformed_tool_call_is_dropped_but_marker_stripped() {
        let raw = "<tool_call>not json at all</tool_call> after";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 0);
        // The marker pair is consumed even when JSON parsing fails.
        assert!(!text.contains("<tool_call>"));
        assert!(text.contains("after"));
    }

    #[test]
    fn tool_call_id_synthesized_when_absent() {
        let raw = "<tool_call>{\"name\":\"x\",\"input\":{}}</tool_call>";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].id.starts_with("toolu_"));
    }

    #[test]
    fn tool_call_id_preserved_when_present() {
        let raw = "<tool_call>{\"id\":\"call_42\",\"name\":\"x\",\"input\":{}}</tool_call>";
        let (_text, calls) = extract_tool_calls(raw);
        assert_eq!(calls[0].id, "call_42");
    }

    #[test]
    fn render_tools_preamble_includes_name_and_schema() {
        let tools = vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: Some("Look up the weather.".to_string()),
            input_schema: serde_json::json!({"type":"object","properties":{"city":{"type":"string"}}}),
        }];
        let p = render_tools_preamble(&tools);
        assert!(p.contains("get_weather"));
        assert!(p.contains("Look up the weather"));
        assert!(p.contains("\"properties\""));
        assert!(p.contains("<tool_call>"));
    }
}
