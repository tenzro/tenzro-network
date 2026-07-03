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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Global singleton for the llama.cpp backend — can only be initialized once per process.
static LLAMA_BACKEND: OnceLock<Arc<LlamaBackend>> = OnceLock::new();

use crate::batching::{BatchEngine, BatchPrompt, BatchRequest};
use crate::catalog::{MtpKind, get_model_by_id};
use crate::error::{ModelError, Result};
use crate::external_engine::ExternalEngine;

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::{LlamaModelParams, LlamaSplitMode};
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::speculative::{MtpSpeculative, MtpSpeculativeParams};

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

        // Determine what's actually active
        let active_backend = if gpu_offload {
            if cfg!(feature = "cuda") || cfg!(feature = "cuda-no-vmm") {
                "CUDA (NVIDIA GPU)".to_string()
            } else if cfg!(feature = "rocm") {
                "ROCm (AMD GPU)".to_string()
            } else if cfg!(feature = "vulkan") {
                "Vulkan (GPU)".to_string()
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "Metal (Apple GPU)".to_string()
            } else {
                "GPU (unknown backend)".to_string()
            }
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
    /// Optional speculative-decoding draft count (1..=6). When `Some(n)`,
    /// the runtime is asked to use the target model's paired drafter
    /// (`HfModelEntry.drafter_id` + `mtp_kind`) and propose `n` tokens
    /// per verification round (llama.cpp `--spec-draft-n-max`). When
    /// `None`, the runtime falls back to single-token autoregressive
    /// sampling. The drafter must be loaded alongside the target;
    /// otherwise the runtime returns `ModelError::MtpUnavailable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_n: Option<u8>,
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
            draft_n: None,
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
}

/// Maximum context length we allow to prevent OOM on consumer hardware.
const MAX_CONTEXT_LENGTH: u32 = 131_072;

/// Default context length used when no catalog entry is available.
const DEFAULT_CONTEXT_LENGTH: u32 = 8192;

/// Headroom multiplier applied to the GGUF file size when estimating the
/// memory a model needs at load. Covers the KV cache, activation buffers, and
/// llama.cpp bookkeeping on top of the resident weights. 1.35× is deliberately
/// conservative for consumer hardware; larger contexts push the real KV cost
/// higher but the check is a floor, not an exact accounting.
const MODEL_LOAD_HEADROOM_NUM: u64 = 135;
const MODEL_LOAD_HEADROOM_DEN: u64 = 100;

/// Maximum number of concurrent requests (in flight + waiting) permitted per
/// loaded model. llama.cpp serializes decode on a single model context, so
/// requests queue behind the one holding the lock. Past this bound we shed
/// load with `ModelError::QueueFull` rather than letting the queue grow
/// unbounded and time every caller out under a thundering herd.
const MAX_INFLIGHT_PER_MODEL: usize = 64;

/// Internal representation of a loaded model
struct LoadedModel {
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
/// model that carries a Multi-Token-Prediction drafter, or one split across a
/// LAN pipeline cluster, is served through the serial single-context path
/// (`Serial`): speculative decoding runs two contexts that can't share the
/// batch scheduler, and a clustered pipeline threads boundary activations
/// across devices per request. The variant is chosen once at load time from
/// the catalog's `mtp_kind` (and the clustered entry point) and never changes.
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
/// Adapts to the provider's hardware automatically:
/// - Metal GPU on macOS ARM64 (auto-detected)
/// - CUDA on NVIDIA GPUs (compile with `--features cuda`)
/// - ROCm on AMD GPUs (compile with `--features rocm`)
/// - Vulkan on any GPU (compile with `--features vulkan`)
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
        let backend = LLAMA_BACKEND.get_or_init(|| {
            let b = LlamaBackend::init()
                .expect("Failed to initialize llama.cpp backend");
            Arc::new(b)
        }).clone();

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
            backend,
            hardware,
        }
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

    /// Load-time memory admission check.
    ///
    /// Estimates the resident footprint as `file_len × headroom` and rejects
    /// the load if available system memory can't cover it. On unified-memory
    /// (Apple Metal) and GPU-offload builds, weights land in shared or device
    /// memory backed by system RAM, so available RAM is the safe proxy — the
    /// check is a floor that prevents a mid-load OOM kill, not exact VRAM
    /// accounting. `TENZRO_SKIP_MODEL_ADMISSION=1` bypasses it for operators who
    /// pin memory out-of-band.
    fn check_memory_admission(model_id: &str, file_len: u64) -> Result<()> {
        if std::env::var("TENZRO_SKIP_MODEL_ADMISSION").as_deref() == Ok("1") {
            return Ok(());
        }

        let required = file_len
            .saturating_mul(MODEL_LOAD_HEADROOM_NUM)
            / MODEL_LOAD_HEADROOM_DEN;

        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let available = sys.available_memory(); // bytes

        if available < required {
            return Err(ModelError::InsufficientMemory {
                model_id: model_id.to_string(),
                required_mb: required / 1_048_576,
                available_mb: available / 1_048_576,
            });
        }
        Ok(())
    }

    /// Load a GGUF model into memory.
    ///
    /// llama.cpp auto-detects the model architecture from GGUF metadata.
    /// GPU layers are offloaded automatically when Metal/CUDA is available.
    ///
    /// Convenience overload: uses the model's trained context length capped
    /// at [`DEFAULT_CONTEXT_LENGTH`]. To use the full catalog context length,
    /// call [`load_model_with_context`] instead.
    pub async fn load_model(
        &self,
        model_id: &str,
        gguf_path: &Path,
    ) -> Result<()> {
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

        info!("Loading model {} from {}", model_id, gguf_path.display());
        let start = Instant::now();

        let gguf_path_owned = gguf_path.to_path_buf();
        let model_id_owned = model_id.to_string();
        let backend = self.backend.clone();

        let loaded = tokio::task::spawn_blocking(move || {
            // Offload all layers to GPU (Metal on macOS, CUDA if feature enabled).
            // n_gpu_layers(1000) means "offload everything available".
            let model_params = LlamaModelParams::default().with_n_gpu_layers(1000);

            let model =
                LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params).map_err(
                    |e| {
                        ModelError::Other(format!(
                            "Failed to load GGUF model '{}': {}",
                            model_id_owned, e
                        ))
                    },
                )?;

            // Determine context length:
            // - If caller provides a context_length, use it (capped at MAX_CONTEXT_LENGTH
            //   and the model's trained context)
            // - Otherwise default to DEFAULT_CONTEXT_LENGTH (safe default)
            let trained_ctx = model.n_ctx_train();
            let effective_ctx = match context_length {
                Some(requested) => trained_ctx
                    .min(requested)
                    .min(MAX_CONTEXT_LENGTH),
                None => trained_ctx.min(DEFAULT_CONTEXT_LENGTH),
            };

            info!(
                "Model {} loaded: {} params, {} layers, trained_context={}, effective_context={}",
                model_id_owned,
                model.n_params(),
                model.n_layer(),
                trained_ctx,
                effective_ctx,
            );

            Ok::<LoadedModel, ModelError>(LoadedModel {
                model,
                backend,
                context_length: effective_ctx,
            })
        })
        .await
        .map_err(|e| ModelError::Other(format!("Task join error: {}", e)))??;

        let elapsed = start.elapsed();
        info!(
            "Model {} loaded in {:.2}s",
            model_id,
            elapsed.as_secs_f64(),
        );

        // A model paired with a Multi-Token-Prediction drafter is served on the
        // serial single-context path: speculative decoding runs the target and
        // drafter as two contexts that can't share one batch scheduler. Every
        // other text model is served through the continuous-batching engine.
        let wants_drafter = get_model_by_id(model_id)
            .map(|e| e.mtp_kind != MtpKind::None)
            .unwrap_or(false);

        let entry = if wants_drafter {
            LoadedEntry::Serial(Arc::new(tokio::sync::Mutex::new(loaded)))
        } else {
            let LoadedModel {
                model,
                backend,
                context_length,
            } = loaded;
            let engine = BatchEngine::spawn(
                model_id.to_string(),
                model,
                backend,
                context_length,
            )?;
            LoadedEntry::Batched(engine)
        };

        self.loaded_models
            .insert(model_id.to_string(), Arc::new(entry));

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

            let model =
                LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params).map_err(
                    |e| {
                        ModelError::Other(format!(
                            "Failed to load clustered GGUF model '{}': {}",
                            model_id_owned, e
                        ))
                    },
                )?;

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

            Ok::<LoadedModel, ModelError>(LoadedModel {
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
        self.loaded_models.insert(
            model_id.to_string(),
            Arc::new(LoadedEntry::Serial(Arc::new(tokio::sync::Mutex::new(loaded)))),
        );

        Ok(())
    }

    /// Unload a model from memory.
    pub async fn unload_model(&self, model_id: &str) -> Result<()> {
        // An externally-served model has no local context — drop the routing
        // registration and we're done.
        if self.external_engines.remove(model_id).is_some() {
            info!("Unregistered external engine for model: {}", model_id);
            return Ok(());
        }
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
            info!("Unloaded model: {} (llama.cpp context freed)", model_id);
        } else {
            warn!("Model {} was not loaded", model_id);
        }
        Ok(())
    }

    /// Check if a model is currently served — either loaded into a local
    /// llama.cpp context or routed to a registered external engine.
    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.loaded_models.contains_key(model_id)
            || self.external_engines.contains_key(model_id)
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
        Self::check_memory_admission(target_model_id, file_len)?;

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
            let model_params = LlamaModelParams::default().with_n_gpu_layers(1000);
            let model =
                LlamaModel::load_from_file(&backend, &gguf_path_owned, &model_params).map_err(
                    |e| {
                        ModelError::Other(format!(
                            "Failed to load MTP drafter for target '{}': {}",
                            target_id_owned, e
                        ))
                    },
                )?;
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
        Ok(())
    }

    /// Unload the MTP drafter paired with `target_model_id`.
    pub async fn unload_drafter(&self, target_model_id: &str) -> Result<()> {
        if let Some((_, drafter_arc)) = self.loaded_drafters.remove(target_model_id) {
            let _lock = drafter_arc.lock().await;
            drop(_lock);
            drop(drafter_arc);
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
        let external = self.external_engines.get(model_id).map(|e| e.value().clone());
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
                Self::run_batched(engine, BatchPrompt::Raw(prompt.to_string()), config, None)
                    .await
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
        let external = self.external_engines.get(model_id).map(|e| e.value().clone());
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

        let _guard = self.acquire_inflight(model_id)?;

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(
                    engine,
                    BatchPrompt::Chat(messages.to_vec()),
                    config,
                    None,
                )
                .await
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
        let external = self.external_engines.get(model_id).map(|e| e.value().clone());
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
        let mut messages = messages.to_vec();
        let tools = tools.to_vec();
        let config = config.clone();
        let max_tokens = config.max_tokens;

        // Inline tool descriptions into a synthetic system message. If the
        // first message is already a system message, we prepend the tools
        // block to it; otherwise we insert a fresh system message.
        if !tools.is_empty() {
            let tools_preamble = render_tools_preamble(&tools);
            if let Some(first) = messages.first_mut() {
                if first.role == "system" {
                    let combined = format!("{}\n\n{}", first.content, tools_preamble);
                    first.content = combined;
                } else {
                    messages.insert(
                        0,
                        ChatMessage {
                            role: "system".to_string(),
                            content: tools_preamble,
                        },
                    );
                }
            } else {
                messages.push(ChatMessage {
                    role: "system".to_string(),
                    content: tools_preamble,
                });
            }
        }

        let inner = if let Some(engine) = external {
            engine.chat(&messages, &config).await?
        } else {
            match entry.as_ref().expect("local entry present when not external").as_ref() {
                LoadedEntry::Batched(engine) => {
                    Self::run_batched(engine, BatchPrompt::Chat(messages), &config, None).await?
                }
                LoadedEntry::Serial(model_mutex) => {
                    let model_mutex = model_mutex.clone();
                    let config = config.clone();
                    tokio::task::spawn_blocking(move || {
                        let loaded = model_mutex.blocking_lock();
                        let prompt = render_chat_prompt(&loaded.model, &messages)?;
                        Self::generate_sync(&loaded, &prompt, &config)
                    })
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))??
                }
            }
        };

        // Parse tool-call markers from the raw output.
        let (clean_text, tool_calls) = extract_tool_calls(&inner.text);

        let stop_reason = if !tool_calls.is_empty() {
            "tool_use".to_string()
        } else if inner.output_tokens >= max_tokens {
            "max_tokens".to_string()
        } else {
            "end_turn".to_string()
        };

        Ok(ChatWithToolsResult {
            text: clean_text,
            tool_calls,
            input_tokens: inner.input_tokens,
            output_tokens: inner.output_tokens,
            generation_time_ms: inner.generation_time_ms,
            tokens_per_second: inner.tokens_per_second,
            stop_reason,
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
        let external = self.external_engines.get(model_id).map(|e| e.value().clone());
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
                    self.loaded_drafters.get(model_id).map(|d| d.value().clone())
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
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
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
        let external = self.external_engines.get(model_id).map(|e| e.value().clone());
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
                    self.loaded_drafters.get(model_id).map(|d| d.value().clone())
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
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
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
        Self::generate_sync_streaming(loaded, None, prompt, config, None)
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
        if let Some(n) = config.draft_n {
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

        let n_ctx_val = ctx.n_ctx() as i32;
        let total_needed = input_tokens as i32 + config.max_tokens as i32;
        if total_needed > n_ctx_val {
            warn!(
                "Requested {} tokens but context is {} -- output will be truncated",
                total_needed, n_ctx_val
            );
        }

        // Create batch sized to fit the entire prompt
        let batch_size = std::cmp::max(tokens_list.len(), 512);
        let mut batch = LlamaBatch::new(batch_size, 1);
        let last_index = (tokens_list.len() - 1) as i32;
        for (i, token) in tokens_list.iter().enumerate() {
            let is_last = i as i32 == last_index;
            batch.add(*token, i as i32, &[0], is_last).map_err(|e| {
                ModelError::Other(format!("Batch add failed: {}", e))
            })?;
        }

        // Decode prompt (prefill)
        ctx.decode(&mut batch)
            .map_err(|e| ModelError::Other(format!("Prompt decode failed: {}", e)))?;

        // Set up sampler chain: penalties -> temp -> top_p -> dist
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::penalties(
                config.repeat_last_n as i32,
                config.repeat_penalty,
                0.0, // frequency penalty
                0.0, // presence penalty
            ),
            LlamaSampler::temp(config.temperature as f32),
            LlamaSampler::top_p(config.top_p as f32, 1),
            LlamaSampler::dist(config.seed as u32),
        ]);

        // Auto-regressive generation loop
        let mut n_cur = batch.n_tokens();
        let mut output_tokens: u32 = 0;
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut output_text = String::new();

        let max_pos = n_ctx_val.min(input_tokens as i32 + config.max_tokens as i32);

        while n_cur < max_pos {
            // Sample next token
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);

            // Check for end of generation
            if loaded.model.is_eog_token(token) {
                break;
            }

            // Decode token to text
            match loaded
                .model
                .token_to_piece(token, &mut decoder, true, None)
            {
                Ok(piece) => {
                    // Stream the token piece if a sender is provided
                    if let Some(tx) = token_tx {
                        // If the receiver is dropped, stop generating
                        if tx.blocking_send(piece.clone()).is_err() {
                            break;
                        }
                    }
                    output_text.push_str(&piece);
                }
                Err(e) => {
                    warn!("Failed to decode token {}: {}", token.0, e);
                }
            }

            output_tokens += 1;

            // Prepare next batch with the sampled token
            batch.clear();
            batch.add(token, n_cur, &[0], true).map_err(|e| {
                ModelError::Other(format!("Batch add failed: {}", e))
            })?;

            // Decode the new token
            ctx.decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Decode failed: {}", e)))?;

            n_cur += 1;
        }

        let elapsed = start.elapsed();
        let generation_time_ms = elapsed.as_millis() as u64;
        let tokens_per_second = if generation_time_ms > 0 {
            (output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
        } else {
            0.0
        };

        Ok(InferenceResult {
            text: output_text,
            input_tokens,
            output_tokens,
            generation_time_ms,
            tokens_per_second,
        })
    }

    /// Speculative-decoding generation loop using llama.cpp's MTP
    /// helper. The target's catalog entry must declare
    /// `mtp_kind: MtpKind::DraftMtp`; the drafter is the
    /// jointly-trained MTP head sidecar GGUF (e.g. Gemma 4's
    /// `mtp-gemma-4-12B-it.gguf`).
    ///
    /// Loop shape per llama.cpp `common_speculative` semantics:
    ///   1. Tokenize prompt and prefill the target context.
    ///   2. Initialize `MtpSpeculative::begin(prompt)`.
    ///   3. Sample one token from the target to seed `id_last`.
    ///   4. Loop:
    ///        a. Ask the drafter for up to `n_max` candidate tokens
    ///           after `id_last`.
    ///        b. Batch-decode the candidates on the target.
    ///        c. Compare each candidate against the target's sample
    ///           and accept the longest matching prefix.
    ///        d. Notify the drafter how many were accepted.
    ///        e. Emit accepted tokens (+ the next target token) and
    ///           update `n_past` / `id_last`.
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

        // Prefill the target context with the prompt.
        let batch_size = std::cmp::max(tokens_list.len(), 512);
        let mut batch = LlamaBatch::new(batch_size, 1);
        let last_index = (tokens_list.len() - 1) as i32;
        for (i, token) in tokens_list.iter().enumerate() {
            let is_last = i as i32 == last_index;
            batch
                .add(*token, i as i32, &[0], is_last)
                .map_err(|e| ModelError::Other(format!("Batch add failed: {}", e)))?;
        }
        spec.target_context_mut()
            .decode(&mut batch)
            .map_err(|e| ModelError::Other(format!("Prompt decode failed: {}", e)))?;

        // Sampler chain — identical to the single-token path so
        // temperature/top_p/repetition penalty behave the same. The
        // drafter only PROPOSES tokens; the target's sampler decides
        // which are kept.
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::penalties(
                config.repeat_last_n as i32,
                config.repeat_penalty,
                0.0,
                0.0,
            ),
            LlamaSampler::temp(config.temperature as f32),
            LlamaSampler::top_p(config.top_p as f32, 1),
            LlamaSampler::dist(config.seed as u32),
        ]);

        let mut n_cur = batch.n_tokens();
        let mut output_tokens: u32 = 0;
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut output_text = String::new();
        let max_pos = (n_ctx_target.get() as i32)
            .min(input_tokens as i32 + config.max_tokens as i32);

        // Seed `id_last` by sampling one token from the target. The
        // drafter conditions its draft on this token.
        let mut id_last = sampler.sample(spec.target_context_mut(), batch.n_tokens() - 1);
        sampler.accept(id_last);

        // Emit the seed token.
        if loaded.model.is_eog_token(id_last) {
            return Ok(InferenceResult {
                text: output_text,
                input_tokens,
                output_tokens,
                generation_time_ms: start.elapsed().as_millis() as u64,
                tokens_per_second: 0.0,
            });
        }
        match loaded
            .model
            .token_to_piece(id_last, &mut decoder, true, None)
        {
            Ok(piece) => {
                if let Some(tx) = token_tx
                    && tx.blocking_send(piece.clone()).is_err()
                {
                    // Receiver dropped — finish what we have.
                    return Ok(InferenceResult {
                        text: output_text,
                        input_tokens,
                        output_tokens,
                        generation_time_ms: start.elapsed().as_millis() as u64,
                        tokens_per_second: 0.0,
                    });
                }
                output_text.push_str(&piece);
            }
            Err(e) => warn!("Failed to decode seed token {}: {}", id_last.0, e),
        }
        output_tokens += 1;
        n_cur += 1;

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
                if let Ok(piece) = loaded.model.token_to_piece(next, &mut decoder, true, None) {
                    if let Some(tx) = token_tx
                        && tx.blocking_send(piece.clone()).is_err()
                    {
                        break;
                    }
                    output_text.push_str(&piece);
                }
                output_tokens += 1;
                n_cur += 1;
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
            spec.target_context_mut()
                .decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Target speculative decode failed: {}", e)))?;

            // 3. Accept / reject by comparing target samples to drafts.
            let mut n_accepted: u16 = 0;
            for (i, draft_tok) in drafts.iter().enumerate() {
                let logit_idx = i as i32;
                let target_sample =
                    sampler.sample(spec.target_context_mut(), logit_idx);
                sampler.accept(target_sample);
                if target_sample == *draft_tok {
                    n_accepted += 1;
                    id_last = target_sample;
                    prompt_so_far.push(target_sample);
                    if loaded.model.is_eog_token(target_sample) {
                        break;
                    }
                    if let Ok(piece) =
                        loaded.model.token_to_piece(target_sample, &mut decoder, true, None)
                    {
                        if let Some(tx) = token_tx
                            && tx.blocking_send(piece.clone()).is_err()
                        {
                            // Receiver dropped.
                            spec.accept(n_accepted)
                                .map_err(|e| ModelError::MtpUnavailable {
                                    reason: format!("MtpSpeculative accept failed: {}", e),
                                })?;
                            return Ok(InferenceResult {
                                text: output_text,
                                input_tokens,
                                output_tokens,
                                generation_time_ms: start.elapsed().as_millis() as u64,
                                tokens_per_second: 0.0,
                            });
                        }
                        output_text.push_str(&piece);
                    }
                    output_tokens += 1;
                } else {
                    // First rejection — keep the target's sample as
                    // the next id_last and stop accepting drafts.
                    id_last = target_sample;
                    prompt_so_far.push(target_sample);
                    if loaded.model.is_eog_token(target_sample) {
                        break;
                    }
                    if let Ok(piece) =
                        loaded.model.token_to_piece(target_sample, &mut decoder, true, None)
                    {
                        if let Some(tx) = token_tx
                            && tx.blocking_send(piece.clone()).is_err()
                        {
                            spec.accept(n_accepted)
                                .map_err(|e| ModelError::MtpUnavailable {
                                    reason: format!("MtpSpeculative accept failed: {}", e),
                                })?;
                            return Ok(InferenceResult {
                                text: output_text,
                                input_tokens,
                                output_tokens,
                                generation_time_ms: start.elapsed().as_millis() as u64,
                                tokens_per_second: 0.0,
                            });
                        }
                        output_text.push_str(&piece);
                    }
                    output_tokens += 1;
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
        Ok(InferenceResult {
            text: output_text,
            input_tokens,
            output_tokens,
            generation_time_ms,
            tokens_per_second,
        })
    }
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
    if let Ok(tmpl) = model.chat_template(None) {
        if let Ok(rendered) = model.apply_chat_template(&tmpl, &llama_messages, true) {
            if !rendered.trim().is_empty() {
                return Ok(rendered);
            }
            warn!("GGUF chat template rendered empty; falling back to ChatML");
        }
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
    out.push_str(
        "You have access to the following tools. To call a tool, emit a \
         JSON object inside <tool_call>...</tool_call> tags with \
         {\"name\": ..., \"input\": {...}}. Only call a tool when needed.\n\n\
         <tools>\n",
    );
    for t in tools {
        out.push_str("  <tool>\n");
        out.push_str(&format!("    <name>{}</name>\n", t.name));
        if let Some(desc) = &t.description {
            out.push_str(&format!("    <description>{}</description>\n", desc));
        }
        out.push_str("    <input_schema>\n");
        out.push_str(
            &serde_json::to_string(&t.input_schema)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        out.push_str("\n    </input_schema>\n");
        out.push_str("  </tool>\n");
    }
    out.push_str("</tools>");
    out
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
    loop {
        let Some(start) = text.find("<tool_call>") else {
            break;
        };
        let after_open = start + "<tool_call>".len();
        let Some(rel_end) = text[after_open..].find("</tool_call>") else {
            break;
        };
        let end = after_open + rel_end;
        let close_end = end + "</tool_call>".len();

        let body = text[after_open..end].trim();
        if let Some(call) = parse_tool_call_json(body) {
            calls.push(call);
        }
        text.replace_range(start..close_end, "");
    }

    // ── Llama 3.x: <|python_tag|>{json}(<|eom_id|>|<|eot_id|>|EOS) ────
    loop {
        let Some(start) = text.find("<|python_tag|>") else {
            break;
        };
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
        serde_json::from_str::<serde_json::Value>(s).unwrap_or(serde_json::Value::String(s.to_string()))
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
            ChatMessage { role: "system".to_string(), content: "be terse".to_string() },
            ChatMessage { role: "user".to_string(), content: "hi".to_string() },
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
    fn extract_qwen_tool_call() {
        let raw = "Sure thing.\n<tool_call>\n{\"name\": \"get_weather\", \"input\": {\"city\": \"Tokyo\"}}\n</tool_call>\nAnything else?";
        let (text, calls) = extract_tool_calls(raw);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].input["city"], "Tokyo");
        assert!(!text.contains("<tool_call>"));
        assert!(text.contains("Sure thing"));
        assert!(text.contains("Anything else"));
    }

    #[test]
    fn extract_multiple_qwen_tool_calls() {
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
    fn extract_mistral_tool_calls_array() {
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
