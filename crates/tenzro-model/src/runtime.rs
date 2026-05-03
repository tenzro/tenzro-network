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
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Global singleton for the llama.cpp backend — can only be initialized once per process.
static LLAMA_BACKEND: OnceLock<Arc<LlamaBackend>> = OnceLock::new();

use crate::catalog::ModelArchitecture;
use crate::error::{ModelError, Result};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;

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

/// Internal representation of a loaded model
struct LoadedModel {
    model: LlamaModel,
    backend: Arc<LlamaBackend>,
    /// Model architecture (stored for future introspection APIs)
    #[allow(dead_code)]
    architecture: ModelArchitecture,
    /// Path to GGUF file (stored for model provenance tracking)
    #[allow(dead_code)]
    gguf_path: PathBuf,
    /// Configured context length from catalog (capped at MAX_CONTEXT_LENGTH)
    context_length: u32,
}

// SAFETY: LlamaModel is Send + Sync per llama-cpp-2 docs.
// LlamaBackend is Send + Sync.
unsafe impl Send for LoadedModel {}
unsafe impl Sync for LoadedModel {}

/// Model runtime -- loads and runs GGUF models for inference via llama.cpp.
///
/// Adapts to the provider's hardware automatically:
/// - Metal GPU on macOS ARM64 (auto-detected)
/// - CUDA on NVIDIA GPUs (compile with `--features cuda`)
/// - ROCm on AMD GPUs (compile with `--features rocm`)
/// - Vulkan on any GPU (compile with `--features vulkan`)
/// - CPU fallback (always available)
pub struct ModelRuntime {
    loaded_models: Arc<DashMap<String, Arc<tokio::sync::Mutex<LoadedModel>>>>,
    backend: Arc<LlamaBackend>,
    hardware: HardwareInfo,
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
            backend,
            hardware,
        }
    }

    /// Get detected hardware information for this runtime.
    ///
    /// Reports which compute backends were compiled in, whether GPU offload
    /// is available, and what backend is actively being used.
    pub fn hardware_info(&self) -> &HardwareInfo {
        &self.hardware
    }

    /// Load a GGUF model into memory.
    ///
    /// llama.cpp auto-detects the model architecture from GGUF metadata,
    /// so the `architecture` parameter is informational only. GPU layers
    /// are offloaded automatically when Metal/CUDA is available.
    ///
    /// Convenience overload: uses the model's trained context length capped
    /// at [`DEFAULT_CONTEXT_LENGTH`]. To use the full catalog context length,
    /// call [`load_model_with_context`] instead.
    pub async fn load_model(
        &self,
        model_id: &str,
        gguf_path: &Path,
        architecture: ModelArchitecture,
    ) -> Result<()> {
        self.load_model_with_context(model_id, gguf_path, architecture, None)
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
        architecture: ModelArchitecture,
        context_length: Option<u32>,
    ) -> Result<()> {
        if self.is_loaded(model_id) {
            info!("Model {} already loaded", model_id);
            return Ok(());
        }

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
                architecture,
                gguf_path: gguf_path_owned,
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

        self.loaded_models
            .insert(model_id.to_string(), Arc::new(tokio::sync::Mutex::new(loaded)));

        Ok(())
    }

    /// Unload a model from memory.
    pub async fn unload_model(&self, model_id: &str) -> Result<()> {
        if let Some((_, model_arc)) = self.loaded_models.remove(model_id) {
            // Acquire the mutex to wait for any in-progress generation
            // to finish before dropping the llama.cpp model context.
            // Without this, the model stays in memory until the
            // generation task completes, causing OOM when loading
            // another model.
            let _lock = model_arc.lock().await;
            // Dropping _lock and model_arc frees the llama.cpp context
            drop(_lock);
            drop(model_arc);
            info!("Unloaded model: {} (llama.cpp context freed)", model_id);
        } else {
            warn!("Model {} was not loaded", model_id);
        }
        Ok(())
    }

    /// Check if a model is currently loaded.
    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.loaded_models.contains_key(model_id)
    }

    /// List all currently loaded model IDs.
    pub fn list_loaded(&self) -> Vec<String> {
        self.loaded_models
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Generate text from a raw prompt string.
    pub async fn generate(
        &self,
        model_id: &str,
        prompt: &str,
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        let model_entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?;

        let model_mutex = model_entry.value().clone();
        let prompt = prompt.to_string();
        let config = config.clone();

        tokio::task::spawn_blocking(move || {
            let loaded = model_mutex.blocking_lock();
            Self::generate_sync(&loaded, &prompt, &config)
        })
        .await
        .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
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
        let model_entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?;

        let model_mutex = model_entry.value().clone();
        let messages = messages.to_vec();
        let config = config.clone();

        tokio::task::spawn_blocking(move || {
            let loaded = model_mutex.blocking_lock();

            // Convert ChatMessage to LlamaChatMessage
            let llama_messages: Vec<LlamaChatMessage> = messages
                .iter()
                .map(|m| {
                    LlamaChatMessage::new(m.role.clone(), m.content.clone()).map_err(|e| {
                        ModelError::Other(format!("Invalid chat message: {}", e))
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            // Apply the model's built-in chat template from GGUF metadata
            let chat_template = loaded.model.chat_template(None).map_err(|e| {
                ModelError::Other(format!("Failed to get chat template: {}", e))
            })?;

            let prompt = loaded
                .model
                .apply_chat_template(&chat_template, &llama_messages, true)
                .map_err(|e| {
                    ModelError::Other(format!("Failed to apply chat template: {}", e))
                })?;

            Self::generate_sync(&loaded, &prompt, &config)
        })
        .await
        .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
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
        let model_entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?;

        let model_mutex = model_entry.value().clone();
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

        let inner = tokio::task::spawn_blocking(move || {
            let loaded = model_mutex.blocking_lock();

            let llama_messages: Vec<LlamaChatMessage> = messages
                .iter()
                .map(|m| {
                    LlamaChatMessage::new(m.role.clone(), m.content.clone()).map_err(|e| {
                        ModelError::Other(format!("Invalid chat message: {}", e))
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let chat_template = loaded.model.chat_template(None).map_err(|e| {
                ModelError::Other(format!("Failed to get chat template: {}", e))
            })?;

            let prompt = loaded
                .model
                .apply_chat_template(&chat_template, &llama_messages, true)
                .map_err(|e| {
                    ModelError::Other(format!("Failed to apply chat template: {}", e))
                })?;

            Self::generate_sync(&loaded, &prompt, &config)
        })
        .await
        .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))??;

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
        let model_entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?;

        let model_mutex = model_entry.value().clone();
        let messages = messages.to_vec();
        let config = config.clone();

        tokio::task::spawn_blocking(move || {
            let loaded = model_mutex.blocking_lock();

            // Convert ChatMessage to LlamaChatMessage
            let llama_messages: Vec<LlamaChatMessage> = messages
                .iter()
                .map(|m| {
                    LlamaChatMessage::new(m.role.clone(), m.content.clone()).map_err(|e| {
                        ModelError::Other(format!("Invalid chat message: {}", e))
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            // Apply the model's built-in chat template from GGUF metadata
            let chat_template = loaded.model.chat_template(None).map_err(|e| {
                ModelError::Other(format!("Failed to get chat template: {}", e))
            })?;

            let prompt = loaded
                .model
                .apply_chat_template(&chat_template, &llama_messages, true)
                .map_err(|e| {
                    ModelError::Other(format!("Failed to apply chat template: {}", e))
                })?;

            Self::generate_sync_streaming(&loaded, &prompt, &config, Some(&token_tx))
        })
        .await
        .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
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
        let model_entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?;

        let model_mutex = model_entry.value().clone();
        let prompt = prompt.to_string();
        let config = config.clone();

        tokio::task::spawn_blocking(move || {
            let loaded = model_mutex.blocking_lock();
            Self::generate_sync_streaming(&loaded, &prompt, &config, Some(&token_tx))
        })
        .await
        .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
    }

    /// Synchronous text generation using llama.cpp
    fn generate_sync(
        loaded: &LoadedModel,
        prompt: &str,
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        Self::generate_sync_streaming(loaded, prompt, config, None)
    }

    /// Core synchronous generation loop, optionally streaming each token.
    fn generate_sync_streaming(
        loaded: &LoadedModel,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        let start = Instant::now();

        // Tokenize input
        let tokens_list = loaded
            .model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {}", e)))?;

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
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(call) = parse_tool_call_value(item) {
                            calls.push(call);
                        }
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
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Some(call) = parse_tool_call_json(trimmed) {
                calls.push(call);
                text.clear();
            }
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
