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

/// The process's one llama.cpp backend, shared by every in-process engine.
pub(crate) fn llama_backend() -> Arc<LlamaBackend> {
    LLAMA_BACKEND
        .get_or_init(|| {
            Arc::new(LlamaBackend::init().expect("Failed to initialize llama.cpp backend"))
        })
        .clone()
}

use crate::catalog::{MtpKind, get_model_by_id};
use crate::error::{ModelError, Result};
use praecise_runtime::batching::{BatchEngine, BatchPrompt, BatchRequest, BatchSpeculation};

use llama_cpp_2::context::LlamaContext;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
#[cfg(feature = "mtmd")]
use llama_cpp_2::mtmd::{
    MtmdBitmap, MtmdContext, MtmdContextParams, MtmdInputText, mtmd_default_marker,
};
use llama_cpp_2::sampling::LlamaSampler;
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

/// The GPUs on this machine, split into those this process may use and those
/// its device-visibility variables hide from it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectedGpus {
    /// Vendors of the GPUs this process can use.
    pub visible: Vec<tenzro_types::GpuVendor>,
    /// Vendors present on the machine but hidden from this process, each with
    /// the variable that hides it.
    pub hidden: Vec<(tenzro_types::GpuVendor, &'static str)>,
}

impl DetectedGpus {
    /// Split the `present` vendors by the process's device-visibility
    /// variables, read through `var`. A GPU is hidden only when its runtime's
    /// variable is set and empty, which is how CUDA, ROCm and Vulkan are told
    /// to use no device; unset means every device is visible. A Vulkan build
    /// (`vulkan`) reaches every vendor through the Vulkan loader, so only
    /// `GGML_VK_VISIBLE_DEVICES` hides a GPU from it; the CUDA and ROCm
    /// variables do not.
    pub fn split(
        present: &[tenzro_types::GpuVendor],
        vulkan: bool,
        var: impl Fn(&str) -> Option<String>,
    ) -> Self {
        use tenzro_types::GpuVendor;
        let hidden_by = |vendor: GpuVendor| -> Option<&'static str> {
            let names: &[&'static str] = match vendor {
                _ if vulkan => &["GGML_VK_VISIBLE_DEVICES"],
                GpuVendor::Nvidia => &["CUDA_VISIBLE_DEVICES"],
                GpuVendor::Amd => &["HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES"],
                GpuVendor::Apple | GpuVendor::Other => &[],
            };
            names
                .iter()
                .copied()
                .find(|name| var(name).is_some_and(|v| v.trim().is_empty()))
        };
        let mut gpus = Self::default();
        for &vendor in present {
            match hidden_by(vendor) {
                Some(name) => gpus.hidden.push((vendor, name)),
                None => gpus.visible.push(vendor),
            }
        }
        gpus
    }

    /// One line per hidden GPU, for the startup warning and the node status.
    pub fn hidden_descriptions(&self) -> Vec<String> {
        self.hidden
            .iter()
            .map(|(vendor, name)| {
                format!("{vendor:?} GPU present but hidden by {name}; running CPU")
            })
            .collect()
    }
}

/// GPUs on this machine, detected once per process: the devices the vendor
/// tools report, plus on Linux every DRM render node whose PCI vendor makes
/// GPUs, so a GPU whose vendor tools are not installed is still seen. An Intel
/// GPU is reported as [`tenzro_types::GpuVendor::Other`].
///
/// Detection shells out to the vendor tools; the first call belongs on a
/// blocking thread.
pub fn detected_gpus() -> &'static DetectedGpus {
    static GPUS: OnceLock<DetectedGpus> = OnceLock::new();
    GPUS.get_or_init(|| {
        let mut present = Vec::new();
        let reported = ModelRuntime::local_hardware().gpus.iter().map(|g| g.vendor);
        for vendor in reported.chain(render_node_vendors()) {
            if !present.contains(&vendor) {
                present.push(vendor);
            }
        }
        let vulkan = crate::hardware_policy::BuildFlavour::current()
            == crate::hardware_policy::BuildFlavour::OtherGpu("vulkan");
        DetectedGpus::split(&present, vulkan, |name| std::env::var(name).ok())
    })
}

/// Vendors of the GPUs this process can use.
pub fn detected_gpu_vendors() -> &'static [tenzro_types::GpuVendor] {
    &detected_gpus().visible
}

/// Decide whether the llama.cpp runtime may start on this machine. `Err` when
/// a visible GPU has no compiled backend, or has one that llama.cpp cannot
/// drive (`has_gpu` false); `Ok(Some(notice))` when GPUs are present but hidden
/// from this process, so it runs on the CPU and says so.
fn check_llm_gpus(
    gpus: &DetectedGpus,
    compiled: &[String],
    has_gpu: bool,
) -> std::result::Result<Option<String>, String> {
    use crate::hardware_policy::{BuildFlavour, gpu_artifact};
    // The CPU build is a deliberate choice: it starts beside a GPU it cannot
    // drive, says so, and refuses GPU-tier models at load.
    if BuildFlavour::of(compiled) == BuildFlavour::Cpu && !gpus.visible.is_empty() {
        return Ok(Some(format!(
            "this is the CPU build of tenzro-node and this machine has a GPU it will not use; \
             it serves CPU-tier models only. Install the GPU build ({}) to serve GPU-tier models.",
            gpu_artifact(),
        )));
    }
    plan_llm_backend(&gpus.visible, compiled)?;
    if !gpus.visible.is_empty() && !has_gpu {
        return Err(format!(
            "this machine has a GPU and this binary was built with the {} backend(s), but \
             llama.cpp reports no usable GPU device, so every model layer would run on the \
             CPU. Check the GPU driver; a build with CMAKE_CUDA_ARCHITECTURES or CUDAARCHS \
             set also produces this state, since ggml selects the architecture list itself.",
            compiled.join(", "),
        ));
    }
    let hidden = gpus.hidden_descriptions();
    Ok((!hidden.is_empty()).then(|| hidden.join("; ")))
}

#[cfg(target_os = "linux")]
fn render_node_vendors() -> Vec<tenzro_types::GpuVendor> {
    let Ok(entries) = std::fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("renderD"))
        .filter_map(|e| std::fs::read_to_string(e.path().join("device/vendor")).ok())
        .filter_map(|id| gpu_vendor_from_pci_id(id.trim()))
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn render_node_vendors() -> Vec<tenzro_types::GpuVendor> {
    Vec::new()
}

/// The GPU vendor behind a PCI vendor id, for the vendors that make GPUs.
/// Virtual display adapters and board management controllers map to `None`.
fn gpu_vendor_from_pci_id(id: &str) -> Option<tenzro_types::GpuVendor> {
    match id {
        "0x10de" => Some(tenzro_types::GpuVendor::Nvidia),
        "0x1002" => Some(tenzro_types::GpuVendor::Amd),
        "0x8086" => Some(tenzro_types::GpuVendor::Other),
        _ => None,
    }
}

/// Decide whether a binary with the `compiled` llama.cpp backends can drive
/// every GPU vendor in `gpus`, or why it cannot. A GPU with no matching backend
/// is an error: the model would load and answer with every layer on the CPU.
pub fn plan_llm_backend(
    gpus: &[tenzro_types::GpuVendor],
    compiled: &[String],
) -> std::result::Result<(), String> {
    use tenzro_types::GpuVendor;
    for vendor in gpus {
        let (gpu, usable): (&str, &[&str]) = match vendor {
            GpuVendor::Nvidia => ("an NVIDIA GPU", &["cuda", "cuda-no-vmm", "vulkan"]),
            GpuVendor::Amd => ("an AMD GPU", &["rocm", "vulkan"]),
            GpuVendor::Apple => ("an Apple GPU", &["metal"]),
            GpuVendor::Other => (
                "a Vulkan-capable GPU",
                &["vulkan", "sycl", "openvino", "opencl"],
            ),
        };
        if !compiled.iter().any(|b| usable.contains(&b.as_str())) {
            return Err(format!(
                "this machine has {gpu} but this binary was built with only the {} backend(s), so \
                 every model layer would run on the CPU; install a build of tenzro-node with one \
                 of these features: {}",
                compiled.join(", "),
                usable.join(", "),
            ));
        }
    }
    Ok(())
}

pub use crate::chat::GenerationConfig;

/// Assemble the llama.cpp sampler chain for a request, with an optional grammar
/// stage in front.
///
/// Stage order mirrors llama.cpp's own default (penalties before truncation,
/// truncation before the distribution draw); optional `top_k`/`min_p` are
/// omitted entirely when unset. The grammar, when present, goes first so it
/// masks tokens that would spell a malformed tool call before any truncation or
/// temperature stage sees the distribution. `None` omits the grammar stage,
/// which is what every non-tool path passes.
fn build_sampler_chain_with_grammar(
    config: &GenerationConfig,
    grammar: Option<LlamaSampler>,
    n_vocab: i32,
) -> LlamaSampler {
    let mut stages = Vec::new();
    if let Some(g) = grammar {
        stages.push(g);
    }
    stages.push(LlamaSampler::penalties(
        n_vocab,
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
/*
 * Chat-template terminators never belong in user-visible content.
 *
 * Generation stops on an EOG token or on a matched stop STRING. A terminator that is neither --
 * `<|im_end|>` on the gemma4 GGUFs is one -- falls between both guards and renders into the reply.
 * Measured on gemma4-e2b: `4<|im_end|>` where every other model answered `4`.
 *
 * These are template markers, not content. No legitimate reply contains them, so adding them to
 * every request's stop set cannot remove anything a caller wanted. They are ADDED to the caller's
 * own stops, never replacing them.
 *
 * This lives at the point where the StopStream is built rather than at any one entry point:
 * `generate_sync_streaming` has eight callers, and an earlier attempt that patched only the
 * batched path left the node's own chat-completion path -- the one `tenzro chat` actually uses --
 * still leaking the terminator.
 */
const TEMPLATE_TERMINATORS: &[&str] = &[
    "<|im_end|>",
    "<end_of_turn>",
    "<|eot_id|>",
    "<|end|>",
    "<|endoftext|>",
    // Muse Glimmer publishes `eos_token_id = [200001, 200008]` — these two.
    // Both are near-misses for entries above and neither matches them:
    //
    //     <|eot|>          is NOT <|eot_id|>     (Llama 3.x)
    //     <|end_of_text|>  is NOT <|endoftext|>  (GPT-2 lineage)
    //
    // Close enough to read as already covered, different enough that the
    // tokenizer never matches — which is how a leak survived a list that
    // looked complete.
    "<|eot|>",
    "<|end_of_text|>",
];

/// The caller's stop strings plus the template terminators above, deduplicated.
fn stops_with_terminators(stop: &[String]) -> Vec<String> {
    let mut out = stop.to_vec();
    for t in TEMPLATE_TERMINATORS {
        if !out.iter().any(|s| s == t) {
            out.push((*t).to_string());
        }
    }
    out
}

use praecise_runtime::ChatTemplateSource;
/// The token-stream splitter lives in praecise-runtime with the engine that
/// feeds it; this path used to carry a second copy, and the two had to be
/// fixed in step.
use praecise_runtime::stream::StopStream;

// The request and result types are in `crate::chat`, which builds without the
// engine. Re-exported so `crate::runtime::…` paths stay unchanged.
pub use crate::chat::{
    ChatMessage, ChatWithToolsResult, InferenceResult, StopReason, ToolCall, ToolDefinition,
};

// The attachment marker is in `crate::chat`, which builds without the engine.
pub use crate::chat::media_marker;

/// Maximum context length we allow to prevent OOM on consumer hardware.
const MAX_CONTEXT_LENGTH: u32 = 131_072;

/// Default context length used when no catalog entry is available.
const DEFAULT_CONTEXT_LENGTH: u32 = 8192;

use crate::memory_budget::{LOAD_HEADROOM_DEN, LOAD_HEADROOM_NUM};

mod session_kv;
pub use session_kv::{ExportedDelta, SequenceEngine, SessionTurn, StandbyModel};

/// Why the batch engine cannot serve `model`, if it cannot.
///
/// An encoder-decoder model is refused. The batch engine keeps one KV stream
/// per sequence slot, and the pinned llama.cpp builds the decoder's
/// cross-attention mask for a single stream, so reserving the graph for a
/// context of more than one stream fails an assertion and aborts the process
/// instead of returning an error. The engine's spawn with sequence migration
/// happens to refuse such a model first, but for a migration reason that is
/// not why it cannot be served, and its other spawns abort. The node refuses
/// it before the engine sees it, with the actual reason.
#[must_use]
pub fn batch_engine_refusal(model: &LlamaModel) -> Option<String> {
    if model.has_encoder() && model.has_decoder() {
        return Some(
            "encoder-decoder models are not served by the batch engine: its context keeps one \
             KV stream per slot, and the engine aborts building the cross-attention graph over \
             more than one stream, so neither generation nor prefix reuse is available for them"
                .to_string(),
        );
    }
    None
}

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
    /// Speculative-decode type for a model whose MTP draft head is trained
    /// *into this same GGUF* (inline / self-speculative — `drafter_id: None`,
    /// `mtp_kind` set). `Some(0)` = draft-mtp, `Some(1)` = draft-dflash; `None`
    /// when the model has no inline head (it either uses a separate drafter or
    /// no speculation). The draft context is built from this model's own
    /// weights, so self-spec adds a context, never a second weight load.
    inline_mtp_spec_type: Option<i32>,
}

/// Whether to memory-map model weights at load.
///
/// Off by default on unified-memory machines. On a discrete-GPU box mmap lets
/// the loader page weights straight from the file into GPU memory, which is
/// why llama.cpp defaults it on. On a unified-memory host there is no such
/// transfer — CPU and GPU share one memory pool — and mapping the file adds a
/// page-fault path over memory the GPU is going to read directly, a real
/// regression rather than a wash.
///
/// `TENZRO_USE_MMAP=1` forces it back on, so the effect can be measured on a
/// given machine instead of assumed.
fn use_mmap_for_weights() -> bool {
    match std::env::var("TENZRO_USE_MMAP").ok().as_deref() {
        Some("1") | Some("true") => true,
        Some(_) => false,
        // Unified memory means the GPU reads the same pages the loader wrote;
        // there is nothing for the mapping to save.
        None => !is_unified_memory(),
    }
}

/// Whether the GPU shares its memory with the host.
///
/// Detected from the backend's device list rather than a model name, so every
/// unified-memory host takes the same path.
fn is_unified_memory() -> bool {
    llama_cpp_2::list_llama_ggml_backend_devices()
        .iter()
        .any(|d| {
            matches!(
                d.device_type,
                llama_cpp_2::LlamaBackendDeviceType::IntegratedGpu
            )
        })
}

/// Speculative type for a model whose MTP head is inline (trained into its own
/// GGUF), or `None` when it has a separate drafter or no MTP. `0` = draft-mtp,
/// `1` = draft-dflash, matching [`LoadedDrafter::spec_type`].
fn inline_mtp_spec_type(model_id: &str) -> Option<i32> {
    let entry = get_model_by_id(model_id)?;
    // A declared drafter means the separate-drafter path, not inline.
    if entry.drafter_id.is_some() {
        return None;
    }
    match entry.mtp_kind {
        MtpKind::DraftMtp => Some(0),
        MtpKind::DraftDflash => Some(1),
        MtpKind::Generic | MtpKind::None => None,
    }
}

/// Whether a separately-shipped drafter GGUF is already in the model store
/// next to its target. The store keeps a model either flat (`<id>.gguf`) or as
/// a directory of shards (`<id>/`), and the target path handed to the loader
/// may itself be a shard inside `<target-id>/`, so both the target's directory
/// and its parent are checked.
/// Whether a model paired with a drafter is served on the single-sequence
/// speculative path instead of the batching engine.
///
/// Speculation makes one stream faster; batching serves many streams at once.
/// On a model several products share, the second decides whether callers get an
/// answer at all: muse-glimmer on one speculative slot took a new request every
/// one to two and a half minutes while everyone else timed out. So batching
/// wins whenever the engine has more than one slot, and speculation is chosen
/// by setting `TENZRO_PREFER_SPECULATION=1`. The node advertises capacity with
/// this same function, so the two never disagree about which path a model is on.
pub fn prefers_speculation() -> bool {
    match std::env::var("TENZRO_PREFER_SPECULATION") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => crate::max_slots() <= 1,
    }
}

fn drafter_on_disk(target_gguf: &Path, drafter_id: &str) -> bool {
    let mut roots: Vec<&Path> = Vec::with_capacity(2);
    if let Some(dir) = target_gguf.parent() {
        roots.push(dir);
        if let Some(store) = dir.parent() {
            roots.push(store);
        }
    }
    roots.into_iter().any(|root| {
        root.join(format!("{drafter_id}.gguf")).is_file() || root.join(drafter_id).is_dir()
    })
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
/// never changes. A model the operator assigned to a hosted engine (vLLM,
/// SGLang, TensorRT-LLM, transformers) is `Hosted`: it runs in a runtime host
/// the node supervises, and answers through the same generation entry points,
/// access check and in-flight admission as the llama.cpp paths.
enum LoadedEntry {
    Batched(BatchEngine),
    Serial(Arc<tokio::sync::Mutex<LoadedModel>>),
    /// A model on a hosted engine, with the chat template its checkpoint
    /// carries.
    Hosted(
        praecise_runtime::backend::Backend,
        Arc<praecise_host::HostedModel>,
        Option<ChatTemplateSource>,
    ),
    /// The first stage of a layer pipeline across several machines; the rest
    /// of the model's blocks run on the other stages.
    Pipeline(Arc<crate::layer_pipeline::PipelineDriver>),
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
    /// Speculative algorithm for this drafter: 0 = draft-mtp, 1 = draft-dflash.
    /// Inferred from the drafter GGUF filename (`dflash-*` → DFlash) so no extra
    /// catalog threading is needed.
    spec_type: i32,
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
    /// Per-model count of requests currently in flight or waiting on the
    /// model mutex, for the stall watchdog. Admission is not decided here:
    /// every request is admitted by the node's traffic manager before it
    /// reaches the runtime.
    inflight: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// When each model's in-flight count last rose from 0. Lets the watchdog
    /// spot a request stuck far past any plausible decode time (a wedged
    /// kernel). Set on the 0→1 transition, cleared on the →0 transition.
    inflight_since: Arc<DashMap<String, std::time::Instant>>,
    /// The salted digests of recently served prompt prefixes, per model. Only
    /// their count is published; a router learns what matches by probing
    /// with digests under the caller's own salt. See [`crate::prefix_affinity`].
    warm_prefixes: Arc<DashMap<String, crate::prefix_affinity::WarmPrefixIndex>>,
    /// Model ids whose multimodal projector loaded, so they accept image or
    /// audio attachments. Held beside `loaded_models` rather than read out of
    /// `LoadedModel` so [`Self::supports_media`] is a lock-free probe — a
    /// discovery call must not queue behind an in-flight generation holding the
    /// model mutex.
    media_capable: Arc<dashmap::DashSet<String>>,
    /// Per-model-id load lock, held across the whole load so concurrent loads
    /// of the same model coalesce into one. Without it the `is_loaded` check
    /// and the map insert straddle a multi-second GPU load, so two serve
    /// requests (or a serve racing the startup reconcile) each launch a full
    /// CUDA load of the same model — two contexts contend for the one GPU and
    /// wedge it. The second caller waits here, then finds the model loaded and
    /// returns. Keyed by `model_id`; the entry is a bare mutex, never removed.
    load_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Operator stops, per model id. A stop bumps the model's generation and
    /// marks it stopped; a load records the generation it started under and
    /// installs its weights only if that is still current and the model is
    /// not stopped, checked under this same lock. A load that was already
    /// running when the operator stopped the model therefore discards what it
    /// loaded instead of leaving weights resident for a model nothing serves.
    /// Only [`Self::resume_model`] lets a stopped model load again.
    stops: Arc<parking_lot::Mutex<std::collections::HashMap<String, StopState>>>,
    /// Which engine holds each model on this node. A load here claims the
    /// model for the Praecise engine and is refused while an ONNX runtime
    /// holds it.
    host: Arc<crate::model_host::ModelHost>,
    backend: Arc<LlamaBackend>,
    hardware: HardwareInfo,
    /// Continuity sessions and standby weights.
    sessions: Arc<session_kv::SessionStore>,
}

/// One model's operator-stop record. See `ModelRuntime::stops`.
#[derive(Debug, Default, Clone, Copy)]
struct StopState {
    generation: u64,
    stopped: bool,
}

/// The generation a load started under, checked again when it installs.
#[derive(Debug, Clone, Copy)]
struct LoadTicket(u64);

/// RAII guard that decrements a model's in-flight counter on drop, so the
/// slot is released whether generation succeeds, errors, or the task is
/// cancelled (client disconnect).
struct InflightGuard {
    counter: Arc<AtomicUsize>,
    model_id: String,
    inflight_since: Arc<DashMap<String, std::time::Instant>>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // fetch_sub returns the prior value; `1` means this was the last
        // in-flight request, so the model is idle again — clear its start stamp.
        if self.counter.fetch_sub(1, Ordering::SeqCst) <= 1 {
            self.inflight_since.remove(&self.model_id);
        }
    }
}

/// Flips its flag to `true` when dropped. Held across a serial decode's
/// `spawn_blocking` await: if the awaiting task is cancelled (client
/// disconnect) before the blocking decode returns, the guard drops and the
/// decode loop observes the flag and stops. Dropping the `JoinHandle` alone
/// does not stop a blocking task, so this is how in-flight GPU work is released
/// on cancellation of a non-streaming serial request (the batched scheduler
/// and the streaming path already detect this via `result_tx`/`token_tx`).
struct CancelOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl ModelRuntime {
    pub fn new() -> Result<Self> {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims the models it loads through `host`, which it
    /// shares with the node's ONNX runtimes so no model is loaded twice.
    ///
    /// A GPU build fails when this machine has a GPU that none of its compiled
    /// backends can drive: every layer would otherwise run on the CPU. The CPU
    /// build starts and serves CPU-tier models only (`hardware_policy`).
    pub fn with_host(host: Arc<crate::model_host::ModelHost>) -> Result<Self> {
        let backend = llama_backend();

        let has_gpu = backend.supports_gpu_offload();
        let hardware = HardwareInfo::detect(has_gpu);

        info!(
            "llama.cpp backend initialized — {} on {}/{} (compiled backends: {})",
            hardware.active_backend,
            hardware.os,
            hardware.cpu_arch,
            hardware.compiled_backends.join(", "),
        );

        // A GPU with no compiled backend for it would put every layer on the
        // CPU while the model loads and answers normally, so it is refused.
        // Detected hardware is compared against the compiled backend list,
        // not llama.cpp's offload flag, which a CPU-only build never sets.
        if let Some(notice) = check_llm_gpus(detected_gpus(), &hardware.compiled_backends, has_gpu)
            .map_err(ModelError::ProviderNotAvailable)?
        {
            warn!("{notice}");
        }

        Ok(Self {
            loaded_models: Arc::new(DashMap::new()),
            loaded_drafters: Arc::new(DashMap::new()),
            inflight: Arc::new(DashMap::new()),
            inflight_since: Arc::new(DashMap::new()),
            warm_prefixes: Arc::new(DashMap::new()),
            media_capable: Arc::new(dashmap::DashSet::new()),
            load_locks: Arc::new(DashMap::new()),
            stops: Arc::default(),
            host,
            backend,
            hardware,
            sessions: Arc::new(session_kv::SessionStore::default()),
        })
    }

    /// The per-model-id load lock, created on first use. Held across a load so
    /// concurrent loads of the same model serialize and coalesce (see the
    /// `load_locks` field). Cloned out of the map so the guard is not held
    /// while awaiting the lock.
    fn load_lock(&self, model_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.load_locks
            .entry(model_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// The ticket a load of `model_id` carries to its install, or a refusal
    /// when the operator has stopped the model.
    fn load_ticket(&self, model_id: &str) -> Result<LoadTicket> {
        let state = self.stops.lock().get(model_id).copied().unwrap_or_default();
        if state.stopped {
            return Err(Self::stopped_error(model_id));
        }
        Ok(LoadTicket(state.generation))
    }

    fn stopped_error(model_id: &str) -> ModelError {
        ModelError::ProviderNotAvailable(format!(
            "{model_id} was stopped by the operator; serve it again to load it"
        ))
    }

    /// Install a loaded entry, unless the model was stopped after the load
    /// took `ticket`. The check and the insert happen under the stop lock, so
    /// a stop either sees the entry and unloads it, or the entry is handed
    /// back to the caller to tear down.
    fn install(
        &self,
        model_id: &str,
        ticket: LoadTicket,
        entry: LoadedEntry,
    ) -> std::result::Result<(), LoadedEntry> {
        let mut entry = Some(entry);
        let installed = self.install_if_current(model_id, ticket, || {
            if let Some(entry) = entry.take() {
                self.loaded_models
                    .insert(model_id.to_string(), Arc::new(entry));
            }
        });
        match entry {
            Some(entry) if !installed => Err(entry),
            _ => Ok(()),
        }
    }

    /// Run `insert` under the stop lock if no stop has landed since `ticket`
    /// was taken; returns whether it ran.
    fn install_if_current(
        &self,
        model_id: &str,
        ticket: LoadTicket,
        insert: impl FnOnce(),
    ) -> bool {
        let stops = self.stops.lock();
        let state = stops.get(model_id).copied().unwrap_or_default();
        if state.stopped || state.generation != ticket.0 {
            return false;
        }
        insert();
        true
    }

    /// Mark `model_id` stopped without unloading anything: every load of it
    /// is refused, and a load already running discards its weights, until
    /// [`Self::resume_model`]. Used for models the operator stopped in an
    /// earlier run of the node.
    pub fn hold_stopped(&self, model_id: &str) {
        let mut stops = self.stops.lock();
        let state = stops.entry(model_id.to_string()).or_default();
        state.generation = state.generation.wrapping_add(1);
        state.stopped = true;
    }

    /// Stop serving `model_id`: refuse every later load of it, make any load
    /// already running discard its weights, then unload it. Returns whether
    /// weights were resident.
    ///
    /// Unlike [`Self::unload_model`], which eviction also uses and which a
    /// later request may undo by loading the model again, this holds until
    /// [`Self::resume_model`].
    pub async fn stop_model(&self, model_id: &str) -> Result<bool> {
        self.hold_stopped(model_id);
        // Drafter first: it is keyed by the target's id.
        let _ = self.unload_drafter(model_id).await;
        match self.unload_model(model_id).await {
            Ok(()) => Ok(true),
            Err(ModelError::ModelNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Let a stopped model load again. Called by an explicit serve.
    pub fn resume_model(&self, model_id: &str) {
        if let Some(state) = self.stops.lock().get_mut(model_id) {
            state.stopped = false;
        }
    }

    /// Whether the operator has stopped `model_id` and not served it since.
    pub fn is_stopped(&self, model_id: &str) -> bool {
        self.stops
            .lock()
            .get(model_id)
            .is_some_and(|state| state.stopped)
    }

    /// Tear down an entry whose load lost to a stop. The load's admission and
    /// engine claim are released by their own guards, which were never
    /// committed.
    fn discard(&self, model_id: &str, entry: LoadedEntry) -> ModelError {
        self.media_capable.remove(model_id);
        match &entry {
            LoadedEntry::Batched(engine) => engine.shutdown(),
            LoadedEntry::Pipeline(driver) => driver.shutdown(),
            LoadedEntry::Serial(_) => {}
            LoadedEntry::Hosted(backend, ..) => self
                .host
                .release(model_id, crate::model_host::Engine::Hosted(*backend)),
        }
        drop(entry);
        warn!("{model_id}: stopped while loading; the loaded weights were discarded");
        ModelError::ProviderNotAvailable(format!(
            "{model_id} was stopped while it was loading; the loaded weights were discarded"
        ))
    }

    /// Record that `model_id` just served `prompt` under the current cache
    /// salt. A request with no salt (an anonymous caller) is not recorded:
    /// nothing could ever probe for it, and recording it unkeyed would let one
    /// caller's prompt be matched by another.
    pub fn record_warm_prompt(&self, model_id: &str, prompt: &[u8]) {
        let Some(salt) = crate::prefix_affinity::current() else {
            return;
        };
        let digests = crate::prefix_affinity::salted_prefix_digests(&salt, prompt);
        if digests.is_empty() {
            return;
        }
        self.warm_prefixes
            .entry(model_id.to_string())
            .or_default()
            .record(&digests);
    }

    /// Leading runs of a probed prompt each model holds warm, for every model
    /// with a match. The probe's digests were computed under the prober's
    /// salt, so only prefixes served under that salt can match.
    pub fn probe_warm_prefix(
        &self,
        digests: &[crate::prefix_affinity::PrefixDigest],
    ) -> std::collections::HashMap<String, u32> {
        self.warm_prefixes
            .iter()
            .filter_map(|e| {
                let runs = e.value().longest_match(digests);
                (runs > 0).then(|| (e.key().clone(), runs))
            })
            .collect()
    }

    /// What this node publishes about its warm prefixes: how many runs it
    /// holds across all models and callers, and nothing about which.
    pub fn warm_prefix_summary(&self) -> tenzro_types::PrefixCacheSummary {
        let runs: usize = self.warm_prefixes.iter().map(|e| e.value().len()).sum();
        tenzro_types::PrefixCacheSummary {
            warm_runs: runs.min(u32::MAX as usize) as u32,
        }
    }

    /// Count a request against `model_id` for the stall watchdog, returning an
    /// RAII guard that uncounts it on drop. Admission (how many requests a
    /// model takes, and who waits) is the node's traffic manager's decision,
    /// made before the request reaches the runtime.
    fn track_inflight(&self, model_id: &str) -> InflightGuard {
        let counter = self
            .inflight
            .entry(model_id.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .value()
            .clone();
        let prior = counter.fetch_add(1, Ordering::SeqCst);
        // Stamp the 0→1 transition so the watchdog can measure how long this
        // model has been continuously busy (a stuck kernel never returns to 0).
        if prior == 0 {
            self.inflight_since
                .insert(model_id.to_string(), std::time::Instant::now());
        }
        InflightGuard {
            counter,
            model_id: model_id.to_string(),
            inflight_since: self.inflight_since.clone(),
        }
    }

    /// Models whose in-flight work has been continuous for longer than
    /// `deadline` — i.e. a request that never returned to zero, the signature of
    /// a wedged decode. Read by the node's watchdog, which only logs and steers
    /// routing away; it never force-kills (validator-safe).
    pub fn stalled_inflight(
        &self,
        deadline: std::time::Duration,
    ) -> Vec<(String, std::time::Duration)> {
        let now = std::time::Instant::now();
        self.inflight_since
            .iter()
            .filter_map(|e| {
                let age = now.saturating_duration_since(*e.value());
                (age >= deadline).then(|| (e.key().clone(), age))
            })
            .collect()
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
    /// Two gates, and a load must pass both.
    ///
    /// **The ledger** charges `file_len x headroom` against the declared
    /// [`Tier::Resident`] pool. It must stay the authority on concurrency:
    /// its admission is an atomic check-and-commit, so two simultaneous loads
    /// cannot both observe the same room and both take it. Free-memory reads
    /// have no such property.
    ///
    /// **The ground** then asks the kernel what the machine actually has. The
    /// ledger cannot answer that, because it only knows what it allocated
    /// itself — memory taken by another process, or by a build someone started
    /// on the box, is invisible to it. That gap is not hypothetical: a host was
    /// driven to unreachable while every figure this ledger held said there was
    /// room.
    ///
    /// The original objection to reading free memory was sound and is answered
    /// rather than ignored. It counts space RocksDB's block cache would grow
    /// into as available — so the ground keeps a margin unspent instead of
    /// lending out the last free byte, and `available_memory` is used rather
    /// than `free_memory` so reclaimable cache is not miscounted as gone. The
    /// race objection is answered by keeping the ledger first and authoritative
    /// for allocation; the ground is a veto over it, never a substitute.
    ///
    /// Order matters: the ground is checked **after** the ledger and its
    /// commitment is released on refusal, so a machine-level refusal does not
    /// leave a phantom reservation behind.
    ///
    /// The commitment is released by [`unload_model`](Self::unload_model).
    /// `TENZRO_SKIP_MODEL_ADMISSION=1` bypasses both checks for operators who
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
            })?;

        if let Err(denied) =
            crate::ground::global().admits(model_id, crate::ground::Axis::Memory, required)
        {
            // Hand back the reservation the ledger just granted. Leaving it
            // would shrink the pool for every later load on the strength of a
            // load that never happened.
            crate::memory_budget::global().release(model_id);
            tracing::warn!(
                model_id = %model_id,
                required_mb = required / 1_048_576,
                "refusing load: the budget had room but the machine does not — {denied}",
            );
            return Err(ModelError::InsufficientMemory {
                model_id: model_id.to_string(),
                required_mb: required / 1_048_576,
                available_mb: denied
                    .measured_free
                    .map(|f| f.saturating_sub(denied.margin) / 1_048_576)
                    .unwrap_or(0),
            });
        }

        Ok(())
    }

    /// Detected local hardware, probed once per process. Detection shells
    /// out to vendor tools (`nvidia-smi` / `rocm-smi`), so callers must be
    /// on a blocking thread — both load paths run inside `spawn_blocking`.
    pub(crate) fn local_hardware() -> &'static tenzro_types::HardwareCapabilities {
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

    /// The longest context whose KV cache still fits the GPU this node actually has.
    ///
    /// `operator_context_cap` above documents the failure: a 131072-token catalog entry asks for a
    /// KV cache larger than a consumer card's whole VRAM, and the load dies on device allocation.
    /// It said "unset means trust the catalog", and trusting it is exactly what fails. Measured
    /// here: a 2.49 GB phi4-mini declaring 128000 tokens asked for a **16 GiB** KV cache on a
    /// 16 GiB card and refused to serve, while its weights would have fitted six times over.
    ///
    /// A shorter window is what the operator wanted in every such case: a model serving 8k of
    /// context is useful, one that will not load is not. The operator cap still wins when set;
    /// this only replaces "trust the catalog" with "trust the card".
    ///
    /// The estimate is deliberately an UPPER bound on bytes-per-token — two caches, every layer,
    /// full embedding width, 2 bytes per element. Grouped-query attention makes the real figure
    /// smaller, so erring here costs context and never a failed load. `None` when no VRAM was
    /// detected, leaving unified-memory and CPU-only hosts exactly as they were.
    fn vram_context_cap(n_layer: u32, n_embd: u32) -> Option<u32> {
        let hw = Self::local_hardware();
        if !hw.detected
            || hw.vram_gb == 0
            || hw.interconnect == tenzro_types::Interconnect::UnifiedMemory
        {
            return None;
        }
        let bytes_per_token =
            2u64 * u64::from(n_layer) * u64::from(n_embd) * Self::kv_bytes_per_element();
        if bytes_per_token == 0 {
            return None;
        }
        // Weights, activations and compute buffers share the card, so the KV cache gets a share
        // rather than the lot. A third leaves room for a model roughly its own size beside it.
        let kv_budget = (u64::from(hw.vram_gb) * 1_073_741_824) / 3;
        let cap = (kv_budget / bytes_per_token).min(u64::from(u32::MAX)) as u32;
        Some(cap.max(2048))
    }

    /// KV cache element type, from `TENZRO_KV_CACHE_TYPE`. Defaults to `q8_0`.
    ///
    /// The KV cache is stored at f16 unless told otherwise, and on a consumer card it is the
    /// allocation that decides whether a long-context model serves at all: a 2.49 GB phi4-mini
    /// declaring 128000 tokens asked for a 16 GiB cache on a 16 GiB card and failed to load.
    /// `q8_0` halves that for, in llama.cpp's own perplexity numbers, a change in the fifth
    /// decimal place — 5.96000 to 5.96004 on a 7B. Practically lossless, and it doubles the
    /// context that fits.
    ///
    /// `q4_0` is offered and NOT the default. The cost is asymmetric — roughly 0.4% perplexity on
    /// the K cache against ~1.4% on V — so an operator who wants it should choose it knowingly
    /// rather than inherit it.
    ///
    /// K and V are set to the SAME type deliberately. Mismatched types miss the fused
    /// flash-attention kernel, and a quantized cache without that kernel is dequantized on every
    /// attention step, which is slower than not quantizing at all.
    fn kv_cache_type() -> llama_cpp_2::context::params::KvCacheType {
        use llama_cpp_2::context::params::KvCacheType;
        match std::env::var("TENZRO_KV_CACHE_TYPE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "f16" | "fp16" => KvCacheType::F16,
            "bf16" => KvCacheType::BF16,
            "q4_0" | "q4" => KvCacheType::Q4_0,
            // Unset or unrecognised: the lossless-in-practice default.
            _ => KvCacheType::Q8_0,
        }
    }

    /// Bytes per token of KV cache for the configured cache type.
    ///
    /// Used by [`vram_context_cap`] so the context ceiling reflects the cache actually being
    /// allocated. Quantizing without telling the ceiling about it would leave the node serving a
    /// context half as long as it could.
    fn kv_bytes_per_element() -> u64 {
        use llama_cpp_2::context::params::KvCacheType;
        match Self::kv_cache_type() {
            KvCacheType::F16 | KvCacheType::BF16 => 2,
            KvCacheType::Q8_0 => 1,
            // q4_0 is 4 bits plus a per-block scale; 1 byte per element is the safe over-estimate.
            _ => 1,
        }
    }

    /// Prompt batch size for architectures with a fixed per-micro-batch cost.
    /// See [`ModelRuntime::prefers_large_ubatch`].
    const LARGE_PROMPT_BATCH: u32 = 2048;

    /// The GGUF's `general.architecture` string, when it declares one.
    ///
    /// Read from the file itself rather than the catalog so an uncatalogued
    /// GGUF still gets the right cache type and batch size — serving is
    /// model-agnostic and the file is the authority on what it is.
    fn model_arch(model: &LlamaModel) -> Option<String> {
        model.meta_val_str("general.architecture").ok()
    }

    /// Architectures whose attention path cannot read a quantized KV cache.
    ///
    /// Empty today. `qwen4_exp` used to be here: its sparse-attention (QSA)
    /// graph was copied from the dense `build_attn` path without the Hadamard
    /// rotation a quantized cache is stored under, so a quantized K or V
    /// aborted inside the attention build rather than degrading. The vendored
    /// graph now applies that rotation to q/k/v on the way in and undoes it on
    /// the output — the rotation is its own inverse — so the quantized cache
    /// works and the measured perplexity cost is in the fifth decimal.
    ///
    /// Kept rather than deleted because the next architecture to copy a dense
    /// attention path will hit the same thing, and a named predicate is where
    /// that belongs.
    fn requires_f16_kv(_arch: &str) -> bool {
        false
    }

    /// Context params with the KV cache and attention kernel this host should actually use.
    ///
    /// Every context was built as `LlamaContextParams::default().with_n_ctx(..)`, which leaves the
    /// KV cache at f16 and the attention policy at llama.cpp's default. On a consumer card the KV
    /// cache is what decides whether a long-context model serves at all, and f16 is twice the size
    /// it needs to be for, in llama.cpp's published perplexity numbers, a difference in the fifth
    /// decimal place.
    ///
    /// Flash attention is requested EXPLICITLY whenever the cache is quantized, not left on `auto`.
    /// Without the fused kernel a quantized cache is dequantized on every attention step, which is
    /// slower than never quantizing — so the two settings are chosen together or not at all. K and
    /// V take the same type for the same reason: mismatched types miss the fused path.
    ///
    /// `arch` is the `general.architecture` string. Passing it lets the KV
    /// cache type and the prompt batch size be chosen per architecture rather
    /// than from one global default: an architecture whose attention path
    /// cannot read a quantized cache is given f16 regardless of the host
    /// setting, and one that pays a fixed per-micro-batch cost is given a
    /// larger prompt batch.
    fn tuned_context_params_for(n_ctx: u32, arch: Option<&str>) -> LlamaContextParams {
        use llama_cpp_2::context::params::KvCacheType;
        let mut kv = Self::kv_cache_type();
        if let Some(a) = arch
            && Self::requires_f16_kv(a)
            && !matches!(kv, KvCacheType::F16 | KvCacheType::BF16)
        {
            tracing::info!(
                arch = a,
                "forcing f16 KV cache: this architecture's attention path \
                 cannot read a quantized cache"
            );
            kv = KvCacheType::F16;
        }
        let quantized = !matches!(kv, KvCacheType::F16 | KvCacheType::BF16);
        let policy = if quantized {
            llama_cpp_sys_2::LLAMA_FLASH_ATTN_TYPE_ENABLED
        } else {
            llama_cpp_sys_2::LLAMA_FLASH_ATTN_TYPE_AUTO
        };

        let mut params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(n_ctx))
            .with_type_k(kv)
            .with_type_v(kv)
            .with_flash_attention_policy(policy);

        // Prompt batch size. The library's `n_batch` already defaults to 2048;
        // `n_ubatch` is the one left at 512, and it is the single biggest
        // prefill lever on the sparse-attention architectures. Their per-graph
        // indexer cost is paid once per micro-batch regardless of its size, so
        // a 4x larger micro-batch amortizes it 4x. Measured on a unified-memory
        // host this is worth roughly 4.7x prefill on `qwen4_exp` — a larger model at ubatch
        // 2048 out-prefills a smaller one at 512. Both are set together so the
        // batch can never be smaller than the micro-batch.
        //
        // Note this is the embedded library, not `llama-server`: its slot
        // count (`n_seq_max`) defaults to 1 here, so the multi-slot abort that
        // affects the standalone server's default of 4 does not apply.
        if let Some(a) = arch
            && Self::prefers_large_ubatch(a)
        {
            params = params.with_n_batch(Self::LARGE_PROMPT_BATCH);
            params = params.with_n_ubatch(Self::LARGE_PROMPT_BATCH);
        }
        params
    }

    /// Architectures that pay a fixed per-micro-batch cost large enough that
    /// the default 512-token prompt batch leaves most of the prefill on the
    /// table. Currently the sparse-attention line, whose indexer runs once per
    /// graph over the whole cache.
    fn prefers_large_ubatch(arch: &str) -> bool {
        matches!(arch, "qwen4_exp" | "qwen4exp")
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
        // Operator escape hatch, because the headroom below is sized for a
        // full-context KV cache and an operator who has capped the context
        // knows better. Measured: qwen3.8-27b UD-Q3_K_XL (12.52 GiB) on a 16 GB
        // RTX 5070 Ti with TENZRO_MAX_CONTEXT=4096 allocates a 16 MiB KV cache,
        // yet 12.52 x 1.29 = 16.15 GiB "needed" beat the 15 GiB detected VRAM
        // and stranded 5 of 66 layers (1401 MiB) in system RAM. Every token then
        // crossed the CPU boundary and decode fell to 10.3 tok/s — slower than
        // the same model on a unified-memory host at NVFP4 (19.4 tok/s) despite the card having
        // 3.3x the memory bandwidth. Set TENZRO_GPU_LAYERS=1000 to force full
        // offload; the load still fails loudly on device allocation if it truly
        // does not fit, which is the honest failure mode.
        if let Ok(v) = std::env::var("TENZRO_GPU_LAYERS")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            return n;
        }
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
        self.load(model_id, gguf_path, context_length, None).await
    }

    /// Load the base GGUF at `base_path` under `model_id` and serve the LoRA
    /// adapter of `adapter` on it. The adapter file is pinned by its SHA-256:
    /// a file that differs, or one the base refuses, fails the load and
    /// nothing is registered.
    pub async fn load_model_with_adapter(
        &self,
        model_id: &str,
        base_path: &Path,
        adapter: crate::AdapterSpec,
        context_length: Option<u32>,
    ) -> Result<()> {
        self.load(model_id, base_path, context_length, Some(adapter))
            .await
    }

    async fn load(
        &self,
        model_id: &str,
        gguf_path: &Path,
        context_length: Option<u32>,
        adapter: Option<crate::AdapterSpec>,
    ) -> Result<()> {
        // Taken before anything else: a stop from here on wins.
        let ticket = self.load_ticket(model_id)?;
        if self.is_loaded(model_id) {
            info!("Model {} already loaded", model_id);
            return Ok(());
        }

        // Single-flight: serialize concurrent loads of this same model so only
        // one GPU load ever runs. A second caller that raced past the check
        // above blocks here, then the re-check below finds the model loaded and
        // returns — without this, both would load a full CUDA context of the
        // same model and wedge the GPU.
        let load_lock = self.load_lock(model_id);
        let _load_guard = load_lock.lock().await;
        if self.is_loaded(model_id) {
            info!("Model {} already loaded (coalesced)", model_id);
            return Ok(());
        }
        // A stop that landed while this caller waited for the lock.
        if self.load_ticket(model_id)?.0 != ticket.0 {
            return Err(Self::stopped_error(model_id));
        }
        // One engine per model: refused here, before any weights are read,
        // while an ONNX runtime holds it. Given back if the load fails.
        let claim = self
            .host
            .claim(model_id, crate::model_host::Engine::Praecise)?;

        // Admission control: refuse to load a model that won't fit in memory
        // rather than let llama.cpp OOM-kill the process mid-load. Uses the
        // GGUF file size (≈ resident weight footprint) plus a headroom margin
        // for the KV cache and activation buffers.
        let file_len = std::fs::metadata(gguf_path)?.len();
        crate::hardware_policy::check_model(
            model_id,
            file_len,
            crate::hardware_policy::usable_accelerators(),
        )
        .map_err(ModelError::ProviderNotAvailable)?;
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
        #[cfg(unix)]
        let staged = self.sessions.staged_for(model_id, gguf_path);

        let loaded = tokio::task::spawn_blocking(move || {
            // GPU offload sized against detected VRAM — full offload when the
            // model fits (or the pool is unified / undetected), a proportional
            // layer count when it doesn't.
            let n_gpu_layers = Self::gpu_layer_budget(&gguf_path_owned, file_len);
            // Load the inline MTP/NextN head when this model self-speculates
            // (catalog `mtp_kind` set, no separate drafter). Without it the
            // `blk.<n>.nextn.*` tensors are skipped as "unused" and the self-spec
            // draft fails (status -3); off otherwise so boot memory does not
            // carry a head the model will not use.
            let model_params = LlamaModelParams::default()
                .with_n_gpu_layers(n_gpu_layers)
                .with_use_mmap(use_mmap_for_weights())
                .with_load_mtp(inline_mtp_spec_type(&model_id_owned).is_some());

            // Weights staged on standby are already resident: activating them
            // skips the read from storage.
            #[cfg(unix)]
            let mut model = match &staged {
                Some(staged) => staged.activate(&backend, &model_params).map_err(|e| {
                    ModelError::Other(format!(
                        "Failed to activate standby model '{model_id_owned}': {e}"
                    ))
                }),
                None => crate::parse_jail::load_llama(&backend, &gguf_path_owned, &model_params)
                    .map_err(|e| {
                        ModelError::Other(format!(
                            "Failed to load GGUF model '{}': {}",
                            model_id_owned, e
                        ))
                    }),
            }?;
            #[cfg(not(unix))]
            let mut model =
                crate::parse_jail::load_llama(&backend, &gguf_path_owned, &model_params).map_err(
                    |e| {
                        ModelError::Other(format!(
                            "Failed to load GGUF model '{}': {}",
                            model_id_owned, e
                        ))
                    },
                )?;

            if let Some(spec) = &adapter {
                praecise_runtime::attach_adapter(&mut model, spec).map_err(|e| {
                    ModelError::Other(format!("'{model_id_owned}' adapter refused: {e}"))
                })?;
                info!(
                    "{}: serving adapter {} on its base",
                    model_id_owned,
                    spec.path.display()
                );
            }

            // Determine context length:
            // - If caller provides a context_length, use it (capped at MAX_CONTEXT_LENGTH
            //   and the model's trained context)
            // - Otherwise default to DEFAULT_CONTEXT_LENGTH (safe default)
            let trained_ctx = model.n_ctx_train();
            let effective_ctx = match context_length {
                Some(requested) => trained_ctx.min(requested).min(MAX_CONTEXT_LENGTH),
                None => trained_ctx.min(DEFAULT_CONTEXT_LENGTH),
            };
            // The operator ceiling wins outright. With none set, the CARD's ceiling applies:
            // "trust the catalog" is what turned a servable model into a failed allocation.
            let effective_ctx = match Self::operator_context_cap() {
                Some(cap) => effective_ctx.min(cap.max(1)),
                None => {
                    let vram_cap =
                        Self::vram_context_cap(model.n_layer() as u32, model.n_embd() as u32);
                    match vram_cap {
                        Some(cap) if cap < effective_ctx => {
                            warn!(
                                "{}: context reduced {} -> {} so the KV cache fits detected VRAM. \
                                 Set TENZRO_MAX_CONTEXT to choose this yourself.",
                                model_id_owned, effective_ctx, cap
                            );
                            cap
                        }
                        _ => effective_ctx,
                    }
                }
            };

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
                inline_mtp_spec_type: inline_mtp_spec_type(&model_id_owned),
            })
        })
        .await
        .map_err(|e| ModelError::Other(format!("Task join error: {}", e)))??;

        let elapsed = start.elapsed();
        info!("Model {} loaded in {:.2}s", model_id, elapsed.as_secs_f64(),);

        // A model that will speculate is served on the serial single-context
        // path only when the operator prefers speculation (see
        // `prefers_speculation`): speculative decoding runs the target and a
        // drafter as two contexts that can't share one batch scheduler. Every
        // other model, including one with a multimodal projector, is served
        // through the continuous-batching engine, which prefills media per
        // sequence and decodes it with the rest of the batch.
        //
        // "Will speculate" is decided from what is on disk now, not from the
        // catalog pairing alone: an inline head always counts, a separate
        // drafter counts only if its GGUF is already beside the target. A
        // paired model whose drafter is absent takes the batched path with
        // every slot — the node applies the same rule when it advertises
        // concurrency, so the two never disagree about which path a model is
        // on. A drafter that appears later cannot attach to a batched target
        // (`load_drafter` refuses); the model has to be re-served.
        let wants_drafter = get_model_by_id(model_id)
            .map(|e| {
                e.mtp_kind != MtpKind::None
                    && e.drafter_id
                        .as_deref()
                        .is_none_or(|d| drafter_on_disk(gguf_path, d))
            })
            .unwrap_or(false);

        #[cfg(feature = "mtmd")]
        let has_projector = loaded.projector.is_some();
        #[cfg(not(feature = "mtmd"))]
        let has_projector = false;

        let entry = if wants_drafter && prefers_speculation() {
            LoadedEntry::Serial(Arc::new(tokio::sync::Mutex::new(loaded)))
        } else {
            #[cfg(feature = "mtmd")]
            let mut loaded = loaded;
            #[cfg(feature = "mtmd")]
            let projector = loaded.projector.take();
            let LoadedModel {
                model,
                backend,
                context_length,
                ..
            } = loaded;
            if let Some(reason) = batch_engine_refusal(&model) {
                return Err(ModelError::Unservable {
                    model_id: model_id.to_string(),
                    reason,
                });
            }
            // Policy is decided here and handed to the engine, rather than the
            // engine reaching back into the catalog. Resolved once per load: it
            // is a function of the model id, so a per-request lookup only
            // repeated the same answer.
            // This is the model's default thinking mode. The batch engine
            // renders the chat template per request, so a request's own
            // `enable_thinking` overrides it, and the engine's per-request
            // reasoning budget closes the block before `max_tokens` runs out,
            // so a small `max_tokens` still gets an answer.
            let enable_thinking = crate::catalog::resolve_enable_thinking(model_id, None);
            #[cfg(feature = "mtmd")]
            let speculation = self.batch_speculation(model_id, gguf_path).await;
            #[cfg(not(feature = "mtmd"))]
            let (projector, speculation) = (None, None);
            // Every batched model can move its sequences to another engine of
            // the same weights, so any of them serves continuity sessions.
            let fingerprint = self.weights_fingerprint(model_id, gguf_path).await?;
            let engine = BatchEngine::spawn_with_migration(
                model_id.to_string(),
                model,
                backend,
                context_length,
                enable_thinking,
                projector,
                speculation,
                fingerprint,
            )?;
            LoadedEntry::Batched(engine)
        };

        if has_projector {
            self.media_capable.insert(model_id.to_string());
        }
        if let Err(entry) = self.install(model_id, ticket, entry) {
            return Err(self.discard(model_id, entry));
        }
        self.sessions.record_path(model_id, gguf_path);
        // Registered: `unload_model` now owns releasing this commitment.
        admission.commit();
        claim.commit();

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
            image_min_tokens: -1,
            image_max_tokens: -1,
            ..MtmdContextParams::default()
        };

        // SAFETY: the projector only ever lives beside this model and is
        // dropped first: in `LoadedModel` it is declared ahead of `model`, and
        // the batch engine drops it explicitly before the model it moved onto
        // its thread.
        match unsafe { MtmdContext::init_from_file(path_str, model, &params) } {
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
    /// The speculation a batched model serves with, from the catalog and the
    /// operator's switch.
    ///
    /// `TENZRO_BATCH_SPECULATION`: `off`, `mtp` (the target's own head), a
    /// drafter's catalog id or GGUF path, or unset for automatic: the catalog's
    /// paired drafter when its GGUF is on disk, else an inline MTP head, else
    /// none. `TENZRO_BATCH_DRAFT_N` caps the tokens drafted per step, defaulting
    /// to the catalog's measured draft length, else 4.
    ///
    /// A drafter that fails to load leaves the model served without
    /// speculation, never unserved.
    async fn batch_speculation(
        &self,
        model_id: &str,
        gguf_path: &Path,
    ) -> Option<BatchSpeculation> {
        let entry = get_model_by_id(model_id);
        let n_max = std::env::var("TENZRO_BATCH_DRAFT_N")
            .ok()
            .and_then(|v| v.trim().parse::<u8>().ok())
            .or_else(|| entry.as_ref().and_then(|e| e.mtp_default_draft_n))
            .unwrap_or(4)
            .clamp(1, 16);
        let choice = std::env::var("TENZRO_BATCH_SPECULATION")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let drafter_path = |id: &str| -> Option<std::path::PathBuf> {
            let as_path = Path::new(id);
            if as_path.extension().is_some_and(|e| e == "gguf") && as_path.is_file() {
                return Some(as_path.to_path_buf());
            }
            let dir = gguf_path.parent()?;
            [
                dir.join(format!("{id}.gguf")),
                dir.parent()?.join(format!("{id}.gguf")),
            ]
            .into_iter()
            .find(|p| p.is_file())
        };

        let drafter = match choice.as_deref() {
            Some("off") | Some("0") | Some("false") => return None,
            Some("mtp") => None,
            Some(id) => match drafter_path(id) {
                Some(p) => Some(p),
                None => {
                    warn!(
                        "TENZRO_BATCH_SPECULATION={id}: no drafter GGUF found; serving {model_id} without speculation"
                    );
                    return None;
                }
            },
            None => entry
                .as_ref()
                .and_then(|e| e.drafter_id.as_deref())
                .and_then(drafter_path),
        };

        let Some(path) = drafter else {
            // The target's own head, when it has one.
            let kind = inline_mtp_spec_type(model_id)?;
            return Some(BatchSpeculation {
                spec_type: kind,
                n_max,
                draft_model: None,
            });
        };

        // The filename names the algorithm: DSpark drafters ship as `*-dspark`,
        // DFlash and DFlash2 as `*-dflash*` (the GGUF itself says which DFlash).
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let spec_type = if file.contains("dspark") {
            2
        } else if file.contains("dflash") {
            1
        } else {
            0
        };
        let backend = self.backend.clone();
        let file_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let load_path = path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let params = LlamaModelParams::default()
                .with_n_gpu_layers(Self::gpu_layer_budget(&load_path, file_len))
                .with_load_mtp(true);
            crate::parse_jail::load_llama(&backend, &load_path, &params)
        })
        .await;
        match loaded {
            Ok(Ok(model)) => {
                info!(
                    "{model_id}: batched speculation with drafter {}",
                    path.display()
                );
                Some(BatchSpeculation {
                    spec_type,
                    n_max,
                    draft_model: Some(model),
                })
            }
            Ok(Err(e)) => {
                warn!(
                    "{model_id}: drafter {} failed to load ({e}); serving without speculation",
                    path.display()
                );
                None
            }
            Err(e) => {
                warn!("{model_id}: drafter load task failed ({e}); serving without speculation");
                None
            }
        }
    }

    pub async fn unload_model(&self, model_id: &str) -> Result<()> {
        self.media_capable.remove(model_id);
        self.sessions.forget_model(model_id);
        if let Some((_, entry)) = self.loaded_models.remove(model_id) {
            let engine = match entry.as_ref() {
                LoadedEntry::Batched(engine) => {
                    // Stop the scheduler thread and join it, which drops the
                    // owned model + context. In-flight requests receive an
                    // error on their result channel.
                    engine.shutdown();
                    crate::model_host::Engine::Praecise
                }
                LoadedEntry::Serial(model_mutex) => {
                    // Acquire the mutex to wait for any in-progress generation
                    // to finish before dropping the llama.cpp model context.
                    // Without this, the model stays in memory until the
                    // generation task completes, causing OOM when loading
                    // another model.
                    let _lock = model_mutex.lock().await;
                    drop(_lock);
                    crate::model_host::Engine::Praecise
                }
                // Releasing the claim below stops the runtime host once its
                // last request ends, and returns its memory to the budget.
                LoadedEntry::Hosted(backend, ..) => crate::model_host::Engine::Hosted(*backend),
                LoadedEntry::Pipeline(driver) => {
                    driver.shutdown();
                    crate::model_host::Engine::Praecise
                }
            };
            drop(entry);
            // Return the claim to the resident tier only after the context is
            // actually gone. Releasing earlier would let a concurrent load be
            // admitted against space this model has not yet freed.
            if engine == crate::model_host::Engine::Praecise {
                crate::memory_budget::global().release(model_id);
            }
            self.host.release(model_id, engine);
            info!("Unloaded model: {} ({} engine released)", model_id, engine);
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(format!(
                "{model_id} is not loaded, so nothing was unloaded"
            )))
        }
    }

    /// Check if a model is currently loaded into a local llama.cpp context.
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
        let ticket = self.load_ticket(target_model_id)?;
        match self.loaded_models.get(target_model_id) {
            None => {
                return Err(ModelError::Other(format!(
                    "Cannot load drafter for `{}`: target model is not loaded",
                    target_model_id
                )));
            }
            Some(entry) => {
                if matches!(
                    entry.as_ref(),
                    LoadedEntry::Hosted(..) | LoadedEntry::Pipeline(_)
                ) {
                    return Err(ModelError::Other(format!(
                        "Cannot load drafter for `{target_model_id}`: target is served by a \
                         hosted engine or a layer pipeline, which runs its own decode loop"
                    )));
                }
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
        // DFlash drafters ship as `dflash-*.gguf`; MTP heads as `mtp-*.gguf`.
        // The filename is the reliable signal for which speculative algorithm to
        // request from llama.cpp's common_speculative.
        let spec_type: i32 = if gguf_path_owned
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("dflash"))
        {
            1
        } else {
            0
        };

        let loaded = tokio::task::spawn_blocking(move || {
            let n_gpu_layers = Self::gpu_layer_budget(&gguf_path_owned, file_len);
            // `with_load_mtp(true)` is REQUIRED here, exactly as it is on the
            // inline path — a separate drafter GGUF is no less an MTP head for
            // living in its own file. Without it llama.cpp loads the sidecar as
            // an ordinary model: it reads the block count, walks blocks from
            // zero, and dies on the first one.
            //
            // Measured 2026-09-01 with Qwen's own Flash-Next MTP head
            // (mtp-Qwen3.8-Flash-Next-Q8_0.gguf). That file holds exactly ONE
            // block, `blk.48` — the head that follows the target's 0..47 — plus
            // token_embd/output and the output_hc_* tensors. The load failed with
            //
            //   check_tensor_dims: tensor 'blk.0.hc_attn_norm.weight' not found
            //
            // which reads like a corrupt or mis-exported drafter and is not: the
            // tensor names are right, block 0 simply is not in an MTP sidecar and
            // never will be. The flag is what tells llama.cpp to expect that
            // shape. Unconditional rather than derived from the catalog, because
            // reaching this function at all means a drafter is being loaded.
            let model_params = LlamaModelParams::default()
                .with_n_gpu_layers(n_gpu_layers)
                .with_load_mtp(true);
            let model = crate::parse_jail::load_llama(&backend, &gguf_path_owned, &model_params)
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
                spec_type,
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

        // Same rule as the target: a drafter whose target was stopped while it
        // loaded is dropped here rather than left resident.
        let mut loaded = Some(loaded);
        let installed = self.install_if_current(target_model_id, ticket, || {
            if let Some(loaded) = loaded.take() {
                self.loaded_drafters.insert(
                    target_model_id.to_string(),
                    Arc::new(tokio::sync::Mutex::new(loaded)),
                );
            }
        });
        if !installed {
            drop(loaded);
            warn!("{target_model_id}: stopped while its drafter loaded; the drafter was discarded");
            return Err(Self::stopped_error(target_model_id));
        }
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

    /// Whether `model_id` can be decoded speculatively on this node — either
    /// from a separately-loaded drafter or from an MTP head inside its own
    /// GGUF.
    ///
    /// Both arms matter. `loaded_drafters` alone is unsound in *both*
    /// directions: an inline-MTP model speculates without ever appearing there
    /// (so testing the map alone reports a false negative and the node is
    /// filtered out of speculative routing forever), while a drafter loaded
    /// for one model says nothing about a different one.
    pub fn can_speculate(&self, model_id: &str) -> bool {
        self.loaded_drafters.contains_key(model_id) || inline_mtp_spec_type(model_id).is_some()
    }

    /// Whether *any* of `model_ids` can be decoded speculatively here.
    ///
    /// The provider announcement carries a single node-wide `mtp_enabled`, so
    /// this is the value it must report — but it has to be computed over the
    /// models actually being announced, not over every drafter in memory.
    /// `mtp_enabled` is a **hard filter** on the consumer side
    /// ([`crate::routing::InferenceRouter::select_provider`] retains only
    /// MTP-capable providers when a caller asks for speculation), and the
    /// serving side answers a request for a non-speculative model with a hard
    /// `MtpUnavailable` error — so advertising node-wide capability that a
    /// given model cannot honour converts a routing preference into a failed
    /// request.
    ///
    /// Read live on each announcement tick (like the warm-prefix summary)
    /// rather than captured at startup: drafters load asynchronously after
    /// their GGUF downloads, so a boot snapshot advertises `false` forever and
    /// the speculative path stays unreachable network-wide.
    pub fn any_can_speculate(&self, model_ids: &[String]) -> bool {
        model_ids.iter().any(|m| self.can_speculate(m))
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
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();
        let _guard = self.track_inflight(model_id);
        match entry.as_ref() {
            LoadedEntry::Batched(_) | LoadedEntry::Hosted(..) | LoadedEntry::Pipeline(_) => {
                Err(ModelError::InferenceError(
                    "commitment verification requires the model loaded in serial mode".to_string(),
                ))
            }
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

        let arch = Self::model_arch(&loaded.model);
        let ctx_params = Self::tuned_context_params_for(n_ctx.get(), arch.as_deref());
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

    /// Run a prompt on a hosted engine and await its result, optionally
    /// streaming text pieces through `token_tx`. The engine is driven on a
    /// blocking thread; a dropped `token_tx` receiver abandons the request in
    /// the runtime host without disturbing its other requests.
    async fn run_hosted(
        model: &Arc<praecise_host::HostedModel>,
        prompt: BatchPrompt,
        config: &GenerationConfig,
        token_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        let model = Arc::clone(model);
        let config = config.clone();
        tokio::task::spawn_blocking(move || {
            let prompt = match &prompt {
                BatchPrompt::Raw(text) => praecise_host::generation::Prompt::Text(text),
                BatchPrompt::Chat(messages) => praecise_host::generation::Prompt::Chat(messages),
            };
            praecise_host::generation::generate(&model, prompt, &config, |piece| {
                token_tx
                    .as_ref()
                    .is_none_or(|tx| tx.blocking_send(piece.to_string()).is_ok())
            })
        })
        .await
        .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {e}")))?
        .map_err(crate::model_host::engine_error)
    }

    /// Serve `model_id` as the first stage of a layer pipeline: load blocks
    /// `plan.stages[0].layers` of `gguf_path` here and connect to the machines
    /// that hold the rest. The model is then served through the same entry
    /// points as a single-machine model (text only). Memory is admitted for this
    /// machine's share of the weights.
    ///
    /// # Errors
    ///
    /// The model is already held by another engine, does not fit, does not
    /// match the plan, or any stage cannot be reached or authenticated.
    pub async fn load_model_pipelined(
        &self,
        model_id: &str,
        gguf_path: &Path,
        plan: praecise_runtime::pipeline::PipelinePlan,
        auth: Arc<dyn praecise_runtime::pipeline::StageAuthenticator>,
        opts: praecise_runtime::pipeline::driver::DriverOptions,
    ) -> Result<()> {
        let ticket = self.load_ticket(model_id)?;
        let load_lock = self.load_lock(model_id);
        let _load_guard = load_lock.lock().await;
        if self.is_loaded(model_id) {
            return Err(ModelError::Other(format!(
                "{model_id} is already loaded on this machine; unload it before serving it across a pipeline"
            )));
        }
        let claim = self
            .host
            .claim(model_id, crate::model_host::Engine::Praecise)?;
        let file_len = std::fs::metadata(gguf_path)?.len();
        let share = plan.stages.first().map_or(0, |s| u64::from(s.layers.len()));
        let stage_bytes = file_len.saturating_mul(share) / u64::from(plan.n_layer.max(1));
        Self::check_memory_admission(model_id, stage_bytes)?;
        let admission = crate::memory_budget::AdmissionGuard::new(model_id);

        let backend = self.backend.clone();
        let gguf = gguf_path.to_path_buf();
        let enable_thinking = crate::catalog::resolve_enable_thinking(model_id, None);
        let gpu = crate::hardware_policy::usable_accelerators() > 0;
        let driver = tokio::task::spawn_blocking(move || {
            crate::layer_pipeline::PipelineDriver::start(
                backend,
                gguf,
                plan,
                auth,
                opts,
                enable_thinking,
                gpu,
            )
        })
        .await
        .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {e}")))??;
        info!(
            model_id,
            stages = driver.n_stages(),
            "serving model across a layer pipeline"
        );
        if let Err(entry) = self.install(model_id, ticket, LoadedEntry::Pipeline(Arc::new(driver)))
        {
            return Err(self.discard(model_id, entry));
        }
        admission.commit();
        claim.commit();
        Ok(())
    }

    /// Serve stage `index` (not the first) of a layer pipeline for `model_id`:
    /// load that stage's blocks of `gguf_path` and listen on `listen` for the
    /// stage before it, for the life of the process. The stage is not a served
    /// model on this machine; memory is admitted for its share of the weights.
    ///
    /// # Errors
    ///
    /// The model is held by another engine, does not fit, does not match the
    /// plan, or the socket cannot be bound.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_pipeline_stage(
        &self,
        model_id: &str,
        gguf_path: &Path,
        plan: praecise_runtime::pipeline::PipelinePlan,
        index: usize,
        listen: String,
        auth: Arc<dyn praecise_runtime::pipeline::StageAuthenticator>,
        opts: praecise_runtime::pipeline::stage::StageOptions,
    ) -> Result<Arc<parking_lot::RwLock<crate::layer_pipeline::StageState>>> {
        let load_lock = self.load_lock(model_id);
        let _load_guard = load_lock.lock().await;
        if self.is_loaded(model_id) {
            return Err(ModelError::Other(format!(
                "{model_id} is already loaded on this machine; unload it before serving a pipeline stage of it"
            )));
        }
        let claim = self
            .host
            .claim(model_id, crate::model_host::Engine::Praecise)?;
        let file_len = std::fs::metadata(gguf_path)?.len();
        let share = plan
            .stages
            .get(index)
            .map_or(0, |s| u64::from(s.layers.len()));
        let stage_bytes = file_len.saturating_mul(share) / u64::from(plan.n_layer.max(1));
        Self::check_memory_admission(model_id, stage_bytes)?;
        let admission = crate::memory_budget::AdmissionGuard::new(model_id);

        let backend = self.backend.clone();
        let gguf = gguf_path.to_path_buf();
        let gpu = crate::hardware_policy::usable_accelerators() > 0;
        let state = tokio::task::spawn_blocking(move || {
            crate::layer_pipeline::spawn_stage(backend, gguf, plan, index, listen, auth, opts, gpu)
        })
        .await
        .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {e}")))??;
        admission.commit();
        claim.commit();
        Ok(state)
    }

    /// Digest naming the weights at `path`, as `model_id` is served from them;
    /// every stage of a layer pipeline must hold weights with the same digest.
    ///
    /// # Errors
    ///
    /// The file cannot be read.
    pub async fn weights_digest(&self, model_id: &str, path: &Path) -> Result<[u8; 32]> {
        Ok(self.weights_fingerprint(model_id, path).await?.0)
    }

    /// The layer-pipeline driver serving `model_id`, when it is served that way.
    pub fn pipeline_driver(
        &self,
        model_id: &str,
    ) -> Option<Arc<crate::layer_pipeline::PipelineDriver>> {
        match self.loaded_models.get(model_id)?.value().as_ref() {
            LoadedEntry::Pipeline(driver) => Some(Arc::clone(driver)),
            _ => None,
        }
    }

    /// The hosted engine the operator assigned `model_id` to, when it is not
    /// served by llama.cpp.
    pub fn hosted_backend(&self, model_id: &str) -> Option<praecise_runtime::backend::Backend> {
        self.host.backend_for(model_id)
    }

    /// Load `model_id` into the hosted engine the operator assigned it to,
    /// from the checkpoint directory `model_dir`, admitting `bytes` of memory.
    /// The model is then served through the same entry points as a llama.cpp
    /// model. Refused when any engine already holds the model.
    pub async fn load_hosted(&self, model_id: &str, model_dir: &Path, bytes: u64) -> Result<()> {
        let backend = self.host.backend_for(model_id).ok_or_else(|| {
            ModelError::InvalidModel(format!("{model_id} is not assigned to a hosted engine"))
        })?;
        let ticket = self.load_ticket(model_id)?;
        let load_lock = self.load_lock(model_id);
        let _load_guard = load_lock.lock().await;
        if self.is_loaded(model_id) {
            return Ok(());
        }
        let host = Arc::clone(&self.host);
        let (id, dir) = (model_id.to_string(), model_dir.to_path_buf());
        let hosted = tokio::task::spawn_blocking(move || host.serve_hosted(&id, &dir, bytes))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {e}")))??;
        // The template a chat turn is rendered through. A checkpoint without
        // one still serves raw prompts; its chat turns are refused.
        let template = match ChatTemplateSource::from_hf_dir(model_dir) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(
                    "{model_id}: no chat template in {}: {e}",
                    model_dir.display()
                );
                None
            }
        };
        if let Err(entry) = self.install(
            model_id,
            ticket,
            LoadedEntry::Hosted(backend, hosted, template),
        ) {
            return Err(self.discard(model_id, entry));
        }
        info!("Loaded model {model_id} on the hosted {backend} engine");
        Ok(())
    }

    /// Submit a prompt to a model's continuous-batching engine and await its
    /// terminal result, optionally streaming token pieces through `token_tx`.
    ///
    /// The `_guard` in-flight reservation is held for the whole await so a
    /// cancelled caller (client disconnect) releases its slot — and, when
    /// streaming, dropping `token_tx`'s receiver signals the scheduler to free
    /// the sequence early. `reasoning_tx` streams the model's reasoning apart
    /// from the answer's tokens.
    async fn run_batched(
        engine: &BatchEngine,
        prompt: BatchPrompt,
        config: &GenerationConfig,
        token_tx: Option<tokio::sync::mpsc::Sender<String>>,
        reasoning_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let mut config = Self::batched_config(engine, config);
        config.reasoning_tx = reasoning_tx;
        engine.submit(BatchRequest {
            prompt,
            config,
            token_tx,
            result_tx,
            media: Vec::new(),
        })?;
        result_rx
            .await
            .map_err(|_| ModelError::Other("batch engine dropped the request".into()))?
            .map_err(ModelError::from)
    }

    /// `config` as a batch engine request carries it.
    fn batched_config(engine: &BatchEngine, config: &GenerationConfig) -> GenerationConfig {
        // The batched engine builds its own `StopStream` from whatever
        // `config.stop` it is handed and never reaches `decode_loop`, where
        // the serial path picks up the chat-template terminators. Handing it
        // the caller's bare list lets a template terminator through as text:
        // measured on muse-glimmer as `'391\n<|im_end|>'` with
        // `finish_reason: stop` — the stop was detected and the token was
        // still in the content, because the engine was never told the token
        // was a stop.
        //
        // Idempotent: `stops_with_terminators` deduplicates, so a list that
        // already carries them is unchanged.
        let mut config = config.clone();
        config.stop = stops_with_terminators(&config.stop);
        // The engine renders the template itself, and a template names its
        // reasoning variable by family: muse-glimmer reads `reasoning_strength`,
        // Qwen `reasoning_effort`. Resolved here from the catalog, as the serial
        // path does; without it the engine always wrote `reasoning_effort`, and
        // muse-glimmer reasoned at its `high` default whatever the caller asked.
        if let Some((name, value)) = crate::catalog::resolve_reasoning_effort(
            engine.model_id(),
            config.reasoning_effort.as_deref(),
        ) {
            config.reasoning_effort = Some(value);
            config.reasoning_kwarg = Some(name);
        }
        config
    }

    /// Generate text from a raw prompt string. The prompt is used as given
    /// and the generated text comes back as it was written: no chat format
    /// applies to a raw completion.
    pub async fn generate(
        &self,
        model_id: &str,
        prompt: &str,
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        crate::access::check(model_id)?;
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.track_inflight(model_id);

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(
                    engine,
                    BatchPrompt::Raw(prompt.to_string()),
                    config,
                    None,
                    None,
                )
                .await
            }
            LoadedEntry::Hosted(_, model, _) => {
                Self::run_hosted(model, BatchPrompt::Raw(prompt.to_string()), config, None).await
            }
            LoadedEntry::Pipeline(driver) => {
                driver
                    .generate(BatchPrompt::Raw(prompt.to_string()), config, None, None)
                    .await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                // Speculative decoding on the raw-completion path too: default
                // draft_n from the catalog when a drafter is loaded.
                let mut config = config.clone();
                if config.draft_n.is_none()
                    && (self.loaded_drafters.contains_key(model_id)
                        || inline_mtp_spec_type(model_id).is_some())
                {
                    config.draft_n = crate::catalog::get_model_by_id(model_id)
                        .and_then(|e| e.mtp_default_draft_n);
                }
                let drafter_mutex = if config.draft_n.is_some() {
                    self.loaded_drafters
                        .get(model_id)
                        .map(|d| d.value().clone())
                } else {
                    None
                };
                let prompt = prompt.to_string();
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let cancel_blocking = cancel.clone();
                let _cancel_guard = CancelOnDrop(cancel);
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let drafter_guard = drafter_mutex.as_ref().map(|d| d.blocking_lock());
                    Self::generate_sync_streaming(
                        &loaded,
                        drafter_guard.as_deref(),
                        &prompt,
                        &config,
                        None,
                        None,
                        None,
                        Some(&cancel_blocking),
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Render a chat turn through the model's own template on whichever
    /// backend serves it, and run it. The result's text, reasoning and tool
    /// calls come back split by the turn's format; the answer streams to
    /// `token_tx` and the reasoning to `reasoning_tx` as they are decoded.
    #[allow(clippy::too_many_arguments)]
    async fn run_turn(
        &self,
        model_id: &str,
        entry: &LoadedEntry,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        config: &GenerationConfig,
        token_tx: Option<tokio::sync::mpsc::Sender<String>>,
        reasoning_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        use crate::tool_grammar::render_turn;
        match entry {
            LoadedEntry::Batched(engine) => {
                let turn = render_turn(engine.chat_template(), model_id, messages, tools, config)?;
                Self::run_batched(
                    engine,
                    BatchPrompt::Raw(turn.prompt),
                    &turn.config,
                    token_tx,
                    reasoning_tx,
                )
                .await
            }
            LoadedEntry::Hosted(_, model, template) => {
                let turn = render_turn(template.as_ref(), model_id, messages, tools, config)?;
                let mut config = turn.config;
                config.reasoning_tx = reasoning_tx;
                Self::run_hosted(model, BatchPrompt::Raw(turn.prompt), &config, token_tx).await
            }
            LoadedEntry::Pipeline(driver) => {
                let turn = render_turn(driver.chat_template(), model_id, messages, tools, config)?;
                driver
                    .generate(
                        BatchPrompt::Raw(turn.prompt),
                        &turn.config,
                        token_tx,
                        reasoning_tx,
                    )
                    .await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                // Speculative decoding engages without the request having to
                // set draft_n when a drafter is loaded for this target. A
                // grammar-constrained turn does not speculate; the decode loop
                // suppresses the drafter for it.
                let mut config = config.clone();
                if config.draft_n.is_none()
                    && (self.loaded_drafters.contains_key(model_id)
                        || inline_mtp_spec_type(model_id).is_some())
                {
                    config.draft_n = crate::catalog::get_model_by_id(model_id)
                        .and_then(|e| e.mtp_default_draft_n);
                }
                let drafter_mutex = if config.draft_n.is_some() {
                    self.loaded_drafters
                        .get(model_id)
                        .map(|d| d.value().clone())
                } else {
                    None
                };
                let messages = messages.to_vec();
                let tools = tools.to_vec();
                let model_id = model_id.to_string();
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let cancel_blocking = cancel.clone();
                let _cancel_guard = CancelOnDrop(cancel);
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let drafter_guard = drafter_mutex.as_ref().map(|d| d.blocking_lock());
                    let template = ChatTemplateSource::from_model(&loaded.model).ok();
                    let turn =
                        render_turn(template.as_ref(), &model_id, &messages, &tools, &config)?;
                    let grammar = if tools.is_empty() {
                        None
                    } else {
                        crate::tool_grammar::tool_grammar(&loaded.model, &turn.format)
                    };
                    Self::generate_sync_streaming(
                        &loaded,
                        drafter_guard.as_deref(),
                        &turn.prompt,
                        &turn.config,
                        token_tx.as_ref(),
                        reasoning_tx.as_ref(),
                        grammar.as_ref(),
                        Some(&cancel_blocking),
                    )
                });
                handle
                    .await
                    .map_err(|e| ModelError::Other(format!("Generation task error: {}", e)))?
            }
        }
    }

    /// Generate text from structured chat messages, rendered through the
    /// model's own chat template. The answer and the reasoning come back
    /// separately, without template markup.
    pub async fn generate_chat(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        crate::access::check(model_id)?;
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

        let _guard = self.track_inflight(model_id);
        self.run_turn(model_id, &entry, messages, &[], config, None, None)
            .await
    }

    /// Generate a chat completion that may call `tools`.
    ///
    /// The tools are rendered through the model's own chat template, in the
    /// format that model was tuned on, and the reply is read back by the same
    /// format: the calls come back as structured [`ToolCall`] values and the
    /// text without call markup. On the serial engine, sampling is also
    /// constrained to a grammar compiled from the tool schemas.
    ///
    /// `stop_reason` follows the rich-shape spec:
    /// - `"tool_use"` — at least one tool call was made.
    /// - `"max_tokens"` — output_tokens reached `config.max_tokens`.
    /// - `"end_turn"` — clean EOG with no tool calls.
    pub async fn generate_chat_with_tools(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<ChatWithToolsResult> {
        crate::access::check(model_id)?;
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.track_inflight(model_id);
        let inner = self
            .run_turn(model_id, &entry, messages, tools, config, None, None)
            .await?;
        Ok(with_tools_result(inner))
    }

    /// Stream text generation token-by-token from structured chat messages.
    ///
    /// The answer streams through `token_tx` and the reasoning through
    /// `reasoning_tx` as they are decoded, each without template markup. A
    /// path that only learns the reasoning at the end (speculative decoding)
    /// leaves it on the returned result's `thinking` instead. The final
    /// `InferenceResult` (with aggregated stats) is returned when generation
    /// completes.
    pub async fn generate_chat_stream(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
        token_tx: tokio::sync::mpsc::Sender<String>,
        reasoning_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        crate::access::check(model_id)?;
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        // Record the served prompt as warm for prefix-affinity advertisement,
        // same as the non-streaming chat path.
        self.record_warm_prompt(model_id, &warm_prompt_bytes(messages));

        let _guard = self.track_inflight(model_id);
        self.run_turn(
            model_id,
            &entry,
            messages,
            &[],
            config,
            Some(token_tx),
            reasoning_tx,
        )
        .await
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
    /// `tools` behaves as in [`Self::generate_chat_with_tools`], without the
    /// grammar: the media prefill carries none. An empty `media` slice is an
    /// ordinary chat request and is forwarded as one.
    pub async fn generate_chat_multimodal(
        &self,
        model_id: &str,
        messages: &[ChatMessage],
        media: &[Vec<u8>],
        tools: &[ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<ChatWithToolsResult> {
        crate::access::check(model_id)?;
        if media.is_empty() {
            return self
                .generate_chat_with_tools(model_id, messages, tools, config)
                .await;
        }

        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.track_inflight(model_id);

        // No warm-prompt record: the prefix a multimodal request leaves in the KV
        // cache holds media embeddings, so text-prefix affinity would mis-route.

        match entry.as_ref() {
            LoadedEntry::Hosted(backend, ..) => Err(ModelError::InferenceError(format!(
                "model {model_id} is served by the hosted {backend} engine, which takes text only"
            ))),
            LoadedEntry::Pipeline(_) => Err(ModelError::InferenceError(format!(
                "model {model_id} is served across a layer pipeline, which takes text only"
            ))),
            LoadedEntry::Batched(engine) => {
                if !self.media_capable.contains(model_id) {
                    return Err(ModelError::InferenceError(format!(
                        "model {} is served text-only — it declares no projector, or its \
                         projector failed to load. Check ModelRuntime::supports_media before \
                         sending attachments.",
                        model_id,
                    )));
                }
                let mut messages = messages.to_vec();
                // Without mtmd no model is ever media-capable, so the check above
                // has already refused.
                #[cfg(feature = "mtmd")]
                Self::place_media_markers(&mut messages, media.len())?;
                let turn = crate::tool_grammar::render_turn(
                    engine.chat_template(),
                    model_id,
                    &messages,
                    tools,
                    config,
                )?;
                let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                engine.submit(BatchRequest {
                    prompt: BatchPrompt::Raw(turn.prompt),
                    config: Self::batched_config(engine, &turn.config),
                    token_tx: None,
                    result_tx,
                    media: media.to_vec(),
                })?;
                let inner = result_rx
                    .await
                    .map_err(|_| ModelError::Other("batch engine dropped the request".into()))?
                    .map_err(ModelError::from)?;
                Ok(with_tools_result(inner))
            }
            LoadedEntry::Serial(model_mutex) => {
                #[cfg(feature = "mtmd")]
                {
                    let model_mutex = model_mutex.clone();
                    let mut messages = messages.to_vec();
                    let media = media.to_vec();
                    let config = config.clone();
                    let tools = tools.to_vec();
                    Self::place_media_markers(&mut messages, media.len())?;
                    let model_id = model_id.to_string();
                    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let cancel_blocking = cancel.clone();
                    let _cancel_guard = CancelOnDrop(cancel);
                    let handle = tokio::task::spawn_blocking(move || -> Result<InferenceResult> {
                        let loaded = model_mutex.blocking_lock();
                        let template = ChatTemplateSource::from_model(&loaded.model).ok();
                        let turn = crate::tool_grammar::render_turn(
                            template.as_ref(),
                            &model_id,
                            &messages,
                            &tools,
                            &config,
                        )?;
                        Self::generate_sync_multimodal(
                            &loaded,
                            &turn.prompt,
                            &media,
                            &turn.config,
                            Some(&cancel_blocking),
                        )
                    });
                    let inner = handle.await.map_err(|e| {
                        ModelError::Other(format!("Generation task error: {}", e))
                    })??;
                    Ok(with_tools_result(inner))
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
        crate::access::check(model_id)?;
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {} not loaded", model_id)))?
            .value()
            .clone();

        let _guard = self.track_inflight(model_id);

        match entry.as_ref() {
            LoadedEntry::Batched(engine) => {
                Self::run_batched(
                    engine,
                    BatchPrompt::Raw(prompt.to_string()),
                    config,
                    Some(token_tx),
                    None,
                )
                .await
            }
            LoadedEntry::Hosted(_, model, _) => {
                Self::run_hosted(
                    model,
                    BatchPrompt::Raw(prompt.to_string()),
                    config,
                    Some(token_tx),
                )
                .await
            }
            LoadedEntry::Pipeline(driver) => {
                driver
                    .generate(
                        BatchPrompt::Raw(prompt.to_string()),
                        config,
                        Some(token_tx),
                        None,
                    )
                    .await
            }
            LoadedEntry::Serial(model_mutex) => {
                let model_mutex = model_mutex.clone();
                // Default draft count from the catalog when omitted but a drafter
                // is loaded, so speculative decoding actually engages (see
                // generate_chat_stream for the rationale).
                let mut config = config.clone();
                if config.draft_n.is_none()
                    && (self.loaded_drafters.contains_key(model_id)
                        || inline_mtp_spec_type(model_id).is_some())
                {
                    config.draft_n = crate::catalog::get_model_by_id(model_id)
                        .and_then(|e| e.mtp_default_draft_n);
                }
                let drafter_mutex = if config.draft_n.is_some() {
                    self.loaded_drafters
                        .get(model_id)
                        .map(|d| d.value().clone())
                } else {
                    None
                };
                let prompt = prompt.to_string();
                let handle = tokio::task::spawn_blocking(move || {
                    let loaded = model_mutex.blocking_lock();
                    let drafter_guard = drafter_mutex.as_ref().map(|d| d.blocking_lock());
                    Self::generate_sync_streaming(
                        &loaded,
                        drafter_guard.as_deref(),
                        &prompt,
                        &config,
                        Some(&token_tx),
                        None,
                        // Plain chat streaming carries no tools.
                        None,
                        // Streaming path: the closing `token_tx` above already
                        // signals client-gone, so no separate cancel flag.
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

    /// Core synchronous generation loop, optionally streaming each
    /// token and optionally running speculative decoding when an MTP
    /// drafter is provided. `reasoning_tx` streams the reasoning apart from
    /// the answer on the plain decode path; the speculative path leaves it on
    /// the result's `thinking`.
    fn generate_sync_streaming(
        loaded: &LoadedModel,
        drafter: Option<&LoadedDrafter>,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        reasoning_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        tool_grammar: Option<&crate::tool_grammar::ToolGrammar>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<InferenceResult> {
        // Both decode branches below build their own `StopStream`, and
        // only one of them added the chat-template terminators:
        // `decode_loop` did, while praecise-runtime's speculative path
        // does `StopStream::new(config.stop.clone())` on the raw list. So
        // whether a terminator was stripped depended on whether the model
        // happened to have an MTP drafter loaded — measured on
        // muse-glimmer as `'391\n<|im_end|>'` reaching the caller.
        //
        // Augmenting here, where the branches diverge, covers both.
        // `stops_with_terminators` deduplicates, so `decode_loop`
        // re-applying it below is a no-op rather than a double-append.
        let mut config = config.clone();
        config.stop = stops_with_terminators(&config.stop);
        let config = &config;
        // MTP / speculative-decoding seam. When the caller passes
        // `draft_n: Some(n)`:
        //   - If a drafter is loaded for this target, run the
        //     speculative path via `MtpSpeculative`.
        //   - If no drafter is loaded, return `MtpUnavailable` with a
        //     reason that tells the caller to load the drafter first
        //     (or unset draft_n for single-token sampling).
        //
        // The binding is Praecise Engine's `llama-cpp-2` MTP
        // speculative-decoding support.
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
            if let Some(drafter) = drafter {
                // Separate-drafter speculative decoding: a paired sidecar GGUF.
                return Self::generate_speculative(
                    loaded,
                    &drafter.model,
                    &drafter.backend,
                    drafter.context_length,
                    drafter.spec_type,
                    prompt,
                    config,
                    token_tx,
                    n,
                    cancel,
                );
            } else if let Some(spec_type) = loaded.inline_mtp_spec_type {
                // Inline (self-speculative) MTP: the draft head is trained into
                // the target's own GGUF, so the draft context is built from the
                // target model/backend — no separate drafter, no second load.
                //
                // Unlike the proven separate-drafter path, inline self-spec is
                // model/fork-specific, so a setup failure must NOT fail the
                // request: `MtpSpeculative` init happens before any token is
                // emitted, so on error we fall through to standard single-token
                // decoding (correctness preserved, just no speedup).
                match Self::generate_speculative(
                    loaded,
                    &loaded.model,
                    &loaded.backend,
                    loaded.context_length,
                    spec_type,
                    prompt,
                    config,
                    token_tx,
                    n,
                    cancel,
                ) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        warn!(
                            "inline MTP self-speculation unavailable on this build \
                             ({e}); serving with standard decoding",
                        );
                        // fall through to standard decode below
                    }
                }
            } else {
                return Err(ModelError::MtpUnavailable {
                    reason: format!(
                        "draft_n={} requested but this target has neither a loaded MTP drafter \
                         nor an inline MTP head. Pair a drafter (catalog `drafter_id` + \
                         `load_drafter`), serve a model with an inline head (`mtp_kind` set, \
                         `drafter_id: None`), or unset draft_n for single-token sampling.",
                        n,
                    ),
                });
            }
            // Reachable only when inline self-spec fell through above: continue
            // to standard single-token decoding below.
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
        let arch = Self::model_arch(&loaded.model);
        let ctx_params = Self::tuned_context_params_for(n_ctx.get(), arch.as_deref());
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
            reasoning_tx,
            Some(first_logits),
            start,
            tool_grammar,
            cancel,
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
        reasoning_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        first_logits: Option<i32>,
        start: Instant,
        tool_grammar: Option<&crate::tool_grammar::ToolGrammar>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
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
            // SAFETY: `sampler` is a local of this function and `loaded`
            // outlives the call, so the grammar is dropped before its model.
            tool_grammar.and_then(|g| unsafe { g.sampler(&loaded.model) }),
            loaded.model.n_vocab(),
        );

        let mut n_cur = n_past;
        let mut output_tokens: u32 = 0;
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut stream = StopStream::new(stops_with_terminators(&config.stop))
            .reading(config.reply_format.as_ref())
            .with_reasoning(reasoning_tx.cloned());
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
            .map(|k| crate::toploc::commitment_k_for(k) as usize);
        let mut commitment_steps: Vec<crate::toploc::StepRecord> = Vec::new();

        let max_pos = n_ctx_val.min(n_past + config.max_tokens as i32);

        while n_cur < max_pos {
            // Client-gone check. Two independent signals, either of which stops
            // the loop before the next decode so we never generate into a dead
            // request and pin the GPU:
            //   - streaming: the caller dropped its `token_tx` receiver;
            //   - non-streaming (and streaming too): `cancel` is flipped by the
            //     `CancelOnDrop` guard on the awaiting task, which fires when the
            //     client disconnects and the serial `spawn_blocking` future is
            //     dropped (dropping a `JoinHandle` does NOT stop the blocking
            //     task, so the flag is how the decode learns the caller is gone).
            // Breaking returns early; the per-request context is dropped by the
            // caller, freeing its KV/VRAM. Mirrors the batched scheduler's
            // `result_tx.is_closed()` sweep in `batching.rs`.
            if token_tx.is_some_and(|tx| tx.is_closed())
                || cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            {
                break;
            }

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
        let reply = stream.finish_parts(token_tx).map_err(ModelError::from)?;

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
            text: reply.text,
            thinking: reply.thinking,
            input_tokens,
            output_tokens,
            generation_time_ms,
            tokens_per_second,
            stop_reason,
            commitment,
            cached_tokens: 0,
            forward_positions: None,
            denoise_steps: None,
            tool_calls: reply.tool_calls,
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
        cancel: Option<&std::sync::atomic::AtomicBool>,
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
            let bitmap = MtmdBitmap::from_buffer(projector, bytes, false).map_err(|e| {
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
        let arch = Self::model_arch(&loaded.model);
        let ctx_params = Self::tuned_context_params_for(n_ctx.get(), arch.as_deref());
        let mut ctx = loaded
            .model
            .new_context(&loaded.backend, ctx_params)
            .map_err(|e| ModelError::Other(format!("Failed to create context: {}", e)))?;

        // Prefill. Text chunks go through llama_decode; image and audio chunks
        // are encoded by the projector and their embeddings decoded in place, in
        // the order the markers appeared.
        let n_batch = ctx.n_batch() as i32;
        let n_past = chunks
            .eval_chunks(projector, &mut ctx, 0, 0, n_batch, true)
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
            None,
            start,
            // The multimodal prefill path does not carry a tool grammar.
            None,
            cancel,
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
    // The draft model/backend are passed explicitly (not a `&LoadedDrafter`) so
    // this one path serves both modes: a *separate* drafter GGUF, and *inline*
    // self-speculation where the draft head is trained into the target's own
    // GGUF — there the caller passes the target's `model`/`backend`, so the
    // draft context is built from the target weights with no second load.
    #[allow(clippy::too_many_arguments)]
    fn generate_speculative(
        loaded: &LoadedModel,
        draft_model: &LlamaModel,
        draft_backend: &LlamaBackend,
        draft_context_length: u32,
        draft_spec_type: i32,
        prompt: &str,
        config: &GenerationConfig,
        token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
        draft_n: u8,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<InferenceResult> {
        // Delegates to the Praecise engine, which runs speculative decode
        // (separate-drafter DFlash + inline MTP self-spec, including the
        // ctx_type=MTP nextn-head path). This crate selects the handles by
        // policy; the engine runs the draft loop.
        praecise_runtime::generate_speculative(
            &loaded.model,
            &loaded.backend,
            loaded.context_length,
            draft_model,
            draft_backend,
            draft_context_length,
            draft_spec_type,
            prompt,
            config,
            token_tx,
            draft_n,
            cancel,
        )
        .map_err(|e| ModelError::MtpUnavailable {
            reason: e.to_string(),
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
/// A chat turn's result in the tool-use shape: the calls the reply made,
/// and why the turn ended. A tool call outranks the engine's own cause: the
/// turn ends because control passes to the caller's tool, whatever halted
/// decoding.
fn with_tools_result(inner: InferenceResult) -> ChatWithToolsResult {
    let tool_calls: Vec<ToolCall> = inner
        .tool_calls
        .into_iter()
        .map(|c| ToolCall {
            id: c.id,
            name: c.name,
            input: c.arguments,
        })
        .collect();
    let stop_reason = if !tool_calls.is_empty() {
        "tool_use"
    } else {
        match inner.stop_reason {
            StopReason::Length => "max_tokens",
            StopReason::StopSequence => "stop_sequence",
            StopReason::Eos => "end_turn",
        }
    };
    ChatWithToolsResult {
        text: inner.text,
        thinking: inner.thinking,
        tool_calls,
        input_tokens: inner.input_tokens,
        output_tokens: inner.output_tokens,
        generation_time_ms: inner.generation_time_ms,
        tokens_per_second: inner.tokens_per_second,
        stop_reason: stop_reason.to_string(),
        commitment: inner.commitment,
    }
}

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
            ..Default::default()
        };
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello");
    }

    /// Single-flight load coalescing: the primitive that prevents a duplicate
    /// GPU load of the same model (the TOCTOU race that wedged the GPU). Two
    /// guarantees: (1) all callers for one model id share the SAME load lock,
    /// so a second load waits on the first rather than running concurrently;
    /// (2) distinct model ids get distinct locks, so loading model A never
    /// blocks loading model B.
    /// Unloading a model that is not loaded is an error, never a silent
    /// success a caller would read as "stopped".
    /// A GPU of any vendor with no compiled backend for it refuses the
    /// runtime instead of running every layer on the CPU.
    #[test]
    fn a_gpu_without_a_compiled_backend_is_refused() {
        use tenzro_types::GpuVendor;
        let cpu: Vec<String> = vec!["cpu".into()];
        for vendor in [
            GpuVendor::Nvidia,
            GpuVendor::Amd,
            GpuVendor::Apple,
            GpuVendor::Other,
        ] {
            let err = plan_llm_backend(&[vendor], &cpu).unwrap_err();
            assert!(err.contains("would run on the CPU"), "{vendor:?}: {err}");
        }
        assert!(plan_llm_backend(&[], &cpu).is_ok());

        let with = |b: &str| vec!["cpu".to_string(), b.to_string()];
        assert!(plan_llm_backend(&[GpuVendor::Nvidia], &with("cuda")).is_ok());
        assert!(plan_llm_backend(&[GpuVendor::Nvidia], &with("vulkan")).is_ok());
        assert!(plan_llm_backend(&[GpuVendor::Amd], &with("rocm")).is_ok());
        assert!(plan_llm_backend(&[GpuVendor::Amd], &with("vulkan")).is_ok());
        assert!(plan_llm_backend(&[GpuVendor::Amd], &with("cuda")).is_err());
        assert!(plan_llm_backend(&[GpuVendor::Other], &with("vulkan")).is_ok());
        assert!(plan_llm_backend(&[GpuVendor::Apple], &with("metal")).is_ok());
        assert!(
            plan_llm_backend(&[GpuVendor::Nvidia, GpuVendor::Amd], &with("cuda")).is_err(),
            "every detected vendor needs a backend"
        );
    }

    /// A GPU hidden by an empty visibility variable lets a CPU runtime start
    /// and says so; the same GPU left visible lets the CPU build start with a
    /// notice that it serves CPU-tier models only.
    #[test]
    fn the_cpu_build_starts_beside_a_hidden_or_visible_gpu_with_a_notice() {
        use tenzro_types::GpuVendor;
        let cpu: Vec<String> = vec!["cpu".into()];
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };

        let hidden = DetectedGpus::split(
            &[GpuVendor::Nvidia],
            false,
            env(&[("CUDA_VISIBLE_DEVICES", "")]),
        );
        assert!(hidden.visible.is_empty());
        let notice = check_llm_gpus(&hidden, &cpu, false)
            .expect("a hidden GPU does not refuse")
            .expect("a hidden GPU is reported, never silent");
        assert!(
            notice.contains("CUDA_VISIBLE_DEVICES") && notice.contains("running CPU"),
            "{notice}"
        );
        assert_eq!(hidden.hidden_descriptions().len(), 1);

        let amd = DetectedGpus::split(
            &[GpuVendor::Amd],
            false,
            env(&[("ROCR_VISIBLE_DEVICES", " ")]),
        );
        assert!(
            check_llm_gpus(&amd, &cpu, false)
                .unwrap()
                .unwrap()
                .contains("ROCR_VISIBLE_DEVICES")
        );

        for visible in [
            DetectedGpus::split(&[GpuVendor::Nvidia], false, env(&[])),
            DetectedGpus::split(
                &[GpuVendor::Nvidia],
                false,
                env(&[("CUDA_VISIBLE_DEVICES", "0")]),
            ),
            DetectedGpus::split(
                &[GpuVendor::Amd],
                false,
                env(&[("CUDA_VISIBLE_DEVICES", "")]),
            ),
            DetectedGpus::split(
                &[GpuVendor::Other],
                false,
                env(&[("CUDA_VISIBLE_DEVICES", "")]),
            ),
        ] {
            assert!(visible.hidden.is_empty(), "{visible:?}");
            let notice = check_llm_gpus(&visible, &cpu, false)
                .expect("the CPU build starts beside a GPU")
                .expect("and says it will not use it");
            assert!(notice.contains("CPU-tier models only"), "{notice}");
            let cuda_on_amd = vec!["cpu".to_string(), "cuda".to_string()];
            if visible.visible.contains(&GpuVendor::Amd) {
                assert!(
                    check_llm_gpus(&visible, &cuda_on_amd, true).is_err(),
                    "{visible:?}"
                );
            }
        }

        let none = DetectedGpus::split(&[], false, env(&[]));
        assert_eq!(check_llm_gpus(&none, &cpu, false), Ok(None));
    }

    /// A Vulkan build reaches every vendor through the Vulkan loader: the
    /// CUDA and ROCm visibility variables do not hide a GPU from it, and an
    /// empty GGML_VK_VISIBLE_DEVICES hides every GPU.
    #[test]
    fn a_vulkan_build_is_hidden_only_by_the_vulkan_visibility_variable() {
        use tenzro_types::GpuVendor;
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        let all = [GpuVendor::Nvidia, GpuVendor::Amd, GpuVendor::Other];
        let cuda_hidden = DetectedGpus::split(
            &all,
            true,
            env(&[("CUDA_VISIBLE_DEVICES", ""), ("ROCR_VISIBLE_DEVICES", "")]),
        );
        assert_eq!(cuda_hidden.visible, all.to_vec());
        let vk_hidden = DetectedGpus::split(&all, true, env(&[("GGML_VK_VISIBLE_DEVICES", "")]));
        assert!(vk_hidden.visible.is_empty());
        assert!(
            vk_hidden
                .hidden
                .iter()
                .all(|(_, v)| *v == "GGML_VK_VISIBLE_DEVICES")
        );

        let vulkan = vec!["cpu".to_string(), "vulkan".to_string()];
        let visible = DetectedGpus::split(&all, true, env(&[]));
        assert_eq!(check_llm_gpus(&visible, &vulkan, true), Ok(None));
        assert!(
            check_llm_gpus(&visible, &vulkan, false).is_err(),
            "a Vulkan build whose loader finds no device refuses rather than run on the CPU"
        );
    }

    #[test]
    fn render_node_vendors_map_gpu_makers_only() {
        use tenzro_types::GpuVendor;
        assert_eq!(gpu_vendor_from_pci_id("0x10de"), Some(GpuVendor::Nvidia));
        assert_eq!(gpu_vendor_from_pci_id("0x1002"), Some(GpuVendor::Amd));
        assert_eq!(gpu_vendor_from_pci_id("0x8086"), Some(GpuVendor::Other));
        // Virtual GPUs and board management controllers are not accelerators.
        assert_eq!(gpu_vendor_from_pci_id("0x1af4"), None);
        assert_eq!(gpu_vendor_from_pci_id("0x1a03"), None);
    }

    #[tokio::test]
    async fn unloading_a_model_that_is_not_loaded_fails() {
        let rt = ModelRuntime::new().unwrap();
        let err = rt.unload_model("never-loaded").await.unwrap_err();
        assert!(matches!(err, ModelError::ModelNotFound(_)), "{err}");
    }

    /// The served list is exactly the models loaded into this runtime, and a
    /// chat for a model that is not loaded here fails instead of being routed
    /// anywhere else.
    #[tokio::test]
    async fn only_locally_loaded_models_are_listed_or_served() {
        let rt = ModelRuntime::new().unwrap();
        assert!(rt.list_loaded().is_empty());
        assert!(!rt.is_loaded("qwen3.8-27b"));
        let messages = [ChatMessage {
            role: "user".to_string(),
            content: "hi".to_string(),
            ..Default::default()
        }];
        let err = rt
            .generate_chat("qwen3.8-27b", &messages, &GenerationConfig::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not loaded"), "{err}");
    }

    #[test]
    fn load_lock_is_shared_per_id_and_distinct_across_ids() {
        let rt = ModelRuntime::new().unwrap();
        let a1 = rt.load_lock("model-a");
        let a2 = rt.load_lock("model-a");
        let b = rt.load_lock("model-b");
        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same model id must return the same load lock (callers coalesce)"
        );
        assert!(
            !Arc::ptr_eq(&a1, &b),
            "different model ids must have independent load locks"
        );
    }

    /// The load lock must serialize concurrent loads of one model: at most one
    /// task is ever inside the critical section (the "load"). That is exactly
    /// what stops two serve requests from both launching a full CUDA context of
    /// the same model.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_loads_of_one_model_serialize() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let rt = Arc::new(ModelRuntime::new().unwrap());
        let in_section = Arc::new(AtomicUsize::new(0));
        let max_in_section = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let rt = rt.clone();
            let in_section = in_section.clone();
            let max_in_section = max_in_section.clone();
            handles.push(tokio::spawn(async move {
                // Same code path the real load takes: fetch the per-id lock and
                // hold it across the (here simulated) load.
                let lock = rt.load_lock("contended-model");
                let _guard = lock.lock().await;
                let cur = in_section.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_section.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(15)).await;
                in_section.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            max_in_section.load(Ordering::SeqCst),
            1,
            "concurrent loads of the same model must serialize (never two at once)"
        );
    }

    #[test]
    fn a_terminator_arriving_last_is_trimmed_at_the_flush() {
        for term in ["<|im_end|>", "<|eot|>", "<|end_of_text|>", "<|endoftext|>"] {
            let mut s = StopStream::new(vec![term.to_string()]);
            for piece in ["391", "\n", term] {
                s.push(piece, None);
            }
            let reply = s.finish_parts(None).unwrap();
            assert_eq!(
                reply.text, "391\n",
                "{term} reached the caller instead of being trimmed"
            );
        }
    }

    /// Multi-byte characters must not be split when holding back a tail.
    #[test]
    fn holding_a_tail_never_splits_a_character() {
        let mut s = StopStream::new(vec!["<|im_end|>".to_string()]);
        for p in ["héllo ", "wörld — ", "ünïcode"] {
            s.push(p, None);
        }
        assert_eq!(s.finish_parts(None).unwrap().text, "héllo wörld — ünïcode");
    }

    /// The incident: a request found the model cold and began loading it, the
    /// operator stopped the model, and the load then installed its weights. The
    /// model sat resident with nothing serving it. A load that took its ticket
    /// before the stop must not install.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_while_a_request_is_loading_discards_the_load() {
        let rt = Arc::new(ModelRuntime::new().unwrap());
        let weights_read = Arc::new(tokio::sync::Notify::new());
        let stopped = Arc::new(tokio::sync::Notify::new());

        let load = {
            let (rt, weights_read, stopped) = (
                Arc::clone(&rt),
                Arc::clone(&weights_read),
                Arc::clone(&stopped),
            );
            tokio::spawn(async move {
                let ticket = rt.load_ticket("muse-a").expect("not stopped yet");
                weights_read.notify_one();
                stopped.notified().await;
                rt.install_if_current("muse-a", ticket, || {})
            })
        };

        weights_read.notified().await;
        assert!(
            !rt.stop_model("muse-a").await.unwrap(),
            "nothing was resident yet"
        );
        stopped.notify_one();

        assert!(
            !load.await.unwrap(),
            "a load that began before the stop installed its weights after it"
        );
        assert!(!rt.is_loaded("muse-a"));
    }

    /// Once stopped, no request path loads the model: the refusal comes before
    /// any file is read, so the error names the stop rather than the path.
    #[tokio::test]
    async fn a_stopped_model_refuses_every_load() {
        let rt = ModelRuntime::new().unwrap();
        rt.stop_model("muse-a").await.unwrap();
        let missing = Path::new("/nonexistent/muse-a.gguf");

        let err = rt
            .load_model_with_context("muse-a", missing, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("stopped by the operator"), "{err}");
        let err = rt.load_drafter("muse-a", missing, None).await.unwrap_err();
        assert!(err.to_string().contains("stopped by the operator"), "{err}");
        assert!(rt.is_stopped("muse-a"));
        // Other models are unaffected.
        assert!(rt.load_ticket("muse-b").is_ok());
    }

    /// A serve after a stop lets the model load again, but a load that was
    /// already running when the stop landed stays discarded: the serve starts
    /// its own load.
    #[test]
    fn a_serve_after_a_stop_reopens_loads_but_not_the_stale_one() {
        let rt = ModelRuntime::new().unwrap();
        let stale = rt.load_ticket("muse-a").unwrap();
        rt.hold_stopped("muse-a");
        rt.resume_model("muse-a");

        assert!(!rt.is_stopped("muse-a"));
        assert!(!rt.install_if_current("muse-a", stale, || {}));
        let fresh = rt.load_ticket("muse-a").expect("serve reopened loads");
        assert!(rt.install_if_current("muse-a", fresh, || {}));
    }

    /// Eviction is not a stop: the next request may load the model again, and
    /// a load in progress across an eviction still installs.
    #[tokio::test]
    async fn eviction_does_not_stop_the_model() {
        let rt = ModelRuntime::new().unwrap();
        let ticket = rt.load_ticket("muse-a").unwrap();
        let _ = rt.unload_model("muse-a").await;
        assert!(!rt.is_stopped("muse-a"));
        assert!(rt.install_if_current("muse-a", ticket, || {}));
    }
}
