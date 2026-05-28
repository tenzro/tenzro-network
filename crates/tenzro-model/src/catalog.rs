//! Curated model catalog with HuggingFace GGUF repository metadata.
//!
//! All models listed here are **ungated** — no HF login required for download.
//! Models use GGUF quantization format for efficient loading via llama.cpp.
//! llama.cpp auto-detects the model architecture from GGUF metadata — the
//! `ModelArchitecture` enum is informational only (for UI display and filtering).

use serde::{Deserialize, Serialize};

/// License tier for catalog entries.
///
/// Drives the gating logic in `ModelRegistry::register_model()`:
///
/// - `Permissive` (Apache-2.0, MIT, BSD-2/3): loaded by default, no friction.
/// - `Attribution` (CC-BY-4.0): loaded by default, attribution string is logged
///   at first load so operators stay compliant with the BY clause.
/// - `CommercialCustom`: bespoke commercial-OK licenses with non-standard terms
///   (DINOv3 License, SAM License with ITAR restrictions, Gemma terms). License
///   summary + URL are logged at first load; explicit `--accept-license <id>`
///   per family must be set on `download` / `serve` to activate.
/// - `NonCommercial` (CC-BY-NC, OpenRAIL-M, etc.): refused unless
///   `--accept-non-commercial` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum LicenseTier {
    #[default]
    Permissive,
    Attribution,
    CommercialCustom,
    NonCommercial,
}


/// A model entry in the curated catalog with HuggingFace metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfModelEntry {
    /// Internal model ID (e.g. "qwen3.5-4b-q4km")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Model family (e.g. "qwen3.5", "gemma3", "mistral")
    pub family: String,
    /// HuggingFace repository ID (e.g. "unsloth/Qwen3.5-4B-GGUF")
    pub hf_repo: String,
    /// GGUF filename to download (e.g. "Qwen3.5-4B-Q4_K_M.gguf")
    pub hf_filename: String,
    /// Parameter count
    pub parameters: String,
    /// Model architecture (informational — llama.cpp auto-detects from GGUF)
    pub architecture: ModelArchitecture,
    /// Context window length
    pub context_length: u32,
    /// Quantization method (e.g. "Q4_K_M", "Q8_0")
    pub quantization: String,
    /// Approximate file size in bytes
    pub size_bytes: u64,
    /// Minimum RAM in GB to load
    pub min_ram_gb: u32,
    /// License
    pub license: String,
    /// Short description
    pub description: String,
    /// Optional speculative-decoding drafter — the catalog ID of a smaller,
    /// vocab-matched GGUF to load alongside this model as the speculative
    /// drafter (llama.cpp `--spec-draft-model` / `-md`). The referenced ID
    /// must resolve via `get_model_by_id`; the drafter entry itself is a
    /// normal `HfModelEntry` and so is independently downloadable. `None`
    /// means no drafter is recommended for this target — either because
    /// none exists with a matching tokenizer, or because community
    /// benchmarks show speculative decoding is net-negative for this
    /// architecture (e.g. small-active-path MoE on consumer GPUs).
    pub drafter_id: Option<String>,
}

/// Model architecture — informational only.
///
/// llama.cpp auto-detects the architecture from GGUF metadata, so this enum
/// is used for UI display, catalog filtering, and documentation purposes.
/// All listed architectures are fully supported by llama.cpp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelArchitecture {
    Llama,
    Qwen2,
    Qwen3,
    Qwen3Moe,
    Qwen35,
    Qwen35Moe,
    Qwen36,
    Qwen36Moe,
    Gemma3,
    Gemma4,
    Gemma4Moe,
    Mistral,
    MistralMoe,
    Phi3,
    Glm,
    Kimi,
    MiniMax,
    DeepSeekV3,
    GptOss,
    Granite,
    GraniteH,
}

impl std::fmt::Display for ModelArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Llama => write!(f, "llama"),
            Self::Qwen2 => write!(f, "qwen2"),
            Self::Qwen3 => write!(f, "qwen3"),
            Self::Qwen3Moe => write!(f, "qwen3moe"),
            Self::Qwen35 => write!(f, "qwen35"),
            Self::Qwen35Moe => write!(f, "qwen35moe"),
            Self::Qwen36 => write!(f, "qwen36"),
            Self::Qwen36Moe => write!(f, "qwen36moe"),
            Self::Gemma3 => write!(f, "gemma3"),
            Self::Gemma4 => write!(f, "gemma4"),
            Self::Gemma4Moe => write!(f, "gemma4moe"),
            Self::Mistral => write!(f, "mistral"),
            Self::MistralMoe => write!(f, "mistralmoe"),
            Self::Phi3 => write!(f, "phi3"),
            Self::Glm => write!(f, "glm"),
            Self::Kimi => write!(f, "kimi"),
            Self::MiniMax => write!(f, "minimax"),
            Self::DeepSeekV3 => write!(f, "deepseekv3"),
            Self::GptOss => write!(f, "gpt-oss"),
            Self::Granite => write!(f, "granite"),
            Self::GraniteH => write!(f, "granite-h"),
        }
    }
}

/// A curated ONNX vision encoder entry.
///
/// Vision encoders run on the `VisionRuntime` (ORT-backed) rather than
/// llama.cpp, so they have a separate metadata shape — no GGUF
/// quantization, no llama.cpp architecture enum, but they do carry the
/// preprocessing parameters the runtime needs (input size, normalization,
/// embedding dim).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxVisionEntry {
    /// Internal model ID (e.g. "clip-vit-b32").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "clip", "siglip2", "dinov3").
    pub family: String,
    /// HuggingFace repository ID (e.g. "Xenova/clip-vit-base-patch32").
    pub hf_repo: String,
    /// ONNX filename within the repo (e.g. "onnx/vision_model.onnx").
    pub hf_filename: String,
    /// Native input resolution in pixels (square — H == W).
    pub input_size: u32,
    /// Output embedding dimension.
    pub embedding_dim: usize,
    /// Recommended preprocessing normalization key — one of
    /// `"clip"`, `"imagenet"`, `"siglip"`. Maps directly to
    /// `ImageNormalization::{CLIP, IMAGENET, SIGLIP}` at load time.
    pub normalization: String,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream base model where applicable).
    pub license: String,
    /// License tier — drives the gating logic in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX vision encoder catalog.
///
/// All entries verified to have **ungated, single-file ONNX exports** on
/// HuggingFace as of 2026-04. Files come from `Xenova/*` and
/// `onnx-community/*` mirrors of upstream base models.
pub fn get_vision_catalog() -> Vec<OnnxVisionEntry> {
    vec![
        // ── CLIP family (MIT, OpenAI) ──────────────────────────────
        OnnxVisionEntry {
            id: "clip-vit-b32".into(),
            name: "CLIP ViT-B/32".into(),
            family: "clip".into(),
            hf_repo: "Xenova/clip-vit-base-patch32".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 512,
            normalization: "clip".into(),
            size_bytes: 352_000_000,
            min_ram_gb: 2,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI CLIP ViT-B/32 — compact image encoder, 512-dim embeddings".into(),
        },
        OnnxVisionEntry {
            id: "clip-vit-l14".into(),
            name: "CLIP ViT-L/14".into(),
            family: "clip".into(),
            hf_repo: "Xenova/clip-vit-large-patch14".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "clip".into(),
            size_bytes: 1_220_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI CLIP ViT-L/14 — large image encoder, 768-dim embeddings".into(),
        },
        // ── SigLIP / SigLIP2 (Apache 2.0, Google) ─────────────────
        OnnxVisionEntry {
            id: "siglip-base-224".into(),
            name: "SigLIP base patch16-224".into(),
            family: "siglip".into(),
            hf_repo: "Xenova/siglip-base-patch16-224".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "siglip".into(),
            size_bytes: 372_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP base — sigmoid-loss image-text encoder".into(),
        },
        OnnxVisionEntry {
            id: "siglip2-base-224".into(),
            name: "SigLIP2 base patch16-224".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-base-patch16-224-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "siglip".into(),
            size_bytes: 372_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 base — improved multilingual image-text encoder".into(),
        },
        OnnxVisionEntry {
            id: "siglip2-large-256".into(),
            name: "SigLIP2 large patch16-256".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-large-patch16-256-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 256,
            embedding_dim: 1024,
            normalization: "siglip".into(),
            size_bytes: 1_300_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 large — high-fidelity multilingual image-text encoder".into(),
        },
        OnnxVisionEntry {
            id: "siglip2-so400m-384".into(),
            name: "SigLIP2 SO400M patch14-384".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-so400m-patch14-384-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 384,
            embedding_dim: 1152,
            normalization: "siglip".into(),
            size_bytes: 1_700_000_000,
            min_ram_gb: 6,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 SO400M-384 — flagship encoder, top zero-shot accuracy".into(),
        },
        // ── DINOv3 family (DINOv3 License — commercial-OK custom) ─
        // Released Sep 2025; ONNX exports at onnx-community mirrors.
        // License is bespoke (not Apache); commercial use permitted with
        // restrictions on derivative-model redistribution. See:
        // https://huggingface.co/facebook/dinov3-vits16-pretrain-lvd1689m
        OnnxVisionEntry {
            id: "dinov3-vits16".into(),
            name: "DINOv3 ViT-S/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vits16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 384,
            normalization: "imagenet".into(),
            size_bytes: 92_000_000,
            min_ram_gb: 1,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-S/16 — next-gen self-supervised features, edge-tier".into(),
        },
        OnnxVisionEntry {
            id: "dinov3-vitb16".into(),
            name: "DINOv3 ViT-B/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vitb16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "imagenet".into(),
            size_bytes: 350_000_000,
            min_ram_gb: 2,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-B/16 — flagship self-supervised features, base-tier".into(),
        },
        OnnxVisionEntry {
            id: "dinov3-vitl16".into(),
            name: "DINOv3 ViT-L/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vitl16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 1024,
            normalization: "imagenet".into(),
            size_bytes: 1_240_000_000,
            min_ram_gb: 4,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-L/16 — large self-supervised features".into(),
        },
    ]
}

/// Look up an ONNX vision encoder by its internal ID.
pub fn get_vision_model_by_id(id: &str) -> Option<OnnxVisionEntry> {
    get_vision_catalog().into_iter().find(|m| m.id == id)
}

/// A curated ONNX timeseries-forecaster entry.
///
/// Forecasters run on the `TimeseriesRuntime` (ORT-backed) and have a
/// distinct shape from the LLM and vision catalogs: no token vocabulary
/// or pixel preprocessing, just the I/O contract the runtime needs to
/// dispatch a forecast — `context_length` (input window), `max_horizon`
/// (output prediction length), and `n_quantiles` (0 for point forecasts,
/// >0 for quantile heads where the output tensor has shape
/// > `[1, max_horizon, n_quantiles]`).
///
/// Source of truth for buildable models: `tools/ts-export/targets.toml`
/// (the export harness that produces the artifacts referenced here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxForecastEntry {
    /// Internal model ID (e.g. "timesfm-2.5-200m").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Architecture family (e.g. "timesfm").
    pub family: String,
    /// Upstream HuggingFace repository ID (PyTorch source weights).
    pub hf_repo: String,
    /// ONNX filename produced by the export harness (relative to
    /// the artifact dir — typically `model.onnx`).
    pub hf_filename: String,
    /// Maximum input context length in timesteps.
    pub context_length: usize,
    /// Maximum forecast horizon in timesteps.
    pub max_horizon: usize,
    /// Number of quantiles in the output head. `0` means a point
    /// forecast (shape `[1, max_horizon]`); `>0` means a quantile
    /// forecast (shape `[1, max_horizon, n_quantiles]`).
    pub n_quantiles: usize,
    /// Approximate parameter count label (e.g. "200M").
    pub parameters: String,
    /// Approximate ONNX file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream model).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX timeseries-forecaster catalog.
///
/// Mirrors the `[[target]]` entries in `tools/ts-export/targets.toml` —
/// each model in this list has a documented export path that produces
/// a single-file ONNX artifact compatible with `GenericForecast`.
pub fn get_forecast_catalog() -> Vec<OnnxForecastEntry> {
    vec![
        // ── TimesFM 2.5 (Apache 2.0, Google) ───────────────────────
        // Decoder-only transformer with patch tokenizer. 10 quantiles.
        // Community ONNX export (pdufour) is the only live-loadable form;
        // upstream google/timesfm-2.5-200m-pytorch ships PyTorch weights.
        // Requires batch_size=2 (force_flip_invariance: true in config) —
        // the runtime tiles input + reads row 0.
        OnnxForecastEntry {
            id: "timesfm-2.5-200m".into(),
            name: "TimesFM 2.5 200M".into(),
            family: "timesfm".into(),
            hf_repo: "pdufour/timesfm-2.5-200m-transformers-onnx".into(),
            hf_filename: "onnx/model.onnx".into(),
            context_length: 2048,
            max_horizon: 128,
            n_quantiles: 10,
            parameters: "200M".into(),
            size_bytes: 1_001_713_626,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description:
                "Google TimesFM 2.5 — foundation timeseries forecaster, patch-tokenized decoder"
                    .into(),
        },
    ]
}

/// Look up an ONNX timeseries forecaster by its internal ID.
pub fn get_forecast_model_by_id(id: &str) -> Option<OnnxForecastEntry> {
    get_forecast_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Text embedding catalog (NEW for wave 1).
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX text-embedding entry.
///
/// Text encoders that map `[B, L]` token sequences to `[B, D]` dense
/// vectors. Served via the same ORT runtime path as vision encoders,
/// not via llama.cpp — even Gemma-derived encoders behave better as
/// bidirectional ONNX exports than as decoder-only GGUF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxTextEmbeddingEntry {
    /// Internal model ID (e.g. "qwen3-embedding-0.6b").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "qwen3-embedding", "embeddinggemma", "bge-m3").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename within the repo.
    pub hf_filename: String,
    /// Tokenizer filename (typically "tokenizer.json"). Loaded by the runtime.
    pub tokenizer_filename: String,
    /// Maximum sequence length the tokenizer/model accepts.
    pub max_sequence_length: u32,
    /// Native output embedding dimension (full vector, before any
    /// Matryoshka truncation).
    pub embedding_dim: u32,
    /// Optional Matryoshka dims allowed (e.g. `vec![512, 256, 128]` for
    /// EmbeddingGemma-300M). Empty means no MRL — only `embedding_dim`.
    pub matryoshka_dims: Vec<u32>,
    /// Whether the model supports fp16 activations. Some ONNX exports
    /// (e.g. EmbeddingGemma) require fp32 due to numerical sensitivity.
    pub supports_fp16: bool,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX text-embedding catalog.
///
/// Verified 2026 SOTA additions: Qwen3-Embedding family (#1 on MTEB
/// multilingual June 2025), EmbeddingGemma 300M (Matryoshka edge-tier),
/// and BGE-M3 (multilingual retrieval classic).
pub fn get_text_embedding_catalog() -> Vec<OnnxTextEmbeddingEntry> {
    vec![
        // ── Qwen3-Embedding (Apache 2.0, Alibaba) ──────────────────
        // #1 on MTEB multilingual (June 2025). Hidden dim varies by tier.
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-0.6b".into(),
            name: "Qwen3-Embedding 0.6B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-0.6B-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 1024,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 1_300_000_000,
            min_ram_gb: 3,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 0.6B — SOTA multilingual text embeddings, edge-tier".into(),
        },
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-4b".into(),
            name: "Qwen3-Embedding 4B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-4B-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 2560,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 7_500_000_000,
            min_ram_gb: 12,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 4B — mid-tier multilingual text embeddings".into(),
        },
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-8b".into(),
            name: "Qwen3-Embedding 8B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-8B-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 4096,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 15_500_000_000,
            min_ram_gb: 20,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 8B — flagship multilingual text embeddings".into(),
        },
        // ── EmbeddingGemma 300M (Gemma terms, Google) ──────────────
        // Matryoshka 768→512→256→128. fp32 only.
        OnnxTextEmbeddingEntry {
            id: "embeddinggemma-300m".into(),
            name: "EmbeddingGemma 300M".into(),
            family: "embeddinggemma".into(),
            hf_repo: "onnx-community/embeddinggemma-300m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 2048,
            embedding_dim: 768,
            matryoshka_dims: vec![512, 256, 128],
            supports_fp16: false,
            size_bytes: 1_200_000_000,
            min_ram_gb: 2,
            license: "Gemma Terms of Use".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Google EmbeddingGemma 300M — Matryoshka edge embeddings, fp32-only".into(),
        },
        // ── BGE-M3 (MIT, BAAI) ─────────────────────────────────────
        // Multilingual + multi-functional (dense, sparse, ColBERT) — dense only here.
        OnnxTextEmbeddingEntry {
            id: "bge-m3".into(),
            name: "BGE-M3".into(),
            family: "bge".into(),
            hf_repo: "BAAI/bge-m3".into(),
            hf_filename: "onnx/model.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 8192,
            embedding_dim: 1024,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 2_300_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "BAAI BGE-M3 — multilingual multi-granularity retrieval encoder".into(),
        },
    ]
}

/// Look up an ONNX text-embedding model by its internal ID.
pub fn get_text_embedding_model_by_id(id: &str) -> Option<OnnxTextEmbeddingEntry> {
    get_text_embedding_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Segmentation catalog (NEW for wave 1).
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX segmentation model entry.
///
/// SAM-family models split into an image encoder (cached per image) and
/// a prompt decoder (mask predictor). Both are required at inference
/// time, so the artifact is a multi-file `Bundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxSegmentationEntry {
    /// Internal model ID (e.g. "sam2-base", "edgesam").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "sam3", "sam2", "edgesam", "mobilesam").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// Encoder ONNX filename within the bundle.
    pub encoder_filename: String,
    /// Decoder ONNX filename within the bundle.
    pub decoder_filename: String,
    /// Native input resolution.
    pub input_size: u32,
    /// Approximate total bundle size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX segmentation catalog.
pub fn get_segmentation_catalog() -> Vec<OnnxSegmentationEntry> {
    // SAM 3 / SAM 3.1 are intentionally absent: their community ONNX exports
    // bundle a CLIP-style text encoder and a 14-input box-prompted decoder
    // that returns a variable number of detections (not the SAM-1/SAM-2
    // point/box prompt → 3-mask shape that this runtime's `Segmenter` trait
    // models). Text-promptable segmentation will land in a separate
    // `text_segmentation_runtime` when Meta or the community publishes a
    // stable ONNX schema.
    vec![
        // ── SAM 2 (community ONNX export — vietanhdev / samexporter) ─
        // Meta source is Apache 2.0; ONNX exports inherit that tier.
        OnnxSegmentationEntry {
            id: "sam2-base".into(),
            name: "SAM 2 base".into(),
            family: "sam2".into(),
            hf_repo: "vietanhdev/segment-anything-2-onnx-models".into(),
            encoder_filename: "sam2_hiera_base_plus_encoder.onnx".into(),
            decoder_filename: "sam2_hiera_base_plus_decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 320_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Meta SAM 2 base (community ONNX export) — previous-gen SOTA".into(),
        },
        OnnxSegmentationEntry {
            id: "sam2-large".into(),
            name: "SAM 2 large".into(),
            family: "sam2".into(),
            hf_repo: "vietanhdev/segment-anything-2-onnx-models".into(),
            encoder_filename: "sam2_hiera_large_encoder.onnx".into(),
            decoder_filename: "sam2_hiera_large_decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 900_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Meta SAM 2 large (community ONNX export) — high-fidelity".into(),
        },
        // ── EdgeSAM (NTU S-Lab 1.0 — non-commercial) ────────────────
        OnnxSegmentationEntry {
            id: "edgesam".into(),
            name: "EdgeSAM".into(),
            family: "edgesam".into(),
            hf_repo: "chongzhou/EdgeSAM".into(),
            encoder_filename: "edge_sam_3x_encoder.onnx".into(),
            decoder_filename: "edge_sam_3x_decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 38_000_000,
            min_ram_gb: 1,
            license: "NTU S-Lab License 1.0".into(),
            license_tier: LicenseTier::NonCommercial,
            description: "EdgeSAM — ultra-compact 9.6M-param segmentation (research-only)".into(),
        },
        // ── MobileSAM (Apache 2.0) — edge tier ─────────────────────
        OnnxSegmentationEntry {
            id: "mobilesam".into(),
            name: "MobileSAM".into(),
            family: "mobilesam".into(),
            hf_repo: "vietanhdev/segment-anything-onnx-models".into(),
            encoder_filename: "mobile_sam_encoder.onnx".into(),
            decoder_filename: "mobile_sam.decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 40_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "MobileSAM (community ONNX export) — compact mobile-optimized".into(),
        },
    ]
}

/// Look up an ONNX segmentation model by its internal ID.
pub fn get_segmentation_model_by_id(id: &str) -> Option<OnnxSegmentationEntry> {
    get_segmentation_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Detection catalog (NEW for wave 1).
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX object-detection entry.
///
/// Real-time DETR-family detectors (single-file ONNX, NMS-free output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxDetectionEntry {
    /// Internal model ID (e.g. "rf-detr-base").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "rf-detr", "d-fine").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename.
    pub hf_filename: String,
    /// Native input resolution.
    pub input_size: u32,
    /// Number of class labels (COCO=80 by default; some checkpoints differ).
    pub num_classes: u32,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX detection catalog.
///
/// RF-DETR is the 2026 SOTA: first real-time detector >60 AP on COCO
/// (ICLR 2026). D-FINE retained as a secondary baseline. Avoids
/// AGPL-licensed Ultralytics YOLO and demoted RT-DETRv2.
pub fn get_detection_catalog() -> Vec<OnnxDetectionEntry> {
    vec![
        // ── RF-DETR (Apache 2.0, Roboflow) ─────────────────────────
        // 6 size tiers from nano to 2x-large.
        // RF-DETR has tier-specific input resolutions (384–880). The
        // detector reads the actual shape from the loaded ONNX session
        // at load time; these catalog values are advisory.
        OnnxDetectionEntry {
            id: "rf-detr-nano".into(),
            name: "RF-DETR nano".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-nano.onnx".into(),
            input_size: 384,
            num_classes: 90,
            size_bytes: 30_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR nano — fastest real-time DETR, edge-tier".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-small".into(),
            name: "RF-DETR small".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-small.onnx".into(),
            input_size: 512,
            num_classes: 90,
            size_bytes: 60_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR small — balanced speed/accuracy".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-medium".into(),
            name: "RF-DETR medium".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-medium.onnx".into(),
            input_size: 576,
            num_classes: 90,
            size_bytes: 110_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR medium — mid-tier real-time DETR".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-base".into(),
            name: "RF-DETR base".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-base-coco.onnx".into(),
            input_size: 560,
            num_classes: 90,
            size_bytes: 180_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR base — real-time DETR baseline (COCO)".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-large".into(),
            name: "RF-DETR large".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-large-2026.onnx".into(),
            input_size: 704,
            num_classes: 90,
            size_bytes: 350_000_000,
            min_ram_gb: 3,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR large — high-accuracy real-time DETR (2026 refresh)".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-2xl".into(),
            name: "RF-DETR 2x-large".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-xxlarge.onnx".into(),
            input_size: 768,
            num_classes: 90,
            size_bytes: 700_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR 2x-large — flagship >60 AP on COCO (ICLR 2026)".into(),
        },
        // ── D-FINE (Apache 2.0) — secondary baseline ──────────────
        OnnxDetectionEntry {
            id: "d-fine-s".into(),
            name: "D-FINE small".into(),
            family: "d-fine".into(),
            hf_repo: "Peterande/D-FINE".into(),
            hf_filename: "dfine_s_coco.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 40_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE small — efficient DETR variant".into(),
        },
        OnnxDetectionEntry {
            id: "d-fine-m".into(),
            name: "D-FINE medium".into(),
            family: "d-fine".into(),
            hf_repo: "Peterande/D-FINE".into(),
            hf_filename: "dfine_m_coco.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 80_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE medium — mid-tier DETR baseline".into(),
        },
        OnnxDetectionEntry {
            id: "d-fine-l".into(),
            name: "D-FINE large".into(),
            family: "d-fine".into(),
            hf_repo: "Peterande/D-FINE".into(),
            hf_filename: "dfine_l_coco.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 130_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE large — high-accuracy DETR baseline".into(),
        },
    ]
}

/// Look up an ONNX detection model by its internal ID.
pub fn get_detection_model_by_id(id: &str) -> Option<OnnxDetectionEntry> {
    get_detection_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Audio (ASR) catalog (NEW for wave 1).
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX audio-ASR entry.
///
/// Whisper-family models split into encoder + decoder (+ optional joiner
/// for transducer-style architectures). Distil-Whisper / Whisper-v3-turbo
/// follow the encoder-decoder split. Moonshine v2 is a single-file
/// encoder-only architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxAudioEntry {
    /// Internal model ID (e.g. "whisper-large-v3-turbo").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "whisper", "moonshine", "parakeet", "canary").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// Encoder ONNX filename (always present).
    pub encoder_filename: String,
    /// Optional decoder filename (None for single-file encoders like Moonshine).
    pub decoder_filename: Option<String>,
    /// Optional joiner filename (transducer-style models like Parakeet).
    pub joiner_filename: Option<String>,
    /// Audio sample rate the model expects (typically 16000 Hz).
    pub sample_rate: u32,
    /// Maximum audio segment length in seconds.
    pub max_audio_seconds: u32,
    /// Languages supported (ISO codes, e.g. ["en", "es", "fr", ...]).
    pub languages: Vec<String>,
    /// Approximate total file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX audio-ASR catalog.
pub fn get_audio_catalog() -> Vec<OnnxAudioEntry> {
    vec![
        // ── Moonshine (MIT, Useful Sensors) ────────────────────────
        // Community ONNX export at onnx-community/moonshine-{tiny,base}-ONNX.
        // Standard transformers.js layout: onnx/encoder_model.onnx +
        // onnx/decoder_model_merged.onnx (single graph keyed by
        // `use_cache_branch` bool input).
        OnnxAudioEntry {
            id: "moonshine-tiny".into(),
            name: "Moonshine Tiny".into(),
            family: "moonshine".into(),
            hf_repo: "onnx-community/moonshine-tiny-ONNX".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 100_000_000,
            min_ram_gb: 1,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Moonshine Tiny — on-device English ASR, edge-tier (raw waveform input)".into(),
        },
        OnnxAudioEntry {
            id: "moonshine-base".into(),
            name: "Moonshine Base".into(),
            family: "moonshine".into(),
            hf_repo: "onnx-community/moonshine-base-ONNX".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 240_000_000,
            min_ram_gb: 1,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Moonshine Base — on-device English ASR, balanced (raw waveform input)".into(),
        },
        // ── Distil-Whisper (MIT, HuggingFace) ──────────────────────
        // Merged decoder with `use_cache_branch` input — single graph
        // handles both prefill and incremental decode.
        OnnxAudioEntry {
            id: "distil-whisper-small-en".into(),
            name: "Distil-Whisper small.en".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-small.en".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 330_000_000,
            min_ram_gb: 2,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper small.en — distilled English ASR (80-mel)".into(),
        },
        OnnxAudioEntry {
            id: "distil-whisper-medium-en".into(),
            name: "Distil-Whisper medium.en".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-medium.en".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 760_000_000,
            min_ram_gb: 3,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper medium.en — higher-accuracy distilled English ASR (80-mel)".into(),
        },
        OnnxAudioEntry {
            id: "distil-whisper-large-v3".into(),
            name: "Distil-Whisper large-v3".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-large-v3".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["multilingual".into()],
            size_bytes: 1_500_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper large-v3 — multilingual distilled ASR (128-mel)".into(),
        },
        // ── Whisper Large-v3-turbo (MIT, OpenAI) ───────────────────
        // Community ONNX export at onnx-community/whisper-large-v3-turbo;
        // OpenAI's own repo ships PyTorch only.
        OnnxAudioEntry {
            id: "whisper-large-v3-turbo".into(),
            name: "Whisper Large-v3-turbo".into(),
            family: "whisper".into(),
            hf_repo: "onnx-community/whisper-large-v3-turbo".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["multilingual".into()],
            size_bytes: 1_600_000_000,
            min_ram_gb: 5,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI Whisper Large-v3-turbo — flagship multilingual ASR (128-mel)".into(),
        },
        // ── Parakeet TDT 0.6B v3 (NVIDIA, CC-BY-4.0) ───────────────
        // Community ONNX export at istupakov/parakeet-tdt-0.6b-v3-onnx.
        // Three-file bundle: encoder + fused decoder_joint + 128-mel
        // preprocessor. Token-and-Duration Transducer — joint emits
        // vocab logits plus per-step duration logits that drive how
        // many encoder frames to advance per emission.
        // `joiner_filename` carries the preprocessor here because the
        // catalog struct doesn't have a dedicated preprocessor slot;
        // `decoder_filename` carries the fused decoder_joint network.
        // Loader resolves `vocab.txt` separately by convention.
        OnnxAudioEntry {
            id: "parakeet-tdt-0.6b-v3".into(),
            name: "NeMo Parakeet TDT 0.6B v3".into(),
            family: "parakeet".into(),
            hf_repo: "istupakov/parakeet-tdt-0.6b-v3-onnx".into(),
            encoder_filename: "encoder-model.onnx".into(),
            decoder_filename: Some("decoder_joint-model.onnx".into()),
            joiner_filename: Some("nemo128.onnx".into()),
            sample_rate: 16000,
            max_audio_seconds: 60,
            languages: vec![
                "en".into(), "es".into(), "fr".into(), "de".into(),
                "bg".into(), "hr".into(), "cs".into(), "da".into(),
                "nl".into(), "et".into(), "fi".into(), "el".into(),
                "hu".into(), "it".into(), "lv".into(), "lt".into(),
                "mt".into(), "pl".into(), "pt".into(), "ro".into(),
                "sk".into(), "sl".into(), "sv".into(), "ru".into(),
                "uk".into(),
            ],
            size_bytes: 2_500_000_000,
            min_ram_gb: 4,
            license: "CC-BY-4.0".into(),
            license_tier: LicenseTier::Attribution,
            description: "NVIDIA Parakeet TDT 0.6B v3 — multilingual TDT transducer (25 langs, 128-mel)".into(),
        },
        // ── Canary 1B Flash ────────────────────────────────────────
        // NeMo Conformer AED ASR (attention encoder-decoder, no blank).
        // 5249-entry SentencePiece vocab, 10-token decoder prefix
        // selecting source/target language + PNC + timestamp + diarize
        // modes. CC-BY-4.0 / Attribution. Reuses Parakeet's nemo128
        // preprocessor — `joiner_filename` slot carries `nemo128.onnx`.
        OnnxAudioEntry {
            id: "canary-1b-flash".into(),
            name: "NVIDIA Canary 1B Flash".into(),
            family: "canary".into(),
            hf_repo: "istupakov/canary-1b-flash-onnx".into(),
            encoder_filename: "encoder-model.onnx".into(),
            decoder_filename: Some("decoder-model.onnx".into()),
            joiner_filename: Some("nemo128.onnx".into()),
            sample_rate: 16000,
            max_audio_seconds: 40,
            languages: vec![
                "en".into(),
                "de".into(),
                "es".into(),
                "fr".into(),
            ],
            size_bytes: 4_000_000_000,
            min_ram_gb: 6,
            license: "CC-BY-4.0".into(),
            license_tier: LicenseTier::Attribution,
            description: "NVIDIA Canary 1B Flash — Conformer AED with translation across 4 languages (en/de/es/fr)".into(),
        },
    ]
}

/// Look up an ONNX audio model by its internal ID.
pub fn get_audio_model_by_id(id: &str) -> Option<OnnxAudioEntry> {
    get_audio_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Video catalog (NEW scaffolding for wave 1 — empty until permissive
// + ONNX-shippable encoder lands).
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX video-encoder entry.
///
/// Empty in wave 1 — the 2026 OSS landscape has no permissive,
/// ONNX-shippable, encoder-only video model. VideoMAE v1/v2 are
/// CC-BY-NC; V-JEPA 2/2.1 license is unclear and ONNX export is
/// non-trivial. The runtime + RPC + CLI surface ships empty so adding
/// entries later is mechanical. Re-evaluate quarterly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxVideoEntry {
    /// Internal model ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename.
    pub hf_filename: String,
    /// Frame side length (typically 224).
    pub frame_size: u32,
    /// Number of frames consumed per clip.
    pub num_frames: u32,
    /// Sampling FPS.
    pub fps: u32,
    /// Output embedding dimension.
    pub embedding_dim: u32,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License.
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX video catalog.
///
/// Returns an empty Vec in wave 1 (intentional). The runtime, RPC, CLI,
/// and MCP surfaces all build and register, but no concrete entries
/// exist until a permissive + ONNX-shippable video encoder is verified.
pub fn get_video_catalog() -> Vec<OnnxVideoEntry> {
    vec![]
}

/// Look up an ONNX video model by its internal ID.
pub fn get_video_model_by_id(id: &str) -> Option<OnnxVideoEntry> {
    get_video_catalog().into_iter().find(|m| m.id == id)
}

/// Get the full curated model catalog.
pub fn get_model_catalog() -> Vec<HfModelEntry> {
    let mut catalog = vec![
    // ── Qwen 3 (Apache 2.0, via unsloth GGUF — official Qwen repos lack Q4_K_M) ──
    HfModelEntry {
        id: "qwen3-0.6b".into(),
        name: "Qwen 3 0.6B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-0.6B-GGUF".into(),
        hf_filename: "Qwen3-0.6B-Q4_K_M.gguf".into(),
        parameters: "0.6B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 396_705_472,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "Compact model optimized for edge deployment".into(),
        drafter_id: None,
    }];
    catalog.push(HfModelEntry {
        id: "qwen3-1.7b".into(),
        name: "Qwen 3 1.7B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-1.7B-GGUF".into(),
        hf_filename: "Qwen3-1.7B-Q4_K_M.gguf".into(),
        parameters: "1.7B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_107_409_472,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Versatile model for various language tasks".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3-4b".into(),
        name: "Qwen 3 4B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-4B-GGUF".into(),
        hf_filename: "Qwen3-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_497_281_312,
        min_ram_gb: 4,
        license: "Apache 2.0".into(),
        description: "Well-balanced model for production use".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3-8b".into(),
        name: "Qwen 3 8B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-8B-GGUF".into(),
        hf_filename: "Qwen3-8B-Q4_K_M.gguf".into(),
        parameters: "8B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_027_784_512,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Extended context model for long-form tasks".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3-14b".into(),
        name: "Qwen 3 14B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-14B-GGUF".into(),
        hf_filename: "Qwen3-14B-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 9_001_753_984,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Premium model with extended context support".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3-32b".into(),
        name: "Qwen 3 32B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-32B-GGUF".into(),
        hf_filename: "Qwen3-32B-Q4_K_M.gguf".into(),
        parameters: "32B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_762_150_048,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Top-tier model with 128K context window".into(),
        drafter_id: Some("qwen3-0.6b".into()),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-30b-a3b".into(),
        name: "Qwen 3 30B-A3B (MoE)".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-30B-A3B-GGUF".into(),
        hf_filename: "Qwen3-30B-A3B-Q4_K_M.gguf".into(),
        parameters: "30B (MoE)".into(),
        architecture: ModelArchitecture::Qwen3Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_556_686_912,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Mixture-of-Experts with 3B active params for efficient scaling".into(),
        drafter_id: None,
    });

    // ── Qwen 3.5 (Apache 2.0, ungated, unsloth GGUF) ──────────────────
    catalog.push(HfModelEntry {
        id: "qwen3.5-0.8b".into(),
        name: "Qwen 3.5 0.8B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-0.8B-GGUF".into(),
        hf_filename: "Qwen3.5-0.8B-Q4_K_M.gguf".into(),
        parameters: "0.8B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 532_517_120,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "Compact multilingual model for efficient on-device inference".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-2b".into(),
        name: "Qwen 3.5 2B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-2B-GGUF".into(),
        hf_filename: "Qwen3.5-2B-Q4_K_M.gguf".into(),
        parameters: "2B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_280_835_840,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Efficient small model for chat and text generation".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-4b".into(),
        name: "Qwen 3.5 4B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-4B-GGUF".into(),
        hf_filename: "Qwen3.5-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_740_937_888,
        min_ram_gb: 4,
        license: "Apache 2.0".into(),
        description: "Mid-size model with strong reasoning and coding performance".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-9b".into(),
        name: "Qwen 3.5 9B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-9B-GGUF".into(),
        hf_filename: "Qwen3.5-9B-Q4_K_M.gguf".into(),
        parameters: "9B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_680_522_464,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "High-performance model for complex language understanding".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-27b".into(),
        name: "Qwen 3.5 27B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-27B-GGUF".into(),
        hf_filename: "Qwen3.5-27B-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_740_812_704,
        min_ram_gb: 20,
        license: "Apache 2.0".into(),
        description: "Flagship Qwen 3.5 model with state-of-the-art performance".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-35b-a3b".into(),
        name: "Qwen 3.5 35B-A3B (MoE)".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-35B-A3B-GGUF".into(),
        hf_filename: "Qwen3.5-35B-A3B-Q4_K_M.gguf".into(),
        parameters: "35B (MoE)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 22_016_023_168,
        min_ram_gb: 14,
        license: "Apache 2.0".into(),
        description: "Mixture-of-Experts with only 3B active params — fast inference at 35B quality".into(),
        drafter_id: None,
    });

    // ── Gemma 3 (Google, ungated via unsloth GGUF) ─────────────────────
    catalog.push(HfModelEntry {
        id: "gemma3-270m".into(),
        name: "Gemma 3 270M".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-270m-it-GGUF".into(),
        hf_filename: "gemma-3-270m-it-Q4_K_M.gguf".into(),
        parameters: "270M".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 253_115_424,
        min_ram_gb: 1,
        license: "Gemma License".into(),
        description: "Tiny Gemma model for ultra-lightweight on-device inference".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma3-1b".into(),
        name: "Gemma 3 1B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-1b-it-GGUF".into(),
        hf_filename: "gemma-3-1b-it-Q4_K_M.gguf".into(),
        parameters: "1B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 806_058_272,
        min_ram_gb: 2,
        license: "Gemma License".into(),
        description: "Google's compact instruction-tuned model".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma3-4b".into(),
        name: "Gemma 3 4B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-4b-it-GGUF".into(),
        hf_filename: "gemma-3-4b-it-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_489_894_016,
        min_ram_gb: 4,
        license: "Gemma License".into(),
        description: "Extended context Gemma model for chat applications".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma3-12b".into(),
        name: "Gemma 3 12B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-12b-it-GGUF".into(),
        hf_filename: "gemma-3-12b-it-Q4_K_M.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 7_300_778_336,
        min_ram_gb: 10,
        license: "Gemma License".into(),
        description: "High-performance instruction-tuned model from Google".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma3-27b".into(),
        name: "Gemma 3 27B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-27b-it-GGUF".into(),
        hf_filename: "gemma-3-27b-it-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_546_688_736,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Google's largest Gemma model with exceptional capabilities".into(),
        drafter_id: None,
    });

    // ── Gemma 4 (Gemma License, via unsloth GGUF) ──────────────────────
    // Drafters: Google's official MTP "assistant" 0.5B-class drafters live at
    // `google/gemma-4-*-it-assistant` (safetensors, Apache-2.0, published
    // 2026-05-05). Community GGUF conversions ship Q8_0/F16 only — no
    // Q4_K_M yet. As of 2026-05-06 only the E2B and 31B sizes have GGUF
    // mirrors; E4B and 26B-A4B drafters are safetensors-only upstream.
    catalog.push(HfModelEntry {
        id: "gemma4-e2b-it-assistant".into(),
        name: "Gemma 4 E2B Assistant (Drafter)".into(),
        family: "gemma4".into(),
        hf_repo: "Radamanthys11/Gemma-4-E2B-it-assistant-GGUF".into(),
        hf_filename: "Gemma-4-E2B-it-assistant.Q8_0.gguf".into(),
        parameters: "0.5B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q8_0".into(),
        size_bytes: 170_000_000,
        min_ram_gb: 1,
        license: "Apache 2.0".into(),
        description: "Google's official MTP drafter for Gemma 4 E2B — speculative decoding pair.".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma4-31b-it-assistant".into(),
        name: "Gemma 4 31B Assistant (Drafter)".into(),
        family: "gemma4".into(),
        hf_repo: "Radamanthys11/Gemma-4-31B-it-assistant-GGUF".into(),
        hf_filename: "Gemma-4-31B-it-assistant.Q8_0.gguf".into(),
        parameters: "0.5B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q8_0".into(),
        size_bytes: 1_000_000_000,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "Google's official MTP drafter for Gemma 4 31B — speculative decoding pair.".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e2b".into(),
        name: "Gemma 4 E2B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E2B-it-GGUF".into(),
        hf_filename: "gemma-4-E2B-it-Q4_K_M.gguf".into(),
        parameters: "E2B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 3_339_569_152,
        min_ram_gb: 4,
        license: "Gemma License".into(),
        description: "Google's compact Gemma 4 multimodal model (text + image, 128K context)".into(),
        drafter_id: Some("gemma4-e2b-it-assistant".into()),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e4b".into(),
        name: "Gemma 4 E4B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E4B-it-GGUF".into(),
        hf_filename: "gemma-4-E4B-it-Q4_K_M.gguf".into(),
        parameters: "E4B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_347_737_600,
        min_ram_gb: 8,
        license: "Gemma License".into(),
        description: "Google's efficient Gemma 4 multimodal model (text + image, 128K context)".into(),
        // No drafter wired: `google/gemma-4-E4B-it-assistant` is safetensors-only
        // upstream; community GGUF conversion not yet published. Wire when one lands.
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma4-26b-a4b".into(),
        name: "Gemma 4 26B-A4B (MoE)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-26B-A4B-it-GGUF".into(),
        hf_filename: "gemma-4-26B-A4B-it-UD-Q4_K_M.gguf".into(),
        parameters: "26B (4B active)".into(),
        architecture: ModelArchitecture::Gemma4Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_146_000_000,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Gemma 4 Mixture-of-Experts: 26B total params, 4B active per token (128K context)".into(),
        // No drafter wired: same situation as E4B — safetensors-only at
        // `google/gemma-4-26B-A4B-it-assistant`. MoE 4B-active also risks
        // the same net-negative speculative profile as Qwen3.6-35B-A3B.
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gemma4-31b".into(),
        name: "Gemma 4 31B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-31B-it-GGUF".into(),
        hf_filename: "gemma-4-31B-it-Q4_K_M.gguf".into(),
        parameters: "31B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_650_142_208,
        min_ram_gb: 24,
        license: "Gemma License".into(),
        description: "Google's largest dense Gemma 4 model with exceptional capabilities (128K context)".into(),
        drafter_id: Some("gemma4-31b-it-assistant".into()),
    });

    // ── Mistral (Apache 2.0, ungated) ──────────────────────────────────
    catalog.push(HfModelEntry {
        id: "mistral-7b".into(),
        name: "Mistral 7B Instruct v0.3".into(),
        family: "mistral".into(),
        hf_repo: "bartowski/Mistral-7B-Instruct-v0.3-GGUF".into(),
        hf_filename: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf".into(),
        parameters: "7B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_372_812_000,
        min_ram_gb: 6,
        license: "Apache 2.0".into(),
        description: "Mistral AI's classic 7B instruction model".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "mistral-nemo-12b".into(),
        name: "Mistral Nemo 12B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Nemo-Instruct-2407-GGUF".into(),
        hf_filename: "Mistral-Nemo-Instruct-2407-Q4_K_M.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 7_477_204_512,
        min_ram_gb: 10,
        license: "Apache 2.0".into(),
        description: "Extended-context Mistral model built with NVIDIA".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-24b".into(),
        name: "Mistral Small 3.2 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF".into(),
        hf_filename: "Mistral-Small-3.2-24B-Instruct-2506-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_333_922_848,
        min_ram_gb: 18,
        license: "Apache 2.0".into(),
        description: "Mistral's latest Small 3.2 model for demanding workloads".into(),
        drafter_id: None,
    });

    // ── Ministral 3 (Mistral AI, Apache 2.0, ungated) ──────────────────
    catalog.push(HfModelEntry {
        id: "ministral3-3b".into(),
        name: "Ministral 3 3B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Ministral-3-3B-Instruct-2512-GGUF".into(),
        hf_filename: "Ministral-3-3B-Instruct-2512-Q4_K_M.gguf".into(),
        parameters: "3B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_146_497_824,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Compact Ministral 3 for lightweight tasks".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "ministral3-8b".into(),
        name: "Ministral 3 8B".into(),
        family: "mistral".into(),
        hf_repo: "bartowski/Ministral-8B-Instruct-2410-GGUF".into(),
        hf_filename: "Ministral-8B-Instruct-2410-Q4_K_M.gguf".into(),
        parameters: "8B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_911_500_096,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Versatile Ministral 3 for general-purpose tasks".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "ministral3-14b".into(),
        name: "Ministral 3 14B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Ministral-3-14B-Instruct-2512-GGUF".into(),
        hf_filename: "Ministral-3-14B-Instruct-2512-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 8_239_067_840,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "High-performance Ministral 3 for complex reasoning".into(),
        drafter_id: None,
    });

    // ── Phi 4 (Microsoft, MIT, ungated) ─────────────────────────────
    catalog.push(HfModelEntry {
        id: "phi4-mini".into(),
        name: "Phi-4 Mini 3.8B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-mini-instruct-GGUF".into(),
        hf_filename: "Phi-4-mini-instruct-Q4_K_M.gguf".into(),
        parameters: "3.8B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_491_874_272,
        min_ram_gb: 3,
        license: "MIT".into(),
        description: "Compact Phi-4 Mini with 128K context".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "phi4".into(),
        name: "Phi-4 14B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/phi-4-GGUF".into(),
        hf_filename: "phi-4-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 16000,
        quantization: "Q4_K_M".into(),
        size_bytes: 8_890_306_112,
        min_ram_gb: 10,
        license: "MIT".into(),
        description: "Microsoft Phi-4 — strong reasoning at 14B".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "phi4-reasoning".into(),
        name: "Phi-4 Reasoning 14B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-reasoning-GGUF".into(),
        hf_filename: "phi-4-reasoning-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 9_053_117_728,
        min_ram_gb: 10,
        license: "MIT".into(),
        description: "Phi-4 fine-tuned for chain-of-thought reasoning".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "phi4-mini-reasoning".into(),
        name: "Phi-4 Mini Reasoning 3.8B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-mini-reasoning-GGUF".into(),
        hf_filename: "Phi-4-mini-reasoning-Q4_K_M.gguf".into(),
        parameters: "3.8B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_491_875_232,
        min_ram_gb: 3,
        license: "MIT".into(),
        description: "Compact Phi-4 Mini fine-tuned for reasoning tasks".into(),
        drafter_id: None,
    });

    // ── SmolLM (HuggingFace, Apache 2.0, ungated) ───────────────────
    catalog.push(HfModelEntry {
        id: "smollm2-1.7b".into(),
        name: "SmolLM2 1.7B".into(),
        family: "smollm".into(),
        hf_repo: "unsloth/SmolLM2-1.7B-Instruct-GGUF".into(),
        hf_filename: "SmolLM2-1.7B-Instruct-Q4_K_M.gguf".into(),
        parameters: "1.7B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 8192,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_055_609_504,
        min_ram_gb: 2,
        license: "Apache-2.0".into(),
        description: "Compact SmolLM2 for on-device AI".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "smollm3-3b".into(),
        name: "SmolLM3 3B".into(),
        family: "smollm".into(),
        hf_repo: "unsloth/SmolLM3-3B-GGUF".into(),
        hf_filename: "SmolLM3-3B-Q4_K_M.gguf".into(),
        parameters: "3B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 65536,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_915_306_528,
        min_ram_gb: 3,
        license: "Apache-2.0".into(),
        description: "SmolLM3 — 11T tokens, dual-mode reasoning".into(),
        drafter_id: None,
    });

    // ── Qwen 3 Coder (Apache 2.0, ungated, unsloth GGUF) ───────────────
    catalog.push(HfModelEntry {
        id: "qwen3-coder-30b-a3b".into(),
        name: "Qwen 3 Coder 30B-A3B (MoE)".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF".into(),
        hf_filename: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf".into(),
        parameters: "30B (MoE)".into(),
        architecture: ModelArchitecture::Qwen3Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_556_689_568,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Code-focused MoE — 30B total, 3B active, 256K context".into(),
        drafter_id: None,
    });

    // ── Nemotron (NVIDIA Open, ungated, unsloth GGUF) ────────────────
    catalog.push(HfModelEntry {
        id: "nemotron-nano-4b".into(),
        name: "Nemotron 3 Nano 4B".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/NVIDIA-Nemotron-3-Nano-4B-GGUF".into(),
        hf_filename: "NVIDIA-Nemotron-3-Nano-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_900_295_712,
        min_ram_gb: 4,
        license: "NVIDIA Open".into(),
        description: "Hybrid Mamba-2 + Attention edge model, 256K context".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "nemotron-nano-30b-a3b".into(),
        name: "Nemotron 3 Nano 30B-A3B (MoE)".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/Nemotron-3-Nano-30B-A3B-GGUF".into(),
        hf_filename: "Nemotron-3-Nano-30B-A3B-Q4_K_M.gguf".into(),
        parameters: "30B (MoE)".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 24_574_373_664,
        min_ram_gb: 16,
        license: "NVIDIA Open".into(),
        description: "Hybrid Mamba-2 MoE — 30B total, 3.5B active, 128K context".into(),
        drafter_id: None,
    });

    // ── GLM-4 (Apache 2.0, via bartowski GGUF) ─────────────────────────
    catalog.push(HfModelEntry {
        id: "glm4-9b".into(),
        name: "GLM-4 9B Chat".into(),
        family: "glm".into(),
        hf_repo: "bartowski/glm-4-9b-chat-GGUF".into(),
        hf_filename: "glm-4-9b-chat-Q4_K_M.gguf".into(),
        parameters: "9B".into(),
        architecture: ModelArchitecture::Glm,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_758_885_888,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Zhipu AI GLM-4 9B instruction-tuned, 128K context".into(),
        drafter_id: None,
    });

    // ── Kimi K2 (MIT, via unsloth GGUF) ──────────────────────────────
    catalog.push(HfModelEntry {
        id: "kimi-k2-instruct".into(),
        name: "Kimi K2 Instruct (MoE)".into(),
        family: "kimi".into(),
        hf_repo: "unsloth/Kimi-K2-Instruct-GGUF".into(),
        hf_filename: "Kimi-K2-Instruct-Q4_K_M.gguf".into(),
        parameters: "1T (MoE, 32B active)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 20_203_667_456,
        min_ram_gb: 24,
        license: "MIT".into(),
        description: "Moonshot AI Kimi K2 MoE — 1T total, 32B active, 128K context".into(),
        drafter_id: None,
    });

    // ── MiniMax M1 (MiniMax Open, via unsloth GGUF) ──────────────────
    catalog.push(HfModelEntry {
        id: "minimax-m1-40b".into(),
        name: "MiniMax M1 40B".into(),
        family: "minimax".into(),
        hf_repo: "unsloth/MiniMax-M1-40B-GGUF".into(),
        hf_filename: "MiniMax-M1-40B-Q4_K_M.gguf".into(),
        parameters: "40B".into(),
        architecture: ModelArchitecture::MiniMax,
        context_length: 1048576,
        quantization: "Q4_K_M".into(),
        size_bytes: 24_198_768_640,
        min_ram_gb: 28,
        license: "MiniMax Open".into(),
        description: "MiniMax M1 40B with Lightning Attention, 1M context".into(),
        drafter_id: None,
    });

    // ── DeepSeek V3 (MIT, via unsloth GGUF) ──────────────────────────
    catalog.push(HfModelEntry {
        id: "deepseek-v3-0324".into(),
        name: "DeepSeek V3 0324 (MoE)".into(),
        family: "deepseek".into(),
        hf_repo: "unsloth/DeepSeek-V3-0324-GGUF".into(),
        hf_filename: "DeepSeek-V3-0324-Q4_K_M.gguf".into(),
        parameters: "685B (MoE, 37B active)".into(),
        architecture: ModelArchitecture::DeepSeekV3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 377_801_089_024,
        min_ram_gb: 256,
        license: "MIT".into(),
        description: "DeepSeek V3 MoE — 685B total, 37B active, 128K context".into(),
        drafter_id: None,
    });

    // NOTE: Llama models removed — not supported on Tenzro Network.
    // Mistral Small 4 (119B MoE) excluded — Q4_K_M split across multiple GGUF files.
    // Mistral Large 3 (675B MoE) excluded — Q4_K_M split across multiple GGUF files.
    // DeepSeek V4 (Pro/Flash) excluded — no community GGUF available as of 2026-04.

    // ── Qwen 3.6 (Apache 2.0, via unsloth GGUF) ──────────────────────
    catalog.push(HfModelEntry {
        id: "qwen3.6-27b".into(),
        name: "Qwen 3.6 27B".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-27B-GGUF".into(),
        hf_filename: "Qwen3.6-27B-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen36,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_800_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 27B — flagship dense model with 128K context".into(),
        // Vocab-matched (248320) per llama.cpp PR #19493; community-validated pairing.
        drafter_id: Some("qwen3.5-0.8b".into()),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.6-35b-a3b".into(),
        name: "Qwen 3.6 35B-A3B (MoE)".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-35B-A3B-GGUF".into(),
        hf_filename: "Qwen3.6-35B-A3B-Q4_K_M.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen36Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 21_400_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 MoE — 35B total, ~3B active per token".into(),
        // Intentionally no drafter: `qwen3.5-0.8b` would be vocab-matched, but the
        // 3B-active-path MoE makes the speculative verify cost outweigh the draft
        // savings on consumer GPUs (RTX 3090: net-negative throughput). Re-evaluate
        // when a smaller MoE-aware drafter or llama.cpp PR #22673 (native MTP) lands.
        drafter_id: None,
    });

    // ── Mistral Small 3.1 / 3.2 (Apache 2.0, via unsloth GGUF) ───────
    // Drafter: alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF — Qwen2.5-0.5B base
    // fine-tuned on Mistral-Small-3.1 outputs across 6 languages. Tokenizer
    // is vocab-compatible with Mistral-Small-3.1/3.2 by construction.
    catalog.push(HfModelEntry {
        id: "mistral-small-3.1-draft-0.5b".into(),
        name: "Mistral Small 3.1 DRAFT 0.5B".into(),
        family: "mistral".into(),
        hf_repo: "alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF".into(),
        hf_filename: "Mistral-Small-3.1-DRAFT-0.5B.Q4_K_M.gguf".into(),
        parameters: "0.5B".into(),
        // GGUF is a Qwen2.5-0.5B fine-tune — llama.cpp loads it as Qwen2.
        architecture: ModelArchitecture::Qwen2,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 397_000_000,
        min_ram_gb: 1,
        license: "Apache 2.0".into(),
        description: "Speculative drafter for Mistral Small 3.1/3.2 — vocab-matched, 6-language fine-tune.".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-3.1-24b".into(),
        name: "Mistral Small 3.1 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.1-24B-Instruct-2503-GGUF".into(),
        hf_filename: "Mistral-Small-3.1-24B-Instruct-2503-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_300_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "Mistral Small 3.1 — improved reasoning over 3.0 baseline".into(),
        drafter_id: Some("mistral-small-3.1-draft-0.5b".into()),
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-3.2-24b".into(),
        name: "Mistral Small 3.2 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF".into(),
        hf_filename: "Mistral-Small-3.2-24B-Instruct-2506-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_300_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "Mistral Small 3.2 — latest 3-series point release".into(),
        drafter_id: Some("mistral-small-3.1-draft-0.5b".into()),
    });

    // ── GPT-OSS (Apache 2.0, OpenAI's open-weights release) ──────────
    catalog.push(HfModelEntry {
        id: "gpt-oss-20b".into(),
        name: "GPT-OSS 20B".into(),
        family: "gpt-oss".into(),
        hf_repo: "unsloth/gpt-oss-20b-GGUF".into(),
        hf_filename: "gpt-oss-20b-Q4_K_M.gguf".into(),
        parameters: "20B".into(),
        architecture: ModelArchitecture::GptOss,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 12_400_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "OpenAI GPT-OSS 20B — open-weights release, native MXFP4".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "gpt-oss-120b".into(),
        name: "GPT-OSS 120B".into(),
        family: "gpt-oss".into(),
        hf_repo: "unsloth/gpt-oss-120b-GGUF".into(),
        hf_filename: "gpt-oss-120b-Q4_K_M.gguf".into(),
        parameters: "120B".into(),
        architecture: ModelArchitecture::GptOss,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 73_500_000_000,
        min_ram_gb: 80,
        license: "Apache 2.0".into(),
        description: "OpenAI GPT-OSS 120B — open-weights release, native MXFP4".into(),
        drafter_id: None,
    });

    // ── IBM Granite 4.0 (Apache 2.0) ─────────────────────────────────
    catalog.push(HfModelEntry {
        id: "granite4-350m".into(),
        name: "Granite 4.0 350M".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-350m-GGUF".into(),
        hf_filename: "granite-4.0-350m-Q4_K_M.gguf".into(),
        parameters: "350M".into(),
        architecture: ModelArchitecture::Granite,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 220_000_000,
        min_ram_gb: 1,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 350M — ultra-compact for edge deployment".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "granite4-1b".into(),
        name: "Granite 4.0 1B".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-1b-GGUF".into(),
        hf_filename: "granite-4.0-1b-Q4_K_M.gguf".into(),
        parameters: "1B".into(),
        architecture: ModelArchitecture::Granite,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 700_000_000,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 1B — compact enterprise model".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "granite4-h-tiny".into(),
        name: "Granite 4.0 H-Tiny".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-h-tiny-GGUF".into(),
        hf_filename: "granite-4.0-h-tiny-Q4_K_M.gguf".into(),
        parameters: "7B (hybrid)".into(),
        architecture: ModelArchitecture::GraniteH,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_300_000_000,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 H-Tiny — hybrid Mamba/Transformer architecture".into(),
        drafter_id: None,
    });
    catalog.push(HfModelEntry {
        id: "granite4-h-small".into(),
        name: "Granite 4.0 H-Small (32B)".into(),
        family: "granite".into(),
        hf_repo: "unsloth/granite-4.0-h-small-GGUF".into(),
        hf_filename: "granite-4.0-h-small-Q4_K_M.gguf".into(),
        parameters: "32B (hybrid)".into(),
        architecture: ModelArchitecture::GraniteH,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_400_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 H-Small — 32B hybrid for long-context enterprise".into(),
        drafter_id: None,
    });

    catalog
}

/// Look up a model by its internal ID.
pub fn get_model_by_id(id: &str) -> Option<HfModelEntry> {
    get_model_catalog().into_iter().find(|m| m.id == id)
}

/// Get all model families.
pub fn get_model_families() -> Vec<String> {
    let catalog = get_model_catalog();
    let mut families: Vec<String> = catalog.iter().map(|m| m.family.clone()).collect();
    families.sort();
    families.dedup();
    families
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_not_empty() {
        let catalog = get_model_catalog();
        assert!(!catalog.is_empty());
        assert!(catalog.len() >= 20, "Expected at least 20 models in catalog");
    }

    #[test]
    fn test_all_entries_have_required_fields() {
        for entry in get_model_catalog() {
            assert!(!entry.id.is_empty(), "Model ID empty");
            assert!(!entry.name.is_empty(), "Model name empty for {}", entry.id);
            assert!(!entry.hf_repo.is_empty(), "HF repo empty for {}", entry.id);
            assert!(!entry.hf_filename.is_empty(), "HF filename empty for {}", entry.id);
            assert!(entry.size_bytes > 0, "Size is 0 for {}", entry.id);
            assert!(entry.min_ram_gb > 0, "Min RAM is 0 for {}", entry.id);
            assert!(entry.context_length > 0, "Context length is 0 for {}", entry.id);
        }
    }

    #[test]
    fn test_get_model_by_id() {
        assert!(get_model_by_id("qwen3-0.6b").is_some());
        assert!(get_model_by_id("gemma3-4b").is_some());
        assert!(get_model_by_id("nonexistent").is_none());
    }

    /// Every `drafter_id` in the catalog must resolve to another catalog
    /// entry. A dangling reference would break speculative-decoding load.
    #[test]
    fn test_drafter_ids_resolve() {
        let catalog = get_model_catalog();
        for entry in &catalog {
            if let Some(drafter) = entry.drafter_id.as_ref() {
                assert!(
                    get_model_by_id(drafter).is_some(),
                    "model `{}` references unknown drafter `{}`",
                    entry.id,
                    drafter,
                );
                // A drafter must not itself nest a drafter.
                let drafter_entry = get_model_by_id(drafter).unwrap();
                assert!(
                    drafter_entry.drafter_id.is_none(),
                    "drafter `{}` itself has a drafter_id — nesting not supported",
                    drafter,
                );
                // Drafter must be smaller than target — sanity check, not a hard
                // requirement of llama.cpp but a precondition for net-positive
                // speculative decoding throughput.
                assert!(
                    drafter_entry.size_bytes < entry.size_bytes,
                    "drafter `{}` ({} bytes) is not smaller than target `{}` ({} bytes)",
                    drafter,
                    drafter_entry.size_bytes,
                    entry.id,
                    entry.size_bytes,
                );
            }
        }
    }

    /// The four target/drafter pairings we explicitly ship as of 2026-05-06.
    /// If any of these stop being wired, speculative decoding regresses for
    /// the corresponding family.
    #[test]
    fn test_known_drafter_pairings() {
        let pairs = [
            ("qwen3-32b", "qwen3-0.6b"),
            ("qwen3.6-27b", "qwen3.5-0.8b"),
            ("mistral-small-3.1-24b", "mistral-small-3.1-draft-0.5b"),
            ("mistral-small-3.2-24b", "mistral-small-3.1-draft-0.5b"),
            ("gemma4-e2b", "gemma4-e2b-it-assistant"),
            ("gemma4-31b", "gemma4-31b-it-assistant"),
        ];
        for (target, expected_drafter) in pairs {
            let entry = get_model_by_id(target)
                .unwrap_or_else(|| panic!("missing target `{}`", target));
            assert_eq!(
                entry.drafter_id.as_deref(),
                Some(expected_drafter),
                "target `{}` should pair with drafter `{}`",
                target,
                expected_drafter,
            );
        }
    }

    #[test]
    fn test_model_families() {
        let families = get_model_families();
        assert!(families.contains(&"qwen3".to_string()));
        assert!(families.contains(&"qwen3.6".to_string()));
        assert!(families.contains(&"gemma3".to_string()));
        assert!(families.contains(&"gemma4".to_string()));
        assert!(families.contains(&"mistral".to_string()));
        assert!(families.contains(&"nemotron".to_string()));
        assert!(families.contains(&"glm".to_string()));
        assert!(families.contains(&"kimi".to_string()));
        assert!(families.contains(&"minimax".to_string()));
        assert!(families.contains(&"deepseek".to_string()));
        assert!(families.contains(&"gpt-oss".to_string()));
        assert!(families.contains(&"granite".to_string()));
    }

    #[test]
    fn test_2026_additions_present() {
        assert!(get_model_by_id("qwen3.6-27b").is_some());
        assert!(get_model_by_id("qwen3.6-35b-a3b").is_some());
        assert!(get_model_by_id("mistral-small-3.1-24b").is_some());
        assert!(get_model_by_id("mistral-small-3.2-24b").is_some());
        assert!(get_model_by_id("gpt-oss-20b").is_some());
        assert!(get_model_by_id("gpt-oss-120b").is_some());
        assert!(get_model_by_id("granite4-350m").is_some());
        assert!(get_model_by_id("granite4-1b").is_some());
        assert!(get_model_by_id("granite4-h-tiny").is_some());
        assert!(get_model_by_id("granite4-h-small").is_some());
    }

    #[test]
    fn test_unique_ids() {
        let catalog = get_model_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate model IDs found");
    }

    #[test]
    fn test_vision_catalog_not_empty() {
        let catalog = get_vision_catalog();
        assert!(!catalog.is_empty());
        assert!(catalog.len() >= 7, "Expected at least 7 vision encoders");
    }

    #[test]
    fn test_vision_entries_have_required_fields() {
        for e in get_vision_catalog() {
            assert!(!e.id.is_empty(), "vision id empty");
            assert!(!e.name.is_empty(), "vision name empty for {}", e.id);
            assert!(!e.hf_repo.is_empty(), "vision repo empty for {}", e.id);
            assert!(
                e.hf_filename.ends_with(".onnx"),
                "vision filename not .onnx for {}: {}",
                e.id,
                e.hf_filename
            );
            assert!(e.input_size > 0, "input_size 0 for {}", e.id);
            assert!(e.embedding_dim > 0, "embedding_dim 0 for {}", e.id);
            assert!(e.size_bytes > 0, "size 0 for {}", e.id);
            assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
            assert!(
                matches!(e.normalization.as_str(), "clip" | "imagenet" | "siglip"),
                "unknown normalization '{}' for {}",
                e.normalization,
                e.id
            );
        }
    }

    #[test]
    fn test_vision_get_by_id() {
        assert!(get_vision_model_by_id("clip-vit-b32").is_some());
        assert!(get_vision_model_by_id("siglip2-base-224").is_some());
        assert!(get_vision_model_by_id("dinov3-vitl16").is_some());
        assert!(get_vision_model_by_id("nonexistent").is_none());
    }

    #[test]
    fn test_vision_unique_ids() {
        let catalog = get_vision_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate vision model IDs");
    }

    #[test]
    fn test_vision_families_present() {
        let catalog = get_vision_catalog();
        let families: std::collections::HashSet<&str> =
            catalog.iter().map(|m| m.family.as_str()).collect();
        assert!(families.contains("clip"));
        assert!(families.contains("siglip"));
        assert!(families.contains("siglip2"));
        assert!(families.contains("dinov3"));
    }

    #[test]
    fn test_forecast_catalog_not_empty() {
        let catalog = get_forecast_catalog();
        assert!(!catalog.is_empty());
    }

    #[test]
    fn test_forecast_entries_have_required_fields() {
        for e in get_forecast_catalog() {
            assert!(!e.id.is_empty(), "forecast id empty");
            assert!(!e.name.is_empty(), "forecast name empty for {}", e.id);
            assert!(!e.hf_repo.is_empty(), "forecast repo empty for {}", e.id);
            assert!(
                e.hf_filename.ends_with(".onnx"),
                "forecast filename not .onnx for {}: {}",
                e.id,
                e.hf_filename
            );
            assert!(e.context_length > 0, "context_length 0 for {}", e.id);
            assert!(e.max_horizon > 0, "max_horizon 0 for {}", e.id);
            assert!(e.size_bytes > 0, "size 0 for {}", e.id);
            assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
            assert!(!e.parameters.is_empty(), "parameters empty for {}", e.id);
            assert!(!e.license.is_empty(), "license empty for {}", e.id);
        }
    }

    #[test]
    fn test_forecast_get_by_id() {
        assert!(get_forecast_model_by_id("timesfm-2.5-200m").is_some());
        assert!(get_forecast_model_by_id("nonexistent").is_none());
    }

    #[test]
    fn test_forecast_unique_ids() {
        let catalog = get_forecast_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate forecast model IDs");
    }

    #[test]
    fn test_forecast_families_present() {
        let catalog = get_forecast_catalog();
        let families: std::collections::HashSet<&str> =
            catalog.iter().map(|m| m.family.as_str()).collect();
        assert!(families.contains("timesfm"));
    }

    #[test]
    fn test_forecast_quantile_shape_invariant() {
        // n_quantiles > 0 → quantile head; TimesFM 2.5 ships 10 bands.
        let timesfm = get_forecast_model_by_id("timesfm-2.5-200m").unwrap();
        assert_eq!(timesfm.n_quantiles, 10);
    }

    // ── Vision catalog (DINOv3 + SigLIP2 large/so400m) ──────────────

    #[test]
    fn test_vision_dinov3_entries_present() {
        for id in &["dinov3-vits16", "dinov3-vitb16", "dinov3-vitl16"] {
            let e = get_vision_model_by_id(id)
                .unwrap_or_else(|| panic!("missing dinov3 entry {}", id));
            assert_eq!(e.family, "dinov3");
            assert_eq!(e.license_tier, LicenseTier::CommercialCustom);
        }
    }

    #[test]
    fn test_vision_siglip2_large_so400m_present() {
        for id in &["siglip2-large-256", "siglip2-so400m-384"] {
            let e = get_vision_model_by_id(id)
                .unwrap_or_else(|| panic!("missing siglip2 entry {}", id));
            assert_eq!(e.family, "siglip2");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    // ── Text embedding catalog ─────────────────────────────────────

    #[test]
    fn test_text_embedding_catalog_not_empty() {
        let catalog = get_text_embedding_catalog();
        assert!(catalog.len() >= 5, "expected at least 5 text-embedding models");
    }

    #[test]
    fn test_text_embedding_required_fields() {
        for e in get_text_embedding_catalog() {
            assert!(!e.id.is_empty());
            assert!(!e.hf_repo.is_empty());
            assert!(e.hf_filename.ends_with(".onnx"), "{} not .onnx", e.id);
            assert!(e.tokenizer_filename.ends_with(".json"));
            assert!(e.max_sequence_length > 0);
            assert!(e.embedding_dim > 0);
            assert!(e.size_bytes > 0);
            assert!(e.min_ram_gb > 0);
        }
    }

    #[test]
    fn test_text_embedding_qwen3_family() {
        for id in &[
            "qwen3-embedding-0.6b",
            "qwen3-embedding-4b",
            "qwen3-embedding-8b",
        ] {
            let e = get_text_embedding_model_by_id(id)
                .unwrap_or_else(|| panic!("missing qwen3-embedding {}", id));
            assert_eq!(e.family, "qwen3-embedding");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_embeddinggemma_matryoshka() {
        let e = get_text_embedding_model_by_id("embeddinggemma-300m").unwrap();
        assert_eq!(e.embedding_dim, 768);
        assert_eq!(e.matryoshka_dims, vec![512, 256, 128]);
        assert!(!e.supports_fp16, "EmbeddingGemma is fp32-only");
        assert_eq!(e.license_tier, LicenseTier::CommercialCustom);
    }

    #[test]
    fn test_text_embedding_unique_ids() {
        let ids: Vec<_> = get_text_embedding_catalog()
            .into_iter()
            .map(|m| m.id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let len_before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len_before, "duplicate text-embedding IDs");
    }

    // ── Segmentation catalog ───────────────────────────────────────

    #[test]
    fn test_segmentation_catalog_not_empty() {
        let catalog = get_segmentation_catalog();
        // SAM 2 base + large, EdgeSAM, MobileSAM. SAM 3 is deferred to a
        // future text-promptable runtime — see comment in
        // `get_segmentation_catalog`.
        assert_eq!(catalog.len(), 4, "expected 4 segmentation models");
    }

    #[test]
    fn test_segmentation_sam2_permissive() {
        for id in &["sam2-base", "sam2-large"] {
            let e = get_segmentation_model_by_id(id)
                .unwrap_or_else(|| panic!("missing {}", id));
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_segmentation_edge_tier() {
        // EdgeSAM is research-only (NTU S-Lab 1.0 = NonCommercial); MobileSAM
        // is Apache 2.0. Both are <50 MB.
        let edgesam = get_segmentation_model_by_id("edgesam").expect("missing edgesam");
        assert_eq!(edgesam.license_tier, LicenseTier::NonCommercial);
        assert!(edgesam.size_bytes < 50_000_000);

        let mobilesam = get_segmentation_model_by_id("mobilesam").expect("missing mobilesam");
        assert_eq!(mobilesam.license_tier, LicenseTier::Permissive);
        assert!(mobilesam.size_bytes < 50_000_000);
    }

    #[test]
    fn test_segmentation_required_fields() {
        for e in get_segmentation_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.encoder_filename.ends_with(".onnx"));
            assert!(e.decoder_filename.ends_with(".onnx"));
            assert!(e.input_size > 0);
            assert!(e.size_bytes > 0);
        }
    }

    // ── Detection catalog ──────────────────────────────────────────

    #[test]
    fn test_detection_catalog_not_empty() {
        let catalog = get_detection_catalog();
        assert!(catalog.len() >= 9, "expected ≥9 detection models");
    }

    #[test]
    fn test_detection_rf_detr_six_tiers() {
        for id in &[
            "rf-detr-nano",
            "rf-detr-small",
            "rf-detr-medium",
            "rf-detr-base",
            "rf-detr-large",
            "rf-detr-2xl",
        ] {
            let e = get_detection_model_by_id(id)
                .unwrap_or_else(|| panic!("missing rf-detr tier {}", id));
            assert_eq!(e.family, "rf-detr");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_detection_required_fields() {
        for e in get_detection_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.hf_filename.ends_with(".onnx"));
            assert!(e.input_size > 0);
            assert!(e.num_classes > 0);
            assert!(e.size_bytes > 0);
        }
    }

    // ── Audio catalog ──────────────────────────────────────────────

    #[test]
    fn test_audio_catalog_not_empty() {
        let catalog = get_audio_catalog();
        assert!(catalog.len() >= 5, "expected ≥5 audio models");
    }

    #[test]
    fn test_audio_required_fields() {
        for e in get_audio_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.encoder_filename.ends_with(".onnx"));
            assert_eq!(e.sample_rate, 16000);
            assert!(e.max_audio_seconds > 0);
            assert!(!e.languages.is_empty(), "{} has no languages", e.id);
        }
    }

    // ── Video catalog (empty scaffolding) ──────────────────────────

    #[test]
    fn test_video_catalog_empty_in_wave_1() {
        let catalog = get_video_catalog();
        assert!(
            catalog.is_empty(),
            "wave 1 ships an empty video catalog by design"
        );
        assert!(get_video_model_by_id("anything").is_none());
    }
}
