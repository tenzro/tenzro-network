//! Multi-modal inference commands for the Tenzro CLI.
//!
//! Wraps the JSON-RPC multi-modal surface:
//!   - `forecast`      → `tenzro_forecast`
//!   - `embed-text`    → `tenzro_textEmbed` (+ `load`/`unload` to serve a catalog encoder locally)
//!   - `embed-image`   → `tenzro_imageEmbed`, `tenzro_imageTextSimilarity`
//!   - `segment`       → `tenzro_segment`
//!   - `text-segment`  → `tenzro_textSegment`
//!   - `detect`        → `tenzro_detect`
//!   - `transcribe`    → `tenzro_transcribe`
//!   - `embed-video`   → `tenzro_videoEmbed`
//!
//! Each subcommand reads the input from a local path (image / audio / video),
//! base64-encodes it, and dispatches to the node. List/catalog subcommands
//! cover the discovery side.
//!
//! `load` differs by modality. `embed-text load` fetches the artifact onto the
//! node, because a download path exists for text encoders. Every other
//! modality registers an ONNX file that is already on the node's filesystem, so
//! those arms take `--path` and resolve it node-side.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde_json::json;

use crate::output;
use crate::rpc::RpcClient;

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

fn read_b64(path: &str) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

// ============================================================================
// embed-text
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedTextCommand {
    /// List the curated text-embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...).
    Catalog(EmbedTextCatalogCmd),
    /// List currently-loaded text encoders on this node.
    List(EmbedTextListCmd),
    /// Download a catalog encoder onto this node and register it for serving.
    Load(EmbedTextLoadCmd),
    /// Unregister a previously-loaded text encoder.
    Unload(EmbedTextUnloadCmd),
    /// Embed one or more strings.
    Run(EmbedTextRunCmd),
}

impl EmbedTextCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct EmbedTextLoadCmd {
    /// Catalog model id (e.g. `qwen3-embedding-0.6b`, `embeddinggemma-300m`, `bge-m3`).
    /// The node fetches the ONNX graph, its external-data sidecar (if any), and
    /// the tokenizer from HuggingFace onto its persistent models dir, then serves it.
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedTextLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_loadTextEmbeddingModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedTextUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedTextUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadTextEmbeddingModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedTextCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedTextCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listTextEmbeddingCatalog", json!({}))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedTextListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedTextListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listTextEmbeddingModels", json!({}))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedTextRunCmd {
    /// Model id of a loaded text encoder.
    #[arg(long)]
    model: String,
    /// Input strings (repeat --input for multiple).
    #[arg(long = "input")]
    inputs: Vec<String>,
    /// Optional Matryoshka truncation dim (e.g. 512, 256, 128 for EmbeddingGemma).
    #[arg(long)]
    requested_dim: Option<u32>,
    /// L2-normalize the output (most retrieval pipelines want this).
    #[arg(long, default_value_t = false)]
    normalize: bool,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedTextRunCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(anyhow!("at least one --input is required"));
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_textEmbed",
                json!({
                    "model_id": self.model,
                    "inputs": self.inputs,
                    "requested_dim": self.requested_dim,
                    "normalize": self.normalize,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// segment
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum SegmentCommand {
    /// List the curated segmentation catalog (SAM 2, EdgeSAM, MobileSAM).
    Catalog(SegmentCatalogCmd),
    /// List currently-loaded segmenters.
    List(SegmentListCmd),
    /// Register an encoder/decoder ONNX pair already on the node's filesystem.
    Load(SegmentLoadCmd),
    /// Unregister a previously-loaded segmenter.
    Unload(SegmentUnloadCmd),
    /// Run a segmentation request given prompts.
    Run(SegmentRunCmd),
}

impl SegmentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct SegmentCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listSegmentationCatalog", json!({}))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SegmentListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listSegmentationModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SegmentLoadCmd {
    /// Model id to register the segmenter under.
    #[arg(long)]
    model: String,
    /// Path on the node to the image-encoder ONNX file.
    #[arg(long = "encoder-path")]
    encoder_path: String,
    /// Path on the node to the mask-decoder ONNX file.
    #[arg(long = "decoder-path")]
    decoder_path: String,
    /// Catalog id (e.g. `sam2-base`) to inherit the family and input resolution
    /// from, and to apply the licence gate.
    #[arg(long = "catalog-id")]
    catalog_id: Option<String>,
    /// Decoder ABI, when not inheriting from the catalog: `sam1` (also EdgeSAM,
    /// MobileSAM) or `sam2`.
    #[arg(long)]
    family: Option<String>,
    /// Native input resolution, when not inheriting from the catalog.
    #[arg(long = "input-size")]
    input_size: Option<u32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.catalog_id.is_none() && (self.family.is_none() || self.input_size.is_none()) {
            return Err(anyhow!(
                "pass --catalog-id, or both --family and --input-size"
            ));
        }
        let mut payload = json!({
            "model_id": self.model,
            "encoder_path": self.encoder_path,
            "decoder_path": self.decoder_path,
        });
        if let Some(c) = &self.catalog_id {
            payload["catalog_id"] = json!(c);
        }
        if let Some(f) = &self.family {
            payload["family"] = json!(f);
        }
        if let Some(s) = self.input_size {
            payload["input_size"] = json!(s);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadSegmentationModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SegmentUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadSegmentationModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SegmentRunCmd {
    #[arg(long)]
    model: String,
    /// Path to the input image (PNG/JPEG/WebP).
    #[arg(long)]
    image: String,
    /// JSON file containing a list of SegmentPrompt values. Coordinates are in
    /// original-image pixels:
    /// `{"type":"point","x":412,"y":310,"is_foreground":true}`,
    /// `{"type":"points","points":[{"x":412,"y":310,"is_foreground":true}]}`,
    /// `{"type":"box","x0":120,"y0":80,"x1":540,"y1":420}`.
    #[arg(long)]
    prompts: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let prompts_str = std::fs::read_to_string(&self.prompts)
            .with_context(|| format!("failed to read prompts file {}", self.prompts))?;
        let prompts: serde_json::Value =
            serde_json::from_str(&prompts_str).with_context(|| "prompts file is not valid JSON")?;
        let image_b64 = read_b64(&self.image)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_segment",
                json!({
                    "model_id": self.model,
                    "image_base64": image_b64,
                    "prompts": prompts,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// text-segment (SAM 3 / SAM 3.1 — open-vocabulary text-promptable segmentation)
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum TextSegmentCommand {
    /// List the curated text-segmentation catalog (SAM 3, SAM 3.1).
    Catalog(TextSegmentCatalogCmd),
    /// List currently-loaded text-promptable segmenters.
    List(TextSegmentListCmd),
    /// Download the SAM-3 bundle from HuggingFace Hub and register it.
    Load(TextSegmentLoadCmd),
    /// Unregister a previously-loaded text-promptable segmenter.
    Unload(TextSegmentUnloadCmd),
    /// Run an open-vocabulary text-prompt segmentation.
    Run(TextSegmentRunCmd),
}

impl TextSegmentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct TextSegmentCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TextSegmentCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listTextSegmentationCatalog", json!({}))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextSegmentListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TextSegmentListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listTextSegmentationModels", json!({}))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextSegmentLoadCmd {
    /// Catalog model id (e.g. `sam3-vit-h`).
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TextSegmentLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_loadTextSegmentationModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextSegmentUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TextSegmentUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadTextSegmentationModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextSegmentRunCmd {
    /// Model id of a loaded SAM-3 segmenter.
    #[arg(long)]
    model: String,
    /// Path to the input image (PNG/JPEG/WebP).
    #[arg(long)]
    image: String,
    /// Free-text label to segment (e.g. `"person"`, `"sofa"`, `"dog"`).
    #[arg(long)]
    text: String,
    /// Optional normalized cxcywh box prompt, four floats in `[0,1]`
    /// (e.g. `--box "0.5,0.5,0.3,0.4"`).
    #[arg(long)]
    r#box: Option<String>,
    /// Score threshold in `[0, 1]`.
    #[arg(long, default_value_t = 0.5)]
    score_threshold: f32,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TextSegmentRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let image_b64 = read_b64(&self.image)?;
        let box_prompt = if let Some(spec) = &self.r#box {
            let parts: Vec<&str> = spec.split(',').collect();
            if parts.len() != 4 {
                return Err(anyhow!(
                    "--box expects four comma-separated floats: cx,cy,w,h"
                ));
            }
            let floats: Vec<f32> = parts
                .iter()
                .map(|s| s.trim().parse::<f32>())
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| anyhow!("invalid float in --box: {}", e))?;
            Some(json!({
                "cx": floats[0],
                "cy": floats[1],
                "w": floats[2],
                "h": floats[3],
            }))
        } else {
            None
        };
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_textSegment",
                json!({
                    "model_id": self.model,
                    "image_base64": image_b64,
                    "text_prompt": self.text,
                    "box_prompt": box_prompt,
                    "score_threshold": self.score_threshold,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// detect
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum DetectCommand {
    /// List the curated detection catalog (RF-DETR, D-FINE).
    Catalog(DetectCatalogCmd),
    /// List currently-loaded detectors.
    List(DetectListCmd),
    /// Register a detector ONNX file already on the node's filesystem.
    Load(DetectLoadCmd),
    /// Unregister a previously-loaded detector.
    Unload(DetectUnloadCmd),
    /// Run object detection.
    Run(DetectRunCmd),
}

impl DetectCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct DetectLoadCmd {
    /// Model id to register the detector under.
    #[arg(long)]
    model: String,
    /// Path on the node to the detector ONNX file.
    #[arg(long)]
    path: String,
    /// Catalog id (e.g. `rf-detr-medium`) to inherit the family, input
    /// resolution and class count from, and to apply the licence gate.
    #[arg(long = "catalog-id")]
    catalog_id: Option<String>,
    /// Output ABI, when not inheriting from the catalog: `rf_detr` or `d_fine`.
    #[arg(long)]
    family: Option<String>,
    /// Native input resolution, when not inheriting from the catalog.
    #[arg(long = "input-size")]
    input_size: Option<u32>,
    /// Class-label count, when not inheriting from the catalog (RF-DETR indexes
    /// 90 COCO slots, D-FINE 80).
    #[arg(long = "num-classes")]
    num_classes: Option<u32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DetectLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.catalog_id.is_none()
            && (self.family.is_none() || self.input_size.is_none() || self.num_classes.is_none())
        {
            return Err(anyhow!(
                "pass --catalog-id, or all of --family, --input-size and --num-classes"
            ));
        }
        let mut payload = json!({
            "model_id": self.model,
            "path": self.path,
        });
        if let Some(c) = &self.catalog_id {
            payload["catalog_id"] = json!(c);
        }
        if let Some(f) = &self.family {
            payload["family"] = json!(f);
        }
        if let Some(s) = self.input_size {
            payload["input_size"] = json!(s);
        }
        if let Some(n) = self.num_classes {
            payload["num_classes"] = json!(n);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadDetectionModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DetectUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DetectUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadDetectionModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DetectCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DetectCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listDetectionCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DetectListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DetectListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listDetectionModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DetectRunCmd {
    #[arg(long)]
    model: String,
    #[arg(long)]
    image: String,
    /// Score threshold in [0, 1]. Default 0.25.
    #[arg(long, default_value_t = 0.25)]
    score_threshold: f32,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DetectRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let image_b64 = read_b64(&self.image)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_detect",
                json!({
                    "model_id": self.model,
                    "image_base64": image_b64,
                    "score_threshold": self.score_threshold,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// transcribe
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum TranscribeCommand {
    /// List the curated audio ASR catalog (Moonshine, Whisper, Parakeet, Canary).
    Catalog(TranscribeCatalogCmd),
    /// List currently-loaded transcribers.
    List(TranscribeListCmd),
    /// Register an ASR bundle already on the node's filesystem.
    Load(TranscribeLoadCmd),
    /// Unregister a previously-loaded transcriber.
    Unload(TranscribeUnloadCmd),
    /// Run an ASR request on an audio file.
    Run(TranscribeRunCmd),
}

impl TranscribeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

/// Which paths are required depends on the family. Moonshine and Whisper take
/// `--tokenizer-path`; Parakeet and Canary take `--preprocessor-path` and
/// `--vocab-path` instead. The node reports what is missing.
#[derive(Debug, Parser)]
pub struct TranscribeLoadCmd {
    /// Model id to register the transcriber under.
    #[arg(long)]
    model: String,
    /// Path on the node to the encoder ONNX file.
    #[arg(long = "encoder-path")]
    encoder_path: String,
    /// Path on the node to the decoder ONNX file (the KV-cache merged decoder
    /// for Moonshine and Whisper, the joint network for Parakeet and Canary).
    #[arg(long = "decoder-path")]
    decoder_path: String,
    /// Catalog id (e.g. `parakeet-tdt-0.6b-v3`) to inherit the family, audio
    /// window and Whisper variant from, and to apply the licence gate.
    #[arg(long = "catalog-id")]
    catalog_id: Option<String>,
    /// Decoding pipeline, when not inheriting from the catalog: `moonshine`,
    /// `whisper`, `parakeet` or `canary`.
    #[arg(long)]
    family: Option<String>,
    /// Path on the node to `tokenizer.json` (Moonshine, Whisper).
    #[arg(long = "tokenizer-path")]
    tokenizer_path: Option<String>,
    /// Path on the node to the mel-spectrogram preprocessor ONNX file
    /// (Parakeet, Canary).
    #[arg(long = "preprocessor-path")]
    preprocessor_path: Option<String>,
    /// Path on the node to the vocabulary file (Parakeet, Canary).
    #[arg(long = "vocab-path")]
    vocab_path: Option<String>,
    /// Whisper checkpoint shape, when the family is `whisper` and no catalog id
    /// is given: `distil-en`, `distil-large-v3` or `large-v3-turbo`.
    #[arg(long = "whisper-variant")]
    whisper_variant: Option<String>,
    /// Longest audio window the encoder accepts, in seconds. Defaults to 30
    /// node-side when neither this nor a catalog id is given.
    #[arg(long = "max-audio-seconds")]
    max_audio_seconds: Option<u32>,
    /// Canary source language (default `en`).
    #[arg(long = "source-lang")]
    source_lang: Option<String>,
    /// Canary target language — set it different from the source to translate
    /// rather than transcribe (default `en`).
    #[arg(long = "target-lang")]
    target_lang: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.catalog_id.is_none() && self.family.is_none() {
            return Err(anyhow!("pass --catalog-id or --family"));
        }
        let mut payload = json!({
            "model_id": self.model,
            "encoder_path": self.encoder_path,
            "decoder_path": self.decoder_path,
        });
        if let Some(c) = &self.catalog_id {
            payload["catalog_id"] = json!(c);
        }
        if let Some(f) = &self.family {
            payload["family"] = json!(f);
        }
        if let Some(t) = &self.tokenizer_path {
            payload["tokenizer_path"] = json!(t);
        }
        if let Some(pp) = &self.preprocessor_path {
            payload["preprocessor_path"] = json!(pp);
        }
        if let Some(v) = &self.vocab_path {
            payload["vocab_path"] = json!(v);
        }
        if let Some(w) = &self.whisper_variant {
            payload["whisper_variant"] = json!(w);
        }
        if let Some(m) = self.max_audio_seconds {
            payload["max_audio_seconds"] = json!(m);
        }
        if let Some(s) = &self.source_lang {
            payload["source_lang"] = json!(s);
        }
        if let Some(t) = &self.target_lang {
            payload["target_lang"] = json!(t);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadAudioModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TranscribeUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_unloadAudioModel", json!({ "model_id": self.model }))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TranscribeCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listAudioCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TranscribeListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listAudioModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TranscribeRunCmd {
    #[arg(long)]
    model: String,
    /// Path to the input audio (WAV/MP3/FLAC).
    #[arg(long)]
    audio: String,
    /// Optional language ISO code (e.g. "en", "fr"). Auto-detect if omitted.
    #[arg(long)]
    language: Option<String>,
    /// Emit per-segment timestamps when supported.
    #[arg(long, default_value_t = false)]
    timestamps: bool,
    /// Optional decoding temperature (sampling-capable models).
    #[arg(long)]
    temperature: Option<f32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let audio_b64 = read_b64(&self.audio)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_transcribe",
                json!({
                    "model_id": self.model,
                    "audio_base64": audio_b64,
                    "language": self.language,
                    "timestamps": self.timestamps,
                    "temperature": self.temperature,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// embed-video
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedVideoCommand {
    /// List the curated video catalog (V-JEPA 2 ViT-L/H/g).
    Catalog(EmbedVideoCatalogCmd),
    /// List currently-loaded video encoders.
    List(EmbedVideoListCmd),
    /// Register a frame-pooling clip encoder over a loaded image encoder.
    Load(EmbedVideoLoadCmd),
    /// Unregister a previously-loaded video encoder.
    Unload(EmbedVideoUnloadCmd),
    /// Embed a video file into a clip-level vector.
    Run(EmbedVideoRunCmd),
}

impl EmbedVideoCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

/// The upstream V-JEPA 2 repos ship safetensors only, so there is no native
/// video graph to register. What the runtime serves is frame pooling over an
/// image tower: load one with `embed-image load`, then name it here.
#[derive(Debug, Parser)]
pub struct EmbedVideoLoadCmd {
    /// Model id to register the clip encoder under.
    #[arg(long)]
    model: String,
    /// Model id of an already-loaded image encoder to pool frames through.
    #[arg(long = "vision-model")]
    vision_model: String,
    /// Evenly-spaced frames sampled per clip. Defaults to 8 node-side.
    #[arg(long = "num-frames")]
    num_frames: Option<u32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedVideoLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut payload = json!({
            "model_id": self.model,
            "vision_model_id": self.vision_model,
        });
        if let Some(n) = self.num_frames {
            payload["num_frames"] = json!(n);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadVideoModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedVideoUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedVideoUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_unloadVideoModel", json!({ "model_id": self.model }))
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedVideoCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedVideoCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listVideoCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedVideoListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedVideoListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listVideoModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedVideoRunCmd {
    #[arg(long)]
    model: String,
    /// Path to a video file (any container ffmpeg can decode).
    #[arg(long)]
    video: String,
    #[arg(long, default_value_t = false)]
    normalize: bool,
    /// Keep every Nth decoded frame instead of spreading the samples evenly
    /// across the clip. Still capped at the encoder's frame budget.
    #[arg(long)]
    frame_stride: Option<u32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedVideoRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let video_b64 = read_b64(&self.video)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_videoEmbed",
                json!({
                    "model_id": self.model,
                    "video_base64": video_b64,
                    "normalize": self.normalize,
                    "frame_stride": self.frame_stride,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// forecast
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum ForecastCommand {
    /// List the curated forecast catalog (TimesFM 2.5, TiRex).
    Catalog(ForecastCatalogCmd),
    /// List currently-loaded forecasters on this node.
    List(ForecastListCmd),
    /// Register a forecast ONNX already present on the node's filesystem.
    Load(ForecastLoadCmd),
    /// Unregister a previously-loaded forecaster.
    Unload(ForecastUnloadCmd),
    /// Run a univariate forecast.
    Run(ForecastRunCmd),
}

impl ForecastCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ForecastCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ForecastCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listForecastCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ForecastListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ForecastListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listForecastModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

/// Unlike `embed-text load`, there is no fetch step here: the node registers
/// an ONNX file that already exists on its own filesystem, so `--path` is
/// resolved node-side.
#[derive(Debug, Parser)]
pub struct ForecastLoadCmd {
    /// Model id to register the forecaster under.
    #[arg(long)]
    model: String,
    /// Path on the node to the ONNX file.
    #[arg(long)]
    path: String,
    /// Catalog id (e.g. `timesfm-2.5-200m`, `tirex-35m`). Supplies
    /// context length, horizon, output tensor name and batch width from the
    /// catalog entry, and enforces its license tier.
    #[arg(long = "catalog-id")]
    catalog_id: Option<String>,
    /// Input context window length. Required without `--catalog-id`.
    #[arg(long = "context-length")]
    context_length: Option<u32>,
    /// Maximum single-pass forecast horizon. Required without `--catalog-id`.
    #[arg(long = "max-horizon")]
    max_horizon: Option<u32>,
    /// Prediction output tensor name, for multi-output graphs whose first
    /// output is not the forecast.
    #[arg(long = "output-name")]
    output_name: Option<String>,
    /// Fixed leading batch dimension the graph requires.
    #[arg(long = "batch-size")]
    batch_size: Option<u32>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ForecastLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.catalog_id.is_none()
            && (self.context_length.is_none() || self.max_horizon.is_none())
        {
            return Err(anyhow!(
                "pass --catalog-id, or both --context-length and --max-horizon"
            ));
        }
        let mut payload = json!({
            "model_id": self.model,
            "path": self.path,
        });
        if let Some(c) = &self.catalog_id {
            payload["catalog_id"] = json!(c);
        }
        if let Some(c) = self.context_length {
            payload["context_length"] = json!(c);
        }
        if let Some(h) = self.max_horizon {
            payload["max_horizon"] = json!(h);
        }
        if let Some(o) = &self.output_name {
            payload["output_name"] = json!(o);
        }
        if let Some(b) = self.batch_size {
            payload["batch_size"] = json!(b);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadForecastModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ForecastUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ForecastUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadForecastModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ForecastRunCmd {
    /// Model id of a loaded forecaster.
    #[arg(long)]
    model: String,
    /// Context series, most-recent-last. Comma-separated or repeated.
    #[arg(long = "context", value_delimiter = ',', num_args = 1..)]
    context: Vec<f64>,
    /// JSON file holding the context series as an array of numbers. Use this
    /// instead of `--context` for series too long for a command line.
    #[arg(long = "context-file", conflicts_with = "context")]
    context_file: Option<String>,
    /// Steps ahead to predict. Must not exceed the model's max horizon.
    #[arg(long)]
    horizon: u32,
    /// Quantile levels to return, e.g. `--quantile 0.1,0.5,0.9`.
    #[arg(long = "quantile", value_delimiter = ',', num_args = 1..)]
    quantiles: Vec<f64>,
    /// Sampling interval of the context series, in seconds.
    #[arg(long = "frequency-seconds")]
    frequency_seconds: Option<u64>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ForecastRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let history: Vec<f64> = match &self.context_file {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read context file {}", p))?;
                serde_json::from_str(&raw)
                    .with_context(|| "context file must be a JSON array of numbers")?
            }
            None => self.context.clone(),
        };
        if history.is_empty() {
            return Err(anyhow!("pass --context or --context-file"));
        }
        let mut payload = json!({
            "model_id": self.model,
            "history": history,
            "horizon": self.horizon,
            "quantiles": self.quantiles,
        });
        if let Some(f) = self.frequency_seconds {
            payload["frequency_seconds"] = json!(f);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_forecast", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// embed-image
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedImageCommand {
    /// List the curated vision-encoder catalog (CLIP, SigLIP2, DINOv3).
    Catalog(EmbedImageCatalogCmd),
    /// List currently-loaded image encoders on this node.
    List(EmbedImageListCmd),
    /// Register a vision-encoder ONNX already present on the node's filesystem.
    Load(EmbedImageLoadCmd),
    /// Unregister a previously-loaded image encoder.
    Unload(EmbedImageUnloadCmd),
    /// Embed a single image.
    Run(EmbedImageRunCmd),
    /// Cosine similarity between an image embedding and a text embedding.
    Similarity(EmbedImageSimilarityCmd),
}

impl EmbedImageCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Load(c) => c.execute().await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
            Self::Similarity(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct EmbedImageCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listVisionCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedImageListCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listVisionModels", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedImageLoadCmd {
    /// Model id to register the encoder under.
    #[arg(long)]
    model: String,
    /// Path on the node to the ONNX file.
    #[arg(long)]
    path: String,
    /// Catalog id (e.g. `clip-vit-b32`, `dinov3-vitb16`). Supplies input size,
    /// embedding dimension and normalization, and enforces the license tier.
    #[arg(long = "catalog-id")]
    catalog_id: Option<String>,
    /// Square input edge in pixels. Required without `--catalog-id`.
    #[arg(long = "input-size")]
    input_size: Option<u32>,
    /// Output embedding dimension. Required without `--catalog-id`.
    #[arg(long = "embedding-dim")]
    embedding_dim: Option<u32>,
    /// Pixel normalization: `clip`, `imagenet` or `siglip`.
    #[arg(long)]
    normalization: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageLoadCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.catalog_id.is_none() && (self.input_size.is_none() || self.embedding_dim.is_none())
        {
            return Err(anyhow!(
                "pass --catalog-id, or both --input-size and --embedding-dim"
            ));
        }
        let mut payload = json!({
            "model_id": self.model,
            "path": self.path,
        });
        if let Some(c) = &self.catalog_id {
            payload["catalog_id"] = json!(c);
        }
        if let Some(s) = self.input_size {
            payload["input_size"] = json!(s);
        }
        if let Some(d) = self.embedding_dim {
            payload["embedding_dim"] = json!(d);
        }
        if let Some(n) = &self.normalization {
            payload["normalization"] = json!(n);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_loadVisionModel", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedImageUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadVisionModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EmbedImageRunCmd {
    /// Model id of a loaded image encoder.
    #[arg(long)]
    model: String,
    /// Path to the input image (PNG/JPEG/WebP).
    #[arg(long)]
    image: String,
    /// L2-normalize the output (most retrieval pipelines want this).
    #[arg(long, default_value_t = false)]
    normalize: bool,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let image_b64 = read_b64(&self.image)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_imageEmbed",
                json!({
                    "model_id": self.model,
                    "image_base64": image_b64,
                    "normalize": self.normalize,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

/// Pure cosine similarity — the node loads no model for this. Both vectors
/// come from the caller: the image side from `embed-image run`, the text side
/// from whichever text tower matches the encoder family.
#[derive(Debug, Parser)]
pub struct EmbedImageSimilarityCmd {
    /// JSON file holding the image embedding as an array of numbers.
    #[arg(long = "image-embedding")]
    image_embedding: String,
    /// JSON file holding the text embedding as an array of numbers.
    #[arg(long = "text-embedding")]
    text_embedding: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl EmbedImageSimilarityCmd {
    pub async fn execute(&self) -> Result<()> {
        let read_vec = |p: &str| -> Result<Vec<f64>> {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read embedding file {}", p))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("{} must be a JSON array of numbers", p))
        };
        let img = read_vec(&self.image_embedding)?;
        let txt = read_vec(&self.text_embedding)?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_imageTextSimilarity",
                json!({
                    "image_embedding": img,
                    "text_embedding": txt,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}
