//! Multi-modal inference commands for the Tenzro CLI.
//!
//! Wraps the JSON-RPC surface added in Layer A:
//!   - `embed-text`  → `tenzro_textEmbed`
//!   - `segment`     → `tenzro_segment`
//!   - `detect`      → `tenzro_detect`
//!   - `transcribe`  → `tenzro_transcribe`
//!   - `embed-video` → `tenzro_videoEmbed`
//!
//! Each subcommand reads the input from a local path (image / audio / video),
//! base64-encodes it, and dispatches to the node. List/catalog subcommands
//! cover the discovery side.

use anyhow::{anyhow, Context, Result};
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
    /// Embed one or more strings.
    Run(EmbedTextRunCmd),
}

impl EmbedTextCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
        let res: serde_json::Value = rpc.call("tenzro_listTextEmbeddingCatalog", json!({})).await?;
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        let res: serde_json::Value = rpc.call("tenzro_listTextEmbeddingModels", json!({})).await?;
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
        Ok(())
    }
}

// ============================================================================
// segment
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum SegmentCommand {
    /// List the curated segmentation catalog (SAM 3, SAM 2, EdgeSAM, MobileSAM).
    Catalog(SegmentCatalogCmd),
    /// List currently-loaded segmenters.
    List(SegmentListCmd),
    /// Run a segmentation request given prompts.
    Run(SegmentRunCmd),
}

impl SegmentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
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
        let res: serde_json::Value = rpc.call("tenzro_listSegmentationCatalog", json!({})).await?;
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
    /// JSON file containing a list of SegmentPrompt values
    /// (`{"type":"point","x":0.5,"y":0.5,"is_foreground":true}`,
    ///  `{"type":"box","x0":..,"y0":..,"x1":..,"y1":..}`).
    #[arg(long)]
    prompts: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SegmentRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let prompts_str = std::fs::read_to_string(&self.prompts)
            .with_context(|| format!("failed to read prompts file {}", self.prompts))?;
        let prompts: serde_json::Value = serde_json::from_str(&prompts_str)
            .with_context(|| "prompts file is not valid JSON")?;
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
    /// Run object detection.
    Run(DetectRunCmd),
}

impl DetectCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
    /// Run an ASR request on an audio file.
    Run(TranscribeRunCmd),
}

impl TranscribeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
        Ok(())
    }
}

// ============================================================================
// embed-video
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedVideoCommand {
    /// List the curated video catalog (empty in wave 1 pending license clearance).
    Catalog(EmbedVideoCatalogCmd),
    /// List currently-loaded video encoders.
    List(EmbedVideoListCmd),
    /// Embed a video file into a clip-level vector.
    Run(EmbedVideoRunCmd),
}

impl EmbedVideoCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
        println!("{}", serde_json::to_string_pretty(&res)?);
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
    /// Optional frame stride override.
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
        println!("{}", serde_json::to_string_pretty(&res)?);
        let _ = output::print_success;
        Ok(())
    }
}
