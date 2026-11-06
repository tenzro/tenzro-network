//! Multi-modal inference commands for the Tenzro CLI.
//!
//! Wraps the JSON-RPC multi-modal surface:
//!   - `forecast`      → `tenzro_forecast`
//!   - `embed-text`    → `tenzro_textEmbed`: text, and pictures and video frames for a vision-language embedder (+ `load`/`unload` to serve a catalog encoder locally)
//!   - `embed-image`   → `tenzro_imageEmbed`, `tenzro_imageTextSimilarity`
//!   - `segment`       → `tenzro_segment`
//!   - `text-segment`  → `tenzro_textSegment`
//!   - `detect`        → `tenzro_detect`
//!   - `transcribe`    → `tenzro_transcribe`
//!   - `embed-video`   → `tenzro_videoEmbed`
//!   - `training`      → `tenzro_loadTrainingModel`, `tenzro_unloadTrainingModel`, `tenzro_trainRound`
//!
//! Each subcommand reads the input from a local path (image / audio / video),
//! base64-encodes it, and dispatches to the node. Catalog subcommands cover
//! the discovery side; `tenzro model list --loaded` lists every loaded model
//! of every type.
//!
//! `load` is the same for every modality: a catalog model id and an optional
//! visibility. The node fetches and verifies the files the signed catalog
//! entry names.

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

/// `load` for every catalog modality.
#[derive(Debug, Parser)]
pub struct CatalogLoadCmd {
    /// Catalog model id (e.g. `clip-vit-b32`, `qwen3-embedding-0.6b`, `rf-detr-base`).
    #[arg(long)]
    model: String,
    /// Visibility override: `public`, `gated` or `private`. Omit to follow the
    /// node's visibility.
    #[arg(long)]
    visibility: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CatalogLoadCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        let mut payload = json!({ "model_id": self.model });
        if let Some(v) = &self.visibility {
            payload["visibility"] = json!(v);
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call(method, payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

// ============================================================================
// embed-text
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedTextCommand {
    /// List the curated text-embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...).
    Catalog(EmbedTextCatalogCmd),
    /// Fetch a catalog encoder onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded text encoder.
    Unload(EmbedTextUnloadCmd),
    /// Embed one or more strings.
    Run(EmbedTextRunCmd),
}

impl EmbedTextCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadTextEmbeddingModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
pub struct EmbedTextRunCmd {
    /// Model id of a loaded text encoder.
    #[arg(long)]
    model: String,
    /// Input strings (repeat --input for multiple).
    #[arg(long = "input")]
    inputs: Vec<String>,
    /// A picture to embed (PNG, JPEG or WebP; repeat for multiple). Needs a
    /// vision-language embedder.
    #[arg(long = "image")]
    images: Vec<String>,
    /// A video to embed, as its frames in order, comma-separated (repeat for
    /// multiple videos). Needs a vision-language embedder.
    #[arg(long = "video-frames", value_delimiter = ',', num_args = 1..)]
    video_frames: Vec<String>,
    /// Text embedded together with the single --image or --video-frames
    /// item, as one input.
    #[arg(long)]
    media_text: Option<String>,
    /// Optional Matryoshka truncation dim (e.g. 512, 256, 128 for EmbeddingGemma).
    #[arg(long)]
    requested_dim: Option<u32>,
    /// L2-normalize the output (most retrieval pipelines want this).
    #[arg(long, default_value_t = false)]
    normalize: bool,
    /// Whether these inputs are a search query or documents being indexed.
    /// Drives the model's own instruction template (Qwen3-Embedding,
    /// EmbeddingGemma, ModernBERT-embed each prefix queries/documents
    /// differently, or not at all for BGE-M3) — see `embed-text catalog`
    /// for which family this model belongs to. Defaults to document.
    #[arg(long, value_enum, default_value_t = EmbedRoleArg::Document)]
    role: EmbedRoleArg,
    /// Task description for the query role (Qwen3-Embedding,
    /// EmbeddingGemma). Falls back to the model's own default task when
    /// omitted. Ignored for the document role and for families with no
    /// instruction template.
    #[arg(long)]
    task: Option<String>,
    /// Title for the document role (EmbeddingGemma only; ignored
    /// elsewhere).
    #[arg(long)]
    title: Option<String>,
    #[command(flatten)]
    routing: TaskRoutingArgs,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum EmbedRoleArg {
    Document,
    Query,
}

impl EmbedTextRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut inputs: Vec<serde_json::Value> = self.inputs.iter().map(|t| json!(t)).collect();
        let mut media: Vec<serde_json::Value> = Vec::new();
        for path in &self.images {
            media.push(json!({ "image": read_b64(path)? }));
        }
        if !self.video_frames.is_empty() {
            let frames = self
                .video_frames
                .iter()
                .map(|p| read_b64(p))
                .collect::<Result<Vec<_>>>()?;
            media.push(json!({ "video": frames }));
        }
        if let Some(text) = &self.media_text {
            match media.as_mut_slice() {
                [item] => item["text"] = json!(text),
                _ => {
                    return Err(anyhow!(
                        "--media-text needs exactly one --image or --video-frames item"
                    ));
                }
            }
        }
        inputs.extend(media);
        if inputs.is_empty() {
            return Err(anyhow!(
                "at least one --input, --image or --video-frames is required"
            ));
        }
        let role = match self.role {
            EmbedRoleArg::Document => json!({"role": "document", "title": self.title}),
            EmbedRoleArg::Query => json!({"role": "query", "task": self.task}),
        };
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_textEmbed",
                json!({
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
                    "model_id": self.model,
                    "inputs": inputs,
                    "requested_dim": self.requested_dim,
                    "normalize": self.normalize,
                    "role": role,
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
    /// Fetch a catalog segmenter onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded segmenter.
    Unload(SegmentUnloadCmd),
    /// Run a segmentation request given prompts.
    Run(SegmentRunCmd),
}

impl SegmentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadSegmentationModel").await,
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
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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
    /// Fetch a catalog SAM-3 bundle onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded text-promptable segmenter.
    Unload(TextSegmentUnloadCmd),
    /// Run an open-vocabulary text-prompt segmentation.
    Run(TextSegmentRunCmd),
}

impl TextSegmentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadTextSegmentationModel").await,
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
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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
    /// Fetch a catalog detector onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded detector.
    Unload(DetectUnloadCmd),
    /// Run object detection.
    Run(DetectRunCmd),
}

impl DetectCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadDetectionModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
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
pub struct DetectRunCmd {
    #[arg(long)]
    model: String,
    #[arg(long)]
    image: String,
    /// Score threshold in [0, 1]. Default 0.25.
    #[arg(long, default_value_t = 0.25)]
    score_threshold: f32,
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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
    /// Fetch a catalog ASR model onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded transcriber.
    Unload(TranscribeUnloadCmd),
    /// Run an ASR request on an audio file.
    Run(TranscribeRunCmd),
    /// Stream a 16-bit PCM WAV to the node in chunks and print partial and
    /// final transcripts as they arrive (`/tenzro/realtime/transcribe`).
    Stream(TranscribeStreamCmd),
}

impl TranscribeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadAudioModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
            Self::Stream(c) => c.execute().await,
        }
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
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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

#[derive(Debug, Parser)]
pub struct TranscribeStreamCmd {
    /// ASR model served by the node.
    #[arg(long)]
    model: String,
    /// 16-bit PCM WAV to stream (the first channel is sent).
    #[arg(long)]
    audio: String,
    /// Optional language ISO code (e.g. "en", "fr").
    #[arg(long)]
    language: Option<String>,
    /// Milliseconds of audio per chunk line.
    #[arg(long, default_value_t = 200)]
    chunk_ms: u32,
    /// Verification level for each final segment: none, receipt, optimistic or tee.
    #[arg(long)]
    verification: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TranscribeStreamCmd {
    pub async fn execute(&self) -> Result<()> {
        let wav =
            std::fs::read(&self.audio).with_context(|| format!("failed to read {}", self.audio))?;
        let (rate, samples) = wav_first_channel(&wav)
            .ok_or_else(|| anyhow!("{} is not a 16-bit PCM WAV", self.audio))?;
        let body = stt_stream_body(
            &json!({
                "model_id": self.model,
                "sample_rate": rate,
                "language": self.language,
                "verification": self.verification,
            }),
            &samples,
            (rate as usize * self.chunk_ms.max(10) as usize / 1000).max(1),
        );
        let rpc = RpcClient::new(&self.rpc);
        let mut response = rpc.post_route("/tenzro/realtime/transcribe", body).await?;
        let mut pending = String::new();
        let mut event = String::new();
        while let Some(chunk) = response.chunk().await? {
            pending.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(i) = pending.find('\n') {
                let line: String = pending.drain(..=i).collect();
                let line = line.trim_end();
                if let Some(name) = line.strip_prefix("event:") {
                    event = name.trim().to_string();
                } else if let Some(data) = line.strip_prefix("data:") {
                    let data: serde_json::Value =
                        serde_json::from_str(data.trim()).unwrap_or(json!(data.trim()));
                    match event.as_str() {
                        "partial" => eprintln!("... {}", data["text"].as_str().unwrap_or("")),
                        "error" => {
                            return Err(anyhow!(
                                "{}",
                                data["message"].as_str().unwrap_or("stream failed")
                            ));
                        }
                        _ => output::print_json(&json!({ "event": event, "data": data }))?,
                    }
                }
            }
        }
        Ok(())
    }
}

/// Sample rate and first-channel samples of a 16-bit PCM WAV.
fn wav_first_channel(wav: &[u8]) -> Option<(u32, Vec<i16>)> {
    if wav.len() < 12 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return None;
    }
    let mut at = 12;
    let mut format = None;
    while at + 8 <= wav.len() {
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into().ok()?) as usize;
        let body = wav.get(at + 8..(at + 8 + len).min(wav.len()))?;
        match &wav[at..at + 4] {
            b"fmt " if body.len() >= 16 => {
                let channels = u16::from_le_bytes([body[2], body[3]]) as usize;
                let rate = u32::from_le_bytes(body[4..8].try_into().ok()?);
                if u16::from_le_bytes([body[0], body[1]]) != 1
                    || u16::from_le_bytes([body[14], body[15]]) != 16
                    || channels == 0
                {
                    return None;
                }
                format = Some((rate, channels));
            }
            b"data" => {
                let (rate, channels) = format?;
                let samples = body
                    .chunks_exact(2 * channels)
                    .map(|f| i16::from_le_bytes([f[0], f[1]]))
                    .collect();
                return Some((rate, samples));
            }
            _ => {}
        }
        at += 8 + len + (len & 1);
    }
    None
}

/// The newline-delimited body of a streamed transcription: the opening line,
/// then one `pcm_s16le_base64` line per `chunk` samples.
fn stt_stream_body(open: &serde_json::Value, samples: &[i16], chunk: usize) -> Vec<u8> {
    let mut body = serde_json::to_vec(open).unwrap_or_default();
    body.push(b'\n');
    for c in samples.chunks(chunk.max(1)) {
        let bytes: Vec<u8> = c.iter().flat_map(|s| s.to_le_bytes()).collect();
        body.extend_from_slice(
            json!({ "pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode(bytes) })
                .to_string()
                .as_bytes(),
        );
        body.push(b'\n');
    }
    body
}

// ============================================================================
// embed-video
// ============================================================================

#[derive(Debug, Subcommand)]
pub enum EmbedVideoCommand {
    /// List the curated video catalog (V-JEPA 2 ViT-L/H/g).
    Catalog(EmbedVideoCatalogCmd),
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
    /// Visibility override: `public`, `gated` or `private`. Omit to follow the
    /// node's visibility.
    #[arg(long)]
    visibility: Option<String>,
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
        if let Some(v) = &self.visibility {
            payload["visibility"] = json!(v);
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
pub struct EmbedVideoRunCmd {
    #[arg(long)]
    model: String,
    /// Path to a video file (MP4, WebM or MKV).
    #[arg(long)]
    video: String,
    #[arg(long, default_value_t = false)]
    normalize: bool,
    /// Keep every Nth decoded frame instead of spreading the samples evenly
    /// across the clip. Still capped at the encoder's frame budget.
    #[arg(long)]
    frame_stride: Option<u32>,
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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
    /// List the curated forecast catalog (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0).
    Catalog(ForecastCatalogCmd),
    /// Fetch a catalog forecaster onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unregister a previously-loaded forecaster.
    Unload(ForecastUnloadCmd),
    /// Run a univariate forecast.
    Run(ForecastRunCmd),
}

impl ForecastCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadForecastModel").await,
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
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
        payload["verification"] = json!(self.routing.verification);
        payload["provider"] = json!(self.routing.provider);
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
    /// Fetch a catalog image encoder onto this node and serve it.
    Load(CatalogLoadCmd),
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
            Self::Load(c) => c.execute("tenzro_loadVisionModel").await,
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
    #[command(flatten)]
    routing: TaskRoutingArgs,
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
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
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

/// Rerankers: cross-encoders that score documents against a query.
#[derive(Debug, Subcommand)]
pub enum RerankCommand {
    /// List the reranker catalog.
    Catalog(RerankCatalogCmd),
    /// Fetch a catalog reranker onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unload a reranker.
    Unload(RerankUnloadCmd),
    /// Score documents against a query, best first.
    Run(RerankRunCmd),
}

impl RerankCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadRerankModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct RerankCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl RerankCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listRerankCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RerankUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl RerankUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadRerankModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RerankRunCmd {
    #[arg(long)]
    model: String,
    /// The query.
    #[arg(long)]
    query: Option<String>,
    /// A picture in the query (PNG, JPEG or WebP), read with the query text.
    /// Needs a vision-language reranker.
    #[arg(long)]
    query_image: Option<String>,
    /// A video in the query, as its frames in order, comma-separated.
    /// Needs a vision-language reranker.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    query_video_frames: Vec<String>,
    /// A text document; repeat for each.
    #[arg(long = "document")]
    documents: Vec<String>,
    /// A picture document (PNG, JPEG or WebP); repeat for each.
    #[arg(long = "document-image")]
    document_images: Vec<String>,
    /// A video document, as its frames in order, comma-separated; repeat
    /// for each video.
    #[arg(long = "document-video-frames")]
    document_videos: Vec<String>,
    /// Return only the best N.
    #[arg(long)]
    top_n: Option<u64>,
    /// Include each document as given in the answer.
    #[arg(long)]
    return_documents: bool,
    #[command(flatten)]
    routing: TaskRoutingArgs,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl RerankRunCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut query = serde_json::Map::new();
        if let Some(text) = &self.query {
            query.insert("text".into(), json!(text));
        }
        if let Some(path) = &self.query_image {
            query.insert("image".into(), json!(read_b64(path)?));
        }
        if !self.query_video_frames.is_empty() {
            let frames = self
                .query_video_frames
                .iter()
                .map(|p| read_b64(p))
                .collect::<Result<Vec<_>>>()?;
            query.insert("video".into(), json!(frames));
        }
        if query.is_empty() {
            return Err(anyhow!(
                "a query needs --query, --query-image or --query-video-frames"
            ));
        }
        let mut documents: Vec<serde_json::Value> =
            self.documents.iter().map(|t| json!(t)).collect();
        for path in &self.document_images {
            documents.push(json!({ "image": read_b64(path)? }));
        }
        for video in &self.document_videos {
            let frames = video.split(',').map(read_b64).collect::<Result<Vec<_>>>()?;
            documents.push(json!({ "video": frames }));
        }
        if documents.is_empty() {
            return Err(anyhow!(
                "at least one --document, --document-image or --document-video-frames is required"
            ));
        }
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_rerank",
                json!({
                    "model_id": self.model,
                    "query": serde_json::Value::Object(query),
                    "documents": documents,
                    "top_n": self.top_n,
                    "return_documents": self.return_documents,
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

/// Decision models: typed questions (yes/no, choice, score) answered about a
/// text in one forward pass.
#[derive(Debug, Subcommand)]
pub enum DecideCommand {
    /// List the decision-model catalog.
    Catalog(DecideCatalogCmd),
    /// Fetch a catalog decision model onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unload a decision model.
    Unload(DecideUnloadCmd),
    /// Answer questions about a text.
    Run(DecideRunCmd),
}

impl DecideCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadDecisionModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Run(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct DecideCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DecideCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listDecisionCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DecideUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DecideUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadDecisionModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DecideRunCmd {
    #[arg(long)]
    model: String,
    /// The text to decide about.
    #[arg(long, conflicts_with = "state_file")]
    state: Option<String>,
    /// A file holding the state: text, or JSON (an email, a ticket, a record).
    #[arg(long)]
    state_file: Option<String>,
    /// A yes/no question as `id=instructions`; repeat for each.
    #[arg(long = "yes-no")]
    yes_no: Vec<String>,
    /// Questions as JSON: an array of `{ id, type, instructions, criteria }`
    /// (see the MCP `decide` tool), or `@path` to read it from a file.
    #[arg(long)]
    questions: Option<String>,
    #[command(flatten)]
    routing: TaskRoutingArgs,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl DecideRunCmd {
    /// The questions of the request, from `--questions` and `--yes-no`.
    fn questions(&self) -> Result<Vec<serde_json::Value>> {
        let mut out: Vec<serde_json::Value> = Vec::new();
        if let Some(q) = &self.questions {
            let text = match q.strip_prefix('@') {
                Some(path) => std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read questions file {path}"))?,
                None => q.clone(),
            };
            let parsed: serde_json::Value =
                serde_json::from_str(&text).with_context(|| "questions are not valid JSON")?;
            match parsed {
                serde_json::Value::Array(items) => out.extend(items),
                _ => return Err(anyhow!("--questions is a JSON array of questions")),
            }
        }
        for spec in &self.yes_no {
            let (id, instructions) = spec
                .split_once('=')
                .ok_or_else(|| anyhow!("--yes-no is `id=instructions`, got `{spec}`"))?;
            out.push(json!({ "id": id, "type": "noul", "instructions": instructions }));
        }
        if out.is_empty() {
            return Err(anyhow!("at least one --yes-no or --questions is required"));
        }
        Ok(out)
    }

    pub async fn execute(&self) -> Result<()> {
        let state = match (&self.state, &self.state_file) {
            (Some(text), None) => json!(text),
            (None, Some(path)) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read state file {path}"))?;
                // JSON in the file is passed as JSON; anything else is text.
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => v,
                    _ => json!(text),
                }
            }
            _ => return Err(anyhow!("give the text with --state or --state-file")),
        };
        let questions = self.questions()?;
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_decide",
                json!({
                    "model_id": self.model,
                    "state": state,
                    "questions": questions,
                    "verification": self.routing.verification,
                    "provider": self.routing.provider,
                }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

/// Speech synthesis on the Praecise engine.
#[derive(Debug, Subcommand)]
pub enum SpeechCommand {
    /// List the speech model catalog.
    Catalog(SpeechCatalogCmd),
    /// Fetch a catalog speech model onto this node and serve it.
    Load(CatalogLoadCmd),
    /// Unload a speech model.
    Unload(SpeechUnloadCmd),
    /// Speak text into a WAV file.
    Speak(SpeechSpeakCmd),
}

impl SpeechCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Load(c) => c.execute("tenzro_loadSpeechModel").await,
            Self::Unload(c) => c.execute().await,
            Self::Speak(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct SpeechCatalogCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SpeechCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_listTtsCatalog", json!({})).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SpeechUnloadCmd {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SpeechUnloadCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc
            .call(
                "tenzro_unloadSpeechModel",
                json!({ "model_id": self.model }),
            )
            .await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SpeechSpeakCmd {
    #[arg(long)]
    model: String,
    /// The text to speak.
    #[arg(long)]
    text: String,
    /// Language code (en, zh, ...).
    #[arg(long)]
    language: Option<String>,
    /// Reference audio of the voice (wav, mp3, flac); the node must allow cloning.
    #[arg(long)]
    voice_reference: Option<std::path::PathBuf>,
    /// Seed; the same seed, text and voice give the same audio.
    #[arg(long)]
    seed: Option<u32>,
    /// Where to write the WAV.
    #[arg(long)]
    out: std::path::PathBuf,
    /// A signed channel voucher (`tenzro escrow voucher --out`) the call's
    /// metered cost is charged against
    #[arg(long)]
    channel_voucher: Option<std::path::PathBuf>,
    #[command(flatten)]
    routing: TaskRoutingArgs,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl SpeechSpeakCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let ref_audio = match &self.voice_reference {
            Some(p) => Some(
                base64::engine::general_purpose::STANDARD
                    .encode(std::fs::read(p).with_context(|| format!("read {}", p.display()))?),
            ),
            None => None,
        };
        let mut req = json!({
            "model_id": self.model,
            "input": self.text,
            "language": self.language,
            "ref_audio": ref_audio,
            "seed": self.seed,
            "verification": self.routing.verification,
            "provider": self.routing.provider,
        });
        if let Some(p) = &self.channel_voucher {
            req["channel_voucher"] = serde_json::from_slice(
                &std::fs::read(p).with_context(|| format!("read {}", p.display()))?,
            )
            .with_context(|| format!("parse {}", p.display()))?;
        }
        let mut res: serde_json::Value = rpc.call("tenzro_speak", req).await?;
        let audio = res
            .get("audio_base64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("the node returned no audio"))?;
        let wav = base64::engine::general_purpose::STANDARD
            .decode(audio)
            .context("audio is not base64")?;
        std::fs::write(&self.out, wav).with_context(|| format!("write {}", self.out.display()))?;
        if let Some(obj) = res.as_object_mut() {
            obj.remove("audio_base64");
            obj.insert("written".into(), json!(self.out.display().to_string()));
        }
        output::print_json(&res)?;
        Ok(())
    }
}

/// How a modality call is verified and which provider serves it.
#[derive(Debug, clap::Args)]
pub struct TaskRoutingArgs {
    /// Verification level: none, receipt, optimistic or tee. A call for a
    /// model the node does not serve is forwarded to a provider offering it,
    /// and an optimistic answer may be re-executed on another provider.
    #[arg(long)]
    verification: Option<String>,
    /// Serve on this provider's offer (its payee address, hex).
    #[arg(long)]
    provider: Option<String>,
}

// ============================================================================
// training
// ============================================================================

/// LoRA training on this node's CUDA device. Operator only.
#[derive(Debug, Subcommand)]
pub enum TrainingCommand {
    /// Load a downloaded catalog language model for training.
    Load(TrainingModelCmd),
    /// Unload a model loaded for training.
    Unload(TrainingModelCmd),
    /// Run one supervised LoRA round.
    Round(TrainingRoundCmd),
}

impl TrainingCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Load(c) => c.execute("tenzro_loadTrainingModel").await,
            Self::Unload(c) => c.execute("tenzro_unloadTrainingModel").await,
            Self::Round(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct TrainingModelCmd {
    /// Catalog model id, downloaded with `tenzro model download`.
    #[arg(long)]
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TrainingModelCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call(method, json!({ "model_id": self.model })).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TrainingRoundCmd {
    /// Model id loaded for training.
    #[arg(long)]
    model: String,
    /// JSON file holding the round: `recipe`, `records` (`[{ prompt,
    /// completion }]`), `sample_seed`, `steps`, `adapter_seed`, and
    /// optionally `start` (`{ state_uri, start_root, steps_taken }`) and
    /// `verification`.
    #[arg(long)]
    round: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl TrainingRoundCmd {
    pub async fn execute(&self) -> Result<()> {
        let raw = std::fs::read_to_string(&self.round)
            .with_context(|| format!("failed to read round file {}", self.round))?;
        let mut payload: serde_json::Value =
            serde_json::from_str(&raw).with_context(|| "round file must be a JSON object")?;
        let obj = payload
            .as_object_mut()
            .ok_or_else(|| anyhow!("round file must be a JSON object"))?;
        obj.insert("model_id".to_string(), json!(self.model));
        let rpc = RpcClient::new(&self.rpc);
        let res: serde_json::Value = rpc.call("tenzro_trainRound", payload).await?;
        output::print_json(&res)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_body_is_an_opening_line_then_chunks() {
        let mut wav = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
        wav.extend_from_slice(&16u32.to_le_bytes());
        for v in [1u16, 2] {
            wav.extend_from_slice(&v.to_le_bytes());
        }
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&32000u32.to_le_bytes());
        wav.extend_from_slice(&4u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&12u32.to_le_bytes());
        for s in [1i16, 9, -2, 9, 3, 9] {
            wav.extend_from_slice(&s.to_le_bytes());
        }
        let (rate, samples) = wav_first_channel(&wav).unwrap();
        assert_eq!((rate, samples.clone()), (8000, vec![1, -2, 3]));
        let body = stt_stream_body(&json!({"model_id": "m"}), &samples, 2);
        let lines: Vec<serde_json::Value> = body
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["model_id"], "m");
        assert!(lines[1]["pcm_s16le_base64"].is_string());
    }
}
