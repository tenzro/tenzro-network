//! Video encoder runtime backed by ONNX Runtime.
//!
//! The video catalog (`get_video_catalog`) advertises the V-JEPA 2
//! family (Meta AI, 2025): ViT-L and ViT-H are MIT, ViT-g is
//! Apache-2.0 — all three are `LicenseTier::Permissive`. They describe
//! reference clip encoders rather than loadable graphs, because the
//! upstream `facebook/vjepa2-*` repos ship `safetensors` only.
//! VideoMAE v1/v2 stay off the catalog (CC-BY-NC); V-JEPA 2.1 stays
//! off (CC-BY-NC-ND).
//!
//! What `load_video_model` registers instead is the
//! `VisionFallbackVideoEncoder` below, which turns any already-loaded
//! `ImageEncoder` (CLIP / SigLIP2 / DINOv3 / ViT) into a video encoder by:
//!
//! 1. Extracting `num_frames` frames from the input video via the system
//!    `ffmpeg` binary (PNG output to a tempdir) — evenly spaced across the
//!    clip, or at a fixed stride when the request carries `frame_stride`.
//! 2. Embedding each frame through the underlying image encoder.
//! 3. Mean-pooling the per-frame embeddings.
//! 4. Optionally L2-normalizing the resulting vector.
//!
//! This is the same pattern that CLIP4Clip and similar zero-shot
//! video-retrieval systems use, and it produces sensible embeddings for
//! cross-modal search without requiring a video-native encoder.
//!
//! # System dependency
//!
//! The fallback encoder shells out to `ffmpeg` (CLI), not `libavcodec`.
//! This keeps the Rust build slim — no `ffmpeg-sys-next` linkage — and
//! matches what containerized deployments already do for thumbnailing.
//! The Dockerfile must include `ffmpeg`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::vision_runtime::{ImageEmbedConfig, ImageEncoder};

/// Configuration for a video-embedding request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoEmbedConfig {
    /// L2-normalize the output embedding.
    #[serde(default)]
    pub normalize: bool,
    /// Keep every `frame_stride`-th decoded frame instead of spreading the
    /// samples evenly across the clip. Still capped at the encoder's
    /// `num_frames`, so a stride tight enough to outrun the cap yields a
    /// window from the start of the clip rather than a survey of all of it.
    #[serde(default)]
    pub frame_stride: Option<u32>,
}

/// Result of a video-embedding call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoEmbedResult {
    pub embedding: Vec<f32>,
    pub dim: usize,
    /// Number of frames actually consumed (after sampling).
    pub frames_consumed: u32,
    /// Duration of the source clip in milliseconds, or 0 when the container
    /// carries no recoverable duration. Video is billed per second of source
    /// as well as per frame embedded, so a caller who uploads an hour-long clip
    /// and samples eight frames from it still pays for the hour of decode.
    pub video_ms: u64,
    pub generation_time_ms: u64,
}

/// Trait for video encoders.
pub trait VideoEncoder: Send + Sync {
    fn embed(&self, video_bytes: &[u8], config: &VideoEmbedConfig) -> Result<VideoEmbedResult>;
    fn frame_size(&self) -> u32;
    fn num_frames(&self) -> u32;
    fn embedding_dim(&self) -> usize;
}

/// Stub video encoder for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubVideoEncoder;

impl StubVideoEncoder {
    pub fn from_onnx(_path: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl VideoEncoder for StubVideoEncoder {
    fn embed(&self, _video_bytes: &[u8], _config: &VideoEmbedConfig) -> Result<VideoEmbedResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn frame_size(&self) -> u32 {
        0
    }
    fn num_frames(&self) -> u32 {
        0
    }
    fn embedding_dim(&self) -> usize {
        0
    }
}

/// Wraps any `ImageEncoder` into a `VideoEncoder` by extracting frames
/// with `ffmpeg` and mean-pooling per-frame embeddings.
///
/// The encoder is owned by `Arc` so the same image model can power both
/// `VisionRuntime::embed` and one or more `VideoRuntime::embed` entries
/// without duplication.
pub struct VisionFallbackVideoEncoder {
    image: Arc<dyn ImageEncoder>,
    num_frames: u32,
}

impl VisionFallbackVideoEncoder {
    /// Build a video encoder backed by an image encoder. `num_frames` is
    /// how many evenly-spaced frames to sample from the input clip — the
    /// canonical CLIP4Clip-style setting is 8 for short clips, 16–32 for
    /// longer ones.
    pub fn new(image: Arc<dyn ImageEncoder>, num_frames: u32) -> Self {
        let num_frames = num_frames.max(1);
        Self { image, num_frames }
    }

    /// Probe the duration of `path` (in seconds) using `ffprobe`. Returns
    /// `None` when the duration cannot be determined; the embed loop
    /// falls back to the `select=eq(...)` filter in that case.
    fn probe_duration(path: &Path) -> Option<f64> {
        let output = std::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
            ])
            .arg(path)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let s = String::from_utf8(output.stdout).ok()?;
        s.trim().parse::<f64>().ok()
    }

    /// Collect frames from every `stride`-th decoded frame, capped at `n`.
    /// `-fps_mode passthrough` keeps ffmpeg from resampling around the
    /// `select` filter's gaps, which would otherwise reintroduce the frames
    /// the stride just skipped.
    fn extract_strided(
        &self,
        video_path: &Path,
        out_dir: &Path,
        stride: u32,
        n: usize,
    ) -> Result<Vec<std::path::PathBuf>> {
        let pattern = out_dir.join("frame_%03d.png");
        let filter = format!("select=not(mod(n\\,{}))", stride);
        let status = std::process::Command::new("ffmpeg")
            .args(["-loglevel", "error", "-y", "-i"])
            .arg(video_path)
            .arg("-vf")
            .arg(&filter)
            .args(["-fps_mode", "passthrough"])
            .args(["-frames:v"])
            .arg(format!("{}", n))
            .arg(&pattern)
            .status()
            .map_err(|e| {
                ModelError::ProviderNotAvailable(format!(
                    "ffmpeg invocation failed: {} (is ffmpeg installed?)",
                    e
                ))
            })?;
        if !status.success() {
            return Err(ModelError::InferenceError(format!(
                "ffmpeg exited with status {} extracting every {}th frame",
                status, stride
            )));
        }
        Ok(Self::collect_sequence(out_dir, n))
    }

    /// Gather `frame_001.png`..`frame_{n:03}.png` from `out_dir`, stopping at
    /// the first gap — ffmpeg writes the sequence contiguously, so a gap means
    /// it ran out of frames to write.
    fn collect_sequence(out_dir: &Path, n: usize) -> Vec<std::path::PathBuf> {
        let mut paths = Vec::new();
        for i in 1..=n {
            let p = out_dir.join(format!("frame_{:03}.png", i));
            if p.exists() {
                paths.push(p);
            } else {
                break;
            }
        }
        paths
    }

    /// Extract up to `num_frames` PNG frames into `out_dir`, written as
    /// `frame_001.png`, `frame_002.png`, etc. Returns the file paths in
    /// extraction order, together with the probed clip duration in seconds
    /// when the container carries one — the caller bills against it, so the
    /// probe result has to travel out rather than only steering the
    /// extraction strategy.
    fn extract_frames(
        &self,
        video_path: &Path,
        out_dir: &Path,
        config: &VideoEmbedConfig,
    ) -> Result<(Vec<std::path::PathBuf>, Option<f64>)> {
        let n = self.num_frames as usize;
        let pattern = out_dir.join("frame_%03d.png");

        // A caller-supplied stride replaces the even-spacing survey: it asks
        // for a specific temporal sampling rate rather than a fixed budget
        // spread over however long the clip happens to be. Duration is still
        // probed, because billing depends on it either way.
        if let Some(stride) = config.frame_stride.filter(|s| *s > 0) {
            let duration = Self::probe_duration(video_path);
            let paths = self.extract_strided(video_path, out_dir, stride, n)?;
            if paths.is_empty() {
                return Err(ModelError::InferenceError(format!(
                    "ffmpeg produced no frames at stride {}",
                    stride
                )));
            }
            return Ok((paths, duration));
        }

        // Strategy: probe duration; if known, extract exactly `n` frames at
        // evenly-spaced timestamps using `select='eq(n,...)'` filter would
        // require frame counts (not always reliable on VFR sources). The
        // robust route is to seek to each timestamp and grab one frame
        // with `-frames:v 1`. We do that in a single ffmpeg invocation
        // using a comma-separated `between(t,...)` expression isn't ideal
        // either; the most portable method is to call ffmpeg N times with
        // `-ss <ts> -i video -frames:v 1 frame_NNN.png`.
        if let Some(duration) = Self::probe_duration(video_path) {
            if duration <= 0.0 {
                return Err(ModelError::InvalidModel(format!(
                    "ffprobe reported non-positive duration {} for video",
                    duration
                )));
            }
            let mut paths = Vec::with_capacity(n);
            for i in 0..n {
                // Sample at the midpoint of each of N equal segments so we
                // never seek to t=0 (often a black frame) or t=duration
                // (past EOF).
                let ts = duration * ((i as f64) + 0.5) / (n as f64);
                let out_path = out_dir.join(format!("frame_{:03}.png", i + 1));
                let status = std::process::Command::new("ffmpeg")
                    .args(["-loglevel", "error", "-y", "-ss"])
                    .arg(format!("{:.3}", ts))
                    .arg("-i")
                    .arg(video_path)
                    .args(["-frames:v", "1"])
                    .arg(&out_path)
                    .status()
                    .map_err(|e| {
                        ModelError::ProviderNotAvailable(format!(
                            "ffmpeg invocation failed: {} (is ffmpeg installed?)",
                            e
                        ))
                    })?;
                if !status.success() {
                    return Err(ModelError::InferenceError(format!(
                        "ffmpeg exited with status {} extracting frame {} at t={:.3}s",
                        status, i, ts
                    )));
                }
                if out_path.exists() {
                    paths.push(out_path);
                }
            }
            if paths.is_empty() {
                return Err(ModelError::InferenceError(
                    "ffmpeg produced no frames despite reported success".into(),
                ));
            }
            Ok((paths, Some(duration)))
        } else {
            // Fallback: use ffmpeg's `select` filter to grab N evenly-spaced
            // frames without knowing the duration up front. This decodes
            // the entire video, which is slower but works for streams
            // where ffprobe can't recover duration.
            let status = std::process::Command::new("ffmpeg")
                .args(["-loglevel", "error", "-y", "-i"])
                .arg(video_path)
                .args(["-vf", "thumbnail,fps=1"])
                .args(["-frames:v"])
                .arg(format!("{}", n))
                .arg(&pattern)
                .status()
                .map_err(|e| {
                    ModelError::ProviderNotAvailable(format!(
                        "ffmpeg invocation failed: {} (is ffmpeg installed?)",
                        e
                    ))
                })?;
            if !status.success() {
                return Err(ModelError::InferenceError(format!(
                    "ffmpeg exited with status {} during fallback frame extraction",
                    status
                )));
            }
            // Collect whatever ffmpeg actually produced.
            let paths = Self::collect_sequence(out_dir, n);
            if paths.is_empty() {
                return Err(ModelError::InferenceError(
                    "ffmpeg fallback produced no frames".into(),
                ));
            }
            Ok((paths, None))
        }
    }
}

impl VideoEncoder for VisionFallbackVideoEncoder {
    fn embed(&self, video_bytes: &[u8], config: &VideoEmbedConfig) -> Result<VideoEmbedResult> {
        if video_bytes.is_empty() {
            return Err(ModelError::InvalidModel("video bytes are empty".into()));
        }

        let start = std::time::Instant::now();

        // Write the input bytes to a temporary file so ffmpeg can demux it.
        // We use `tempfile::NamedTempFile` here to get an automatically
        // cleaned-up path. The image encoder is run after the file is
        // released, so we hold the handle across the ffmpeg call only.
        let tmpdir = tempfile::tempdir()
            .map_err(|e| ModelError::InferenceError(format!("tempdir: {}", e)))?;
        let video_path = tmpdir.path().join("video.bin");
        std::fs::write(&video_path, video_bytes)
            .map_err(|e| ModelError::InferenceError(format!("write video: {}", e)))?;

        let (frame_paths, duration_secs) =
            self.extract_frames(&video_path, tmpdir.path(), config)?;

        // Embed each frame. We accumulate sums in f64 to avoid f32
        // precision loss when many frames are averaged.
        let dim = self.image.embedding_dim();
        let mut sum = vec![0.0_f64; dim];
        let frame_cfg = ImageEmbedConfig {
            // Per-frame embeddings are accumulated as raw vectors;
            // normalization happens once at the end on the pooled vector.
            normalize: false,
        };
        let mut consumed: u32 = 0;
        for path in &frame_paths {
            let bytes = std::fs::read(path)
                .map_err(|e| ModelError::InferenceError(format!("read frame: {}", e)))?;
            let r = self.image.embed(&bytes, &frame_cfg)?;
            if r.embedding.len() != dim {
                return Err(ModelError::InferenceError(format!(
                    "image encoder returned dim {}, expected {}",
                    r.embedding.len(),
                    dim
                )));
            }
            for (i, v) in r.embedding.iter().enumerate() {
                sum[i] += *v as f64;
            }
            consumed += 1;
        }
        if consumed == 0 {
            return Err(ModelError::InferenceError(
                "video encoder produced zero usable frames".into(),
            ));
        }

        let mut embedding: Vec<f32> = sum.iter().map(|v| (*v / consumed as f64) as f32).collect();

        if config.normalize {
            let norm: f32 = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
            if norm > 0.0 {
                for v in embedding.iter_mut() {
                    *v /= norm;
                }
            }
        }

        let dim = embedding.len();
        Ok(VideoEmbedResult {
            embedding,
            dim,
            frames_consumed: consumed,
            // A stream ffprobe cannot measure bills on frames alone rather than
            // guessing at a duration from the sampled frame count.
            video_ms: duration_secs
                .filter(|d| *d > 0.0)
                .map(|d| (d * 1000.0).round() as u64)
                .unwrap_or(0),
            generation_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn frame_size(&self) -> u32 {
        self.image.input_size()
    }

    fn num_frames(&self) -> u32 {
        self.num_frames
    }

    fn embedding_dim(&self) -> usize {
        self.image.embedding_dim()
    }
}

/// Runtime that owns multiple loaded video encoders.
pub struct VideoRuntime {
    models: dashmap::DashMap<String, Arc<dyn VideoEncoder>>,
}

impl Default for VideoRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn VideoEncoder>) {
        self.models.insert(model_id.into(), model);
    }

    /// Convenience: register a vision-fallback video encoder by wrapping
    /// an existing image encoder.
    pub fn register_vision_fallback(
        &self,
        model_id: impl Into<String>,
        image: Arc<dyn ImageEncoder>,
        num_frames: u32,
    ) {
        let enc = VisionFallbackVideoEncoder::new(image, num_frames);
        self.models
            .insert(model_id.into(), Arc::new(enc) as Arc<dyn VideoEncoder>);
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id).is_some()
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    pub async fn embed(
        &self,
        model_id: &str,
        video_bytes: Vec<u8>,
        config: VideoEmbedConfig,
    ) -> Result<VideoEmbedResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.embed(&video_bytes, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock image encoder that returns a fixed embedding regardless of input.
    /// Lets us exercise the video runtime's pooling and dispatch logic
    /// without a real ONNX model.
    struct ConstantImage {
        dim: usize,
        value: f32,
    }
    impl ImageEncoder for ConstantImage {
        fn embed(
            &self,
            _bytes: &[u8],
            _cfg: &ImageEmbedConfig,
        ) -> Result<crate::vision_runtime::ImageEmbedResult> {
            Ok(crate::vision_runtime::ImageEmbedResult {
                embedding: vec![self.value; self.dim],
                dim: self.dim,
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            224
        }
        fn embedding_dim(&self) -> usize {
            self.dim
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = VideoRuntime::new();
        assert!(rt.loaded_models().is_empty());
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = VideoRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_video_encoder_returns_provider_not_available() {
        let stub = StubVideoEncoder;
        let res = stub.embed(&[], &VideoEmbedConfig::default());
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn embed_on_unknown_model_returns_not_found() {
        let rt = VideoRuntime::new();
        let res = rt
            .embed("missing", vec![], VideoEmbedConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[test]
    fn vision_fallback_carries_underlying_dims() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage {
            dim: 768,
            value: 0.5,
        });
        let v = VisionFallbackVideoEncoder::new(img, 8);
        assert_eq!(v.embedding_dim(), 768);
        assert_eq!(v.frame_size(), 224);
        assert_eq!(v.num_frames(), 8);
    }

    #[test]
    fn vision_fallback_rejects_empty_video() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage { dim: 8, value: 0.1 });
        let v = VisionFallbackVideoEncoder::new(img, 4);
        let r = v.embed(&[], &VideoEmbedConfig::default());
        assert!(matches!(r, Err(ModelError::InvalidModel(_))));
    }

    /// A stride of zero would make `mod(n,0)` undefined, so it has to fall
    /// through to even spacing rather than reach the filter.
    #[test]
    fn zero_stride_falls_through_to_even_spacing() {
        let cfg = VideoEmbedConfig {
            normalize: false,
            frame_stride: Some(0),
        };
        assert!(cfg.frame_stride.filter(|s| *s > 0).is_none());
    }

    #[test]
    fn collect_sequence_stops_at_first_gap() {
        let dir = tempfile::tempdir().unwrap();
        for i in [1usize, 2, 4] {
            std::fs::write(dir.path().join(format!("frame_{:03}.png", i)), b"x").unwrap();
        }
        let paths = VisionFallbackVideoEncoder::collect_sequence(dir.path(), 8);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn num_frames_clamped_to_at_least_one() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage { dim: 4, value: 0.0 });
        let v = VisionFallbackVideoEncoder::new(img, 0);
        assert_eq!(v.num_frames(), 1);
    }
}
