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
//! `FramePooledVideoEncoder` below, which turns any already-loaded
//! `ImageEncoder` (CLIP / SigLIP2 / DINOv3 / ViT) into a video encoder by:
//!
//! 1. Decoding `num_frames` frames from the input video in process,
//!    evenly spaced across the clip, or at a fixed stride when the request
//!    carries `frame_stride`.
//! 2. Embedding each frame through the underlying image encoder.
//! 3. Mean-pooling the per-frame embeddings.
//! 4. Optionally L2-normalizing the resulting vector.
//!
//! Frames are decoded in process by the Praecise engine's video codec (MP4
//! and Matroska/WebM holding H.264, H.265 or AV1); the node never starts an
//! external decoder.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};
use crate::vision_runtime::ImageEncoder;

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

/// Wraps any `ImageEncoder` into a `VideoEncoder` by decoding frames in
/// process and mean-pooling per-frame embeddings.
///
/// The encoder is owned by `Arc` so the same image model can power both
/// `VisionRuntime::embed` and one or more `VideoRuntime::embed` entries
/// without duplication.
pub struct FramePooledVideoEncoder {
    image: Arc<dyn ImageEncoder>,
    num_frames: u32,
}

impl FramePooledVideoEncoder {
    /// Build a video encoder backed by an image encoder. `num_frames` is
    /// how many evenly-spaced frames to sample from the input clip — the
    /// canonical CLIP4Clip-style setting is 8 for short clips, 16–32 for
    /// longer ones.
    pub fn new(image: Arc<dyn ImageEncoder>, num_frames: u32) -> Self {
        let num_frames = num_frames.max(1);
        Self { image, num_frames }
    }
}

impl VideoEncoder for FramePooledVideoEncoder {
    fn embed(&self, video_bytes: &[u8], config: &VideoEmbedConfig) -> Result<VideoEmbedResult> {
        if video_bytes.is_empty() {
            return Err(ModelError::InvalidModel("video bytes are empty".into()));
        }

        let started = std::time::Instant::now();
        let info = praecise_diffusion::codec::probe(video_bytes)
            .map_err(|e| ModelError::InvalidInput(format!("video: {e}")))?;
        let picks = sample_frames(info.frames, self.num_frames, config.frame_stride);
        let last = *picks
            .last()
            .ok_or_else(|| ModelError::InvalidInput("the video has no frames".into()))?;
        let image_cfg = crate::vision_runtime::ImageEmbedConfig { normalize: false };
        let mut sum = vec![0f64; self.image.embedding_dim()];
        let mut next = 0usize;
        let mut failure = None;
        praecise_diffusion::codec::decode_each(video_bytes, |index, rgb| {
            if next < picks.len() && picks[next] == index {
                next += 1;
                match frame_png(info.width, info.height, rgb).and_then(|png| {
                    self.image
                        .embed(&png, &image_cfg)
                        .map_err(crate::error::ModelError::from)
                }) {
                    Ok(r) if r.embedding.len() == sum.len() => {
                        for (a, v) in sum.iter_mut().zip(&r.embedding) {
                            *a += f64::from(*v);
                        }
                    }
                    Ok(r) => {
                        failure = Some(ModelError::InferenceError(format!(
                            "frame embedding of {} dimensions, expected {}",
                            r.embedding.len(),
                            sum.len()
                        )));
                        return false;
                    }
                    Err(e) => {
                        failure = Some(e);
                        return false;
                    }
                }
            }
            index < last
        })
        .map_err(|e| ModelError::InvalidInput(format!("video: {e}")))?;
        if let Some(e) = failure {
            return Err(e);
        }
        let n = picks.len() as f64;
        let mut embedding: Vec<f32> = sum.iter().map(|v| (v / n) as f32).collect();
        if config.normalize {
            let norm = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
            if norm > 0.0 {
                embedding.iter_mut().for_each(|v| *v /= norm);
            }
        }
        let video_ms = if info.fps > 0.0 {
            (f64::from(info.frames) * 1000.0 / f64::from(info.fps)).round() as u64
        } else {
            0
        };
        Ok(VideoEmbedResult {
            dim: embedding.len(),
            embedding,
            frames_consumed: picks.len() as u32,
            video_ms,
            generation_time_ms: started.elapsed().as_millis() as u64,
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

/// Indices of the frames to embed out of `total`: every `stride`-th from the
/// start when a stride is given, otherwise `wanted` spread evenly from the
/// first frame to the last; at most `wanted` either way.
fn sample_frames(total: u32, wanted: u32, stride: Option<u32>) -> Vec<u32> {
    let wanted = wanted.max(1).min(total);
    if let Some(s) = stride.filter(|s| *s > 0) {
        return (0..total)
            .step_by(s as usize)
            .take(wanted as usize)
            .collect();
    }
    if wanted <= 1 {
        return if total == 0 { Vec::new() } else { vec![0] };
    }
    (0..wanted)
        .map(|k| {
            ((u64::from(k) * u64::from(total - 1) + u64::from(wanted - 1) / 2)
                / u64::from(wanted - 1)) as u32
        })
        .collect()
}

/// One decoded frame as PNG bytes, the form image encoders take.
fn frame_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>> {
    let img = image::RgbImage::from_raw(width, height, rgb.to_vec())
        .ok_or_else(|| ModelError::InvalidInput("decoded frame size mismatch".into()))?;
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png)
        .map_err(|e| ModelError::InferenceError(format!("frame encode: {e}")))?;
    Ok(out.into_inner())
}

/// Runtime that owns multiple loaded video encoders.
pub struct VideoRuntime {
    models: EngineModels<dyn VideoEncoder>,
}

impl Default for VideoRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("video"), host),
        }
    }

    pub fn register(
        &self,
        model_id: impl Into<String>,
        model: Arc<dyn VideoEncoder>,
    ) -> Result<()> {
        self.models.insert(model_id, model)
    }

    /// Register a video encoder that pools frames through an image encoder
    /// the vision runtime already holds, so no second copy of its graph is
    /// loaded.
    pub fn register_frame_pooled(
        &self,
        model_id: impl Into<String>,
        image: Arc<dyn ImageEncoder>,
        num_frames: u32,
    ) -> Result<()> {
        let enc = FramePooledVideoEncoder::new(image, num_frames);
        self.models
            .insert(model_id, Arc::new(enc) as Arc<dyn VideoEncoder>)
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id)
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.ids()
    }

    pub async fn embed(
        &self,
        model_id: &str,
        video_bytes: Vec<u8>,
        config: VideoEmbedConfig,
    ) -> Result<VideoEmbedResult> {
        self.models
            .run(model_id, move |model| model.embed(&video_bytes, &config))
            .await
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
            _cfg: &crate::vision_runtime::ImageEmbedConfig,
        ) -> praecise_onnx::Result<crate::vision_runtime::ImageEmbedResult> {
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
    fn frame_pooled_carries_underlying_dims() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage {
            dim: 768,
            value: 0.5,
        });
        let v = FramePooledVideoEncoder::new(img, 8);
        assert_eq!(v.embedding_dim(), 768);
        assert_eq!(v.frame_size(), 224);
        assert_eq!(v.num_frames(), 8);
    }

    #[test]
    fn frame_pooled_rejects_empty_video() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage { dim: 8, value: 0.1 });
        let v = FramePooledVideoEncoder::new(img, 4);
        let r = v.embed(&[], &VideoEmbedConfig::default());
        assert!(matches!(r, Err(ModelError::InvalidModel(_))));
    }

    /// An image encoder whose embedding is the picture's mean red, green
    /// and blue, so pooling over decoded frames can be checked.
    struct MeanColour;
    impl ImageEncoder for MeanColour {
        fn embed(
            &self,
            bytes: &[u8],
            _cfg: &crate::vision_runtime::ImageEmbedConfig,
        ) -> praecise_onnx::Result<crate::vision_runtime::ImageEmbedResult> {
            let img = image::load_from_memory(bytes).unwrap().to_rgb8();
            let n = f32::from(u16::try_from(img.width() * img.height()).unwrap());
            let mut m = vec![0f32; 3];
            for p in img.pixels() {
                for c in 0..3 {
                    m[c] += f32::from(p[c]) / n;
                }
            }
            Ok(crate::vision_runtime::ImageEmbedResult {
                embedding: m,
                dim: 3,
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            32
        }
        fn embedding_dim(&self) -> usize {
            3
        }
    }

    #[test]
    fn frame_pooled_decodes_an_mp4_and_pools_the_sampled_frames() {
        // Ten flat frames whose green steps by 20; at 10 fps the clip is one second.
        let (w, h) = (32u32, 32u32);
        let rgb: Vec<u8> = (0..10u8)
            .flat_map(|f| (0..w * h).flat_map(move |_| [200, 20 * f + 10, 60]))
            .collect();
        let mp4 = praecise_diffusion::codec::encode(
            praecise_diffusion::codec::EncodeOptions::default(),
            w,
            h,
            10.0,
            &rgb,
            None,
        )
        .unwrap();
        let v = FramePooledVideoEncoder::new(Arc::new(MeanColour), 4);
        let r = v.embed(&mp4, &VideoEmbedConfig::default()).unwrap();
        assert_eq!((r.frames_consumed, r.video_ms, r.dim), (4, 1000, 3));
        // Frames 0, 3, 6 and 9: mean green (10 + 70 + 130 + 190) / 4 = 100.
        assert!(
            (r.embedding[0] - 200.0).abs() < 3.0 && (r.embedding[1] - 100.0).abs() < 3.0,
            "{:?}",
            r.embedding
        );
        let strided = v
            .embed(
                &mp4,
                &VideoEmbedConfig {
                    normalize: true,
                    frame_stride: Some(5),
                },
            )
            .unwrap();
        assert_eq!(strided.frames_consumed, 2);
        let norm: f32 = strided.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
        assert!(matches!(
            v.embed(b"not a video", &VideoEmbedConfig::default()),
            Err(ModelError::InvalidInput(_))
        ));
    }

    #[test]
    fn frames_are_sampled_evenly_or_by_stride() {
        assert_eq!(sample_frames(10, 4, None), vec![0, 3, 6, 9]);
        assert_eq!(sample_frames(3, 8, None), vec![0, 1, 2]);
        assert_eq!(sample_frames(10, 1, None), vec![0]);
        assert_eq!(sample_frames(10, 3, Some(4)), vec![0, 4, 8]);
        assert_eq!(sample_frames(10, 2, Some(4)), vec![0, 4]);
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
    fn num_frames_clamped_to_at_least_one() {
        let img: Arc<dyn ImageEncoder> = Arc::new(ConstantImage { dim: 4, value: 0.0 });
        let v = FramePooledVideoEncoder::new(img, 0);
        assert_eq!(v.num_frames(), 1);
    }
}
