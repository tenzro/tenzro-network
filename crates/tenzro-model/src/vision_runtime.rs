//! Vision encoder runtime backed by ONNX Runtime.
//!
//! This module is gated behind the `onnx` cargo feature. When the feature
//! is off, a thin stub is exposed so callers can still compile and surface
//! a clean "ONNX backend not enabled" error at runtime — exactly the same
//! shape as the real implementation.
//!
//! # Scope
//!
//! Foundation vision encoders in 2026 (CLIP family, SigLIP / SigLIP2,
//! DINOv2, TIPS) all share a similar interface: a preprocessed image tensor
//! `[batch=1, 3, H, W]` (NCHW, normalized) goes in, a fixed-dim embedding
//! vector comes out. CLIP/SigLIP also expose a paired text encoder for
//! image-text similarity.
//!
//! This runtime focuses on the **image side** — image embedding and dense
//! features. Text-side encoders for CLIP/SigLIP are handled by the LLM
//! tokenizer + model runtime since their text towers are transformer
//! decoders that load fine through llama-cpp / standard chat infrastructure.
//! For the rare case where a custom ONNX text tower is required, callers
//! can register a second `GenericImageEncoder` with text input shape and
//! call it manually — but the common path is image-only.
//!
//! # Preprocessing
//!
//! Standard ImageNet/CLIP normalization is applied:
//!   - Decode (PNG/JPEG/WebP via the `image` crate)
//!   - Resize to `(input_size, input_size)` with Lanczos3 filter
//!   - Convert to f32 in `[0, 1]`
//!   - Subtract per-channel mean, divide by per-channel std
//!   - Reshape NHWC → NCHW
//!
//! Default mean/std are CLIP-style (`[0.48145466, 0.4578275, 0.40821073]`,
//! `[0.26862954, 0.26130258, 0.27577711]`) but configurable for
//! ImageNet/SigLIP/DINOv2 variants at registration time.
//!
//! # Threading
//!
//! `VisionRuntime` is `Send + Sync` and holds loaded ONNX sessions in a
//! `DashMap` keyed by model_id. ORT sessions are not concurrent-safe, so
//! sessions are wrapped in `parking_lot::Mutex`. Inference is dispatched
//! through `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Per-channel mean and std used to normalize pixel values before feeding
/// the encoder. Channels are RGB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageNormalization {
    pub mean: [f32; 3],
    pub std: [f32; 3],
}

impl ImageNormalization {
    /// CLIP / OpenCLIP standard normalization.
    pub const CLIP: Self = Self {
        mean: [0.48145466, 0.4578275, 0.40821073],
        std: [0.26862954, 0.261_302_6, 0.275_777_1],
    };

    /// ImageNet standard normalization (used by DINOv2, many ResNets).
    pub const IMAGENET: Self = Self {
        mean: [0.485, 0.456, 0.406],
        std: [0.229, 0.224, 0.225],
    };

    /// SigLIP / SigLIP2 normalization (symmetric around 0.5).
    pub const SIGLIP: Self = Self {
        mean: [0.5, 0.5, 0.5],
        std: [0.5, 0.5, 0.5],
    };
}

impl Default for ImageNormalization {
    fn default() -> Self {
        Self::CLIP
    }
}

/// Configuration for an image embedding request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageEmbedConfig {
    /// L2-normalize the output embedding. Most retrieval / similarity
    /// pipelines want this on; raw dense features want it off.
    #[serde(default)]
    pub normalize: bool,
}

/// Result of an image embedding call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEmbedResult {
    /// Embedding vector. Length is the encoder's native embedding dim
    /// (e.g. 512 for CLIP ViT-B/32, 768 for SigLIP-So400M, 1024 for DINOv2-L).
    pub embedding: Vec<f32>,
    /// Embedding dimensionality, mirrors `embedding.len()` for convenience.
    pub dim: usize,
    /// Total inference wall time in milliseconds (decode + preprocess + ORT run).
    pub generation_time_ms: u64,
}

/// Trait for image encoders. Implementations adapt model-specific
/// preprocessing and tensor layout to a common signature.
pub trait ImageEncoder: Send + Sync {
    /// Encode a single image (raw bytes — PNG, JPEG, WebP).
    fn embed(&self, image_bytes: &[u8], config: &ImageEmbedConfig) -> Result<ImageEmbedResult>;

    /// Native input resolution (e.g. 224, 336, 384, 448).
    fn input_size(&self) -> u32;

    /// Native embedding dimension.
    fn embedding_dim(&self) -> usize;
}

mod onnx_backend {
    use super::*;
    use image::imageops::FilterType;
    use ndarray::Array4;
    use ort::session::{Session, builder::GraphOptimizationLevel};
    use ort::value::Tensor;
    use std::time::Instant;

    /// Generic ONNX image encoder — fits CLIP, SigLIP/SigLIP2, DINOv2,
    /// TIPS, and similar architectures with `[1, 3, H, W] -> [1, D]` shape.
    ///
    /// `Session::run` requires `&mut self` in ort 2.x, so the session is
    /// wrapped in a `Mutex` to expose a `&self` API. ONNX Runtime sessions
    /// are not safe to call concurrently from multiple threads regardless,
    /// so the mutex matches the underlying contract rather than restricting it.
    pub struct GenericImageEncoder {
        session: parking_lot::Mutex<Session>,
        input_size: u32,
        embedding_dim: usize,
        normalization: ImageNormalization,
        input_name: String,
        output_name: String,
    }

    impl GenericImageEncoder {
        /// Load an ONNX file and inspect its input/output names.
        pub fn from_onnx(
            path: impl AsRef<Path>,
            input_size: u32,
            embedding_dim: usize,
            normalization: ImageNormalization,
        ) -> Result<Self> {
            let session = Session::builder()
                .map_err(|e| ModelError::InvalidModel(format!("ORT session builder: {}", e)))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| ModelError::InvalidModel(format!("ORT optimization level: {}", e)))?
                .commit_from_file(path.as_ref())
                .map_err(|e| ModelError::ProviderNotAvailable(format!("ORT load failed: {}", e)))?;

            let input_name = session
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("ONNX model has no inputs".to_string()))?;
            let output_name = session
                .outputs
                .first()
                .map(|o| o.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("ONNX model has no outputs".to_string()))?;

            Ok(Self {
                session: parking_lot::Mutex::new(session),
                input_size,
                embedding_dim,
                normalization,
                input_name,
                output_name,
            })
        }

        /// Decode → resize → normalize → NCHW. Returns a `[1, 3, H, W]`
        /// tensor ready for ORT.
        fn preprocess(&self, image_bytes: &[u8]) -> Result<Array4<f32>> {
            let img = image::load_from_memory(image_bytes)
                .map_err(|e| ModelError::InvalidModel(format!("image decode: {}", e)))?
                .to_rgb8();

            let size = self.input_size;
            let resized = image::imageops::resize(&img, size, size, FilterType::Lanczos3);

            let h = size as usize;
            let w = size as usize;
            let mut arr = Array4::<f32>::zeros((1, 3, h, w));
            let mean = self.normalization.mean;
            let std = self.normalization.std;

            for y in 0..h {
                for x in 0..w {
                    let px = resized.get_pixel(x as u32, y as u32);
                    for c in 0..3 {
                        let v = (px[c] as f32 / 255.0 - mean[c]) / std[c];
                        arr[[0, c, y, x]] = v;
                    }
                }
            }

            Ok(arr)
        }
    }

    impl ImageEncoder for GenericImageEncoder {
        fn embed(
            &self,
            image_bytes: &[u8],
            config: &ImageEmbedConfig,
        ) -> Result<ImageEmbedResult> {
            if image_bytes.is_empty() {
                return Err(ModelError::InvalidModel("image bytes are empty".to_string()));
            }

            let start = Instant::now();
            let arr = self.preprocess(image_bytes)?;

            let input_tensor = Tensor::from_array(arr)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor: {}", e)))?;

            // Lock the session for the duration of run() — ORT sessions are
            // not safe to call concurrently. Extract the result into owned
            // memory before releasing the lock.
            let (dims, mut raw): (Vec<i64>, Vec<f32>) = {
                let mut session = self.session.lock();
                let outputs = session
                    .run(ort::inputs![self.input_name.as_str() => input_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;

                let out_value = outputs.get(self.output_name.as_str()).ok_or_else(|| {
                    ModelError::InferenceError(format!("missing output '{}'", self.output_name))
                })?;

                let (shape, data) = out_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract: {}", e)))?;
                (shape.iter().copied().collect(), data.to_vec())
            };

            // Expect [1, D] (pooled embedding) — accept [1, 1, D] too as
            // some exports add a singleton sequence axis.
            let embedding: Vec<f32> = match dims.as_slice() {
                [1, d] => {
                    let d = *d as usize;
                    raw.truncate(d);
                    raw
                }
                [1, 1, d] => {
                    let d = *d as usize;
                    raw.truncate(d);
                    raw
                }
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "unexpected output shape {:?}, expected [1, D] or [1, 1, D]",
                        other
                    )));
                }
            };

            let mut embedding = embedding;
            if config.normalize {
                let norm: f32 = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for v in embedding.iter_mut() {
                        *v /= norm;
                    }
                }
            }

            let dim = embedding.len();
            Ok(ImageEmbedResult {
                embedding,
                dim,
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn input_size(&self) -> u32 {
            self.input_size
        }

        fn embedding_dim(&self) -> usize {
            self.embedding_dim
        }
    }
}

pub use onnx_backend::GenericImageEncoder;

/// Cosine similarity between two equal-length embeddings. Returns 0.0 if
/// either vector is empty or has zero norm. Range is `[-1.0, 1.0]`.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0_f32;
    let mut na = 0.0_f32;
    let mut nb = 0.0_f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom > 0.0 { dot / denom } else { 0.0 }
}

/// Runtime that owns multiple loaded image encoders, keyed by model_id.
///
/// This is the vision equivalent of `ModelRuntime` for chat models — the
/// node calls into it when handling `tenzro_imageEmbed` /
/// `tenzro_imageTextSimilarity` RPC requests.
pub struct VisionRuntime {
    models: dashmap::DashMap<String, Arc<dyn ImageEncoder>>,
}

impl Default for VisionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl VisionRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    /// Register a pre-loaded encoder under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn ImageEncoder>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load an ONNX model from disk and register it.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        input_size: u32,
        embedding_dim: usize,
        normalization: ImageNormalization,
    ) -> Result<()> {
        let model =
            GenericImageEncoder::from_onnx(path, input_size, embedding_dim, normalization)?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn ImageEncoder>);
        Ok(())
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

    /// Embed an image with a registered encoder. Inference is dispatched
    /// to `spawn_blocking` so the async caller's runtime isn't stalled.
    pub async fn embed(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        config: ImageEmbedConfig,
    ) -> Result<ImageEmbedResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| Arc::clone(kv.value()))
            .ok_or_else(|| {
                ModelError::ModelNotFound(format!("vision encoder '{}'", model_id))
            })?;

        tokio::task::spawn_blocking(move || model.embed(&image_bytes, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("blocking task panic: {}", e)))?
    }

    /// Compute cosine similarity between an image embedding (computed via
    /// `embed`) and a text embedding (provided by the caller — typically
    /// produced by the model's text tower running on the chat runtime).
    /// Both vectors should be L2-normalized; if not, the function falls
    /// back to plain cosine.
    ///
    /// This is a pure helper that doesn't load anything — the work is done
    /// by `embed` plus whatever the caller used to encode the text side.
    pub fn similarity(image_embedding: &[f32], text_embedding: &[f32]) -> f32 {
        cosine_similarity(image_embedding, text_embedding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_config_default() {
        let c = ImageEmbedConfig::default();
        assert!(!c.normalize);
    }

    #[test]
    fn embed_result_serializes() {
        let r = ImageEmbedResult {
            embedding: vec![0.1, 0.2, 0.3],
            dim: 3,
            generation_time_ms: 7,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"embedding\""));
        assert!(json.contains("\"dim\":3"));
        let back: ImageEmbedResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.embedding, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn normalization_constants() {
        let clip = ImageNormalization::CLIP;
        assert!((clip.mean[0] - 0.48145466).abs() < 1e-6);
        let inet = ImageNormalization::IMAGENET;
        assert!((inet.std[0] - 0.229).abs() < 1e-6);
        let sig = ImageNormalization::SIGLIP;
        assert_eq!(sig.mean, [0.5, 0.5, 0.5]);
    }

    #[test]
    fn cosine_similarity_basics() {
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]), 1.0);
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]), -1.0);
        assert!((cosine_similarity(&[1.0, 0.0], &[0.0, 1.0])).abs() < 1e-6);
        // mismatched lengths
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 0.0]), 0.0);
        // empty
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        // zero vector
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = VisionRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn runtime_unregister_returns_false_when_absent() {
        let rt = VisionRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[tokio::test]
    async fn embed_on_unknown_model_returns_not_found() {
        let rt = VisionRuntime::new();
        let err = rt
            .embed("nope", vec![0u8; 16], ImageEmbedConfig::default())
            .await
            .unwrap_err();
        match err {
            ModelError::ModelNotFound(_) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }


    /// A trivial mock encoder used to exercise the runtime dispatch path
    /// without requiring ONNX.
    struct ConstantEncoder {
        dim: usize,
        value: f32,
    }
    impl ImageEncoder for ConstantEncoder {
        fn embed(
            &self,
            _image_bytes: &[u8],
            config: &ImageEmbedConfig,
        ) -> Result<ImageEmbedResult> {
            let mut e = vec![self.value; self.dim];
            if config.normalize {
                let norm: f32 = e.iter().map(|v| v * v).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for v in e.iter_mut() {
                        *v /= norm;
                    }
                }
            }
            let dim = e.len();
            Ok(ImageEmbedResult {
                embedding: e,
                dim,
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

    #[tokio::test]
    async fn runtime_dispatches_to_registered_model() {
        let rt = VisionRuntime::new();
        rt.register(
            "constant",
            Arc::new(ConstantEncoder { dim: 4, value: 1.0 }),
        );
        assert!(rt.is_loaded("constant"));
        let r = rt
            .embed("constant", vec![0u8; 8], ImageEmbedConfig::default())
            .await
            .unwrap();
        assert_eq!(r.dim, 4);
        assert_eq!(r.embedding, vec![1.0; 4]);
    }

    #[tokio::test]
    async fn embed_normalize_produces_unit_vector() {
        let rt = VisionRuntime::new();
        rt.register(
            "constant",
            Arc::new(ConstantEncoder { dim: 4, value: 2.0 }),
        );
        let cfg = ImageEmbedConfig { normalize: true };
        let r = rt.embed("constant", vec![0u8; 8], cfg).await.unwrap();
        let norm: f32 = r.embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "expected unit norm, got {}", norm);
    }

    #[test]
    fn similarity_helper_matches_cosine() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(VisionRuntime::similarity(&a, &b), 1.0);
    }
}
