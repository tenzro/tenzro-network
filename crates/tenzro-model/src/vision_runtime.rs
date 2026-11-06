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

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::vision::{
    GenericImageEncoder, ImageEmbedConfig, ImageEmbedResult, ImageEncoder, ImageNormalization,
    cosine_similarity, image_dimensions,
};

/// Runtime that owns multiple loaded image encoders, keyed by model_id.
///
/// This is the vision equivalent of `ModelRuntime` for chat models — the
/// node calls into it when handling `tenzro_imageEmbed` /
/// `tenzro_imageTextSimilarity` RPC requests.
pub struct VisionRuntime {
    models: EngineModels<dyn ImageEncoder>,
}

impl Default for VisionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl VisionRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("vision"), host),
        }
    }

    /// Register a pre-loaded encoder under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(
        &self,
        model_id: impl Into<String>,
        model: Arc<dyn ImageEncoder>,
    ) -> Result<()> {
        self.models.insert(model_id, model)
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
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model =
                GenericImageEncoder::from_onnx(path, input_size, embedding_dim, normalization)?;
            Ok(Arc::new(model) as Arc<dyn ImageEncoder>)
        })
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

    /// Hand out a loaded encoder so another runtime can build on it. The video
    /// runtime uses this to wrap an image encoder as a frame-pooling clip
    /// encoder without loading a second copy of the graph.
    pub fn encoder(&self, model_id: &str) -> Option<Arc<dyn ImageEncoder>> {
        self.models.get(model_id)
    }

    /// Embed an image with a registered encoder, through the runtime's
    /// admission, on a blocking thread.
    pub async fn embed(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        config: ImageEmbedConfig,
    ) -> Result<ImageEmbedResult> {
        self.models
            .run(model_id, move |model| {
                model.embed(&image_bytes, &config).map_err(ModelError::from)
            })
            .await
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
        ) -> praecise_onnx::Result<ImageEmbedResult> {
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
        rt.register("constant", Arc::new(ConstantEncoder { dim: 4, value: 1.0 }))
            .unwrap();
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
        rt.register("constant", Arc::new(ConstantEncoder { dim: 4, value: 2.0 }))
            .unwrap();
        let cfg = ImageEmbedConfig { normalize: true };
        let r = rt.embed("constant", vec![0u8; 8], cfg).await.unwrap();
        let norm: f32 = r.embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-6,
            "expected unit norm, got {}",
            norm
        );
    }

    #[test]
    fn similarity_helper_matches_cosine() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(VisionRuntime::similarity(&a, &b), 1.0);
    }
}
