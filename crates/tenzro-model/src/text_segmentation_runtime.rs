//! Text-promptable segmentation runtime — SAM 3 / SAM 3.1 family.
//!
//! SAM 3 is Meta's text-and-box-promptable open-vocabulary segmenter. It
//! is architecturally distinct from SAM 1 (`EdgeSAM`, `MobileSAM`) and
//! SAM 2 (Hiera): instead of one point/box prompt → 3 mask candidates,
//! SAM 3 runs three separate ONNX graphs in sequence and emits a
//! *detection*-shaped result — N (bbox, score, mask) triples per call,
//! gated by a free-text label.
//!
//! ```text
//!                 ┌─────────────────────────────┐
//!   image bytes ─▶│ sam3_image_encoder.onnx     │── backbone_fpn[3]
//!                 │ uint8 (3, 1008, 1008)       │── vision_pos_enc[3]
//!                 └─────────────────────────────┘
//!                                                       │
//!                 ┌─────────────────────────────┐       │
//!   text prompt ─▶│ sam3_language_encoder.onnx  │── language_mask
//!                 │ int64 (1, 32) CLIP BPE      │── language_features
//!                 └─────────────────────────────┘  (── language_embeds, unused)
//!                                                       │
//!                                                       ▼
//!                 ┌─────────────────────────────────────────────┐
//!   box prompt ──▶│ sam3_decoder.onnx                           │── boxes  (N, 4) cxcywh normalized
//!   (optional)    │  in: backbone_fpn_{0,1,2}, vision_pos_enc_2,│── scores (N,)
//!                 │      language_mask, language_features,      │── masks  (N, 1, H, W) bool-like
//!                 │      box_coords (1,1,4), box_labels (1,1),  │
//!                 │      box_masks (1,1) bool                   │
//!                 └─────────────────────────────────────────────┘
//! ```
//!
//! # Why a separate runtime from [`crate::segmentation_runtime`]
//!
//! SAM 1/2 expose a stable `(image_bytes, [point|box]+) → 1 SegmentMask`
//! API that the existing [`crate::segmentation_runtime::Segmenter`] trait
//! captures. SAM 3 is structurally different:
//!
//! - **Three ONNX graphs**, not two. Adds a tokenized text encoder.
//! - **Detection-style output**: variable number of (bbox, score, mask)
//!   triples per query, not a single argmax-IoU mask. Closer to the
//!   shape served by [`crate::detection_runtime::Detector`].
//! - **Open vocabulary**: prompt is a free-text label (e.g.
//!   `"person"`), not a point/box.
//! - **uint8 image input** with no normalization (just HWC→CHW
//!   transpose at 1008×1008). SAM 1 uses 0–255 + SAM mean/std and SAM
//!   2 uses ImageNet norm on `[0,1]`.
//!
//! Adding a `SamFamily::Sam3` variant to the existing runtime would
//! require widening the `Segmenter` trait's return type and shimming
//! the missing text-encoder path through the same trait — which would
//! break the SAM 1/2 callers without buying anything. A sibling module
//! with its own trait is the right factoring.
//!
//! # Threading
//!
//! `TextSegmentationRuntime` is `Send + Sync` and stores models in a
//! `DashMap<String, Arc<dyn TextPromptableSegmenter>>` keyed by model_id.
//! ORT sessions are not concurrent-safe — each of the three sessions
//! lives behind a `parking_lot::Mutex`. Inference is dispatched through
//! `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::text_segmentation::{
    Sam3Segmenter, TextPromptableSegmenter, TextSegmentBoxPrompt, TextSegmentConfig,
    TextSegmentResult, TextSegmentation,
};

/// Placeholder segmenter for tests and dependency-injection points that
/// need a `TextPromptableSegmenter` without loading a real SAM 3 bundle.
/// Always returns [`ModelError::ProviderNotAvailable`] from
/// `segment_with_text` so call sites can exercise their error paths.
#[derive(Debug)]
pub struct StubTextSegmenter;

impl TextPromptableSegmenter for StubTextSegmenter {
    fn segment_with_text(
        &self,
        _image_bytes: &[u8],
        _config: &TextSegmentConfig,
    ) -> praecise_onnx::Result<TextSegmentResult> {
        Err(praecise_onnx::Error::ProviderNotAvailable(
            "StubTextSegmenter cannot perform inference — load a real SAM 3 bundle".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
    fn context_length(&self) -> u32 {
        0
    }
}

/// Runtime owning one or more loaded text-promptable segmenters.
pub struct TextSegmentationRuntime {
    models: EngineModels<dyn TextPromptableSegmenter>,
}

impl Default for TextSegmentationRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TextSegmentationRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("text-segmentation"), host),
        }
    }

    pub fn register(
        &self,
        model_id: impl Into<String>,
        model: Arc<dyn TextPromptableSegmenter>,
    ) -> Result<()> {
        self.models.insert(model_id, model)
    }

    /// Load a SAM-3-family bundle from disk (image encoder + language
    /// encoder + decoder + tokenizer.json) and register it under
    /// `model_id`.
    pub fn load_sam3(
        &self,
        model_id: impl Into<String>,
        image_encoder_path: impl AsRef<Path>,
        language_encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = Sam3Segmenter::from_onnx(
                image_encoder_path,
                language_encoder_path,
                decoder_path,
                tokenizer_path,
            )?;
            Ok(Arc::new(model) as Arc<dyn TextPromptableSegmenter>)
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

    pub async fn segment_with_text(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        config: TextSegmentConfig,
    ) -> Result<TextSegmentResult> {
        self.models
            .run(model_id, move |model| {
                model
                    .segment_with_text(&image_bytes, &config)
                    .map_err(ModelError::from)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock segmenter that returns one fixed detection. Exercises
    /// runtime dispatch and DashMap bookkeeping without loading ONNX.
    struct ConstantTextSegmenter;
    impl TextPromptableSegmenter for ConstantTextSegmenter {
        fn segment_with_text(
            &self,
            _image_bytes: &[u8],
            _config: &TextSegmentConfig,
        ) -> praecise_onnx::Result<TextSegmentResult> {
            Ok(TextSegmentResult {
                segmentations: vec![TextSegmentation {
                    bbox: [0.0, 0.0, 10.0, 10.0],
                    score: 0.9,
                    width: 10,
                    height: 10,
                    mask: vec![1u8; 100],
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            1008
        }
        fn context_length(&self) -> u32 {
            32
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = TextSegmentationRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = TextSegmentationRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_returns_provider_not_available() {
        let stub = StubTextSegmenter;
        let res = stub.segment_with_text(&[], &TextSegmentConfig::default());
        assert!(matches!(
            res,
            Err(praecise_onnx::Error::ProviderNotAvailable(_))
        ));
    }

    #[tokio::test]
    async fn segment_on_unknown_model_returns_not_found() {
        let rt = TextSegmentationRuntime::new();
        let res = rt
            .segment_with_text("missing", vec![], TextSegmentConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_segmenter() {
        let rt = TextSegmentationRuntime::new();
        rt.register("mock", Arc::new(ConstantTextSegmenter))
            .unwrap();
        let cfg = TextSegmentConfig {
            text_prompt: "person".to_string(),
            box_prompt: None,
            score_threshold: 0.5,
        };
        let r = rt.segment_with_text("mock", vec![1], cfg).await.unwrap();
        assert_eq!(r.segmentations.len(), 1);
        assert_eq!(r.segmentations[0].width, 10);
        assert_eq!(r.segmentations[0].mask.len(), 100);
    }

    #[test]
    fn box_prompt_round_trip() {
        let b = TextSegmentBoxPrompt {
            cx: 0.5,
            cy: 0.5,
            w: 0.2,
            h: 0.3,
        };
        let s = serde_json::to_string(&b).unwrap();
        let _: TextSegmentBoxPrompt = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn config_default_threshold_is_half() {
        let cfg = TextSegmentConfig::default();
        assert!((cfg.score_threshold - 0.5).abs() < f32::EPSILON);
    }
}
