//! Segmentation runtime backed by ONNX Runtime.
//!
//! Supports two SAM dialects that share the same point/box prompt API:
//!
//! - **SAM 1 family** (EdgeSAM, MobileSAM): 6-input decoder, longest-side
//!   resize-to-1024 with zero-padding, SAM normalization (mean
//!   `[123.675, 116.28, 103.53]`, std `[58.395, 57.12, 57.375]` over raw
//!   0–255 pixel values), decoder consumes `image_embeddings` +
//!   `point_coords` + `point_labels` + `mask_input` + `has_mask_input` +
//!   `orig_im_size`. The decoder graph rescales output masks to the
//!   original image size internally.
//!
//! - **SAM 2 family** (Hiera base+, Hiera large): 7-input decoder, plain
//!   bilinear resize to `(input_size, input_size)` (no padding), ImageNet
//!   normalization on `[0, 1]` pixels. Encoder produces three outputs:
//!   `high_res_feats_0` `[1, 32, 256, 256]`, `high_res_feats_1`
//!   `[1, 64, 128, 128]`, and `image_embed` `[1, 256, 64, 64]`. The
//!   decoder consumes all three plus the same prompt tensors as SAM 1,
//!   but **without** `orig_im_size` — output masks come back at
//!   `[1, 3, H/4, W/4]` resolution and the runtime rescales them to the
//!   original image.
//!
//! In both families, prompt labels follow SAM convention:
//!   - `1.0` = foreground point
//!   - `0.0` = background point
//!   - `2.0` = top-left box corner
//!   - `3.0` = bottom-right box corner
//!   - `-1.0` = padding (used when no prompt is supplied for a slot)
//!
//! Point coordinates are passed in the encoder's resized pixel space, *not*
//! normalized `[0, 1]`. The runtime converts user-supplied prompts (in
//! original image pixels) into encoder space before invoking the decoder.
//!
//! The decoder returns 3 mask candidates per request along with an IoU
//! prediction per mask; this runtime returns the argmax-IoU mask resampled
//! to the original image size as a `[H * W]` u8 buffer.
//!
//! SAM 3 / SAM 3.1 are text-promptable and use a different decoder
//! topology (image encoder + language encoder + detection-shaped box
//! decoder). They live in [`crate::text_segmentation_runtime`] with
//! their own [`TextPromptableSegmenter`](crate::text_segmentation_runtime::TextPromptableSegmenter)
//! trait — same crate, separate type, different I/O contract.

use std::path::Path;
use std::sync::Arc;

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::segmentation::{
    BoxPrompt, GenericSamSegmenter, PointPrompt, SamFamily, SegmentMask, SegmentPrompt,
    SegmentResult, Segmenter,
};

/// Stub segmenter for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubSegmenter;

impl StubSegmenter {
    pub fn from_onnx(_encoder: impl AsRef<Path>, _decoder: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl Segmenter for StubSegmenter {
    fn segment(
        &self,
        _image_bytes: &[u8],
        _prompts: &[SegmentPrompt],
    ) -> praecise_onnx::Result<SegmentResult> {
        Err(praecise_onnx::Error::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
}

/// Runtime that owns multiple loaded segmentation models.
pub struct SegmentationRuntime {
    models: EngineModels<dyn Segmenter>,
}

impl Default for SegmentationRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentationRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("segmentation"), host),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Segmenter>) -> Result<()> {
        self.models.insert(model_id, model)
    }

    /// Load an encoder/decoder pair from disk and register them under
    /// `model_id`. The caller picks the correct `SamFamily` based on the
    /// catalog entry's `family` field (`sam2` → `Sam2`, otherwise `Sam1`).
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        family: SamFamily,
        input_size: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model =
                GenericSamSegmenter::from_onnx(encoder_path, decoder_path, family, input_size)?;
            Ok(Arc::new(model) as Arc<dyn Segmenter>)
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

    pub async fn segment(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        prompts: Vec<SegmentPrompt>,
    ) -> Result<SegmentResult> {
        self.models
            .run(model_id, move |model| {
                model
                    .segment(&image_bytes, &prompts)
                    .map_err(ModelError::from)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock segmenter that returns a fixed 10x10 mask. Exercises runtime
    /// dispatch and dashmap bookkeeping without loading an ONNX file.
    struct ConstantSegmenter {
        input_size: u32,
    }
    impl Segmenter for ConstantSegmenter {
        fn segment(
            &self,
            _image_bytes: &[u8],
            _prompts: &[SegmentPrompt],
        ) -> praecise_onnx::Result<SegmentResult> {
            Ok(SegmentResult {
                masks: vec![SegmentMask {
                    width: 10,
                    height: 10,
                    mask: vec![1u8; 100],
                    score: 0.88,
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            self.input_size
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = SegmentationRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = SegmentationRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_segmenter_returns_provider_not_available() {
        let stub = StubSegmenter;
        let res = stub.segment(&[], &[]);
        assert!(matches!(
            res,
            Err(praecise_onnx::Error::ProviderNotAvailable(_))
        ));
    }

    #[tokio::test]
    async fn segment_on_unknown_model_returns_not_found() {
        let rt = SegmentationRuntime::new();
        let res = rt.segment("missing", vec![], vec![]).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_segmenter() {
        let rt = SegmentationRuntime::new();
        rt.register("mock", Arc::new(ConstantSegmenter { input_size: 1024 }))
            .unwrap();
        let r = rt
            .segment(
                "mock",
                vec![1],
                vec![SegmentPrompt::Point(PointPrompt {
                    x: 0.0,
                    y: 0.0,
                    is_foreground: true,
                })],
            )
            .await
            .unwrap();
        assert_eq!(r.masks.len(), 1);
        assert_eq!(r.masks[0].width, 10);
        assert_eq!(r.masks[0].height, 10);
        assert_eq!(r.masks[0].mask.len(), 100);
    }

    #[test]
    fn prompt_serializes_round_trip() {
        let p = SegmentPrompt::Point(PointPrompt {
            x: 1.0,
            y: 2.0,
            is_foreground: true,
        });
        let s = serde_json::to_string(&p).unwrap();
        let _: SegmentPrompt = serde_json::from_str(&s).unwrap();
    }
}
