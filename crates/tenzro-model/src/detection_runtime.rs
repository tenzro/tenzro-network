//! Object detection runtime backed by ONNX Runtime.
//!
//! Supports the two open-license, NMS-free DETR families that ship in the
//! Tenzro detection catalog:
//!
//! - **RF-DETR** (Roboflow, Apache 2.0, ICLR 2026 — the first real-time
//!   detector to break >60 AP on COCO). Single input `"input"` of shape
//!   `[1, 3, H, W]` with ImageNet normalization. Two outputs: `"dets"` —
//!   cxcywh boxes in `[0, 1]` normalized image coordinates of shape
//!   `[1, num_queries, 4]`, and `"labels"` — raw class logits of shape
//!   `[1, num_queries, num_classes]` that the client must sigmoid.
//!   RF-DETR was trained with **90-class COCO indexing** (the original
//!   Detectron2 layout that includes 11 deprecated "background" slots), so
//!   the catalog records `num_classes: 90`.
//!
//! - **D-FINE** (Peterande/D-FINE, Apache 2.0). Two inputs `"images"` of
//!   shape `[1, 3, 640, 640]` and `"orig_target_sizes"` of dtype int64,
//!   shape `[1, 2]` carrying the unresized `(H, W)` of the source image.
//!   Pixel values are scaled to `[0, 1]` *only* — no ImageNet normalization.
//!   Three outputs already in fully postprocessed form: `"labels"` (int64),
//!   `"boxes"` (xyxy pixel coordinates relative to the original image),
//!   and `"scores"` (post-sigmoid, sorted descending). D-FINE uses standard
//!   80-class COCO indexing.
//!
//! # Pre/post-processing
//!
//! - **Decode** PNG/JPEG/WebP via the `image` crate.
//! - **Resize** to `(input_size, input_size)` with Lanczos3.
//! - **NHWC → NCHW** float layout.
//! - **RF-DETR:** normalize with ImageNet mean/std. Postprocess by
//!   sigmoiding the class logits, taking the per-query top-1 class, filtering
//!   by `score_threshold`, converting cxcywh → xyxy, and scaling to the
//!   *original* image pixel coordinates.
//! - **D-FINE:** scale to `[0, 1]` only and pass `orig_target_sizes`
//!   directly; the graph emits final xyxy pixel boxes already in the
//!   original image's coordinate frame.
//!
//! # Threading
//!
//! `DetectionRuntime` is `Send + Sync` and holds loaded ONNX sessions in a
//! `DashMap` keyed by model_id. ORT sessions are not concurrent-safe, so
//! sessions are wrapped in `parking_lot::Mutex`. Inference is dispatched
//! through `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::detection::{
    DetectResult, Detection, Detector, DetrFamily, GenericDetrDetector,
};

/// Stub detector for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubDetector;

impl StubDetector {
    pub fn from_onnx(_path: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl Detector for StubDetector {
    fn detect(
        &self,
        _image_bytes: &[u8],
        _score_threshold: f32,
    ) -> praecise_onnx::Result<DetectResult> {
        Err(praecise_onnx::Error::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
    fn num_classes(&self) -> u32 {
        0
    }
}

/// Runtime that owns multiple loaded detection models.
pub struct DetectionRuntime {
    models: EngineModels<dyn Detector>,
}

impl Default for DetectionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("detection"), host),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Detector>) -> Result<()> {
        self.models.insert(model_id, model)
    }

    /// Load an ONNX detector from disk and register it under `model_id`.
    /// The caller is responsible for picking the correct `DetrFamily` based
    /// on the catalog entry's `family` field.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        family: DetrFamily,
        input_size: u32,
        num_classes: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = GenericDetrDetector::from_onnx(path, family, input_size, num_classes)?;
            Ok(Arc::new(model) as Arc<dyn Detector>)
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

    pub async fn detect(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        score_threshold: f32,
    ) -> Result<DetectResult> {
        self.models
            .run(model_id, move |model| {
                model
                    .detect(&image_bytes, score_threshold)
                    .map_err(ModelError::from)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock detector that returns a deterministic synthetic result. Used to
    /// exercise the runtime's dispatch and dashmap bookkeeping without
    /// loading an ONNX file.
    struct ConstantDetector {
        input_size: u32,
        num_classes: u32,
    }
    impl Detector for ConstantDetector {
        fn detect(
            &self,
            _image_bytes: &[u8],
            _threshold: f32,
        ) -> praecise_onnx::Result<DetectResult> {
            Ok(DetectResult {
                detections: vec![Detection {
                    bbox: [0.0, 0.0, 10.0, 10.0],
                    label_id: 1,
                    label: Some("person".into()),
                    score: 0.99,
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            self.input_size
        }
        fn num_classes(&self) -> u32 {
            self.num_classes
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = DetectionRuntime::new();
        assert!(rt.loaded_models().is_empty());
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = DetectionRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_detector_returns_provider_not_available() {
        let stub = StubDetector;
        let res = stub.detect(&[], 0.5);
        assert!(matches!(
            res,
            Err(praecise_onnx::Error::ProviderNotAvailable(_))
        ));
    }

    #[tokio::test]
    async fn detect_on_unknown_model_returns_not_found() {
        let rt = DetectionRuntime::new();
        let res = rt.detect("missing", vec![], 0.5).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_detector() {
        let rt = DetectionRuntime::new();
        rt.register(
            "test-model",
            Arc::new(ConstantDetector {
                input_size: 640,
                num_classes: 80,
            }),
        )
        .unwrap();
        let r = rt.detect("test-model", vec![1, 2, 3], 0.0).await.unwrap();
        assert_eq!(r.detections.len(), 1);
        assert_eq!(r.detections[0].label_id, 1);
        assert!((r.detections[0].score - 0.99).abs() < 1e-6);
    }

    #[test]
    fn detection_serializes_round_trip() {
        let d = Detection {
            bbox: [1.0, 2.0, 3.0, 4.0],
            label_id: 0,
            label: Some("person".into()),
            score: 0.95,
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Detection = serde_json::from_str(&s).unwrap();
        assert_eq!(back.bbox, d.bbox);
        assert_eq!(back.label_id, d.label_id);
    }
}
