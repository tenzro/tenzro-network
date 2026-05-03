//! Object detection runtime backed by ONNX Runtime.
//!
//! Stub-only in wave 1. The runtime registry, prompt types, and result
//! types are stable; concrete ORT-backed `GenericDetector` lands when
//! the catalog's RF-DETR / D-FINE entries have verified ONNX exports.
//!
//! # Output
//!
//! DETR-family detectors are NMS-free: just sigmoid the class logits
//! and threshold by score. RF-DETR (ICLR 2026) is the first real-time
//! detector to break >60 AP on COCO.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A single detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Bounding box in input-image pixel coordinates: (x0, y0, x1, y1).
    pub bbox: [f32; 4],
    /// Class index (catalog-dependent — COCO uses 0..80).
    pub label_id: u32,
    /// Optional class label string when the registry was loaded with
    /// a labels file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Confidence in [0, 1].
    pub score: f32,
}

/// Result of a detection call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub detections: Vec<Detection>,
    pub generation_time_ms: u64,
}

/// Trait for object detectors.
pub trait Detector: Send + Sync {
    fn detect(&self, image_bytes: &[u8], score_threshold: f32) -> Result<DetectResult>;
    fn input_size(&self) -> u32;
    fn num_classes(&self) -> u32;
}

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
    fn detect(&self, _image_bytes: &[u8], _score_threshold: f32) -> Result<DetectResult> {
        Err(ModelError::ProviderNotAvailable(
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
    models: dashmap::DashMap<String, Arc<dyn Detector>>,
}

impl Default for DetectionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Detector>) {
        self.models.insert(model_id.into(), model);
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

    pub async fn detect(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        score_threshold: f32,
    ) -> Result<DetectResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.detect(&image_bytes, score_threshold))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn detect_on_unknown_model_returns_not_found() {
        let rt = DetectionRuntime::new();
        let res = rt.detect("missing", vec![], 0.5).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
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
