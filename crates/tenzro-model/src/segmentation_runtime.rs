//! Segmentation runtime backed by ONNX Runtime.
//!
//! This module is gated behind the `onnx` cargo feature. When the
//! feature is off, a stub is exposed.
//!
//! # Scope
//!
//! SAM-family models (SAM 3, SAM 2, EdgeSAM, MobileSAM) split into:
//!
//! - **Image encoder**: image → embedding tensor `[1, C, H, W]`
//!   (cached per image — expensive, ~95% of total cost).
//! - **Prompt decoder**: embedding + prompt (point/box/mask) →
//!   per-prompt mask `[1, H, W]` (cheap, run once per query).
//!
//! API: `segment(model_id, image, prompts) -> Vec<Mask>`. Masks are
//! returned at input resolution as flat `[H * W]` u8 buffers (0/1).
//!
//! # Threading
//!
//! Per-session `parking_lot::Mutex` + `spawn_blocking`. Encoder and
//! decoder share a single `Mutex` per model — they're called
//! sequentially per request, so the contention pattern is identical
//! to single-session models.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A point prompt for segmentation. Points anchor the mask to a target
/// pixel; the `is_foreground` flag distinguishes "this is the object"
/// (true) from "this is background" (false).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointPrompt {
    pub x: f32,
    pub y: f32,
    pub is_foreground: bool,
}

/// A bounding-box prompt for segmentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxPrompt {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

/// A unified segmentation prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SegmentPrompt {
    Point(PointPrompt),
    Box(BoxPrompt),
    Points(Vec<PointPrompt>),
}

/// A single output mask from a segmentation call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMask {
    /// Width of the mask in pixels.
    pub width: u32,
    /// Height of the mask in pixels.
    pub height: u32,
    /// Flat `[H * W]` u8 buffer (0 = background, 1 = foreground).
    pub mask: Vec<u8>,
    /// Predicted IoU / confidence score for this mask, in `[0, 1]`.
    pub score: f32,
}

/// Result of a segmentation call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentResult {
    pub masks: Vec<SegmentMask>,
    pub generation_time_ms: u64,
}

/// Trait for segmentation models.
pub trait Segmenter: Send + Sync {
    fn segment(&self, image_bytes: &[u8], prompts: &[SegmentPrompt]) -> Result<SegmentResult>;
    fn input_size(&self) -> u32;
}

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
    fn segment(&self, _image_bytes: &[u8], _prompts: &[SegmentPrompt]) -> Result<SegmentResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
}

/// Runtime that owns multiple loaded segmentation models.
pub struct SegmentationRuntime {
    models: dashmap::DashMap<String, Arc<dyn Segmenter>>,
}

impl Default for SegmentationRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentationRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Segmenter>) {
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

    pub async fn segment(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        prompts: Vec<SegmentPrompt>,
    ) -> Result<SegmentResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.segment(&image_bytes, &prompts))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn segment_on_unknown_model_returns_not_found() {
        let rt = SegmentationRuntime::new();
        let res = rt.segment("missing", vec![], vec![]).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
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
