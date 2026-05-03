//! Video encoder runtime backed by ONNX Runtime.
//!
//! Stub-only in wave 1. The runtime registry, request/result types, and
//! trait are stable; concrete entries land when a permissive,
//! ONNX-shippable, encoder-only video model is verified (see
//! `catalog::get_video_catalog` — currently empty).
//!
//! As of April 2026 the OSS landscape has no permissive +
//! ONNX-shippable encoder. VideoMAE v1/v2 are CC-BY-NC; V-JEPA 2/2.1
//! license is unclear and ONNX export is non-trivial. The runtime
//! ships empty so adding entries later is mechanical.
//!
//! # Frame extraction
//!
//! Real implementation will shell out to `ffmpeg` for frame extraction
//! (simpler container builds than vendoring `ffmpeg-next`).

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a video-embedding request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoEmbedConfig {
    /// L2-normalize the output embedding.
    #[serde(default)]
    pub normalize: bool,
    /// Optional frame stride override (default: model's native fps).
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
        let res = rt.embed("missing", vec![], VideoEmbedConfig::default()).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }
}
