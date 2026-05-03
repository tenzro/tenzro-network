//! Text embedding runtime backed by ONNX Runtime.
//!
//! This module is gated behind the `onnx` cargo feature. When the feature
//! is off, a stub is exposed so callers compile and surface a clean
//! "ONNX backend not enabled" error at runtime — same shape as the real
//! implementation.
//!
//! # Scope
//!
//! Foundation text encoders in 2026 (Qwen3-Embedding 0.6B/4B/8B,
//! EmbeddingGemma 300M, BGE-M3, Snowflake Arctic) all share a similar
//! interface: a `[B, L]` int64 token tensor plus an `[B, L]` int64
//! attention-mask tensor go in, an `[B, D]` float embedding tensor
//! comes out (after pooling).
//!
//! EmbeddingGemma additionally supports Matryoshka truncation (768 → 512
//! → 256 → 128) — the runtime slices and re-normalizes after pooling
//! when a smaller `requested_dim` is set.
//!
//! # Threading
//!
//! `TextEmbeddingRuntime` is `Send + Sync` and holds loaded ONNX
//! sessions in a `DashMap` keyed by model_id. ORT sessions are not
//! safe to call concurrently, so each session lives behind a
//! `parking_lot::Mutex`. Inference is dispatched through
//! `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a text-embedding request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextEmbedConfig {
    /// Optional Matryoshka dimension. Must be one of the `matryoshka_dims`
    /// declared by the catalog entry, or `None` for the native dim.
    #[serde(default)]
    pub requested_dim: Option<u32>,
    /// L2-normalize the output embedding. Most retrieval pipelines want
    /// this on; downstream classification heads want it off.
    #[serde(default)]
    pub normalize: bool,
}

/// Result of a text-embedding call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbedResult {
    /// Embedding vectors, one per input string. Outer length =
    /// `inputs.len()`, inner length = effective embedding dim
    /// (post-Matryoshka if requested).
    pub embeddings: Vec<Vec<f32>>,
    /// Effective embedding dim used (after Matryoshka truncation).
    pub dim: usize,
    /// Total inference wall time in milliseconds (tokenize + ORT run).
    pub generation_time_ms: u64,
}

/// Trait for text encoders. Implementations adapt model-specific
/// tokenization and pooling to a common signature.
pub trait TextEncoder: Send + Sync {
    /// Encode a batch of strings to dense vectors.
    fn embed(&self, inputs: &[String], config: &TextEmbedConfig) -> Result<TextEmbedResult>;

    /// Native embedding dimension (before any Matryoshka truncation).
    fn embedding_dim(&self) -> usize;

    /// Maximum sequence length the tokenizer will produce.
    fn max_sequence_length(&self) -> usize;
}

/// Stub text encoder used when the `onnx` feature is not compiled in.
/// Constructing it returns an error so callers can detect the missing
/// backend before wiring it through registries.
#[derive(Debug)]
pub struct StubTextEncoder;

impl StubTextEncoder {
    pub fn from_onnx(_path: impl AsRef<Path>, _tokenizer_path: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl TextEncoder for StubTextEncoder {
    fn embed(&self, _inputs: &[String], _config: &TextEmbedConfig) -> Result<TextEmbedResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn embedding_dim(&self) -> usize {
        0
    }
    fn max_sequence_length(&self) -> usize {
        0
    }
}

/// Runtime that owns multiple loaded text encoders, keyed by model_id.
///
/// Mirrors `VisionRuntime` / `TimeseriesRuntime` shape. Wave 1 ships
/// the registry + stub backend; the ORT-backed real implementation
/// lands when the catalog's text-embedding entries have verified ONNX
/// exports on HuggingFace.
pub struct TextEmbeddingRuntime {
    models: dashmap::DashMap<String, Arc<dyn TextEncoder>>,
}

impl Default for TextEmbeddingRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEmbeddingRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    /// Register a pre-loaded encoder under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn TextEncoder>) {
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

    /// Embed strings with a registered encoder. Dispatched to
    /// `spawn_blocking` so the async caller's runtime isn't stalled.
    pub async fn embed(
        &self,
        model_id: &str,
        inputs: Vec<String>,
        config: TextEmbedConfig,
    ) -> Result<TextEmbedResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.embed(&inputs, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let rt = TextEmbeddingRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = TextEmbeddingRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_encoder_returns_provider_not_available() {
        let stub = StubTextEncoder;
        let res = stub.embed(&["hello".into()], &TextEmbedConfig::default());
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn embed_on_unknown_model_returns_not_found() {
        let rt = TextEmbeddingRuntime::new();
        let res = rt.embed("missing", vec!["x".into()], TextEmbedConfig::default()).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }
}
