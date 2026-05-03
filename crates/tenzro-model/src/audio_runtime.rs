//! Audio (ASR-only) runtime backed by ONNX Runtime.
//!
//! Stub-only in wave 1. The runtime registry, request/result types,
//! and trait are stable; concrete ORT-backed implementations land
//! when the catalog's audio entries (Moonshine v2, Distil-Whisper,
//! Whisper-v3-turbo, Parakeet TDT 0.6B v3, Canary 1B Flash) have
//! verified ONNX exports.
//!
//! # Audio formats
//!
//! Real implementation will accept raw bytes (WAV via `hound`,
//! MP3/FLAC via `symphonia`) and resample to 16 kHz mono. Mel
//! spectrogram parameters (n_fft, hop_length, n_mels) differ across
//! Whisper/Moonshine/Parakeet — each runtime owns its own
//! preprocessing.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a transcription request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TranscribeConfig {
    /// Target language (ISO code, e.g. "en", "fr"). `None` = auto-detect
    /// when the model supports it; explicit when the model is single-language.
    #[serde(default)]
    pub language: Option<String>,
    /// Emit per-token timestamps when supported.
    #[serde(default)]
    pub timestamps: bool,
    /// Optional decoding temperature for sampling-capable models.
    #[serde(default)]
    pub temperature: Option<f32>,
}

/// A single transcript segment with optional timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptSegment {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_seconds: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_seconds: Option<f32>,
}

/// Result of a transcription call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscribeResult {
    /// Concatenated transcript text.
    pub text: String,
    /// Optional per-segment breakdown when `timestamps=true`.
    #[serde(default)]
    pub segments: Vec<TranscriptSegment>,
    /// Detected language (when auto-detection runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub generation_time_ms: u64,
}

/// Trait for ASR models.
pub trait Transcriber: Send + Sync {
    fn transcribe(&self, audio_bytes: &[u8], config: &TranscribeConfig) -> Result<TranscribeResult>;
    fn sample_rate(&self) -> u32;
    fn max_audio_seconds(&self) -> u32;
}

/// Stub transcriber for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubTranscriber;

impl StubTranscriber {
    pub fn from_onnx(
        _encoder: impl AsRef<Path>,
        _decoder: Option<&Path>,
        _joiner: Option<&Path>,
    ) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl Transcriber for StubTranscriber {
    fn transcribe(
        &self,
        _audio_bytes: &[u8],
        _config: &TranscribeConfig,
    ) -> Result<TranscribeResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn sample_rate(&self) -> u32 {
        0
    }
    fn max_audio_seconds(&self) -> u32 {
        0
    }
}

/// Runtime that owns multiple loaded ASR models.
pub struct AudioRuntime {
    models: dashmap::DashMap<String, Arc<dyn Transcriber>>,
}

impl Default for AudioRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Transcriber>) {
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

    pub async fn transcribe(
        &self,
        model_id: &str,
        audio_bytes: Vec<u8>,
        config: TranscribeConfig,
    ) -> Result<TranscribeResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.transcribe(&audio_bytes, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let rt = AudioRuntime::new();
        assert!(rt.loaded_models().is_empty());
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = AudioRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_transcriber_returns_provider_not_available() {
        let stub = StubTranscriber;
        let res = stub.transcribe(&[], &TranscribeConfig::default());
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn transcribe_on_unknown_model_returns_not_found() {
        let rt = AudioRuntime::new();
        let res = rt
            .transcribe("missing", vec![], TranscribeConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[test]
    fn segment_serializes_round_trip() {
        let s = TranscriptSegment {
            text: "hello".into(),
            start_seconds: Some(0.0),
            end_seconds: Some(1.0),
        };
        let json = serde_json::to_string(&s).unwrap();
        let _: TranscriptSegment = serde_json::from_str(&json).unwrap();
    }
}
