//! Audio (ASR) runtime backed by ONNX Runtime.
//!
//! Four concrete transcriber families cover the full catalog:
//!
//! - **Moonshine v2** (`MoonshineTranscriber`) — raw 16 kHz waveform input,
//!   encoder + autoregressive decoder loop with merged-decoder KV-cache
//!   (`use_cache_branch` bool input). Single output `last_hidden_state`
//!   per step → argmax token → SentencePiece detokenize.
//! - **Distil-Whisper** small.en / medium.en / large-v3 and **Whisper
//!   large-v3-turbo** (`WhisperTranscriber`) — 80 or 128 log-mel
//!   spectrogram input, encoder + autoregressive decoder loop with
//!   `use_cache_branch` merged decoder. BPE detokenize.
//! - **NeMo Parakeet TDT 0.6B v3** (`ParakeetTranscriber`) — Token-and-
//!   Duration Transducer. Three ORT sessions: NeMo-exported 128-mel
//!   preprocessor (`waveforms` → `features`), Conformer encoder
//!   (`audio_signal` → `outputs, encoded_lengths`), fused
//!   decoder+joint network (vocab + duration logits per step, two LSTM
//!   states). Inner loop emits up to `max_tokens_per_step` per encoder
//!   frame; duration logits select how many frames to skip.
//!   `vocab.txt` is parsed line-by-line (`token id`, last entry
//!   `<blk> N` marks the blank index).
//! - **NVIDIA Canary 1B Flash** (`CanaryTranscriber`) — NeMo Conformer
//!   AED (attention encoder-decoder). Supports English, German, Spanish,
//!   French with cross-lingual translation. SentencePiece detokenize.
//!
//! `AudioRuntime` exposes `load_moonshine`, `load_whisper`,
//! `load_parakeet`, and `load_canary` to construct these from on-disk
//! ONNX bundles produced by Optimum / transformers.js /
//! istupakov-onnx-asr / NeMo exports.

use std::path::Path;
use std::sync::Arc;

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::audio::{
    CanaryTranscriber, MoonshineTranscriber, ParakeetTranscriber, TranscribeConfig,
    TranscribeResult, Transcriber, TranscriptSegment, WhisperFamily, WhisperTranscriber,
};

/// Runtime that owns multiple loaded ASR models.
pub struct AudioRuntime {
    models: EngineModels<dyn Transcriber>,
}

impl Default for AudioRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("audio"), host),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Transcriber>) -> Result<()> {
        self.models.insert(model_id, model)
    }

    /// Load a Moonshine v2 ASR model from a downloaded HF bundle.
    /// `encoder_path` and `decoder_path` are the encoder/decoder ONNX files;
    /// `tokenizer_path` is the SentencePiece-derived `tokenizer.json`.
    pub fn load_moonshine(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = MoonshineTranscriber::from_onnx(
                encoder_path,
                decoder_path,
                tokenizer_path,
                max_audio_seconds,
            )?;
            Ok(Arc::new(model) as Arc<dyn Transcriber>)
        })
    }

    /// Load a Whisper-family ASR model (Distil-Whisper or Whisper-turbo).
    pub fn load_whisper(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        family: WhisperFamily,
        max_audio_seconds: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = WhisperTranscriber::from_onnx(
                encoder_path,
                decoder_path,
                tokenizer_path,
                family,
                max_audio_seconds,
            )?;
            Ok(Arc::new(model) as Arc<dyn Transcriber>)
        })
    }

    /// Load a NeMo Parakeet TDT 0.6B v3 ASR model from a downloaded
    /// istupakov-style ONNX bundle. Inputs:
    /// - `preprocessor_path`: `nemo128.onnx` (waveform → 128-mel features).
    /// - `encoder_path`: `encoder-model.onnx`.
    /// - `decoder_joint_path`: `decoder_joint-model.onnx`.
    /// - `vocab_path`: `vocab.txt` (`token id` per line, trailing `<blk>`).
    pub fn load_parakeet(
        &self,
        model_id: impl Into<String>,
        preprocessor_path: impl AsRef<Path>,
        encoder_path: impl AsRef<Path>,
        decoder_joint_path: impl AsRef<Path>,
        vocab_path: impl AsRef<Path>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = ParakeetTranscriber::from_onnx(
                preprocessor_path,
                encoder_path,
                decoder_joint_path,
                vocab_path,
                max_audio_seconds,
            )?;
            Ok(Arc::new(model) as Arc<dyn Transcriber>)
        })
    }

    /// Load an NVIDIA Canary-1B-Flash AED ASR model from a downloaded
    /// istupakov-style ONNX bundle. Inputs:
    /// - `preprocessor_path`: `nemo128.onnx` (shared with Parakeet —
    ///   waveform → 128-mel features).
    /// - `encoder_path`: `encoder-model.onnx` (NeMo Conformer encoder).
    /// - `decoder_path`: `decoder-model.onnx` (cross-attention AED decoder).
    /// - `vocab_path`: `vocab.txt` (`token id` per line, 5249 tokens
    ///   including `<|endoftext|>` and the language/task control tags).
    /// - `source_lang` / `target_lang`: ISO codes (`"en"`, `"de"`,
    ///   `"es"`, `"fr"`) used to build the 10-token decoder prefix.
    pub fn load_canary(
        &self,
        model_id: impl Into<String>,
        preprocessor_path: impl AsRef<Path>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        vocab_path: impl AsRef<Path>,
        source_lang: impl Into<String>,
        target_lang: impl Into<String>,
        max_audio_seconds: u32,
    ) -> Result<()> {
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = CanaryTranscriber::from_onnx(
                preprocessor_path,
                encoder_path,
                decoder_path,
                vocab_path,
                source_lang,
                target_lang,
                max_audio_seconds,
            )?;
            Ok(Arc::new(model) as Arc<dyn Transcriber>)
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

    pub async fn transcribe(
        &self,
        model_id: &str,
        audio_bytes: Vec<u8>,
        config: TranscribeConfig,
    ) -> Result<TranscribeResult> {
        self.models
            .run(model_id, move |model| {
                model
                    .transcribe(&audio_bytes, &config)
                    .map_err(ModelError::from)
            })
            .await
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

    #[test]
    fn whisper_family_n_mels() {
        assert_eq!(WhisperFamily::DistilEn.n_mels(), 80);
        assert_eq!(WhisperFamily::DistilLargeV3.n_mels(), 128);
        assert_eq!(WhisperFamily::LargeV3Turbo.n_mels(), 128);
        assert!(!WhisperFamily::DistilEn.is_multilingual());
        assert!(WhisperFamily::DistilLargeV3.is_multilingual());
        assert!(WhisperFamily::LargeV3Turbo.is_multilingual());
    }
}
