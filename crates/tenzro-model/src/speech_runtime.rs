//! Speech synthesis.
//!
//! A speech model is a GGUF backbone and its audio projector, served in the
//! node process on the Praecise engine, on the same llama.cpp backend and
//! device as every other model this node serves, and claimed and admitted
//! through the node's [`ModelHost`] like them. Samples are decoded in chunks
//! and handed out as they appear, so a reply can start playing before the
//! utterance is finished.

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::mtmd::{MtmdBitmap, MtmdContext, MtmdContextParams, MtmdGenAudioType};
use praecise_runtime::speech::{SpeechRequest, synthesize, wav16};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

/// Context the backbone reads the text and generates in.
const SPEECH_CONTEXT: u32 = 8192;

/// Upper bound on text one request may speak.
pub const MAX_SPEECH_CHARACTERS: usize = 4096;

/// A loaded speech model.
pub struct SpeechModel {
    // Declared before `model`: the projector points into the backbone and is
    // dropped first.
    projector: Mutex<MtmdContext>,
    model: LlamaModel,
    sample_rate: u32,
}

/// What to speak.
#[derive(Debug, Clone)]
pub struct SpeechInput {
    /// The text.
    pub text: String,
    /// Language code, where the model takes one.
    pub language: Option<String>,
    /// Reference audio of the voice (wav, mp3 or flac bytes), where the
    /// operator allows cloning and the model takes it.
    pub speaker_reference: Option<Vec<u8>>,
    /// Seed for every sampler; the same seed, text, voice and weights give
    /// the same samples.
    pub seed: u32,
    /// Upper bound on frames.
    pub max_frames: usize,
}

/// A finished utterance.
#[derive(Debug, Clone)]
pub struct Speech {
    /// 16-bit mono WAV.
    pub wav: Vec<u8>,
    /// Samples per second.
    pub sample_rate: u32,
    /// Length in milliseconds.
    pub duration_ms: u64,
    /// Frames generated.
    pub frames: usize,
}

/// Speech models loaded on this node.
pub struct SpeechRuntime {
    models: EngineModels<SpeechModel>,
}

impl std::fmt::Debug for SpeechRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeechRuntime")
            .field("loaded", &self.loaded())
            .finish()
    }
}

impl Default for SpeechRuntime {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

impl SpeechRuntime {
    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::PraeciseTask("speech"), host),
        }
    }

    /// Load the backbone `gguf` and its audio projector `mmproj` as
    /// `model_id`. Blocking: call from a blocking thread.
    ///
    /// # Errors
    /// [`ModelError::EngineConflict`] when another engine holds the model id,
    /// or the backend's refusal: a projector that generates no audio is not a
    /// speech model.
    pub fn load(&self, model_id: &str, gguf: &Path, mmproj: &Path) -> Result<()> {
        let bytes = std::fs::metadata(gguf)?.len() + std::fs::metadata(mmproj)?.len();
        self.models.load_reserving(model_id, bytes, || {
            let backend = crate::runtime::llama_backend();
            let params = LlamaModelParams::default().with_n_gpu_layers(1000);
            let model = crate::parse_jail::load_llama(&backend, gguf, &params).map_err(|e| {
                ModelError::InvalidModel(format!("speech backbone {model_id}: {e}"))
            })?;
            let mmproj = mmproj.to_str().ok_or_else(|| {
                ModelError::InvalidModel(format!("{model_id}: projector path is not UTF-8"))
            })?;
            // SAFETY: the projector is stored beside `model` in `SpeechModel`,
            // declared first, so it is dropped before the backbone it points into.
            let projector = unsafe {
                MtmdContext::init_from_file(mmproj, &model, &MtmdContextParams::default())
            }
            .map_err(|e| ModelError::InvalidModel(format!("speech projector {model_id}: {e}")))?;
            if projector
                .gen_audio_type()
                .map_err(|e| ModelError::InvalidModel(e.to_string()))?
                == MtmdGenAudioType::None
            {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id}: the projector generates no audio; it is not a speech model"
                )));
            }
            let sample_rate = projector.get_audio_sample_rate().unwrap_or(24_000);
            Ok(Arc::new(SpeechModel {
                projector: Mutex::new(projector),
                model,
                sample_rate,
            }))
        })
    }

    /// Unload a model, giving back its claim. `false` when it was not loaded.
    pub fn unload(&self, model_id: &str) -> bool {
        self.models.remove(model_id)
    }

    /// Ids of the loaded models.
    #[must_use]
    pub fn loaded(&self) -> Vec<String> {
        let mut ids = self.models.ids();
        ids.sort();
        ids
    }

    /// Whether `model_id` is loaded.
    #[must_use]
    pub fn contains(&self, model_id: &str) -> bool {
        self.models.contains(model_id)
    }

    /// Speak `input` with `model_id`, after the caller's access check and a
    /// slot from the node's admission. Each new run of samples goes to
    /// `on_chunk` (sample rate, mono samples in [-1, 1]) as it is decoded.
    ///
    /// # Errors
    /// [`ModelError::AccessDenied`] or [`ModelError::Busy`] from the shared
    /// path, [`ModelError::ModelNotFound`] when the model is not loaded,
    /// [`ModelError::InferenceError`] for empty or oversized text, or the
    /// engine's refusal.
    pub async fn synthesize(
        &self,
        model_id: &str,
        input: SpeechInput,
        mut on_chunk: impl FnMut(u32, &[f32]) + Send + 'static,
    ) -> Result<Speech> {
        if input.text.trim().is_empty() || input.text.chars().count() > MAX_SPEECH_CHARACTERS {
            return Err(ModelError::InferenceError(format!(
                "speech text is 1 to {MAX_SPEECH_CHARACTERS} characters"
            )));
        }
        self.models
            .run(model_id, move |m| {
                let projector = m.projector.lock().map_err(|_| {
                    ModelError::InferenceError("speech projector lock poisoned".into())
                })?;
                let reference = input
                    .speaker_reference
                    .as_deref()
                    .map(|b| MtmdBitmap::from_buffer(&projector, b, false))
                    .transpose()
                    .map_err(|e| ModelError::InferenceError(format!("speaker reference: {e}")))?;
                let backend = crate::runtime::llama_backend();
                let params = LlamaContextParams::default()
                    .with_n_ctx(NonZeroU32::new(SPEECH_CONTEXT))
                    .with_n_batch(512)
                    .with_embeddings(true);
                let mut ctx = m
                    .model
                    .new_context(&backend, params)
                    .map_err(|e| ModelError::InferenceError(format!("speech context: {e}")))?;
                let speech = synthesize(
                    &mut ctx,
                    &projector,
                    &SpeechRequest {
                        text: &input.text,
                        speaker_reference: reference.as_ref(),
                        language: input.language.as_deref(),
                        max_frames: input.max_frames,
                        temperature: 0.9,
                        top_k: 50,
                        top_p: 1.0,
                        seed: input.seed,
                        chunk_frames: 12,
                    },
                    // every chunk is delivered; the utterance runs to its end
                    move |rate, samples| {
                        on_chunk(rate, samples);
                        std::ops::ControlFlow::Continue(())
                    },
                )
                .map_err(|e| ModelError::InferenceError(e.to_string()))?;
                let sample_rate = if speech.sample_rate == 0 {
                    m.sample_rate
                } else {
                    speech.sample_rate
                };
                Ok(Speech {
                    wav: wav16(sample_rate, &speech.samples),
                    sample_rate,
                    duration_ms: (speech.samples.len() as u64 * 1000)
                        / u64::from(sample_rate.max(1)),
                    frames: speech.frames,
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(text: &str) -> SpeechInput {
        SpeechInput {
            text: text.into(),
            language: None,
            speaker_reference: None,
            seed: 1,
            max_frames: 10,
        }
    }

    #[tokio::test]
    async fn speaking_with_a_model_that_is_not_loaded_is_refused() {
        let rt = SpeechRuntime::default();
        let r = rt.synthesize("absent", input("hello"), |_, _| {}).await;
        assert!(matches!(r, Err(ModelError::ModelNotFound(_))), "{r:?}");
    }

    #[tokio::test]
    async fn empty_or_oversized_text_is_refused_before_any_work() {
        let rt = SpeechRuntime::default();
        let empty = rt.synthesize("absent", input("  "), |_, _| {}).await;
        assert!(
            matches!(empty, Err(ModelError::InferenceError(_))),
            "{empty:?}"
        );
        let long = "a".repeat(MAX_SPEECH_CHARACTERS + 1);
        let over = rt.synthesize("absent", input(&long), |_, _| {}).await;
        assert!(
            matches!(over, Err(ModelError::InferenceError(_))),
            "{over:?}"
        );
    }
}
