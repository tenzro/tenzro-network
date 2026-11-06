//! Spoken replies from omni models.
//!
//! An omni model is two GGUF pairs from one checkpoint: the thinker, which
//! reads the conversation (text and audio) and writes the reply, and the
//! talker, which speaks the reply while it is being written. Both run in the
//! node process on the Praecise engine, on the same backend and device as
//! every other model this node serves, claimed and admitted through the
//! node's [`ModelHost`]. Reply text and audio reach the caller as they are
//! made, and the caller can stop a turn mid-sentence (a listener talking over
//! it).

use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::{Arc, Mutex};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{LlamaChatMessage, LlamaModel};
use llama_cpp_2::mtmd::{
    MtmdBitmap, MtmdContext, MtmdContextParams, MtmdGenAudioType, mtmd_default_marker,
};
use praecise_runtime::omni::{ReplySampling, TurnRequest, VoiceSampling, speak_turn};

use crate::error::{ModelError, Result};

use crate::model_host::{Engine, EngineModels, ModelHost};
pub use praecise_runtime::duplex::{DuplexConfig, DuplexEvent, DuplexSession};
pub use praecise_runtime::speech::wav16;

/// Context the thinker reads the conversation and writes in.
const THINKER_CONTEXT: u32 = 16_384;
/// Positions one decode takes; an audio clip is read in one decode.
const THINKER_BATCH: u32 = 4096;
/// Context the talker speaks in: its prompt plus one position per frame.
const TALKER_CONTEXT: u32 = 8192;

/// Upper bound on the conversation's text.
pub const MAX_TURN_CHARACTERS: usize = 32_768;
/// Upper bound on audio heard in one turn.
pub const MAX_TURN_AUDIO_MS: u64 = 120_000;

/// A loaded omni model.
pub struct OmniModel {
    // Declared before the models: each projector points into its backbone
    // and is dropped first.
    thinker_projector: Mutex<MtmdContext>,
    talker_projector: Mutex<MtmdContext>,
    thinker: LlamaModel,
    talker: LlamaModel,
    sample_rate: u32,
}

/// One message of the conversation.
#[derive(Debug, Clone)]
pub struct OmniMessage {
    /// `system`, `user` or `assistant`.
    pub role: String,
    /// The text.
    pub text: String,
    /// Audio clips (wav, mp3 or flac bytes) the message carries, heard before
    /// its text.
    pub audio: Vec<Vec<u8>>,
}

/// What to answer, and how.
#[derive(Debug, Clone)]
pub struct OmniInput {
    /// The conversation so far, ending with the user's turn.
    pub messages: Vec<OmniMessage>,
    /// Voice name.
    pub voice: String,
    /// Seed for every sampler; the same seed, conversation, voice and weights
    /// give the same reply and samples.
    pub seed: u32,
    /// Upper bound on reply tokens.
    pub max_reply_tokens: usize,
    /// Upper bound on audio frames.
    pub max_frames: usize,
}

/// A finished (or stopped) turn.
#[derive(Debug, Clone)]
pub struct OmniTurn {
    /// The reply as written.
    pub text: String,
    /// The reply as spoken, 16-bit mono WAV.
    pub wav: Vec<u8>,
    /// Samples per second.
    pub sample_rate: u32,
    /// Length of the spoken reply in milliseconds.
    pub duration_ms: u64,
    /// Audio frames generated.
    pub frames: usize,
    /// Tokens the thinker read.
    pub prompt_tokens: usize,
    /// Tokens the thinker wrote.
    pub reply_tokens: usize,
    /// Audio heard, in milliseconds.
    pub audio_in_ms: u64,
    /// The caller stopped the turn before the model finished it.
    pub interrupted: bool,
}

/// Omni models loaded on this node.
pub struct OmniRuntime {
    models: EngineModels<OmniModel>,
}

impl std::fmt::Debug for OmniRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OmniRuntime")
            .field("loaded", &self.loaded())
            .finish()
    }
}

impl Default for OmniRuntime {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

fn invalid(what: impl std::fmt::Display) -> ModelError {
    ModelError::InferenceError(what.to_string())
}

/// The longest prefix of `bytes` that is whole UTF-8.
fn utf8_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    }
}

impl OmniRuntime {
    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::PraeciseTask("omni"), host),
        }
    }

    /// Load the thinker (`thinker`, `thinker_mmproj`) and the talker
    /// (`talker`, `talker_mmproj`) as `model_id`. Blocking: call from a
    /// blocking thread.
    ///
    /// # Errors
    /// [`ModelError::EngineConflict`] when another engine holds the model id,
    /// or the backend's refusal: a talker projector that does not speak a
    /// reading model's reply, or a thinker projector without audio input.
    pub fn load(
        &self,
        model_id: &str,
        thinker: &Path,
        thinker_mmproj: &Path,
        talker: &Path,
        talker_mmproj: &Path,
    ) -> Result<()> {
        let mut bytes = 0;
        for p in [thinker, thinker_mmproj, talker, talker_mmproj] {
            bytes += std::fs::metadata(p)?.len();
        }
        self.models.load_reserving(model_id, bytes, || {
            let backend = crate::runtime::llama_backend();
            let params = LlamaModelParams::default().with_n_gpu_layers(1000);
            let load = |path: &Path, what: &str| {
                crate::parse_jail::load_llama(&backend, path, &params)
                    .map_err(|e| ModelError::InvalidModel(format!("{what} {model_id}: {e}")))
            };
            let thinker_model = load(thinker, "omni thinker")?;
            let talker_model = load(talker, "omni talker")?;
            let path_str = |p: &Path| {
                p.to_str().map(str::to_owned).ok_or_else(|| {
                    ModelError::InvalidModel(format!("{model_id}: projector path is not UTF-8"))
                })
            };
            // SAFETY: each projector is stored beside its backbone in
            // `OmniModel`, declared first, so it is dropped before the backbone
            // it points into.
            let thinker_projector = unsafe {
                MtmdContext::init_from_file(
                    &path_str(thinker_mmproj)?,
                    &thinker_model,
                    &MtmdContextParams::default(),
                )
            }
            .map_err(|e| {
                ModelError::InvalidModel(format!("omni thinker projector {model_id}: {e}"))
            })?;
            if !thinker_projector.support_audio() {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id}: the thinker's projector takes no audio"
                )));
            }
            // SAFETY: as above.
            let talker_projector = unsafe {
                MtmdContext::init_from_file(
                    &path_str(talker_mmproj)?,
                    &talker_model,
                    &MtmdContextParams::default(),
                )
            }
            .map_err(|e| {
                ModelError::InvalidModel(format!("omni talker projector {model_id}: {e}"))
            })?;
            if talker_projector
                .gen_audio_type()
                .map_err(|e| ModelError::InvalidModel(e.to_string()))?
                != MtmdGenAudioType::Qwen3Omni
            {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id}: the talker's projector does not speak a reading model's reply"
                )));
            }
            let sample_rate = talker_projector.get_audio_sample_rate().unwrap_or(24_000);
            Ok(Arc::new(OmniModel {
                thinker_projector: Mutex::new(thinker_projector),
                talker_projector: Mutex::new(talker_projector),
                thinker: thinker_model,
                talker: talker_model,
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

    /// Answer `input` with `model_id` in speech, after the caller's access
    /// check and a slot from the node's admission. `on_text` receives the
    /// reply text as it is written, `on_audio` the speech as it is decoded;
    /// `on_audio` stops the turn by returning [`ControlFlow::Break`].
    ///
    /// # Errors
    /// [`ModelError::AccessDenied`] or [`ModelError::Busy`] from the shared
    /// path, [`ModelError::ModelNotFound`] when the model is not loaded,
    /// [`ModelError::InferenceError`] for an empty or oversized conversation,
    /// undecodable audio, or the engine's refusal.
    pub async fn speak_turn(
        &self,
        model_id: &str,
        input: OmniInput,
        mut on_text: impl FnMut(&str) + Send + 'static,
        on_audio: impl FnMut(u32, &[f32]) -> ControlFlow<()> + Send + 'static,
    ) -> Result<OmniTurn> {
        let chars: usize = input.messages.iter().map(|m| m.text.chars().count()).sum();
        if input.messages.is_empty() || chars > MAX_TURN_CHARACTERS {
            return Err(invalid(format!(
                "a turn has at least one message and at most {MAX_TURN_CHARACTERS} characters of text"
            )));
        }
        if input.messages.last().map(|m| m.role.as_str()) != Some("user") {
            return Err(invalid("the conversation ends with the user's turn"));
        }
        if input.voice.trim().is_empty() {
            return Err(invalid("a voice is required"));
        }
        self.models
            .run(model_id, move |m| {
                let thinker_projector = m
                    .thinker_projector
                    .lock()
                    .map_err(|_| invalid("omni thinker projector lock poisoned"))?;
                let talker_projector = m
                    .talker_projector
                    .lock()
                    .map_err(|_| invalid("omni talker projector lock poisoned"))?;

                // the audio clips, each heard before its message's text
                let mut clips = Vec::new();
                let mut chat = Vec::with_capacity(input.messages.len());
                let mut audio_in_ms = 0u64;
                for msg in &input.messages {
                    let mut content = String::new();
                    for bytes in &msg.audio {
                        let clip = MtmdBitmap::from_buffer(&thinker_projector, bytes, false)
                            .map_err(|e| invalid(format!("audio: {e}")))?;
                        if !clip.is_audio() {
                            return Err(invalid("a message's clip is not audio"));
                        }
                        let rate = thinker_projector
                            .get_audio_sample_rate()
                            .unwrap_or(16_000)
                            .max(1);
                        audio_in_ms += u64::from(clip.nx()) * 1000 / u64::from(rate);
                        clips.push(clip);
                        content.push_str(mtmd_default_marker());
                    }
                    content.push_str(&msg.text);
                    chat.push(
                        LlamaChatMessage::new(msg.role.clone(), content)
                            .map_err(|e| invalid(format!("message: {e}")))?,
                    );
                }
                if audio_in_ms > MAX_TURN_AUDIO_MS {
                    return Err(invalid(format!(
                        "a turn hears at most {} s of audio",
                        MAX_TURN_AUDIO_MS / 1000
                    )));
                }
                let template = m
                    .thinker
                    .chat_template(None)
                    .map_err(|e| invalid(format!("the thinker has no chat template: {e}")))?;
                let prompt = m
                    .thinker
                    .apply_chat_template(&template, &chat, true)
                    .map_err(|e| invalid(format!("chat template: {e}")))?;

                let backend = crate::runtime::llama_backend();
                let mut thinker_ctx = m
                    .thinker
                    .new_context(
                        &backend,
                        LlamaContextParams::default()
                            .with_n_ctx(NonZeroU32::new(THINKER_CONTEXT))
                            .with_n_batch(THINKER_BATCH)
                            .with_n_ubatch(THINKER_BATCH),
                    )
                    .map_err(|e| invalid(format!("omni thinker context: {e}")))?;
                let mut talker_ctx = m
                    .talker
                    .new_context(
                        &backend,
                        LlamaContextParams::default()
                            .with_n_ctx(NonZeroU32::new(TALKER_CONTEXT))
                            .with_n_batch(512)
                            .with_embeddings(true),
                    )
                    .map_err(|e| invalid(format!("omni talker context: {e}")))?;

                let refs: Vec<&MtmdBitmap> = clips.iter().collect();
                let thinker = &m.thinker;
                let mut text_bytes: Vec<u8> = Vec::new();
                let mut sent = 0usize;
                let turn = speak_turn(
                    &mut thinker_ctx,
                    &thinker_projector,
                    &mut talker_ctx,
                    &talker_projector,
                    &TurnRequest {
                        prompt: &prompt,
                        audio: &refs,
                        max_reply_tokens: input.max_reply_tokens,
                        reply: ReplySampling {
                            temperature: 0.7,
                            top_k: 20,
                            top_p: 0.8,
                            seed: input.seed,
                        },
                        voice: VoiceSampling {
                            voice: &input.voice,
                            max_frames: input.max_frames,
                            temperature: 0.9,
                            top_k: 50,
                            top_p: 1.0,
                            projector_top_p: 0.8,
                            repetition_penalty: 1.05,
                            seed: input.seed,
                            chunk_frames: 6,
                        },
                    },
                    |token| {
                        if thinker.is_eog_token(token) {
                            return;
                        }
                        if let Ok(piece) = thinker.token_to_piece_bytes(token, 64, false, None) {
                            text_bytes.extend_from_slice(&piece);
                            let whole = utf8_prefix(&text_bytes);
                            if whole.len() > sent {
                                on_text(&whole[sent..]);
                                sent = whole.len();
                            }
                        }
                    },
                    on_audio,
                )
                .map_err(|e| invalid(e.to_string()))?;
                let sample_rate = if turn.speech.sample_rate == 0 {
                    m.sample_rate
                } else {
                    turn.speech.sample_rate
                };
                Ok(OmniTurn {
                    text: String::from_utf8_lossy(&text_bytes).into_owned(),
                    wav: wav16(sample_rate, &turn.speech.samples),
                    sample_rate,
                    duration_ms: (turn.speech.samples.len() as u64 * 1000)
                        / u64::from(sample_rate.max(1)),
                    frames: turn.speech.frames,
                    prompt_tokens: turn.prompt_tokens,
                    reply_tokens: turn.reply_tokens.len(),
                    audio_in_ms,
                    interrupted: turn.speech.interrupted,
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(messages: Vec<OmniMessage>) -> OmniInput {
        OmniInput {
            messages,
            voice: "ethan".into(),
            seed: 1,
            max_reply_tokens: 16,
            max_frames: 16,
        }
    }

    fn user(text: &str) -> OmniMessage {
        OmniMessage {
            role: "user".into(),
            text: text.into(),
            audio: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_turn_with_a_model_that_is_not_loaded_is_refused() {
        let rt = OmniRuntime::default();
        let r = rt
            .speak_turn(
                "absent",
                input(vec![user("hello")]),
                |_| {},
                |_, _| ControlFlow::Continue(()),
            )
            .await;
        assert!(matches!(r, Err(ModelError::ModelNotFound(_))), "{r:?}");
    }

    #[tokio::test]
    async fn malformed_turns_are_refused_before_any_work() {
        let rt = OmniRuntime::default();
        let empty = rt
            .speak_turn(
                "absent",
                input(Vec::new()),
                |_| {},
                |_, _| ControlFlow::Continue(()),
            )
            .await;
        assert!(
            matches!(empty, Err(ModelError::InferenceError(_))),
            "{empty:?}"
        );
        let mut assistant_last = input(vec![user("hi")]);
        assistant_last.messages.push(OmniMessage {
            role: "assistant".into(),
            text: "hello".into(),
            audio: Vec::new(),
        });
        let r = rt
            .speak_turn(
                "absent",
                assistant_last,
                |_| {},
                |_, _| ControlFlow::Continue(()),
            )
            .await;
        assert!(matches!(r, Err(ModelError::InferenceError(_))), "{r:?}");
        let long = "a".repeat(MAX_TURN_CHARACTERS + 1);
        let r = rt
            .speak_turn(
                "absent",
                input(vec![user(&long)]),
                |_| {},
                |_, _| ControlFlow::Continue(()),
            )
            .await;
        assert!(matches!(r, Err(ModelError::InferenceError(_))), "{r:?}");
    }

    #[test]
    fn reply_text_is_handed_out_on_whole_characters() {
        assert_eq!(utf8_prefix("héllo".as_bytes()), "héllo");
        let e = "é".as_bytes();
        assert_eq!(utf8_prefix(&[b'a', e[0]]), "a");
    }
}
