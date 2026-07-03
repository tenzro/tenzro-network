//! Continuous batching engine for GGUF text generation.
//!
//! The naive serving model creates a fresh `llama_context` per request and
//! serializes every decode behind one mutex, so N concurrent requests decode
//! strictly one after another. This engine instead holds a single long-lived
//! `llama_context` per model with a fixed pool of sequence slots and interleaves
//! every active request into one `llama_decode` per step. Throughput scales with
//! the number of active sequences because a decode over K sequences costs close
//! to a decode over one — the same weight matrices are read once and applied to
//! K token rows.
//!
//! ## Slot model
//!
//! The context is built with `n_seq_max = MAX_SLOTS` KV-cache sequence slots.
//! Each in-flight request owns one slot (its `seq_id`). A request's KV history
//! lives under its `seq_id`; when it finishes, `clear_kv_cache_seq` frees that
//! slot's KV so a waiting request can take it.
//!
//! ## Scheduler loop
//!
//! One dedicated OS thread per model owns the `LlamaModel` and its
//! `LlamaContext` together (they share one stack, so the context's borrow of the
//! model is sound without a self-referential struct). Each iteration:
//!
//! 1. **Admit** — pull waiting requests into any free slots and tokenize their
//!    prompt onto the slot as a pending prefill.
//! 2. **Prefill** — for each slot with a pending prompt, add the whole prompt to
//!    the batch requesting logits only at the prompt's last position.
//! 3. **Extend** — for every already-running sequence, add its last sampled token
//!    at its next position, requesting logits there.
//! 4. **Decode** — one `llama_decode` over the interleaved batch.
//! 5. **Sample** — for each sequence, sample from its own logits index with its
//!    own `LlamaSampler` (so repetition/penalty state is per-request), stream the
//!    decoded piece, and advance or finish the sequence.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::token::LlamaToken;
use tracing::{info, warn};

use crate::error::{ModelError, Result};
use crate::runtime::{ChatMessage, GenerationConfig, InferenceResult};

/// Number of concurrent sequence slots a batched context serves. This is the
/// KV-cache `n_seq_max` and the ceiling on requests decoded in one step. 32 is
/// a balance: enough parallelism to saturate a GPU's matmul on decode, small
/// enough that the per-slot KV cache (`n_ctx` tokens × slots) stays within the
/// memory a single loaded model already reserves.
const MAX_SLOTS: usize = 32;

/// Physical batch capacity for a single `llama_decode`. Must cover the worst
/// case of one full prompt prefill plus one extension token for every other
/// active slot. Prompts larger than this are prefilled in chunks.
const PHYSICAL_BATCH: usize = 2048;

/// How long the scheduler parks waiting for the first request before looping to
/// re-check the shutdown signal. Bounds shutdown latency when the engine is idle
/// without spinning the CPU.
const IDLE_POLL: Duration = Duration::from_millis(50);

/// The prompt for a batch request, before tokenization.
///
/// Chat templating needs `&LlamaModel`, which the scheduler thread owns, so the
/// engine defers it to admission time rather than requiring callers to hold a
/// model reference. `Raw` is a fully-formed prompt string; `Chat` is a message
/// list the scheduler renders through the model's GGUF chat template.
pub enum BatchPrompt {
    /// A prompt string that is already fully formed (no templating applied).
    Raw(String),
    /// Chat messages rendered through the model's built-in chat template at
    /// admission time, with the generation prompt appended.
    Chat(Vec<ChatMessage>),
}

/// One unit of work submitted to a model's batch engine.
pub struct BatchRequest {
    pub prompt: BatchPrompt,
    pub config: GenerationConfig,
    /// Per-token streaming sink. `None` for non-streaming callers; the final
    /// aggregate still returns via `result_tx`.
    pub token_tx: Option<tokio::sync::mpsc::Sender<String>>,
    /// Where the terminal [`InferenceResult`] (or error) is delivered.
    pub result_tx: tokio::sync::oneshot::Sender<Result<InferenceResult>>,
}

/// Handle to a per-model continuous-batching engine. Cloneable; every clone
/// submits to the same scheduler thread.
#[derive(Clone)]
pub struct BatchEngine {
    tx: Sender<BatchRequest>,
    inner: Arc<EngineInner>,
}

struct EngineInner {
    model_id: String,
    handle: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Closing this drops the scheduler's receiver, ending the loop.
    shutdown: Sender<()>,
}

impl BatchEngine {
    /// Spawn a batch engine for an already-loaded model. Takes ownership of the
    /// `LlamaModel` — it is moved onto the scheduler thread and lives there for
    /// the engine's lifetime. `context_length` is the effective (catalog-capped)
    /// per-sequence context window.
    pub fn spawn(
        model_id: String,
        model: LlamaModel,
        backend: Arc<LlamaBackend>,
        context_length: u32,
    ) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<BatchRequest>();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

        let model_id_thread = model_id.clone();
        let handle = std::thread::Builder::new()
            .name(format!("batch-{}", model_id))
            .spawn(move || {
                if let Err(e) = scheduler_loop(
                    &model_id_thread,
                    model,
                    &backend,
                    context_length,
                    &rx,
                    &shutdown_rx,
                ) {
                    warn!(
                        "batch engine for {} exited with error: {}",
                        model_id_thread, e
                    );
                }
            })
            .map_err(|e| {
                ModelError::Other(format!("failed to spawn batch scheduler thread: {}", e))
            })?;

        Ok(Self {
            tx,
            inner: Arc::new(EngineInner {
                model_id,
                handle: std::sync::Mutex::new(Some(handle)),
                shutdown: shutdown_tx,
            }),
        })
    }

    /// Submit a request to the scheduler. Returns immediately; the caller awaits
    /// the request's `result_tx` (and drains `token_tx` if streaming).
    pub fn submit(&self, req: BatchRequest) -> Result<()> {
        self.tx.send(req).map_err(|_| {
            ModelError::Other(format!(
                "batch engine for {} is no longer running",
                self.inner.model_id
            ))
        })
    }

    /// Signal the scheduler to stop and join its thread. In-flight requests
    /// receive an error on their `result_tx`.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown.send(());
        if let Some(handle) = self.inner.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EngineInner {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
        if let Some(handle) = self.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

/// A running sequence occupying one slot.
struct Sequence {
    /// KV-cache sequence id == slot index.
    seq_id: i32,
    sampler: LlamaSampler,
    token_tx: Option<tokio::sync::mpsc::Sender<String>>,
    result_tx: Option<tokio::sync::oneshot::Sender<Result<InferenceResult>>>,
    decoder: encoding_rs::Decoder,
    /// Prompt tokens staged by `admit`, waiting for the scheduler to prefill
    /// them. `None` once prefill has run.
    pending_prompt: Option<Vec<LlamaToken>>,
    /// Next KV position for this sequence.
    n_past: i32,
    input_tokens: u32,
    output_tokens: u32,
    /// Absolute position ceiling: `input_tokens + max_tokens`, capped at context.
    max_pos: i32,
    output_text: String,
    started: Instant,
    /// The token to feed at the next decode step (the one just sampled). `None`
    /// during prefill, where logits come from the prompt tail instead.
    pending_token: Option<LlamaToken>,
}

impl Sequence {
    fn finish(&mut self) {
        let elapsed = self.started.elapsed();
        let generation_time_ms = elapsed.as_millis() as u64;
        let tokens_per_second = if generation_time_ms > 0 {
            (self.output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
        } else {
            0.0
        };
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(Ok(InferenceResult {
                text: std::mem::take(&mut self.output_text),
                input_tokens: self.input_tokens,
                output_tokens: self.output_tokens,
                generation_time_ms,
                tokens_per_second,
            }));
        }
    }

    fn fail(&mut self, err: ModelError) {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(Err(err));
        }
    }
}

fn build_sampler(config: &GenerationConfig) -> LlamaSampler {
    LlamaSampler::chain_simple([
        LlamaSampler::penalties(config.repeat_last_n as i32, config.repeat_penalty, 0.0, 0.0),
        LlamaSampler::temp(config.temperature as f32),
        LlamaSampler::top_p(config.top_p as f32, 1),
        LlamaSampler::dist(config.seed as u32),
    ])
}

#[allow(clippy::too_many_lines)]
fn scheduler_loop(
    model_id: &str,
    model: LlamaModel,
    backend: &LlamaBackend,
    context_length: u32,
    rx: &Receiver<BatchRequest>,
    shutdown_rx: &Receiver<()>,
) -> Result<()> {
    use std::num::NonZeroU32;

    let n_ctx = NonZeroU32::new(context_length).unwrap_or(NonZeroU32::new(8192).unwrap());

    // One long-lived context with MAX_SLOTS sequence slots. n_batch/n_ubatch
    // cover the interleaved prefill+extend batch.
    let ctx_params = LlamaContextParams::default()
        .with_n_ctx(Some(n_ctx))
        .with_n_seq_max(MAX_SLOTS as u32)
        .with_n_batch(PHYSICAL_BATCH as u32)
        .with_n_ubatch(PHYSICAL_BATCH as u32);

    let mut ctx = model
        .new_context(backend, ctx_params)
        .map_err(|e| ModelError::Other(format!("batch context init failed: {}", e)))?;

    let ctx_size = ctx.n_ctx() as i32;

    info!(
        "batch engine for {} online: {} slots, ctx={}",
        model_id, MAX_SLOTS, ctx_size
    );

    // Slots: None == free.
    let mut slots: Vec<Option<Sequence>> = (0..MAX_SLOTS).map(|_| None).collect();
    let mut batch = LlamaBatch::new(PHYSICAL_BATCH, MAX_SLOTS as i32);

    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        let active = slots.iter().filter(|s| s.is_some()).count();

        // Admit new requests into free slots. When idle, block (bounded) on the
        // first one so the thread parks instead of spinning; then drain the rest
        // non-blocking.
        if active == 0 {
            match rx.recv_timeout(IDLE_POLL) {
                Ok(req) => admit(&model, ctx_size, &mut slots, req),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Fill any remaining free slots without blocking.
        while slots.iter().any(|s| s.is_none()) {
            match rx.try_recv() {
                Ok(req) => admit(&model, ctx_size, &mut slots, req),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // Build the interleaved batch: whole-prompt prefill for freshly-admitted
        // sequences, one extension token for already-running ones. `logits_slot`
        // maps a batch logits index back to the slot that owns it.
        batch.clear();
        let mut logits_slot: Vec<(i32, usize)> = Vec::with_capacity(MAX_SLOTS);
        let mut batch_full = false;

        for (slot_idx, maybe_seq) in slots.iter_mut().enumerate() {
            let Some(seq) = maybe_seq.as_mut() else {
                continue;
            };

            if let Some(prompt) = seq.pending_prompt.take() {
                // Prefill: add the whole prompt, logits only on the last token.
                let last = prompt.len() - 1;
                let mut overflowed = false;
                for (i, tok) in prompt.iter().enumerate() {
                    let want_logits = i == last;
                    if batch
                        .add(*tok, seq.n_past + i as i32, &[seq.seq_id], want_logits)
                        .is_err()
                    {
                        // Batch can't hold this whole prompt this step. Restore
                        // the prompt and try again next step (with a fresh batch).
                        seq.pending_prompt = Some(prompt.clone());
                        overflowed = true;
                        batch_full = true;
                        break;
                    }
                }
                if overflowed {
                    continue;
                }
                seq.n_past += prompt.len() as i32;
                let idx = batch.n_tokens() - 1;
                logits_slot.push((idx, slot_idx));
            } else if let Some(tok) = seq.pending_token.take() {
                // Running sequence: add its just-sampled token at n_past (the next
                // free KV position). n_past advances only after the token is
                // committed here, mirroring prefill — so the KV cache and the
                // batch positions stay consecutive (Y = X + 1).
                if batch.add(tok, seq.n_past, &[seq.seq_id], true).is_err() {
                    // Batch full — leave this token pending for the next step.
                    seq.pending_token = Some(tok);
                    batch_full = true;
                    continue;
                }
                seq.n_past += 1;
                let idx = batch.n_tokens() - 1;
                logits_slot.push((idx, slot_idx));
            }
        }

        if batch.n_tokens() == 0 {
            // Nothing to decode. Either every slot is free (loop back to admit)
            // or the batch overflowed with everything deferred (spin once).
            if !batch_full {
                continue;
            }
            continue;
        }

        if let Err(e) = ctx.decode(&mut batch) {
            // A decode failure is fatal to every sequence in this step.
            for (_idx, slot_idx) in &logits_slot {
                if let Some(mut seq) = slots[*slot_idx].take() {
                    let _ = ctx.clear_kv_cache_seq(Some(seq.seq_id as u32), None, None);
                    seq.fail(ModelError::InferenceError(format!("decode failed: {}", e)));
                }
            }
            continue;
        }

        // Sample each sequence from its own logits index.
        for (logits_idx, slot_idx) in logits_slot {
            let mut free_slot = false;
            {
                let Some(seq) = slots[slot_idx].as_mut() else {
                    continue;
                };

                let token = seq.sampler.sample(&ctx, logits_idx);
                seq.sampler.accept(token);

                if model.is_eog_token(token) {
                    free_slot = true;
                } else {
                    match model.token_to_piece(token, &mut seq.decoder, true, None) {
                        Ok(piece) => {
                            let receiver_gone = seq
                                .token_tx
                                .as_ref()
                                .map(|tx| tx.blocking_send(piece.clone()).is_err())
                                .unwrap_or(false);
                            seq.output_text.push_str(&piece);
                            seq.output_tokens += 1;
                            if receiver_gone {
                                free_slot = true;
                            }
                        }
                        Err(e) => {
                            warn!("token decode failed on {}: {}", model_id, e);
                            seq.output_tokens += 1;
                        }
                    }

                    if !free_slot {
                        // Stop once the committed prompt plus everything generated
                        // so far reaches the ceiling (max_tokens, capped at ctx).
                        if seq.input_tokens as i32 + seq.output_tokens as i32 >= seq.max_pos {
                            free_slot = true;
                        } else {
                            seq.pending_token = Some(token);
                        }
                    }
                }
            }

            if free_slot {
                finalize_and_free(&mut ctx, &mut slots, slot_idx);
            }
        }
    }

    // Drain remaining slots on shutdown.
    for slot in slots.iter_mut() {
        if let Some(mut seq) = slot.take() {
            seq.fail(ModelError::Other("batch engine shutting down".into()));
        }
    }

    info!("batch engine for {} stopped", model_id);
    Ok(())
}

/// Finalize a finished sequence and free its slot + KV.
fn finalize_and_free(
    ctx: &mut llama_cpp_2::context::LlamaContext,
    slots: &mut [Option<Sequence>],
    slot_idx: usize,
) {
    if let Some(mut seq) = slots[slot_idx].take() {
        let _ = ctx.clear_kv_cache_seq(Some(seq.seq_id as u32), None, None);
        seq.finish();
    }
}

/// Tokenize an admitted request into the first free slot and stage its prompt
/// for prefill. Prefill decode happens on the scheduler thread (the only holder
/// of the `LlamaContext`); `admit` only tokenizes and records the prompt.
fn admit(model: &LlamaModel, ctx_size: i32, slots: &mut [Option<Sequence>], req: BatchRequest) {
    let Some(slot_idx) = slots.iter().position(|s| s.is_none()) else {
        // No free slot — reject rather than block. Caller sheds load.
        let _ = req.result_tx.send(Err(ModelError::QueueFull {
            model_id: "batched".into(),
            waiting: slots.len(),
            max: slots.len(),
        }));
        return;
    };
    let seq_id = slot_idx as i32;

    // Render the prompt to a final string. Chat messages go through the model's
    // GGUF chat template (per-architecture: Gemma `<start_of_turn>`, Qwen
    // `<|im_start|>`, ...) with the generation prompt appended.
    let prompt = match render_prompt(model, &req.prompt) {
        Ok(p) => p,
        Err(e) => {
            let _ = req.result_tx.send(Err(e));
            return;
        }
    };

    let tokens = match model.str_to_token(&prompt, AddBos::Always) {
        Ok(t) => t,
        Err(e) => {
            let _ = req
                .result_tx
                .send(Err(ModelError::Other(format!("tokenization failed: {}", e))));
            return;
        }
    };
    if tokens.is_empty() {
        let _ = req
            .result_tx
            .send(Err(ModelError::Other("empty prompt".into())));
        return;
    }

    let input_tokens = tokens.len() as u32;
    // A prompt that alone fills the context leaves no room to generate.
    if input_tokens as i32 >= ctx_size {
        let _ = req.result_tx.send(Err(ModelError::InferenceError(format!(
            "prompt of {} tokens exceeds context window {}",
            input_tokens, ctx_size
        ))));
        return;
    }
    let max_pos = ctx_size.min(input_tokens as i32 + req.config.max_tokens as i32);

    slots[slot_idx] = Some(Sequence {
        seq_id,
        sampler: build_sampler(&req.config),
        token_tx: req.token_tx,
        result_tx: Some(req.result_tx),
        decoder: encoding_rs::UTF_8.new_decoder(),
        pending_prompt: Some(tokens),
        n_past: 0,
        input_tokens,
        output_tokens: 0,
        max_pos,
        output_text: String::new(),
        started: Instant::now(),
        pending_token: None,
    });
}

/// Render a [`BatchPrompt`] to the final prompt string fed to the tokenizer.
fn render_prompt(model: &LlamaModel, prompt: &BatchPrompt) -> Result<String> {
    match prompt {
        BatchPrompt::Raw(s) => Ok(s.clone()),
        BatchPrompt::Chat(messages) => {
            let llama_messages: Vec<LlamaChatMessage> = messages
                .iter()
                .map(|m| {
                    LlamaChatMessage::new(m.role.clone(), m.content.clone())
                        .map_err(|e| ModelError::Other(format!("Invalid chat message: {}", e)))
                })
                .collect::<Result<Vec<_>>>()?;

            // Prefer the GGUF's embedded template; fall back to ChatML when it
            // is missing or renders empty (some Qwen3 templates render to a
            // zero-length body on this llama.cpp build, which would tokenize to
            // zero tokens). Keeps both serving modes templating identically.
            if let Ok(tmpl) = model.chat_template(None) {
                if let Ok(rendered) = model.apply_chat_template(&tmpl, &llama_messages, true) {
                    if !rendered.trim().is_empty() {
                        return Ok(rendered);
                    }
                }
            }
            Ok(crate::runtime::render_chatml_prompt(messages))
        }
    }
}
