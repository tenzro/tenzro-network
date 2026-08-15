//! Continuous batching engine for GGUF text generation.
//!
//! Backend-gated (llama.cpp): compiled under the `bundled-llama` feature.
//!
//! Holds a single long-lived `llama_context` per model with a fixed pool of
//! sequence slots and interleaves every active request into one `llama_decode`
//! per step. Throughput scales with the number of active sequences because a
//! decode over K sequences costs close to a decode over one — the same weight
//! matrices are read once and applied to K token rows.
//!
//! ## Slot model
//!
//! The context is built with `n_seq_max = max_slots()` KV-cache sequence slots.
//! Each in-flight request owns one slot (its `seq_id`); the number of admitted
//! requests never exceeds the slot count, so a `seq_id` is always a valid slot
//! index. When a request finishes its slot's KV is cleared so a waiting request
//! can take it.
//!
//! ## Scheduler loop
//!
//! One dedicated OS thread per model owns the `LlamaModel` and its
//! `LlamaContext`. Each iteration admits waiting requests into free slots,
//! extends every running sequence by its last sampled token, spends the
//! remaining batch capacity prefilling prompts, runs one `llama_decode`, then
//! samples each sequence from its own logits with its own sampler.

use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::token::LlamaToken;
use tracing::{info, warn};

use crate::config::GenerationConfig;
use crate::error::{Error, Result};
use crate::prompt::render_chatml_prompt;
use crate::result::{ChatMessage, InferenceResult, StopReason};
use crate::stream::StopStream;

/// Number of concurrent sequence slots a batched context serves by default.
/// This is the KV-cache `n_seq_max` and the ceiling on requests decoded in one
/// step. llama.cpp divides the context across it, so the per-request window is
/// `n_ctx / n_seq_max`.
const MAX_SLOTS_DEFAULT: usize = 32;

/// Sequence slots, overridable with `TENZRO_MAX_SLOTS`.
///
/// This is `n_seq_max`. On a device that cannot afford `32 x` a useful window,
/// fewer slots buy back per-request context. The host's admission layer must
/// not advertise more concurrency than this — a request is only ever admitted
/// into one of these slots, so `n_seq_max` is the true concurrent capacity.
pub fn max_slots() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("TENZRO_MAX_SLOTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(MAX_SLOTS_DEFAULT)
    })
}

/// Physical batch capacity for a single `llama_decode`, overridable with
/// `TENZRO_PHYSICAL_BATCH`. Sets `n_batch`/`n_ubatch`; the compute buffer
/// scales with it.
const PHYSICAL_BATCH_DEFAULT: usize = 2048;

/// Physical batch size (see [`PHYSICAL_BATCH_DEFAULT`]).
fn physical_batch() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("TENZRO_PHYSICAL_BATCH")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v >= 32)
            .unwrap_or(PHYSICAL_BATCH_DEFAULT)
    })
}

/// Prompt tokens one slot may contribute to a single batch. Bounding the
/// per-slot share lets several prefills advance together instead of one long
/// prompt consuming every step's spare capacity until it is done.
const PREFILL_CHUNK: usize = 512;

/// How long the scheduler parks waiting for the first request before looping to
/// re-check the shutdown signal. Bounds shutdown latency when idle without
/// spinning the CPU.
const IDLE_POLL: Duration = Duration::from_millis(50);

/// The prompt for a batch request, before tokenization.
///
/// `Raw` is a fully-formed prompt string; `Chat` is a message list the
/// scheduler renders through the model's GGUF chat template (falling back to
/// ChatML). A host with model-specific templating renders its own prompt and
/// submits it as `Raw`.
pub enum BatchPrompt {
    /// A prompt string that is already fully formed (no templating applied).
    Raw(String),
    /// Chat messages rendered through the model's built-in chat template at
    /// admission time, with the generation prompt appended.
    Chat(Vec<ChatMessage>),
}

/// One unit of work submitted to a model's batch engine.
pub struct BatchRequest {
    /// The prompt to serve.
    pub prompt: BatchPrompt,
    /// Sampling / generation configuration.
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
    /// the engine's lifetime. `context_length` is the effective (host-capped)
    /// per-sequence context window. `enable_thinking` is passed to templates
    /// that support a reasoning toggle.
    pub fn spawn(
        model_id: String,
        model: LlamaModel,
        backend: Arc<LlamaBackend>,
        context_length: u32,
        enable_thinking: bool,
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
                    enable_thinking,
                    &rx,
                    &shutdown_rx,
                ) {
                    warn!(
                        "batch engine for {} exited with error: {}",
                        model_id_thread, e
                    );
                }
            })
            .map_err(|e| Error::Other(format!("failed to spawn batch scheduler thread: {}", e)))?;

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
            Error::Other(format!(
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
    /// them. `None` once the whole prompt has been committed to the KV cache.
    pending_prompt: Option<Vec<LlamaToken>>,
    /// How many tokens of `pending_prompt` are already committed.
    prefill_cursor: usize,
    /// Next KV position for this sequence.
    n_past: i32,
    input_tokens: u32,
    output_tokens: u32,
    /// Absolute position ceiling: `input_tokens + max_tokens`, capped at context.
    max_pos: i32,
    /// Accumulates decoded pieces, trims a configured stop sequence out of the
    /// text, and holds back bytes that could still turn out to be the start of
    /// one so a delimiter never reaches a streaming client.
    stream: StopStream,
    started: Instant,
    /// The token to feed at the next decode step (the one just sampled). `None`
    /// during prefill, where logits come from the prompt tail instead.
    pending_token: Option<LlamaToken>,
}

impl Sequence {
    fn finish(mut self) {
        let elapsed = self.started.elapsed();
        let generation_time_ms = elapsed.as_millis() as u64;
        let tokens_per_second = if generation_time_ms > 0 {
            (self.output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
        } else {
            0.0
        };
        // A stop sequence outranks the position ceiling, which outranks
        // end-of-generation: the sequence is what halted decoding, and the
        // trimmed text alone cannot tell the caller which of the three it was.
        let stop_reason = if self.stream.hit_stop() {
            StopReason::StopSequence
        } else if self.input_tokens as i32 + self.output_tokens as i32 >= self.max_pos {
            StopReason::Length
        } else {
            StopReason::Eos
        };
        let token_tx = self.token_tx.take();
        let (text, thinking) = self.stream.finish_parts(token_tx.as_ref());
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(Ok(InferenceResult {
                text,
                thinking,
                input_tokens: self.input_tokens,
                output_tokens: self.output_tokens,
                generation_time_ms,
                tokens_per_second,
                stop_reason,
                commitment: None,
            }));
        }
    }

    fn fail(&mut self, err: Error) {
        if let Some(result_tx) = self.result_tx.take() {
            let _ = result_tx.send(Err(err));
        }
    }
}

fn build_sampler(config: &GenerationConfig, n_vocab: i32) -> LlamaSampler {
    LlamaSampler::chain_simple([
        LlamaSampler::penalties(
            n_vocab,
            config.repeat_last_n as i32,
            config.repeat_penalty,
            0.0,
            0.0,
        ),
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
    enable_thinking: bool,
    rx: &Receiver<BatchRequest>,
    shutdown_rx: &Receiver<()>,
) -> Result<()> {
    use std::num::NonZeroU32;

    let n_ctx = NonZeroU32::new(context_length).unwrap_or(NonZeroU32::new(8192).unwrap());

    // One long-lived context with max_slots() sequence slots. n_batch/n_ubatch
    // cover the interleaved prefill+extend batch.
    let ctx_params = LlamaContextParams::default()
        .with_n_ctx(Some(n_ctx))
        .with_n_seq_max(max_slots() as u32)
        .with_n_batch(physical_batch() as u32)
        .with_n_ubatch(physical_batch() as u32);

    let mut ctx = model
        .new_context(backend, ctx_params)
        .map_err(|e| Error::Other(format!("batch context init failed: {}", e)))?;

    let ctx_size = ctx.n_ctx() as i32;

    info!(
        "batch engine for {} online: {} slots, ctx={}",
        model_id,
        max_slots(),
        ctx_size
    );

    // Slots: None == free.
    let mut slots: Vec<Option<Sequence>> = (0..max_slots()).map(|_| None).collect();
    let mut batch = LlamaBatch::new(physical_batch(), max_slots() as i32);

    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        // Cancellation sweep: free any slot whose client is gone before more GPU
        // work. A dropped result/stream receiver closes `result_tx`, covering
        // both streaming and non-streaming cancellation. Matches the consumer's
        // verified scheduler.
        for slot_idx in 0..slots.len() {
            let client_gone = slots[slot_idx]
                .as_ref()
                .and_then(|s| s.result_tx.as_ref())
                .is_some_and(tokio::sync::oneshot::Sender::is_closed);
            if client_gone && let Some(seq) = slots[slot_idx].take() {
                let _ = ctx.clear_kv_cache_seq(Some(seq.seq_id as u32), None, None);
            }
        }

        let active = slots.iter().filter(|s| s.is_some()).count();

        // Admit new requests into free slots. When idle, block (bounded) on the
        // first one so the thread parks instead of spinning; then drain the rest
        // non-blocking.
        if active == 0 {
            match rx.recv_timeout(IDLE_POLL) {
                Ok(req) => admit(&model, ctx_size, &mut slots, req, enable_thinking),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Fill any remaining free slots without blocking.
        while slots.iter().any(|s| s.is_none()) {
            match rx.try_recv() {
                Ok(req) => admit(&model, ctx_size, &mut slots, req, enable_thinking),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // Build the interleaved batch. `logits_slot` maps a batch logits index
        // back to the slot that owns it.
        batch.clear();
        let mut logits_slot: Vec<(i32, usize)> = Vec::with_capacity(max_slots());

        // Extension first: every running sequence contributes exactly one token,
        // so a slot mid-prefill can never hold back the slots already generating.
        for (slot_idx, maybe_seq) in slots.iter_mut().enumerate() {
            let Some(seq) = maybe_seq.as_mut() else {
                continue;
            };
            let Some(tok) = seq.pending_token.take() else {
                continue;
            };
            if batch.add(tok, seq.n_past, &[seq.seq_id], true).is_err() {
                seq.pending_token = Some(tok);
                continue;
            }
            seq.n_past += 1;
            logits_slot.push((batch.n_tokens() - 1, slot_idx));
        }

        // Prefill with what capacity is left, capped per slot.
        for (slot_idx, maybe_seq) in slots.iter_mut().enumerate() {
            let Some(seq) = maybe_seq.as_mut() else {
                continue;
            };
            let Some(prompt) = seq.pending_prompt.take() else {
                continue;
            };

            let room = physical_batch()
                .saturating_sub(batch.n_tokens() as usize)
                .min(PREFILL_CHUNK);
            let start = seq.prefill_cursor;
            let end = prompt.len().min(start + room);
            let last = prompt.len() - 1;

            let mut cursor = start;
            while cursor < end {
                if batch
                    .add(prompt[cursor], seq.n_past, &[seq.seq_id], cursor == last)
                    .is_err()
                {
                    break;
                }
                seq.n_past += 1;
                cursor += 1;
            }

            if cursor > last {
                // Whole prompt committed; its tail carries this slot's logits.
                seq.prefill_cursor = 0;
                logits_slot.push((batch.n_tokens() - 1, slot_idx));
            } else {
                // More prompt to go — no logits from this slot this step.
                seq.prefill_cursor = cursor;
                seq.pending_prompt = Some(prompt);
            }
        }

        if batch.n_tokens() == 0 {
            continue;
        }

        if let Err(e) = ctx.decode(&mut batch) {
            // A decode failure is fatal to every sequence in this step.
            for (_idx, slot_idx) in &logits_slot {
                if let Some(mut seq) = slots[*slot_idx].take() {
                    let _ = ctx.clear_kv_cache_seq(Some(seq.seq_id as u32), None, None);
                    seq.fail(Error::Inference(format!("decode failed: {}", e)));
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
                            let open = seq.stream.push(&piece, seq.token_tx.as_ref());
                            seq.output_tokens += 1;
                            if !open || seq.stream.hit_stop() {
                                free_slot = true;
                            }
                        }
                        Err(e) => {
                            warn!("token decode failed on {}: {}", model_id, e);
                            seq.output_tokens += 1;
                        }
                    }

                    if !free_slot {
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
            seq.fail(Error::Other("batch engine shutting down".into()));
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
    if let Some(seq) = slots[slot_idx].take() {
        let _ = ctx.clear_kv_cache_seq(Some(seq.seq_id as u32), None, None);
        seq.finish();
    }
}

/// Tokenize an admitted request into the first free slot and stage its prompt
/// for prefill.
fn admit(
    model: &LlamaModel,
    ctx_size: i32,
    slots: &mut [Option<Sequence>],
    req: BatchRequest,
    enable_thinking: bool,
) {
    let Some(slot_idx) = slots.iter().position(|s| s.is_none()) else {
        // No free slot — reject rather than block. Caller sheds load.
        let _ = req.result_tx.send(Err(Error::QueueFull {
            model_id: "batched".into(),
            waiting: slots.len(),
            max: slots.len(),
        }));
        return;
    };
    let seq_id = slot_idx as i32;

    let prompt = match render_prompt(model, &req.prompt, enable_thinking) {
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
                .send(Err(Error::Other(format!("tokenization failed: {}", e))));
            return;
        }
    };
    if tokens.is_empty() {
        let _ = req
            .result_tx
            .send(Err(Error::Other("empty prompt".into())));
        return;
    }

    let input_tokens = tokens.len() as u32;
    // A prompt that alone fills the context leaves no room to generate.
    if input_tokens as i32 >= ctx_size {
        let _ = req.result_tx.send(Err(Error::Inference(format!(
            "prompt of {} tokens exceeds context window {}",
            input_tokens, ctx_size
        ))));
        return;
    }
    let max_pos = ctx_size.min(input_tokens as i32 + req.config.max_tokens as i32);

    slots[slot_idx] = Some(Sequence {
        seq_id,
        sampler: build_sampler(&req.config, model.n_vocab()),
        token_tx: req.token_tx,
        result_tx: Some(req.result_tx),
        decoder: encoding_rs::UTF_8.new_decoder(),
        pending_prompt: Some(tokens),
        prefill_cursor: 0,
        n_past: 0,
        input_tokens,
        output_tokens: 0,
        max_pos,
        stream: StopStream::new(req.config.stop),
        started: Instant::now(),
        pending_token: None,
    });
}

/// Render a [`BatchPrompt`] to the final prompt string fed to the tokenizer.
///
/// Backend-generic: uses the model's own embedded GGUF chat template, falling
/// back to ChatML. A host with model-specific templating (e.g. tool-calling
/// grammars or arch-specific native chat formats) renders upstream and submits
/// a [`BatchPrompt::Raw`]. `_enable_thinking` is reserved for templates that
/// take a reasoning-toggle variable; this binding's `apply_chat_template` does
/// not, so the model's template default applies.
fn render_prompt(
    model: &LlamaModel,
    prompt: &BatchPrompt,
    _enable_thinking: bool,
) -> Result<String> {
    match prompt {
        BatchPrompt::Raw(s) => Ok(s.clone()),
        BatchPrompt::Chat(messages) => {
            let llama_messages: Vec<LlamaChatMessage> = messages
                .iter()
                .map(|m| {
                    LlamaChatMessage::new(m.role.clone(), m.content.clone())
                        .map_err(|e| Error::Other(format!("Invalid chat message: {}", e)))
                })
                .collect::<Result<Vec<_>>>()?;

            // Prefer the GGUF's embedded template; fall back to ChatML when it
            // is missing or renders empty.
            if let Ok(tmpl) = model.chat_template(None)
                && let Ok(rendered) = model.apply_chat_template(&tmpl, &llama_messages, true)
                && !rendered.trim().is_empty()
            {
                return Ok(rendered);
            }
            Ok(render_chatml_prompt(messages))
        }
    }
}
