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

/// What a slot's KV cache still holds after its request finished.
///
/// The whole point of prefix reuse: an agent's next turn repeats the system
/// prompt, the tool schemas and the entire conversation so far, and re-reading
/// those through the model is the single largest cost in an agent loop. Keeping
/// the tokens that are already in KV lets the next request start where the last
/// one diverged instead of at zero.
#[derive(Default, Clone)]
struct CachedPrefix {
    /// Tokens resident in this sequence's KV, in order.
    tokens: Vec<LlamaToken>,
}

/// Length of the shared prefix of two token runs.
fn common_prefix_len(a: &[LlamaToken], b: &[LlamaToken]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
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
    /// Every token committed to this sequence's KV — prompt then generated —
    /// so the next request on this slot can measure its shared prefix.
    resident: Vec<LlamaToken>,
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
    // What each slot's KV still holds between requests, so a follow-up turn can
    // start from the divergence instead of from zero.
    let mut cached: Vec<CachedPrefix> = (0..max_slots()).map(|_| CachedPrefix::default()).collect();
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
                // The KV is gone, so the cache record must go with it. Leaving
                // it would promise the next request a prefix that is no longer
                // resident, and it would prefill from a position the cache
                // cannot satisfy.
                cached[slot_idx].tokens.clear();
            }
        }

        let active = slots.iter().filter(|s| s.is_some()).count();

        // Admit new requests into free slots. When idle, block (bounded) on the
        // first one so the thread parks instead of spinning; then drain the rest
        // non-blocking.
        if active == 0 {
            match rx.recv_timeout(IDLE_POLL) {
                Ok(req) => {
                    if let Some(r) =
                        admit(&model, ctx_size, &mut slots, &mut cached, req, enable_thinking)
                    {
                        apply_prefix_reuse(&mut ctx, &mut slots, &mut cached, r);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Fill any remaining free slots without blocking.
        while slots.iter().any(|s| s.is_none()) {
            match rx.try_recv() {
                Ok(req) => {
                    if let Some(r) =
                        admit(&model, ctx_size, &mut slots, &mut cached, req, enable_thinking)
                    {
                        apply_prefix_reuse(&mut ctx, &mut slots, &mut cached, r);
                    }
                }
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
            // Generated tokens land in KV too, so a follow-up turn that repeats
            // this answer as history reuses it rather than re-decoding it.
            seq.resident.push(tok);
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
                seq.resident.push(prompt[cursor]);
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
                    // Same reason as the cancellation sweep: a discarded KV must
                    // not leave a cache record behind, or one decode failure
                    // becomes a permanent one for every later request on the
                    // slot.
                    cached[*slot_idx].tokens.clear();
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
                finalize_and_free(&mut ctx, &mut slots, &mut cached, slot_idx);
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

/// Finalize a finished sequence and free its slot, keeping its KV for reuse.
fn finalize_and_free(
    _ctx: &mut llama_cpp_2::context::LlamaContext,
    slots: &mut [Option<Sequence>],
    cached: &mut [CachedPrefix],
    slot_idx: usize,
) {
    if let Some(seq) = slots[slot_idx].take() {
        // Keep the KV. The next request on this slot is very often the same
        // conversation one turn later, and re-decoding a prefix we already hold
        // is the largest avoidable cost in an agent loop. `admit` trims
        // whatever the next prompt diverges from.
        cached[slot_idx].tokens = seq.resident.clone();
        seq.finish();
    }
}

/// Drop the part of a slot's KV cache that the new prompt diverges from, and
/// record what the slot now holds.
///
/// Order matters: the trim must happen before the scheduler decodes anything
/// into this sequence, or the new tokens would be written on top of positions
/// still holding the previous request's.
fn apply_prefix_reuse(
    ctx: &mut llama_cpp_2::context::LlamaContext,
    slots: &mut [Option<Sequence>],
    cached: &mut [CachedPrefix],
    r: PrefixReuse,
) {
    // Everything from the divergence onward was computed under a different
    // prefix, so it is wrong rather than merely old. `None` for the end means
    // "to the end of the sequence".
    let seq = r.slot_idx as u32;

    // Nothing past the reused span means nothing to drop. This is the ordinary
    // agent turn — the conversation grew, so the new prompt starts with the
    // whole of the old one — and it is also the only case that works on a model
    // whose layers carry recurrent state, because such a cache can be cleared
    // but not rewound to an arbitrary position. Asking it to trim here would be
    // refused and would cost us the reuse we already have.
    if r.reused > 0 && r.reused == r.cached_len {
        cached[r.slot_idx].tokens = r.prompt[..r.reused].to_vec();
        tracing::info!(
            slot = r.slot_idx,
            reused_tokens = r.reused,
            prompt_tokens = r.prompt.len(),
            "prefix cache hit (extension, no trim needed)"
        );
        return;
    }

    let removed = ctx
        .clear_kv_cache_seq(Some(seq), Some(r.reused as u32), None)
        .unwrap_or(false);

    // Trust the trim only after confirming it. `llama_memory_seq_rm` returns
    // true without removing anything when a cache shares cells, and a cache
    // that kept its old positions is not a slow path — on an M-RoPE model the
    // next batch must start strictly beyond the highest cached position, so a
    // stale entry makes the request unschedulable and it fails outright.
    // Verify against the cache itself rather than the return value.
    let stale = ctx.kv_cache_seq_pos_max(r.slot_idx as i32) >= r.reused as i32;

    if !removed || stale {
        // Could not trim to the divergence. Drop the sequence's KV entirely and
        // prefill from zero: strictly slower, but correct, and self-healing
        // because the slot starts clean on the next turn either way.
        let _ = ctx.clear_kv_cache_seq(Some(seq), None, None);
        cached[r.slot_idx].tokens.clear();
        if let Some(s) = slots[r.slot_idx].as_mut() {
            s.prefill_cursor = 0;
            s.n_past = 0;
            s.resident.clear();
        }
        tracing::info!(
            slot = r.slot_idx,
            wanted_reuse = r.reused,
            removed,
            "prefix trim refused by the KV cache; prefilling from zero"
        );
        return;
    }

    cached[r.slot_idx].tokens = r.prompt[..r.reused].to_vec();
    if r.reused > 0 {
        tracing::info!(
            slot = r.slot_idx,
            reused_tokens = r.reused,
            prompt_tokens = r.prompt.len(),
            "prefix cache hit"
        );
    }
}

/// Tokenize an admitted request into the first free slot and stage its prompt
/// for prefill.
fn admit(
    model: &LlamaModel,
    ctx_size: i32,
    slots: &mut [Option<Sequence>],
    cached: &mut [CachedPrefix],
    req: BatchRequest,
    enable_thinking: bool,
) -> Option<PrefixReuse> {
    let Some(slot_idx) = slots.iter().position(|s| s.is_none()) else {
        // No free slot — reject rather than block. Caller sheds load.
        let _ = req.result_tx.send(Err(Error::QueueFull {
            model_id: "batched".into(),
            waiting: slots.len(),
            max: slots.len(),
        }));
        return None;
    };
    let seq_id = slot_idx as i32;

    let prompt = match render_prompt(model, &req.prompt, enable_thinking) {
        Ok(p) => p,
        Err(e) => {
            let _ = req.result_tx.send(Err(e));
            return None;
        }
    };

    let tokens = match model.str_to_token(&prompt, AddBos::Always) {
        Ok(t) => t,
        Err(e) => {
            let _ = req
                .result_tx
                .send(Err(Error::Other(format!("tokenization failed: {}", e))));
            return None;
        }
    };
    if tokens.is_empty() {
        let _ = req
            .result_tx
            .send(Err(Error::Other("empty prompt".into())));
        return None;
    }

    let input_tokens = tokens.len() as u32;
    // A prompt that alone fills the context leaves no room to generate.
    if input_tokens as i32 >= ctx_size {
        let _ = req.result_tx.send(Err(Error::Inference(format!(
            "prompt of {} tokens exceeds context window {}",
            input_tokens, ctx_size
        ))));
        return None;
    }
    let max_pos = ctx_size.min(input_tokens as i32 + req.config.max_tokens as i32);

    // Reuse whatever of this slot's KV already matches. The tokens are
    // identical up to `reuse`, so those positions are already correct in the
    // cache and only the divergent tail needs decoding. Everything at or past
    // the divergence is dropped, because a KV entry computed under a different
    // prefix is wrong, not merely stale.
    let cached_len = cached[slot_idx].tokens.len();
    let reuse = common_prefix_len(&cached[slot_idx].tokens, &tokens);
    // A one-token overlap (the BOS) is not worth the bookkeeping, and reusing
    // the entire prompt would leave nothing to decode and no logits to sample
    // from — so always leave at least the final token to be processed.
    let reuse = if reuse < 2 { 0 } else { reuse.min(tokens.len() - 1) };

    slots[slot_idx] = Some(Sequence {
        seq_id,
        sampler: build_sampler(&req.config, model.n_vocab()),
        token_tx: req.token_tx,
        result_tx: Some(req.result_tx),
        decoder: encoding_rs::UTF_8.new_decoder(),
        pending_prompt: Some(tokens.clone()),
        // Prefill resumes at the divergence rather than at zero.
        prefill_cursor: reuse,
        n_past: reuse as i32,
        // The reused prefix is already in KV, so it counts as resident.
        resident: tokens[..reuse].to_vec(),
        input_tokens,
        output_tokens: 0,
        max_pos,
        stream: StopStream::new(req.config.stop),
        started: Instant::now(),
        pending_token: None,
    });

    Some(PrefixReuse {
        slot_idx,
        reused: reuse,
        cached_len,
        prompt: tokens,
    })
}

/// What `admit` decided about an incoming request's prefix.
///
/// Returned rather than acted on inside `admit`, because trimming the KV cache
/// needs the context and `admit` deliberately does not take it — tokenizing
/// must not be able to touch the cache.
struct PrefixReuse {
    slot_idx: usize,
    /// Tokens taken from cache instead of re-decoded.
    reused: usize,
    /// What the slot held before this request. When the whole of it is reused
    /// the prompt merely extends the cache and nothing has to be dropped, which
    /// is the difference between a trim we can skip and one that must succeed.
    cached_len: usize,
    prompt: Vec<LlamaToken>,
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

#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn toks(ids: &[i32]) -> Vec<LlamaToken> {
        ids.iter().copied().map(LlamaToken).collect()
    }

    /// The decision `admit` makes, extracted so it can be tested without a
    /// model, a context, or a GPU.
    fn reuse_for(cached: &[LlamaToken], prompt: &[LlamaToken]) -> usize {
        let r = common_prefix_len(cached, prompt);
        if r < 2 { 0 } else { r.min(prompt.len() - 1) }
    }

    #[test]
    fn a_follow_up_turn_reuses_the_conversation_so_far() {
        // The agent case: turn two repeats turn one verbatim and appends.
        let turn1 = toks(&[1, 2, 3, 4, 5]);
        let turn2 = toks(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(reuse_for(&turn1, &turn2), 5, "the whole prior turn is already in KV");
    }

    #[test]
    fn a_different_conversation_reuses_nothing() {
        let cached = toks(&[1, 2, 3, 4]);
        let other = toks(&[9, 8, 7, 6]);
        assert_eq!(reuse_for(&cached, &other), 0);
    }

    /// Whether the cache has to be trimmed at all, which decides whether reuse
    /// survives on a model whose state cannot be rewound.
    fn needs_trim(cached: &[LlamaToken], prompt: &[LlamaToken]) -> bool {
        let reuse = reuse_for(cached, prompt);
        !(reuse > 0 && reuse == cached.len())
    }

    #[test]
    fn extending_a_conversation_needs_no_trim() {
        // Turn two repeats turn one verbatim and appends: everything cached is
        // still a prefix, so there is nothing to drop and the reuse holds even
        // where a partial trim would be refused.
        let turn1 = toks(&[1, 2, 3, 4, 5]);
        let turn2 = toks(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(!needs_trim(&turn1, &turn2));
    }

    #[test]
    fn diverging_from_the_cache_needs_a_trim() {
        // The cached tail (4, 5) is not in the new prompt, so those entries are
        // wrong rather than stale and cannot simply be kept.
        let cached = toks(&[1, 2, 3, 4, 5]);
        let prompt = toks(&[1, 2, 3, 9, 9, 9]);
        assert!(needs_trim(&cached, &prompt));
    }

    #[test]
    fn divergence_mid_prompt_stops_the_reuse_there() {
        // Everything past the divergence was computed under a different prefix,
        // so it is wrong rather than stale and must not be reused.
        let cached = toks(&[1, 2, 3, 40, 50]);
        let prompt = toks(&[1, 2, 3, 41, 51]);
        assert_eq!(reuse_for(&cached, &prompt), 3);
    }

    #[test]
    fn an_identical_prompt_still_leaves_a_token_to_decode() {
        // Reusing everything would leave no token to run through the model and
        // so no logits to sample the reply from.
        let same = toks(&[1, 2, 3, 4, 5]);
        assert_eq!(reuse_for(&same, &same), 4, "must hold back the final token");
    }

    #[test]
    fn a_bos_only_overlap_is_not_worth_reusing() {
        let cached = toks(&[1, 77, 78]);
        let prompt = toks(&[1, 90, 91]);
        assert_eq!(reuse_for(&cached, &prompt), 0);
    }

    #[test]
    fn a_cold_slot_reuses_nothing() {
        assert_eq!(reuse_for(&[], &toks(&[1, 2, 3])), 0);
    }

    #[test]
    fn a_shorter_prompt_than_the_cache_is_bounded_by_the_prompt() {
        // Cache holds a long conversation; the new prompt is a prefix of it.
        let cached = toks(&[1, 2, 3, 4, 5, 6, 7]);
        let prompt = toks(&[1, 2, 3]);
        assert_eq!(reuse_for(&cached, &prompt), 2, "never past the prompt's own end");
    }
}
