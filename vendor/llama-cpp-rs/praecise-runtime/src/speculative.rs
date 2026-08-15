//! Self-speculative decode (DFlash / MTP) over the bundled llama.cpp backend.
//!
//! Backend-gated. Verifies a whole draft block in one target decode and
//! accepts the longest matching prefix plus one bonus token. The speedup is
//! algorithmic (fewer sequential target forward passes) and rides on the
//! backend's kernels; this is the orchestration around them.

use std::num::NonZeroU32;

use llama_cpp_2::context::params::{LlamaContextParams, LlamaContextType};
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::speculative::{MtpSpeculative, MtpSpeculativeParams};

use crate::config::GenerationConfig;
use crate::error::{Error, Result};
use crate::result::{InferenceResult, StopReason};
use crate::sampling::build_sampler_chain;
use crate::stream::StopStream;

/// Fallback context length when neither the model nor caller specifies one.
const DEFAULT_CONTEXT_LENGTH: u32 = 8192;

/// Run speculative decoding: the drafter proposes a block of tokens, the target
/// verifies them in one decode, and the longest matching prefix (plus a bonus
/// token) is accepted. `draft_n` caps the block size (1..=6 typical).
/// The draft model/backend are passed explicitly (not a consumer's model
/// wrapper) so this one engine serves both modes: a *separate* drafter GGUF,
/// and *inline* self-speculation where the draft head lives in the target's own
/// GGUF — there the caller passes the target's own `model`/`backend`, so the
/// draft context is built from the target weights with no second load.
#[allow(clippy::too_many_arguments)]
pub fn generate_speculative(
    target_model: &LlamaModel,
    target_backend: &LlamaBackend,
    target_context_length: u32,
    draft_model: &LlamaModel,
    draft_backend: &LlamaBackend,
    draft_context_length: u32,
    draft_spec_type: i32,
    prompt: &str,
    config: &GenerationConfig,
    token_tx: Option<&tokio::sync::mpsc::Sender<String>>,
    draft_n: u8,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<InferenceResult> {
    let start = std::time::Instant::now();

    let tokens_list = target_model
        .str_to_token(prompt, AddBos::Always)
        .map_err(|e| Error::Other(format!("Tokenization failed: {}", e)))?;
    if tokens_list.is_empty() {
        return Err(Error::Inference("prompt tokenized to zero tokens".to_string()));
    }
    let input_tokens = tokens_list.len() as u32;

    let n_ctx_target = NonZeroU32::new(target_context_length)
        .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());
    let n_ctx_draft = NonZeroU32::new(draft_context_length)
        .unwrap_or(NonZeroU32::new(DEFAULT_CONTEXT_LENGTH).unwrap());

    // Target holds recurrent-state rollback slots (n_rs_seq = draft n_max) to
    // undo rejected draft tokens; the draft context keeps the default 0.
    let target_ctx = target_model
        .new_context(
            target_backend,
            LlamaContextParams::default()
                .with_n_ctx(Some(n_ctx_target))
                .with_n_rs_seq(u32::from(draft_n)),
        )
        .map_err(|e| Error::Other(format!("Failed to create target context: {}", e)))?;
    // The draft context references the target via `ctx_other` (reads the
    // target's token embeddings / lm_head through it). For inline self-spec the
    // caller passes the target model here, so this shares the target weights.
    //
    // A draft-mtp head (spec_type 0) MUST run as an MTP-typed context so the
    // graph builds the nextn head as the drafter; without `ctx_type = MTP` the
    // draft decode runs the base graph and `common_speculative_process` fails
    // (status -3). DFlash (spec_type 1) uses the default context type.
    let mut draft_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx_draft));
    if draft_spec_type == 0 {
        draft_params = draft_params.with_context_type(LlamaContextType::Mtp);
    }
    let draft_ctx = draft_model
        .new_context_with_ctx_other(draft_backend, draft_params, &target_ctx)
        .map_err(|e| Error::Other(format!("Failed to create draft context: {}", e)))?;

    let mut spec = MtpSpeculative::new(
        target_ctx,
        draft_ctx,
        MtpSpeculativeParams {
            n_max: draft_n as i32,
            n_min: 0,
            p_min: 0.0,
            spec_type: draft_spec_type,
        },
    )
    .map_err(|e| Error::SpeculativeUnavailable {
        reason: format!("MtpSpeculative init failed: {}", e),
    })?;

    // Verify batch: id_last + up to draft_n block candidates.
    let mut batch = LlamaBatch::new((draft_n as usize) + 1, 1);

    // The drafter only PROPOSES tokens; the target's sampler decides.
    let mut sampler = build_sampler_chain(config, target_model.n_vocab());
    let mut output_tokens: u32 = 0;
    let mut decoder = encoding_rs::UTF_8.new_decoder();
    let mut stream = StopStream::new(config.stop.clone());
    let max_pos = (n_ctx_target.get() as i32).min(input_tokens as i32 + config.max_tokens as i32);

    // DFlash/MTP prefill: decode the prompt EXCEPT its last token, calling
    // `process()` after every target ubatch so the draft context mirrors the
    // prompt. The last prompt token is kept as `id_last`, added first in every
    // verify batch and never decoded during prefill.
    let (id_last_ref, prefill_toks) = tokens_list
        .split_last()
        .ok_or_else(|| Error::Inference("empty prompt".into()))?;
    let mut id_last = *id_last_ref;
    let n_batch = (spec.target_context_mut().n_batch() as usize).max(1);
    {
        let cap = n_batch.min(prefill_toks.len().max(1));
        let mut pbatch = LlamaBatch::new(cap, 1);
        let mut s = 0usize;
        while s < prefill_toks.len() {
            let e = (s + n_batch).min(prefill_toks.len());
            pbatch.clear();
            for (off, tok) in prefill_toks[s..e].iter().enumerate() {
                pbatch
                    .add(*tok, (s + off) as i32, &[0], false)
                    .map_err(|err| Error::Other(format!("Batch add failed: {}", err)))?;
            }
            spec.target_context_mut()
                .decode(&mut pbatch)
                .map_err(|err| Error::Other(format!("Prompt decode failed: {}", err)))?;
            spec.process(&pbatch).map_err(|err| Error::SpeculativeUnavailable {
                reason: format!("MtpSpeculative prefill process failed: {}", err),
            })?;
            s = e;
        }
    }

    let mut n_past = prefill_toks.len() as i32;

    spec.begin(prefill_toks).map_err(|e| Error::SpeculativeUnavailable {
        reason: format!("MtpSpeculative begin failed: {}", e),
    })?;

    let mut prompt_so_far: Vec<llama_cpp_2::token::LlamaToken> = tokens_list.clone();

    'genloop: while n_past < max_pos && !target_model.is_eog_token(id_last) {
        // Client-gone: stop before more GPU work if the stream receiver dropped
        // or the caller flipped `cancel` on disconnect. Contexts drop at return.
        if token_tx.is_some_and(|tx| tx.is_closed())
            || cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        {
            break 'genloop;
        }
        // 1. Ask the drafter for a block of candidates (may be empty).
        let drafts = match spec.draft(n_past, id_last, &prompt_so_far) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "Speculative draft failed at n_past={}: {} — verifying id_last only",
                    n_past,
                    e
                );
                Vec::new()
            }
        };

        // 2. Verify batch: id_last FIRST, then the drafts, logits everywhere.
        batch.clear();
        batch
            .add(id_last, n_past, &[0], true)
            .map_err(|e| Error::Other(format!("Batch add failed: {}", e)))?;
        for (i, draft_tok) in drafts.iter().enumerate() {
            batch
                .add(*draft_tok, n_past + 1 + i as i32, &[0], true)
                .map_err(|e| Error::Other(format!("Batch add failed: {}", e)))?;
        }
        spec.target_context_mut()
            .decode(&mut batch)
            .map_err(|e| Error::Other(format!("Target speculative decode failed: {}", e)))?;

        // 3. Drop the draft context's speculative block before re-processing.
        let _ = spec
            .draft_context_mut()
            .kv_cache_seq_rm(0, Some(n_past as u32), None);

        // 4. Re-seed the draft context from this decode for the next block.
        spec.process(&batch).map_err(|e| Error::SpeculativeUnavailable {
            reason: format!("MtpSpeculative process failed: {}", e),
        })?;

        // 5. Accept the longest matching prefix.
        let mut n_accepted: u16 = 0;
        let mut idx: i32 = 0;
        let mut stop_now = false;
        loop {
            let sampled = sampler.sample(spec.target_context_mut(), idx);
            sampler.accept(sampled);
            id_last = sampled;
            prompt_so_far.push(sampled);
            if target_model.is_eog_token(sampled) {
                stop_now = true;
                break;
            }
            output_tokens += 1;
            if let Ok(piece) = target_model.token_to_piece(sampled, &mut decoder, true, None) {
                if !(stream.push(&piece, token_tx) && !stream.hit_stop()) {
                    stop_now = true;
                }
            }
            let matched = (idx as usize) < drafts.len() && sampled == drafts[idx as usize];
            if matched {
                n_accepted += 1;
                idx += 1;
                if stop_now || output_tokens >= config.max_tokens {
                    break;
                }
            } else {
                break;
            }
        }

        // 6. Tell the drafter how many drafts were accepted.
        if !drafts.is_empty() {
            spec.accept(n_accepted).map_err(|e| Error::SpeculativeUnavailable {
                reason: format!("MtpSpeculative accept failed: {}", e),
            })?;
        }

        // 7. Advance and trim rejected-draft KV from both contexts.
        n_past += 1 + n_accepted as i32;
        let _ = spec
            .target_context_mut()
            .kv_cache_seq_rm(0, Some(n_past as u32), None);
        let _ = spec
            .draft_context_mut()
            .kv_cache_seq_rm(0, Some(n_past as u32), None);

        if stop_now {
            break 'genloop;
        }
    }

    let elapsed = start.elapsed();
    let generation_time_ms = elapsed.as_millis() as u64;
    let tokens_per_second = if generation_time_ms > 0 {
        (output_tokens as f64) / (generation_time_ms as f64 / 1000.0)
    } else {
        0.0
    };
    let stop_reason = StopReason::from_loop(stream.hit_stop(), output_tokens, config.max_tokens);
    let (text, thinking) = stream.finish_parts(token_tx);
    Ok(InferenceResult {
        text,
        thinking,
        input_tokens,
        output_tokens,
        generation_time_ms,
        tokens_per_second,
        stop_reason,
        // Speculative decode does not record a commitment yet; the top-k
        // capture lives in the standard decode loop that moves in with the
        // orchestrator.
        commitment: None,
    })
}
