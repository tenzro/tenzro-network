//! Deterministic re-prefill failover for proxied streaming completions.
//!
//! When a network model is served by a remote provider and that provider
//! drops mid-generation (TLS reset, stall, process death), the gateway node
//! has already forwarded some tokens to the client. Re-issuing the original
//! prompt against a fresh provider would restart the completion from token 0
//! — the client sees the text rewind and pay twice.
//!
//! Instead the gateway captures enough state to let a *different* provider
//! continue where the first left off: the original chat messages, the
//! sampling parameters (seed, temperature, top_p, max_tokens), and the
//! assistant text emitted so far. The continuation request feeds the emitted
//! text back as the prefix of the assistant turn. Because the sampling seed
//! and parameters travel with the request, a provider serving the same model
//! re-prefills the identical prefix and resumes sampling from the same
//! distribution — the client sees an uninterrupted stream.
//!
//! This is metadata-only failover: no KV-cache bytes cross the wire (a 4k
//! prefix is >1 GB of KV state). The receiving provider re-computes the
//! prefix from the emitted text, which is the same trade the local
//! [`crate::streaming::cursor`] resume path makes for client reconnects.

use crate::chat_content::MessageContent;
use serde::{Deserialize, Serialize};

/// A single chat turn in the OpenAI `{role, content}` shape. `content` keeps the
/// string-or-parts shape the client sent, so a continuation re-sends a
/// multimodal turn with its image and audio parts intact — a continuation that
/// dropped them would re-prefill a different context and break determinism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTurn {
    pub role: String,
    pub content: MessageContent,
}

/// Captured sampling state for a proxied streaming completion, sufficient for
/// a different provider to deterministically re-prefill the emitted prefix and
/// continue the stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingState {
    /// The model id the completion targets. The continuation must land on a
    /// provider serving the same model — a different model would tokenize the
    /// prefix differently and break determinism.
    pub model_id: String,
    /// The original request messages, verbatim. The continuation request
    /// re-sends these so the new provider re-derives the full context.
    pub messages: Vec<ChatTurn>,
    /// Sampling seed. Travels with the continuation so the receiving provider
    /// samples from the identical distribution. Defaults to the runtime
    /// default (42) when the client did not pin one.
    pub seed: u64,
    /// Sampling temperature, as sent by the client (`None` = provider default).
    pub temperature: Option<f64>,
    /// Nucleus sampling top_p, as sent by the client (`None` = provider default).
    pub top_p: Option<f64>,
    /// Output-token ceiling, as sent by the client (`None` = provider default).
    /// The continuation reduces this by the number of tokens already emitted so
    /// the combined completion honours the original ceiling.
    pub max_tokens: Option<u32>,
    /// Multi-Token-Prediction draft count, carried through so the continuation
    /// keeps the same throughput profile.
    pub draft_n: Option<u8>,
    /// Assistant text emitted to the client before the drop. Fed back as the
    /// prefix of the assistant turn in the continuation request.
    pub emitted_text: String,
    /// Approximate count of tokens emitted so far, used only to shrink
    /// `max_tokens` for the continuation. Word-count is a deliberate
    /// under-estimate — undershooting the ceiling is safe, overshooting would
    /// truncate the continuation early.
    pub emitted_token_estimate: u32,
}

impl SamplingState {
    /// Build the capture from an incoming request's messages + sampling params.
    /// `emitted_text` starts empty and is grown by [`Self::record_emitted`] as
    /// the proxy loop forwards deltas.
    pub fn new(
        model_id: String,
        messages: Vec<ChatTurn>,
        seed: u64,
        temperature: Option<f64>,
        top_p: Option<f64>,
        max_tokens: Option<u32>,
        draft_n: Option<u8>,
    ) -> Self {
        Self {
            model_id,
            messages,
            seed,
            temperature,
            top_p,
            max_tokens,
            draft_n,
            emitted_text: String::new(),
            emitted_token_estimate: 0,
        }
    }

    /// Fold an emitted assistant delta into the captured prefix. Called for
    /// every forwarded SSE frame's `choices[0].delta.content`.
    pub fn record_emitted(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }
        self.emitted_text.push_str(delta);
        // Whitespace-split word count as a token under-estimate.
        self.emitted_token_estimate = self.emitted_text.split_whitespace().count() as u32;
    }

    /// Whether any assistant text was emitted before the drop. A drop before
    /// the first token is a plain call failure, not a mid-stream continuation
    /// — the caller retries from scratch rather than through this path.
    pub fn has_emitted(&self) -> bool {
        !self.emitted_text.is_empty()
    }

    /// Build the continuation request body for a different provider. The
    /// assistant text emitted so far is appended as a trailing assistant
    /// message; a provider that supports prefix continuation re-prefills it and
    /// resumes sampling. `max_tokens` is reduced by the emitted estimate so the
    /// combined output honours the original ceiling.
    pub fn continuation_body(&self) -> serde_json::Value {
        let mut messages = self.messages.clone();
        messages.push(ChatTurn {
            role: "assistant".to_string(),
            content: MessageContent::Text(self.emitted_text.clone()),
        });
        let remaining_max = self
            .max_tokens
            .map(|m| m.saturating_sub(self.emitted_token_estimate).max(1));
        serde_json::json!({
            "model": self.model_id,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": remaining_max,
            "top_p": self.top_p,
            "stream": true,
            "draft_n": self.draft_n,
            "seed": self.seed,
            // Signals to a Tenzro-aware provider that the trailing assistant
            // message is a prefix to continue, not a completed turn — the
            // provider re-prefills it and keeps sampling rather than treating
            // it as a finished conversation turn.
            "continue_final_message": true,
        })
    }
}

/// Parse the billable units out of an OpenAI-shaped response body or streaming
/// chunk. Returns `None` when the value carries no usage block, which is every
/// delta frame of a stream.
///
/// A gateway settling for a peer needs the served counts to price what it owes,
/// and the counts have to come from the provider that generated them rather than
/// from a word-count of the forwarded text.
///
/// `usage.prompt_tokens_details.cached_tokens` is a subset of `prompt_tokens`,
/// so it is subtracted out and carried as a cached read: the two legs are priced
/// at different rates, and summing them would bill a cache hit twice.
pub fn usage_units(value: &serde_json::Value) -> Option<tenzro_types::model::BillableUnits> {
    let usage = value.get("usage").filter(|u| !u.is_null())?;
    let count = |v: Option<&serde_json::Value>| -> u32 {
        v.and_then(|v| v.as_u64()).unwrap_or(0).min(u32::MAX as u64) as u32
    };

    let prompt = count(usage.get("prompt_tokens"));
    let completion = count(usage.get("completion_tokens"));
    let cached_read = count(
        usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens")),
    )
    .min(prompt);

    // `completion_tokens_details.reasoning_tokens` is deliberately not read:
    // those tokens are already inside `completion_tokens` and so are already
    // billed as output. `reasoning_loops` counts recurrent passes, not tokens.
    Some(
        tenzro_types::model::BillableUnits::tokens(prompt - cached_read, completion)
            .with_cache(cached_read, 0),
    )
}

/// [`usage_units`] against one raw SSE chunk payload.
pub fn extract_usage_units(payload: &str) -> Option<tenzro_types::model::BillableUnits> {
    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return None;
    }
    usage_units(&serde_json::from_str::<serde_json::Value>(trimmed).ok()?)
}

/// Parse the assistant content delta out of one OpenAI streaming chunk
/// payload. Returns the `choices[0].delta.content` string when present, empty
/// otherwise (role-only opening frames, finish frames, `[DONE]`).
pub fn extract_delta_content(payload: &str) -> String {
    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return String::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return String::new();
    };
    value
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string()
}
