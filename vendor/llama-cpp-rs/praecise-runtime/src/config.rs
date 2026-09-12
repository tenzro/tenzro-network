//! Generation configuration for a single inference request.

use serde::{Deserialize, Serialize};

/// Configuration for text generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationConfig {
    /// Sampling temperature.
    pub temperature: f64,
    /// Nucleus (top-p) sampling threshold.
    pub top_p: f64,
    /// Maximum number of tokens to generate.
    pub max_tokens: u32,
    /// Repetition penalty applied over the recent window.
    pub repeat_penalty: f32,
    /// Number of recent tokens the repetition penalty considers.
    pub repeat_last_n: usize,
    /// RNG seed.
    pub seed: u64,
    /// Top-k truncation. `None` leaves the candidate set untruncated by rank,
    /// which is what the nucleus (`top_p`) stage alone does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Minimum-probability floor relative to the most likely token. `None`
    /// disables the stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_p: Option<f64>,
    /// Per-occurrence logit penalty. `0.0` disables it.
    #[serde(default)]
    pub frequency_penalty: f32,
    /// Flat logit penalty for any token already present. `0.0` disables it.
    #[serde(default)]
    pub presence_penalty: f32,
    /// Stop sequences. Generation halts as soon as the decoded text ends with
    /// one of these, and the matched suffix is trimmed from the returned text
    /// so the caller never sees the delimiter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// Optional speculative-decoding draft count. `Some(n)` asks the runtime to
    /// use the model's paired drafter (DFlash / MTP head) and propose `n`
    /// tokens per verification round; `None` falls back to single-token
    /// autoregressive sampling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_n: Option<u8>,
    /// Verifiable-inference commitment width. `Some(k)` records the top-`k`
    /// logits at each generated step so the result carries a
    /// [`crate::toploc::InferenceCommitment`] a verifier can later recompute
    /// and check; `None` disables it (no commitment overhead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_k: Option<u8>,
    /// Reasoning budget for model families whose chat template exposes one
    /// (Qwen 3.8: `xhigh` — its own default — plus `medium` and `low`). This is
    /// a template variable rather than a sampler setting, so it is rendered
    /// into the prompt, not applied to logits. `None` leaves the template's
    /// default in place; an unrecognised value is rejected by the template
    /// itself rather than being silently dropped here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// OpenAI-style structured-output constraint (`{"type":"json_schema",…}`,
    /// `{"type":"json_object"}`), forwarded verbatim to external engines —
    /// SGLang enforces it at the sampler through its grammar backend
    /// (xgrammar), so a constrained response cannot be malformed. The
    /// in-process llama.cpp path does not enforce it yet and ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<serde_json::Value>,
    /// Per-request override of the served model's thinking mode, for chat
    /// templates with an `enable_thinking` toggle (Qwen 3.x, Gemma 4). `None`
    /// keeps the engine's default — which an operator may have pinned off for
    /// an API-facing model so plain callers get answers, not deliberation.
    /// `Some(true)` is how a client that *renders* the reasoning (a coding
    /// assistant showing its process) asks for it on a request-by-request
    /// basis; the host returns it separately from the answer so the two never
    /// mix in the caller's output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_thinking: Option<bool>,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.9,
            max_tokens: 512,
            repeat_penalty: 1.1,
            repeat_last_n: 64,
            seed: 42,
            top_k: None,
            min_p: None,
            frequency_penalty: 0.0,
            presence_penalty: 0.0,
            stop: Vec::new(),
            draft_n: None,
            commitment_k: None,
            reasoning_effort: None,
            response_format: None,
            enable_thinking: None,
        }
    }
}
