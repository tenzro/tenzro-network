//! Inference result and stop-reason types.

use serde::{Deserialize, Serialize};

/// Why generation stopped. The text alone cannot distinguish a trimmed stop
/// sequence from an end-of-generation token, so this reports the cause beside
/// the token counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The model emitted an end-of-generation token.
    Eos,
    /// The token budget in [`crate::config::GenerationConfig::max_tokens`] was
    /// exhausted.
    Length,
    /// Decoded text ended with one of the configured stop sequences.
    StopSequence,
}

impl StopReason {
    /// Termination cause for a loop that ran to completion: a stop sequence
    /// wins over an exhausted budget, since the sequence is what halted
    /// decoding.
    pub fn from_loop(hit_stop: bool, output_tokens: u32, max_tokens: u32) -> Self {
        if hit_stop {
            Self::StopSequence
        } else if output_tokens >= max_tokens {
            Self::Length
        } else {
            Self::Eos
        }
    }

    /// Wire spelling, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eos => "eos",
            Self::Length => "length",
            Self::StopSequence => "stop_sequence",
        }
    }
}

/// Result from running inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// What the caller is meant to see. Reasoning spans are already removed, so
    /// a caller never has to strip `<think>` itself.
    pub text: String,
    /// The model's reasoning, when it produced any. Separate from [`Self::text`]
    /// so a surface can render, collapse or drop it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    /// Prompt token count.
    pub input_tokens: u32,
    /// Generated token count.
    pub output_tokens: u32,
    /// Wall-clock generation time in milliseconds.
    pub generation_time_ms: u64,
    /// Decode throughput in tokens per second.
    pub tokens_per_second: f64,
    /// Engine-observed termination cause.
    pub stop_reason: StopReason,
    /// Verifiable-inference commitment, present when the request set
    /// [`crate::config::GenerationConfig::commitment_k`]. Carries the per-step
    /// top-k logit records a verifier can recompute against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<crate::toploc::InferenceCommitment>,
}

/// A chat message with role and content, for chat-template formatting.
///
/// The tool fields carry a turn's tool structure to templates that render tool
/// history themselves. A model whose template has tool branches — muse-glimmer
/// renders an assistant tool call as `<|start|>assistant to=NAME<|message|>`
/// plus ATEM markup, and a result as `<|start|>tool NAME<|message|><tool_output
/// …>` — must be shown its own dialect, because it will imitate whatever its
/// history shows it. Flattening tool history into text taught it a foreign
/// dialect, which it then reproduced instead of calling a tool: measured,
/// giving it `<tool_use …>` XML made it emit `<tool_use …>` XML, and giving it
/// prose made it emit prose.
///
/// Every field is optional and skipped when absent, so a template that has no
/// tool branches sees exactly what it saw before.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message role (`system`, `user`, `assistant`, `tool`, …).
    pub role: String,
    /// Message content.
    pub content: String,
    /// Tool calls this assistant turn made, in the OpenAI shape templates
    /// expect: `[{id, type: "function", function: {name, arguments}}]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<serde_json::Value>,
    /// For `role == "tool"`: the tool that produced this result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// For `role == "tool"`: the call this result answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    /// A plain turn with no tool structure — the shape every caller used before
    /// the tool fields existed.
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
            ..Default::default()
        }
    }
}
