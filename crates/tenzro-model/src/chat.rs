//! Chat request and result types.
//!
//! The shapes a chat request and its reply take on every path: a local model
//! run by `ModelRuntime`, and a request forwarded to a provider over the
//! network. They build without the `engine` feature, so a node that serves no
//! model still speaks the same request and reply types.

use serde::{Deserialize, Serialize};

// StopReason, InferenceResult, ChatMessage and GenerationConfig live in
// praecise-runtime with the other generation types, outside its llama.cpp
// backend. Re-exported so the public `tenzro_model::` surface stays unchanged.
pub use praecise_runtime::{ChatMessage, GenerationConfig, InferenceResult, StopReason};

/// Tool definition passed into `ModelRuntime::generate_chat_with_tools`.
///
/// Mirrors the rich-shape `ToolSchema` used at the RPC layer but stays
/// in the inference crate to avoid pulling RPC types into runtime code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input. Must be a JSON object.
    pub input_schema: serde_json::Value,
}

/// A tool invocation extracted from model output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCall {
    /// Caller-assigned (or model-emitted) call id; we synthesize one if the
    /// model didn't supply it.
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// Result of a tool-aware chat generation. Carries the same per-token
/// stats as [`InferenceResult`] plus extracted tool calls and the
/// stop reason inferred from the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatWithToolsResult {
    /// Free-text portion of the model's reply (with tool-call markers and any
    /// reasoning span stripped).
    pub text: String,
    /// The model's reasoning span, when it emitted one. Carried separately so
    /// a caller can render or discard it; it must never be concatenated into
    /// [`Self::text`], which is the answer.
    pub thinking: Option<String>,
    /// Tool calls extracted from the raw output, in emission order.
    pub tool_calls: Vec<ToolCall>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub generation_time_ms: u64,
    pub tokens_per_second: f64,
    /// Why generation stopped: `"end_turn"`, `"tool_use"`, `"max_tokens"`,
    /// `"stop_sequence"`. Mirrors the spec's `stop_reason` enum.
    pub stop_reason: String,
    /// TOPLOC top-k logit commitment, when the caller requested one via
    /// [`GenerationConfig::commitment_k`] and the single-token serial
    /// path served the request. `None` for the batch engine and speculative
    /// decoding.
    pub commitment: Option<crate::toploc::InferenceCommitment>,
}

/// The literal that marks where an attachment binds in a multimodal prompt.
///
/// A caller that assembles its own prompt writes one of these per attachment,
/// in the position the attachment belongs, and mtmd substitutes the encoded
/// embeddings there. Callers that place none get one per attachment prepended
/// to the last user turn.
///
/// Built without the `mtmd` feature it is llama.cpp's default marker as a
/// literal: a node that runs no model still renders a prompt the way the
/// provider it forwards to will read it.
pub fn media_marker() -> &'static str {
    #[cfg(feature = "mtmd")]
    {
        llama_cpp_2::mtmd::mtmd_default_marker()
    }
    #[cfg(not(feature = "mtmd"))]
    {
        "<__media__>"
    }
}
