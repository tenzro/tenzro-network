//! EU AI Act Article 50 disclosure injection.
//!
//! Article 50 (effective 2026-08-02) sets four disclosure obligations on
//! generative-AI providers:
//!
//! - **§50(1)** — humans interacting with a chatbot must be told they are
//!   interacting with an AI, unless that fact is "obvious from the
//!   circumstances of use." Tenzro's UX surfaces (CLI chat REPL, desktop app,
//!   website chat) carry this disclosure inline.
//! - **§50(2)** — synthetic content must be marked in machine-readable form
//!   so downstream tooling can detect AI provenance. Implemented via
//!   [`InferenceResponse::synthetic_content`] +
//!   [`InferenceResponse::provenance`] in `tenzro-types`, populated by the
//!   inference router before responses leave a provider node.
//! - **§50(3)** — emotion-recognition / biometric-categorization systems
//!   must inform exposed individuals. Out of scope for the current Tenzro
//!   model catalog.
//! - **§50(4)** — deepfakes (content imitating a real person, place, or
//!   event) must be labeled as such. Implemented via
//!   `crate::provenance::ASSERTION_DEEPFAKE` on the provenance manifest.
//!
//! This module is the **transport-neutral injection point** — it produces
//! the disclosure string and the metadata key/value pairs, and the
//! individual transports (HTTP, JSON-RPC, MCP, A2A, CLI) attach them in
//! whatever shape that surface uses. Keeping the wording in one place is
//! what gives compliance auditors a single line to point at when they ask
//! "where do you say this is AI?"
//!
//! [`InferenceResponse::synthetic_content`]: tenzro_types::InferenceResponse::synthetic_content
//! [`InferenceResponse::provenance`]: tenzro_types::InferenceResponse::provenance

/// Standard HTTP response header name used to surface the Art. 50(1)
/// disclosure on every MCP / Web API response that returns AI-generated
/// content. Lowercase per RFC 7230 §3.2 (header names are case-insensitive,
/// but axum normalizes to lowercase on the wire).
pub const EU_AI_DISCLOSURE_HEADER: &str = "eu-ai-disclosure";

/// Value emitted in [`EU_AI_DISCLOSURE_HEADER`] and in A2A
/// `Message.metadata.eu_ai_disclosure`. Phrased to satisfy Art. 50(1)
/// without legalese — the goal is to be understood by both software and
/// the human watching the trace.
pub const EU_AI_DISCLOSURE_TEXT: &str =
    "AI-generated content from Tenzro Network. EU AI Act Article 50(1).";

/// Metadata key used inside A2A `Message.metadata` and JSON-RPC response
/// envelopes to convey the disclosure programmatically. Kept stable across
/// transports so SDKs can surface the same flag regardless of how they
/// reached the node.
pub const EU_AI_DISCLOSURE_METADATA_KEY: &str = "eu_ai_disclosure";

/// Prefix rendered in front of every assistant-generated chunk in the CLI
/// chat REPL. The Art. 50(1) "obvious from the circumstances of use"
/// exemption arguably applies to a CLI explicitly named `tenzro chat`, but
/// erring on the side of explicit disclosure is cheap and removes the
/// auditor's argument that "obvious" was a judgment call.
pub const CLI_CHAT_AI_PREFIX: &str = "[AI]";

/// Returns a `(key, value)` pair to insert into A2A `Message.metadata` or
/// any other JSON-object-shaped metadata map.
///
/// Use case: A2A handlers receive an `InferenceResponse`, build a
/// `Message`, and call `metadata.insert(key.into(), value.into())`.
pub fn metadata_pair() -> (&'static str, &'static str) {
    (EU_AI_DISCLOSURE_METADATA_KEY, EU_AI_DISCLOSURE_TEXT)
}

/// Returns the canonical `(header_name, header_value)` pair for HTTP
/// responses (MCP, Web API, A2A SSE).
pub fn http_header_pair() -> (&'static str, &'static str) {
    (EU_AI_DISCLOSURE_HEADER, EU_AI_DISCLOSURE_TEXT)
}

/// Renders an assistant chat chunk with the Art. 50(1) prefix. Idempotent:
/// already-prefixed strings are returned unchanged so the CLI doesn't end
/// up emitting `[AI] [AI] hello`.
pub fn render_cli_chat_chunk(text: &str) -> String {
    let trimmed = text.trim_start();
    if trimmed.starts_with(CLI_CHAT_AI_PREFIX) {
        text.to_string()
    } else {
        format!("{} {}", CLI_CHAT_AI_PREFIX, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_pair_uses_stable_key() {
        let (k, v) = metadata_pair();
        assert_eq!(k, "eu_ai_disclosure");
        assert!(v.contains("AI-generated"));
        assert!(v.contains("Article 50"));
    }

    #[test]
    fn http_header_pair_uses_lowercase_name() {
        let (name, _) = http_header_pair();
        assert_eq!(name, "eu-ai-disclosure");
        assert!(name.chars().all(|c| !c.is_uppercase()));
    }

    #[test]
    fn render_cli_chat_chunk_prefixes_plain_text() {
        let rendered = render_cli_chat_chunk("hello world");
        assert_eq!(rendered, "[AI] hello world");
    }

    #[test]
    fn render_cli_chat_chunk_is_idempotent() {
        let once = render_cli_chat_chunk("hello world");
        let twice = render_cli_chat_chunk(&once);
        assert_eq!(once, twice, "double-prefixing must not happen");
    }

    #[test]
    fn render_cli_chat_chunk_handles_leading_whitespace() {
        // A model that already emitted `[AI]` after some indentation should
        // still be treated as already-disclosed.
        let rendered = render_cli_chat_chunk("   [AI] response");
        assert_eq!(rendered, "   [AI] response");
    }
}
