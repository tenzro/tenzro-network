//! Parser for muse-glimmer's harmony / onyx agentic OUTPUT format.
//!
//! muse-glimmer does not emit `<think>…</think>` + a generic tool-call
//! dialect. It emits a sequence of **channels/segments**, each addressed to a
//! recipient:
//!
//! ```text
//! to=self<|message|>We need to code a game...<|eom|>\
//! <|start|>assistant to=list_dir<|message|><|eom|>\
//! <|start|>assistant to=user<|message|>Here is the game...<|eot|>
//! ```
//!
//! - A segment begins `<|start|>assistant to=<recipient><|message|>`. The very
//!   first segment of a completion may omit the leading `<|start|>assistant`
//!   and begin `to=<recipient><|message|>`.
//! - A segment ends with `<|eom|>` (end-of-message, more segments follow),
//!   `<|eot|>` (end-of-turn, final), or simply end-of-string when the model was
//!   cut off at `max_tokens`.
//! - **recipient = `self`** → the model's private reasoning → **thinking**
//!   (collapsed, NOT shown as content).
//! - **recipient = `user`** → the final answer → **content**.
//! - **recipient = `<tool_name>`** (anything else, e.g. `list_dir`,
//!   `todo_write`) → a **tool call**: the recipient is the tool name; the
//!   arguments are in the segment body. The body may be ATEM markup
//!   (`<atem:function_calls><atem:invoke name="TOOL"><atem:parameter
//!   name="P">VALUE</atem:parameter>…</atem:invoke></atem:function_calls>`), a
//!   JSON object, or empty.
//!
//! Special tokens stripped everywhere: `<|start|>`, `<|message|>`, `<|eom|>`,
//! `<|eot|>`, `<|end|>`, `<|return|>`, `<|channel|>`, and the
//! `assistant`/`to=<recipient>` headers. (Token ids for reference: eom=200007,
//! eot=200008, eos=200001 — but this operates on the detokenized TEXT.)
//!
//! This is intentionally model-aware: the generic `<think>` splitter and the
//! generic tool-call extractor are left to handle qwen/gemma/deepseek/glm and
//! every other model unchanged. Only muse-glimmer is routed here.

use crate::runtime::ToolCall;

/// Whether a served model emits the muse-glimmer harmony/onyx output format and
/// should be parsed with [`parse_muse_harmony`] instead of the generic
/// `<think>` splitter + generic tool extraction.
///
/// Matches the catalog id (`muse-glimmer-30b`) and family (`muse-glimmer`), so
/// it also holds for any future muse-glimmer size or a re-served copy under a
/// name that keeps the family stem.
pub(crate) fn is_muse_harmony_model(model_id: &str) -> bool {
    let m = model_id.to_ascii_lowercase();
    m.contains("muse-glimmer") || m.contains("muse_glimmer")
}

/// The parsed result of a muse-glimmer completion: reasoning collapsed into
/// `thinking`, the user-facing answer in `content`, and each tool segment as a
/// [`ToolCall`] in emission order.
#[derive(Debug, Clone)]
pub struct MuseParsed {
    /// Concatenation of every `to=self` body — the model's reasoning. `None`
    /// when the model emitted no reasoning segment.
    pub thinking: Option<String>,
    /// Concatenation of every `to=user` body — the final answer.
    pub content: String,
    /// One entry per `to=<tool>` segment, in the order the model emitted them.
    pub tool_calls: Vec<ToolCall>,
}

/// Tokens that terminate a segment body. A body runs from just past its
/// `<|message|>` to the earliest of these (or end-of-string).
const SEGMENT_TERMINATORS: &[&str] = &[
    "<|eom|>",
    "<|eot|>",
    "<|start|>",
    "<|end|>",
    "<|return|>",
    "<|channel|>",
];

const MESSAGE: &str = "<|message|>";

/// Parse a raw muse-glimmer completion into thinking / content / tool_calls.
///
/// Robust to: a missing leading `<|start|>assistant`, a final segment ended by
/// `<|eot|>` or by end-of-string (no terminator, e.g. a `max_tokens` cutoff),
/// whitespace/newlines, and empty bodies. A `to=` occurring inside prose is not
/// mistaken for a header because a header requires a valid identifier recipient
/// immediately followed by `<|message|>`.
pub(crate) fn parse_muse_harmony(raw: &str) -> MuseParsed {
    let mut thinking = String::new();
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();

    // Walk segment by segment. A header is `to=<recipient><|message|>`; the
    // body runs to the next segment terminator or end-of-string.
    let mut pos = 0usize;
    while let Some(rel) = raw[pos..].find("to=") {
        let to_at = pos + rel;
        let after_to = to_at + "to=".len();

        // The recipient runs from just past `to=` up to `<|message|>`.
        let Some(msg_rel) = raw[after_to..].find(MESSAGE) else {
            break;
        };
        let msg_at = after_to + msg_rel;
        let recipient = raw[after_to..msg_at].trim();

        // A real header names a single identifier recipient. If the slice
        // between `to=` and `<|message|>` is not one, this `to=` is prose (or a
        // malformed head) — step past it and keep scanning rather than swallow
        // the rest of the stream as a bogus segment.
        if !is_valid_recipient(recipient) {
            pos = after_to;
            continue;
        }

        let body_start = msg_at + MESSAGE.len();
        let body_end = SEGMENT_TERMINATORS
            .iter()
            .filter_map(|t| raw[body_start..].find(t).map(|i| body_start + i))
            .min()
            .unwrap_or(raw.len());
        let body = raw[body_start..body_end].trim();

        match recipient {
            "self" => append_body(&mut thinking, body),
            "user" => append_body(&mut content, body),
            tool => {
                tool_calls.push(ToolCall {
                    id: synth_call_id(),
                    name: tool.to_string(),
                    input: parse_tool_args(body),
                });
            }
        }

        pos = body_end;
    }

    let thinking = thinking.trim().to_string();
    MuseParsed {
        thinking: (!thinking.is_empty()).then_some(thinking),
        content: content.trim().to_string(),
        tool_calls,
    }
}

/// Append a (already-trimmed) body to an accumulator, newline-separating
/// multiple bodies of the same recipient and skipping empties.
fn append_body(acc: &mut String, body: &str) {
    if body.is_empty() {
        return;
    }
    if !acc.is_empty() {
        acc.push('\n');
    }
    acc.push_str(body);
}

/// A recipient is a short identifier: `self`, `user`, or a tool name such as
/// `list_dir` / `todo_write`. Anything with whitespace, a marker, or an
/// out-of-range character is prose that happened to contain `to=`.
fn is_valid_recipient(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 64
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Parse a tool segment body into an arguments object.
///
/// - Empty body → `{}`.
/// - JSON object → used as-is.
/// - ATEM markup → `{param: value, …}`.
/// - Anything else → `{}` (never drop the call over an unreadable body).
fn parse_tool_args(body: &str) -> serde_json::Value {
    let body = body.trim();
    if body.is_empty() {
        return empty_object();
    }

    // A JSON object body is used verbatim.
    if body.starts_with('{')
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            return v;
        }

    // ATEM markup body.
    if body.contains("<atem:")
        && let Some(v) = parse_atem_params(body) {
            return v;
        }

    empty_object()
}

/// Parse ATEM invoke blocks that arrive WITHOUT a harmony `to=<tool>` header.
///
/// muse normally names the tool in the segment header and puts only the
/// arguments in the body, which [`parse_muse_harmony`] handles. Mid-agent-loop
/// it also emits the markup bare — `<atem:function_calls><atem:invoke
/// name="TOOL">…</atem:invoke></atem:function_calls>` with no header at all —
/// and then the tool name is in the `invoke` tag instead. Unparsed, that
/// reached the caller as prose and the run ended a step early while reporting
/// success.
///
/// Returns the text with the consumed blocks removed, plus the calls found.
pub(crate) fn parse_bare_atem(raw: &str) -> (String, Vec<ToolCall>) {
    const OPEN: &str = "<atem:invoke";
    const CLOSE: &str = "</atem:invoke>";

    let mut calls = Vec::new();
    let mut text = raw.to_string();

    while let Some(start) = text.find(OPEN) {
        let after_open = start + OPEN.len();
        let Some(gt_rel) = text[after_open..].find('>') else {
            break;
        };
        let attrs_end = after_open + gt_rel;
        let Some(close_rel) = text[attrs_end..].find(CLOSE) else {
            // Truncated mid-emission: leave it and stop rather than invent a
            // call from half of one.
            break;
        };
        let body_end = attrs_end + close_rel;
        let close_end = body_end + CLOSE.len();

        let name = extract_attr(&text[after_open..attrs_end], "name");
        let body = text[attrs_end + 1..body_end].trim().to_string();

        match name {
            Some(name) if !name.is_empty() => {
                calls.push(ToolCall {
                    id: synth_call_id(),
                    name,
                    input: parse_tool_args(&body),
                });
                text.replace_range(start..close_end, "");
            }
            // An invoke with no name is not a call we can place.
            _ => break,
        }
    }

    // Drop the wrapper the invokes sat inside, so it does not surface as text.
    for tag in [
        "<atem:function_calls>",
        "</atem:function_calls>",
        "</atem:invoke>",
        "</atem:parameter>",
    ] {
        text = text.replace(tag, "");
    }

    (text.trim().to_string(), calls)
}

/// Parse ATEM `<atem:parameter name="P">VALUE</atem:parameter>` pairs (anywhere
/// inside the body, ignoring the `<atem:function_calls>` / `<atem:invoke>`
/// wrapper) into a JSON object. Returns `None` when no parameter was found.
fn parse_atem_params(body: &str) -> Option<serde_json::Value> {
    const OPEN: &str = "<atem:parameter";
    const CLOSE: &str = "</atem:parameter>";

    let mut map = serde_json::Map::new();
    let mut from = 0usize;
    while let Some(rel) = body[from..].find(OPEN) {
        let tag_at = from + rel;
        let after_open = tag_at + OPEN.len();
        // End of the opening tag's attribute list.
        let Some(gt_rel) = body[after_open..].find('>') else {
            break;
        };
        let attrs_end = after_open + gt_rel;
        let attrs = &body[after_open..attrs_end];

        let val_start = attrs_end + 1;
        let Some(close_rel) = body[val_start..].find(CLOSE) else {
            break;
        };
        let val_end = val_start + close_rel;

        if let Some(name) = extract_attr(attrs, "name") {
            let raw_val = body[val_start..val_end].trim();
            map.insert(name, coerce_value(raw_val));
        }

        from = val_end + CLOSE.len();
    }

    (!map.is_empty()).then(|| serde_json::Value::Object(map))
}

/// Pull the value of `attr="…"` out of a tag's attribute slice.
fn extract_attr(attrs: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = attrs.find(&needle)? + needle.len();
    let end = attrs[start..].find('"')? + start;
    Some(attrs[start..end].to_string())
}

/// Coerce an ATEM parameter value string into a typed JSON value when it parses
/// as one (number, bool, null, quoted string, array, object); otherwise keep it
/// as a plain string — a bare path like `src/main.rs` is not valid JSON and
/// must survive as a string rather than be dropped.
fn coerce_value(s: &str) -> serde_json::Value {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        return v;
    }
    serde_json::Value::String(s.to_string())
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Synthesize a call id in the same shape the rest of the runtime uses when the
/// model does not supply one.
fn synth_call_id() -> String {
    format!("toolu_{}", uuid::Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The exact live example from the bug report: reasoning, an empty-arg tool
    /// call, then the final answer.
    #[test]
    fn live_example_self_tool_user() {
        let raw = "to=self<|message|>We need to code a game...<|eom|>\
                   <|start|>assistant to=list_dir<|message|><|eom|>\
                   <|start|>assistant to=user<|message|>Here is the game...<|eot|>";
        let p = parse_muse_harmony(raw);

        assert_eq!(p.thinking.as_deref(), Some("We need to code a game..."));
        assert_eq!(p.content, "Here is the game...");
        assert_eq!(p.tool_calls.len(), 1);
        assert_eq!(p.tool_calls[0].name, "list_dir");
        // Empty body → empty args object, but the call is preserved.
        assert_eq!(p.tool_calls[0].input, json!({}));
    }

    /// A tool call whose body is ATEM markup with typed and string params.
    #[test]
    fn tool_call_with_atem_params() {
        let raw = "<|start|>assistant to=todo_write<|message|>\
                   <atem:function_calls>\
                   <atem:invoke name=\"todo_write\">\
                   <atem:parameter name=\"path\">src/main.rs</atem:parameter>\
                   <atem:parameter name=\"line\">42</atem:parameter>\
                   <atem:parameter name=\"overwrite\">true</atem:parameter>\
                   </atem:invoke>\
                   </atem:function_calls><|eot|>";
        let p = parse_muse_harmony(raw);

        assert_eq!(p.thinking, None);
        assert_eq!(p.content, "");
        assert_eq!(p.tool_calls.len(), 1);
        assert_eq!(p.tool_calls[0].name, "todo_write");
        assert_eq!(
            p.tool_calls[0].input,
            json!({ "path": "src/main.rs", "line": 42, "overwrite": true })
        );
    }

    /// A tool call whose body is a JSON object is used verbatim.
    #[test]
    fn tool_call_with_json_body() {
        let raw = "to=search<|message|>{\"query\": \"rust\", \"limit\": 5}<|eot|>";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.tool_calls.len(), 1);
        assert_eq!(p.tool_calls[0].name, "search");
        assert_eq!(
            p.tool_calls[0].input,
            json!({ "query": "rust", "limit": 5 })
        );
        assert_eq!(p.content, "");
    }

    /// A response that is only a final answer to the user.
    #[test]
    fn user_only_response() {
        let raw = "<|start|>assistant to=user<|message|>The answer is 4.<|eot|>";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.thinking, None);
        assert_eq!(p.content, "The answer is 4.");
        assert!(p.tool_calls.is_empty());
    }

    /// A response with no leading `<|start|>assistant` and only a `to=user`
    /// segment terminated by `<|eot|>`.
    #[test]
    fn user_only_no_leading_start() {
        let raw = "to=user<|message|>Hello, world.<|eot|>";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.content, "Hello, world.");
        assert_eq!(p.thinking, None);
    }

    /// Interleaved self / tool / user: order preserved, thinking concatenated.
    #[test]
    fn interleaved_self_tool_user() {
        let raw = "to=self<|message|>First I think.<|eom|>\
                   <|start|>assistant to=read_file<|message|>\
                   <atem:function_calls><atem:invoke name=\"read_file\">\
                   <atem:parameter name=\"path\">a.txt</atem:parameter>\
                   </atem:invoke></atem:function_calls><|eom|>\
                   <|start|>assistant to=self<|message|>Now I know more.<|eom|>\
                   <|start|>assistant to=write_file<|message|>{\"path\":\"b.txt\"}<|eom|>\
                   <|start|>assistant to=user<|message|>Done.<|eot|>";
        let p = parse_muse_harmony(raw);

        assert_eq!(
            p.thinking.as_deref(),
            Some("First I think.\nNow I know more.")
        );
        assert_eq!(p.content, "Done.");
        assert_eq!(p.tool_calls.len(), 2);
        assert_eq!(p.tool_calls[0].name, "read_file");
        assert_eq!(p.tool_calls[0].input, json!({ "path": "a.txt" }));
        assert_eq!(p.tool_calls[1].name, "write_file");
        assert_eq!(p.tool_calls[1].input, json!({ "path": "b.txt" }));
    }

    /// A truncated final segment — `max_tokens` cut generation before any
    /// terminator. The partial body still parses.
    #[test]
    fn truncated_final_segment_no_terminator() {
        let raw = "to=self<|message|>Let me reason about this<|eom|>\
                   <|start|>assistant to=user<|message|>The answer begins here and then";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.thinking.as_deref(), Some("Let me reason about this"));
        assert_eq!(p.content, "The answer begins here and then");
        assert!(p.tool_calls.is_empty());
    }

    /// Truncated mid-reasoning: only a `to=self` opener, no body terminator and
    /// no answer.
    #[test]
    fn truncated_mid_reasoning() {
        let raw = "to=self<|message|>still thinking about the";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.thinking.as_deref(), Some("still thinking about the"));
        assert_eq!(p.content, "");
        assert!(p.tool_calls.is_empty());
    }

    /// `to=` inside prose is not mistaken for a segment header.
    #[test]
    fn to_in_prose_is_not_a_header() {
        let raw = "to=user<|message|>Set the flag to=yes when ready.<|eot|>";
        let p = parse_muse_harmony(raw);
        assert_eq!(p.content, "Set the flag to=yes when ready.");
        assert!(p.tool_calls.is_empty());
    }

    /// Empty input yields empty everything.
    #[test]
    fn empty_input() {
        let p = parse_muse_harmony("");
        assert_eq!(p.thinking, None);
        assert_eq!(p.content, "");
        assert!(p.tool_calls.is_empty());
    }

    #[test]
    fn model_detection() {
        assert!(is_muse_harmony_model("muse-glimmer-30b"));
        assert!(is_muse_harmony_model("Muse-Glimmer-30B"));
        assert!(is_muse_harmony_model("muse_glimmer"));
        assert!(!is_muse_harmony_model("qwen3.6-35b-a3b-mtp"));
        assert!(!is_muse_harmony_model("gemma-4-12b-it"));
    }
}
