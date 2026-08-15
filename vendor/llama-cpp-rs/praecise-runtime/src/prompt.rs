//! Prompt rendering helpers (backend-free).

use crate::result::ChatMessage;

/// Render chat messages as a ChatML prompt with an open assistant turn.
///
/// The universal fallback used when a model exposes no usable embedded chat
/// template (or it renders empty). A host with model-specific templating can
/// render its own prompt and submit it as a raw string instead.
pub fn render_chatml_prompt(messages: &[ChatMessage]) -> String {
    let mut out = String::new();
    for m in messages {
        out.push_str("<|im_start|>");
        out.push_str(&m.role);
        out.push('\n');
        out.push_str(&m.content);
        out.push_str("<|im_end|>\n");
    }
    out.push_str("<|im_start|>assistant\n");
    out
}
