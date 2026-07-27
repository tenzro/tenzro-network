//! Message content shapes for the OpenAI-compatible chat surface.
//!
//! A chat message's `content` arrives either as a bare string or as an array of
//! typed parts. The array form is how image, audio and file inputs reach a
//! model. Both shapes are modelled here so a gateway node can re-serialize a
//! proxied request in the shape the client sent — a provider that only accepts
//! one of the two forms still receives a valid request, and a multimodal
//! request reaches a capable peer with its parts intact.

use serde::{Deserialize, Serialize};

/// An image reference in a content part. `url` is either an `https://` URL or a
/// `data:` URI carrying base64 bytes. `detail` is the resolution hint
/// (`auto` / `low` / `high`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImageUrlPart {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Base64 audio bytes plus their container format (`wav` / `mp3`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputAudioPart {
    pub data: String,
    pub format: String,
}

/// A file input, either uploaded ahead of time (`file_id`) or inlined as
/// base64 (`file_data` with `filename`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilePart {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// One part of a multimodal message body. The tag field is `type`, matching the
/// OpenAI wire shape (`{"type": "image_url", "image_url": {…}}`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
    ImageUrl { image_url: ImageUrlPart },
    InputAudio { input_audio: InputAudioPart },
    File { file: FilePart },
}

impl ContentPart {
    /// The wire `type` value, for error messages that name the part a runtime
    /// could not render.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Text { .. } => "text",
            Self::ImageUrl { .. } => "image_url",
            Self::InputAudio { .. } => "input_audio",
            Self::File { .. } => "file",
        }
    }
}

/// A message body: a bare string or an array of parts. Untagged, so it
/// deserializes from whichever shape the client sent and serializes back into
/// that same shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

impl MessageContent {
    /// Flatten to plain text for a text-only runtime. Multiple text parts are
    /// newline-joined rather than concatenated, so adjacent parts do not fuse
    /// into a single word.
    pub fn as_text(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Parts(parts) => parts
                .iter()
                .filter_map(|p| match p {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    /// The `type` of the first part a text-only runtime cannot render, or
    /// `None` when the whole body is text. Callers refuse the request rather
    /// than silently dropping the part a caller paid to have processed.
    pub fn unsupported_part(&self) -> Option<&'static str> {
        match self {
            Self::Text(_) => None,
            Self::Parts(parts) => parts
                .iter()
                .find(|p| !matches!(p, ContentPart::Text { .. }))
                .map(ContentPart::type_name),
        }
    }

    /// Canonical bytes for hashing this body into a signed receipt. The string
    /// form hashes verbatim; the parts form hashes its JSON serialization so
    /// image URLs and inlined bytes are bound by the receipt too, not just the
    /// text parts. Both the gateway and the serving node derive this from the
    /// same serializer, so their digests agree over the wire.
    pub fn canonical_input(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Parts(parts) => serde_json::to_string(parts).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_content_round_trips_as_a_string() {
        let c: MessageContent = serde_json::from_str(r#""hello""#).unwrap();
        assert_eq!(c.as_text(), "hello");
        assert_eq!(serde_json::to_string(&c).unwrap(), r#""hello""#);
        assert!(c.unsupported_part().is_none());
    }

    #[test]
    fn parts_content_round_trips_as_an_array() {
        let wire = r#"[{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"https://example.test/a.png"}}]"#;
        let c: MessageContent = serde_json::from_str(wire).unwrap();
        assert_eq!(c.as_text(), "describe");
        assert_eq!(c.unsupported_part(), Some("image_url"));
        assert_eq!(serde_json::to_string(&c).unwrap(), wire);
    }

    #[test]
    fn multiple_text_parts_join_with_newlines() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"text","text":"one"},{"type":"text","text":"two"}]"#,
        )
        .unwrap();
        assert_eq!(c.as_text(), "one\ntwo");
        assert!(c.unsupported_part().is_none());
    }

    #[test]
    fn canonical_input_binds_every_part() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"text","text":"hi"},{"type":"input_audio","input_audio":{"data":"AA==","format":"wav"}}]"#,
        )
        .unwrap();
        let canonical = c.canonical_input();
        assert!(canonical.contains("input_audio"));
        assert!(canonical.contains("AA=="));
    }

    #[test]
    fn detail_and_file_fields_are_omitted_when_unset() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"file","file":{"file_id":"f-1"}}]"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"[{"type":"file","file":{"file_id":"f-1"}}]"#
        );
    }
}
