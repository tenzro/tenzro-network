//! Message content shapes for the OpenAI-compatible chat surface.
//!
//! A chat message's `content` arrives either as a bare string or as an array of
//! typed parts. The array form is how image, audio and file inputs reach a
//! model. Both shapes are modelled here so a gateway node can re-serialize a
//! proxied request in the shape the client sent — a provider that only accepts
//! one of the two forms still receives a valid request, and a multimodal
//! request reaches a capable peer with its parts intact.
//!
//! A model serving with a multimodal projector renders `image_url` parts whose
//! bytes are inlined as a `data:` URI; every other non-text part, and remote
//! image URLs, are refused by name rather than dropped.

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

    /// The `type` of the first part the serving runtime cannot render, or
    /// `None` when every part can be. `accepts_media` is whether the model
    /// loaded a multimodal projector: with one, `image_url` parts render
    /// through it; without one they are refused like the rest. Callers refuse
    /// the request rather than silently dropping a part a caller paid to have
    /// processed.
    pub fn unsupported_part(&self, accepts_media: bool) -> Option<&'static str> {
        match self {
            Self::Text(_) => None,
            Self::Parts(parts) => parts
                .iter()
                .find(|p| match p {
                    ContentPart::Text { .. } => false,
                    ContentPart::ImageUrl { .. } => !accepts_media,
                    _ => true,
                })
                .map(ContentPart::type_name),
        }
    }

    /// Decodes this body's image parts, in the order they appear.
    ///
    /// Only inlined bytes are read. A `data:` URI carries the image in the
    /// request itself, so the serving node needs no outbound fetch; an
    /// `https://` URL is refused, because retrieving a caller-named remote
    /// resource is not something a serving node should do on a caller's behalf,
    /// and the caller can inline the bytes instead.
    pub fn image_bytes(&self) -> Result<Vec<Vec<u8>>, String> {
        use base64::Engine as _;

        let parts = match self {
            Self::Text(_) => return Ok(Vec::new()),
            Self::Parts(parts) => parts,
        };
        let mut out = Vec::new();
        for p in parts {
            let ContentPart::ImageUrl { image_url } = p else {
                continue;
            };
            let url = image_url.url.trim();
            let Some(rest) = url.strip_prefix("data:") else {
                return Err(format!(
                    "image_url '{}' is not a data: URI — inline the bytes as \
                     data:image/png;base64,<payload> so the serving node needs no outbound fetch",
                    url.chars().take(64).collect::<String>()
                ));
            };
            let Some((meta, payload)) = rest.split_once(',') else {
                return Err(
                    "image_url data: URI has no ',' separating its metadata from its payload"
                        .to_string(),
                );
            };
            if !meta.ends_with(";base64") {
                return Err(format!(
                    "image_url data: URI must be base64-encoded (got '{}')",
                    meta
                ));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(payload)
                .map_err(|e| format!("image_url data: URI carries undecodable base64: {}", e))?;
            out.push(bytes);
        }
        Ok(out)
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
        assert!(c.unsupported_part(false).is_none());
        assert!(c.image_bytes().unwrap().is_empty());
    }

    #[test]
    fn parts_content_round_trips_as_an_array() {
        let wire = r#"[{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"https://example.test/a.png"}}]"#;
        let c: MessageContent = serde_json::from_str(wire).unwrap();
        assert_eq!(c.as_text(), "describe");
        assert_eq!(c.unsupported_part(false), Some("image_url"));
        assert_eq!(serde_json::to_string(&c).unwrap(), wire);
    }

    #[test]
    fn multiple_text_parts_join_with_newlines() {
        let c: MessageContent =
            serde_json::from_str(r#"[{"type":"text","text":"one"},{"type":"text","text":"two"}]"#)
                .unwrap();
        assert_eq!(c.as_text(), "one\ntwo");
        assert!(c.unsupported_part(false).is_none());
    }

    #[test]
    fn image_parts_are_supported_only_with_a_projector() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAEC"}}]"#,
        )
        .unwrap();
        assert_eq!(c.unsupported_part(false), Some("image_url"));
        assert!(c.unsupported_part(true).is_none());
        assert_eq!(c.image_bytes().unwrap(), vec![vec![0u8, 1, 2]]);
    }

    #[test]
    fn audio_and_file_parts_are_refused_even_with_a_projector() {
        let audio: MessageContent = serde_json::from_str(
            r#"[{"type":"input_audio","input_audio":{"data":"AA==","format":"wav"}}]"#,
        )
        .unwrap();
        assert_eq!(audio.unsupported_part(true), Some("input_audio"));
        let file: MessageContent =
            serde_json::from_str(r#"[{"type":"file","file":{"file_id":"f-1"}}]"#).unwrap();
        assert_eq!(file.unsupported_part(true), Some("file"));
    }

    #[test]
    fn remote_image_urls_are_refused_rather_than_fetched() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"image_url","image_url":{"url":"https://example.test/a.png"}}]"#,
        )
        .unwrap();
        let err = c.image_bytes().unwrap_err();
        assert!(err.contains("not a data: URI"), "{err}");
    }

    #[test]
    fn image_bytes_follow_part_order() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAE="}},
                {"type":"text","text":"and"},
                {"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/"}}]"#,
        )
        .unwrap();
        let images = c.image_bytes().unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0], vec![0u8, 1]);
        assert_eq!(images[1][0..3], [0xFF, 0xD8, 0xFF]);
    }

    #[test]
    fn non_base64_data_uris_are_refused() {
        let c: MessageContent = serde_json::from_str(
            r#"[{"type":"image_url","image_url":{"url":"data:image/png,rawbytes"}}]"#,
        )
        .unwrap();
        assert!(c.image_bytes().unwrap_err().contains("must be base64"));
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
        let c: MessageContent =
            serde_json::from_str(r#"[{"type":"file","file":{"file_id":"f-1"}}]"#).unwrap();
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"[{"type":"file","file":{"file_id":"f-1"}}]"#
        );
    }
}
