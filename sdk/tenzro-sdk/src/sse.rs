//! Incremental Server-Sent Events decoder.
//!
//! Network reads cut a stream at arbitrary byte offsets: inside a UTF-8
//! character, between the `\r` and `\n` of a line break, or in the middle of
//! a multi-line event. [`SseDecoder`] buffers across reads and yields an event
//! only once its terminating blank line has arrived. [`SseDecoder::finish`]
//! flushes an event the stream ended without terminating.

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field, when the event named one.
    pub event: Option<String>,
    /// The `data:` lines, joined with `\n`.
    pub data: String,
    /// The last `id:` seen on the stream so far.
    pub id: Option<String>,
}

/// Decodes a byte stream into [`SseEvent`]s. Accepts `\r\n`, `\n` and `\r`
/// line breaks, skips `:` comment lines, and ignores unknown fields.
#[derive(Debug, Default)]
pub struct SseDecoder {
    line: Vec<u8>,
    after_cr: bool,
    data: Option<String>,
    event: Option<String>,
    last_id: Option<String>,
}

impl SseDecoder {
    /// A decoder at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb one network read and return the events it completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        for &b in bytes {
            if std::mem::take(&mut self.after_cr) && b == b'\n' {
                continue;
            }
            match b {
                b'\n' => self.end_line(&mut out),
                b'\r' => {
                    self.end_line(&mut out);
                    self.after_cr = true;
                }
                _ => self.line.push(b),
            }
        }
        out
    }

    /// End of stream: process an unterminated last line and dispatch the
    /// event it belongs to.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if !self.line.is_empty() {
            self.end_line(&mut out);
        }
        self.dispatch(&mut out);
        out
    }

    fn end_line(&mut self, out: &mut Vec<SseEvent>) {
        let raw = std::mem::take(&mut self.line);
        if raw.is_empty() {
            self.dispatch(out);
            return;
        }
        let line = String::from_utf8_lossy(&raw);
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.find(':') {
            Some(i) => {
                let value = &line[i + 1..];
                (&line[..i], value.strip_prefix(' ').unwrap_or(value))
            }
            None => (&line[..], ""),
        };
        match field {
            "data" => match self.data.as_mut() {
                Some(data) => {
                    data.push('\n');
                    data.push_str(value);
                }
                None => self.data = Some(value.to_string()),
            },
            "event" => self.event = Some(value.to_string()),
            "id" if !value.contains('\0') => self.last_id = Some(value.to_string()),
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        let event = self.event.take();
        if let Some(data) = self.data.take() {
            out.push(SseEvent {
                event,
                data,
                id: self.last_id.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut d = SseDecoder::new();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(c));
        }
        out.extend(d.finish());
        out
    }

    #[test]
    fn joins_multi_line_data_and_tracks_id() {
        let events = decode_all(&[b"id: a:1\nevent: x\ndata: one\ndata:two\n\ndata: three\n\n"]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "one\ntwo");
        assert_eq!(events[0].event.as_deref(), Some("x"));
        assert_eq!(events[0].id.as_deref(), Some("a:1"));
        assert_eq!(events[1].event, None);
        assert_eq!(events[1].id.as_deref(), Some("a:1"));
    }

    #[test]
    fn crlf_split_between_reads_is_one_line_break() {
        let events = decode_all(&[b"data: a\r", b"\ndata: b\r\n\r", b"\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb");
    }

    #[test]
    fn comments_and_blank_events_dispatch_nothing() {
        let events = decode_all(&[b": ping\n\n\n: again\n\n"]);
        assert!(events.is_empty());
    }

    #[test]
    fn unterminated_last_event_is_flushed() {
        let events = decode_all(&[b"data: [DO", b"NE]"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "[DONE]");
    }

    #[test]
    fn utf8_split_inside_a_character_survives() {
        let bytes = "data: wörld\n\n".as_bytes();
        let cut = "data: w".len() + 1;
        let events = decode_all(&[&bytes[..cut], &bytes[cut..]]);
        assert_eq!(events[0].data, "wörld");
    }
}
