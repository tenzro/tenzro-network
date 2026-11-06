//! The shared contract fixtures under `sdk/fixtures`, which the TypeScript SDK
//! runs too: recorded chat streams decoded at every chunk boundary.

use serde_json::{Value, json};
use std::path::PathBuf;
use tenzro_sdk::{ChatStreamAssembler, SseDecoder};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

const STREAMS: &[&str] = &["content", "reasoning", "tool-calls", "usage", "error"];

/// Decode `chunks` as one stream: the events up to the end or the first
/// error, the completion, and the error.
fn run(chunks: &[&[u8]]) -> Value {
    let mut decoder = SseDecoder::new();
    let mut assembler = ChatStreamAssembler::new();
    let mut events = Vec::new();
    let mut frames = Vec::new();
    for c in chunks {
        frames.extend(decoder.push(c));
    }
    frames.extend(decoder.finish());
    for frame in frames {
        match assembler.push(&frame.data) {
            Ok(evs) => events.extend(evs),
            Err(e) => {
                return json!({ "events": events, "completion": null, "error": e });
            }
        }
        if assembler.is_done() {
            break;
        }
    }
    assert!(assembler.is_done(), "stream ended without [DONE]");
    json!({ "events": events, "completion": assembler.completion(), "error": null })
}

#[test]
fn chat_streams_decode_identically_at_every_chunk_boundary() {
    let dir = fixtures().join("chat-stream");
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    for name in STREAMS {
        let bytes = std::fs::read(dir.join(format!("{name}.sse"))).unwrap();
        let want = &expected[*name];
        assert_eq!(&run(&[&bytes]), want, "{name}: whole stream");
        for cut in 0..=bytes.len() {
            let got = run(&[&bytes[..cut], &bytes[cut..]]);
            assert_eq!(&got, want, "{name}: split at byte {cut}");
        }
        let singles: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(&run(&singles), want, "{name}: one byte per read");
    }
}

#[test]
fn reasoning_arrives_before_the_answer() {
    let bytes = std::fs::read(fixtures().join("chat-stream/reasoning.sse")).unwrap();
    let out = run(&[&bytes]);
    let kinds: Vec<&str> = out["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    let first_content = kinds.iter().position(|k| *k == "content").unwrap();
    assert!(kinds[..first_content].contains(&"reasoning"));
    assert!(!kinds[first_content..].contains(&"reasoning"));
}
