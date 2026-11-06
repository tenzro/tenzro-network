//! Spoken replies from omni models: one model hears the turn (text and
//! audio), writes its reply and speaks it while writing, in the node process
//! on the Praecise engine.
//!
//! Two surfaces, both on the realtime transport:
//!
//! - `POST /tenzro/realtime/turn` with `omni_model` (instead of the
//!   `stt_model` / `chat_model` / `speech_model` legs): one turn in, the reply
//!   streamed as `reply` deltas (`text`) and `audio` chunks (`seq`,
//!   `sample_rate`, `pcm_s16le_base64`) as they are made, then `done`.
//! - `POST /tenzro/realtime/converse`: full duplex. The request body streams
//!   the listener's microphone as newline-delimited JSON (a first line
//!   `{ omni_model, voice, sample_rate? (default 16000), messages?, seed?,
//!   verification?, payment?, channel_voucher?, caller_address? }`, then
//!   `{ pcm_s16le_base64 }` lines, echo-cancelled at the client) while the
//!   answer streams back: `turn_started`, `turn_ended` (`audio_ms`), `reply`,
//!   `audio`, `barge_in` when the listener talks over the reply (the reply
//!   stops at once), and `done` per answered turn. The session keeps the
//!   conversation.
//!
//! Each answered turn is one call to the model, admitted, billed and
//! receipted on the same path every other model call takes: prompt and reply
//! tokens, audio heard and audio spoken (`BillableUnits`). A turn the
//! listener interrupts is billed for what was made up to then.

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_model::omni_runtime::{
    DuplexConfig, DuplexEvent, DuplexSession, OmniInput, OmniMessage, OmniTurn,
};
use tenzro_types::model::BillableUnits;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, bill_local_units, forecast_err, missing_param, units_to_json};
use crate::verifiable_inference::{attach_task_receipt, task_level};

/// Reply tokens a turn may ask for at most.
const MAX_REPLY_TOKENS: usize = 2048;
/// Frames a turn may ask for at most (about 5 minutes of speech at 12.5 Hz).
const MAX_FRAMES: usize = 4096;
/// Longest frame line of the duplex body.
const MAX_LINE_BYTES: usize = 4 << 20;
/// Longest duplex session.
const MAX_SESSION_MS: u64 = 3_600_000;
/// Fields a duplex session forwards to each turn unchanged.
const SHARED: &[&str] = &[
    "verification",
    "receipt_nonce",
    "payment",
    "channel_voucher",
    "caller_address",
    "seed",
    "voice",
    "max_reply_tokens",
    "max_frames",
];

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn event(name: &str, data: &Value) -> Event {
    Event::default().event(name).data(data.to_string())
}

pub(crate) fn pcm_s16le(samples: &[f32]) -> String {
    let bytes: Vec<u8> = samples
        .iter()
        .flat_map(|s| {
            #[allow(clippy::cast_possible_truncation)]
            let v = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
            v.to_le_bytes()
        })
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn messages(p: &Value) -> Result<Vec<OmniMessage>, JsonRpcError> {
    let list = p
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| missing_param("messages"))?;
    let mut out = Vec::with_capacity(list.len());
    for m in list {
        let role = m
            .get("role")
            .and_then(Value::as_str)
            .filter(|r| matches!(*r, "system" | "user" | "assistant"))
            .ok_or_else(|| invalid("each message has a role: system, user or assistant"))?;
        let text = match m.get("content") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(invalid("a message's content is text")),
        };
        let audio = match m.get("audio_base64") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(b64)) => vec![
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| invalid("audio_base64 is base64 audio (wav, mp3 or flac)"))?,
            ],
            Some(_) => return Err(invalid("audio_base64 is a string")),
        };
        if text.is_empty() && audio.is_empty() {
            return Err(invalid("a message carries text or audio"));
        }
        out.push(OmniMessage {
            role: role.to_string(),
            text,
            audio,
        });
    }
    Ok(out)
}

fn bounded(p: &Value, key: &str, max: usize) -> Result<usize, JsonRpcError> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(max),
        Some(v) => v
            .as_u64()
            .filter(|n| *n > 0 && *n as usize <= max)
            .map(|n| n as usize)
            .ok_or_else(|| invalid(format!("{key} is 1 to {max}"))),
    }
}

/// One spoken turn on this node: the reply's text and audio go to `on_text`
/// and `on_audio` as they are made; the answer's JSON (everything but the
/// audio) comes back with the turn. Params: `{ model_id, messages: [{ role,
/// content?, audio_base64? }], voice, seed?, max_reply_tokens?, max_frames?,
/// verification?, receipt_nonce?, payment? }`.
pub(crate) async fn voice_turn(
    node: &Arc<TenzroNode>,
    p: &Value,
    on_text: impl FnMut(&str) + Send + 'static,
    on_audio: impl FnMut(u32, &[f32]) -> ControlFlow<()> + Send + 'static,
) -> Result<(OmniTurn, Value), JsonRpcError> {
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let entry = tenzro_model::get_omni_model_by_id(model_id)
        .ok_or_else(|| crate::rpc::not_in_catalog("omni", model_id))?;
    if !node.omni_runtime.contains(model_id) {
        return Err(JsonRpcError {
            code: -32004,
            message: format!("{model_id} is not served on this node"),
            data: None,
        });
    }
    let voice = p
        .get("voice")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("voice"))?;
    if !entry.voices.iter().any(|v| v.eq_ignore_ascii_case(voice)) {
        return Err(invalid(format!(
            "{model_id} speaks in {}; not {voice}",
            entry.voices.join(", ")
        )));
    }
    let seed = match p.get("seed") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| invalid("seed is a u32"))?,
    };
    let input = OmniInput {
        messages: messages(p)?,
        voice: voice.to_ascii_lowercase(),
        seed,
        max_reply_tokens: bounded(p, "max_reply_tokens", MAX_REPLY_TOKENS)?,
        max_frames: bounded(p, "max_frames", MAX_FRAMES)?,
    };
    let bytes_in: u64 = input
        .messages
        .iter()
        .map(|m| m.text.len() as u64 + m.audio.iter().map(|a| a.len() as u64).sum::<u64>())
        .sum();
    let level = task_level(node, p, model_id)?;

    let started = std::time::Instant::now();
    let first_audio = Arc::new(Mutex::new(None::<u64>));
    let marker = first_audio.clone();
    let mut on_audio = on_audio;
    let turn = node
        .omni_runtime
        .speak_turn(model_id, input, on_text, move |rate, samples| {
            if let Ok(mut f) = marker.lock()
                && f.is_none()
                && !samples.is_empty()
            {
                *f = Some(started.elapsed().as_millis() as u64);
            }
            on_audio(rate, samples)
        })
        .await
        .map_err(forecast_err)?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let units = BillableUnits::tokens(
        u32::try_from(turn.prompt_tokens).unwrap_or(u32::MAX),
        u32::try_from(turn.reply_tokens).unwrap_or(u32::MAX),
    )
    .with_audio_ms(turn.audio_in_ms)
    .with_audio_out_ms(turn.duration_ms);
    let (cost_wei, settlement) = bill_local_units(
        node,
        p,
        model_id,
        units.clone(),
        bytes_in,
        turn.wav.len() as u64,
        latency_ms,
    )
    .await?;
    let mut out = json!({
        "model_id": model_id,
        "text": turn.text,
        "format": "wav",
        "audio_sha256": hex::encode(Sha256::digest(&turn.wav)),
        "sample_rate": turn.sample_rate,
        "duration_ms": turn.duration_ms,
        "frames": turn.frames,
        "interrupted": turn.interrupted,
        "first_audio_ms": *first_audio.lock().map_err(|_| invalid("lock"))?,
        "seed": seed,
    });
    attach_task_receipt(node, p, model_id, "omni", level, units.clone(), &mut out).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".to_string(), units_to_json(&units));
        obj.insert("cost_wei".to_string(), json!(cost_wei.to_string()));
        obj.insert("settlement".to_string(), settlement.to_json());
    }
    Ok((turn, out))
}

/// The `omni_model` path of `POST /tenzro/realtime/turn`: the caller's audio
/// (and the conversation so far) to one spoken reply, streamed.
pub(crate) async fn run_turn(node: Arc<TenzroNode>, body: Value, tx: mpsc::UnboundedSender<Event>) {
    let fail = |message: String| event("error", &json!({ "stage": "reply", "message": message }));
    let mut p = json!({ "model_id": body.get("omni_model") });
    for f in SHARED {
        if let Some(v) = body.get(*f).filter(|v| !v.is_null()) {
            p[*f] = v.clone();
        }
    }
    let mut history = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(json!({ "role": "user", "audio_base64": body.get("audio_base64") }));
    p["messages"] = Value::Array(history);

    let text_tx = tx.clone();
    let audio_tx = tx.clone();
    let mut seq = 0u64;
    let answered = voice_turn(
        &node,
        &p,
        move |delta| {
            let _ = text_tx.send(event("reply", &json!({ "text": delta })));
        },
        move |rate, samples| {
            seq += 1;
            let sent = audio_tx.send(event(
                "audio",
                &json!({ "seq": seq, "sample_rate": rate, "pcm_s16le_base64": pcm_s16le(samples) }),
            ));
            // a caller that went away stops the turn
            if sent.is_err() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    )
    .await;
    match answered {
        Ok((_, out)) => drop(tx.send(event("done", &out))),
        Err(e) => drop(tx.send(fail(e.message))),
    }
}

/// `POST /tenzro/realtime/converse`; see the module docs.
pub(crate) async fn handle_converse_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    body: axum::body::Body,
) -> Response {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(tenzro_model::access::inherit(run_conversation(
        node, body, tx,
    )));
    let stream = futures::StreamExt::map(
        UnboundedReceiverStream::new(rx),
        Ok::<_, std::convert::Infallible>,
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn pcm_line(line: &Value) -> Result<Vec<f32>, String> {
    let b64 = line
        .get("pcm_s16le_base64")
        .and_then(Value::as_str)
        .ok_or("a chunk line carries pcm_s16le_base64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("pcm_s16le_base64: {e}"))?;
    if bytes.len() % 2 != 0 {
        return Err("pcm_s16le_base64 holds an odd number of bytes".to_string());
    }
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| f32::from(i16::from_le_bytes([b[0], b[1]])) / 32768.0)
        .collect())
}

/// One full-duplex session: the listener's stream in, turns answered while
/// the stream keeps arriving, a reply stopped as soon as the listener talks
/// over it.
async fn run_conversation(
    node: Arc<TenzroNode>,
    body: axum::body::Body,
    tx: mpsc::UnboundedSender<Event>,
) {
    use futures::StreamExt;
    let fail = |message: String| event("error", &json!({ "message": message }));
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut opening: Option<Value> = None;
    let mut session: Option<Arc<Mutex<DuplexSession>>> = None;
    let history: Arc<Mutex<Vec<Value>>> = Arc::default();
    let busy = Arc::new(AtomicBool::new(false));
    let pending = Arc::new(AtomicBool::new(false));
    let mut heard_ms = 0u64;
    let mut rate = 16_000u32;
    loop {
        let line = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => {
                let rest = buf.split_off(i + 1);
                std::mem::replace(&mut buf, rest)
            }
            None => match stream.next().await {
                Some(Ok(chunk)) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() > MAX_LINE_BYTES {
                        return drop(
                            tx.send(fail(format!("a line is at most {MAX_LINE_BYTES} bytes"))),
                        );
                    }
                    continue;
                }
                Some(Err(e)) => return drop(tx.send(fail(format!("reading the stream: {e}")))),
                None => break,
            },
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => return drop(tx.send(fail(format!("a line is not JSON: {e}")))),
        };
        let Some(sess) = session.as_ref() else {
            // the opening line
            if value.get("omni_model").and_then(Value::as_str).is_none() {
                return drop(tx.send(fail("the first line names omni_model".into())));
            }
            if value.get("voice").and_then(Value::as_str).is_none() {
                return drop(tx.send(fail("the first line names a voice".into())));
            }
            rate = match value.get("sample_rate") {
                None | Some(Value::Null) => 16_000,
                Some(v) => match v
                    .as_u64()
                    .and_then(|r| u32::try_from(r).ok())
                    .filter(|r| (8_000..=48_000).contains(r))
                {
                    Some(r) => r,
                    None => return drop(tx.send(fail("sample_rate is 8000 to 48000".into()))),
                },
            };
            if let Some(m) = value.get("messages").and_then(Value::as_array)
                && let Ok(mut h) = history.lock()
            {
                h.extend(m.iter().cloned());
            }
            session = Some(Arc::new(Mutex::new(DuplexSession::new(DuplexConfig {
                sample_rate: rate,
                ..DuplexConfig::default()
            }))));
            opening = Some(value);
            continue;
        };
        let samples = match pcm_line(&value) {
            Ok(s) => s,
            Err(e) => return drop(tx.send(fail(e))),
        };
        heard_ms += samples.len() as u64 * 1000 / u64::from(rate);
        if heard_ms > MAX_SESSION_MS {
            return drop(tx.send(fail("the session reached its length limit".into())));
        }
        let events = match sess.lock() {
            Ok(mut s) => s.push_input(&samples),
            Err(_) => return drop(tx.send(fail("session lock poisoned".into()))),
        };
        for ev in events {
            match ev {
                DuplexEvent::TurnStarted => drop(tx.send(event("turn_started", &json!({})))),
                DuplexEvent::BargeIn => drop(tx.send(event("barge_in", &json!({})))),
                DuplexEvent::TurnEnded { audio } => {
                    let audio_ms = audio.len() as u64 * 1000 / u64::from(rate);
                    let _ = tx.send(event("turn_ended", &json!({ "audio_ms": audio_ms })));
                    if busy.swap(true, Ordering::SeqCst) {
                        // still answering: the new turn joins the history and is answered next
                        if let Ok(mut h) = history.lock() {
                            h.push(user_audio(rate, &audio));
                        }
                        pending.store(true, Ordering::SeqCst);
                        continue;
                    }
                    let Some(open) = opening.clone() else {
                        continue;
                    };
                    if let Ok(mut h) = history.lock() {
                        h.push(user_audio(rate, &audio));
                    }
                    tokio::spawn(answer(
                        node.clone(),
                        open,
                        history.clone(),
                        sess.clone(),
                        busy.clone(),
                        pending.clone(),
                        tx.clone(),
                    ));
                }
            }
        }
    }
}

fn user_audio(rate: u32, audio: &[f32]) -> Value {
    let wav = tenzro_model::omni_runtime::wav16(rate, audio);
    json!({ "role": "user", "audio_base64": base64::engine::general_purpose::STANDARD.encode(wav) })
}

/// Answer the conversation so far, and again while turns arrived during an
/// answer.
async fn answer(
    node: Arc<TenzroNode>,
    open: Value,
    history: Arc<Mutex<Vec<Value>>>,
    session: Arc<Mutex<DuplexSession>>,
    busy: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<Event>,
) {
    loop {
        answer_once(&node, &open, &history, &session, &tx).await;
        if !pending.swap(false, Ordering::SeqCst) {
            break;
        }
    }
    busy.store(false, Ordering::SeqCst);
}

/// One answer; the session stops the reply on a barge-in. The reply's text
/// joins the history, as far as it was written.
async fn answer_once(
    node: &Arc<TenzroNode>,
    open: &Value,
    history: &Arc<Mutex<Vec<Value>>>,
    session: &Arc<Mutex<DuplexSession>>,
    tx: &mpsc::UnboundedSender<Event>,
) {
    let mut p = json!({ "model_id": open.get("omni_model") });
    for f in SHARED {
        if let Some(v) = open.get(*f).filter(|v| !v.is_null()) {
            p[*f] = v.clone();
        }
    }
    p["messages"] = Value::Array(history.lock().map(|h| h.clone()).unwrap_or_default());
    if let Ok(mut s) = session.lock() {
        s.start_response();
    }
    let text_tx = tx.clone();
    let audio_tx = tx.clone();
    let audio_session = session.clone();
    let mut seq = 0u64;
    let answered = voice_turn(
        node,
        &p,
        move |delta| {
            let _ = text_tx.send(event("reply", &json!({ "text": delta })));
        },
        move |rate, samples| {
            let flow = audio_session
                .lock()
                .map_or(ControlFlow::Break(()), |mut s| s.push_output(samples));
            if flow.is_continue() {
                seq += 1;
                let _ = audio_tx.send(event(
                    "audio",
                    &json!({ "seq": seq, "sample_rate": rate, "pcm_s16le_base64": pcm_s16le(samples) }),
                ));
            }
            flow
        },
    )
    .await;
    let latency = session.lock().ok().and_then(|mut s| {
        s.end_response();
        s.first_audio_latency()
    });
    match answered {
        Ok((turn, mut out)) => {
            if let Ok(mut h) = history.lock()
                && !turn.text.is_empty()
            {
                h.push(json!({ "role": "assistant", "content": turn.text }));
            }
            if let (Some(obj), Some(l)) = (out.as_object_mut(), latency) {
                obj.insert(
                    "end_of_turn_to_audio_ms".into(),
                    json!(l.as_millis() as u64),
                );
            }
            let _ = tx.send(event("done", &out));
        }
        Err(e) => {
            let _ = tx.send(event(
                "error",
                &json!({ "stage": "reply", "message": e.message }),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_take_text_audio_or_both_and_refuse_the_rest() {
        let ok = json!({ "messages": [
            { "role": "system", "content": "be brief" },
            { "role": "user", "audio_base64": base64::engine::general_purpose::STANDARD.encode(b"RIFF") },
            { "role": "user", "content": "and this?" },
        ]});
        let m = messages(&ok).expect("messages");
        assert_eq!(m.len(), 3);
        assert_eq!(m[1].audio.len(), 1);
        assert!(m[1].text.is_empty());

        for bad in [
            json!({}),
            json!({ "messages": [{ "role": "tool", "content": "x" }] }),
            json!({ "messages": [{ "role": "user" }] }),
            json!({ "messages": [{ "role": "user", "content": 3 }] }),
            json!({ "messages": [{ "role": "user", "audio_base64": "%%" }] }),
        ] {
            assert!(messages(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn limits_default_to_the_maximum_and_refuse_out_of_range() {
        assert_eq!(
            bounded(&json!({}), "max_frames", MAX_FRAMES).unwrap(),
            MAX_FRAMES
        );
        assert_eq!(
            bounded(&json!({ "max_frames": 10 }), "max_frames", MAX_FRAMES).unwrap(),
            10
        );
        assert!(bounded(&json!({ "max_frames": 0 }), "max_frames", MAX_FRAMES).is_err());
        assert!(
            bounded(
                &json!({ "max_frames": MAX_FRAMES + 1 }),
                "max_frames",
                MAX_FRAMES
            )
            .is_err()
        );
    }

    #[test]
    fn pcm_lines_decode_little_endian_samples() {
        let pcm: Vec<u8> = [0i16, 16384, -32768]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect();
        let line =
            json!({ "pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode(pcm) });
        assert_eq!(pcm_line(&line).unwrap(), vec![0.0, 0.5, -1.0]);
        assert!(pcm_line(&json!({ "pcm_s16le_base64": "AAA" })).is_err());
    }
}
