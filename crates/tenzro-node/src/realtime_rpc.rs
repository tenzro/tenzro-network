//! Realtime speech: `POST /tenzro/realtime/turn`.
//!
//! One spoken turn in, one spoken reply out, streamed as server-sent events
//! while it is produced: the turn is transcribed, the transcript is answered
//! by a chat model, and the answer is spoken, the audio arriving in chunks
//! as it is decoded. Each leg runs on this node through the same path its
//! own surface uses (`tenzro_transcribe`, `tenzro_chat`, `tenzro_speak`), so
//! each is admitted, billed and receipted on its own terms: audio in by the
//! second, tokens, then characters and audio out by the second.
//!
//! Body: `{ stt_model, chat_model, speech_model, audio_base64, messages?,
//! language?, seed?, verification?, receipt_nonce?, payment? }`. With
//! `omni_model` and `voice` in place of the three legs, one omni model hears
//! the turn and speaks its reply while writing it (see [`crate::voice_rpc`]):
//! `reply` events then carry text deltas. `messages`
//! is the conversation so far (OpenAI shape); the caller keeps it.
//!
//! Events, in order: `transcript` (`text`, `units`, `tenzro_receipt`),
//! `reply` (`text`, `units`, `tenzro_receipt`), `audio` (`seq`,
//! `sample_rate`, `pcm_s16le_base64`) for each chunk, then `done` (the
//! speech leg's `audio_sha256`, `duration_ms`, `units`, `tenzro_receipt`).
//! A failing leg ends the stream with an `error` event naming it.
//!
//! Streaming transcription: `POST /tenzro/realtime/transcribe`, on the same
//! transport. The request body is streamed as newline-delimited JSON while
//! the audio is captured: a first line `{ model_id, sample_rate? (default
//! 16000), language?, verification?, payment?, channel_voucher?,
//! caller_address? }`, then one line per chunk `{ pcm_s16le_base64 }` (mono
//! 16-bit little-endian samples), ending when the body ends. Events:
//! `partial` (`text`, `start_ms`, `end_ms`) about once a second over the
//! audio not yet committed; `final` (`seq`, `text`, `start_ms`, `end_ms`,
//! `units`, `cost_wei`, `settlement`, `tenzro_receipt`) when a segment is
//! committed at a pause (or at its quietest point once it is long); then
//! `done` (`segments`, `audio_ms`, `cost_wei`). Each final segment is one
//! `tenzro_transcribe` call, admitted, billed by the second of audio and
//! receipted on its terms, so every second is billed once; partials are
//! re-decodes of the open segment and are not billed. The session runs on a
//! node that serves the model.

use std::sync::Arc;

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn event(name: &str, data: &Value) -> Event {
    Event::default().event(name).data(data.to_string())
}

/// Fields every leg forwards unchanged.
const SHARED: &[&str] = &[
    "verification",
    "receipt_nonce",
    "payment",
    "channel_voucher",
    "language",
    "seed",
];

fn leg(body: &Value, model_key: &str, extra: Value) -> Result<Value, String> {
    let model = body
        .get(model_key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {model_key}"))?;
    let mut p = json!({ "model_id": model });
    for f in SHARED {
        if let Some(v) = body.get(*f).filter(|v| !v.is_null()) {
            p[*f] = v.clone();
        }
    }
    if let (Some(obj), Some(more)) = (p.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    Ok(p)
}

/// The chat answer's text, from either answer shape `tenzro_chat` returns.
fn reply_text(out: &Value) -> Option<String> {
    out.get("output")
        .and_then(Value::as_str)
        .or_else(|| {
            out.pointer("/choices/0/message/content")
                .and_then(Value::as_str)
        })
        .map(str::to_string)
}

fn pcm_s16le(samples: &[f32]) -> String {
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

async fn run_turn(node: Arc<TenzroNode>, body: Value, tx: mpsc::UnboundedSender<Event>) {
    // one omni model hears, answers and speaks in a single call
    if body.get("omni_model").is_some_and(|m| !m.is_null()) {
        return crate::voice_rpc::run_turn(node, body, tx).await;
    }
    let fail = |stage: &str, message: String| {
        event("error", &json!({ "stage": stage, "message": message }))
    };

    // Transcribe.
    let stt = match leg(
        &body,
        "stt_model",
        json!({ "audio_base64": body.get("audio_base64") }),
    ) {
        Ok(p) => p,
        Err(e) => return drop(tx.send(fail("transcript", e))),
    };
    let heard = match crate::rpc::handle_transcribe(&node, Some(stt)).await {
        Ok(v) => v,
        Err(e) => return drop(tx.send(fail("transcript", e.message))),
    };
    let text = heard
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let _ = tx.send(event(
        "transcript",
        &json!({
            "text": text,
            "units": heard.get("units"),
            "tenzro_receipt": heard.get("tenzro_receipt"),
        }),
    ));
    if text.is_empty() {
        let _ = tx.send(fail("transcript", "the turn holds no speech".into()));
        return;
    }

    // Answer.
    let mut messages = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    messages.push(json!({ "role": "user", "content": text }));
    let chat = match leg(&body, "chat_model", json!({ "messages": messages })) {
        Ok(mut p) => {
            if let Some(obj) = p.as_object_mut() {
                obj.remove("language");
            }
            p
        }
        Err(e) => return drop(tx.send(fail("reply", e))),
    };
    let answered = match crate::rpc::handle_chat(&node, Some(chat), None).await {
        Ok(v) => v,
        Err(e) => return drop(tx.send(fail("reply", e.message))),
    };
    let Some(reply) = reply_text(&answered).filter(|r| !r.trim().is_empty()) else {
        let _ = tx.send(fail("reply", "the chat model returned no text".into()));
        return;
    };
    let _ = tx.send(event(
        "reply",
        &json!({
            "text": reply,
            "units": answered.get("units"),
            "tenzro_receipt": answered.get("tenzro_receipt"),
        }),
    ));

    // Speak, chunk by chunk.
    let speech = match leg(&body, "speech_model", json!({ "input": reply })) {
        Ok(p) => p,
        Err(e) => return drop(tx.send(fail("audio", e))),
    };
    let chunks = tx.clone();
    let mut seq = 0u64;
    let spoken = crate::speech_rpc::speak(&node, &speech, move |rate, samples| {
        seq += 1;
        let _ = chunks.send(event(
            "audio",
            &json!({
                "seq": seq,
                "sample_rate": rate,
                "pcm_s16le_base64": pcm_s16le(samples),
            }),
        ));
    })
    .await;
    match spoken {
        Ok((_, out)) => {
            let _ = tx.send(event("done", &out));
        }
        Err(e) => {
            let _ = tx.send(fail("audio", e.message));
        }
    }
}

/// `POST /tenzro/realtime/turn`; see the module docs.
pub(crate) async fn handle_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(run_turn(node, body, tx));
    let stream = futures::StreamExt::map(
        UnboundedReceiverStream::new(rx),
        Ok::<_, std::convert::Infallible>,
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── Streaming transcription ──

/// New audio, in milliseconds, between two looks at the open segment.
const PARTIAL_STEP_MS: u64 = 1000;
/// An open segment is committed at a pause once it holds this much audio.
const MIN_SEGMENT_MS: u64 = 3000;
/// Past this much, it is committed at the quietest point of its second half.
const MAX_SEGMENT_MS: u64 = 15_000;
/// Trailing quiet that counts as a pause.
const PAUSE_MS: u64 = 300;
/// A window is quiet at or below this RMS (in sample units), or at or below
/// a tenth of the open segment's loudest window when that is higher.
const QUIET_RMS: u16 = 200;
/// Longest stream accepted, and longest frame line.
const MAX_STREAM_MS: u64 = 3_600_000;
const MAX_FRAME_BYTES: usize = 4 << 20;
const DEFAULT_SAMPLE_RATE: u32 = 16_000;

/// What to do with the open segment after new audio arrived.
#[derive(Debug, PartialEq, Eq)]
enum SttStep {
    /// Not enough new audio since the last look.
    Wait,
    /// Re-decode the open segment as a partial transcript.
    Partial,
    /// Commit this many leading samples as a final segment.
    Commit(usize),
}

/// The open segment of a streamed recording and where it starts.
struct Segmenter {
    rate: u32,
    open: Vec<i16>,
    /// Samples committed before the open segment.
    committed: u64,
    /// Length of the open segment at the last look.
    looked_at: usize,
}

impl Segmenter {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            open: Vec::new(),
            committed: 0,
            looked_at: 0,
        }
    }

    fn ms(&self, samples: u64) -> u64 {
        samples * 1000 / self.rate as u64
    }

    fn push(&mut self, samples: &[i16]) {
        self.open.extend_from_slice(samples);
    }

    fn total_ms(&self) -> u64 {
        self.ms(self.committed + self.open.len() as u64)
    }

    fn step(&mut self) -> SttStep {
        if self.ms((self.open.len() - self.looked_at) as u64) < PARTIAL_STEP_MS {
            return SttStep::Wait;
        }
        self.looked_at = self.open.len();
        let window = crate::task_route::envelope_window(self.rate);
        let env = crate::task_route::rms_windows(&self.open, window);
        let loudest = env.iter().copied().max().unwrap_or(0);
        let quiet = QUIET_RMS.max(loudest / 10);
        let open_ms = self.ms(self.open.len() as u64);
        if open_ms >= MAX_SEGMENT_MS {
            let half = env.len() / 2;
            let (at, _) = env[half..]
                .iter()
                .enumerate()
                .min_by_key(|(i, v)| (**v, std::cmp::Reverse(*i)))
                .unwrap_or((0, &0));
            return SttStep::Commit(((half + at + 1) * window).min(self.open.len()));
        }
        let pause = (PAUSE_MS * self.rate as u64 / 1000).div_ceil(window as u64) as usize;
        if open_ms >= MIN_SEGMENT_MS
            && env.len() >= pause
            && env[env.len() - pause..].iter().all(|v| *v <= quiet)
        {
            return SttStep::Commit(self.open.len());
        }
        SttStep::Partial
    }

    /// The open segment's first `n` samples and their span, removed.
    fn take(&mut self, n: usize) -> (Vec<i16>, u64, u64) {
        let rest = self.open.split_off(n.min(self.open.len()));
        let seg = std::mem::replace(&mut self.open, rest);
        let start = self.ms(self.committed);
        self.committed += seg.len() as u64;
        self.looked_at = 0;
        (seg, start, self.ms(self.committed))
    }

    /// The open segment and its span, without removing it.
    fn open_span(&self) -> (&[i16], u64, u64) {
        (&self.open, self.ms(self.committed), self.total_ms())
    }
}

/// A mono 16-bit PCM WAV of `samples` at `rate`.
fn wav16(rate: u32, samples: &[i16]) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut w = Vec::with_capacity(44 + samples.len() * 2);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data_len).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&rate.to_le_bytes());
    w.extend_from_slice(&(rate * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        w.extend_from_slice(&s.to_le_bytes());
    }
    w
}

/// Fields of the opening line every final segment's `tenzro_transcribe`
/// call carries.
const STT_SHARED: &[&str] = &[
    "model_id",
    "language",
    "verification",
    "payment",
    "channel_voucher",
    "caller_address",
];

/// The open session: its opening line, the segmenter, and running totals.
struct SttSession {
    node: Arc<TenzroNode>,
    open: Value,
    model_id: String,
    seg: Segmenter,
    finals: u64,
    cost_wei: u128,
    tx: mpsc::UnboundedSender<SttEvent>,
}

impl SttSession {
    async fn partial(&self) -> Result<(), String> {
        let (samples, start_ms, end_ms) = self.seg.open_span();
        if samples.is_empty() {
            return Ok(());
        }
        let cfg = tenzro_model::TranscribeConfig {
            language: self
                .open
                .get("language")
                .and_then(Value::as_str)
                .map(str::to_string),
            timestamps: false,
            temperature: None,
        };
        let heard = self
            .node
            .audio_runtime
            .transcribe(&self.model_id, wav16(self.seg.rate, samples), cfg)
            .await
            .map_err(|e| e.to_string())?;
        let _ = self.tx.send((
            "partial",
            json!({
                "text": heard.text.trim(),
                "start_ms": start_ms,
                "end_ms": end_ms,
            }),
        ));
        Ok(())
    }

    async fn commit(&mut self, n: usize) -> Result<(), String> {
        let (samples, start_ms, end_ms) = self.seg.take(n);
        if samples.is_empty() {
            return Ok(());
        }
        let mut p = json!({
            "audio_base64": base64::engine::general_purpose::STANDARD.encode(wav16(self.seg.rate, &samples)),
        });
        for f in STT_SHARED {
            if let Some(v) = self.open.get(*f).filter(|v| !v.is_null()) {
                p[*f] = v.clone();
            }
        }
        let heard = crate::rpc::handle_transcribe(&self.node, Some(p))
            .await
            .map_err(|e| e.message)?;
        self.finals += 1;
        self.cost_wei += heard
            .get("cost_wei")
            .and_then(Value::as_str)
            .and_then(|c| c.parse::<u128>().ok())
            .unwrap_or(0);
        let _ = self.tx.send((
            "final",
            json!({
                "seq": self.finals,
                "text": heard.get("text").and_then(Value::as_str).unwrap_or("").trim(),
                "start_ms": start_ms,
                "end_ms": end_ms,
                "units": heard.get("units"),
                "cost_wei": heard.get("cost_wei"),
                "settlement": heard.get("settlement"),
                "tenzro_receipt": heard.get("tenzro_receipt"),
            }),
        ));
        Ok(())
    }

    /// Feed one chunk of samples and act on the open segment.
    async fn feed(&mut self, samples: &[i16]) -> Result<(), String> {
        self.seg.push(samples);
        if self.seg.total_ms() > MAX_STREAM_MS {
            return Err(format!(
                "a stream holds at most {} s of audio",
                MAX_STREAM_MS / 1000
            ));
        }
        loop {
            match self.seg.step() {
                SttStep::Wait => return Ok(()),
                SttStep::Partial => return self.partial().await,
                SttStep::Commit(n) => self.commit(n).await?,
            }
        }
    }
}

/// The opening line's model and sample rate, refused when this node does
/// not serve the model or the level asked for.
fn open_session(node: &Arc<TenzroNode>, open: &Value) -> Result<(String, u32), String> {
    let model_id = open
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or("the first line needs model_id")?;
    let rate = match open.get("sample_rate") {
        None | Some(Value::Null) => DEFAULT_SAMPLE_RATE,
        Some(v) => v
            .as_u64()
            .filter(|r| (8_000..=48_000).contains(r))
            .ok_or("sample_rate is between 8000 and 48000")? as u32,
    };
    if !node.audio_runtime.is_loaded(model_id) {
        return Err(format!(
            "streaming transcription runs on a node serving the model; {model_id} is not loaded here \
             (tenzro_transcribe routes a recording to any provider offering it)"
        ));
    }
    crate::verifiable_inference::task_level(node, open, model_id).map_err(|e| e.message)?;
    Ok((model_id.to_string(), rate))
}

/// Mono 16-bit little-endian samples from a chunk line.
fn chunk_samples(line: &Value) -> Result<Vec<i16>, String> {
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
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect())
}

/// One event of a streamed transcription: its name and data.
pub(crate) type SttEvent = (&'static str, Value);

/// Run a streamed transcription over `body`, sending its events to `tx`.
pub(crate) async fn run_transcription(
    node: Arc<TenzroNode>,
    body: axum::body::Body,
    tx: mpsc::UnboundedSender<SttEvent>,
) {
    use futures::StreamExt;
    let fail = |message: String| ("error", json!({ "message": message }));
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut session: Option<SttSession> = None;
    let mut ended = false;
    while !ended {
        let line = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => {
                let rest = buf.split_off(i + 1);
                std::mem::replace(&mut buf, rest)
            }
            None => match stream.next().await {
                Some(Ok(chunk)) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() > MAX_FRAME_BYTES {
                        return drop(
                            tx.send(fail(format!("a line is at most {MAX_FRAME_BYTES} bytes"))),
                        );
                    }
                    continue;
                }
                Some(Err(e)) => return drop(tx.send(fail(format!("reading the stream: {e}")))),
                None => {
                    ended = true;
                    std::mem::take(&mut buf)
                }
            },
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => return drop(tx.send(fail(format!("a line is not JSON: {e}")))),
        };
        let result = if let Some(s) = session.as_mut() {
            match chunk_samples(&value) {
                Ok(samples) => s.feed(&samples).await,
                Err(e) => Err(e),
            }
        } else {
            open_session(&node, &value)
                .map(|(model_id, rate)| SttSession {
                    node: node.clone(),
                    open: value,
                    model_id,
                    seg: Segmenter::new(rate),
                    finals: 0,
                    cost_wei: 0,
                    tx: tx.clone(),
                })
                .map(|opened| session = Some(opened))
        };
        if let Err(e) = result {
            return drop(tx.send(fail(e)));
        }
    }
    let Some(mut s) = session else {
        return drop(tx.send(fail("the stream ended before its first line".to_string())));
    };
    let rest = s.seg.open.len();
    if let Err(e) = s.commit(rest).await {
        return drop(tx.send(fail(e)));
    }
    let _ = tx.send((
        "done",
        json!({
            "segments": s.finals,
            "audio_ms": s.seg.total_ms(),
            "cost_wei": s.cost_wei.to_string(),
        }),
    ));
}

/// `POST /tenzro/realtime/transcribe`; see the module docs.
pub(crate) async fn handle_transcribe_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    body: axum::body::Body,
) -> Response {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(tenzro_model::access::inherit(run_transcription(
        node, body, tx,
    )));
    let stream = futures::StreamExt::map(UnboundedReceiverStream::new(rx), |(name, data)| {
        Ok::<_, std::convert::Infallible>(event(name, &data))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// The NDJSON body the streaming transport takes for a whole recording: the
/// opening line, then the WAV's first channel in `chunk_ms` chunks.
fn recording_body(p: &Value) -> Result<Vec<u8>, String> {
    let audio = p
        .get("audio_base64")
        .and_then(Value::as_str)
        .ok_or("missing 'audio_base64'")?;
    let wav = base64::engine::general_purpose::STANDARD
        .decode(audio)
        .map_err(|e| format!("audio_base64: {e}"))?;
    let (rate, samples) =
        crate::task_route::wav_first_channel(&wav).ok_or("audio_base64 is not a 16-bit PCM WAV")?;
    let chunk_ms = p
        .get("chunk_ms")
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .max(10) as usize;
    let chunk = (rate as usize * chunk_ms / 1000).max(1);
    let mut body = serde_json::to_vec(&json!({
        "model_id": p.get("model_id"),
        "sample_rate": rate,
        "language": p.get("language"),
        "verification": p.get("verification"),
    }))
    .map_err(|e| e.to_string())?;
    body.push(b'\n');
    for c in samples.chunks(chunk) {
        let pcm: Vec<u8> = c.iter().flat_map(|s| s.to_le_bytes()).collect();
        body.extend_from_slice(
            json!({ "pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode(pcm) })
                .to_string()
                .as_bytes(),
        );
        body.push(b'\n');
    }
    Ok(body)
}

/// `tenzro_transcribeStream`: a whole recording through the streaming
/// transcription, as a live stream would be fed, answering every event in
/// order (`{ events: [{ event, data }] }`). Params: `{ model_id,
/// audio_base64 (16-bit PCM WAV, first channel), language?, chunk_ms?,
/// verification? }`. Finals are `tenzro_transcribe` calls, billed and
/// receipted as the stream's are.
pub(crate) async fn handle_transcribe_stream(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| crate::rpc::missing_param("params"))?;
    let body = recording_body(&p).map_err(|message| JsonRpcError {
        code: -32602,
        message,
        data: None,
    })?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    run_transcription(node.clone(), axum::body::Body::from(body), tx).await;
    let mut events = Vec::new();
    while let Ok((name, data)) = rx.try_recv() {
        events.push(json!({ "event": name, "data": data }));
    }
    Ok(json!({ "events": events }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(rate: u32, ms: u64, amp: i16) -> Vec<i16> {
        (0..rate as u64 * ms / 1000)
            .map(|i| if i % 2 == 0 { amp } else { -amp })
            .collect()
    }

    #[test]
    fn segments_commit_at_a_pause_and_partial_otherwise() {
        let mut seg = Segmenter::new(16_000);
        seg.push(&tone(16_000, 900, 3000));
        assert_eq!(seg.step(), SttStep::Wait, "under a second of new audio");
        seg.push(&tone(16_000, 200, 3000));
        assert_eq!(seg.step(), SttStep::Partial, "speech, no pause yet");
        seg.push(&tone(16_000, 2000, 3000));
        seg.push(&tone(16_000, 400, 0));
        let n = seg.open.len();
        assert_eq!(seg.step(), SttStep::Commit(n), "three seconds then a pause");
        let (samples, start, end) = seg.take(n);
        assert_eq!((samples.len(), start, end), (n, 0, 3500));
        assert_eq!(seg.open_span().1, 3500);
    }

    #[test]
    fn long_segments_commit_at_their_quietest_point() {
        let mut seg = Segmenter::new(16_000);
        seg.push(&tone(16_000, 10_000, 3000));
        seg.push(&tone(16_000, 100, 50));
        seg.push(&tone(16_000, 5_000, 3000));
        let Some(SttStep::Commit(n)) = (0..20)
            .map(|_| seg.step())
            .find(|s| matches!(s, SttStep::Commit(_)))
        else {
            panic!("a 15 s segment is committed");
        };
        let ms = n as u64 * 1000 / 16_000;
        assert!(
            (10_000..=10_100).contains(&ms),
            "cut inside the quiet stretch, at {ms} ms"
        );
    }

    #[test]
    fn realtime_routes_are_gated_as_media() {
        use tenzro_types::node_access::MethodClass;
        for path in ["/tenzro/realtime/transcribe", "/tenzro/realtime/turn"] {
            assert!(
                matches!(crate::access::route_class(path), MethodClass::Media),
                "{path}"
            );
        }
        assert!(matches!(
            crate::access::route_class("/tenzro/rerank"),
            MethodClass::Inference
        ));
    }

    #[test]
    fn wav_and_chunks_round_trip() {
        let w = wav16(16_000, &[1, -2, 300]);
        assert_eq!(crate::task_route::speech_envelope(&w).unwrap().len(), 1);
        let line = json!({"pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode([1u8, 0, 0xfe, 0xff])});
        assert_eq!(chunk_samples(&line).unwrap(), vec![1, -2]);
        let odd =
            json!({"pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode([1u8])});
        assert!(chunk_samples(&odd).is_err());
        assert!(chunk_samples(&json!({})).is_err());
    }

    #[test]
    fn a_recording_is_fed_as_the_stream_would_be() {
        let w = wav16(1000, &[7; 450]);
        let p = json!({ "model_id": "m", "audio_base64": base64::engine::general_purpose::STANDARD.encode(&w), "chunk_ms": 200 });
        let body = recording_body(&p).unwrap();
        let lines: Vec<Value> = body
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        assert_eq!(lines[0]["sample_rate"], json!(1000));
        assert_eq!(lines[0]["model_id"], json!("m"));
        let samples: Vec<i16> = lines[1..]
            .iter()
            .flat_map(|l| chunk_samples(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1 + 3, "200, 200 and 50 samples");
        assert_eq!(samples, vec![7; 450]);
        assert!(recording_body(&json!({ "audio_base64": "AAAA" })).is_err());
    }

    #[test]
    fn legs_carry_their_model_and_the_shared_fields_only() {
        let body = json!({
            "stt_model": "s", "chat_model": "c", "speech_model": "t",
            "verification": "receipt", "seed": 3, "audio_base64": "AAAA", "messages": [],
        });
        let p = leg(&body, "speech_model", json!({ "input": "hi" })).unwrap();
        assert_eq!(
            p,
            json!({ "model_id": "t", "verification": "receipt", "seed": 3, "input": "hi" })
        );
        assert!(leg(&body, "absent_model", json!({})).is_err());
    }

    #[test]
    fn the_reply_reads_from_either_chat_shape() {
        assert_eq!(reply_text(&json!({ "output": "a" })).as_deref(), Some("a"));
        assert_eq!(
            reply_text(&json!({ "choices": [{ "message": { "content": "b" } }] })).as_deref(),
            Some("b")
        );
        assert_eq!(reply_text(&json!({})), None);
    }

    #[test]
    fn pcm_is_clamped_little_endian_16_bit() {
        let b = base64::engine::general_purpose::STANDARD
            .decode(pcm_s16le(&[0.0, 2.0, -1.0]))
            .unwrap();
        assert_eq!(b, vec![0, 0, 0xff, 0x7f, 0x01, 0x80]);
    }
}
