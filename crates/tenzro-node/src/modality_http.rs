//! HTTP routes for modality calls: `/v1/embeddings`,
//! `/v1/audio/transcriptions`, `/tenzro/detections`, `/tenzro/segmentations`
//! and `/tenzro/video/embeddings`.
//!
//! Each route translates its body into the parameters of the JSON-RPC method
//! that serves the same task and calls that method's handler, so a call over
//! HTTP is served here or by another provider, receipted, billed and sampled
//! for optimistic re-execution exactly as the JSON-RPC call is. Only the
//! request and response shapes are the route's own. Payment on these routes
//! is collected by their gate, so no settlement fields are passed through;
//! the fields that choose where and how a call is served (`provider`,
//! `verification`, `receipt_nonce`) are.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, json_error_response, units_from_json, units_to_json};

/// Body fields that choose where and how a call is served.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Routing {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    verification: Option<String>,
    #[serde(default)]
    receipt_nonce: Option<String>,
}

impl Routing {
    /// The method parameters for `model`, carrying the routing fields.
    fn params(&self, model: &str) -> Map<String, Value> {
        let mut p = Map::new();
        p.insert("model_id".into(), json!(model));
        for (k, v) in [
            ("provider", &self.provider),
            ("verification", &self.verification),
            ("receipt_nonce", &self.receipt_nonce),
        ] {
            if let Some(v) = v {
                p.insert(k.into(), json!(v));
            }
        }
        p
    }
}

/// The HTTP answer to a method's error.
pub(crate) fn rpc_error_response(e: &JsonRpcError, modality: &str) -> Response {
    let (status, kind, code) = match e.code {
        -32602 | -32021 => (
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid_request".to_string(),
        ),
        -32004 => (
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "model_not_loaded".to_string(),
        ),
        -32005 => {
            let data = e.data.clone().unwrap_or(Value::Null);
            let retry_ms = data
                .get("retry_after_ms")
                .and_then(Value::as_u64)
                .unwrap_or(1000);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    header::RETRY_AFTER,
                    retry_ms.div_ceil(1000).max(1).to_string(),
                )],
                Json(json!({
                    "error": {
                        "type": "capacity",
                        "message": e.message,
                        "retry_after_ms": retry_ms,
                        "detail": data.get("detail"),
                    }
                })),
            )
                .into_response();
        }
        -32011 => (
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            format!("{modality}_unavailable"),
        ),
        -32000 => (
            StatusCode::BAD_GATEWAY,
            "server_error",
            "provider_error".to_string(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            format!("{modality}_error"),
        ),
    };
    json_error_response(status, &e.message, kind, &code)
}

/// The method's answer with the route's `object` and `model` added.
fn answered(mut out: Value, object: &str, model: &str) -> Response {
    if let Some(obj) = out.as_object_mut() {
        obj.insert("object".into(), json!(object));
        obj.insert("model".into(), json!(model));
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// Rewrite each item's `mask` (one byte a pixel) as `mask_base64`. A 1024²
/// mask as a JSON array of integers is about 3 MB of text.
fn masks_as_base64(items: Option<&mut Value>) {
    let Some(Value::Array(items)) = items else {
        return;
    };
    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::Array(mask)) = obj.remove("mask") {
            let bytes: Vec<u8> = mask
                .iter()
                .map(|v| v.as_u64().unwrap_or(0).min(255) as u8)
                .collect();
            obj.insert(
                "mask_base64".into(),
                json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
        }
    }
}

/// Request body for `POST /tenzro/detections`.
#[derive(Debug, Deserialize)]
pub(crate) struct DetectionRequest {
    model: String,
    image_base64: String,
    #[serde(default)]
    score_threshold: Option<f32>,
    #[serde(flatten)]
    routing: Routing,
}

/// `POST /tenzro/detections`: `tenzro_detect`.
pub(crate) async fn detections(
    State(node): State<Arc<TenzroNode>>,
    Json(r): Json<DetectionRequest>,
) -> Response {
    let mut p = r.routing.params(&r.model);
    p.insert("image_base64".into(), json!(r.image_base64));
    if let Some(t) = r.score_threshold {
        p.insert("score_threshold".into(), json!(t));
    }
    match crate::rpc::handle_detect(&node, Some(Value::Object(p))).await {
        Ok(out) => answered(out, "detection", &r.model),
        Err(e) => rpc_error_response(&e, "detection"),
    }
}

/// Request body for `POST /tenzro/segmentations`. `prompts` (points, point
/// sets, boxes) is `tenzro_segment`; `text_prompt` (with an optional
/// `box_prompt` narrowing it) is `tenzro_textSegment`. The two name different
/// models, so a request sends one or the other.
#[derive(Debug, Deserialize)]
pub(crate) struct SegmentationRequest {
    model: String,
    image_base64: String,
    #[serde(default)]
    prompts: Option<Value>,
    #[serde(default)]
    text_prompt: Option<String>,
    #[serde(default)]
    box_prompt: Option<Value>,
    #[serde(default)]
    score_threshold: Option<f32>,
    #[serde(flatten)]
    routing: Routing,
}

/// `POST /tenzro/segmentations`: `tenzro_segment` or `tenzro_textSegment`,
/// masks base64-encoded.
pub(crate) async fn segmentations(
    State(node): State<Arc<TenzroNode>>,
    Json(r): Json<SegmentationRequest>,
) -> Response {
    let refuse = |message: &str, code: &str| {
        json_error_response(
            StatusCode::BAD_REQUEST,
            message,
            "invalid_request_error",
            code,
        )
    };
    match (r.prompts.is_some(), r.text_prompt.is_some()) {
        (true, true) => {
            return refuse(
                "'prompts' and 'text_prompt' name different runtimes holding different models: send one or the other",
                "ambiguous_segmentation_prompt",
            );
        }
        (false, false) => {
            return refuse(
                "send 'prompts' for point or box segmentation, or 'text_prompt' for open-vocabulary segmentation",
                "missing_segmentation_prompt",
            );
        }
        _ => {}
    }
    if r.box_prompt.is_some() && r.text_prompt.is_none() {
        return refuse(
            "'box_prompt' narrows a 'text_prompt'; a geometric box travels as an entry in 'prompts'",
            "misplaced_box_prompt",
        );
    }
    let mut p = r.routing.params(&r.model);
    p.insert("image_base64".into(), json!(r.image_base64));
    if let Some(t) = r.score_threshold {
        p.insert("score_threshold".into(), json!(t));
    }
    let served = if let Some(text) = r.text_prompt {
        p.insert("text_prompt".into(), json!(text));
        if let Some(b) = r.box_prompt {
            p.insert("box_prompt".into(), b);
        }
        crate::rpc::handle_text_segment(&node, Some(Value::Object(p))).await
    } else {
        p.insert("prompts".into(), r.prompts.unwrap_or(Value::Null));
        crate::rpc::handle_segment(&node, Some(Value::Object(p))).await
    };
    match served {
        Ok(mut out) => {
            masks_as_base64(out.get_mut("masks"));
            masks_as_base64(out.get_mut("segmentations"));
            answered(out, "segmentation", &r.model)
        }
        Err(e) => rpc_error_response(&e, "segmentation"),
    }
}

/// Request body for `POST /tenzro/video/embeddings`: one clip, one vector
/// and the count of frames consumed.
#[derive(Debug, Deserialize)]
pub(crate) struct VideoEmbeddingRequest {
    model: String,
    video_base64: String,
    #[serde(default)]
    normalize: Option<bool>,
    #[serde(default)]
    frame_stride: Option<u32>,
    #[serde(flatten)]
    routing: Routing,
}

/// `POST /tenzro/video/embeddings`: `tenzro_videoEmbed`.
pub(crate) async fn video_embeddings(
    State(node): State<Arc<TenzroNode>>,
    Json(r): Json<VideoEmbeddingRequest>,
) -> Response {
    let mut p = r.routing.params(&r.model);
    p.insert("video_base64".into(), json!(r.video_base64));
    if let Some(n) = r.normalize {
        p.insert("normalize".into(), json!(n));
    }
    if let Some(s) = r.frame_stride {
        p.insert("frame_stride".into(), json!(s));
    }
    match crate::rpc::handle_video_embed(&node, Some(Value::Object(p))).await {
        Ok(out) => answered(out, "video_embedding", &r.model),
        Err(e) => rpc_error_response(&e, "video_embedding"),
    }
}

/// Request body for `POST /v1/embeddings`.
///
/// `input` is one input or an array of them; an input is a string (text) or
/// `{ text?, image?: base64, video?: [base64 frame, ...] }`, embedded as one
/// item. A `model` naming an image encoder embeds pictures alone, one
/// `tenzro_imageEmbed` per picture; any other model is one `tenzro_textEmbed`
/// over every input. `dimensions` requests Matryoshka truncation on the text
/// encoders that support it; only the `float` encoding is served.
#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddingsRequest {
    model: String,
    input: Value,
    #[serde(default)]
    dimensions: Option<u32>,
    #[serde(default)]
    encoding_format: Option<String>,
    /// L2-normalize the output vectors; off by default, as with OpenAI.
    #[serde(default)]
    normalize: Option<bool>,
    /// `"query"` or `"document"` (the default): selects the model's
    /// instruction template.
    #[serde(default)]
    input_type: Option<String>,
    /// Task description for `input_type: "query"`.
    #[serde(default)]
    task: Option<String>,
    /// Title for `input_type: "document"` (EmbeddingGemma only).
    #[serde(default)]
    title: Option<String>,
    #[serde(flatten)]
    routing: Routing,
}

impl EmbeddingsRequest {
    fn role(&self) -> Value {
        match self.input_type.as_deref() {
            Some("query") => json!({ "role": "query", "task": self.task }),
            _ => json!({ "role": "document", "title": self.title }),
        }
    }
}

/// `POST /v1/embeddings`: OpenAI-compatible embeddings over text, pictures
/// and video, answered in the OpenAI `{ object, data, model, usage }` shape
/// with the units, cost and signed receipts beside it.
pub(crate) async fn embeddings(
    State(node): State<Arc<TenzroNode>>,
    Json(r): Json<EmbeddingsRequest>,
) -> Response {
    let refuse = |message: &str, code: &str| {
        json_error_response(
            StatusCode::BAD_REQUEST,
            message,
            "invalid_request_error",
            code,
        )
    };
    if let Some(fmt) = r.encoding_format.as_deref()
        && !fmt.eq_ignore_ascii_case("float")
    {
        return refuse(
            &format!("unsupported encoding_format '{fmt}' (only 'float' is served)"),
            "unsupported_encoding_format",
        );
    }
    let inputs = match &r.input {
        Value::Array(v) => v.clone(),
        one => vec![one.clone()],
    };
    if inputs.is_empty() {
        return refuse(
            "'input' must be a non-empty input or array of inputs",
            "missing_input",
        );
    }

    #[cfg(feature = "inference")]
    let image_encoder = tenzro_model::get_vision_model_by_id(&r.model).is_some()
        || node.vision_runtime.is_loaded(&r.model);
    // The light build loads no encoder, so only the catalog names one.
    #[cfg(not(feature = "inference"))]
    let image_encoder = tenzro_model::get_vision_model_by_id(&r.model).is_some();
    let mut answers = Vec::new();
    if image_encoder {
        if r.dimensions.is_some() {
            return refuse(
                "'dimensions' is not served for an image encoder, which emits its trained width",
                "unsupported_dimensions_for_image",
            );
        }
        for (index, input) in inputs.iter().enumerate() {
            let picture = input
                .as_object()
                .filter(|o| o.len() == 1)
                .and_then(|o| o.get("image"))
                .and_then(Value::as_str);
            let Some(picture) = picture else {
                return refuse(
                    &format!(
                        "input {index}: model '{}' is an image encoder and embeds a picture alone (no text, no video)",
                        r.model
                    ),
                    "unsupported_input_for_model",
                );
            };
            let mut p = r.routing.params(&r.model);
            p.insert("image_base64".into(), json!(picture));
            p.insert("normalize".into(), json!(r.normalize.unwrap_or(false)));
            match crate::rpc::handle_image_embed(&node, Some(Value::Object(p))).await {
                Ok(out) => answers.push(out),
                Err(e) => return rpc_error_response(&e, "embedding"),
            }
        }
    } else {
        let mut p = r.routing.params(&r.model);
        p.insert("inputs".into(), Value::Array(inputs));
        p.insert("normalize".into(), json!(r.normalize.unwrap_or(false)));
        p.insert("role".into(), r.role());
        if let Some(d) = r.dimensions {
            p.insert("requested_dim".into(), json!(d));
        }
        match crate::rpc::handle_text_embed(&node, Some(Value::Object(p))).await {
            Ok(out) => answers.push(out),
            Err(e) => return rpc_error_response(&e, "embedding"),
        }
    }
    (StatusCode::OK, Json(embeddings_body(&r.model, &answers))).into_response()
}

/// The OpenAI embeddings body over one `tenzro_textEmbed` answer or one
/// `tenzro_imageEmbed` answer per picture.
fn embeddings_body(model: &str, answers: &[Value]) -> Value {
    let mut vectors = Vec::new();
    let mut dim = 0u64;
    let mut units = tenzro_types::model::BillableUnits::default();
    let mut cost: u128 = 0;
    let mut receipts = Vec::new();
    for a in answers {
        match a.get("embeddings").and_then(Value::as_array) {
            Some(many) => vectors.extend(many.iter().cloned()),
            None => vectors.push(a.get("embedding").cloned().unwrap_or(Value::Null)),
        }
        dim = a.get("dim").and_then(Value::as_u64).unwrap_or(dim);
        if let Some(u) = a.get("units") {
            units.accumulate(&units_from_json(u));
        }
        cost = cost.saturating_add(
            a.get("cost_wei")
                .and_then(Value::as_str)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0),
        );
        if let Some(rcpt) = a.get("tenzro_receipt") {
            receipts.push(rcpt.clone());
        }
    }
    let data: Vec<Value> = vectors
        .into_iter()
        .enumerate()
        .map(|(index, embedding)| json!({ "object": "embedding", "index": index, "embedding": embedding }))
        .collect();
    json!({
        "object": "list",
        "data": data,
        "model": model,
        "dimensions": dim,
        // An image encoder reads no text tokens: its work is in
        // `units.image_tokens` and the OpenAI token fields stay at zero.
        "usage": { "prompt_tokens": units.prompt_tokens(), "total_tokens": units.total_tokens() },
        "units": units_to_json(&units),
        "cost_wei": cost.to_string(),
        "tenzro_receipts": receipts,
    })
}

/// Response shape requested on `/v1/audio/transcriptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptionFormat {
    Json,
    Text,
    VerboseJson,
    Srt,
    Vtt,
}

impl TranscriptionFormat {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "verbose_json" => Some(Self::VerboseJson),
            "srt" => Some(Self::Srt),
            "vtt" => Some(Self::Vtt),
            _ => None,
        }
    }

    /// Whether the format renders per-segment time ranges, and so needs them
    /// whatever the caller asked for.
    fn needs_timestamps(self) -> bool {
        matches!(self, Self::VerboseJson | Self::Srt | Self::Vtt)
    }
}

/// Seconds as `HH:MM:SS,mmm` (SubRip) or `HH:MM:SS.mmm` (WebVTT).
fn format_timecode(seconds: f64, millis_separator: char) -> String {
    let total_ms = (seconds.max(0.0) * 1000.0).round() as u64;
    let total_s = total_ms / 1000;
    format!(
        "{:02}:{:02}:{:02}{}{:03}",
        total_s / 3600,
        (total_s % 3600) / 60,
        total_s % 60,
        millis_separator,
        total_ms % 1000
    )
}

/// `POST /v1/audio/transcriptions`: OpenAI-compatible speech recognition,
/// `tenzro_transcribe` over a `multipart/form-data` upload (`file`, `model`,
/// and optionally `language`, `response_format`, `temperature`,
/// `timestamp_granularities`, `prompt` (empty only), and `provider`,
/// `verification`, `receipt_nonce`).
///
/// `response_format` is `json` (default), `text`, `verbose_json`, `srt` or
/// `vtt`; the three that render time ranges ask for segment timestamps.
/// Fields the method has no use for are refused by name rather than dropped,
/// so a caller never pays for instructions that were ignored. The plain-text
/// formats carry the cost and the signed receipt (base64 JSON) in headers.
pub(crate) async fn transcriptions(
    State(node): State<Arc<TenzroNode>>,
    mut multipart: Multipart,
) -> Response {
    let refuse = |message: &str, code: &str| {
        json_error_response(
            StatusCode::BAD_REQUEST,
            message,
            "invalid_request_error",
            code,
        )
    };
    let mut audio: Option<Vec<u8>> = None;
    let mut model: Option<String> = None;
    let mut routing = Routing::default();
    let mut language: Option<String> = None;
    let mut response_format = TranscriptionFormat::Json;
    let mut temperature: Option<f32> = None;
    let mut want_segment_timestamps = false;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return refuse(
                    &format!("malformed multipart body: {e}"),
                    "malformed_multipart",
                );
            }
        };
        let Some(name) = field.name().map(str::to_string) else {
            continue;
        };
        if name == "file" {
            match field.bytes().await {
                Ok(b) => audio = Some(b.to_vec()),
                Err(e) => {
                    return refuse(
                        &format!("could not read the 'file' part: {e}"),
                        "unreadable_form_field",
                    );
                }
            }
            continue;
        }
        if !matches!(
            name.as_str(),
            "model"
                | "language"
                | "response_format"
                | "temperature"
                | "timestamp_granularities"
                | "timestamp_granularities[]"
                | "prompt"
                | "provider"
                | "verification"
                | "receipt_nonce"
        ) {
            return refuse(
                &format!("unknown form field '{name}'"),
                "unknown_form_field",
            );
        }
        let value = match field.text().await {
            Ok(v) => v,
            Err(e) => {
                return refuse(
                    &format!("could not read the '{name}' part: {e}"),
                    "unreadable_form_field",
                );
            }
        };
        match name.as_str() {
            "model" => model = Some(value),
            "provider" => routing.provider = Some(value),
            "verification" => routing.verification = Some(value),
            "receipt_nonce" => routing.receipt_nonce = Some(value),
            "language" => language = Some(value).filter(|v| !v.trim().is_empty()),
            "response_format" => match TranscriptionFormat::parse(&value) {
                Some(f) => response_format = f,
                None => {
                    return refuse(
                        &format!(
                            "unsupported response_format '{value}' (json, text, verbose_json, srt, vtt)"
                        ),
                        "unsupported_response_format",
                    );
                }
            },
            "temperature" => match value.trim().parse::<f32>() {
                Ok(t) => temperature = Some(t),
                Err(_) => {
                    return refuse(
                        &format!("'temperature' must be a number, got '{value}'"),
                        "invalid_temperature",
                    );
                }
            },
            "prompt" => {
                if !value.trim().is_empty() {
                    return refuse(
                        "'prompt' is not served: the speech recognizers take no text conditioning on this route",
                        "unsupported_prompt",
                    );
                }
            }
            _ => match value.to_ascii_lowercase().as_str() {
                "segment" => want_segment_timestamps = true,
                "word" => {
                    return refuse(
                        "timestamp_granularities 'word' is not served: the recognizers emit segment time ranges only; request 'segment'",
                        "unsupported_timestamp_granularity",
                    );
                }
                other => {
                    return refuse(
                        &format!("unknown timestamp_granularities value '{other}'"),
                        "unsupported_timestamp_granularity",
                    );
                }
            },
        }
    }

    let Some(audio) = audio.filter(|a| !a.is_empty()) else {
        return refuse(
            "'file' is required and carries the recording",
            "missing_file",
        );
    };
    let Some(model) = model else {
        return refuse("'model' is required", "missing_model");
    };
    let mut p = routing.params(&model);
    p.insert(
        "audio_base64".into(),
        json!(base64::engine::general_purpose::STANDARD.encode(&audio)),
    );
    p.insert(
        "timestamps".into(),
        json!(want_segment_timestamps || response_format.needs_timestamps()),
    );
    if let Some(l) = language {
        p.insert("language".into(), json!(l));
    }
    if let Some(t) = temperature {
        p.insert("temperature".into(), json!(t));
    }
    let out = match crate::rpc::handle_transcribe(&node, Some(Value::Object(p))).await {
        Ok(out) => out,
        Err(e) => return rpc_error_response(&e, "transcription"),
    };
    render_transcription(&model, &out, response_format)
}

/// A `tenzro_transcribe` answer in the requested format.
fn render_transcription(model: &str, out: &Value, format: TranscriptionFormat) -> Response {
    let text = out
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let segments = out
        .get("segments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let delivery = |content_type: &'static str, body: String| {
        let receipt = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(out.get("tenzro_receipt").unwrap_or(&Value::Null))
                .unwrap_or_default(),
        );
        let cost = out
            .get("cost_wei")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string();
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type.to_string()),
                (HeaderName::from_static("x-tenzro-cost-wei"), cost),
                (HeaderName::from_static("x-tenzro-receipt"), receipt),
            ],
            body,
        )
            .into_response()
    };
    match format {
        TranscriptionFormat::Json => (
            StatusCode::OK,
            Json(json!({
                "text": text,
                "units": out.get("units"),
                "cost_wei": out.get("cost_wei"),
                "tenzro_receipt": out.get("tenzro_receipt"),
            })),
        )
            .into_response(),
        TranscriptionFormat::Text => delivery("text/plain; charset=utf-8", text),
        TranscriptionFormat::VerboseJson => {
            let duration = segments
                .iter()
                .filter_map(|s| s.get("end_seconds").and_then(Value::as_f64))
                .fold(0.0f64, f64::max);
            let segments: Vec<Value> = segments
                .iter()
                .enumerate()
                .map(|(id, s)| {
                    json!({
                        "id": id,
                        "start": s.get("start_seconds"),
                        "end": s.get("end_seconds"),
                        "text": s.get("text"),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "task": "transcribe",
                    "language": out.get("language"),
                    "duration": duration,
                    "text": text,
                    "segments": segments,
                    "units": out.get("units"),
                    "cost_wei": out.get("cost_wei"),
                    "tenzro_receipt": out.get("tenzro_receipt"),
                })),
            )
                .into_response()
        }
        TranscriptionFormat::Srt | TranscriptionFormat::Vtt => {
            let timed: Vec<(f64, f64, &str)> = segments
                .iter()
                .filter_map(|s| {
                    Some((
                        s.get("start_seconds")?.as_f64()?,
                        s.get("end_seconds")?.as_f64()?,
                        s.get("text")?.as_str()?,
                    ))
                })
                .collect();
            if timed.is_empty() {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "model '{model}' returned no segment time ranges, so a subtitle body cannot be built: request response_format 'json' or 'text'"
                    ),
                    "invalid_request_error",
                    "timestamps_unavailable",
                );
            }
            let srt = format == TranscriptionFormat::Srt;
            let sep = if srt { ',' } else { '.' };
            let mut body = if srt {
                String::new()
            } else {
                "WEBVTT\n\n".to_string()
            };
            for (index, (start, end, line)) in timed.iter().enumerate() {
                if srt {
                    body.push_str(&format!("{}\n", index + 1));
                }
                body.push_str(&format!(
                    "{} --> {}\n{}\n\n",
                    format_timecode(*start, sep),
                    format_timecode(*end, sep),
                    line.trim()
                ));
            }
            delivery(
                if srt {
                    "application/x-subrip; charset=utf-8"
                } else {
                    "text/vtt; charset=utf-8"
                },
                body,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_fields_reach_the_method_and_payment_does_not() {
        let r: DetectionRequest = serde_json::from_value(json!({
            "model": "m", "image_base64": "", "provider": "ab", "verification": "optimistic",
            "payment": {"x": 1}, "channel_voucher": {"y": 2},
        }))
        .unwrap();
        let p = r.routing.params(&r.model);
        assert_eq!(p["model_id"], json!("m"));
        assert_eq!(p["provider"], json!("ab"));
        assert_eq!(p["verification"], json!("optimistic"));
        assert!(!p.contains_key("payment") && !p.contains_key("channel_voucher"));
    }

    #[test]
    fn method_errors_map_to_http_statuses() {
        let e = |code| JsonRpcError {
            code,
            message: "m".into(),
            data: None,
        };
        assert_eq!(
            rpc_error_response(&e(-32602), "x").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rpc_error_response(&e(-32004), "x").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rpc_error_response(&e(-32011), "x").status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            rpc_error_response(&e(-32000), "x").status(),
            StatusCode::BAD_GATEWAY
        );
        let busy = JsonRpcError {
            code: -32005,
            message: "busy".into(),
            data: Some(json!({ "retry_after_ms": 2500 })),
        };
        let resp = rpc_error_response(&busy, "x");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "3");
    }

    #[test]
    fn masks_travel_base64() {
        let mut out = json!({ "masks": [{ "width": 2, "height": 1, "mask": [0, 1] }] });
        masks_as_base64(out.get_mut("masks"));
        assert_eq!(out["masks"][0]["mask_base64"], json!("AAE="));
        assert!(out["masks"][0].get("mask").is_none());
    }

    #[test]
    fn embeddings_answers_merge_into_the_openai_shape() {
        let one = |v: f32| {
            json!({
                "embedding": [v, v], "dim": 2,
                "units": units_to_json(&tenzro_types::model::BillableUnits::default().with_image_tokens(4)),
                "cost_wei": "5", "tenzro_receipt": { "n": v },
            })
        };
        let body = embeddings_body("vit", &[one(1.0), one(2.0)]);
        assert_eq!(body["data"][1]["index"], json!(1));
        assert_eq!(body["data"][1]["embedding"], json!([2.0, 2.0]));
        assert_eq!(body["cost_wei"], json!("10"));
        assert_eq!(body["tenzro_receipts"].as_array().unwrap().len(), 2);
        assert_eq!(units_from_json(&body["units"]).image_tokens(), 8);

        let text = json!({ "embeddings": [[0.5], [0.25]], "dim": 1, "prompt_tokens": 3,
            "units": units_to_json(&tenzro_types::model::BillableUnits::tokens(3, 0)), "cost_wei": "1" });
        let body = embeddings_body("e", &[text]);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["usage"]["prompt_tokens"], json!(3));
    }

    #[test]
    fn subtitles_render_from_the_method_answer() {
        let out = json!({ "text": "hi there", "segments": [{ "text": " hi there ", "start_seconds": 0.0, "end_seconds": 1.5 }],
            "cost_wei": "7", "tenzro_receipt": { "r": 1 } });
        let resp = render_transcription("m", &out, TranscriptionFormat::Srt);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-tenzro-cost-wei"], "7");
        assert_eq!(format_timecode(3723.25, ','), "01:02:03,250");
        let untimed = json!({ "text": "x", "segments": [{ "text": "x" }] });
        assert_eq!(
            render_transcription("m", &untimed, TranscriptionFormat::Vtt).status(),
            StatusCode::BAD_REQUEST
        );
    }
}
