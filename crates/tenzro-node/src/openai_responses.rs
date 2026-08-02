//! Translation between the Responses shape and the chat-completions shape.
//!
//! `/v1/responses` is a projection of `/v1/chat/completions`, not a second
//! implementation. A Responses request is rewritten into a chat body, served by
//! the chat handler — which owns offer resolution, provider pinning, mid-stream
//! failover, settlement, provenance signing and the jurisdiction receipt — and
//! the chat result is rewritten back into a Responses object.
//!
//! Unrecognized request fields reach the chat body verbatim, so every Tenzro
//! extension the chat surface accepts (`models`, `provider`, `seed`,
//! `jurisdiction`, `jurisdiction_receipt`, `draft_n`, `verifiable`, `user`,
//! `stop`, `top_k`, `min_p`, the penalties, `stream_options`) is served here
//! without a second definition to keep in step.
//!
//! Anything the chat body has no home for is refused by name rather than
//! dropped: a caller that asked for tool calling or a stored conversation is
//! told it is not served, instead of being billed for a completion that quietly
//! ignored the ask.

use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Response fields carried through from the chat body untouched. These are the
/// Tenzro additions to the OpenAI shape — the settlement figure, the throughput
/// numbers, the signed provenance manifest, the jurisdiction receipt and the
/// TOPLOC commitment. A caller that verifies them on `/v1/chat/completions`
/// verifies the identical bytes here.
const CARRIED_KEYS: [&str; 6] = [
    "cost_wei",
    "generation_time_ms",
    "tokens_per_second",
    "tenzro_provenance",
    "tenzro_jurisdiction",
    "commitment",
];

/// A Responses request the chat surface cannot serve faithfully. Surfaced to
/// the caller as an HTTP 400 with `code` naming what was refused.
#[derive(Debug, Clone)]
pub struct TranslationError {
    pub message: String,
    pub code: &'static str,
}

impl TranslationError {
    fn new(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }
}

/// A Responses `input`: a bare string, or an array of items.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponsesInput {
    Text(String),
    Items(Vec<Value>),
}

/// Request body for `/v1/responses`.
#[derive(Debug, Deserialize)]
pub struct ResponsesRequest {
    pub model: String,
    #[serde(default)]
    pub input: Option<ResponsesInput>,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub metadata: Option<Value>,
    /// Accepted and reported back as `false`. No response is retained, so
    /// claiming otherwise would promise a `previous_response_id` turn that this
    /// gateway cannot serve.
    #[serde(default)]
    pub store: Option<bool>,
    #[serde(default)]
    pub previous_response_id: Option<String>,
    #[serde(default)]
    pub tools: Option<Value>,
    #[serde(default)]
    pub tool_choice: Option<Value>,
    /// Everything else, forwarded to the chat body unchanged.
    #[serde(flatten)]
    pub passthrough: Map<String, Value>,
}

/// The request fields echoed on the response object. Only fields the gateway
/// honours appear here — echoing a parameter that was ignored would report
/// settings the generation never saw.
#[derive(Debug, Clone, Default)]
pub struct ResponsesEcho {
    pub instructions: Option<String>,
    pub metadata: Option<Value>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_output_tokens: Option<u32>,
}

impl ResponsesRequest {
    /// Whether the caller asked for a streamed response.
    pub fn wants_stream(&self) -> bool {
        self.stream.unwrap_or(false)
    }

    /// The model the caller named, before offer resolution picks the canonical
    /// registry id. Used to seed the response object when a stream faults
    /// before the first chunk names the served model.
    pub fn model_hint(&self) -> &str {
        &self.model
    }

    pub fn echo(&self) -> ResponsesEcho {
        ResponsesEcho {
            instructions: self.instructions.clone(),
            metadata: self.metadata.clone(),
            temperature: self.temperature,
            top_p: self.top_p,
            max_output_tokens: self.max_output_tokens,
        }
    }

    /// Rewrite into the chat-completions body the gateway serves.
    pub fn into_chat_body(self) -> Result<Value, TranslationError> {
        if self.previous_response_id.is_some() {
            return Err(TranslationError::new(
                "previous_response_id is not served — this gateway retains no responses, so prior turns must be replayed in `input`",
                "unsupported_previous_response_id",
            ));
        }
        if self.tools.as_ref().is_some_and(non_empty_value) {
            return Err(TranslationError::new(
                "tools are not served on this endpoint",
                "unsupported_tools",
            ));
        }
        if self
            .tool_choice
            .as_ref()
            .and_then(Value::as_str)
            .is_some_and(|c| !c.eq_ignore_ascii_case("none"))
            || self.tool_choice.as_ref().is_some_and(Value::is_object)
        {
            return Err(TranslationError::new(
                "tool_choice is not served on this endpoint",
                "unsupported_tool_choice",
            ));
        }

        let mut messages: Vec<Value> = Vec::new();
        if let Some(instructions) = self
            .instructions
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            messages.push(json!({ "role": "system", "content": instructions }));
        }

        match self.input {
            None => {
                return Err(TranslationError::new(
                    "`input` is required",
                    "missing_input",
                ));
            }
            Some(ResponsesInput::Text(text)) => {
                messages.push(json!({ "role": "user", "content": text }));
            }
            Some(ResponsesInput::Items(items)) => {
                if items.is_empty() {
                    return Err(TranslationError::new(
                        "`input` is required",
                        "missing_input",
                    ));
                }
                for item in items {
                    messages.push(convert_input_item(item)?);
                }
            }
        }

        let mut body = self.passthrough;
        body.insert("model".to_string(), Value::String(self.model));
        body.insert("messages".to_string(), Value::Array(messages));
        if let Some(v) = self.temperature {
            body.insert("temperature".to_string(), json!(v));
        }
        if let Some(v) = self.top_p {
            body.insert("top_p".to_string(), json!(v));
        }
        if let Some(v) = self.max_output_tokens {
            body.insert("max_tokens".to_string(), json!(v));
        }
        if let Some(v) = self.stream {
            body.insert("stream".to_string(), json!(v));
        }
        Ok(Value::Object(body))
    }
}

/// Whether a `tools` value asks for anything. An absent list and an empty list
/// both mean "no tools" and are accepted.
fn non_empty_value(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

/// Rewrite one `input` item as a chat message.
fn convert_input_item(item: Value) -> Result<Value, TranslationError> {
    let Value::Object(mut obj) = item else {
        return Err(TranslationError::new(
            "each `input` entry must be an object, or the whole `input` must be a string",
            "invalid_input_item",
        ));
    };
    if let Some(kind) = obj.get("type").and_then(Value::as_str)
        && kind != "message"
    {
        return Err(TranslationError::new(
            format!("input item of type '{kind}' is not served"),
            "unsupported_input_item",
        ));
    }
    let role = obj
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user")
        .to_string();
    let content = match obj.remove("content") {
        Some(Value::String(s)) => Value::String(s),
        Some(Value::Array(parts)) => {
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                out.push(convert_content_part(part)?);
            }
            Value::Array(out)
        }
        _ => {
            return Err(TranslationError::new(
                "each `input` message needs `content` as a string or an array of parts",
                "invalid_input_item",
            ));
        }
    };
    Ok(json!({ "role": role, "content": content }))
}

/// Rewrite one Responses content part in the chat vocabulary. The two surfaces
/// name the same parts differently — `input_text` against `text`, `input_image`
/// carrying a bare URL against `image_url` carrying an object.
fn convert_content_part(part: Value) -> Result<Value, TranslationError> {
    let Value::Object(obj) = part else {
        return Err(TranslationError::new(
            "each content part must be an object",
            "invalid_content_part",
        ));
    };
    match obj.get("type").and_then(Value::as_str).unwrap_or_default() {
        "input_text" | "output_text" | "text" => {
            let text = obj.get("text").and_then(Value::as_str).unwrap_or_default();
            Ok(json!({ "type": "text", "text": text }))
        }
        "input_image" => {
            let url = obj
                .get("image_url")
                .and_then(Value::as_str)
                .or_else(|| {
                    obj.get("image_url")
                        .and_then(|v| v.get("url"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| {
                    TranslationError::new(
                        "input_image needs `image_url`; a `file_id` reference is not served",
                        "unsupported_content_part",
                    )
                })?;
            let mut image = Map::new();
            image.insert("url".to_string(), Value::String(url.to_string()));
            if let Some(detail) = obj.get("detail").and_then(Value::as_str) {
                image.insert("detail".to_string(), Value::String(detail.to_string()));
            }
            Ok(json!({ "type": "image_url", "image_url": image }))
        }
        "input_file" => {
            let mut file = Map::new();
            for key in ["file_id", "file_data", "filename"] {
                if let Some(v) = obj.get(key).and_then(Value::as_str) {
                    file.insert(key.to_string(), Value::String(v.to_string()));
                }
            }
            if file.is_empty() {
                return Err(TranslationError::new(
                    "input_file needs `file_id` or `file_data`",
                    "invalid_content_part",
                ));
            }
            Ok(json!({ "type": "file", "file": file }))
        }
        "input_audio" => {
            let audio = obj.get("input_audio").cloned().ok_or_else(|| {
                TranslationError::new(
                    "input_audio needs an `input_audio` object",
                    "invalid_content_part",
                )
            })?;
            Ok(json!({ "type": "input_audio", "input_audio": audio }))
        }
        other => Err(TranslationError::new(
            format!("content part of type '{other}' is not served"),
            "unsupported_content_part",
        )),
    }
}

/// Accumulated state for one Responses object. The buffered path fills it from
/// a finished chat completion; the streamed path fills it chunk by chunk. Both
/// render through the same [`ResponseBuilder::object`], so a streamed
/// `response.completed` and a buffered body describe the same generation with
/// the same fields.
#[derive(Debug, Clone)]
pub struct ResponseBuilder {
    id: String,
    item_id: String,
    created_at: u64,
    model: String,
    echo: ResponsesEcho,
    text: String,
    usage: Option<Value>,
    finish_reason: Option<String>,
    native_finish_reason: Option<String>,
    error: Option<Value>,
    extras: Map<String, Value>,
}

impl ResponseBuilder {
    pub fn new(model_hint: &str, echo: ResponsesEcho) -> Self {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        Self {
            id: format!("resp_{suffix}"),
            item_id: format!("msg_{suffix}"),
            created_at: unix_secs(),
            model: model_hint.to_string(),
            echo,
            text: String::new(),
            usage: None,
            finish_reason: None,
            native_finish_reason: None,
            error: None,
            extras: Map::new(),
        }
    }

    /// Derive the response and message ids from the chat completion id, so a
    /// `resp_…` in a caller's logs traces back to the `chatcmpl-…` the gateway
    /// recorded for the same generation.
    fn adopt_completion_id(&mut self, chat_id: &str) {
        let suffix = chat_id.strip_prefix("chatcmpl-").unwrap_or(chat_id);
        if suffix.is_empty() {
            return;
        }
        self.id = format!("resp_{suffix}");
        self.item_id = format!("msg_{suffix}");
    }

    /// Absorb the fields a chat completion body and a chat chunk share: the id,
    /// the creation time, the served model, the usage counts, the finish reason
    /// and the carried Tenzro fields.
    fn absorb_common(&mut self, obj: &Map<String, Value>) {
        if let Some(id) = obj.get("id").and_then(Value::as_str) {
            self.adopt_completion_id(id);
        }
        if let Some(created) = obj.get("created").and_then(Value::as_u64) {
            self.created_at = created;
        }
        if let Some(model) = obj.get("model").and_then(Value::as_str) {
            self.model = model.to_string();
        }
        if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
            self.usage = Some(json!({
                "input_tokens": usage.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
                "output_tokens": usage.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
                "total_tokens": usage.get("total_tokens").and_then(Value::as_u64).unwrap_or(0),
            }));
        }
        for key in CARRIED_KEYS {
            if let Some(v) = obj.get(key)
                && !v.is_null()
            {
                self.extras.insert(key.to_string(), v.clone());
            }
        }
    }

    fn set_finish(&mut self, choice: &Map<String, Value>) {
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(reason.to_string());
        }
        if let Some(native) = choice.get("native_finish_reason").and_then(Value::as_str) {
            self.native_finish_reason = Some(native.to_string());
        }
    }

    fn status(&self) -> &'static str {
        if self.error.is_some() {
            return "failed";
        }
        match self.finish_reason.as_deref() {
            Some("length") | Some("content_filter") => "incomplete",
            _ => "completed",
        }
    }

    fn incomplete_reason(&self) -> Option<&'static str> {
        match self.finish_reason.as_deref() {
            Some("length") => Some("max_output_tokens"),
            Some("content_filter") => Some("content_filter"),
            _ => None,
        }
    }

    fn message_item(&self, status: &str) -> Value {
        json!({
            "id": self.item_id,
            "type": "message",
            "status": status,
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": self.text,
                "annotations": [],
            }],
        })
    }

    /// Render the response object. `include_output` is false for the opening
    /// events, where the message item does not exist yet.
    fn object(&self, status: &str, include_output: bool) -> Value {
        let mut out = Map::new();
        out.insert("id".to_string(), Value::String(self.id.clone()));
        out.insert("object".to_string(), Value::String("response".to_string()));
        out.insert("created_at".to_string(), json!(self.created_at));
        out.insert("status".to_string(), Value::String(status.to_string()));
        out.insert("model".to_string(), Value::String(self.model.clone()));
        out.insert(
            "output".to_string(),
            if include_output {
                // An item can only be `completed` or `incomplete`; a failed
                // generation reports the reason in `error`, not on the item.
                let item_status = if status == "completed" {
                    "completed"
                } else {
                    "incomplete"
                };
                json!([self.message_item(item_status)])
            } else {
                json!([])
            },
        );
        out.insert(
            "output_text".to_string(),
            Value::String(if include_output {
                self.text.clone()
            } else {
                String::new()
            }),
        );
        out.insert(
            "instructions".to_string(),
            self.echo
                .instructions
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "max_output_tokens".to_string(),
            self.echo
                .max_output_tokens
                .map(|v| json!(v))
                .unwrap_or(Value::Null),
        );
        out.insert(
            "temperature".to_string(),
            self.echo
                .temperature
                .map(|v| json!(v))
                .unwrap_or(Value::Null),
        );
        out.insert(
            "top_p".to_string(),
            self.echo.top_p.map(|v| json!(v)).unwrap_or(Value::Null),
        );
        out.insert(
            "metadata".to_string(),
            self.echo.metadata.clone().unwrap_or_else(|| json!({})),
        );
        // No response is retained, so the caller is told so regardless of what
        // it asked for — a `true` here would advertise a follow-up turn keyed
        // on `previous_response_id` that this gateway refuses.
        out.insert("store".to_string(), Value::Bool(false));
        out.insert(
            "incomplete_details".to_string(),
            match self.incomplete_reason().filter(|_| status == "incomplete") {
                Some(reason) => json!({ "reason": reason }),
                None => Value::Null,
            },
        );
        out.insert(
            "error".to_string(),
            self.error.clone().unwrap_or(Value::Null),
        );
        out.insert(
            "usage".to_string(),
            self.usage.clone().unwrap_or(Value::Null),
        );
        out.insert(
            "native_finish_reason".to_string(),
            self.native_finish_reason
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        for (key, value) in &self.extras {
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

/// Rewrite a finished chat completion body as a Responses object.
pub fn from_chat_completion(chat: &Value, model_hint: &str, echo: ResponsesEcho) -> Value {
    let mut builder = ResponseBuilder::new(model_hint, echo);
    if let Some(obj) = chat.as_object() {
        builder.absorb_common(obj);
        if let Some(choice) = obj
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(Value::as_object)
        {
            builder.set_finish(choice);
            if let Some(text) = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
            {
                builder.text.push_str(text);
            }
        }
    }
    let status = builder.status();
    builder.object(status, true)
}

/// One named SSE event of a streamed Responses generation.
#[derive(Debug, Clone)]
pub struct FramedEvent {
    pub name: String,
    pub data: Value,
}

/// Rewrites a chat-completions SSE stream as the typed event sequence the
/// Responses surface emits.
///
/// The chat stream is a run of `chat.completion.chunk` frames terminated by
/// `[DONE]`; the Responses stream is `response.created` → `response.in_progress`
/// → `response.output_item.added` → `response.content_part.added` → one
/// `response.output_text.delta` per token → `response.output_text.done` →
/// `response.content_part.done` → `response.output_item.done` →
/// `response.completed`. There is no `[DONE]` sentinel: the terminal event is
/// the terminator.
///
/// The opening events are withheld until the first chunk arrives, because that
/// chunk carries the served model id and the completion id the response object
/// is keyed on — emitting `response.created` before them would name the model
/// the caller asked for rather than the one that answered.
#[derive(Debug)]
pub struct ResponseStreamFramer {
    builder: ResponseBuilder,
    seq: u64,
    opened: bool,
    closed: bool,
}

impl ResponseStreamFramer {
    pub fn new(model_hint: &str, echo: ResponsesEcho) -> Self {
        Self {
            builder: ResponseBuilder::new(model_hint, echo),
            seq: 0,
            opened: false,
            closed: false,
        }
    }

    fn emit(&mut self, name: &str, mut data: Value) -> FramedEvent {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("type".to_string(), Value::String(name.to_string()));
            obj.insert("sequence_number".to_string(), json!(self.seq));
        }
        self.seq += 1;
        FramedEvent {
            name: name.to_string(),
            data,
        }
    }

    fn open(&mut self) -> Vec<FramedEvent> {
        if self.opened {
            return Vec::new();
        }
        self.opened = true;
        let opening = self.builder.object("in_progress", false);
        let item_id = self.builder.item_id.clone();
        let created = json!({ "response": opening });
        let in_progress = created.clone();
        let item_added = json!({
            "output_index": 0,
            "item": {
                "id": item_id,
                "type": "message",
                "status": "in_progress",
                "role": "assistant",
                "content": [],
            },
        });
        let part_added = json!({
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "part": { "type": "output_text", "text": "", "annotations": [] },
        });
        vec![
            self.emit("response.created", created),
            self.emit("response.in_progress", in_progress),
            self.emit("response.output_item.added", item_added),
            self.emit("response.content_part.added", part_added),
        ]
    }

    /// Feed one `data:` payload from the chat stream. Frames that do not parse,
    /// and the `[DONE]` sentinel, produce no output of their own — the sentinel
    /// closes the stream through [`ResponseStreamFramer::close`].
    pub fn on_payload(&mut self, payload: &str) -> Vec<FramedEvent> {
        let payload = payload.trim();
        if payload.is_empty() {
            return Vec::new();
        }
        if payload == "[DONE]" {
            return self.close();
        }
        let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(payload) else {
            return Vec::new();
        };

        if let Some(error) = obj.get("error").filter(|e| !e.is_null()) {
            self.builder.error = Some(error.clone());
            let mut events = self.open();
            events.extend(self.close());
            return events;
        }

        self.builder.absorb_common(&obj);
        let mut events = self.open();

        let Some(choice) = obj
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(Value::as_object)
        else {
            return events;
        };
        self.builder.set_finish(choice);

        if let Some(delta) = choice
            .get("delta")
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            self.builder.text.push_str(delta);
            let item_id = self.builder.item_id.clone();
            let delta = delta.to_string();
            events.push(self.emit(
                "response.output_text.delta",
                json!({
                    "item_id": item_id,
                    "output_index": 0,
                    "content_index": 0,
                    "delta": delta,
                    "logprobs": [],
                }),
            ));
        }
        events
    }

    /// Terminal events. Idempotent, so a `[DONE]` sentinel followed by the end
    /// of the transport does not emit the tail twice.
    pub fn close(&mut self) -> Vec<FramedEvent> {
        if self.closed {
            return Vec::new();
        }
        let mut events = self.open();
        self.closed = true;

        let item_id = self.builder.item_id.clone();
        let text = self.builder.text.clone();
        let status = self.builder.status();
        let item_status = if status == "failed" {
            "incomplete"
        } else {
            status
        };

        events.push(self.emit(
            "response.output_text.done",
            json!({
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "text": text,
                "logprobs": [],
            }),
        ));
        events.push(self.emit(
            "response.content_part.done",
            json!({
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": { "type": "output_text", "text": text, "annotations": [] },
            }),
        ));
        let item = self.builder.message_item(item_status);
        events.push(self.emit(
            "response.output_item.done",
            json!({ "output_index": 0, "item": item }),
        ));

        let terminal = match status {
            "failed" => "response.failed",
            "incomplete" => "response.incomplete",
            _ => "response.completed",
        };
        let object = self.builder.object(status, true);
        events.push(self.emit(terminal, json!({ "response": object })));
        events
    }

    /// Close the stream as a failure, for a transport that ended before the
    /// generation did.
    pub fn fail(&mut self, message: &str, code: &str) -> Vec<FramedEvent> {
        if self.closed {
            return Vec::new();
        }
        self.builder.error = Some(json!({ "code": code, "message": message }));
        self.close()
    }
}

/// Split a byte buffer into complete SSE frames, returning the `(id, data)` of
/// each and leaving any partial trailing frame in the buffer.
///
/// A frame's `data` is the concatenation of its `data:` lines; comment lines
/// (keep-alive pings) yield no data and are skipped by the caller.
pub fn drain_sse_frames(buffer: &mut String) -> Vec<(Option<String>, String)> {
    let mut frames = Vec::new();
    while let Some(end) = buffer.find("\n\n") {
        let frame: String = buffer.drain(..end + 2).collect();
        let mut id = None;
        let mut data: Vec<&str> = Vec::new();
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data.push(rest.strip_prefix(' ').unwrap_or(rest));
            } else if let Some(rest) = line.strip_prefix("id:") {
                id = Some(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
        }
        if !data.is_empty() {
            frames.push((id, data.join("\n")));
        }
    }
    frames
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> ResponsesRequest {
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn a_bare_string_input_becomes_one_user_message() {
        let req = parse(r#"{"model":"m","input":"hello"}"#);
        let body = req.into_chat_body().unwrap();
        assert_eq!(body["model"], "m");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "hello");
    }

    #[test]
    fn instructions_lead_as_a_system_message() {
        let req = parse(r#"{"model":"m","input":"hi","instructions":"be terse"}"#);
        let body = req.into_chat_body().unwrap();
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "be terse");
        assert_eq!(body["messages"][1]["role"], "user");
    }

    #[test]
    fn max_output_tokens_maps_onto_max_tokens() {
        let req = parse(r#"{"model":"m","input":"hi","max_output_tokens":64}"#);
        let body = req.into_chat_body().unwrap();
        assert_eq!(body["max_tokens"], 64);
    }

    #[test]
    fn tenzro_extensions_reach_the_chat_body_untouched() {
        let req = parse(
            r#"{"model":"m","input":"hi","models":["b"],"provider":{"only":["p"]},
                "jurisdiction":"EU","seed":7,"verifiable":true,"stop":["x"]}"#,
        );
        let body = req.into_chat_body().unwrap();
        assert_eq!(body["models"][0], "b");
        assert_eq!(body["provider"]["only"][0], "p");
        assert_eq!(body["jurisdiction"], "EU");
        assert_eq!(body["seed"], 7);
        assert_eq!(body["verifiable"], true);
        assert_eq!(body["stop"][0], "x");
    }

    #[test]
    fn typed_input_parts_are_rewritten_in_the_chat_vocabulary() {
        let req = parse(
            r#"{"model":"m","input":[{"role":"user","content":[
                {"type":"input_text","text":"describe"},
                {"type":"input_image","image_url":"https://example.test/a.png","detail":"low"}]}]}"#,
        );
        let body = req.into_chat_body().unwrap();
        let parts = &body["messages"][0]["content"];
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[0]["text"], "describe");
        assert_eq!(parts[1]["type"], "image_url");
        assert_eq!(parts[1]["image_url"]["url"], "https://example.test/a.png");
        assert_eq!(parts[1]["image_url"]["detail"], "low");
    }

    #[test]
    fn a_stored_conversation_is_refused_by_name() {
        let req = parse(r#"{"model":"m","input":"hi","previous_response_id":"resp_1"}"#);
        let err = req.into_chat_body().unwrap_err();
        assert_eq!(err.code, "unsupported_previous_response_id");
    }

    #[test]
    fn tools_are_refused_but_an_empty_list_is_accepted() {
        let err = parse(r#"{"model":"m","input":"hi","tools":[{"type":"function"}]}"#)
            .into_chat_body()
            .unwrap_err();
        assert_eq!(err.code, "unsupported_tools");
        assert!(
            parse(r#"{"model":"m","input":"hi","tools":[]}"#)
                .into_chat_body()
                .is_ok()
        );
    }

    #[test]
    fn an_unrenderable_input_item_is_named_in_the_refusal() {
        let err = parse(
            r#"{"model":"m","input":[{"type":"function_call_output","call_id":"c","output":"x"}]}"#,
        )
        .into_chat_body()
        .unwrap_err();
        assert_eq!(err.code, "unsupported_input_item");
        assert!(err.message.contains("function_call_output"));
    }

    #[test]
    fn missing_input_is_refused() {
        assert_eq!(
            parse(r#"{"model":"m"}"#).into_chat_body().unwrap_err().code,
            "missing_input"
        );
        assert_eq!(
            parse(r#"{"model":"m","input":[]}"#)
                .into_chat_body()
                .unwrap_err()
                .code,
            "missing_input"
        );
    }

    fn completion(finish: &str) -> Value {
        json!({
            "id": "chatcmpl-abc",
            "object": "chat.completion",
            "created": 1700,
            "model": "served-model",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "hi there" },
                "finish_reason": finish,
                "native_finish_reason": "end_turn",
            }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5 },
            "cost_wei": "42",
            "tenzro_provenance": { "sig": "s" },
        })
    }

    #[test]
    fn a_completion_becomes_a_response_object() {
        let out = from_chat_completion(&completion("stop"), "m", ResponsesEcho::default());
        assert_eq!(out["id"], "resp_abc");
        assert_eq!(out["object"], "response");
        assert_eq!(out["created_at"], 1700);
        assert_eq!(out["status"], "completed");
        assert_eq!(out["model"], "served-model");
        assert_eq!(out["output"][0]["type"], "message");
        assert_eq!(out["output"][0]["role"], "assistant");
        assert_eq!(out["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(out["output"][0]["content"][0]["text"], "hi there");
        assert_eq!(out["output_text"], "hi there");
        assert_eq!(out["usage"]["input_tokens"], 3);
        assert_eq!(out["usage"]["output_tokens"], 2);
        assert_eq!(out["usage"]["total_tokens"], 5);
        assert_eq!(out["native_finish_reason"], "end_turn");
        assert_eq!(out["store"], false);
        assert!(out["incomplete_details"].is_null());
    }

    #[test]
    fn the_carried_tenzro_fields_survive_the_rewrite() {
        let out = from_chat_completion(&completion("stop"), "m", ResponsesEcho::default());
        assert_eq!(out["cost_wei"], "42");
        assert_eq!(out["tenzro_provenance"]["sig"], "s");
    }

    #[test]
    fn a_truncated_completion_reports_incomplete() {
        let out = from_chat_completion(&completion("length"), "m", ResponsesEcho::default());
        assert_eq!(out["status"], "incomplete");
        assert_eq!(out["incomplete_details"]["reason"], "max_output_tokens");
    }

    #[test]
    fn the_echoed_fields_are_the_ones_the_gateway_honours() {
        let echo = ResponsesEcho {
            instructions: Some("be terse".into()),
            metadata: Some(json!({ "k": "v" })),
            temperature: Some(0.25),
            top_p: Some(0.9),
            max_output_tokens: Some(64),
        };
        let out = from_chat_completion(&completion("stop"), "m", echo);
        assert_eq!(out["instructions"], "be terse");
        assert_eq!(out["metadata"]["k"], "v");
        assert_eq!(out["temperature"], 0.25);
        assert_eq!(out["top_p"], 0.9);
        assert_eq!(out["max_output_tokens"], 64);
    }

    fn chunk(delta: &str) -> String {
        json!({
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "created": 1700,
            "model": "served-model",
            "choices": [{ "index": 0, "delta": { "content": delta }, "finish_reason": null }],
        })
        .to_string()
    }

    fn final_chunk(finish: &str) -> String {
        json!({
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "created": 1700,
            "model": "served-model",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": finish,
                "native_finish_reason": finish,
            }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5 },
        })
        .to_string()
    }

    fn drive(payloads: &[String]) -> Vec<FramedEvent> {
        let mut framer = ResponseStreamFramer::new("m", ResponsesEcho::default());
        let mut events = Vec::new();
        for p in payloads {
            events.extend(framer.on_payload(p));
        }
        events.extend(framer.close());
        events
    }

    #[test]
    fn a_stream_frames_the_documented_event_order() {
        let events = drive(&[
            chunk("hi"),
            chunk(" there"),
            final_chunk("stop"),
            "[DONE]".to_string(),
        ]);
        let names: Vec<&str> = events.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
    }

    #[test]
    fn sequence_numbers_are_monotonic_from_zero() {
        let events = drive(&[chunk("hi"), final_chunk("stop")]);
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.data["sequence_number"], i as u64);
            assert_eq!(e.data["type"], e.name.as_str());
        }
    }

    #[test]
    fn the_terminal_event_carries_the_whole_generation() {
        let events = drive(&[chunk("hi"), chunk(" there"), final_chunk("stop")]);
        let last = events.last().unwrap();
        assert_eq!(last.name, "response.completed");
        let r = &last.data["response"];
        assert_eq!(r["id"], "resp_abc");
        assert_eq!(r["status"], "completed");
        assert_eq!(r["output_text"], "hi there");
        assert_eq!(r["usage"]["output_tokens"], 2);
    }

    #[test]
    fn a_truncated_stream_terminates_as_incomplete() {
        let events = drive(&[chunk("hi"), final_chunk("length")]);
        let last = events.last().unwrap();
        assert_eq!(last.name, "response.incomplete");
        assert_eq!(
            last.data["response"]["incomplete_details"]["reason"],
            "max_output_tokens"
        );
    }

    #[test]
    fn closing_twice_emits_the_tail_once() {
        let mut framer = ResponseStreamFramer::new("m", ResponsesEcho::default());
        framer.on_payload(&chunk("hi"));
        let first = framer.close();
        assert!(!first.is_empty());
        assert!(framer.close().is_empty());
        assert!(framer.fail("gone", "transport_error").is_empty());
    }

    #[test]
    fn a_stream_that_never_started_fails_with_the_full_event_sequence() {
        let mut framer = ResponseStreamFramer::new("m", ResponsesEcho::default());
        let events = framer.fail("upstream closed", "transport_error");
        let last = events.last().unwrap();
        assert_eq!(last.name, "response.failed");
        assert_eq!(last.data["response"]["status"], "failed");
        assert_eq!(last.data["response"]["error"]["code"], "transport_error");
        assert_eq!(last.data["response"]["model"], "m");
    }

    #[test]
    fn sse_frames_split_on_the_blank_line_and_keep_the_partial_tail() {
        let mut buf = String::from("id: r:1\ndata: {\"a\":1}\n\n:ping\n\ndata: {\"b\"");
        let frames = drain_sse_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0.as_deref(), Some("r:1"));
        assert_eq!(frames[0].1, "{\"a\":1}");
        assert_eq!(buf, "data: {\"b\"");
    }

    #[test]
    fn multi_line_data_is_rejoined_with_newlines() {
        let mut buf = String::from("data: one\ndata: two\n\n");
        let frames = drain_sse_frames(&mut buf);
        assert_eq!(frames[0].1, "one\ntwo");
        assert!(buf.is_empty());
    }
}
