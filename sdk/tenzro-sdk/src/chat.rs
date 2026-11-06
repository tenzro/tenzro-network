//! The node's chat completion contract: the request `POST /v1/chat/completions`
//! accepts, and the adaptor that turns its streamed chunks into typed events.
//!
//! The node splits reasoning from the answer and assembles tool calls on its
//! side, so the adaptor reads fields and never parses model markup.

use crate::error::ApiError;
use crate::provider::ChatMessage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A chat completion request.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChatRequest {
    /// Model id, as listed by `GET /v1/models`.
    pub model: String,
    /// The conversation so far.
    pub messages: Vec<ChatMessage>,
    /// Functions the model may call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ChatTool>>,
    /// `"none"`, `"auto"`, `"required"`, or `{"type":"function","function":{"name":..}}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Output token ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Reasoning budget level for thinking models.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Whether the model may think before answering. Unset keeps the node's
    /// per-model default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_thinking: Option<bool>,
    /// Streaming options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,
    /// Which provider machines may serve the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderPreferences>,
}

impl ChatRequest {
    /// A request for `model` over `messages`, every option at the node's default.
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            ..Self::default()
        }
    }
}

/// Reasoning budget levels the node accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
}

/// Streaming options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamOptions {
    /// Append a final chunk carrying the token counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_usage: Option<bool>,
}

/// Provider pin: machine addresses (hex or base58) a request may or may not
/// be served by.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderPreferences {
    /// Serve only on these providers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only: Option<Vec<String>>,
    /// Never serve on these providers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore: Option<Vec<String>>,
}

/// A function the model may call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTool {
    /// Always `"function"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The function's declaration.
    pub function: ChatFunction,
}

impl ChatTool {
    /// A function tool with a JSON Schema for its arguments.
    pub fn function(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: Value,
    ) -> Self {
        Self {
            kind: "function".to_string(),
            function: ChatFunction {
                name: name.into(),
                description: Some(description.into()),
                parameters: Some(parameters),
            },
        }
    }
}

/// A function declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatFunction {
    /// Function name.
    pub name: String,
    /// What the function does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema of the arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
}

/// A tool call the model made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Call id, echoed back as `tool_call_id` on the tool's reply.
    pub id: String,
    /// Always `"function"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The function and its JSON-encoded arguments.
    pub function: ToolCallFunction,
}

/// The function a tool call names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallFunction {
    /// Function name.
    pub name: String,
    /// Arguments as a JSON string.
    pub arguments: String,
}

/// Token counts for one completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

/// One piece of a streamed completion, in arrival order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatStreamEvent {
    /// Reasoning text, delivered as the model produces it.
    Reasoning { text: String },
    /// Answer text.
    Content { text: String },
    /// Part of a tool call. `id` and `name` arrive on the call's first delta;
    /// `arguments` is appended per `index`.
    ToolCall {
        index: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        arguments: String,
    },
    /// Why generation ended, in the OpenAI vocabulary and the engine's own.
    Finish {
        finish_reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        native_finish_reason: Option<String>,
    },
    /// Token counts and the cost the node priced them at, in wei.
    Usage {
        usage: Usage,
        #[serde(skip_serializing_if = "Option::is_none")]
        cost_wei: Option<String>,
    },
}

/// A finished completion, assembled from its stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletion {
    pub id: Option<String>,
    pub model: Option<String>,
    /// The answer.
    pub content: String,
    /// The reasoning, empty when the model did not think.
    pub reasoning: String,
    /// Tool calls in index order.
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<String>,
    pub native_finish_reason: Option<String>,
    pub usage: Option<Usage>,
    /// Cost in wei, as a decimal string.
    pub cost_wei: Option<String>,
}

/// Turns the `data` payloads of a chat stream into [`ChatStreamEvent`]s and
/// accumulates the [`ChatCompletion`] they add up to.
#[derive(Debug, Default)]
pub struct ChatStreamAssembler {
    id: Option<String>,
    model: Option<String>,
    content: String,
    reasoning: String,
    tool_calls: BTreeMap<u32, ToolCall>,
    finish_reason: Option<String>,
    native_finish_reason: Option<String>,
    usage: Option<Usage>,
    cost_wei: Option<String>,
    done: bool,
}

impl ChatStreamAssembler {
    /// An assembler at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the `[DONE]` terminator has arrived.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Absorb one event's `data` and return the events it carries. An error
    /// frame, or a payload that is not a chunk, is returned as the error.
    pub fn push(&mut self, data: &str) -> Result<Vec<ChatStreamEvent>, ApiError> {
        if data == "[DONE]" {
            self.done = true;
            return Ok(Vec::new());
        }
        let frame: Value = serde_json::from_str(data)
            .map_err(|e| ApiError::malformed(format!("stream frame is not JSON: {e}")))?;
        if let Some(err) = ApiError::from_body(&frame) {
            return Err(err);
        }
        if self.id.is_none() {
            self.id = frame.get("id").and_then(Value::as_str).map(str::to_string);
        }
        if self.model.is_none() {
            self.model = frame
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string);
        }

        let mut events = Vec::new();
        if let Some(choice) = frame.get("choices").and_then(|c| c.get(0)) {
            let delta = choice.get("delta").unwrap_or(&Value::Null);
            if let Some(text) = non_empty_str(delta.get("reasoning_content")) {
                self.reasoning.push_str(text);
                events.push(ChatStreamEvent::Reasoning {
                    text: text.to_string(),
                });
            }
            if let Some(text) = non_empty_str(delta.get("content")) {
                self.content.push_str(text);
                events.push(ChatStreamEvent::Content {
                    text: text.to_string(),
                });
            }
            for call in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                events.push(self.absorb_tool_call(call)?);
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                let native = choice
                    .get("native_finish_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.finish_reason = Some(reason.to_string());
                self.native_finish_reason = native.clone();
                events.push(ChatStreamEvent::Finish {
                    finish_reason: reason.to_string(),
                    native_finish_reason: native,
                });
            }
        }
        if let Some(usage) = frame.get("usage").filter(|u| u.is_object()) {
            let usage: Usage = serde_json::from_value(usage.clone())
                .map_err(|e| ApiError::malformed(format!("usage is malformed: {e}")))?;
            let cost_wei = frame
                .get("cost_wei")
                .and_then(Value::as_str)
                .map(str::to_string);
            if self.usage.as_ref() != Some(&usage) || self.cost_wei != cost_wei {
                self.usage = Some(usage.clone());
                self.cost_wei = cost_wei.clone();
                events.push(ChatStreamEvent::Usage { usage, cost_wei });
            }
        }
        Ok(events)
    }

    fn absorb_tool_call(&mut self, call: &Value) -> Result<ChatStreamEvent, ApiError> {
        let index = call
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::malformed("tool call delta has no index".to_string()))?
            as u32;
        let id = call.get("id").and_then(Value::as_str).map(str::to_string);
        let function = call.get("function").unwrap_or(&Value::Null);
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string);
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let entry = self.tool_calls.entry(index).or_insert_with(|| ToolCall {
            id: String::new(),
            kind: "function".to_string(),
            function: ToolCallFunction {
                name: String::new(),
                arguments: String::new(),
            },
        });
        if let Some(id) = &id {
            entry.id = id.clone();
        }
        if let Some(name) = &name {
            entry.function.name = name.clone();
        }
        entry.function.arguments.push_str(&arguments);
        Ok(ChatStreamEvent::ToolCall {
            index,
            id,
            name,
            arguments,
        })
    }

    /// The completion the stream added up to.
    pub fn completion(&self) -> ChatCompletion {
        ChatCompletion {
            id: self.id.clone(),
            model: self.model.clone(),
            content: self.content.clone(),
            reasoning: self.reasoning.clone(),
            tool_calls: self.tool_calls.values().cloned().collect(),
            finish_reason: self.finish_reason.clone(),
            native_finish_reason: self.native_finish_reason.clone(),
            usage: self.usage.clone(),
            cost_wei: self.cost_wei.clone(),
        }
    }
}

fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}
