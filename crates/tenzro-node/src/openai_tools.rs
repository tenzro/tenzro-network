//! OpenAI tool calling on `/v1/chat/completions`.
//!
//! Standard agent history carries tool structure: an assistant turn with
//! `content: null` plus `tool_calls`, then a `role: "tool"` turn carrying
//! `tool_call_id`. A message type without those fields either fails to
//! deserialize such a turn or silently drops its tool fields, and a request
//! whose `tools` are ignored is served as a plain chat that never calls one.
//!
//! This module owns the wire types and the rules around them:
//!
//! * [`OpenAIChatMessage`] carries the full OpenAI message shape, including
//!   `tool_calls`, `tool_call_id`, `name` and an echoed `reasoning_content`.
//! * [`ToolPlan::from_request`] validates `tools` and `tool_choice` before any
//!   work is admitted, and turns them into the runtime's [`ToolDefinition`]s.
//! * [`ToolPlan::check_calls`] enforces what the caller asked for on the way
//!   out: `required` and a named function must produce a call, a call must name
//!   a declared function, and a `strict` function's arguments must satisfy its
//!   schema. A reply that breaks any of these is an error, never a silent
//!   success.
//! * [`openai_tool_calls`] renders the runtime's calls in the OpenAI shape,
//!   with `arguments` as a JSON string.
//!
//! Nothing here is model-specific. How a model is told about tools, and how
//! its reply is parsed back, is the runtime's business
//! (`ModelRuntime::generate_chat_with_tools`); this layer only speaks the wire
//! format and holds the reply to the caller's contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_model::{ChatMessage as ModelChatMessage, ToolCall, ToolDefinition};
#[cfg(feature = "inference")]
use tenzro_model::{GenerationConfig, InferenceResult, ModelRuntime, StopReason};

use crate::chat_content::MessageContent;

/// One message of an OpenAI chat request, in the shape clients send.
///
/// `content` is optional because an assistant turn that only called tools
/// carries `content: null`. `reasoning_content` is accepted on an echoed
/// assistant turn; it is not rendered back into the prompt, because the chat
/// templates this runtime serves drop prior reasoning themselves.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAIChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<MessageContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCall>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
}

impl OpenAIChatMessage {
    /// A plain text turn.
    pub fn text(role: String, content: String) -> Self {
        Self {
            role,
            content: Some(MessageContent::Text(content)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
            reasoning_content: None,
        }
    }

    /// The body as plain text, empty for a tool-call-only assistant turn.
    pub fn text_content(&self) -> String {
        self.content
            .as_ref()
            .map(MessageContent::as_text)
            .unwrap_or_default()
    }

    /// The runtime's message shape, tool structure included, so a template
    /// with tool branches renders tool history in its own dialect.
    pub fn to_model(&self) -> ModelChatMessage {
        ModelChatMessage {
            role: self.role.clone(),
            content: self.text_content(),
            tool_calls: self
                .tool_calls
                .as_ref()
                .filter(|c| !c.is_empty())
                .map(|calls| {
                    Value::Array(
                        calls
                            .iter()
                            .map(|c| {
                                serde_json::json!({
                                    "id": c.id,
                                    "type": "function",
                                    "function": {
                                        "name": c.function.name,
                                        // Templates index into the arguments
                                        // as an object, so the JSON string the
                                        // wire carries is parsed back here.
                                        "arguments": serde_json::from_str::<Value>(&c.function.arguments)
                                            .unwrap_or_else(|_| Value::String(c.function.arguments.clone())),
                                    },
                                })
                            })
                            .collect(),
                    )
                }),
            name: self.name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            reasoning_content: self.reasoning_content.clone(),
        }
    }
}

/// A tool call as it appears on the wire, in history and in responses.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OpenAIToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: OpenAIFunctionCall,
}

/// The function half of a tool call. `arguments` is a JSON-encoded string.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OpenAIFunctionCall {
    pub name: String,
    pub arguments: String,
}

/// A declared tool. Only `function` tools exist in the chat-completions API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAITool {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: OpenAIFunctionDef,
}

/// A function the model may call.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAIFunctionDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
    /// `true` asks for arguments that always satisfy `parameters`. The reply is
    /// checked against the schema and refused when it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// What the caller allowed or required of the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolMode {
    /// The model may answer or call a tool.
    Auto,
    /// The model must call at least one tool.
    Required,
    /// The model must call this function.
    Named(String),
}

/// A validation failure, carried as `(code, message)` for the OpenAI error
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
}

impl ToolError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The request's tools, validated and ready for the runtime.
#[derive(Debug, Clone)]
pub struct ToolPlan {
    pub definitions: Vec<ToolDefinition>,
    pub mode: ToolMode,
    /// `false` when the caller sent `parallel_tool_calls: false`: at most one
    /// call is returned per turn.
    pub parallel: bool,
    /// Parameter schemas of the functions declared `strict`, by name.
    strict: Vec<(String, Value)>,
}

/// Longest function name the API accepts, and the characters it may use.
fn valid_function_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl ToolPlan {
    /// Validate `tools` and `tool_choice`. `Ok(None)` means the request uses no
    /// tools: none were declared, or `tool_choice` is `"none"`.
    pub fn from_request(
        tools: Option<&[OpenAITool]>,
        tool_choice: Option<&Value>,
    ) -> Result<Option<Self>, ToolError> {
        let tools = tools.unwrap_or_default();
        let mode = match tool_choice {
            None => ToolMode::Auto,
            Some(Value::String(s)) => match s.as_str() {
                "auto" => ToolMode::Auto,
                "required" => ToolMode::Required,
                "none" => return Ok(None),
                other => {
                    return Err(ToolError::new(
                        "invalid_tool_choice",
                        format!("tool_choice '{other}' is not one of none, auto, required"),
                    ));
                }
            },
            Some(Value::Object(obj)) => {
                let name = obj
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .filter(|_| obj.get("type").and_then(Value::as_str) == Some("function"))
                    .ok_or_else(|| {
                        ToolError::new(
                            "invalid_tool_choice",
                            "tool_choice object must be {\"type\":\"function\",\"function\":{\"name\":...}}",
                        )
                    })?;
                ToolMode::Named(name.to_string())
            }
            Some(_) => {
                return Err(ToolError::new(
                    "invalid_tool_choice",
                    "tool_choice must be a string or a function object",
                ));
            }
        };
        if tools.is_empty() {
            return match mode {
                ToolMode::Auto => Ok(None),
                _ => Err(ToolError::new(
                    "invalid_tool_choice",
                    "tool_choice requires a tool call but no tools were declared",
                )),
            };
        }

        let mut definitions = Vec::with_capacity(tools.len());
        let mut strict = Vec::new();
        for tool in tools {
            if tool.kind != "function" {
                return Err(ToolError::new(
                    "unsupported_tool_type",
                    format!(
                        "tool type '{}' is not served; only 'function' tools are",
                        tool.kind
                    ),
                ));
            }
            let f = &tool.function;
            if !valid_function_name(&f.name) {
                return Err(ToolError::new(
                    "invalid_tool_name",
                    format!(
                        "function name '{}' must match ^[a-zA-Z0-9_-]{{1,64}}$",
                        f.name
                    ),
                ));
            }
            if definitions
                .iter()
                .any(|d: &ToolDefinition| d.name == f.name)
            {
                return Err(ToolError::new(
                    "duplicate_tool_name",
                    format!("function '{}' is declared twice", f.name),
                ));
            }
            // The API treats an omitted schema as a function with no
            // arguments; the runtime needs an object either way.
            let schema = f
                .parameters
                .clone()
                .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
            if !schema.is_object() {
                return Err(ToolError::new(
                    "invalid_tool_parameters",
                    format!("parameters of '{}' must be a JSON Schema object", f.name),
                ));
            }
            if f.strict == Some(true) {
                strict.push((f.name.clone(), schema.clone()));
            }
            definitions.push(ToolDefinition {
                name: f.name.clone(),
                description: f.description.clone(),
                input_schema: schema,
            });
        }

        if let ToolMode::Named(name) = &mode {
            // A named choice is served by offering the model that function
            // alone: it cannot call what it was never shown.
            let Some(only) = definitions.iter().find(|d| &d.name == name).cloned() else {
                return Err(ToolError::new(
                    "invalid_tool_choice",
                    format!("tool_choice names '{name}', which is not among the declared tools"),
                ));
            };
            definitions = vec![only];
        }

        Ok(Some(Self {
            definitions,
            mode,
            parallel: true,
            strict,
        }))
    }

    /// The calls a reply returns: at most one when parallel calls are off,
    /// then held to the contract by [`Self::check_calls`].
    pub fn take_calls(&self, mut calls: Vec<ToolCall>) -> Result<Vec<ToolCall>, ToolError> {
        if !self.parallel {
            calls.truncate(1);
        }
        self.check_calls(&calls)?;
        Ok(calls)
    }

    /// Hold the model's reply to the caller's contract. Every rule here is a
    /// refusal rather than a repair: an agent loop that receives a call to an
    /// undeclared function, or strict arguments that break their schema,
    /// cannot tell it apart from a correct reply.
    pub fn check_calls(&self, calls: &[ToolCall]) -> Result<(), ToolError> {
        match &self.mode {
            ToolMode::Auto => {}
            ToolMode::Required if calls.is_empty() => {
                return Err(ToolError::new(
                    "tool_choice_unsatisfied",
                    "tool_choice is 'required' but the model called no tool",
                ));
            }
            ToolMode::Named(name) if !calls.iter().any(|c| &c.name == name) => {
                return Err(ToolError::new(
                    "tool_choice_unsatisfied",
                    format!("tool_choice names '{name}' but the model did not call it"),
                ));
            }
            _ => {}
        }
        for call in calls {
            if !self.definitions.iter().any(|d| d.name == call.name) {
                return Err(ToolError::new(
                    "undeclared_tool_call",
                    format!(
                        "the model called '{}', which the request did not declare",
                        call.name
                    ),
                ));
            }
            if let Some((_, schema)) = self.strict.iter().find(|(n, _)| n == &call.name)
                && let Err(path) = validate_schema(schema, &call.input, "$")
            {
                return Err(ToolError::new(
                    "tool_arguments_invalid",
                    format!(
                        "arguments of strict function '{}' do not satisfy its schema at {path}",
                        call.name
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// A finished local generation: the engine's result plus any tool calls the
/// reply made, already held to the caller's contract.
#[cfg(feature = "inference")]
pub struct LocalChatOutcome {
    pub result: InferenceResult,
    pub tool_calls: Vec<OpenAIToolCall>,
}

#[cfg(feature = "inference")]
impl LocalChatOutcome {
    /// `(finish_reason, native_finish_reason)`. A tool call outranks the
    /// engine's own cause: the turn ends because control passes to the tool.
    pub fn finish_reasons(&self) -> (&'static str, &'static str) {
        if self.tool_calls.is_empty() {
            let native = self.result.stop_reason.as_str();
            (crate::rpc::normalize_finish_reason(native), native)
        } else {
            ("tool_calls", "tool_use")
        }
    }
}

/// Why a local generation produced no outcome.
#[cfg(feature = "inference")]
pub enum LocalChatError {
    /// The engine failed.
    Model(tenzro_model::ModelError),
    /// The engine answered, but not as the request's tools required.
    Tools(ToolError),
}

/// Run one buffered chat generation on the local runtime.
///
/// A request with neither tools nor attachments takes the plain chat path.
/// Anything else takes the tool- and media-aware path, which returns the
/// reply's tool calls beside its text; those are then held to `plan`.
#[cfg(feature = "inference")]
pub async fn generate_local(
    runtime: &ModelRuntime,
    model_id: &str,
    messages: &[ModelChatMessage],
    media: &[Vec<u8>],
    plan: Option<&ToolPlan>,
    config: &GenerationConfig,
) -> Result<LocalChatOutcome, LocalChatError> {
    if plan.is_none() && media.is_empty() {
        return runtime
            .generate_chat(model_id, messages, config)
            .await
            .map(|result| LocalChatOutcome {
                result,
                tool_calls: Vec::new(),
            })
            .map_err(LocalChatError::Model);
    }
    let definitions = plan.map(|p| p.definitions.as_slice()).unwrap_or_default();
    let r = runtime
        .generate_chat_multimodal(model_id, messages, media, definitions, config)
        .await
        .map_err(LocalChatError::Model)?;
    let calls = match plan {
        Some(p) => p.take_calls(r.tool_calls).map_err(LocalChatError::Tools)?,
        None => Vec::new(),
    };
    Ok(LocalChatOutcome {
        result: InferenceResult {
            text: r.text,
            thinking: r.thinking,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            generation_time_ms: r.generation_time_ms,
            tokens_per_second: r.tokens_per_second,
            // The tool-aware path reports its cause in the rich vocabulary.
            stop_reason: match r.stop_reason.as_str() {
                "max_tokens" => StopReason::Length,
                "stop_sequence" => StopReason::StopSequence,
                _ => StopReason::Eos,
            },
            commitment: r.commitment,
            // The tool- and media-aware path does not reuse a cached prefix.
            cached_tokens: 0,
            forward_positions: None,
            denoise_steps: None,
            // The calls are carried alongside, in the shape the caller asked for.
            tool_calls: Vec::new(),
        },
        tool_calls: openai_tool_calls(&calls),
    })
}

/// The runtime's calls in the OpenAI response shape.
pub fn openai_tool_calls(calls: &[ToolCall]) -> Vec<OpenAIToolCall> {
    calls
        .iter()
        .map(|c| OpenAIToolCall {
            id: c.id.clone(),
            kind: "function".to_string(),
            function: OpenAIFunctionCall {
                name: c.name.clone(),
                arguments: serde_json::to_string(&c.input).unwrap_or_else(|_| "{}".to_string()),
            },
        })
        .collect()
}

/// Streaming deltas for a finished set of calls: one delta per call, each
/// carrying its `index`, id, name and the complete arguments string. OpenAI
/// clients accumulate `arguments` by index, so a single delta per call is a
/// valid stream.
pub fn streamed_tool_call_deltas(calls: &[OpenAIToolCall]) -> Vec<Value> {
    calls
        .iter()
        .enumerate()
        .map(|(index, c)| {
            serde_json::json!({
                "index": index,
                "id": c.id,
                "type": "function",
                "function": { "name": c.function.name, "arguments": c.function.arguments },
            })
        })
        .collect()
}

/// Check `value` against the JSON Schema keywords that decide a tool call's
/// shape: `type` (a name or a list of names), `enum`, `const`, `required`,
/// `properties`, `additionalProperties: false`, `items`, `minItems`/`maxItems`,
/// and `anyOf`/`oneOf`. Returns the JSON path of the first violation.
///
/// Keywords outside this set are not checked. They constrain values rather
/// than structure (`pattern`, `format`, numeric bounds), and a validator that
/// half-implements them would claim a guarantee it does not give.
pub fn validate_schema(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let Some(schema) = schema.as_object() else {
        // `true` / an empty schema accepts anything; `false` accepts nothing.
        return match schema {
            Value::Bool(false) => Err(path.to_string()),
            _ => Ok(()),
        };
    };
    if let Some(ty) = schema.get("type") {
        let names: Vec<&str> = match ty {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !names.is_empty() && !names.iter().any(|n| type_matches(n, value)) {
            return Err(path.to_string());
        }
    }
    if let Some(Value::Array(allowed)) = schema.get("enum")
        && !allowed.contains(value)
    {
        return Err(path.to_string());
    }
    if let Some(c) = schema.get("const")
        && c != value
    {
        return Err(path.to_string());
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = schema.get(key) {
            let passing = branches
                .iter()
                .filter(|b| validate_schema(b, value, path).is_ok())
                .count();
            let ok = if key == "anyOf" {
                passing >= 1
            } else {
                passing == 1
            };
            if !ok {
                return Err(path.to_string());
            }
        }
    }
    if let Some(obj) = value.as_object() {
        if let Some(Value::Array(required)) = schema.get("required") {
            for r in required.iter().filter_map(Value::as_str) {
                if !obj.contains_key(r) {
                    return Err(format!("{path}.{r}"));
                }
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(sub) => validate_schema(sub, v, &format!("{path}.{k}"))?,
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => return Err(format!("{path}.{k}")),
                    Some(sub @ Value::Object(_)) => {
                        validate_schema(sub, v, &format!("{path}.{k}"))?
                    }
                    _ => {}
                },
            }
        }
    }
    if let Some(arr) = value.as_array() {
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
            && (arr.len() as u64) < min
        {
            return Err(path.to_string());
        }
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
            && (arr.len() as u64) > max
        {
            return Err(path.to_string());
        }
        if let Some(items) = schema.get("items") {
            for (i, v) in arr.iter().enumerate() {
                validate_schema(items, v, &format!("{path}[{i}]"))?;
            }
        }
    }
    Ok(())
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn weather_tool(strict: bool) -> OpenAITool {
        serde_json::from_value(json!({
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Weather for a city",
                "strict": strict,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                        "unit": {"type": "string", "enum": ["c", "f"]}
                    },
                    "required": ["city"],
                    "additionalProperties": false
                }
            }
        }))
        .unwrap()
    }

    fn call(name: &str, input: Value) -> ToolCall {
        ToolCall {
            id: "call_1".into(),
            name: name.into(),
            input,
        }
    }

    #[test]
    fn standard_agent_history_deserializes_with_its_tool_fields() {
        // The exact shape the OpenAI SDK sends back after a tool round-trip.
        let history: Vec<OpenAIChatMessage> = serde_json::from_value(json!([
            {"role": "user", "content": "weather in Paris?"},
            {"role": "assistant", "content": null, "tool_calls": [
                {"id": "call_abc", "type": "function",
                 "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}
            ]},
            {"role": "tool", "tool_call_id": "call_abc", "content": "18C"}
        ]))
        .unwrap();
        assert_eq!(history.len(), 3);
        let assistant = history[1].to_model();
        assert_eq!(assistant.content, "");
        let calls = assistant.tool_calls.unwrap();
        assert_eq!(calls[0]["function"]["name"], "get_weather");
        // Arguments reach the template as an object, not a string.
        assert_eq!(calls[0]["function"]["arguments"]["city"], "Paris");
        let tool = history[2].to_model();
        assert_eq!(tool.role, "tool");
        assert_eq!(tool.tool_call_id.as_deref(), Some("call_abc"));
        assert_eq!(tool.content, "18C");
    }

    #[test]
    fn tool_history_round_trips_to_the_same_wire_shape() {
        let wire = json!({"role": "assistant", "content": null, "tool_calls": [
            {"id": "call_abc", "type": "function",
             "function": {"name": "f", "arguments": "{}"}}
        ]});
        let m: OpenAIChatMessage = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&m).unwrap(), wire);
    }

    #[test]
    fn no_tools_or_choice_none_is_a_plain_chat() {
        assert!(ToolPlan::from_request(None, None).unwrap().is_none());
        let tools = [weather_tool(false)];
        assert!(
            ToolPlan::from_request(Some(&tools), Some(&json!("none")))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn required_without_tools_is_refused() {
        let err = ToolPlan::from_request(None, Some(&json!("required"))).unwrap_err();
        assert_eq!(err.code, "invalid_tool_choice");
    }

    #[test]
    fn bad_declarations_are_refused_by_name() {
        let mut t = weather_tool(false);
        t.kind = "code_interpreter".into();
        assert_eq!(
            ToolPlan::from_request(Some(&[t]), None).unwrap_err().code,
            "unsupported_tool_type"
        );
        let mut t = weather_tool(false);
        t.function.name = "has space".into();
        assert_eq!(
            ToolPlan::from_request(Some(&[t]), None).unwrap_err().code,
            "invalid_tool_name"
        );
        let t = weather_tool(false);
        assert_eq!(
            ToolPlan::from_request(Some(&[t.clone(), t]), None)
                .unwrap_err()
                .code,
            "duplicate_tool_name"
        );
        let mut t = weather_tool(false);
        t.function.parameters = Some(json!("not a schema"));
        assert_eq!(
            ToolPlan::from_request(Some(&[t]), None).unwrap_err().code,
            "invalid_tool_parameters"
        );
    }

    #[test]
    fn named_choice_offers_only_that_function_and_must_be_called() {
        let mut other = weather_tool(false);
        other.function.name = "get_time".into();
        let tools = [weather_tool(false), other];
        let plan = ToolPlan::from_request(
            Some(&tools),
            Some(&json!({"type": "function", "function": {"name": "get_time"}})),
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.definitions.len(), 1);
        assert_eq!(plan.definitions[0].name, "get_time");
        assert!(plan.check_calls(&[call("get_time", json!({}))]).is_ok());
        assert_eq!(
            plan.check_calls(&[]).unwrap_err().code,
            "tool_choice_unsatisfied"
        );
        let missing = ToolPlan::from_request(
            Some(&tools),
            Some(&json!({"type": "function", "function": {"name": "nope"}})),
        )
        .unwrap_err();
        assert_eq!(missing.code, "invalid_tool_choice");
    }

    #[test]
    fn required_with_no_call_is_an_error_not_a_plain_answer() {
        let tools = [weather_tool(false)];
        let plan = ToolPlan::from_request(Some(&tools), Some(&json!("required")))
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.check_calls(&[]).unwrap_err().code,
            "tool_choice_unsatisfied"
        );
    }

    #[test]
    fn a_call_to_an_undeclared_function_is_refused() {
        let tools = [weather_tool(false)];
        let plan = ToolPlan::from_request(Some(&tools), None).unwrap().unwrap();
        assert_eq!(
            plan.check_calls(&[call("rm_rf", json!({}))])
                .unwrap_err()
                .code,
            "undeclared_tool_call"
        );
    }

    #[test]
    fn strict_arguments_are_held_to_the_schema() {
        let tools = [weather_tool(true)];
        let plan = ToolPlan::from_request(Some(&tools), None).unwrap().unwrap();
        assert!(
            plan.check_calls(&[call("get_weather", json!({"city": "Paris", "unit": "c"}))])
                .is_ok()
        );
        for bad in [
            json!({}),
            json!({"city": 7}),
            json!({"city": "Paris", "unit": "kelvin"}),
            json!({"city": "Paris", "extra": true}),
        ] {
            assert_eq!(
                plan.check_calls(&[call("get_weather", bad.clone())])
                    .unwrap_err()
                    .code,
                "tool_arguments_invalid",
                "{bad}"
            );
        }
        // Non-strict functions are passed through as the model wrote them.
        let lax = ToolPlan::from_request(Some(&[weather_tool(false)]), None)
            .unwrap()
            .unwrap();
        assert!(lax.check_calls(&[call("get_weather", json!({}))]).is_ok());
    }

    #[test]
    fn parallel_off_returns_at_most_one_call() {
        let tools = [weather_tool(false)];
        let mut plan = ToolPlan::from_request(Some(&tools), None).unwrap().unwrap();
        let two = vec![
            call("get_weather", json!({"city": "Paris"})),
            call("get_weather", json!({"city": "Rome"})),
        ];
        assert_eq!(plan.take_calls(two.clone()).unwrap().len(), 2);
        plan.parallel = false;
        let one = plan.take_calls(two).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].input["city"], "Paris");
    }

    #[test]
    fn response_calls_carry_arguments_as_a_json_string() {
        let out = openai_tool_calls(&[call("get_weather", json!({"city": "Paris"}))]);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v[0]["type"], "function");
        assert_eq!(v[0]["function"]["arguments"], "{\"city\":\"Paris\"}");
        let deltas = streamed_tool_call_deltas(&out);
        assert_eq!(deltas[0]["index"], 0);
        assert_eq!(deltas[0]["function"]["name"], "get_weather");
    }

    #[test]
    fn schema_validator_handles_nested_and_union_types() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
                "mode": {"anyOf": [{"const": "a"}, {"type": "null"}]}
            },
            "required": ["items"]
        });
        assert!(validate_schema(&schema, &json!({"items": [1, 2], "mode": null}), "$").is_ok());
        assert_eq!(
            validate_schema(&schema, &json!({"items": [1, "x"]}), "$").unwrap_err(),
            "$.items[1]"
        );
        assert!(validate_schema(&schema, &json!({"items": []}), "$").is_err());
        assert!(validate_schema(&schema, &json!({"items": [1], "mode": "b"}), "$").is_err());
    }
}
