//! The compact tool listing, served at `/mcp/compact`, for agents that look
//! up the tools they need instead of loading every definition up front. It
//! lists two tools:
//!
//! - `search` finds tools by words in their name, description or JSON-RPC
//!   method and returns each match with its exact input and output schema,
//!   as `tools/list` on `/mcp` states them.
//! - `call` invokes one tool by name. Its arguments are checked against that
//!   tool's input schema first; the call then takes the same path as calling
//!   the tool directly on `/mcp`: the caller's own credentials, the agent's
//!   terms and pinned tools, spend limits, receipts and the audit log.
//!
//! Nothing here runs code on the node. `/mcp` keeps the full listing.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::ErrorData;
use rmcp::model::{CallToolRequestParams, ErrorCode, JsonObject, Tool, ToolAnnotations};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The tool that finds tools.
pub(super) const SEARCH: &str = "search";
/// The tool that calls one.
pub(super) const CALL: &str = "call";

const DEFAULT_MATCHES: usize = 10;
const MAX_MATCHES: usize = 50;

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchParams {
    #[schemars(
        description = "Words to find in a tool's name, description or JSON-RPC method, e.g. \"list providers\" or \"escrow release\"; every word must appear"
    )]
    pub query: String,
    #[schemars(
        description = "true: only tools that change nothing; false: only tools that may change state"
    )]
    pub read_only: Option<bool>,
    #[schemars(description = "Most matches to return (default 10, at most 50)")]
    pub limit: Option<u32>,
}

/// One tool `search` found.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolMatch {
    /// The name to pass to `call`.
    pub name: String,
    pub description: String,
    /// Whether the tool only reads.
    pub read_only: bool,
    /// The JSON-RPC method the tool forwards its `params` to, for a tool
    /// that mirrors one method.
    pub method: Option<String>,
    /// The tool's input schema (JSON Schema), exactly as `/mcp` lists it.
    pub input_schema: JsonObject,
    /// The tool's output schema (JSON Schema), exactly as `/mcp` lists it.
    pub output_schema: Option<JsonObject>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SearchOutput {
    pub matches: Vec<ToolMatch>,
    /// How many tools matched before `limit` cut the list.
    pub total: u32,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CallParams {
    #[schemars(description = "The tool's name, as search returns it")]
    pub name: String,
    #[schemars(description = "The tool's arguments, matching the input schema search returns")]
    pub arguments: Option<JsonObject>,
}

/// The compact listing.
pub(super) fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            SEARCH,
            "Find this node's tools (wallet, identity, payments, models, inference, storage, bridge, governance and more) by words in their name, description or JSON-RPC method. Returns each match with its exact input and output schema; pass its name to call.",
            Arc::new(JsonObject::new()),
        )
        .with_input_schema::<SearchParams>()
        .with_output_schema::<SearchOutput>()
        .with_annotations(ToolAnnotations::new().read_only(true)),
        Tool::new(
            CALL,
            "Call one of this node's tools by name with arguments matching its input schema. The result is that tool's own result; credentials, agent terms, spend limits, receipts and audit apply exactly as when the tool is called directly.",
            Arc::new(JsonObject::new()),
        )
        .with_input_schema::<CallParams>()
        .with_annotations(ToolAnnotations::new().read_only(false)),
    ]
}

/// The tools in `all` matching `params`, best first: a tool scores by how
/// many query words its name holds, then by name.
pub(super) fn search(all: Vec<Tool>, params: SearchParams) -> SearchOutput {
    let words: Vec<String> = params
        .query
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let method_of = |name: &str| {
        super::rpc_tools::RPC_TOOLS
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.method)
    };
    let mut found: Vec<(usize, ToolMatch)> = all
        .into_iter()
        .filter_map(|tool| {
            let name = tool.name.to_string();
            let description = tool.description.as_deref().unwrap_or("").to_string();
            let method = method_of(&name);
            let read_only = tool
                .annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
                .unwrap_or(false);
            if params.read_only.is_some_and(|r| r != read_only) {
                return None;
            }
            let name_text = name.replace('_', " ");
            let haystack = format!(
                "{name_text} {name} {} {}",
                description.to_lowercase(),
                method.unwrap_or("").to_lowercase()
            );
            if !words.iter().all(|w| haystack.contains(w.as_str())) {
                return None;
            }
            let score = words
                .iter()
                .filter(|w| name_text.contains(w.as_str()))
                .count();
            Some((
                score,
                ToolMatch {
                    name,
                    description,
                    read_only,
                    method: method.map(str::to_string),
                    input_schema: (*tool.input_schema).clone(),
                    output_schema: tool.output_schema.as_deref().cloned(),
                },
            ))
        })
        .collect();
    found.sort_by(|(sa, a), (sb, b)| sb.cmp(sa).then_with(|| a.name.cmp(&b.name)));
    let total = found.len() as u32;
    let limit = params
        .limit
        .map_or(DEFAULT_MATCHES, |l| (l as usize).clamp(1, MAX_MATCHES));
    SearchOutput {
        matches: found.into_iter().take(limit).map(|(_, m)| m).collect(),
        total,
    }
}

fn refused(message: String, data: Value) -> ErrorData {
    ErrorData {
        code: ErrorCode::INVALID_PARAMS,
        message: Cow::from(message),
        data: Some(data),
    }
}

/// What in `args` the top level of `schema` refuses: a required argument
/// left out, an argument the schema closes out, or one of the wrong JSON
/// type. Nested values are checked when the tool decodes them.
fn problems(schema: &JsonObject, args: &JsonObject) -> Vec<String> {
    let mut out = Vec::new();
    let props = schema.get("properties").and_then(Value::as_object);
    for key in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if args.get(key).is_none_or(Value::is_null) {
            out.push(format!("`{key}` is required"));
        }
    }
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
    for (key, value) in args {
        let Some(prop) = props.and_then(|p| p.get(key)) else {
            if closed {
                out.push(format!("`{key}` is not an argument of this tool"));
            }
            continue;
        };
        let types: Vec<&str> = match prop.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
            _ => continue,
        };
        let fits = types.iter().any(|t| match *t {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            "null" => value.is_null(),
            _ => true,
        });
        if !fits {
            out.push(format!("`{key}` must be {}", types.join(" or ")));
        }
    }
    out
}

/// Turn a `call` into the call of the tool it names, from `all`, once its
/// arguments pass that tool's input schema. An unknown tool or arguments the
/// schema refuses are invalid params, with the reason in `data`.
pub(super) fn unwrap_call(
    mut request: CallToolRequestParams,
    all: &[Tool],
) -> Result<CallToolRequestParams, ErrorData> {
    let call: CallParams =
        serde_json::from_value(Value::Object(request.arguments.take().unwrap_or_default()))
            .map_err(|e| {
                refused(
                    format!("call takes {{name, arguments}}: {e}"),
                    serde_json::json!({ "reason": "invalid_arguments", "tool": CALL }),
                )
            })?;
    let Some(tool) = all.iter().find(|t| t.name == call.name) else {
        return Err(refused(
            format!("no tool named `{}`; find one with search", call.name),
            serde_json::json!({ "reason": "unknown_tool", "tool": call.name }),
        ));
    };
    let arguments = call.arguments.unwrap_or_default();
    let found = problems(&tool.input_schema, &arguments);
    if !found.is_empty() {
        return Err(refused(
            format!(
                "arguments for `{}` do not match its input schema",
                call.name
            ),
            serde_json::json!({
                "reason": "invalid_arguments",
                "tool": call.name,
                "problems": found,
            }),
        ));
    }
    request.name = Cow::Owned(call.name);
    request.arguments = Some(arguments);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(v: Value) -> JsonObject {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn arguments_are_checked_against_the_top_of_the_schema() {
        let schema = object(serde_json::json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "limit": { "type": ["integer", "null"] }
            },
            "required": ["address"],
            "additionalProperties": false
        }));
        assert!(problems(&schema, &object(serde_json::json!({ "address": "0x01" }))).is_empty());
        let mut found = problems(
            &schema,
            &object(serde_json::json!({ "limit": 1.5, "extra": 1 })),
        );
        found.sort();
        assert_eq!(
            found,
            vec![
                "`address` is required".to_string(),
                "`extra` is not an argument of this tool".to_string(),
                "`limit` must be integer or null".to_string(),
            ]
        );
    }
}
