//! Thin JSON-RPC client over `reqwest` for the Tenzro node's registry methods.
//!
//! This module wraps the 17 existing `tenzro_*` registry RPCs that the node
//! already exposes (`tenzro-node/src/rpc.rs`). It is the **only** place in
//! `tenzro-agent-kit` that speaks JSON-RPC to the local node — every other
//! module composes this client.
//!
//! ## Design
//!
//! - One `reqwest::Client` per `RegistryClient` instance (cheap to clone, the
//!   underlying connection pool is shared).
//! - Every method maps 1:1 to a `tenzro_*` RPC method on the node.
//! - All responses are deserialized straight into the strongly-typed
//!   `tenzro-types` structs (`AgentTemplate`, `ToolDefinition`,
//!   `SkillDefinition`) so callers never touch raw JSON.
//! - Errors are funneled through [`AgentKitError`] so callers can match on
//!   transport vs RPC vs deserialization failures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use tenzro_types::agent_template::{AgentTemplate, AgentTemplateFilter};
use tenzro_types::skill::{SkillDefinition, SkillFilter};
use tenzro_types::tool::{ToolDefinition, ToolFilter};

use crate::error::AgentKitError;

/// JSON-RPC 2.0 envelope.
#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

/// JSON-RPC client over the local Tenzro node's HTTP endpoint.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    rpc_url: Arc<String>,
    http: Client,
    next_id: Arc<AtomicU64>,
}

impl RegistryClient {
    /// Constructs a new client targeting `rpc_url` (e.g. `http://127.0.0.1:8545`).
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client builder failed");
        Self {
            rpc_url: Arc::new(rpc_url.into()),
            http,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Returns the configured RPC endpoint.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Public low-level JSON-RPC call that returns the raw
    /// [`serde_json::Value`] result. Used by the executor for dispatch
    /// methods that don't have a typed wrapper (e.g. `tenzro_bridgeTokens`,
    /// `tenzro_payMpp`, `tenzro_payX402`, `tenzro_submitDamlCommand`).
    pub async fn call_raw(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, AgentKitError> {
        self.call(method, params).await
    }

    /// Low-level call: sends a JSON-RPC request and decodes the result into `T`.
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, AgentKitError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        tracing::debug!(target: "tenzro_agent_kit::registry", method, "rpc call");

        let resp = self
            .http
            .post(self.rpc_url.as_str())
            .json(&req)
            .send()
            .await
            .map_err(AgentKitError::from)?;

        let status = resp.status();
        let body = resp.text().await.map_err(AgentKitError::from)?;

        if !status.is_success() {
            return Err(AgentKitError::RpcTransport(format!(
                "http {} from {}: {}",
                status, self.rpc_url, body
            )));
        }

        let envelope: JsonRpcResponse = serde_json::from_str(&body)
            .map_err(|e| AgentKitError::RpcDeserialize(format!("envelope: {e}; body: {body}")))?;

        // Validate JSON-RPC 2.0 envelope per §5: `jsonrpc` MUST be "2.0",
        // `id` MUST match the request id (servers may omit when echoing
        // notifications, but for our request/response calls it is required).
        if let Some(jr) = envelope.jsonrpc.as_deref()
            && jr != "2.0"
        {
            return Err(AgentKitError::RpcDeserialize(format!(
                "envelope jsonrpc field is '{jr}', expected '2.0'"
            )));
        }
        if let Some(resp_id) = envelope.id
            && resp_id != id
        {
            tracing::warn!(
                target: "tenzro_agent_kit::registry",
                request_id = id, response_id = resp_id,
                "rpc id mismatch — server echoed unexpected id"
            );
        }

        if let Some(err) = envelope.error {
            return Err(AgentKitError::RpcError {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }

        let result = envelope.result.ok_or_else(|| {
            AgentKitError::RpcDeserialize("rpc response missing both result and error".into())
        })?;

        serde_json::from_value::<T>(result).map_err(|e| {
            AgentKitError::RpcDeserialize(format!("result decode for {method}: {e}"))
        })
    }

    // ────────────────────────────────────────────────────────────────────────
    // Agent template registry
    // ────────────────────────────────────────────────────────────────────────

    /// Lists agent templates from `CF_AGENT_TEMPLATES`, optionally filtered.
    pub async fn list_templates(
        &self,
        filter: Option<AgentTemplateFilter>,
    ) -> Result<Vec<AgentTemplate>, AgentKitError> {
        let params = match filter {
            Some(f) => {
                let mut obj = serde_json::Map::new();
                if let Some(limit) = f.limit {
                    obj.insert("limit".to_string(), json!(limit));
                }
                if let Some(tag) = f.tag {
                    obj.insert("tag".to_string(), json!(tag));
                }
                if let Some(creator) = f.creator {
                    obj.insert("creator".to_string(), json!(creator));
                }
                if f.free_only.unwrap_or(false) {
                    obj.insert("free_only".to_string(), json!(true));
                }
                Value::Object(obj)
            }
            None => json!({}),
        };
        self.call("tenzro_listAgentTemplates", params).await
    }

    /// Fetches a single template by id.
    pub async fn get_template(&self, template_id: &str) -> Result<AgentTemplate, AgentKitError> {
        let result: Option<AgentTemplate> = self
            .call("tenzro_getAgentTemplate", json!({ "template_id": template_id }))
            .await?;
        result.ok_or_else(|| AgentKitError::TemplateNotFound(template_id.to_string()))
    }

    /// Publishes a new agent template to `CF_AGENT_TEMPLATES`. Returns the
    /// minted `template_id`.
    pub async fn register_template(&self, template: &AgentTemplate) -> Result<String, AgentKitError> {
        let mut params = serde_json::Map::new();
        params.insert("name".to_string(), json!(template.name));
        params.insert("description".to_string(), json!(template.description));
        params.insert("system_prompt".to_string(), json!(template.system_prompt));
        params.insert("creator".to_string(), json!(template.creator));
        params.insert(
            "template_type".to_string(),
            json!(serde_json::to_string(&template.template_type)
                .unwrap_or_else(|_| "\"autonomous\"".to_string())
                .trim_matches('"')
                .to_string()),
        );
        params.insert("tags".to_string(), json!(template.tags));
        if let Some(docs_url) = &template.docs_url {
            params.insert("docs_url".to_string(), json!(docs_url));
        }
        if let Some(ref hash) = template.content_hash
            && !hash.is_empty()
        {
            params.insert("content_hash".to_string(), json!(hash));
        }
        if let Some(spec) = &template.execution_spec {
            params.insert("execution_spec".to_string(), serde_json::to_value(spec)?);
        }
        if !template.version.is_empty() {
            params.insert("version".to_string(), json!(template.version));
        }

        let result: Value = self
            .call("tenzro_registerAgentTemplate", Value::Object(params))
            .await?;

        // Try several common shapes used by Tenzro RPC handlers.
        if let Some(id) = result.get("template_id").and_then(|v| v.as_str()) {
            return Ok(id.to_string());
        }
        if let Some(id) = result.get("id").and_then(|v| v.as_str()) {
            return Ok(id.to_string());
        }
        if let Some(id) = result.as_str() {
            return Ok(id.to_string());
        }
        Err(AgentKitError::RpcDeserialize(format!(
            "register_template: unexpected response shape: {result}"
        )))
    }

    // ────────────────────────────────────────────────────────────────────────
    // Tool registry
    // ────────────────────────────────────────────────────────────────────────

    /// Searches tools by query string (matches against name/description/capabilities).
    pub async fn search_tools(
        &self,
        filter: ToolFilter,
    ) -> Result<Vec<ToolDefinition>, AgentKitError> {
        let mut obj = serde_json::Map::new();
        if let Some(q) = filter.query {
            obj.insert("query".to_string(), json!(q));
        }
        if let Some(tt) = filter.tool_type {
            obj.insert("tool_type".to_string(), json!(tt));
        }
        if let Some(cat) = filter.category {
            obj.insert("category".to_string(), json!(cat));
        }
        if let Some(creator) = filter.creator_did {
            obj.insert("creator_did".to_string(), json!(creator));
        }
        if let Some(status) = filter.status {
            obj.insert("status".to_string(), json!(status));
        }
        if let Some(limit) = filter.limit {
            obj.insert("limit".to_string(), json!(limit));
        }
        if let Some(offset) = filter.offset {
            obj.insert("offset".to_string(), json!(offset));
        }
        self.call("tenzro_searchTools", Value::Object(obj)).await
    }

    /// Lists all tools (no filtering).
    pub async fn list_tools(&self) -> Result<Vec<ToolDefinition>, AgentKitError> {
        self.call("tenzro_listTools", json!({})).await
    }

    /// Invokes a registered tool by id with the given JSON params.
    pub async fn use_tool(
        &self,
        tool_id: &str,
        tool_name: Option<&str>,
        params: Value,
    ) -> Result<Value, AgentKitError> {
        let mut req = serde_json::Map::new();
        req.insert("tool_id".to_string(), json!(tool_id));
        if let Some(name) = tool_name {
            req.insert("tool_name".to_string(), json!(name));
        }
        req.insert("params".to_string(), params);
        self.call("tenzro_useTool", Value::Object(req)).await
    }

    // ────────────────────────────────────────────────────────────────────────
    // Skill registry
    // ────────────────────────────────────────────────────────────────────────

    /// Searches skills by query string.
    pub async fn search_skills(
        &self,
        filter: SkillFilter,
    ) -> Result<Vec<SkillDefinition>, AgentKitError> {
        let mut obj = serde_json::Map::new();
        if let Some(q) = filter.query {
            obj.insert("query".to_string(), json!(q));
        }
        if let Some(tag) = filter.tag {
            obj.insert("tag".to_string(), json!(tag));
        }
        if let Some(creator) = filter.creator_did {
            obj.insert("creator_did".to_string(), json!(creator));
        }
        if let Some(cap) = filter.capability {
            obj.insert("capability".to_string(), json!(cap));
        }
        if let Some(max_price) = filter.max_price {
            obj.insert("max_price".to_string(), json!(max_price.to_string()));
        }
        if let Some(active) = filter.active_only {
            obj.insert("active_only".to_string(), json!(active));
        }
        if let Some(limit) = filter.limit {
            obj.insert("limit".to_string(), json!(limit));
        }
        if let Some(offset) = filter.offset {
            obj.insert("offset".to_string(), json!(offset));
        }
        self.call("tenzro_searchSkills", Value::Object(obj)).await
    }

    /// Lists all skills (no filtering).
    pub async fn list_skills(&self) -> Result<Vec<SkillDefinition>, AgentKitError> {
        self.call("tenzro_listSkills", json!({})).await
    }

    /// Invokes a registered skill by id with the given input JSON.
    pub async fn use_skill(
        &self,
        skill_id: &str,
        input: Value,
    ) -> Result<Value, AgentKitError> {
        self.call(
            "tenzro_useSkill",
            json!({ "skill_id": skill_id, "input": input }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_client_construction() {
        let client = RegistryClient::new("http://127.0.0.1:8545");
        assert_eq!(client.rpc_url(), "http://127.0.0.1:8545");
    }

    #[test]
    fn registry_client_clone_shares_id_counter() {
        let a = RegistryClient::new("http://127.0.0.1:8545");
        let b = a.clone();
        let id1 = a.next_id.fetch_add(1, Ordering::Relaxed);
        let id2 = b.next_id.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id1, id2);
    }
}
