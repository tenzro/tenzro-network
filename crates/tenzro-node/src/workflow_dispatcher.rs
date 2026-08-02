//! Bridge between [`crate::workflow_executor::StepDispatcher`] and
//! the node's existing RPC handlers.
//!
//! The executor crate can stay decoupled from the substantial RPC
//! handler module by holding only an `Arc<dyn StepDispatcher>`. This
//! struct is that implementation — it constructs the JSON params each
//! handler expects and forwards through, mapping errors back into
//! `ExecutorError`.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::json;

use crate::TenzroNode;
use crate::workflow_executor::{ExecutorError, StepDispatcher};

pub struct NodeStepDispatcher {
    node: Arc<TenzroNode>,
}

impl NodeStepDispatcher {
    pub fn new(node: Arc<TenzroNode>) -> Arc<Self> {
        Arc::new(Self { node })
    }
}

fn extract_output(result: serde_json::Value) -> serde_json::Value {
    // RPC handlers wrap their payload in `{ "output": ..., ... }` for
    // tool / knowledge invocations. Surface `output` when present so
    // downstream step inputs reference the payload directly via
    // `{{ steps.NAME.output.X }}`.
    if let Some(out) = result.get("output").cloned() {
        return out;
    }
    result
}

/// Strip a Markdown code fence, which models commonly wrap a JSON reply in
/// even when asked for bare JSON.
fn unfence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    // Drop the language tag that may follow the opening fence.
    let rest = match rest.find('\n') {
        Some(i) => &rest[i + 1..],
        None => rest,
    };
    rest.strip_suffix("```").unwrap_or(rest).trim()
}

/// Reduce a chat response to the step output later steps reference.
///
/// A step's output is the assistant's text. When a step prompt asks for
/// JSON so a later step can read individual fields, the parsed object is
/// surfaced instead, making `{{ steps.NAME.output.FIELD }}` resolvable.
/// Text that is not JSON is surfaced as-is.
fn model_step_output(result: serde_json::Value) -> serde_json::Value {
    let text = result
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<String>()
        })
        .unwrap_or_default();
    if text.trim().is_empty() {
        return result;
    }
    match serde_json::from_str::<serde_json::Value>(unfence(&text)) {
        Ok(parsed) if parsed.is_object() || parsed.is_array() => parsed,
        _ => serde_json::Value::String(text),
    }
}

#[async_trait::async_trait]
impl StepDispatcher for NodeStepDispatcher {
    async fn dispatch_tool(
        &self,
        tool_id: &str,
        tool_name: &str,
        params: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError> {
        let mut p = json!({
            "tool_id": tool_id,
            "tool_name": tool_name,
            "params": params,
        });
        if let Some(w) = payer_wallet
            && let serde_json::Value::Object(obj) = &mut p
        {
            obj.insert("payer_wallet".to_string(), json!(w));
        }
        let result = crate::rpc::handle_use_tool_external(&self.node, p, api_key)
            .await
            .map_err(|e| ExecutorError::Dispatch(format!("use_tool: {}", e)))?;
        Ok(extract_output(result))
    }

    async fn dispatch_knowledge(
        &self,
        knowledge_id: &str,
        params: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError> {
        let mut p = json!({
            "knowledge_id": knowledge_id,
            "params": params,
        });
        if let Some(w) = payer_wallet
            && let serde_json::Value::Object(obj) = &mut p
        {
            obj.insert("payer_wallet".to_string(), json!(w));
        }
        let result = crate::rpc::handle_use_knowledge_external(&self.node, p, api_key)
            .await
            .map_err(|e| ExecutorError::Dispatch(format!("use_knowledge: {}", e)))?;
        Ok(extract_output(result))
    }

    async fn dispatch_model(
        &self,
        model_id: &str,
        params: serde_json::Value,
        _api_key: Option<&str>,
        _payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError> {
        // Text embedding takes text and returns vectors rather than
        // turns, and serves from its own runtime. A step carrying
        // `input` / `inputs` without a `prompt` is that request.
        if params.get("prompt").is_none()
            && let Some(text) = params.get("input").or_else(|| params.get("inputs"))
        {
            let inputs = match text {
                serde_json::Value::Array(items) => items.clone(),
                other => vec![serde_json::Value::String(match other.as_str() {
                    Some(s) => s.to_string(),
                    None => serde_json::to_string(other).unwrap_or_default(),
                })],
            };
            let mut p = json!({ "model_id": model_id, "inputs": inputs });
            if let serde_json::Value::Object(obj) = &mut p {
                for key in ["requested_dim", "normalize"] {
                    if let Some(v) = params.get(key) {
                        obj.insert(key.to_string(), v.clone());
                    }
                }
            }
            let result = crate::rpc::handle_text_embed(&self.node, Some(p))
                .await
                .map_err(|e| ExecutorError::Dispatch(format!("text_embed: {}", e.message)))?;
            return Ok(result);
        }

        // Models route through `tenzro_chat`. Build a chat envelope
        // around the step's free-form params: when params carry a
        // `prompt` field, use it directly; otherwise serialize the
        // whole object into a single user-turn message.
        let prompt = if let Some(p) = params.get("prompt").and_then(|v| v.as_str()) {
            p.to_string()
        } else {
            serde_json::to_string(&params).unwrap_or_default()
        };
        let chat_params = json!({
            "model": model_id,
            "messages": [
                { "role": "user", "content": prompt }
            ]
        });
        let result = crate::rpc::handle_chat_external(&self.node, chat_params)
            .await
            .map_err(|e| ExecutorError::Dispatch(format!("chat: {}", e)))?;
        Ok(model_step_output(result))
    }

    async fn dispatch_spawn_agent(
        &self,
        parent_did: &str,
        agent_template_id: &str,
        tnzo_budget: u128,
        valid_until: Option<i64>,
        scope_overrides: serde_json::Value,
        _api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError> {
        let display_name = scope_overrides
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Workflow Child Agent")
            .to_string();
        let mut p = json!({
            "parent_did": parent_did,
            "display_name": display_name,
            "tnzo_budget": tnzo_budget.to_string(),
            "agent_template_id": agent_template_id,
        });
        if let serde_json::Value::Object(obj) = &mut p {
            if let Some(w) = payer_wallet {
                obj.insert("parent_wallet".to_string(), json!(w));
            }
            if let Some(t) = valid_until {
                obj.insert("valid_until".to_string(), json!(t));
            }
            if let Some(m) = scope_overrides.get("max_per_transaction") {
                obj.insert("max_per_transaction".to_string(), m.clone());
            }
            if let Some(m) = scope_overrides.get("max_daily_spend") {
                obj.insert("max_daily_spend".to_string(), m.clone());
            }
        }
        let result = crate::rpc::handle_spawn_child_agent_external(&self.node, p)
            .await
            .map_err(|e| ExecutorError::Dispatch(format!("spawn_child_agent: {}", e)))?;
        Ok(result)
    }

    async fn mirror_to_canton(
        &self,
        workflow_id: &str,
        template_id: &str,
        outputs: &BTreeMap<String, serde_json::Value>,
    ) -> Result<(), ExecutorError> {
        // Real Canton mirror: when the node has a Canton adapter and
        // it's enabled in config, submit a `Tenzro.Workflow:Receipt`
        // create command marking the saga's completion on Canton.
        //
        // Sagas are not canton-scoped RPCs — there is no presenting API
        // key to read a target network from — so the mirror always
        // anchors to the operator's default network, and reads that
        // network's `workflow_receipt_template` override.
        //
        // When Canton is not enabled on this node, mirror is a no-op
        // (the operator chose not to anchor to Canton). The execution
        // result is unaffected — saga completion is already durable in
        // CF_SETTLEMENTS.
        if !self.node.config().canton.enabled {
            tracing::debug!(
                workflow_id = %workflow_id,
                "Canton mirror skipped — Canton not enabled on this node"
            );
            return Ok(());
        }
        let mirror_net = self.node.config().canton.default_network;
        let adapter = match self.node.canton_adapter(mirror_net) {
            Some(a) => a,
            None => {
                tracing::debug!(
                    workflow_id = %workflow_id,
                    canton_network = %mirror_net,
                    "Canton mirror skipped — adapter not initialized"
                );
                return Ok(());
            }
        };

        let mirrored_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let create_arguments = serde_json::json!({
            "workflowId": workflow_id,
            "templateId": template_id,
            "stepOutputs": outputs,
            "mirroredAt": mirrored_at,
        });

        // The receipt template id can be operator-configured per network;
        // default to the canonical Tenzro workflow receipt template.
        // Format is `#<package-name>:<Module>:<Template>` so the
        // participant resolves the latest installed version of the
        // package.
        let template_id_canton = self
            .node
            .config()
            .canton
            .network(mirror_net)
            .and_then(|n| n.workflow_receipt_template.as_deref())
            .unwrap_or("#tenzro-workflow:Tenzro.Workflow:Receipt");

        match adapter
            .submit_create_command(template_id_canton, create_arguments)
            .await
        {
            Ok(receipt) => {
                tracing::info!(
                    workflow_id = %workflow_id,
                    template_id = %template_id,
                    "Workflow mirrored to Canton: {}",
                    receipt
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    "Canton mirror submission failed (non-fatal): {}",
                    e
                );
                // Mirror failure is non-fatal because the run is
                // already complete on-protocol. We surface as an
                // event for operator observability but don't roll
                // the workflow back.
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chat_reply(text: &str) -> serde_json::Value {
        json!({
            "content": [{ "type": "text", "text": text }],
            "model": "qwen3-8b"
        })
    }

    #[test]
    fn unfence_strips_fence_and_language_tag() {
        assert_eq!(unfence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(unfence("```\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(unfence("  {\"a\":1}  "), "{\"a\":1}");
    }

    #[test]
    fn model_step_output_parses_fenced_json_object() {
        let out = model_step_output(chat_reply(
            "```json\n{\"recommendation\":\"buy\",\"size\":\"10\"}\n```",
        ));
        assert_eq!(out, json!({ "recommendation": "buy", "size": "10" }));
    }

    #[test]
    fn model_step_output_surfaces_plain_text_as_string() {
        let out = model_step_output(chat_reply("hold, the spread is too wide"));
        assert_eq!(out, json!("hold, the spread is too wide"));
    }

    #[test]
    fn model_step_output_falls_back_to_whole_envelope() {
        let envelope = json!({ "embedding": [0.1, 0.2], "model": "qwen3-embedding-0.6b" });
        assert_eq!(model_step_output(envelope.clone()), envelope);
    }
}
