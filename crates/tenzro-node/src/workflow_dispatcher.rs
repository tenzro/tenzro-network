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

use crate::workflow_executor::{ExecutorError, StepDispatcher};
use crate::TenzroNode;

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
        if let Some(w) = payer_wallet {
            if let serde_json::Value::Object(obj) = &mut p {
                obj.insert("payer_wallet".to_string(), json!(w));
            }
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
        if let Some(w) = payer_wallet {
            if let serde_json::Value::Object(obj) = &mut p {
                obj.insert("payer_wallet".to_string(), json!(w));
            }
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
        Ok(result)
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
        // Canton mirror is best-effort: we emit a structured event the
        // operator's Canton DAML mirror can subscribe to. The actual
        // DAML create lands when the operator's existing
        // `tenzro_mirrorWorkflowToCanton` flow ships in the Canton
        // agentic wave.
        let payload = serde_json::json!({
            "workflow_id": workflow_id,
            "template_id": template_id,
            "step_outputs": outputs,
            "mirrored_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
        tracing::info!(
            workflow_id = %workflow_id,
            template_id = %template_id,
            "Workflow completed — canton mirror payload prepared: {}",
            payload
        );
        Ok(())
    }
}
