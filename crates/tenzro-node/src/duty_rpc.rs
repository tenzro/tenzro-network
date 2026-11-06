//! Reads of network duties and checks of evidence against chain state.
//!
//! - `tenzro_getDuty { duty_id }`: one duty: the work, its reward and vault,
//!   who funded it, and whether it is open, paid or expired.
//! - `tenzro_listDuties {}`: every open duty, oldest first, for anyone who
//!   wants to do the work.
//! - `tenzro_verifyEvidence { items }`: what each evidence item proves
//!   against chain state, for applications that pay on delivery.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn chain(node: &Arc<TenzroNode>) -> Result<tenzro_vm::StateAdapter, JsonRpcError> {
    crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "this node holds no chain state".into(),
        data: None,
    })
}

/// `tenzro_getDuty { duty_id }`.
pub(crate) async fn handle_get_duty(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let id: [u8; 32] = params
        .get("duty_id")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("duty_id must be 32 bytes of hex"))?;
    let state = chain(node)?;
    Ok(tenzro_vm::native::duty::read_duty(&state, &id)
        .map(|d| json!(d))
        .unwrap_or(Value::Null))
}

/// `tenzro_listDuties`: every open duty, oldest first.
pub(crate) async fn handle_list_duties(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let state = chain(node)?;
    let duties: Vec<_> = tenzro_vm::native::duty::open_duties(&state)
        .iter()
        .filter_map(|id| tenzro_vm::native::duty::read_duty(&state, id))
        .collect();
    Ok(json!({ "count": duties.len(), "duties": duties }))
}

/// `tenzro_verifyEvidence { items }`: each item checked against chain state.
/// An item state does not support is answered as an error naming why.
pub(crate) async fn handle_verify_evidence(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let items: Vec<tenzro_types::evidence::Evidence> = params
        .get("items")
        .cloned()
        .ok_or_else(|| bad("Missing 'items'"))
        .and_then(|v| serde_json::from_value(v).map_err(|e| bad(format!("items: {e}"))))?;
    let state = chain(node)?;
    let checked = tenzro_vm::native::check_evidence(&state, &items).map_err(|e| JsonRpcError {
        code: -32000,
        message: e.to_string(),
        data: None,
    })?;
    Ok(json!({ "items": checked }))
}
