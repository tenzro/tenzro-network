//! Read RPCs over the token ledger's rule engine.
//!
//! Every write to a token (issuer powers, policy, claims, holder transfers)
//! is a signed `Token` transaction executed by the VM; nothing here writes.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, chain_state};

fn bad(message: String) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message,
        data: None,
    }
}

fn hex_param(p: &Value, key: &str) -> Result<Vec<u8>, JsonRpcError> {
    let raw = p
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad(format!("Missing {key}")))?;
    hex::decode(raw.trim_start_matches("0x")).map_err(|_| bad(format!("{key} is not hex")))
}

/// `tenzro_canTransfer { token_id, from, to, amount }` — whether the
/// token's rules allow the holder transfer now, with the refusal code and
/// reason when they do not. The same engine every view of the token runs.
pub(crate) fn handle_can_transfer(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params
        .map(|p| match p {
            Value::Array(mut a) if !a.is_empty() => a.remove(0),
            other => other,
        })
        .unwrap_or(Value::Null);
    let token: [u8; 32] = hex_param(&p, "token_id")?
        .try_into()
        .map_err(|_| bad("token_id is 32 bytes".to_string()))?;
    let from = hex_param(&p, "from")?;
    let to = hex_param(&p, "to")?;
    let amount: u128 = p
        .get("amount")
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .ok_or_else(|| bad("Missing amount".to_string()))?
        .parse()
        .map_err(|_| bad("amount is a decimal integer".to_string()))?;
    let chain = chain_state(node)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let verdict = tenzro_vm::token_ledger::can_transfer(
        &mut tenzro_vm::token_ledger::StateView(&chain),
        &token,
        &from,
        &to,
        amount,
        now_ms,
    )
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
    })?;
    Ok(match verdict {
        Ok(()) => json!({ "allowed": true }),
        Err(r) => json!({ "allowed": false, "code": r.code(), "reason": r.to_string() }),
    })
}
