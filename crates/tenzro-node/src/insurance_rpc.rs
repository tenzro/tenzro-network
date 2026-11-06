//! Reads of the insurance pool and the claims it paid, from chain state.
//!
//! - `tenzro_getInsurancePoolBalance`: the pool vault, its balance, where it
//!   was funded from, and the cap one claim meets.
//! - `tenzro_listInsuranceClaims`, `tenzro_getInsuranceClaim { claim_id }`:
//!   the claims it paid (`PayInsuranceClaim`).

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_vm::traits::VmState;

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

/// The insurance pool read from `state`: its vault, balance, history and
/// the caps a claim meets.
pub(crate) fn insurance_pool_of(state: &dyn VmState) -> Value {
    use tenzro_vm::native::insurance;
    let vault = insurance::pool_address();
    let balance = state.get_balance(vault.as_bytes());
    let totals = insurance::read_totals(state);
    json!({
        "vault": format!("0x{}", hex::encode(vault.as_bytes())),
        "balance_wei": balance.to_string(),
        "claims_paid": totals.claims_paid,
        "total_paid_wei": totals.total_paid.to_string(),
        "from_fees_wei": totals.from_fees.to_string(),
        "from_slashes_wei": totals.from_slashes.to_string(),
        "max_claim_wei": insurance::claim_cap(state, balance).to_string(),
    })
}

/// `tenzro_getInsurancePoolBalance`.
pub(crate) async fn handle_get_insurance_pool(
    node: &Arc<TenzroNode>,
) -> Result<Value, JsonRpcError> {
    Ok(insurance_pool_of(&chain(node)?))
}

/// `tenzro_listInsuranceClaims`: every paid claim, oldest first.
pub(crate) async fn handle_list_insurance_claims(
    node: &Arc<TenzroNode>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::insurance;
    let state = chain(node)?;
    let claims: Vec<_> = insurance::claim_ids(&state)
        .iter()
        .filter_map(|id| insurance::read_claim(&state, id))
        .collect();
    Ok(json!({ "count": claims.len(), "claims": claims }))
}

/// `tenzro_getInsuranceClaim { claim_id }`.
pub(crate) async fn handle_get_insurance_claim(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let id = params
        .get("claim_id")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'claim_id'"))?;
    let state = chain(node)?;
    Ok(
        tenzro_vm::native::insurance::read_claim(&state, id.trim_start_matches("0x"))
            .map(|c| json!(c))
            .unwrap_or(Value::Null),
    )
}
