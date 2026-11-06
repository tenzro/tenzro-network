//! JSON-RPC for attestation-bound key release (see
//! `tenzro_vm::native::key_release`).
//!
//! - `tenzro_registerKeyRelease` and `tenzro_revokeKeyRelease` take a
//!   `KeyRelease` transaction signed by the account that owns (or will own)
//!   the model's policy; see `handle_signed_submission` in `rpc.rs`.
//! - `tenzro_requestKeyRelease` is how an operator's attested environment
//!   asks the provider's node for a model's key. Its proof is the evidence
//!   itself: the operator's admitted TPM quotes the release binding, and the
//!   rest of the environment must verify against the model's policy and the
//!   governed GPU values. The provider's node, which must own the policy,
//!   then records the release on chain from its own account, which pays.
//! - `tenzro_getKeyRelease` reads a model's policy and releases. Given the
//!   environment's request, once its release is on chain, it also returns
//!   the content key sealed to the environment's release key, opened for
//!   that one sealing by the provider's hardware.

use std::sync::Arc;

use serde_json::Value;
use tenzro_tee::key_release::{
    ContentKeyHolder, ContentKeyRoot, HardwareContentKeys, ReleaseContext, verify_release,
};
use tenzro_types::key_release::{KeyReleaseOp, ReleaseRequest};
use tenzro_vm::native::key_release::{
    GAS_KEY_RELEASE, authorize, gpu_governance, read_event_by_binding, read_model,
};

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, chain_state};

/// Directory under the data directory holding this provider's wrapped
/// content keys, one `WrappedContentKey` JSON file per model.
pub const WRAPPED_KEYS_DIR: &str = "key-release";

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32001,
        message: message.into(),
        data: None,
    }
}

fn object(params: Option<Value>) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| invalid("Missing params"))?;
    Ok(match p {
        Value::Array(mut a) if !a.is_empty() => a.swap_remove(0),
        p => p,
    })
}

fn release_request(params: &Value) -> Result<ReleaseRequest, JsonRpcError> {
    serde_json::from_value(
        params
            .get("request")
            .cloned()
            .ok_or_else(|| invalid("Missing 'request': the environment's ReleaseRequest"))?,
    )
    .map_err(|e| invalid(format!("invalid release request: {e}")))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// `tenzro_requestKeyRelease { request }`: verify the environment's evidence
/// and record the release from this node's account, which must own the
/// model's policy. Returns the binding to collect the key under with
/// `tenzro_getKeyRelease`.
pub(crate) async fn handle_request_key_release(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params)?;
    let request = release_request(&params)?;
    let op = KeyReleaseOp::Release {
        request: request.clone(),
    };
    op.validate().map_err(invalid)?;
    let submitter = node.ledger_submitter().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "this node has no account to record releases from".into(),
        data: None,
    })?;
    let owner = submitter.address();
    let state = chain_state(node)?;
    let model = read_model(&state, &request.model_id).ok_or_else(|| {
        refused(format!(
            "{} has no key-release policy; its key is never released",
            request.model_id
        ))
    })?;
    if model.owner != hex::encode(owner.as_bytes()) {
        return Err(refused(format!(
            "this node does not own {}'s key-release policy",
            request.model_id
        )));
    }
    // The operator's proof: its admitted TPM quoted this binding, and the
    // environment verifies against the policy and the governed GPU values.
    let admitted =
        tenzro_vm::native::funding::machine_attestation(&state, &request.evidence.operator_did)
            .map_err(refused)?;
    let (roots, references) = gpu_governance(&state).map_err(refused)?;
    let verified = verify_release(
        &request,
        &model.policy,
        &ReleaseContext {
            admitted: &admitted.evidence,
            gpu_roots: &roots,
            gpu_references: &references,
            now: (now_ms().max(0) / 1000) as u64,
        },
    )
    .map_err(|e| refused(format!("key release refused: {e}")))?;
    // Everything the chain will check, checked now.
    authorize(&state, owner.as_bytes(), now_ms(), &op)
        .map_err(|e| refused(format!("key release refused: {e}")))?;
    let submitted = crate::rpc::submit_as_validator(
        node,
        tenzro_types::transaction::TransactionType::KeyRelease { op },
        GAS_KEY_RELEASE * 2,
    )
    .await?;
    Ok(serde_json::json!({
        "status": "submitted",
        "model_id": request.model_id,
        "binding": hex::encode(verified.binding),
        "tx_hash": submitted.get("tx_hash").cloned().unwrap_or(Value::Null),
    }))
}

/// This node's content keys: wrapped to its TPM or Secure Enclave, kept in
/// [`WRAPPED_KEYS_DIR`].
fn machine_content_keys(node: &TenzroNode) -> Result<HardwareContentKeys, JsonRpcError> {
    let mut keys = HardwareContentKeys::new(ContentKeyRoot::Machine);
    keys.load_dir(&node.config().data_dir.join(WRAPPED_KEYS_DIR))
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("reading wrapped content keys: {e}"),
            data: None,
        })?;
    Ok(keys)
}

/// `tenzro_getKeyRelease { model_id, request? }`: the model's policy, owner,
/// release count and revocation. With the environment's `request`, its
/// recorded release, and once recorded, the content key sealed to its
/// release key under the binding.
pub(crate) async fn handle_get_key_release(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object(params)?;
    let state = chain_state(node)?;
    let request = match params.get("request") {
        Some(_) => Some(release_request(&params)?),
        None => None,
    };
    let model_id = match (&request, params.get("model_id").and_then(Value::as_str)) {
        (Some(r), _) => r.model_id.clone(),
        (None, Some(m)) => m.to_string(),
        (None, None) => return Err(invalid("Missing 'model_id' or 'request'")),
    };
    let Some(model) = read_model(&state, &model_id) else {
        return Ok(serde_json::json!({ "model_id": model_id, "registered": false }));
    };
    let mut out = serde_json::json!({
        "model_id": model_id,
        "registered": true,
        "owner": model.owner,
        "policy": model.policy,
        "releases": model.releases,
        "revoked_at_ms": model.revoked_at_ms,
    });
    let Some(request) = request else {
        return Ok(out);
    };
    let binding = hex::encode(request.binding());
    let Some(event) = read_event_by_binding(&state, &model_id, &binding) else {
        out["recorded"] = Value::Bool(false);
        return Ok(out);
    };
    if event.release_key != hex::encode(request.release_key.fingerprint()) {
        return Err(refused("the recorded release names another release key"));
    }
    out["recorded"] = Value::Bool(true);
    out["event"] = serde_json::to_value(&event).unwrap_or(Value::Null);
    // Sealing is this provider's alone: only the policy's owner holds the
    // wrapped key, and only its hardware opens it.
    let owns = node
        .ledger_submitter()
        .is_some_and(|s| hex::encode(s.address().as_bytes()) == model.owner);
    if owns {
        let holder = machine_content_keys(node)?;
        let key = holder
            .content_key(&model_id)
            .map_err(|e| refused(format!("opening the content key: {e}")))?;
        let sealed =
            tenzro_crypto::hybrid_seal::seal(&request.release_key, &request.binding(), &key[..])
                .map_err(|e| refused(format!("sealing the content key: {e}")))?;
        out["sealed"] = serde_json::to_value(&sealed).unwrap_or(Value::Null);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_read_from_its_params() {
        assert!(release_request(&serde_json::json!({})).is_err());
        assert!(release_request(&serde_json::json!({ "request": { "model_id": 1 } })).is_err());
        assert!(object(None).is_err());
        assert_eq!(
            object(Some(serde_json::json!([{ "a": 1 }]))).unwrap(),
            serde_json::json!({ "a": 1 })
        );
    }
}
