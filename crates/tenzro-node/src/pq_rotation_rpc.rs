//! `tenzro_rotateIdentityToPq`: hand an identity's authority to an ML-DSA-65
//! key while its DID stays the one its hardware key derived.
//!
//! The rotation is checked and applied by
//! [`tenzro_identity::IdentityRegistry::apply_pq_rotation`]; this handler only
//! decodes it.

use std::sync::Arc;

use serde_json::Value;
use tenzro_identity::pq_rotation::{PqKeyBackend, PqRotation};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn hex_field(params: &Value, name: &str) -> Result<Vec<u8>, JsonRpcError> {
    let s = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Missing {name}")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|e| invalid(format!("{name} is not hex: {e}")))
}

/// Decode the RPC form of a rotation: `did`, `new_pq_key`, `backend`
/// (`secure_enclave` / `tpm` / `software`), `sequence`,
/// `authority_signature`, `new_key_signature`, byte fields in hex.
pub(crate) fn parse_rotation(params: &Value) -> Result<PqRotation, JsonRpcError> {
    let backend: PqKeyBackend = serde_json::from_value(
        params
            .get("backend")
            .cloned()
            .ok_or_else(|| invalid("Missing backend"))?,
    )
    .map_err(|e| invalid(format!("backend: {e}")))?;
    Ok(PqRotation {
        did: params
            .get("did")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Missing did"))?
            .to_string(),
        new_pq_key: hex_field(params, "new_pq_key")?,
        backend,
        sequence: params
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("Missing sequence"))?,
        authority_signature: hex_field(params, "authority_signature")?,
        new_key_signature: hex_field(params, "new_key_signature")?,
    })
}

pub(crate) async fn handle_rotate_identity_to_pq(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    };
    let rotation = parse_rotation(&params)?;
    let registry = node.identity_registry().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "identity registry not initialized".to_string(),
        data: None,
    })?;
    let identity = registry
        .apply_pq_rotation(&rotation)
        .map_err(|e| JsonRpcError {
            code: -32003,
            message: e.to_string(),
            data: None,
        })?;
    Ok(serde_json::json!({
        "did": identity.did_string(),
        "sequence": rotation.sequence,
        "backend": rotation.backend.as_str(),
        "hardware_held": rotation.backend != PqKeyBackend::Software,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rotation_decodes_from_its_rpc_form_and_rejects_bad_hex() {
        let good = serde_json::json!({
            "did": "did:tenzro:human:x",
            "new_pq_key": "0xabcd",
            "backend": "secure_enclave",
            "sequence": 1,
            "authority_signature": "01",
            "new_key_signature": "02",
        });
        let r = parse_rotation(&good).unwrap();
        assert_eq!(r.new_pq_key, vec![0xab, 0xcd]);
        assert_eq!(r.backend, PqKeyBackend::SecureEnclave);
        let mut bad = good.clone();
        bad["authority_signature"] = "zz".into();
        assert!(parse_rotation(&bad).is_err());
        let mut unknown = good;
        unknown["backend"] = "enclave-ish".into();
        assert!(parse_rotation(&unknown).is_err());
    }
}
