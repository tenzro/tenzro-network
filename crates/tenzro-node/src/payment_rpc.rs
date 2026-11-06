//! JSON-RPC surface of the payment gateway: checking a credential against
//! the challenge it answers.

use std::sync::Arc;

use serde_json::Value;
use tenzro_payments::types::PaymentCredential;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn invalid(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

pub(crate) fn credential_from(params: Option<Value>) -> Result<PaymentCredential, JsonRpcError> {
    let params = params.ok_or_else(|| invalid("Missing params"))?;
    let params = match params {
        Value::Array(mut a) if !a.is_empty() => a.swap_remove(0),
        other => other,
    };
    let value = params.get("credential").cloned().unwrap_or(params);
    serde_json::from_value(value).map_err(|e| invalid(format!("Invalid payment credential: {e}")))
}

/// `tenzro_verifyPayment`: check a credential against its challenge without
/// settling it. Reports the account the credential would debit and the DID
/// bound to it; never reports success for a credential that would not pay.
pub(crate) async fn verify(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let credential = credential_from(params)?;
    let gateway = node.payment_gateway().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Payment gateway not initialized".to_string(),
        data: None,
    })?;
    match gateway.preflight(&credential).await {
        Ok(v) => {
            let (leg, payer) = match &v.leg {
                tenzro_payments::SettlementLeg::Payer(p) => {
                    ("payer", Some(hex::encode(p.address.as_bytes())))
                }
                tenzro_payments::SettlementLeg::Voucher(voucher) => {
                    ("voucher", Some(hex::encode(voucher.escrow_id)))
                }
                tenzro_payments::SettlementLeg::Foreign => ("foreign", None),
            };
            Ok(serde_json::json!({
                "challenge_id": v.challenge_id,
                "verified": true,
                "amount": v.amount.to_string(),
                "payer_did": v.payer_did,
                "leg": leg,
                "debits": payer,
            }))
        }
        Err(e) => Ok(serde_json::json!({
            "challenge_id": credential.challenge_id,
            "verified": false,
            "reason": e.to_string(),
        })),
    }
}

/// How far a signed request's `timestamp_ms` may be from this node's clock.
const REQUEST_SKEW_MS: i64 = 5 * 60 * 1000;

/// Signatures already accepted, with the time they expire from the window.
static SEEN_REQUESTS: std::sync::OnceLock<dashmap::DashMap<Vec<u8>, i64>> =
    std::sync::OnceLock::new();

/// What a signed request is remembered by: its signature, whatever form it
/// takes (a hex string, or the composite signature object clients send), as
/// its canonical JSON. `None` when there is none.
fn replay_key(params: &Value) -> Option<Vec<u8>> {
    let sig = params.get("signature")?;
    match sig {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        v => Some(serde_json::to_vec(v).ok()?),
    }
}

/// Require that `owner` signed this exact request, once.
///
/// The signature covers `method`, `canonical` and the request's
/// `timestamp_ms`, which must be within five minutes of now; a signature is
/// accepted once within that window, so a captured request cannot be replayed
/// to move the owner's funds again.
pub(crate) fn require_signed_owner_request(
    node: &crate::node::TenzroNode,
    params: &Value,
    owner: &tenzro_types::primitives::Address,
    method: &str,
    canonical: &[u8],
) -> Result<(), JsonRpcError> {
    let timestamp_ms = params
        .get("timestamp_ms")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| invalid("Missing timestamp_ms: this request must be signed by its owner"))?;
    let now = chrono::Utc::now().timestamp_millis();
    if (now - timestamp_ms).abs() > REQUEST_SKEW_MS {
        return Err(JsonRpcError {
            code: -32001,
            message: "signed request timestamp is outside the five-minute window".to_string(),
            data: None,
        });
    }
    let mut signed = canonical.to_vec();
    signed.extend_from_slice(&timestamp_ms.to_le_bytes());
    crate::rpc::require_address_owner(node, params, owner, method, &signed)?;

    let sig = replay_key(params).ok_or_else(|| invalid("Missing signature"))?;
    let seen = SEEN_REQUESTS.get_or_init(dashmap::DashMap::new);
    seen.retain(|_, expires| *expires > now);
    match seen.entry(sig) {
        dashmap::mapref::entry::Entry::Occupied(_) => Err(JsonRpcError {
            code: -32001,
            message: "signed request already used".to_string(),
            data: None,
        }),
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(timestamp_ms + REQUEST_SKEW_MS);
            Ok(())
        }
    }
}

#[cfg(test)]
mod replay_key_tests {
    use super::replay_key;
    use serde_json::json;

    /// Two requests carrying different composite signatures are remembered
    /// apart; the same one twice is the same entry; none is refused.
    #[test]
    fn each_signed_request_is_remembered_by_its_own_signature() {
        let a = json!({ "signature": { "classical": { "Raw": "aa" }, "pq": null } });
        let b = json!({ "signature": { "classical": { "Raw": "bb" }, "pq": null } });
        assert_ne!(replay_key(&a), replay_key(&b));
        assert_eq!(replay_key(&a), replay_key(&a.clone()));
        assert_ne!(
            replay_key(&json!({ "signature": "aa" })),
            replay_key(&json!({ "signature": "bb" }))
        );
        assert_eq!(replay_key(&json!({})), None);
        assert_eq!(replay_key(&json!({ "signature": "" })), None);
    }
}
