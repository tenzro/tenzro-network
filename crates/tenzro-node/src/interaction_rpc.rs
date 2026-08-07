//! Recording and verifying interactions on the Tenzro Ledger.
//!
//! `InteractionProvenance` was a designed accounting record with **no endpoint
//! at all** — the type existed, nothing could reach it. These handlers are that
//! surface, and they are the reason Tenzro can be the accounting layer for
//! access rather than only the payment layer.
//!
//! # The gap this closes
//!
//! An edge gateway can meter a request and charge for it. What it cannot do is
//! answer, afterwards and to somebody who trusts neither party, *which* party
//! consumed *what*, under *whose* authority, and whether the payment that
//! cleared corresponds to the work that happened. Cloudflare — shipping exactly
//! that gateway — states the limit plainly: payment proves budget, not trust,
//! and audit trails are the developer's problem.
//!
//! So each side keeps its own log, the logs disagree, and the disagreement is
//! settled by whoever is more trusted rather than by evidence. Anchoring the
//! record's digest on the ledger replaces that with arithmetic: a counterparty
//! recomputes the digest from the record it was shown and checks it against
//! what was anchored.
//!
//! # One record for every kind of interaction
//!
//! A fetch, an inference, a storage read and a marketplace invocation are the
//! same shape — a party consumed a resource under an authority and a charge
//! landed somewhere. They share one record and one digest, so an audit is a
//! lookup rather than a reconciliation across per-surface logs.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::provenance::InteractionProvenance;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Keyspace for anchored interaction records.
const INTERACTION_PREFIX: &str = "interaction:";

fn interaction_key(id: &str) -> Vec<u8> {
    format!("{INTERACTION_PREFIX}{id}").into_bytes()
}

fn storage(node: &Arc<TenzroNode>) -> Result<Arc<dyn KvStore>, JsonRpcError> {
    node.storage()
        .map(|s| s.clone() as Arc<dyn KvStore>)
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "Storage not initialized".to_string(),
            data: None,
        })
}

fn internal(what: &str, e: impl std::fmt::Display) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: format!("{what}: {e}"),
        data: None,
    }
}

fn invalid(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

// ---------------------------------------------------------------------------
// tenzro_recordInteraction
// ---------------------------------------------------------------------------

/// Params for `tenzro_recordInteraction`.
#[derive(Debug, Deserialize)]
pub struct RecordInteractionRequest {
    /// The full provenance record being anchored.
    pub interaction: InteractionProvenance,
}

/// Result of anchoring a record.
#[derive(Debug, Serialize)]
pub struct RecordInteractionResponse {
    /// Joins to the usage record and the settlement receipt.
    pub interaction_id: String,
    /// Content address a counterparty recomputes to check the record.
    pub attestation_digest: String,
    /// Whether a charge was actually taken.
    pub billed: bool,
    /// Whether this replaced an existing anchor for the same id.
    pub replaced: bool,
}

/// `tenzro_recordInteraction` — anchor an interaction record.
///
/// Admin-gated: the node is the **attester**, and an endpoint that let any
/// caller anchor a record naming this node as attester would let anyone forge
/// receipts in the operator's name. That is the whole value of the record, so
/// it is the one thing that must not be open.
///
/// Re-anchoring the same `interaction_id` is permitted and reported, because a
/// record legitimately gains fields as a charge moves from accrued to settled.
/// The digest changes when it does, which is correct: the earlier digest
/// attested an earlier state, and both remain checkable against whatever was
/// anchored at the time.
pub(crate) async fn handle_record_interaction(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RecordInteractionRequest = crate::passkey_rpc::parse_params(params)?;
    let record = req.interaction;

    record
        .validate_attestable()
        .map_err(|e| invalid(e.to_string()))?;

    let store = storage(node)?;
    let key = interaction_key(&record.interaction_id);
    let replaced = store
        .get(CF_SETTLEMENTS, &key)
        .map_err(|e| internal("read interaction", e))?
        .is_some();

    store
        .put(
            CF_SETTLEMENTS,
            &key,
            &serde_json::to_vec(&record).map_err(|e| internal("encode interaction", e))?,
        )
        .map_err(|e| internal("persist interaction", e))?;

    serde_json::to_value(RecordInteractionResponse {
        interaction_id: record.interaction_id.clone(),
        attestation_digest: record.attestation_digest_hex(),
        billed: record.is_billed(),
        replaced,
    })
    .map_err(|e| internal("encode response", e))
}

// ---------------------------------------------------------------------------
// tenzro_getInteraction
// ---------------------------------------------------------------------------

/// Params for `tenzro_getInteraction`.
#[derive(Debug, Deserialize)]
pub struct GetInteractionRequest {
    /// The interaction to read.
    pub interaction_id: String,
}

/// `tenzro_getInteraction` — read an anchored record and its digest.
///
/// Open. A receipt nobody but the issuer can read is not a receipt: the payer,
/// the payee and any auditor either party shows it to all need the same view,
/// and the record carries digests rather than credentials precisely so it can
/// be shown.
pub(crate) async fn handle_get_interaction(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetInteractionRequest = crate::passkey_rpc::parse_params(params)?;
    let store = storage(node)?;

    let raw = store
        .get(CF_SETTLEMENTS, &interaction_key(&req.interaction_id))
        .map_err(|e| internal("read interaction", e))?
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message: format!("No interaction anchored under `{}`", req.interaction_id),
            data: None,
        })?;

    let record: InteractionProvenance =
        serde_json::from_slice(&raw).map_err(|e| internal("decode interaction", e))?;

    Ok(serde_json::json!({
        "interaction": record,
        "attestation_digest": record.attestation_digest_hex(),
        "billed": record.is_billed(),
    }))
}

// ---------------------------------------------------------------------------
// tenzro_verifyInteraction
// ---------------------------------------------------------------------------

/// Params for `tenzro_verifyInteraction`.
#[derive(Debug, Deserialize)]
pub struct VerifyInteractionRequest {
    /// The record as the caller received it.
    pub interaction: InteractionProvenance,
}

/// `tenzro_verifyInteraction` — check a record against what was anchored.
///
/// Open, and the point of the whole module. A counterparty submits the record
/// it was handed; the node recomputes the digest from the submitted fields and
/// compares it to the digest of what it anchored under that id. A record that
/// was altered after issue produces a different digest and is reported as a
/// mismatch, with both digests returned so the caller can see it rather than
/// take the node's word.
///
/// Verification is deliberately **not** a signature check against the node's
/// key. It compares content addresses, so the answer does not depend on
/// trusting the verifying node — a caller can recompute the same digest itself
/// from the same published rule and reach the same conclusion offline.
pub(crate) async fn handle_verify_interaction(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: VerifyInteractionRequest = crate::passkey_rpc::parse_params(params)?;
    let submitted = req.interaction;
    let submitted_digest = submitted.attestation_digest_hex();

    let store = storage(node)?;
    let raw = store
        .get(CF_SETTLEMENTS, &interaction_key(&submitted.interaction_id))
        .map_err(|e| internal("read interaction", e))?;

    let Some(raw) = raw else {
        return Ok(serde_json::json!({
            "verified": false,
            "reason": "not_anchored",
            "detail": format!(
                "No interaction is anchored under `{}` on this node. An unanchored record is \
                 not a forged one — it may have been anchored elsewhere.",
                submitted.interaction_id
            ),
            "submitted_digest": submitted_digest,
        }));
    };

    let anchored: InteractionProvenance =
        serde_json::from_slice(&raw).map_err(|e| internal("decode interaction", e))?;
    let anchored_digest = anchored.attestation_digest_hex();
    let verified = anchored_digest == submitted_digest;

    Ok(serde_json::json!({
        "verified": verified,
        "reason": if verified { "match" } else { "digest_mismatch" },
        "submitted_digest": submitted_digest,
        "anchored_digest": anchored_digest,
        "interaction_id": submitted.interaction_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_and_prefixed() {
        assert_ne!(interaction_key("a"), interaction_key("b"));
        assert!(
            String::from_utf8(interaction_key("a"))
                .unwrap()
                .starts_with(INTERACTION_PREFIX)
        );
    }

    #[test]
    fn requests_deserialize_from_a_bare_object() {
        // The wire shape every surface sends; a one-element array is rejected.
        let r: GetInteractionRequest =
            serde_json::from_value(serde_json::json!({"interaction_id": "int-1"})).unwrap();
        assert_eq!(r.interaction_id, "int-1");
        assert!(
            serde_json::from_value::<GetInteractionRequest>(
                serde_json::json!([{"interaction_id": "int-1"}])
            )
            .is_err()
        );
    }

    #[test]
    fn a_missing_params_value_is_invalid_params_not_a_panic() {
        let e = crate::passkey_rpc::parse_params::<GetInteractionRequest>(None).unwrap_err();
        assert_eq!(e.code, -32602);
    }
}
