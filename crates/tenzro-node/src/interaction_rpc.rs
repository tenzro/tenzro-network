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

// ---------------------------------------------------------------------------
// tenzro_mirrorSettlement
// ---------------------------------------------------------------------------

/// Params for `tenzro_mirrorSettlement`.
#[derive(Debug, Deserialize)]
pub struct MirrorSettlementRequest {
    /// The interaction to mirror. Must already be anchored.
    pub interaction_id: String,
    /// Chains to mirror onto, as CAIP-2 ids or adapter chain names.
    pub targets: Vec<MirrorTargetSpec>,
    /// Whether the primary settlement committed. Durability requires both a
    /// committed primary and a confirmed self-contained mirror.
    #[serde(default = "default_true")]
    pub primary_committed: bool,
}

fn default_true() -> bool {
    true
}

/// One requested target.
#[derive(Debug, Deserialize)]
pub struct MirrorTargetSpec {
    /// CAIP-2 id or adapter chain name.
    pub chain: String,
    /// `true` writes the canonical settlement bytes, so the record stays
    /// readable with no Tenzro node — the only form that survives a testnet
    /// reset or a mainnet cutover. `false` writes the digest alone.
    #[serde(default = "default_true")]
    pub self_contained: bool,
}

/// `tenzro_mirrorSettlement` — record an anchored settlement on other chains.
///
/// Admin-gated: mirroring spends gas on every target and writes this node's
/// attestation onto public chains. An open endpoint would let anyone drain the
/// operator's bridge balances and publish records in their name.
///
/// Each target is dispatched independently. There is no two-phase commit across
/// chains that do not know about each other, so a failure on one is reported
/// rather than rolling back one that already landed — partial success is the
/// normal case.
pub(crate) async fn handle_mirror_settlement(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_payments::settlement_mirror::{MirrorPlan, MirrorTarget};

    let req: MirrorSettlementRequest = crate::passkey_rpc::parse_params(params)?;

    let store = storage(node)?;
    let raw = store
        .get(CF_SETTLEMENTS, &interaction_key(&req.interaction_id))
        .map_err(|e| internal("read interaction", e))?
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message: format!(
                "No interaction anchored under `{}`. Anchor it before mirroring: a mirror of a \
                 record this node never attested is a claim it cannot stand behind.",
                req.interaction_id
            ),
            data: None,
        })?;
    let mut record: InteractionProvenance =
        serde_json::from_slice(&raw).map_err(|e| internal("decode interaction", e))?;

    let targets: Vec<MirrorTarget> = req
        .targets
        .iter()
        .map(|t| {
            if t.self_contained {
                MirrorTarget::self_contained(t.chain.clone())
            } else {
                MirrorTarget::digest_only(t.chain.clone())
            }
        })
        .collect();

    // Every chain the registered adapters can reach, so a plan is validated
    // against what this node can actually write to rather than against the
    // smaller set of networks it settles on natively.
    let reachable = reachable_chains(node).await;
    let plan = MirrorPlan::new(targets, &reachable).map_err(|e| invalid(e.to_string()))?;

    let report = crate::settlement_mirror_dispatch::mirror_and_record(
        node,
        &mut record,
        &plan,
        req.primary_committed,
    )
    .await;

    // Persist the record with its confirmed secondaries folded in.
    store
        .put(
            CF_SETTLEMENTS,
            &interaction_key(&record.interaction_id),
            &serde_json::to_vec(&record).map_err(|e| internal("encode interaction", e))?,
        )
        .map_err(|e| internal("persist interaction", e))?;

    Ok(serde_json::json!({
        "interaction_id": record.interaction_id,
        "attestation_digest": record.attestation_digest_hex(),
        "primary_committed": report.primary_committed,
        "fully_mirrored": report.fully_mirrored(),
        // The question the whole feature exists to answer: does this record
        // survive the Tenzro Ledger losing state?
        "durable_beyond_primary": report.is_durable_beyond_primary(),
        "outcomes": report.outcomes.iter().map(|o| serde_json::json!({
            "chain": o.target.caip2,
            "durability": o.target.durability.as_str(),
            "state": o.state.as_str(),
            "reference": match &o.state {
                tenzro_payments::settlement_mirror::MirrorState::Confirmed { reference, .. } => {
                    Some(reference.clone())
                }
                _ => None,
            },
            "reason": match &o.state {
                tenzro_payments::settlement_mirror::MirrorState::Failed { reason } => {
                    Some(reason.clone())
                }
                _ => None,
            },
        })).collect::<Vec<_>>(),
        "secondary_settlements": record.secondary_settlements,
    }))
}

/// Every chain this node can write to: the networks it settles on natively,
/// plus every chain the registered bridge adapters reach.
async fn reachable_chains(node: &Arc<TenzroNode>) -> Vec<String> {
    let mut out: Vec<String> = tenzro_types::settlement_network::SETTLEMENT_NETWORKS
        .iter()
        .map(|n| n.caip2.to_string())
        .collect();
    if let Some(router) = node.bridge_router() {
        for coverage in router.list_chains().await {
            let chain = coverage.chain.chain_id;
            // Record both forms: adapters route on names, plans are usually
            // written in CAIP-2, and a caller should not have to know which
            // this node happens to hold.
            if let Some(caip2) = tenzro_types::settlement_network::caip2_for_chain_name(&chain) {
                out.push(caip2.to_string());
            }
            out.push(chain);
        }
    }
    out.sort();
    out.dedup();
    out
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
