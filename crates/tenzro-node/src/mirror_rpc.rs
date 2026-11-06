//! `tenzro_mirrorSettlement`: record a settlement on other chains.
//!
//! The caller hands over the interaction record of the settlement it wants
//! mirrored. Each target is written independently; the response carries the
//! record with its confirmed secondary settlements folded in, so the caller
//! holds the updated record. The node keeps no copy.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tenzro_types::provenance::InteractionProvenance;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn invalid(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

// ---------------------------------------------------------------------------
// tenzro_mirrorSettlement
// ---------------------------------------------------------------------------

/// Params for `tenzro_mirrorSettlement`.
#[derive(Debug, Deserialize)]
pub struct MirrorSettlementRequest {
    /// The interaction record of the settlement to mirror.
    pub interaction: InteractionProvenance,
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

/// `tenzro_mirrorSettlement` — record a settlement on other chains.
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

    let mut record = req.interaction;
    record
        .validate_attestable()
        .map_err(|e| invalid(e.to_string()))?;

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

    // Every chain a governed route serves, so a plan is validated
    // against what this node can actually write to rather than against the
    // smaller set of networks it settles on natively.
    let reachable = reachable_chains(node).await;
    let plan = MirrorPlan::new(targets, &reachable).map_err(|e| invalid(e.to_string()))?;

    let dispatch = crate::settlement_mirror_dispatch::mirror_and_record(
        &mut record,
        &plan,
        req.primary_committed,
    );
    let report = &dispatch.report;

    Ok(serde_json::json!({
        "interaction": record,
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
        // Sign each in hardware and submit it with `tenzro_sendRawTransaction`.
        "transactions": dispatch.transactions.iter().map(|(chain, tx_type)| serde_json::json!({
            "chain": chain,
            "tx_type": tx_type,
        })).collect::<Vec<_>>(),
    }))
}

/// Every chain this node can write to: the networks it settles on natively,
/// plus every chain a governed bridge route serves.
async fn reachable_chains(node: &Arc<TenzroNode>) -> Vec<String> {
    let chain_id = node.chain_id();
    let mut out: Vec<String> = tenzro_types::settlement_network::settlement_networks(chain_id)
        .into_iter()
        .map(|n| n.caip2.into_owned())
        .collect();
    if let Ok(state) = crate::bridge_routes::NodeRouteState::open(node) {
        for route in state.list() {
            let chain = route.source_chain;
            // Record both forms: routes are keyed by name, plans are usually
            // written in CAIP-2, and a caller should not have to know which
            // this node happens to hold.
            if let Some(caip2) =
                tenzro_types::settlement_network::caip2_for_chain_name(&chain, chain_id)
            {
                out.push(caip2.into_owned());
            }
            out.push(chain);
        }
    }
    out.sort();
    out.dedup();
    out
}
