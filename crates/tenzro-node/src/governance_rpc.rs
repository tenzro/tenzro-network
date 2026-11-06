//! Read RPCs for governance state kept in consensus: proposals and their
//! tallies, voting weight, guardian seats and the enactment pause, enacted
//! network policy, tranched grants.
//!
//! Every governance action is an ordinary signed transaction, submitted
//! through `tenzro_sendRawTransaction`:
//! `GovernancePropose`, `GovernanceVote`, `GovernanceExecute`,
//! `GovernanceVeto`, and `Funding` (whose gas the treasury pays).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, chain_state};

/// Most proposals one `tenzro_listProposals` call returns.
const MAX_LIST: u64 = 100;

fn params_object(params: &Option<Value>) -> Option<&Value> {
    params.as_ref().map(|p| match p.as_array() {
        Some(a) => a.first().unwrap_or(&Value::Null),
        None => p,
    })
}

fn param<'a>(params: &'a Option<Value>, key: &str) -> Result<&'a str, JsonRpcError> {
    params_object(params)
        .and_then(|p| p.get(key))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("Missing {key}"),
            data: None,
        })
}

fn to_value<T: serde::Serialize>(v: Option<T>) -> Result<Value, JsonRpcError> {
    match v {
        Some(v) => serde_json::to_value(v).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("encode: {e}"),
            data: None,
        }),
        None => Ok(Value::Null),
    }
}

fn proposal_json(
    proposal: &tenzro_vm::governance::Proposal,
    tally: &tenzro_vm::governance::Tally,
    veto_locked: u128,
) -> Value {
    json!({
        "proposal": proposal,
        "kind": proposal.action.kind(),
        "tally": {
            "yes": tally.yes.to_string(),
            "no": tally.no.to_string(),
            "total_eligible": tally.total_eligible.to_string(),
        },
        "veto_locked": veto_locked.to_string(),
    })
}

/// `tenzro_getProposal { proposal_id }` — a governance proposal and its
/// running tally. `null` when there is none.
pub(crate) fn handle_get_proposal(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let id = param(&params, "proposal_id")?;
    let chain = chain_state(node)?;
    Ok(match tenzro_vm::native::read_proposal(&chain, id) {
        Some((proposal, tally)) => {
            let locked = tenzro_vm::native::veto_escrow::locked_total(&chain, &proposal.id);
            proposal_json(&proposal, &tally, locked)
        }
        None => Value::Null,
    })
}

/// `tenzro_listProposals { limit?, before?, kind? }` — proposals newest
/// first. `before` is a 1-based position from a previous page's `next`;
/// `kind` keeps only one action kind (`policy_update`, `treasury_grant`, ...).
pub(crate) fn handle_list_proposals(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params_object(&params);
    let get_u64 = |k: &str| p.and_then(|p| p.get(k)).and_then(|v| v.as_u64());
    let limit = get_u64("limit").unwrap_or(20).clamp(1, MAX_LIST);
    let kind = p.and_then(|p| p.get("kind")).and_then(|v| v.as_str());
    let chain = chain_state(node)?;
    let total = tenzro_vm::native::proposal_count(&chain);
    let mut position = get_u64("before").map_or(total, |b| b.saturating_sub(1).min(total));
    let mut proposals = Vec::new();
    while position > 0 && (proposals.len() as u64) < limit {
        if let Some(id) = tenzro_vm::native::proposal_id_at(&chain, position)
            && let Some((proposal, tally)) = tenzro_vm::native::read_proposal(&chain, &id)
            && kind.is_none_or(|k| proposal.action.kind() == k)
        {
            let locked = tenzro_vm::native::veto_escrow::locked_total(&chain, &proposal.id);
            proposals.push(proposal_json(&proposal, &tally, locked));
        }
        position -= 1;
    }
    Ok(json!({
        "proposals": proposals,
        "total": total,
        "next": if position > 0 { Some(position + 1) } else { None },
    }))
}

/// `tenzro_getVotingPower { address }` — the bonded stake an account votes
/// with, and the network total a tally is measured against.
pub(crate) fn handle_get_voting_power(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let raw = param(&params, "address")?;
    let bytes = hex::decode(raw.trim_start_matches("0x")).map_err(|_| JsonRpcError {
        code: -32602,
        message: "address is not hex".to_string(),
        data: None,
    })?;
    let chain = chain_state(node)?;
    Ok(json!({
        "address": raw,
        "voting_power": tenzro_vm::native::own_bonded_stake_of(&chain, &bytes).to_string(),
        "total_bonded": tenzro_vm::native::governance_total_bonded(&chain).to_string(),
    }))
}

/// `tenzro_getSponsoredBond { address }` — the governance-sponsored part of
/// a validator's stake: bonded, unbonding and when that can return to the
/// treasury, the part it put up itself, and the governed caps with what is
/// out network-wide.
pub(crate) fn handle_get_sponsored_bond(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::sponsored_bond::{MAX_PER_VALIDATOR_PARAM, MAX_TOTAL_PARAM};
    let raw = param(&params, "address")?;
    let bytes = hex::decode(raw.trim_start_matches("0x")).map_err(|_| JsonRpcError {
        code: -32602,
        message: "address is not hex".to_string(),
        data: None,
    })?;
    let chain = chain_state(node)?;
    Ok(json!({
        "address": raw,
        "bonded": tenzro_vm::native::bonded_stake_of(&chain, &bytes).to_string(),
        "own_bonded": tenzro_vm::native::own_bonded_stake_of(&chain, &bytes).to_string(),
        "sponsored_bonded": tenzro_vm::native::sponsored_bond_of(&chain, &bytes).to_string(),
        "sponsored_unbonding": tenzro_vm::native::sponsored_unbonding_of(&chain, &bytes).to_string(),
        "sponsored_outstanding_total": tenzro_vm::native::total_sponsored_outstanding(&chain).to_string(),
        "max_per_validator_tnzo": tenzro_vm::native::network_param(&chain, MAX_PER_VALIDATOR_PARAM),
        "max_total_tnzo": tenzro_vm::native::network_param(&chain, MAX_TOTAL_PARAM),
    }))
}

/// `tenzro_getTreasuryPayouts { address?, offset?, limit? }` — every
/// disbursement of sponsorship and grants, oldest first, each with its
/// recipient, amount, class and the proposal that paid it; the total per
/// class; and the governed caps. With an address, whether it is an approved
/// operator or grantee (with the criteria it was approved on) and the total
/// it has been paid.
pub(crate) fn handle_get_treasury_payouts(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::payout_gates as gates;
    let p = params_object(&params);
    let get_u64 = |k: &str| p.and_then(|p| p.get(k)).and_then(|v| v.as_u64());
    let offset = get_u64("offset").unwrap_or(0);
    let limit = get_u64("limit").unwrap_or(100).clamp(1, MAX_LIST);
    let chain = chain_state(node)?;
    let report = gates::payout_report(&chain, offset, limit);
    let address = match p.and_then(|p| p.get("address")).and_then(|v| v.as_str()) {
        Some(raw) => {
            let bytes = hex::decode(raw.trim_start_matches("0x")).map_err(|_| JsonRpcError {
                code: -32602,
                message: "address is not hex".to_string(),
                data: None,
            })?;
            Some(json!({
                "address": raw,
                "total_received": gates::recipient_total(&chain, &bytes).to_string(),
                "operator": gates::operator_approval(&chain, &bytes),
                "grantee": gates::grantee_approval(&chain, &bytes),
            }))
        }
        None => None,
    };
    let param_of = |key: &str| tenzro_vm::native::network_param(&chain, key);
    Ok(json!({
        "count": report.count,
        "by_class": report.by_class,
        "records": report.records,
        "caps": {
            "sponsorship_yearly_max_tnzo": param_of(gates::SPONSORSHIP_YEARLY_PARAM),
            "running_cost_per_verified_epoch_wei": param_of(gates::PER_VERIFIED_EPOCH_PARAM),
            "per_grantee_yearly_max_tnzo": param_of(gates::GRANTEE_YEARLY_PARAM),
            "combined_yearly_max_tnzo": param_of(gates::COMBINED_YEARLY_PARAM),
        },
        "address": address,
    }))
}

/// `tenzro_getGuardianState { address? }` — every seat, the steward sunset
/// and cap, the steward treasury hold, the enactment pause (until when
/// it holds, and until when a new one is refused), the guardian threshold,
/// and with an address the guardian seat it holds and whether that seat is
/// live now.
pub(crate) fn handle_get_guardian_state(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::guardian;
    let chain = chain_state(node)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let pause = guardian::pause_record(&chain, guardian::PauseScope::Enactment);
    let hold = guardian::pause_record(&chain, guardian::PauseScope::Treasury);
    let seats: Vec<Value> = guardian::seats(&chain)
        .into_iter()
        .map(|(address, seat)| {
            let live = guardian::seat_live(&chain, &seat, now_ms);
            json!({ "address": address, "seat": seat, "active": live })
        })
        .collect();
    let mut out = json!({
        "pause": pause,
        "paused": now_ms < pause.paused_until_ms,
        "treasury_hold": hold,
        "treasury_held": now_ms < hold.paused_until_ms,
        "threshold": guardian::threshold(&chain),
        "steward_sunset_ms": guardian::steward_sunset_ms(&chain),
        "steward_max_seats": guardian::steward_max_seats(&chain),
        "seats": seats,
    });
    if let Ok(raw) = param(&params, "address") {
        let bytes = hex::decode(raw.trim_start_matches("0x")).map_err(|_| JsonRpcError {
            code: -32602,
            message: "address is not hex".to_string(),
            data: None,
        })?;
        let seat = guardian::load_seat(&chain, &bytes);
        out["active"] = json!(
            seat.as_ref()
                .is_some_and(|s| guardian::seat_live(&chain, s, now_ms))
        );
        out["seat"] = to_value(seat)?;
    }
    Ok(out)
}

/// `tenzro_getPolicy { kind }` — the last policy change of `kind` that
/// governance enacted, with the proposal that decided it. `null` while the
/// genesis setting stands.
pub(crate) fn handle_get_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let kind = param(&params, "kind")?;
    let chain = chain_state(node)?;
    to_value(tenzro_vm::native::read_policy(&chain, kind))
}

/// `tenzro_decodeAction { transaction, block? } | { preimage }` — what a
/// transaction does, derived by this node so an approval never shows a front
/// end's own rendering. For a privileged transaction: the typed preimage it
/// is signed over, its digest, and what it does in words, generated from the
/// preimage alone. For any transaction given whole: its `effects`, executed
/// unsigned on a copy of the state after `block` (the head when absent),
/// with a digest a second node reproduces for the same block. Given only
/// preimage bytes (hex) it decodes them.
pub(crate) async fn handle_decode_action(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::typed_action::{action_preimage, decode_preimage, describe, preimage_bytes};
    let bad = |message: String| JsonRpcError {
        code: -32602,
        message,
        data: None,
    };
    let obj = params_object(&params)
        .ok_or_else(|| bad("expected { transaction } or { preimage }".into()))?;
    if let Some(hex_bytes) = obj.get("preimage").and_then(Value::as_str) {
        let bytes =
            hex::decode(hex_bytes.trim_start_matches("0x")).map_err(|e| bad(e.to_string()))?;
        let (preimage, digest) = decode_preimage(&bytes).map_err(bad)?;
        return Ok(json!({
            "class": preimage.class,
            "digest": hex::encode(digest),
            "preimage_hex": hex::encode(preimage_bytes(&preimage)),
            "description": describe(&preimage),
            "preimage": preimage,
        }));
    }
    let tx: tenzro_types::transaction::Transaction = obj
        .get("transaction")
        .cloned()
        .ok_or_else(|| bad("expected { transaction } or { preimage }".into()))
        .and_then(|t| serde_json::from_value(t).map_err(|e| bad(format!("transaction: {e}"))))?;
    let effects = crate::approval_effects::simulate(node, &tx, obj.get("block")).await?;
    Ok(match action_preimage(&tx) {
        Some(p) => {
            let digest = tenzro_types::typed_action::preimage_digest(&p);
            json!({
                "class": p.class,
                "digest": hex::encode(digest),
                "preimage_hex": hex::encode(preimage_bytes(&p)),
                "description": describe(&p),
                "preimage": p,
                "effects": effects,
            })
        }
        // An ordinary transaction is signed over its hash.
        None => json!({
            "class": Value::Null,
            "digest": hex::encode(tx.hash().as_bytes()),
            "effects": effects,
        }),
    })
}

fn code_hash_param(params: &Option<Value>) -> Result<[u8; 32], JsonRpcError> {
    let raw = param(params, "code_hash")?;
    hex::decode(raw.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "code_hash must be 32 bytes of hex".into(),
            data: None,
        })
}

/// `tenzro_getUpgradeReadiness { code_hash }` — which validators' machines
/// have quoted the binary, their share of bonded stake against the share
/// required, the activation consensus scheduled last, and whether this node
/// runs the binary.
pub(crate) fn handle_get_upgrade_readiness(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let code_hash = code_hash_param(&params)?;
    let chain = chain_state(node)?;
    let r = tenzro_vm::native::readiness(&chain, &code_hash);
    let hex_hash = hex::encode(code_hash);
    let runs = node
        .policy_applier()
        .is_some_and(|p| p.runs_binary(&hex_hash));
    Ok(json!({
        "code_hash": hex_hash,
        "ready_stake": r.ready_stake.to_string(),
        "total_bonded": r.total_bonded.to_string(),
        "ready_bps": r.ready_bps(),
        "required_bps": r.required_bps,
        "met": r.met(),
        "signals": r.signals,
        "scheduled": tenzro_vm::native::read_upgrade_activation(&chain),
        "this_node_runs_it": runs,
    }))
}

/// `tenzro_signalUpgradeReady { code_hash }` — hash the binary staged in
/// this node's data directory, and if it is the one named, quote it with this
/// machine's TPM and send `UpgradeReady` from the validator account.
pub(crate) async fn handle_signal_upgrade_ready(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let code_hash = code_hash_param(&params)?;
    let refused = |message: String| JsonRpcError {
        code: -32000,
        message,
        data: None,
    };
    let path = crate::policy_reflection::staged_binary_path(&node.config().data_dir);
    let staged = crate::policy_reflection::binary_hash(&path)
        .map_err(|e| refused(format!("no binary staged at {}: {e}", path.display())))?;
    if staged != code_hash {
        return Err(refused(format!(
            "the staged binary hashes to {}, not {}",
            hex::encode(staged),
            hex::encode(code_hash)
        )));
    }
    let submitter = node
        .ledger_submitter()
        .ok_or_else(|| refused("this node has no validator account to signal from".into()))?;
    let digest =
        tenzro_vm::governance::upgrade_ready_digest(&code_hash, submitter.address().as_bytes());
    let evidence = quote(digest).await.map_err(refused)?;
    let quote = serde_json::to_vec(&evidence).map_err(|e| refused(e.to_string()))?;
    crate::rpc::submit_as_validator(
        node,
        tenzro_types::TransactionType::UpgradeReady {
            code_hash: hex::encode(code_hash),
            quote,
        },
        tenzro_vm::native::upgrade::GAS_UPGRADE_READY * 2,
    )
    .await
}

#[cfg(any(target_os = "linux", windows))]
async fn quote(digest: [u8; 32]) -> Result<tenzro_tee::tpm_attest::TpmEvidence, String> {
    tokio::task::spawn_blocking(move || tenzro_tee::tpm_attest::quote_local_machine(&digest))
        .await
        .map_err(|e| format!("TPM quote task failed: {e}"))?
        .map(|(_, evidence)| evidence)
        .map_err(|e| format!("TPM quote failed: {e}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn quote(_digest: [u8; 32]) -> Result<tenzro_tee::tpm_attest::TpmEvidence, String> {
    Err("readiness is quoted by a Linux TPM 2.0 resource manager (/dev/tpmrm0)".into())
}

/// `tenzro_getGrant { grant_id }` — a tranched grant: recipient, tranches
/// and how many are paid.
pub(crate) fn handle_get_grant(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let id = param(&params, "grant_id")?;
    let chain = chain_state(node)?;
    to_value(tenzro_vm::native::read_grant(&chain, id))
}

/// `tenzro_getTreasuryAccounts {}` — the treasury's keyless accounts on every
/// chain with account code, each with the last remote grant an enacted
/// proposal wrote for it. Bitcoin is listed as moving through the deposit
/// route.
pub(crate) fn handle_get_treasury_accounts(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::treasury_remote::{self, TREASURY_DID};
    let chain = chain_state(node)?;
    let accounts: Vec<Value> = treasury_remote::account_chains(&chain)
        .iter()
        .map(|caip2| match treasury_remote::treasury_account(&chain, caip2) {
            Ok(a) => {
                let grant = tenzro_vm::native::remote_grant::read_grant(&chain, TREASURY_DID, caip2).map(|g| {
                    json!({
                        "seq": g.seq,
                        "payload_hash": hex::encode(g.payload_hash),
                        "amount": g.budget.to_string(),
                        "not_after_ms": g.not_after_ms,
                        "void": g.void,
                    })
                });
                json!({ "caip2": caip2, "address": a.address, "caip10": a.caip10(), "grant": grant })
            }
            Err(e) => json!({ "caip2": caip2, "error": e }),
        })
        .collect();
    Ok(json!({
        "did": TREASURY_DID,
        "tenzro": hex::encode(tenzro_types::fees::network_treasury_address().as_bytes()),
        "accounts": accounts,
        "bitcoin": "deposit route",
    }))
}
