//! Reads of settlement plans, the split preview and the reconciliation of
//! each route's settlement lock.
//!
//! Plans, decisions and leg receipts are consensus records written by the
//! VM's settlement owner; these handlers only read them. Each answer carries
//! the committed-state key of its record so a caller can fetch a state proof
//! for it with `tenzro_getStateProof`. Opening a plan and proving a leg are
//! signed `SettlementPlan` transactions, submitted like any other.

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_storage::KvStore;
use tenzro_types::bridge_route::{BridgeRouteAdapter, bridge_route_storage_key};
use tenzro_types::settlement::{
    MAX_LEG_EVIDENCE, MAX_RECON_ENTRIES, PlanOp, ReconEntry, ReconMismatch, SettlementPlan, leg_id,
};
use tenzro_types::split::SplitRule;

/// Most plans one `tenzro_listPlans` page returns.
const MAX_LIST: usize = 200;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn state(node: &Arc<TenzroNode>) -> Result<tenzro_vm::StateAdapter, JsonRpcError> {
    let storage = node
        .storage()
        .cloned()
        .ok_or_else(|| err(-32000, "Storage not available"))?;
    Ok(tenzro_vm::StateAdapter::with_storage(storage))
}

fn hex32(params: &Value, field: &str) -> Result<[u8; 32], JsonRpcError> {
    let s = params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| err(-32602, format!("missing '{field}' (32-byte hex)")))?;
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| err(-32602, format!("'{field}' must be 32 bytes of hex")))
}

/// The committed-state location of a system record, for `tenzro_getStateProof`.
fn proof_key(record_key: &str) -> Value {
    let key = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(record_key.as_bytes())
    );
    json!({ "namespace": tenzro_storage::CF_STATE, "key": hex::encode(key.as_bytes()) })
}

fn plan_json(plan: &SettlementPlan) -> Value {
    let id = hex::encode(plan.plan_id);
    json!({
        "plan": plan,
        "split_hash": hex::encode(plan.split.hash()),
        "leg_ids": (0..plan.legs.len()).map(|i| hex::encode(leg_id(&plan.plan_id, i as u8))).collect::<Vec<_>>(),
        "vault": hex::encode(tenzro_vm::native::plan_vault_address(&plan.plan_id).as_bytes()),
        "proof": proof_key(&format!("plan:{id}")),
    })
}

/// `tenzro_getPlan {plan_id}`.
pub(crate) async fn get_plan(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let id = hex32(&params, "plan_id")?;
    let plan = tenzro_vm::native::read_plan(&state(node)?, &id)
        .ok_or_else(|| err(-32004, format!("plan 0x{} not found", hex::encode(id))))?;
    Ok(plan_json(&plan))
}

/// `tenzro_getPlanDecision {plan_id}`: the decision, and the fixed-size
/// commitment at `decision:<plan_id>` that remote locks prove.
pub(crate) async fn get_plan_decision(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let id = hex32(&params, "plan_id")?;
    let state = state(node)?;
    let decision = tenzro_vm::native::read_decision(&state, &id)
        .ok_or_else(|| err(-32004, format!("plan 0x{} is not decided", hex::encode(id))))?;
    let commitment = tenzro_vm::native::read_decision_commitment(&state, &id).unwrap_or_default();
    Ok(json!({
        "decision": decision,
        "commitment": hex::encode(commitment),
        "proof": proof_key(&format!("decision:{}", hex::encode(id))),
    }))
}

/// `tenzro_getLegReceipt {leg_id}` or `{plan_id, index}`: the leg's receipt
/// once its plan is decided, and the evidence recorded for it (`ple:`): the
/// class it reached, the evidence digest, a hash-locked leg's funding
/// transaction and, once the plan commits, the preimage its recipient
/// claims with. Each with its state-proof key; `commitment` is the receipt
/// as stored, the bytes a contract on another chain proves.
pub(crate) async fn get_leg_receipt(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let id = match params.get("leg_id") {
        Some(_) => hex32(&params, "leg_id")?,
        None => {
            let plan = hex32(&params, "plan_id")?;
            let index = params
                .get("index")
                .and_then(Value::as_u64)
                .filter(|i| *i < tenzro_types::settlement::MAX_PLAN_LEGS as u64)
                .ok_or_else(|| err(-32602, "give 'leg_id', or 'plan_id' and 'index' (0 to 15)"))?;
            leg_id(&plan, index as u8)
        }
    };
    let state = state(node)?;
    let receipt = tenzro_vm::native::read_leg_receipt(&state, &id);
    let evidence = tenzro_vm::native::read_leg_evidence(&state, &id);
    if receipt.is_none() && evidence.is_none() {
        return Err(err(
            -32004,
            format!("no receipt or evidence for leg 0x{}", hex::encode(id)),
        ));
    }
    Ok(json!({
        "leg_id": hex::encode(id),
        "receipt": receipt,
        "commitment": tenzro_vm::native::read_leg_receipt_commitment(&state, &id).map(hex::encode),
        "proof": proof_key(&format!("plr:{}", hex::encode(id))),
        "evidence": evidence,
        "evidence_proof": proof_key(&format!("ple:{}", hex::encode(id))),
    }))
}

/// `tenzro_listPlans {payer?, status?, limit?}`: plans in key order.
pub(crate) async fn list_plans(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let payer = match params.get("payer").and_then(Value::as_str) {
        Some(p) => Some(
            hex::decode(p.trim_start_matches("0x"))
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or_else(|| err(-32602, "'payer' must be 32 bytes of hex"))?,
        ),
        None => None,
    };
    let status = params
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_string);
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(50, |l| (l as usize).min(MAX_LIST));
    let storage = node
        .storage()
        .cloned()
        .ok_or_else(|| err(-32000, "Storage not available"))?;
    let prefix = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(b"plan:")
    );
    let mut plans = Vec::new();
    for (_, blob) in storage
        .scan_prefix(tenzro_storage::CF_STATE, prefix.as_bytes())
        .map_err(|e| err(-32000, format!("Storage error: {e}")))?
    {
        let Ok(plan) = serde_json::from_slice::<SettlementPlan>(&blob) else {
            continue;
        };
        if payer
            .as_deref()
            .is_some_and(|p| p != plan.opened_by.as_bytes())
        {
            continue;
        }
        if status
            .as_deref()
            .is_some_and(|s| serde_json::to_value(plan.status).ok() != Some(json!(s)))
        {
            continue;
        }
        plans.push(plan_json(&plan));
        if plans.len() == limit {
            break;
        }
    }
    Ok(json!({ "plans": plans }))
}

/// `tenzro_previewSplit {gross, split, network_fees?}`: the exact division the
/// VM would make now, under the live fee parameters.
pub(crate) async fn preview_split(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let amount = |field: &str| -> Result<u128, JsonRpcError> {
        match params.get(field) {
            None if field == "network_fees" => Ok(0),
            Some(Value::String(s)) => s
                .parse()
                .map_err(|_| err(-32602, format!("'{field}' is not a decimal amount"))),
            Some(Value::Number(n)) => n
                .as_u64()
                .map(u128::from)
                .ok_or_else(|| err(-32602, format!("'{field}' is not an amount"))),
            _ => Err(err(
                -32602,
                format!("missing '{field}' (wei, decimal string)"),
            )),
        }
    };
    let gross = amount("gross")?;
    let network_fees = amount("network_fees")?;
    let rule: SplitRule =
        serde_json::from_value(params.get("split").cloned().unwrap_or(Value::Null))
            .map_err(|e| err(-32602, format!("'split' is not a split rule: {e}")))?;
    let fee_params = tenzro_vm::native::economy::fee_params(&state(node)?);
    let allocation = tenzro_types::split::apply(gross, &rule, &fee_params, network_fees)
        .map_err(|e| err(-32602, e.to_string()))?;
    Ok(json!({
        "allocation": allocation,
        "split_hash": hex::encode(rule.hash()),
        "fee_params": fee_params,
    }))
}

/// `tenzro_getNettingBatch {asset, seq?, participant?}`: an asset's netting
/// batch (the latest when `seq` is omitted) with its record key for a state
/// proof, the participant's collateral, defaults, and, once the batch
/// settled, its gross-to-net statement: every obligation it is party to with
/// a Merkle path to the batch's obligations root, and the instructions
/// naming it.
pub(crate) async fn get_netting_batch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::native::settlement_netting as netting;
    let params = params.unwrap_or(Value::Null);
    let asset = hex32(&params, "asset")?;
    let state = state(node)?;
    let seq = match params.get("seq").and_then(Value::as_u64) {
        Some(s) => s,
        None => netting::latest_seq(&state, &asset).ok_or_else(|| {
            err(
                -32004,
                format!("asset 0x{} has no netting batch", hex::encode(asset)),
            )
        })?,
    };
    let batch = netting::read_batch(&state, &asset, seq).ok_or_else(|| {
        err(
            -32004,
            format!("no netting batch {seq} for asset 0x{}", hex::encode(asset)),
        )
    })?;
    let mut out = json!({
        "batch": batch,
        "proof": proof_key(&format!("nbat:{}:{seq}", hex::encode(asset))),
    });
    if params.get("participant").is_some_and(|p| !p.is_null()) {
        let who = tenzro_types::primitives::Address::new(hex32(&params, "participant")?);
        out["collateral"] = json!(netting::usable_collateral(&state, &who, &asset).to_string());
        out["collateral_vault"] = json!(hex::encode(
            netting::collateral_vault(&who, &asset).as_bytes()
        ));
        out["defaults"] = json!(netting::read_defaults(&state, &who));
        if let Some(st) = &batch.settlement {
            let full = tenzro_settlement::netting::NettingBatch {
                batch_id: st.batch_id.clone(),
                obligations: batch.obligations.clone(),
                instructions: st.instructions.clone(),
                gross_total: st.gross_total,
                net_total: st.net_total,
            };
            out["statement"] = json!(tenzro_settlement::netting::statement(&full, &who));
        }
    }
    Ok(out)
}

/// The route `{adapter, chain}` a reconciliation call names.
fn route_params(params: &Value) -> Result<(BridgeRouteAdapter, String), JsonRpcError> {
    let adapter = params
        .get("adapter")
        .cloned()
        .ok_or_else(|| {
            err(
                -32602,
                "missing 'adapter' (the route's bridge protocol, e.g. \"ccip\")",
            )
        })
        .and_then(|a| {
            serde_json::from_value(a).map_err(|e| err(-32602, format!("unknown 'adapter': {e}")))
        })?;
    let chain = params
        .get("chain")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| err(-32602, "missing 'chain' (the route's external chain)"))?;
    Ok((adapter, chain.to_ascii_lowercase()))
}

fn recon_proof(adapter: BridgeRouteAdapter, chain: &str) -> Value {
    proof_key(&format!(
        "recon:{}",
        bridge_route_storage_key(adapter, chain)
    ))
}

fn mismatch_json(m: &ReconMismatch) -> Value {
    json!({
        "mismatch": m,
        "proof": proof_key(&format!("recon_mismatch:{}:{}", bridge_route_storage_key(m.adapter, &m.chain), m.position)),
    })
}

/// `tenzro_submitReconciliation {adapter, chain, entries, checkpoint}`: checks
/// the entries continue the route's stored reconciliation and returns the
/// `SettlementPlan` `reconcile` transaction to sign and send, with the count
/// and running hash the checkpoint must prove for it to be admitted.
pub(crate) async fn submit_reconciliation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let (adapter, chain) = route_params(&params)?;
    let entries: Vec<ReconEntry> = params
        .get("entries")
        .cloned()
        .ok_or_else(|| {
            err(
                -32602,
                "missing 'entries' (the lock's entries since the last reconciliation)",
            )
        })
        .and_then(|e| {
            serde_json::from_value(e).map_err(|e| err(-32602, format!("invalid 'entries': {e}")))
        })?;
    if entries.is_empty() || entries.len() > MAX_RECON_ENTRIES {
        return Err(err(
            -32602,
            format!("a reconciliation submits 1 to {MAX_RECON_ENTRIES} entries"),
        ));
    }
    let checkpoint = params
        .get("checkpoint")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .filter(|b| !b.is_empty() && b.len() <= MAX_LEG_EVIDENCE)
        .ok_or_else(|| {
            err(
                -32602,
                "missing 'checkpoint' (hex of the route's proof of the lock checkpoint)",
            )
        })?;
    let state = state(node)?;
    if tenzro_vm::native::read_bridge_route(&state, adapter, &chain)
        .and_then(|r| r.settlement_lock)
        .is_none()
    {
        return Err(err(
            -32004,
            format!(
                "route {} has no settlement lock",
                bridge_route_storage_key(adapter, &chain)
            ),
        ));
    }
    let stored =
        tenzro_vm::native::read_reconciliation(&state, adapter, &chain).unwrap_or_default();
    let acc = entries.iter().fold(stored.acc, |a, e| e.fold(&a));
    let count = stored.count + entries.len() as u64;
    let op = PlanOp::Reconcile {
        adapter,
        chain: chain.clone(),
        entries,
        checkpoint,
    };
    Ok(json!({
        "tx_type": tenzro_types::transaction::TransactionType::SettlementPlan { op },
        "reconciled": stored.count,
        "count": count,
        "acc": hex::encode(acc),
        "proof": recon_proof(adapter, &chain),
    }))
}

/// `tenzro_getReconciliation {adapter, chain}`: how far the route's lock is
/// reconciled, with the positions of its mismatches, and this epoch's
/// reconciliation duty of the route (paid to the first verified
/// reconciliation in the epoch).
pub(crate) async fn get_reconciliation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let (adapter, chain) = route_params(&params)?;
    let state = state(node)?;
    let rec = tenzro_vm::native::read_reconciliation(&state, adapter, &chain);
    let duty = tenzro_vm::native::read_recon_duty(&state, adapter, &chain);
    if rec.is_none() && duty.is_none() {
        return Err(err(
            -32004,
            format!(
                "route {} has no reconciliation and no reconciliation duty",
                bridge_route_storage_key(adapter, &chain)
            ),
        ));
    }
    Ok(json!({ "reconciliation": rec, "duty": duty, "proof": recon_proof(adapter, &chain) }))
}

/// `tenzro_listMismatches {adapter, chain}`: every mismatch stored for the
/// route's lock, in order, each with its state-proof key.
pub(crate) async fn list_mismatches(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let (adapter, chain) = route_params(&params)?;
    let found = tenzro_vm::native::list_mismatches(&state(node)?, adapter, &chain);
    Ok(json!({ "mismatches": found.iter().map(mismatch_json).collect::<Vec<_>>() }))
}
