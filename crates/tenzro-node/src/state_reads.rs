//! Escrow and kill-switch reads. Both records live only in consensus state;
//! a single record is loaded from state, and lists walk the event log for the
//! records' creation logs, then load each from state.

use std::sync::Arc;

use serde_json::Value;
use tenzro_settlement::EscrowAccount;
use tenzro_types::chain_event::{ChainEvent, ChainEventKind};
use tenzro_types::kill_switch::KillSwitchReceipt;
use tenzro_types::primitives::Address;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn hex_id(params: &Value, key: &str) -> Result<[u8; 32], JsonRpcError> {
    let raw = match params.as_array() {
        Some(a) => a.first().and_then(Value::as_str),
        None => params.get(key).and_then(Value::as_str),
    }
    .ok_or_else(|| err(-32602, format!("missing {key}")))?;
    hex::decode(raw.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| err(-32602, format!("{key} must be 32 bytes of hex")))
}

/// The system log `e` carries, as `(topic, data)`.
fn system_log(e: &ChainEvent) -> Option<(&[u8], &[u8])> {
    let ChainEventKind::Log {
        address,
        topics,
        data,
    } = &e.kind
    else {
        return None;
    };
    let emitter = if address.len() == 32 {
        &address[12..]
    } else {
        &address[..]
    };
    if emitter != tenzro_vm::native::SYSTEM_ADDRESS.as_slice() {
        return None;
    }
    Some((topics.first()?.as_slice(), data.as_slice()))
}

fn log_request(params: &Value) -> Result<crate::event_index::ReadRequest, JsonRpcError> {
    if params.get("filter").is_some_and(|f| !f.is_null()) {
        return Err(err(-32602, "this list selects its events itself"));
    }
    let mut req = crate::event_index::ReadRequest::parse(params, None)?;
    req.filter =
        tenzro_events::EventFilter::new().with_event_types(vec![tenzro_events::EventType::Log]);
    Ok(req)
}

pub(crate) fn escrow_json(escrow: &EscrowAccount) -> Value {
    serde_json::json!({
        "escrow_id": format!("0x{}", escrow.escrow_id),
        "payer": format!("0x{}", hex::encode(escrow.payer.as_bytes())),
        "payee": format!("0x{}", hex::encode(escrow.payee.as_bytes())),
        "amount": escrow.amount.to_string(),
        "asset_id": escrow.asset_id,
        "status": format!("{:?}", escrow.status),
        "created_at": escrow.created_at.as_millis(),
        "expires_at": escrow.expires_at.as_millis(),
        "release_conditions": escrow.release_conditions,
        "claimed": escrow.claimed.to_string(),
        "reference": escrow.reference.map(hex::encode),
    })
}

/// `tenzro_getEscrow { escrow_id }`: the escrow record in state.
pub(crate) async fn get_escrow(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let id = hex_id(&params, "escrow_id")?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    tenzro_vm::native::read_escrow(&chain, &id)
        .map(|e| escrow_json(&e))
        .ok_or_else(|| err(-32004, format!("no escrow 0x{}", hex::encode(id))))
}

/// `tenzro_listEscrowsByPayer { payer, from_cursor?, from_height?, to_cursor?, limit? }`
/// and `tenzro_listEscrowsByPayee { payee, .. }`: escrows in creation order,
/// from their `EscrowCreated` logs, each with its event cursor. Pass the
/// returned `cursor` back as `from_cursor` to continue with no gap.
pub(crate) async fn list_escrows(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    side: &str,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let party = params
        .get(side)
        .and_then(Value::as_str)
        .ok_or_else(|| err(-32602, format!("missing {side}")))?;
    let party = Address::from_hex(party).map_err(|e| err(-32602, format!("{side}: {e}")))?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let req = log_request(&params)?;
    let escrow_of = |e: &ChainEvent| -> Option<EscrowAccount> {
        let (topic, data) = system_log(e)?;
        if topic != b"EscrowCreated" {
            return None;
        }
        let id: [u8; 32] = data.get(..32)?.try_into().ok()?;
        let escrow = tenzro_vm::native::read_escrow(&chain, &id)?;
        let mine = if side == "payer" {
            escrow.payer == party
        } else {
            escrow.payee == party
        };
        mine.then_some(escrow)
    };
    let page = crate::event_index::read_where(node, &req, &|e| escrow_of(e).is_some()).await?;
    let escrows: Vec<Value> = page
        .events
        .iter()
        .filter_map(|e| {
            let mut v = escrow_json(&escrow_of(e)?);
            v["cursor"] = Value::from(e.cursor.to_string());
            Some(v)
        })
        .collect();
    Ok(
        serde_json::json!({ side: format!("0x{}", hex::encode(party.as_bytes())), "escrows": escrows, "cursor": page.cursor.map(|c| c.to_string()) }),
    )
}

pub(crate) fn kill_switch_json(r: &KillSwitchReceipt) -> Value {
    serde_json::json!({
        "receipt_id": r.receipt_id,
        "action": r.action.as_str(),
        "agent_did": r.agent_did,
        "controller_did": r.controller_did,
        "reason_code": r.reason_code,
        "reason_text": r.reason_text,
        "evidence_hash": r.evidence_hash,
        "slash_bps": r.slash_bps,
        "cascade": r.cascade,
        "pause_until": r.pause_until,
        "frozen_at_block": r.frozen_at_block.0,
        "timestamp": r.timestamp.as_millis(),
    })
}

/// `tenzro_getKillSwitchReceipt { receipt_id }`: the receipt in state, or null.
pub(crate) async fn get_kill_switch_receipt(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let id = hex_id(&params, "receipt_id")?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    Ok(
        tenzro_vm::native::read_kill_switch_receipt(&chain, &hex::encode(id))
            .map(|r| kill_switch_json(&r))
            .unwrap_or(Value::Null),
    )
}

/// `tenzro_listKillSwitchByAgent { agent_did, .. }` and
/// `tenzro_listKillSwitchByController { controller_did, .. }`: kill-switch
/// receipts in chain order from their logs, each with its event cursor.
pub(crate) async fn list_kill_switch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    side: &str,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let did = params
        .get(side)
        .and_then(Value::as_str)
        .ok_or_else(|| err(-32602, format!("missing {side}")))?
        .to_owned();
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let req = log_request(&params)?;
    let receipt_of = |e: &ChainEvent| -> Option<KillSwitchReceipt> {
        let (topic, data) = system_log(e)?;
        if !tenzro_vm::native::KILL_SWITCH_TOPICS.contains(&topic) {
            return None;
        }
        let (agent, controller, id) = tenzro_vm::native::decode_kill_switch_log(data)?;
        let mine = if side == "agent_did" {
            agent == did
        } else {
            controller == did
        };
        if !mine {
            return None;
        }
        tenzro_vm::native::read_kill_switch_receipt(&chain, &id)
    };
    let page = crate::event_index::read_where(node, &req, &|e| receipt_of(e).is_some()).await?;
    let receipts: Vec<Value> = page
        .events
        .iter()
        .filter_map(|e| {
            let mut v = kill_switch_json(&receipt_of(e)?);
            v["cursor"] = Value::from(e.cursor.to_string());
            Some(v)
        })
        .collect();
    Ok(
        serde_json::json!({ side: did, "receipts": receipts, "cursor": page.cursor.map(|c| c.to_string()) }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::kill_switch::KillSwitchAction;
    use tenzro_types::primitives::{BlockHeight, Timestamp};

    fn receipt(action: KillSwitchAction, pause_until: Option<u64>) -> KillSwitchReceipt {
        KillSwitchReceipt {
            receipt_id: "ab".repeat(32),
            action,
            agent_did: "did:tenzro:machine:agent".to_string(),
            controller_did: "did:tenzro:human:owner".to_string(),
            reason_code: 3,
            reason_text: None,
            evidence_hash: None,
            slash_bps: None,
            cascade: None,
            pause_until,
            frozen_at_block: BlockHeight::new(10),
            timestamp: Timestamp::new(1_000),
        }
    }

    #[test]
    fn a_kill_switch_receipt_names_when_a_pause_ends() {
        let paused = kill_switch_json(&receipt(KillSwitchAction::Pause, Some(1_800_000_000)));
        assert_eq!(paused["pause_until"], serde_json::json!(1_800_000_000u64));
        // An indefinite pause, and every other action, carry it as null.
        let indefinite = kill_switch_json(&receipt(KillSwitchAction::Pause, None));
        assert!(indefinite.get("pause_until").is_some_and(Value::is_null));
        let quarantined = kill_switch_json(&receipt(KillSwitchAction::Quarantine, None));
        assert!(quarantined.get("pause_until").is_some_and(Value::is_null));
    }
}
