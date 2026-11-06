//! Reads the public network pages are built from: an address's
//! transactions, the peers this node hears from, a provider's scorecard,
//! the network's settlement activity by epoch, and decoded transactions and
//! certificate signers.

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_storage::{CF_TRANSACTIONS, KvStore};
use tenzro_types::primitives::Address;
use tenzro_types::transaction::{SignedTransaction, TransactionType};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn bad(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

fn internal(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: msg.into(),
        data: None,
    }
}

fn hex_addr(a: &Address) -> String {
    format!("0x{}", hex::encode(a.as_bytes()))
}

fn norm(s: &str) -> String {
    s.trim_start_matches("0x").to_ascii_lowercase()
}

/// Shortest byte string rendered as hex rather than a list of numbers.
const HEX_MIN_BYTES: usize = 16;
/// Longest byte string rendered in full; a longer one is its length and
/// SHA-256.
const HEX_MAX_BYTES: usize = 32 * 1024;
/// Largest integer a JSON number carries exactly in every client.
const SAFE_INTEGER: u64 = (1 << 53) - 1;

/// `v` with every integer above 2^53 - 1 as a decimal string, and every list
/// of at least [`HEX_MIN_BYTES`] integers that all fit a byte as `0x` hex
/// (or, past [`HEX_MAX_BYTES`], as its length and SHA-256).
pub(crate) fn json_safe(v: Value) -> Value {
    match v {
        Value::Number(n) => match n.as_u64() {
            Some(u) if u > SAFE_INTEGER => Value::String(u.to_string()),
            None if n.as_i64().is_none() && n.as_f64().is_none() => Value::String(n.to_string()),
            None => match n.as_i64() {
                Some(i) if i.unsigned_abs() > SAFE_INTEGER => Value::String(i.to_string()),
                _ => Value::Number(n),
            },
            _ => Value::Number(n),
        },
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = (items.len() >= HEX_MIN_BYTES)
                .then(|| {
                    items
                        .iter()
                        .map(|i| i.as_u64().filter(|b| *b <= 255).map(|b| b as u8))
                        .collect()
                })
                .flatten();
            match bytes {
                Some(b) if b.len() > HEX_MAX_BYTES => json!({
                    "bytes": b.len(),
                    "sha256": format!("0x{}", hex::encode(Sha256::digest(&b))),
                }),
                Some(b) => Value::String(format!("0x{}", hex::encode(b))),
                None => Value::Array(items.into_iter().map(json_safe).collect()),
            }
        }
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, json_safe(v))).collect())
        }
        other => other,
    }
}

/// A transaction type's variant name and its decoded fields.
pub(crate) fn describe(tx_type: &TransactionType) -> (String, Value) {
    match serde_json::to_value(tx_type) {
        Ok(Value::String(name)) => (name, Value::Null),
        Ok(Value::Object(map)) if map.len() == 1 => {
            let (name, payload) = map.into_iter().next().expect("one entry");
            (name, json_safe(payload))
        }
        Ok(other) => ("Unknown".to_string(), json_safe(other)),
        Err(e) => ("Unknown".to_string(), json!({ "error": e.to_string() })),
    }
}

/// The value a transaction moves to its recipient, for a transfer.
pub(crate) fn transferred(tx_type: &TransactionType) -> String {
    match tx_type {
        TransactionType::Transfer { amount } => amount.to_string(),
        _ => "0".to_string(),
    }
}

fn stored_tx(store: &dyn KvStore, hash: &str) -> Option<SignedTransaction> {
    store
        .get(CF_TRANSACTIONS, hash.as_bytes())
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn stored_receipt(store: &dyn KvStore, hash: &str) -> Option<crate::event_loop::TxReceiptRecord> {
    store
        .get(CF_TRANSACTIONS, format!("receipt:{hash}").as_bytes())
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

const HISTORY_DEFAULT_PAGE: usize = 25;
const HISTORY_MAX_PAGE: usize = 100;

/// `tenzro_getTransactionHistory { address, cursor?, limit? }`: the
/// transactions `address` sent or received, newest first.
pub(crate) async fn handle_transaction_history(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = match params {
        Some(Value::Array(a)) => match a.into_iter().next() {
            Some(Value::String(s)) => json!({ "address": s }),
            Some(v) => v,
            None => Value::Null,
        },
        Some(v) => v,
        None => Value::Null,
    };
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("address is required"))
        .and_then(|a| Address::from_hex(a).map_err(|e| bad(format!("address: {e}"))))?;
    let before = match params.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            s.parse::<u64>()
                .map_err(|_| bad("cursor is a decimal position"))?,
        ),
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| bad("cursor is a decimal position"))?,
        ),
    };
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(HISTORY_DEFAULT_PAGE, |l| {
            (l as usize).clamp(1, HISTORY_MAX_PAGE)
        });
    let store = node
        .storage()
        .ok_or_else(|| internal("storage not initialized"))?;
    let page = crate::transaction_index::page(store.as_ref(), &address, before, limit)
        .map_err(internal)?;
    let transactions: Vec<Value> = page
        .entries
        .iter()
        .map(|e| {
            let tx = stored_tx(store.as_ref(), &e.tx_hash);
            let receipt = stored_receipt(store.as_ref(), &e.tx_hash);
            let (kind, value, from, to) = match &tx {
                Some(t) => (
                    Some(describe(&t.transaction.tx_type).0),
                    Some(transferred(&t.transaction.tx_type)),
                    Some(hex_addr(&t.transaction.from)),
                    Some(hex_addr(&t.transaction.to)),
                ),
                None => (None, None, None, None),
            };
            json!({
                "hash": e.tx_hash,
                "block_height": e.height,
                "tx_index": e.tx_index,
                "direction": e.direction,
                "type": kind,
                "from": from,
                "to": to,
                "value": value,
                "status": receipt.as_ref().map(|r| if r.success { "success" } else { "reverted" }),
                "fee_paid": receipt.as_ref().map(|r| r.fee_paid.to_string()),
            })
        })
        .collect();
    Ok(json!({
        "address": hex_addr(&address),
        "transactions": transactions,
        "cursor": page.cursor.map(|c| c.to_string()),
        "total": page.total,
        "kept": page.total.min(crate::transaction_index::MAX_PER_ADDRESS),
        "indexed_from_height": page.indexed_from,
    }))
}

/// The kind of hardware a node's identity key is held in, as it declared
/// it: `tpm`, `enclave`, `delegated_tpm` or `passkey`.
pub(crate) fn anchor_kind(identity_root: &str) -> Option<&'static str> {
    match identity_root {
        "tpm" => Some("tpm"),
        "secure-enclave" => Some("enclave"),
        "tpm-delegated" => Some("delegated_tpm"),
        "passkey-delegated" => Some("passkey"),
        _ => None,
    }
}

/// This node's own identity anchor kind.
pub(crate) fn local_anchor_kind() -> Option<&'static str> {
    tenzro_network::service::identity_root().and_then(|r| anchor_kind(r.as_str()))
}

fn roles_of(a: &tenzro_network::ProviderAnnouncementMessage, validator: bool) -> Vec<String> {
    let mut roles = Vec::new();
    if validator {
        roles.push("validator".to_string());
    }
    if !a.provider_type.is_empty() {
        roles.push(format!("provider:{}", a.provider_type));
    }
    for c in &a.capabilities {
        roles.push(c.clone());
    }
    for w in &a.worker_roles {
        if let Ok(Value::String(s)) = serde_json::to_value(w) {
            roles.push(format!("worker:{s}"));
        }
    }
    roles.sort();
    roles.dedup();
    roles
}

/// `tenzro_listPeers`: this node and every peer whose signed announcement it
/// holds, with what each declared.
pub(crate) async fn handle_list_peers(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let validators = node.consensus().map(|c| c.validator_set());
    let is_validator = |addr: &str| {
        let Some(set) = validators.as_ref() else {
            return false;
        };
        Address::from_hex(addr).is_ok_and(|a| set.get_by_address(&a).is_some())
    };
    let mut peers = Vec::new();
    let own_endpoint = node.iroh_resolver().map(|r| r.endpoint_id().to_string());
    let own_account = node.operator_payee().map(|a| hex_addr(&a));
    let mut own_roles: Vec<String> = Vec::new();
    if own_account.as_deref().is_some_and(is_validator) {
        own_roles.push("validator".to_string());
    }
    if !node.served_models.is_empty() {
        own_roles.push("provider:ai".to_string());
    }
    peers.push(json!({
        "peer_id": own_endpoint,
        "self": true,
        "account": own_account,
        "machine_did": crate::identity_bootstrap::machine_did(),
        "roles": own_roles,
        "hardware_tier": crate::work_settlements::local_tier().await,
        "identity_anchor": local_anchor_kind(),
        "region": node.config().region,
        "region_source": node.config().region.as_ref().map(|_| "declared"),
        "version": env!("CARGO_PKG_VERSION"),
    }));
    let now = chrono::Utc::now().timestamp_millis();
    for entry in node.network_providers_snapshot() {
        let a = &entry.announcement;
        if own_endpoint.as_deref() == Some(a.iroh_endpoint_id.as_str()) {
            continue;
        }
        let tier = if a.hardware.detected {
            Some(crate::work_settlements::tier_name(a.hardware.class()))
        } else {
            None
        };
        peers.push(json!({
            "peer_id": a.iroh_endpoint_id,
            "self": false,
            "account": (!a.provider_address.is_empty()).then(|| a.provider_address.clone()),
            "machine_did": (!a.machine_did.is_empty()).then(|| a.machine_did.clone()),
            "roles": roles_of(a, is_validator(&a.provider_address)),
            "hardware_tier": tier,
            "identity_anchor": anchor_kind(&a.trust_profile.identity_root),
            "region": a.region,
            "region_source": a.region.as_ref().map(|_| "declared"),
            // Announcements do not carry a software version.
            "version": Value::Null,
            "announced_at_ms": a.timestamp,
            "age_ms": now.saturating_sub(a.timestamp),
        }));
    }
    Ok(json!({ "peers": peers }))
}

/// A sorted sample's `q`-quantile (nearest rank).
fn quantile(sorted: &[u64], q: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    Some(sorted[rank - 1])
}

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// `tenzro_getProviderScorecard { provider }`: a provider's standing on
/// chain, its announced price cards, and the latency and volume of the
/// settlements this node recorded for it over the last day and week.
pub(crate) async fn handle_provider_scorecard(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let provider = params
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("provider (an account address) is required"))
        .and_then(|a| Address::from_hex(a).map_err(|e| bad(format!("provider: {e}"))))?;
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| internal("chain state is not available"))?;
    let did = tenzro_vm::native::identity_did_of(&chain, provider.as_bytes());
    let bond = did
        .as_deref()
        .and_then(|d| tenzro_vm::native::compute_bond(&chain, d));
    let role_stakes: Vec<Value> = tenzro_vm::native::role_stakes_of(&chain, provider.as_bytes())
        .into_iter()
        .map(|(role, stake)| {
            json!({
                "role": serde_json::to_value(role).unwrap_or(Value::Null),
                "stake": json_safe(serde_json::to_value(stake).unwrap_or(Value::Null)),
            })
        })
        .collect();
    let validator = node
        .consensus()
        .and_then(|c| c.validator_set().get_by_address(&provider).cloned())
        .map(|v| json_safe(serde_json::to_value(v).unwrap_or(Value::Null)));
    let reputation = node
        .provider_manager()
        .and_then(|pm| pm.get_reputation(&provider));

    let key = norm(&hex_addr(&provider));
    let mut cards = serde_json::Map::new();
    if node.operator_payee().as_ref() == Some(&provider) {
        let (served, _) =
            crate::visibility_rpc::announced_models(&node.served_models, node.visibility());
        let pricing = node.provider_pricing.read();
        for m in served {
            let card = pricing.card_for(&m).clone();
            cards.insert(m, serde_json::to_value(card).unwrap_or(Value::Null));
        }
    }
    for e in node.network_models_snapshot() {
        if norm(&e.registration.provider) == key {
            cards
                .entry(e.registration.model_id.clone())
                .or_insert_with(|| {
                    serde_json::to_value(&e.registration.pricing).unwrap_or(Value::Null)
                });
        }
    }

    let store = node
        .storage()
        .ok_or_else(|| internal("storage not initialized"))?;
    let now = crate::calendar::now_ms();
    let (entries, complete) = crate::work_settlements::provider_since(
        store.as_ref(),
        &provider,
        now.saturating_sub(7 * DAY_MS),
    )
    .map_err(internal)?;
    let window = |since: u64| {
        let picked: Vec<&crate::work_settlements::WorkSettlement> =
            entries.iter().filter(|e| e.served_at_ms >= since).collect();
        let mut latencies: Vec<u64> = picked
            .iter()
            .filter_map(|e| e.requested_at_ms.map(|r| e.served_at_ms.saturating_sub(r)))
            .collect();
        latencies.sort_unstable();
        let value: u128 = picked.iter().map(|e| e.amount).sum();
        json!({
            "settled": picked.len(),
            "value": value.to_string(),
            "latency_samples": latencies.len(),
            "latency_p50_ms": quantile(&latencies, 0.50),
            "latency_p95_ms": quantile(&latencies, 0.95),
        })
    };
    Ok(json!({
        "provider": hex_addr(&provider),
        "standing": {
            "did": did,
            "compute_bond": bond.map(|b| json_safe(serde_json::to_value(b).unwrap_or(Value::Null))),
            "role_stakes": role_stakes,
            "validator": validator,
            "source": "chain",
        },
        "reputation": { "score": reputation, "source": "node_local" },
        "price_cards": cards,
        "settled": {
            "last_24h": window(now.saturating_sub(DAY_MS)),
            "last_7d": window(now.saturating_sub(7 * DAY_MS)),
            "complete": complete,
            "source": "node_local",
        },
    }))
}

/// Most epochs one activity read returns.
const MAX_ACTIVITY_EPOCHS: u64 = 168;
const DEFAULT_ACTIVITY_EPOCHS: u64 = 24;

/// `tenzro_getNetworkActivity { epochs? }`: settlement activity on the
/// chain for the latest reward epochs, newest first, from consensus state.
pub(crate) async fn handle_network_activity(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let count = params
        .get("epochs")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_ACTIVITY_EPOCHS, |n| n.clamp(1, MAX_ACTIVITY_EPOCHS));
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| internal("chain state is not available"))?;
    let current = tenzro_vm::native::read_reward_state(&chain)
        .map_err(|e| internal(format!("reward state: {e}")))?
        .current_epoch;
    let kept_from = tenzro_vm::native::rewards::first_kept_epoch(&chain)
        .map_err(|e| internal(format!("reward state: {e}")))?;
    let first = current.saturating_sub(count - 1).max(kept_from);
    let mut epochs = Vec::new();
    let mut totals = tenzro_vm::native::EpochActivity::default();
    for epoch in (first..=current).rev() {
        let a = tenzro_vm::native::read_epoch_activity(&chain, epoch);
        totals.settled_value += a.settled_value;
        totals.settlements += a.settlements;
        totals.payments += a.payments;
        totals.organic_value += a.organic_value;
        totals.settlement_fees += a.settlement_fees;
        totals.burned += a.burned;
        let mut v = serde_json::to_value(&a).unwrap_or(Value::Null);
        v["epoch"] = json!(epoch);
        v["in_progress"] = json!(epoch == current);
        epochs.push(v);
    }
    Ok(json!({
        "current_epoch": current,
        "kept_from_epoch": kept_from,
        "epochs": epochs,
        "totals": {
            "settled_value": totals.settled_value.to_string(),
            "settlements": totals.settlements,
            "payments": totals.payments,
            "organic_value": totals.organic_value.to_string(),
            "settlement_fees": totals.settlement_fees.to_string(),
            "burned": totals.burned.to_string(),
        },
    }))
}

/// The members who signed `cert`, from its epoch's committee: each signer's
/// committee index, account, seats and stake, its hardware key's
/// fingerprint and the session certificate digest it signed under.
pub(crate) fn decode_signers(
    cert: &tenzro_consensus::Certificate,
    committee: Option<&tenzro_consensus::Committee>,
) -> Value {
    let signers: Vec<Value> = cert
        .signers
        .iter()
        .zip(&cert.sessions)
        .map(|(index, session)| {
            let member = committee.and_then(|c| c.member(*index));
            json!({
                "index": index,
                "address": member.map(|m| hex_addr(&m.address)),
                "seats": member.map(|m| m.seats),
                "stake": member.map(|m| m.stake.to_string()),
                "key_fingerprint": member.map(|m| format!("0x{}", hex::encode(m.public_key.fingerprint()))),
                "session_digest": format!("0x{}", hex::encode(session)),
            })
        })
        .collect();
    let signed_seats: Option<u64> =
        committee.map(|c| cert.signers.iter().map(|i| c.seats(*i)).sum());
    json!({
        "signers": signers,
        "signed_seats": signed_seats,
        "total_seats": committee.map(|c| c.total_seats()),
        "quorum": committee.map(|c| c.quorum()),
        "committee_known": committee.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_integers_become_strings_and_byte_lists_become_hex() {
        let v = json!({
            "small": 7,
            "big": 1u64 << 60,
            "bytes": (0..32).collect::<Vec<u8>>(),
            "short": [1, 2, 3],
            "mixed": (0..20).map(|i| i * 100).collect::<Vec<u32>>(),
        });
        let s = json_safe(v);
        assert_eq!(s["small"], 7);
        assert_eq!(s["big"], (1u64 << 60).to_string());
        assert_eq!(
            s["bytes"],
            format!("0x{}", hex::encode((0..32).collect::<Vec<u8>>()))
        );
        assert_eq!(s["short"], json!([1, 2, 3]));
        assert!(s["mixed"].is_array());
    }

    #[test]
    fn a_huge_byte_string_is_its_length_and_digest() {
        let b = vec![7u8; HEX_MAX_BYTES + 1];
        let s = json_safe(serde_json::to_value(&b).unwrap());
        assert_eq!(s["bytes"], HEX_MAX_BYTES + 1);
        assert_eq!(
            s["sha256"],
            format!("0x{}", hex::encode(Sha256::digest(&b)))
        );
    }

    #[test]
    fn every_transaction_type_is_named_by_its_variant() {
        let (name, payload) = describe(&TransactionType::Transfer { amount: 5 });
        assert_eq!(name, "Transfer");
        assert_eq!(payload["amount"], 5);
        let (name, payload) = describe(&TransactionType::ContractDeploy {
            code: vec![0xab; 20],
            args: Vec::new(),
        });
        assert_eq!(name, "ContractDeploy");
        assert_eq!(payload["code"], format!("0x{}", "ab".repeat(20)));
        assert_eq!(payload["args"], json!([]));
    }

    #[test]
    fn identity_roots_map_to_anchor_kinds() {
        assert_eq!(anchor_kind("tpm"), Some("tpm"));
        assert_eq!(anchor_kind("secure-enclave"), Some("enclave"));
        assert_eq!(anchor_kind("tpm-delegated"), Some("delegated_tpm"));
        assert_eq!(anchor_kind("passkey-delegated"), Some("passkey"));
        assert_eq!(anchor_kind(""), None);
    }

    #[test]
    fn quantiles_take_the_nearest_rank() {
        assert_eq!(quantile(&[], 0.5), None);
        assert_eq!(quantile(&[10], 0.95), Some(10));
        let s: Vec<u64> = (1..=100).collect();
        assert_eq!(quantile(&s, 0.50), Some(50));
        assert_eq!(quantile(&s, 0.95), Some(95));
    }
}
