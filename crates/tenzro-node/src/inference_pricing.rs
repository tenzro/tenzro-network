//! Pricing the calls this node serves, on its operator's rate cards.
//!
//! The rule is [`tenzro_types::price_card::RateCard::charge_wei`]; this
//! module supplies what it reads from the chain: which units are billable
//! (the units this node's engines meter, and any unit registered in the
//! generic registry since), the TNZO/USD rate a USD card converts at, and
//! the operator's published cards. The chain itself never prices anything:
//! a card is a registry entry it stores and does not read.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_storage::KvStore as _;
use tenzro_types::meter::{UnitDef, genesis_units};
use tenzro_types::model::BillableUnits;
use tenzro_types::price_card::{CARD_KIND, PriceCard, PricingError, RateCard, card_entry_name};
use tenzro_types::primitives::Address;
use tenzro_types::registry::{RegistryEntry, owned_id};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// A unit's definition from its registry entry, kind `unit`.
pub fn registered_unit(state: &dyn tenzro_vm::traits::VmState, id: &str) -> Option<UnitDef> {
    tenzro_vm::native::registry::read_entry(state, id)
        .filter(|e| e.kind == "unit" && e.retired_at_ms.is_none())
        .and_then(|e| serde_json::from_slice(&e.data_bytes()?).ok())
}

/// Whether `unit` is billable: one this node's engines meter, or one
/// registered on the chain this node follows. `None` when neither.
pub fn unit_billable(node: &TenzroNode, unit: &str) -> Option<bool> {
    genesis_units()
        .into_iter()
        .find(|u| u.id == unit)
        .map(|u| u.billable)
        .or_else(|| {
            node.chain_state()
                .and_then(|s| registered_unit(&s, unit))
                .map(|d| d.billable)
        })
}

/// The TNZO/USD rate in force (billionths of a dollar per TNZO), or 0 when
/// this node has no chain state.
pub fn tnzo_usd_nano(node: &TenzroNode) -> u128 {
    node.chain_state()
        .map(|s| tenzro_vm::native::read_fee_rate(&s).rate_nano_usd)
        .unwrap_or(0)
}

/// What `units` cost on `card`, in TNZO base units, at the rate in force.
pub fn charge_wei(
    node: &TenzroNode,
    card: &RateCard,
    units: &BillableUnits,
) -> Result<u128, PricingError> {
    card.charge_wei(units, |u| unit_billable(node, u), tnzo_usd_nano(node))
}

/// Check a card the operator sets: every line a known billable unit.
pub fn validate_card(node: &TenzroNode, card: &RateCard) -> Result<(), PricingError> {
    card.validate(usize::MAX, |u| unit_billable(node, u))
}

/// The pricing context the router ranks and prices with: the units this
/// node's engines meter, every registered unit a card of this node prices,
/// and the rate in force.
pub fn price_context(node: &TenzroNode) -> tenzro_model::PriceContext {
    let mut ctx = tenzro_model::PriceContext::genesis(tnzo_usd_nano(node));
    if let Some(state) = node.chain_state() {
        let pricing = node.provider_pricing.read();
        let extra = std::iter::once(&pricing.default)
            .chain(pricing.models.values())
            .flat_map(|c| c.lines.keys())
            .filter_map(|k| {
                tenzro_types::meter::parse_key(k)
                    .ok()
                    .map(|(u, _)| u.to_string())
            })
            .filter_map(|u| registered_unit(&state, &u))
            .collect::<Vec<_>>();
        ctx = ctx.with_units(extra);
    }
    ctx
}

/// The account this node's cards are published under and its receipts name:
/// its operator's payee.
pub fn card_account(node: &TenzroNode) -> Option<Address> {
    node.operator_payee()
}

fn entry_json(e: &RegistryEntry, now: i64) -> Value {
    json!({
        "id": e.id,
        "kind": e.kind,
        "owner": hex::encode(e.owner.as_bytes()),
        "version": e.version,
        "anchor": e.anchor,
        "data": e.data,
        "digest": e.digest(),
        "put_at_ms": e.put_at_ms,
        "retired_at_ms": e.retired_at_ms,
        "standing": e.standing_at(now),
    })
}

/// `tenzro_getRegistryEntry { id, version? }`: an entry of the generic
/// registry, the latest version or the one named, with its digest.
pub(crate) async fn get_registry_entry(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let id = params
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "Missing id"))?;
    let state = node
        .chain_state()
        .ok_or_else(|| err(-32000, "This node has no chain state"))?;
    let e = match params.get("version").and_then(|v| v.as_u64()) {
        Some(v) => tenzro_vm::native::registry::read_entry_version(&state, id, v),
        None => tenzro_vm::native::registry::read_entry(&state, id),
    };
    Ok(e.map(|e| entry_json(&e, crate::calendar::now_ms() as i64))
        .unwrap_or(Value::Null))
}

/// `tenzro_getPriceCard { provider, model_id }`: the card `provider`
/// publishes for a model, decoded, with its registry entry.
pub(crate) async fn get_price_card(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let provider = params
        .get("provider")
        .and_then(|v| v.as_str())
        .and_then(|h| Address::from_hex(h).ok())
        .ok_or_else(|| err(-32602, "provider must be a hex address"))?;
    let model_id = params
        .get("model_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "Missing model_id"))?;
    let state = node
        .chain_state()
        .ok_or_else(|| err(-32000, "This node has no chain state"))?;
    let id = owned_id(&provider, &card_entry_name(model_id));
    let Some(e) = tenzro_vm::native::registry::read_entry(&state, &id) else {
        return Ok(Value::Null);
    };
    let card: Option<PriceCard> = e.data_bytes().and_then(|b| serde_json::from_slice(&b).ok());
    let mut out = entry_json(&e, crate::calendar::now_ms() as i64);
    out["card"] = serde_json::to_value(card).unwrap_or(Value::Null);
    Ok(out)
}

/// The card `provider` would publish for `model_id` from this node: the
/// operator's card for the model with the model's weights hash. `None` when
/// the latest published version already says the same.
pub fn card_to_publish(node: &TenzroNode, model_id: &str, provider: &Address) -> Option<PriceCard> {
    let entry = tenzro_model::catalog::entry(model_id)?;
    let card = PriceCard {
        model_id: model_id.to_string(),
        model_hash: crate::inference_receipt::model_hash_of(&entry),
        rates: node.provider_pricing.read().card_for(model_id).clone(),
    };
    let published = node.chain_state().and_then(|s| {
        tenzro_vm::native::registry::read_entry(&s, &owned_id(provider, &card_entry_name(model_id)))
    });
    let same = published
        .filter(|e| e.retired_at_ms.is_none())
        .and_then(|e| e.data_bytes())
        .and_then(|b| serde_json::from_slice::<PriceCard>(&b).ok())
        .is_some_and(|p| p == card);
    (!same).then_some(card)
}

/// `tenzro_priceCardToPublish { model_id, provider }`: the registry entry
/// (`id`, `kind`, hex `data`) `provider` would put to publish this node's
/// card for a model, for the provider to sign itself; `entry: null` when the
/// published card already says the same.
pub(crate) async fn price_card_to_publish(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let model_id = params
        .get("model_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "Missing model_id"))?;
    let provider = params
        .get("provider")
        .and_then(|v| v.as_str())
        .and_then(|h| Address::from_hex(h).ok())
        .ok_or_else(|| err(-32602, "provider must be a hex address"))?;
    if tenzro_model::catalog::entry(model_id).is_none() {
        return Err(err(
            -32004,
            format!("{model_id} is not in this node's catalog"),
        ));
    }
    validate_card(node, node.provider_pricing.read().card_for(model_id))
        .map_err(|e| err(-32602, e.to_string()))?;
    Ok(match card_to_publish(node, model_id, &provider) {
        Some(card) => json!({
            "entry": {
                "id": owned_id(&provider, &card_entry_name(model_id)),
                "kind": CARD_KIND,
                "data": hex::encode(serde_json::to_vec(&card).unwrap_or_default()),
            }
        }),
        None => json!({ "entry": Value::Null }),
    })
}

/// What a receipt says the call was charged on: the published card's entry
/// digest, the rate a USD card converted at, and the charge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PricedOn {
    /// Digest of the registry entry carrying the card.
    pub card: String,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub rate_nano_usd: u128,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub charge: u128,
}

/// The published card this node's operator charges `model_id` on, with the
/// rate in force and what `units` cost on it. `None` when the operator has
/// published no card for the model, or it does not price the units.
pub fn priced_on(node: &TenzroNode, model_id: &str, units: &BillableUnits) -> Option<PricedOn> {
    let provider = card_account(node)?;
    let state = node.chain_state()?;
    let e = tenzro_vm::native::registry::read_entry(
        &state,
        &owned_id(&provider, &card_entry_name(model_id)),
    )
    .filter(|e| e.retired_at_ms.is_none())?;
    let card: PriceCard = serde_json::from_slice(&e.data_bytes()?).ok()?;
    let rate = match card.rates.denom {
        tenzro_types::price_card::Denom::NanoUsd => tnzo_usd_nano(node),
        tenzro_types::price_card::Denom::Wei => 0,
    };
    let charge = card
        .rates
        .charge_wei(units, |u| unit_billable(node, u), rate)
        .ok()?;
    Some(PricedOn {
        card: e.digest(),
        rate_nano_usd: rate,
        charge,
    })
}

/// Most entries one `tenzro_listRegistry` page returns.
const MAX_LIST: usize = 500;

/// `tenzro_listRegistry { kind, after?, limit? }`: every standing entry of a
/// kind (a service type), in id order, after the id `after`. Nothing is
/// ranked or filtered: what to show and in what order is the caller's.
pub(crate) async fn list_registry(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let kind = params
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "Missing kind"))?;
    tenzro_types::registry::check_kind(kind).map_err(|e| err(-32602, e.to_string()))?;
    let after = params.get("after").and_then(|v| v.as_str()).unwrap_or("");
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map_or(100, |l| l as usize)
        .min(MAX_LIST);
    let storage = node
        .storage()
        .cloned()
        .ok_or_else(|| err(-32000, "This node has no chain state"))?;
    let state = node
        .chain_state()
        .ok_or_else(|| err(-32000, "This node has no chain state"))?;
    let index = format!("regk:{kind}:");
    let prefix = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(index.as_bytes())
    );
    let mut ids: Vec<String> = storage
        .scan_prefix(tenzro_storage::kv::CF_STATE, prefix.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .filter_map(|(k, _)| {
            let hex_key = std::str::from_utf8(&k)
                .ok()?
                .rsplit(':')
                .next()?
                .to_string();
            let key = String::from_utf8(hex::decode(hex_key).ok()?).ok()?;
            key.strip_prefix(&index).map(str::to_string)
        })
        .filter(|id| id.as_str() > after)
        .collect();
    ids.sort();
    let now = crate::calendar::now_ms() as i64;
    let entries: Vec<Value> = ids
        .iter()
        .take(limit)
        .filter_map(|id| tenzro_vm::native::registry::read_entry(&state, id))
        .map(|e| entry_json(&e, now))
        .collect();
    let next = (ids.len() > limit).then(|| ids[limit - 1].clone());
    Ok(json!({ "kind": kind, "entries": entries, "next": next }))
}
