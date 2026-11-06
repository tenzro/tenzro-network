//! `tenzro_getNetworkParams { key? }`: every governed network parameter
//! from consensus state, with its bounds, genesis value, the direction that
//! tightens it, its capture-guard direction, and any enacted change still
//! waiting for its epoch.
//! Values are decimal strings: several exceed what a JSON number holds
//! exactly.
//!
//! These values change only through an enacted `parameter_change`
//! governance proposal; there is no other way to set them. The full listing
//! also carries the running-cost reserve the `treasury.*` parameters drive.
//!
//! `tenzro_listLevers`: the same parameters as levers, grouped by the area
//! they govern, each with its kind (`status`: enabled, paused or retired;
//! `switch`: on or off; `value`: a tunable amount or cap), its status where
//! it has one, and the change waiting for its epoch; plus every installed
//! bridge route with the mode its record and its transport's lever leave it
//! in.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_vm::governance::{
    GOVERNED_PARAMS, GovernedParam, LeverStatus, Tighten, bridge_adapter_status_key, capture_guard,
    governed_param,
};
use tenzro_vm::native::{bridge_route_stop, network_param, params_epoch, pending_param};
use tenzro_vm::traits::VmState;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn param_json(chain: &dyn VmState, p: &GovernedParam) -> Value {
    json!({
        "key": p.key,
        "value": network_param(chain, p.key).to_string(),
        "genesis": p.genesis.to_string(),
        "min": p.min.to_string(),
        "max": p.max.to_string(),
        "tightens": p.tighten,
        "capture_guard": capture_guard(p.key),
        "description": p.description,
        "pending": pending_param(chain, p.key).map(|c| json!({
            "value": c.value.to_string(),
            "activates_epoch": c.activates_epoch,
            "proposal_id": c.proposal_id,
        })),
    })
}

/// The running-cost reserve the treasury parameters drive: its balance,
/// the accounts of the last epoch boundary, and the payments waiting.
fn reserve_json(chain: &dyn VmState) -> Value {
    use tenzro_vm::native::treasury_reserve as r;
    let book = r::read_book(chain);
    json!({
        "address": hex::encode(r::reserve_address().as_bytes()),
        "balance": chain.get_balance(r::reserve_address().as_bytes()).to_string(),
        "treasury_balance": chain
            .get_balance(tenzro_vm::native::derive_treasury_address().as_bytes())
            .to_string(),
        "book": book,
        "queue": r::read_queue(chain),
    })
}

/// `tenzro_getNetworkParams`.
pub(crate) async fn handle_get_network_params(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let chain = crate::rpc::chain_state(node)?;
    let key = params.as_ref().and_then(|p| {
        p.get("key")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    if let Some(key) = key {
        let p = governed_param(&key).ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("{key} is not a governed network parameter"),
            data: None,
        })?;
        return Ok(param_json(&chain, p));
    }
    Ok(json!({
        "epoch": params_epoch(&chain),
        "params": GOVERNED_PARAMS.iter().map(|p| param_json(&chain, p)).collect::<Vec<_>>(),
        "treasury_reserve": reserve_json(&chain),
    }))
}

/// How a lever is operated.
fn lever_kind(p: &GovernedParam) -> &'static str {
    if p.tighten == Tighten::Retire {
        "status"
    } else if p.min == 0 && p.max == 1 && p.key.ends_with("_enabled") {
        "switch"
    } else {
        "value"
    }
}

/// The status `value` names for a lever of `kind`, if it has one.
fn lever_status_name(kind: &str, value: u64) -> Option<&'static str> {
    match kind {
        "status" => Some(LeverStatus::from_value(value).as_str()),
        "switch" => Some(if value == 1 { "enabled" } else { "paused" }),
        _ => None,
    }
}

fn lever_json(chain: &dyn VmState, p: &GovernedParam) -> Value {
    let kind = lever_kind(p);
    let value = network_param(chain, p.key);
    json!({
        "key": p.key,
        "area": p.key.split('.').next().unwrap_or(p.key),
        "kind": kind,
        "value": value.to_string(),
        "status": if kind == "status" {
            Some(tenzro_vm::native::lever_status(chain, p.key).as_str())
        } else {
            lever_status_name(kind, value)
        },
        "guardian_pause_until_epoch": (kind == "status")
            .then(|| tenzro_vm::native::feature_pause::pause_of(chain, p.key).until_epoch)
            .filter(|until| *until > params_epoch(chain)),
        "genesis": p.genesis.to_string(),
        "min": p.min.to_string(),
        "max": p.max.to_string(),
        "tightens": p.tighten,
        "description": p.description,
        "pending": pending_param(chain, p.key).map(|c| json!({
            "value": c.value.to_string(),
            "status": lever_status_name(kind, c.value),
            "activates_epoch": c.activates_epoch,
            "proposal_id": c.proposal_id,
        })),
    })
}

/// `tenzro_listLevers { area? }`.
pub(crate) async fn handle_list_levers(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let chain = crate::rpc::chain_state(node)?;
    let area = params.as_ref().and_then(|p| {
        p.get("area")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let wanted = |key: &str| {
        area.as_deref()
            .is_none_or(|a| key.split('.').next() == Some(a))
    };
    let levers: Vec<Value> = GOVERNED_PARAMS
        .iter()
        .filter(|p| wanted(p.key))
        .map(|p| lever_json(&chain, p))
        .collect();
    let routes: Vec<Value> = if wanted("bridge.") {
        crate::bridge_routes::NodeRouteState::open(node)?
            .list()
            .iter()
            .map(|r| {
                let stop = bridge_route_stop(&chain, r.adapter, &r.source_chain);
                json!({
                    "adapter": r.adapter.as_str(),
                    "source_chain": r.source_chain,
                    "mode": stop.as_ref().map_or("open", |(m, _)| m.as_str()),
                    "reason": stop.map(|(_, why)| why),
                    "transport_lever": bridge_adapter_status_key(r.adapter),
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(json!({
        "epoch": params_epoch(&chain),
        "total": levers.len(),
        "levers": levers,
        "bridge_routes": routes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every lever is classified, every status lever reads as one of the
    /// three statuses, and the switches are the `_enabled` flags.
    #[test]
    fn every_lever_has_a_kind_and_status_levers_name_their_status() {
        let mut statuses = 0;
        for p in GOVERNED_PARAMS {
            let kind = lever_kind(p);
            match kind {
                "status" => {
                    statuses += 1;
                    assert!(p.key.ends_with(".status"), "{}", p.key);
                    assert_eq!(lever_status_name(kind, 0), Some("enabled"));
                    assert_eq!(lever_status_name(kind, 1), Some("paused"));
                    assert_eq!(lever_status_name(kind, 2), Some("retired"));
                }
                "switch" => assert!(p.key.ends_with("_enabled"), "{}", p.key),
                _ => assert_eq!(lever_status_name(kind, p.genesis), None),
            }
        }
        assert!(statuses >= 23);
        assert_eq!(
            lever_kind(governed_param("payments.attested_enabled").unwrap()),
            "switch"
        );
    }
}
