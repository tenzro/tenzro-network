//! Proof of Reserve on bridge routes, cross-checked with the route
//! framework's supply record.
//!
//! A route's reserve feed is installed by a `SetReserveFeed` governance vote
//! under the asset id `tnzo:<route key>` ([`reserve_asset_id`]); validators
//! read only the aggregator consensus names. It reports the
//! TNZO held on Tenzro behind the route's representation, as an independent
//! oracle network observes it. Once per epoch a validator reads the feed of
//! every live route and sets it against the route's supply record
//! ([`tenzro_bridge::route::reserve::cross_check`]). A reading the record
//! cannot explain is flagged as a `TripBridge` finding with the round as
//! evidence; the route pauses once validators holding two thirds of bonded
//! stake have flagged the same round. `tenzro_readPorReserve` on a route's
//! asset id returns the same check.

use std::sync::Arc;

use serde_json::Value;
use tenzro_bridge::PorReading;
use tenzro_bridge::route::BridgeRoute;
use tenzro_bridge::route::reserve::{ReserveCheck, cross_check, reserve_asset_id};
use tenzro_bridge::route::state::{RouteState, SupplyRecord, read_supply};
use tenzro_types::bridge_route::MintRateLimit;
use tracing::warn;

use crate::bridge_routes::NodeRouteState;
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A route with the records its reserve is checked against.
struct RouteView {
    route: BridgeRoute,
    supply: SupplyRecord,
    network: MintRateLimit,
    paused: bool,
}

fn views(state: &NodeRouteState) -> Vec<RouteView> {
    state
        .list()
        .into_iter()
        .map(|route| RouteView {
            supply: read_supply(state, &route),
            network: state.network_limit(&route).unwrap_or(route.mint_limit),
            paused: state.stopped(&route).is_some_and(|(mode, _)| {
                mode == tenzro_types::bridge_route::BridgeRouteMode::Paused
            }),
            route,
        })
        .collect()
}

/// The reserve feed governance installed for `asset_id`, if any.
pub(crate) fn installed_feed(
    node: &TenzroNode,
    asset_id: &str,
) -> Option<tenzro_types::ReserveFeed> {
    let state = node.chain_state()?;
    tenzro_vm::native::economy::read_reserve_feed(&state, asset_id)
}

/// Read the live reserve of `asset_id` through its installed feed.
pub(crate) async fn read_installed(
    node: &Arc<TenzroNode>,
    asset_id: &str,
) -> Result<(tenzro_types::ReserveFeed, PorReading), JsonRpcError> {
    let feed = installed_feed(node, asset_id).ok_or_else(|| JsonRpcError {
        code: -32001,
        message: format!(
            "no reserve feed is installed for {asset_id}; one is set by a SetReserveFeed vote"
        ),
        data: None,
    })?;
    let reading = node
        .chainlink_por_adapter()
        .read_reserve(&feed)
        .await
        .map_err(|e| JsonRpcError {
            code: -32001,
            message: format!("PoR read failed: {e}"),
            data: None,
        })?;
    Ok((feed, reading))
}

fn check(view: &RouteView, reading: &PorReading) -> Option<ReserveCheck> {
    match cross_check(&view.route, &view.supply, view.network, reading, now_secs()) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!(route = %view.route.storage_key(), error = %e, "reserve reading not usable");
            None
        }
    }
}

/// The cross-check for `asset_id` when it names a route's reserve feed, as
/// `tenzro_readPorReserve` returns it beside the reading.
pub(crate) fn route_check(
    node: &Arc<TenzroNode>,
    asset_id: &str,
    reading: &PorReading,
) -> Result<Option<Value>, JsonRpcError> {
    if !asset_id.starts_with("tnzo:") {
        return Ok(None);
    }
    let state = NodeRouteState::open(node)?;
    Ok(views(&state)
        .iter()
        .find(|v| reserve_asset_id(&v.route) == asset_id)
        .and_then(|v| check(v, reading))
        .and_then(|c| serde_json::to_value(c).ok()))
}

/// Read every live route's reserve feed and flag the routes whose reserve
/// the supply record cannot explain, as findings of `epoch`.
pub(crate) async fn watch_reserves(node: &Arc<TenzroNode>, epoch: u64) {
    let Ok(state) = NodeRouteState::open(node) else {
        return;
    };
    let routes = views(&state);
    drop(state);
    let feeds = node.chainlink_por_adapter();
    let mut findings = Vec::new();
    for view in routes.iter().filter(|v| !v.paused) {
        let asset = reserve_asset_id(&view.route);
        let Some(feed) = installed_feed(node, &asset) else {
            continue;
        };
        let reading = match feeds.read_reserve(&feed).await {
            Ok(r) => r,
            Err(e) => {
                warn!(route = %view.route.storage_key(), error = %e, "reserve feed unreadable");
                continue;
            }
        };
        if let Some(c) = check(view, &reading).filter(|c| !c.holds) {
            warn!(
                route = %c.route,
                reserve = %c.reserve,
                locked = %c.locked,
                allowance = %c.allowance,
                "reserve disagrees with the route's supply record; flagging the route"
            );
            findings.push(tenzro_types::agent_audit::AuditFinding::TripBridge {
                adapter: view.route.adapter,
                source_chain: view.route.source_chain.clone(),
                evidence_hash: c.evidence_hash(),
                reason: c.reason(),
            });
        }
    }
    if !findings.is_empty() {
        crate::agent_audit::submit_flag(node, epoch, findings)
            .await
            .ok();
    }
}
