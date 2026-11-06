//! Governed bridge routes, read from and written to consensus state.
//!
//! A route is written only by an enacted `SetBridgeRoute` governance proposal
//! and lives under the governed-state address in committed VM state.
//! [`NodeRouteState`] is the view the route framework
//! ([`tenzro_bridge::route::RouteFramework`]) works against: routes, circuit
//! breakers and network-wide mint limits as governance set them, and the
//! framework's own nonces, epoch totals, sequences and supply records under
//! the same address. `tenzro_listBridgeRoutes` / `tenzro_getBridgeRoute`
//! publish the same records, so anyone can audit which committees, caps and
//! supply every node enforces.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_bridge::route::lane::{LaneDirection, lane_bucket};
use tenzro_bridge::route::state::{RouteState, epoch_usage, read_supply};
use tenzro_bridge::route::{
    BridgeRoute, BridgeRouteAdapter, MintRateLimit, RouteFramework, VerifierQuorum,
};
use tenzro_bridge::{BridgeError, Result as BridgeResult};
use tenzro_storage::{CF_STATE, KvStore};
use tenzro_types::bridge_route::BRIDGE_ROUTE_KEY_PREFIX;
use tenzro_vm::VmState;
use tenzro_vm::native::GOVERNED_STATE_ADDRESS;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Committed consensus state as the route framework sees it, for reading.
/// Route state is written only by `Bridge` transactions in a block
/// (`tenzro_vm::native::bridge`), so this view refuses writes.
pub struct NodeRouteState {
    storage: Arc<dyn KvStore>,
    state: tenzro_vm::StateAdapter,
    chain_id: u64,
    epoch: u64,
    now_ms: i64,
}

impl NodeRouteState {
    /// The view over `storage` for this node's chain, at the current epoch
    /// and wall-clock time.
    pub(crate) fn open(node: &Arc<TenzroNode>) -> Result<Self, JsonRpcError> {
        let storage: Arc<dyn KvStore> = node
            .storage()
            .cloned()
            .ok_or_else(|| rpc_err(-32603, "Storage not initialized"))?;
        Self::over(storage, chain_id(node))
    }

    /// The view over `storage` for the chain `chain_id`.
    pub(crate) fn over(storage: Arc<dyn KvStore>, chain_id: u64) -> Result<Self, JsonRpcError> {
        let state = tenzro_vm::StateAdapter::with_storage(storage.clone());
        let epoch = tenzro_vm::native::read_reward_state(&state)
            .map_err(|e| rpc_err(-32603, format!("epoch unavailable: {e}")))?
            .current_epoch;
        Ok(Self {
            storage,
            state,
            chain_id,
            epoch,
            now_ms: chrono::Utc::now().timestamp_millis(),
        })
    }

    /// Every installed route, in key order. A record that does not decode is
    /// skipped here; the framework refuses it by the same rule.
    pub fn list(&self) -> Vec<BridgeRoute> {
        let prefix = format!(
            "storage:{}:{}",
            hex::encode(GOVERNED_STATE_ADDRESS),
            hex::encode(BRIDGE_ROUTE_KEY_PREFIX.as_bytes())
        );
        self.storage
            .scan_prefix(CF_STATE, prefix.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }
}

impl RouteState for NodeRouteState {
    fn local_chain_id(&self) -> u64 {
        self.chain_id
    }

    fn now_ms(&self) -> i64 {
        self.now_ms
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn route(&self, adapter: BridgeRouteAdapter, chain: &str) -> Option<BridgeRoute> {
        tenzro_vm::native::read_bridge_route(&self.state, adapter, chain)
    }

    fn stopped(
        &self,
        route: &BridgeRoute,
    ) -> Option<(tenzro_types::bridge_route::BridgeRouteMode, String)> {
        tenzro_vm::native::bridge_route_stop(&self.state, route.adapter, &route.source_chain)
    }

    fn network_limit(&self, route: &BridgeRoute) -> Option<MintRateLimit> {
        tenzro_vm::native::read_bridge_mint_limits(&self.state).map(|l| l.for_route(route))
    }

    fn outflow_limits(&self) -> Option<tenzro_types::bridge_route::NetworkOutflowLimits> {
        tenzro_vm::native::security::outflow_limits_in_force(&self.state)
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.state
            .get_storage(&GOVERNED_STATE_ADDRESS, key.as_bytes())
            .filter(|v| !v.is_empty())
    }

    fn apply(&mut self, _writes: Vec<(String, Vec<u8>)>) -> BridgeResult<()> {
        Err(BridgeError::InvalidParameter(
            "route state is written only by Bridge transactions in a block".into(),
        ))
    }
}

fn rpc_err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// A supply record with its amounts as decimal strings, as every other
/// amount on the RPC surface is.
pub(crate) fn supply_json(supply: &tenzro_bridge::route::state::SupplyRecord) -> Value {
    json!({
        "locked": supply.locked.to_string(),
        "bridged": supply.bridged.to_string(),
    })
}

/// This node's chain id.
pub(crate) fn chain_id(node: &Arc<TenzroNode>) -> u64 {
    node.config().chain_id()
}

fn quorum_json(q: &VerifierQuorum) -> Value {
    json!({
        "set_index": q.set_index,
        "threshold": q.threshold,
        "size": q.size,
        "drawn": q.members.len() == q.size as usize && q.size > 0,
        "members": q.members.iter().map(|m| json!({
            "address": format!("0x{}", hex::encode(m.address)),
            "operator": m.operator,
            "rpc_provider": m.rpc_provider,
        })).collect::<Vec<_>>(),
    })
}

/// The route's latest drawn verifier committees, each with its expiry and
/// the digest the committee before it signs to hand bridge contracts over to
/// it.
fn committee_sets_json(state: &NodeRouteState, route: &BridgeRoute) -> Vec<Value> {
    let key = route.storage_key();
    let last = route.verifiers.set_index;
    (last.saturating_sub(3)..=last)
        .filter_map(|i| tenzro_vm::native::bridge_committee::read_committee_set(&state.state, &key, i))
        .map(|set| {
            let digest = tenzro_vm::native::bridge_committee::handover_digest(state.chain_id, route, &set);
            json!({
                "set_index": set.quorum.set_index,
                "threshold": set.quorum.threshold,
                "members": set.quorum.members.iter().map(|m| format!("0x{}", hex::encode(m.address))).collect::<Vec<_>>(),
                "expires_at_secs": set.expires_at_secs,
                "handover_digest": format!("0x{}", hex::encode(digest)),
            })
        })
        .collect()
}

/// A route as the read RPCs publish it: its record, whether it passes the
/// route rules, whether its breaker holds it, what it may still mint this
/// epoch, and its supply record.
fn route_json(framework: &RouteFramework, state: &NodeRouteState, route: &BridgeRoute) -> Value {
    let violation = route.validate().err().map(|e| e.to_string());
    let circuit =
        tenzro_vm::native::read_bridge_circuit(&state.state, route.adapter, &route.source_chain);
    let network = state.network_limit(route);
    let usage = network.map(|n| epoch_usage(state, route, n));
    json!({
        "key": route.storage_key(),
        "record": route,
        "adapter": route.adapter.as_str(),
        "family": route.family.as_str(),
        "source_chain": route.source_chain,
        "source_chain_id": route.source_chain_id,
        "local_selector": route.local_selector,
        "peer": format!("0x{}", hex::encode(route.peer)),
        "ramp": format!("0x{}", hex::encode(route.ramp)),
        "local_endpoint": format!("0x{}", hex::encode(route.local_endpoint)),
        "remote_token": format!("0x{}", hex::encode(route.remote_token)),
        "verifiers": quorum_json(&route.verifiers),
        "committee_sets": committee_sets_json(state, route),
        "blessing": route.blessing.as_ref().map(quorum_json),
        "assets": route.assets.iter().map(|a| {
            let supply = tenzro_bridge::route::state::read_asset_supply(state, route, a);
            json!({
                "symbol": a.symbol,
                "caip19": a.caip19,
                "representation": hex::encode(a.representation_id()),
                "enabled": a.enabled,
                "max_outstanding": a.max_outstanding.to_string(),
                "vault_holds": supply.locked.to_string(),
                "issued": supply.bridged.to_string(),
            })
        }).collect::<Vec<_>>(),
        "native_asset": route.native_asset,
        "light_client": route.light_client,
        "light_client_head": framework.light_client_head(state, route),
        "finality_depth": framework.finality_depth(route).ok(),
        "mint_limit": {
            "per_mint": route.mint_limit.per_mint.to_string(),
            "per_epoch": route.mint_limit.per_epoch.to_string(),
            "network_per_mint": network.map(|n| n.per_mint.to_string()),
            "network_per_epoch": network.map(|n| n.per_epoch.to_string()),
            "epoch": state.epoch(),
            "minted_this_epoch": usage.map(|u| u.minted.to_string()),
            "remaining_this_epoch": usage.map(|u| u.remaining.to_string()),
        },
        "lane": route.lane_limits.map(|l| json!({
            "version": l.version.as_str(),
            "off_ramp": format!("0x{}", hex::encode(l.off_ramp)),
            "ccv_and_executor_hash": format!("0x{}", hex::encode(l.ccv_and_executor_hash)),
            "outbound": lane_bucket(state, route, LaneDirection::Outbound),
            "inbound": lane_bucket(state, route, LaneDirection::Inbound),
        })),
        "supply": supply_json(&read_supply(state, route)),
        "ibc": route.ibc.as_ref().map(|_| tenzro_bridge::route::ibc_core::status(state, route).ok()),
        "mode": circuit.as_ref().map_or("open", |c| c.mode.as_str()),
        "circuit": circuit,
        "placeholders": tenzro_vm::native::read_route_placeholders(&state.state, route.adapter, &route.source_chain),
        "open_refusal": tenzro_vm::native::bridge_route_open_refusal(&state.state, route.adapter, &route.source_chain),
        "enforced": violation.is_none(),
        "violation": violation,
    })
}

/// `tenzro_listBridgeRoutes` — every governed route.
pub(crate) async fn handle_list_bridge_routes(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let state = NodeRouteState::open(node)?;
    let framework = node.route_framework();
    let routes: Vec<Value> = state
        .list()
        .iter()
        .map(|r| route_json(framework, &state, r))
        .collect();
    Ok(json!({ "total": routes.len(), "routes": routes }))
}

/// `tenzro_getBridgeRoute` — the route for `{adapter, source_chain}`.
pub(crate) async fn handle_get_bridge_route(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let p = params.as_array().and_then(|a| a.first()).unwrap_or(&params);
    let field = |key: &str| {
        p.get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| rpc_err(-32602, format!("missing required parameter: {key}")))
    };
    let adapter_name = field("adapter")?;
    let adapter = BridgeRouteAdapter::parse(adapter_name).ok_or_else(|| {
        rpc_err(
            -32602,
            format!(
                "'{adapter_name}' is not a route transport ({})",
                BridgeRouteAdapter::names()
            ),
        )
    })?;
    let source_chain = field("source_chain")?;
    let state = NodeRouteState::open(node)?;
    match state.route(adapter, &source_chain.to_ascii_lowercase()) {
        Some(route) => Ok(route_json(node.route_framework(), &state, &route)),
        None => Err(rpc_err(
            -32004,
            format!(
                "no governed {} route for '{source_chain}'; traffic on it is refused",
                adapter.as_str()
            ),
        )),
    }
}

/// `tenzro_getBridgeOutflow` — the network-wide exit limits as consensus
/// state holds them: for each unit, the cap in force per epoch (the lower of
/// the governed cap and the stake-backed one), the governed cap, how much has
/// left over every route together this epoch and how much waits in the exit
/// queue; the security ratio and its inputs; the exit delay rule; the most
/// one proposal may raise a cap; and the last exit id queued.
pub(crate) async fn handle_get_bridge_outflow(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_vm::governance as g;
    let state = NodeRouteState::open(node)?;
    let governed = tenzro_vm::native::read_bridge_outflow_limits(&state.state);
    let units: Vec<Value> = governed
        .as_ref()
        .map(|l| l.caps.clone())
        .unwrap_or_default()
        .iter()
        .filter_map(|c| {
            let usage = tenzro_bridge::route::state::outflow_usage(&state, &c.unit)?;
            let mut u = json!(usage);
            u["governed_per_epoch"] = json!(c.per_epoch.to_string());
            u["queued"] =
                json!(tenzro_vm::native::bridge_exit::queued(&state.state, &c.unit).to_string());
            Some(u)
        })
        .collect();
    let param = |key| tenzro_vm::native::network_param(&state.state, key);
    Ok(json!({
        "epoch": state.epoch,
        "units": units,
        "security": tenzro_vm::native::security::report(&state.state),
        "queue_max_epochs": param(tenzro_vm::native::security::QUEUE_MAX_EPOCHS_PARAM),
        "exit_delay_threshold_bps": param(g::BRIDGE_EXIT_DELAY_THRESHOLD_PARAM),
        "exit_delay_ms": param(g::BRIDGE_EXIT_DELAY_PARAM),
        "max_cap_raise_bps": param(g::MAX_CAP_RAISE_PARAM),
        "last_exit_id": tenzro_vm::native::bridge_exit::last_exit_id(&state.state),
    }))
}

/// `tenzro_getBridgeExit` — the queued exit `{id}`: who sent it, where to,
/// how much, and when it may be released.
pub(crate) async fn handle_get_bridge_exit(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let p = params.as_array().and_then(|a| a.first()).unwrap_or(&params);
    let id = p
        .get("id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| rpc_err(-32602, "missing required parameter: id"))?;
    let state = NodeRouteState::open(node)?;
    let exit = tenzro_vm::native::bridge_exit::read_exit(&state.state, id).ok_or_else(|| {
        rpc_err(
            -32004,
            format!("no exit {id} is queued; it was released, cancelled or never queued"),
        )
    })?;
    let faulted = tenzro_vm::native::bridge_exit::faulted_since_queued(&state.state, &exit);
    let mut out = json!(exit);
    out["cancellable_by_anyone"] = json!(faulted);
    Ok(out)
}

/// `tenzro_getBridgeOutbound` — the outbound record `sequence` of the route
/// `{adapter, source_chain}`, as relayers and signers take it. For a deposit
/// route it is a withdrawal: its transaction id, the outputs it spends and
/// pays, and the digest each input is signed over.
pub(crate) async fn handle_get_bridge_outbound(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_bridge::route::bitcoin::route_descriptor;
    use tenzro_bridge::route::bitcoin_spend::Withdrawal;
    let params = params.unwrap_or(Value::Null);
    let p = params.as_array().and_then(|a| a.first()).unwrap_or(&params);
    let adapter_name = p
        .get("adapter")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let adapter = BridgeRouteAdapter::parse(adapter_name).ok_or_else(|| {
        rpc_err(
            -32602,
            format!(
                "'{adapter_name}' is not a route transport ({})",
                BridgeRouteAdapter::names()
            ),
        )
    })?;
    let source_chain = p
        .get("source_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| rpc_err(-32602, "missing required parameter: source_chain"))?
        .to_ascii_lowercase();
    let sequence = p
        .get("sequence")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| rpc_err(-32602, "missing required parameter: sequence"))?;
    let state = NodeRouteState::open(node)?;
    let route = state.route(adapter, &source_chain).ok_or_else(|| {
        rpc_err(
            -32004,
            format!(
                "no governed {} route for '{source_chain}'",
                adapter.as_str()
            ),
        )
    })?;
    let bytes = state
        .get(&tenzro_bridge::route::state::outbound_key(&route, sequence))
        .ok_or_else(|| {
            rpc_err(
                -32004,
                format!(
                    "route {} has no outbound record {sequence}",
                    route.storage_key()
                ),
            )
        })?;
    let mut out = json!({
        "route": route.storage_key(),
        "sequence": sequence,
        "message": format!("0x{}", hex::encode(&bytes)),
    });
    if adapter == BridgeRouteAdapter::Deposit {
        let bad = |e: tenzro_bridge::BridgeError| rpc_err(-32603, e.to_string());
        let (desc, _) = route_descriptor(&route).map_err(bad)?;
        let w = Withdrawal::decode(&bytes).map_err(bad)?;
        let sighashes = (0..w.tx.inputs.len())
            .map(|i| w.sighash(&desc, i).map(|d| format!("0x{}", hex::encode(d))))
            .collect::<Result<Vec<_>, _>>()
            .map_err(bad)?;
        let mut txid = w.txid();
        txid.reverse();
        out["withdrawal"] = json!({
            "txid": hex::encode(txid),
            "inputs": w.tx.inputs.iter().zip(&w.values).map(|(i, v)| {
                let mut id: [u8; 32] = i.prevout[..32].try_into().expect("32 bytes");
                id.reverse();
                json!({ "txid": hex::encode(id), "vout": u32::from_le_bytes(i.prevout[32..].try_into().expect("4 bytes")), "value": v })
            }).collect::<Vec<_>>(),
            "outputs": w.tx.outputs.iter().map(|o| json!({ "value": o.value, "script": hex::encode(&o.script) })).collect::<Vec<_>>(),
            "sighashes": sighashes,
            "descriptor": desc.descriptor(),
            "signers": desc.signers.iter().map(hex::encode).collect::<Vec<_>>(),
            "threshold": desc.threshold,
        });
    }
    if adapter == BridgeRouteAdapter::Ibc {
        use tenzro_bridge::route::ibc::Packet;
        use tenzro_bridge::route::ibc_core::{packet_status, store_key};
        let bad = |e: tenzro_bridge::BridgeError| rpc_err(-32603, e.to_string());
        let version = route
            .ibc
            .as_ref()
            .map(|i| i.version)
            .ok_or_else(|| rpc_err(-32603, "the IBC route has no settings"))?;
        let packet = Packet::decode(&bytes, version).map_err(bad)?;
        let path = packet.commitment_key();
        out["packet"] = json!({
            "version": version.as_str(),
            "commitment_path": format!("0x{}", hex::encode(&path)),
            "commitment": format!("0x{}", hex::encode(packet.commitment())),
            "state_key": format!("0x{}", hex::encode(store_key(&path))),
            "timeout_timestamp": packet.timeout_timestamp,
            "status": packet_status(&state, &route, sequence).map_err(bad)?,
        });
    }
    Ok(out)
}
