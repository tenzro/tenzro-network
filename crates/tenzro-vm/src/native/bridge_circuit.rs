//! The bridge circuit breaker and the network-wide bridge mint limits.
//!
//! Each governed bridge route has its own breaker, which holds the route
//! [`BridgeRouteMode::Disabled`] (winding down: nothing new goes out, TNZO
//! already sent out can still come back) or [`BridgeRouteMode::Paused`]
//! (nothing moves). Validators holding two thirds of bonded stake pause a
//! route on a finding (see [`super::agent_audit`]); governance sets any mode,
//! disabling or pausing on the expedited track if it must be quick. Only
//! governance opens a route, and only one whose fields are all filled and
//! whose light client has been bootstrapped from its anchor. Every node reads
//! the mode from chain state.
//!
//! The network-wide mint limits bound what any one route may mint per mint
//! and per epoch, on top of the route's own limits. Genesis writes a starting
//! value; governance replaces it.

use serde::{Deserialize, Serialize};
use tenzro_types::bridge_route::{
    BridgeRoute, BridgeRouteAdapter, BridgeRouteMode, NetworkMintLimits, NetworkOutflowLimits,
    OutflowCap, TNZO_UNIT, bridge_route_storage_key,
};

use super::funding::{read_json, write_json};
use super::*;

/// Topic of the log a route's breaker emits when it trips.
pub const BRIDGE_CIRCUIT_TOPIC: &[u8] = b"BridgeCircuitTripped";
/// Topic of the log a route's breaker emits when governance lifts it.
pub const BRIDGE_CIRCUIT_LIFTED_TOPIC: &[u8] = b"BridgeCircuitLifted";
/// Storage key of the network-wide bridge mint limits.
pub const BRIDGE_MINT_LIMITS_KEY: &str = "bridge_mint_limits";
/// Starting network-wide cap on one bridge mint, whole TNZO.
pub const DEFAULT_BRIDGE_MINT_PER_MINT_TNZO: u64 = 10_000;
/// Starting network-wide limit on what one route mints per epoch, whole TNZO.
pub const DEFAULT_BRIDGE_MINT_PER_EPOCH_TNZO: u64 = 100_000;
/// Starting cap on one mint through a route without a light client, whole
/// TNZO.
pub const DEFAULT_BRIDGE_ATTESTED_PER_MINT_TNZO: u64 = 2_000;
/// Starting limit on what one route without a light client mints per epoch,
/// whole TNZO.
pub const DEFAULT_BRIDGE_ATTESTED_PER_EPOCH_TNZO: u64 = 20_000;
/// Starting cap on one mint through any route whose destination verifies
/// only classical signatures (every route today), whole TNZO. Low on
/// purpose: it is the most that can be minted against the external chain's
/// own signature scheme, which a break of classical cryptography forges.
pub const DEFAULT_BRIDGE_CLASSICAL_PER_MINT_TNZO: u64 = 500;
/// Starting limit on what one such route mints per epoch, whole TNZO.
pub const DEFAULT_BRIDGE_CLASSICAL_PER_EPOCH_TNZO: u64 = 2_000;
/// Storage key of the network-wide outflow caps.
pub const BRIDGE_OUTFLOW_LIMITS_KEY: &str = "bridge_outflow_limits";
/// Starting network-wide cap on TNZO leaving over all routes in one epoch,
/// whole TNZO.
pub const DEFAULT_BRIDGE_OUTFLOW_PER_EPOCH_TNZO: u64 = 100_000;

/// The outflow caps a network starts with when its genesis names none:
/// TNZO only.
pub fn default_bridge_outflow() -> NetworkOutflowLimits {
    NetworkOutflowLimits {
        caps: vec![OutflowCap {
            unit: TNZO_UNIT.to_string(),
            per_epoch: u128::from(DEFAULT_BRIDGE_OUTFLOW_PER_EPOCH_TNZO)
                * tenzro_types::constants::ONE_TNZO,
        }],
    }
}

/// The network-wide outflow caps, if set.
pub fn read_bridge_outflow_limits(state: &dyn VmState) -> Option<NetworkOutflowLimits> {
    read_json(state, BRIDGE_OUTFLOW_LIMITS_KEY)
}

/// The most one enacted proposal may raise a cap to, bps of its value.
pub fn max_cap_raise_bps(state: &dyn VmState) -> u64 {
    network_param(state, crate::governance::MAX_CAP_RAISE_PARAM)
}

/// Refuse a route that would raise the caps of the installed route it
/// replaces by more than one step allows. A route genesis left with
/// placeholders has carried nothing and takes its caps whole.
pub fn check_route_raise(state: &dyn VmState, route: &BridgeRoute) -> Result<()> {
    let Some(current) = read_bridge_route(state, route.adapter, &route.source_chain) else {
        return Ok(());
    };
    if !read_route_placeholders(state, route.adapter, &route.source_chain).is_empty() {
        return Ok(());
    }
    route
        .raised_within(&current, max_cap_raise_bps(state))
        .map_err(|e| VmError::InvalidTransaction(format!("bridge route refused: {e}")))
}

/// Who stopped a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCircuitAuthority {
    /// Validators holding two thirds of bonded stake, on anomaly evidence.
    Validators,
    /// An enacted governance policy update, or genesis.
    Governance,
    /// A proven reconciliation mismatch of the route's settlement lock.
    Reconciliation,
}

/// A stopped route as chain state records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCircuitTrip {
    /// The route's bridge protocol.
    pub adapter: BridgeRouteAdapter,
    /// The route's external chain.
    pub source_chain: String,
    /// Disabled or paused.
    pub mode: BridgeRouteMode,
    /// Who stopped it.
    pub by: BridgeCircuitAuthority,
    /// Why.
    pub reason: String,
    /// SHA-256 of the anomaly evidence, hex, for a validator trip.
    pub evidence_hash: Option<String>,
    /// Epoch it was stopped in.
    pub epoch: u64,
    /// Block time, ms.
    pub at_ms: i64,
}

/// Where chain state (under the system address) records the route's mode.
pub fn circuit_key(adapter: BridgeRouteAdapter, source_chain: &str) -> String {
    format!(
        "bridge_circuit:{}",
        bridge_route_storage_key(adapter, source_chain)
    )
}

/// Where chain state records the fields of a route that genesis left as
/// placeholders.
pub fn placeholders_key(adapter: BridgeRouteAdapter, source_chain: &str) -> String {
    format!(
        "bridge_placeholders:{}",
        bridge_route_storage_key(adapter, source_chain)
    )
}

/// The record that stops the route `(adapter, source_chain)`, if one does.
pub fn read_bridge_circuit(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
) -> Option<BridgeCircuitTrip> {
    read_json(state, &circuit_key(adapter, source_chain))
}

/// What stops the route `(adapter, source_chain)` now, and why: the stricter
/// of the route's own circuit record and its transport's status lever. A
/// paused transport carries nothing; a retired one winds down as a disabled
/// route does.
pub fn bridge_route_stop(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
) -> Option<(BridgeRouteMode, String)> {
    // Without a block time a watcher's self-expiring pause is not read;
    // the adapters that gate a route's mints and releases use
    // [`bridge_route_stop_at`].
    bridge_route_stop_at(state, adapter, source_chain, i64::MIN)
}

/// [`bridge_route_stop`] at block time `now_ms`, which also reads the pause a
/// bonded watcher holds on the route (see `bridge_watcher`).
pub fn bridge_route_stop_at(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
    now_ms: i64,
) -> Option<(BridgeRouteMode, String)> {
    use crate::governance::LeverStatus;
    let record = read_bridge_circuit(state, adapter, source_chain).map(|t| (t.mode, t.reason));
    let lever = crate::governance::bridge_adapter_status_key(adapter).and_then(|key| {
        let mode = match super::lever_status(state, key) {
            LeverStatus::Enabled => return None,
            LeverStatus::Paused => BridgeRouteMode::Paused,
            LeverStatus::Retired => BridgeRouteMode::Disabled,
        };
        Some((
            mode,
            format!(
                "{} by governance ({key})",
                super::lever_status(state, key).as_str()
            ),
        ))
    });
    let rank = |m: BridgeRouteMode| match m {
        BridgeRouteMode::Open => 0,
        BridgeRouteMode::Disabled => 1,
        BridgeRouteMode::Paused => 2,
    };
    let base = match (record, lever) {
        (Some(r), Some(l)) => Some(if rank(l.0) > rank(r.0) { l } else { r }),
        (r, l) => r.or(l),
    };
    let watcher = super::bridge_watcher::stop_at(state, adapter, source_chain, now_ms);
    match (base, watcher) {
        (Some(b), Some(w)) => Some(if rank(w.0) > rank(b.0) { w } else { b }),
        (b, w) => b.or(w),
    }
}

/// The route's mode: open unless a record stops it.
pub fn read_bridge_route_mode(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
) -> BridgeRouteMode {
    read_bridge_circuit(state, adapter, source_chain).map_or(BridgeRouteMode::Open, |t| t.mode)
}

/// The route fields genesis left as placeholders and no governance vote has
/// filled since.
pub fn read_route_placeholders(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
) -> Vec<String> {
    read_json(state, &placeholders_key(adapter, source_chain)).unwrap_or_default()
}

/// The network-wide mint limits every route is bound by, when set.
pub fn read_bridge_mint_limits(state: &dyn VmState) -> Option<NetworkMintLimits> {
    read_json(state, BRIDGE_MINT_LIMITS_KEY)
}

fn clear(state: &mut dyn VmState, key: String, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    if prior.as_ref().is_none_or(|p| p.is_empty()) {
        return;
    }
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(Vec::new()),
    ));
}

/// Forget a route's placeholders: governance installed the route whole.
pub(super) fn clear_placeholders(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
    changes: &mut Vec<StateChange>,
) {
    clear(state, placeholders_key(adapter, source_chain), changes);
}

/// Stop a route. A validator trip pauses and a reconciliation trip disables:
/// neither weakens a stricter record nor replaces a pause, so the evidence
/// that stopped the route is not overwritten. Governance replaces whatever
/// record is there.
pub(super) fn trip(
    state: &mut dyn VmState,
    trip: &BridgeCircuitTrip,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let existing = read_bridge_circuit(state, trip.adapter, &trip.source_chain);
    if trip.by != BridgeCircuitAuthority::Governance
        && existing
            .as_ref()
            .is_some_and(|e| e.mode == BridgeRouteMode::Paused || e.mode == trip.mode)
    {
        return Ok(());
    }
    write_json(
        state,
        &circuit_key(trip.adapter, &trip.source_chain),
        trip,
        changes,
    )?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![BRIDGE_CIRCUIT_TOPIC.to_vec()],
        serde_json::to_vec(trip).map_err(|e| VmError::Internal(format!("encode trip log: {e}")))?,
    ));
    Ok(())
}

/// Why the route `(adapter, source_chain)` may not be opened, naming the
/// route and what is missing: it is not installed, a field is still a
/// genesis placeholder, it breaks the route rules, or its light client has
/// not been bootstrapped from its anchor.
pub fn open_refusal(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
) -> Option<String> {
    let key = bridge_route_storage_key(adapter, source_chain);
    let Some(route) = read_bridge_route(state, adapter, source_chain) else {
        return Some(format!("route {key} is not installed"));
    };
    let placeholders = read_route_placeholders(state, adapter, source_chain);
    if !placeholders.is_empty() {
        return Some(format!(
            "route {key} still holds placeholders: {}",
            placeholders.join(", ")
        ));
    }
    if let Err(e) = route.validate() {
        return Some(format!("route {key} breaks the route rules: {e}"));
    }
    if let Some(anchor) = &route.light_client
        && anchor.keeps_state()
        && state
            .get_storage(&SYSTEM_ADDRESS, anchor.store_key(&route).as_bytes())
            .is_none_or(|b| b.is_empty())
    {
        return Some(format!(
            "route {key}: light_client has not been bootstrapped from its anchor; relay the bootstrap first"
        ));
    }
    None
}

/// Apply a bridge policy update enacted by governance: set a route's mode,
/// or replace the network-wide mint limits. Other updates are ignored.
pub(super) fn apply_policy(
    state: &mut dyn VmState,
    update: &tenzro_types::token::PolicyUpdate,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    use tenzro_types::token::PolicyUpdate;
    match update {
        PolicyUpdate::BridgeCircuitSet {
            adapter,
            source_chain,
            mode: BridgeRouteMode::Open,
            ..
        } => {
            let source_chain = source_chain.to_ascii_lowercase();
            if let Some(refusal) = open_refusal(state, *adapter, &source_chain) {
                return Err(VmError::InvalidTransaction(format!(
                    "opening refused: {refusal}"
                )));
            }
            if read_bridge_circuit(state, *adapter, &source_chain).is_none() {
                return Ok(());
            }
            clear(state, circuit_key(*adapter, &source_chain), changes);
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![BRIDGE_CIRCUIT_LIFTED_TOPIC.to_vec()],
                serde_json::to_vec(&serde_json::json!({
                    "adapter": adapter,
                    "source_chain": source_chain,
                    "at_ms": now_ms,
                }))
                .map_err(|e| VmError::Internal(format!("encode lift log: {e}")))?,
            ));
            Ok(())
        }
        PolicyUpdate::BridgeCircuitSet {
            adapter,
            source_chain,
            mode,
            reason,
        } => {
            let epoch = rewards::read_reward_state(state)?.current_epoch;
            trip(
                state,
                &BridgeCircuitTrip {
                    adapter: *adapter,
                    source_chain: source_chain.to_ascii_lowercase(),
                    mode: *mode,
                    by: BridgeCircuitAuthority::Governance,
                    reason: reason.clone(),
                    evidence_hash: None,
                    epoch,
                    at_ms: now_ms,
                },
                changes,
                logs,
            )
        }
        PolicyUpdate::BridgeMintLimitsSet { limits } => {
            limits
                .validate()
                .map_err(|e| VmError::InvalidTransaction(format!("bridge mint limits: {e}")))?;
            if let Some(current) = read_bridge_mint_limits(state) {
                limits
                    .raised_within(&current, max_cap_raise_bps(state))
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
            }
            write_json(state, BRIDGE_MINT_LIMITS_KEY, limits, changes)?;
            Ok(())
        }
        PolicyUpdate::BridgeOutflowLimitsSet { limits } => {
            limits
                .validate()
                .map_err(|e| VmError::InvalidTransaction(format!("bridge outflow limits: {e}")))?;
            let current = read_bridge_outflow_limits(state).unwrap_or_default();
            limits
                .raised_within(&current, max_cap_raise_bps(state))
                .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
            if super::security::raises_any(&current, limits) {
                super::security::require_secure(state, limits, "raising a bridge outflow cap")?;
            }
            write_json(state, BRIDGE_OUTFLOW_LIMITS_KEY, limits, changes)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod raise_tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use tenzro_types::bridge_route::{LaneRateLimit, MintRateLimit};
    use tenzro_types::token::PolicyUpdate;

    fn route(outflow: u128) -> BridgeRoute {
        let mut r: BridgeRoute = serde_json::from_value(serde_json::json!({
            "adapter": "ccip", "family": "evm", "source_chain": "ethereum",
            "source_chain_id": 1, "local_selector": 2,
            "peer": vec![1u8; 32], "ramp": vec![1u8; 32], "local_endpoint": vec![1u8; 32], "remote_token": vec![1u8; 32],
            "verifiers": {"set_index": 0, "size": 0, "members": [], "threshold": 0},
            "blessing": null, "light_client": null,
            "mint_limit": {"per_mint": 10, "per_epoch": 100},
            "outflow": {"capacity": 100, "rate": 1},
            "lane_limits": null, "ibc": null, "settlement_lock": null
        }))
        .unwrap();
        r.outflow = LaneRateLimit {
            capacity: outflow,
            rate: 1,
        };
        r
    }

    #[test]
    fn a_route_update_raises_a_cap_at_most_by_the_governed_factor() {
        let mut state = StateAdapter::new();
        let mut changes = Vec::new();
        // Nothing installed: any caps.
        assert!(check_route_raise(&state, &route(1_000_000)).is_ok());
        let current = route(100);
        write_json(&mut state, &current.storage_key(), &current, &mut changes).unwrap();
        assert!(check_route_raise(&state, &route(200)).is_ok());
        assert!(check_route_raise(&state, &route(50)).is_ok());
        let err = check_route_raise(&state, &route(201)).unwrap_err();
        assert!(err.to_string().contains("outflow.capacity"), "{err}");
        // A route genesis left with placeholders takes its caps whole.
        write_json(
            &mut state,
            &placeholders_key(current.adapter, &current.source_chain),
            &vec!["verifiers".to_string()],
            &mut changes,
        )
        .unwrap();
        assert!(check_route_raise(&state, &route(1_000_000)).is_ok());
    }

    #[test]
    fn network_limit_updates_raise_a_cap_at_most_by_the_governed_factor() {
        let mut state = StateAdapter::new();
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        let caps = |tnzo: u128| NetworkOutflowLimits {
            caps: vec![OutflowCap {
                unit: TNZO_UNIT.into(),
                per_epoch: tnzo,
            }],
        };
        let set = |l| PolicyUpdate::BridgeOutflowLimitsSet { limits: l };
        super::super::staking::add_bond(&mut state, &[1; 32], 1_000_000_000, 0).unwrap();
        apply_policy(&mut state, &set(caps(1_000)), 0, &mut changes, &mut logs).unwrap();
        assert!(apply_policy(&mut state, &set(caps(2_001)), 0, &mut changes, &mut logs).is_err());
        apply_policy(&mut state, &set(caps(2_000)), 0, &mut changes, &mut logs).unwrap();
        apply_policy(&mut state, &set(caps(1)), 0, &mut changes, &mut logs).unwrap();
        assert_eq!(read_bridge_outflow_limits(&state), Some(caps(1)));

        let limits = |m: u128| NetworkMintLimits {
            proven: MintRateLimit {
                per_mint: m,
                per_epoch: 10 * m,
            },
            attested: MintRateLimit {
                per_mint: m / 2,
                per_epoch: 5 * m,
            },
            classical: MintRateLimit {
                per_mint: m / 4,
                per_epoch: 2 * m,
            },
        };
        let set = |l| PolicyUpdate::BridgeMintLimitsSet { limits: l };
        apply_policy(&mut state, &set(limits(100)), 0, &mut changes, &mut logs).unwrap();
        assert!(apply_policy(&mut state, &set(limits(300)), 0, &mut changes, &mut logs).is_err());
        apply_policy(&mut state, &set(limits(200)), 0, &mut changes, &mut logs).unwrap();
    }

    #[test]
    fn an_outflow_cap_rises_only_while_stake_secures_it_and_falls_at_any_time() {
        let mut state = StateAdapter::new();
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        let caps = |tnzo: u128| NetworkOutflowLimits {
            caps: vec![OutflowCap {
                unit: TNZO_UNIT.into(),
                per_epoch: tnzo,
            }],
        };
        let set = |l| PolicyUpdate::BridgeOutflowLimitsSet { limits: l };
        // 3,600 bonded: 1,200 slashable; at k = 1.5 over a day of epochs
        // the caps may let out at most 800, about 33 an epoch.
        super::super::staking::add_bond(&mut state, &[1; 32], 3_600, 0).unwrap();
        apply_policy(&mut state, &set(caps(33)), 0, &mut changes, &mut logs).unwrap();
        let refused = apply_policy(&mut state, &set(caps(34)), 0, &mut changes, &mut logs);
        assert!(refused.unwrap_err().to_string().contains("security"));
        // A cut is never gated, even with no stake behind it at all.
        let mut bare = StateAdapter::new();
        write_json(
            &mut bare,
            BRIDGE_OUTFLOW_LIMITS_KEY,
            &caps(1_000),
            &mut changes,
        )
        .unwrap();
        apply_policy(&mut bare, &set(caps(10)), 0, &mut changes, &mut logs).unwrap();
        assert_eq!(read_bridge_outflow_limits(&bare), Some(caps(10)));
    }

    #[test]
    fn the_exit_limits_and_the_raise_bound_move_one_step_at_a_time() {
        use crate::governance::{
            BRIDGE_EXIT_DELAY_PARAM, BRIDGE_EXIT_DELAY_THRESHOLD_PARAM, MAX_CAP_RAISE_PARAM,
            cap_change_allowed,
        };
        assert!(
            cap_change_allowed(BRIDGE_EXIT_DELAY_THRESHOLD_PARAM, 2_500, 5_000, 20_000).is_ok()
        );
        assert!(
            cap_change_allowed(BRIDGE_EXIT_DELAY_THRESHOLD_PARAM, 2_500, 5_001, 20_000).is_err()
        );
        assert!(cap_change_allowed(BRIDGE_EXIT_DELAY_PARAM, 1_000, 500, 20_000).is_ok());
        assert!(cap_change_allowed(BRIDGE_EXIT_DELAY_PARAM, 1_000, 499, 20_000).is_err());
        assert!(cap_change_allowed(BRIDGE_EXIT_DELAY_PARAM, 1_000, 9_000, 20_000).is_ok());
        assert!(cap_change_allowed(MAX_CAP_RAISE_PARAM, 20_000, 40_000, 20_000).is_ok());
        assert!(cap_change_allowed(MAX_CAP_RAISE_PARAM, 20_000, 40_001, 20_000).is_err());
        assert!(cap_change_allowed("stake.validator_tnzo", 1, 1_000, 20_000).is_ok());
    }
}
