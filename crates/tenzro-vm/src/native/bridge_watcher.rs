//! A permissionless, bonded, self-expiring pause of one bridge route.
//!
//! Validators holding two thirds of bonded stake pause a route on a finding
//! (`agent_audit`). A cartel holding more than a third of stake can withhold
//! its flags and keep that path shut, so any bonded account can also signal
//! an anomaly itself and stop the route for a short, governed time, which is
//! the time governance's expedited track or the validators need to act:
//!
//! - the watcher must hold at least `bridge.watcher_min_stake_tnzo` bonded
//!   for at least `bridge.watcher_min_bond_age_ms`, so a bond posted for the
//!   occasion does not count;
//! - the pause lasts `bridge.watcher_pause_ms` and lifts by itself; a route
//!   cannot be paused by a watcher again until `bridge.watcher_cooloff_ms`
//!   after the last pause ended, and a watcher has one open signal at a time,
//!   so spam is bounded by the cooloff and by the slashing;
//! - the same evidence hash is accepted once;
//! - `Settle` (anyone, after `bridge.watcher_review_ms` past the end of the
//!   pause) decides the signal: it is confirmed when validators, the
//!   reconciliation check or governance stopped the route, a bridge
//!   transport lever is not enabled, or the value monitor froze the bridge
//!   module, any of them after the signal. Otherwise the watcher is slashed
//!   `bridge.watcher_slash_bps` of everything it has at stake (bonded and
//!   unbonding) into the insurance pool.
//!
//! The pause is read by the route's adapters at block time
//! ([`stop_at`]); it needs no transaction to lift.

use serde::{Deserialize, Serialize};
use tenzro_types::bridge_route::{BridgeRouteAdapter, BridgeRouteMode};

use super::staking::{self, SlashedStake};
use super::*;

/// Selector of a watcher's operations.
pub const SELECTOR_BRIDGE_WATCHER: [u8; 4] = [0x01, 0x00, 0x00, 0xDD];

/// Gas of one operation.
pub const GAS_BRIDGE_WATCHER: u64 = 50_000;

/// Governed: how long a watcher's pause holds, ms.
pub const PAUSE_MS_PARAM: &str = "bridge.watcher_pause_ms";
/// Genesis value of [`PAUSE_MS_PARAM`]: six hours.
pub const DEFAULT_PAUSE_MS: u64 = 6 * 60 * 60 * 1000;
/// Governed: how long after a pause ended a route cannot be paused by a
/// watcher again, ms.
pub const COOLOFF_MS_PARAM: &str = "bridge.watcher_cooloff_ms";
/// Genesis value of [`COOLOFF_MS_PARAM`]: one day.
pub const DEFAULT_COOLOFF_MS: u64 = 24 * 60 * 60 * 1000;
/// Governed: how long after a pause ended governance and the validators
/// have to confirm it before it is judged, ms.
pub const REVIEW_MS_PARAM: &str = "bridge.watcher_review_ms";
/// Genesis value of [`REVIEW_MS_PARAM`]: three days.
pub const DEFAULT_REVIEW_MS: u64 = 3 * 24 * 60 * 60 * 1000;
/// Governed: share of its stake an unconfirmed watcher loses, basis points.
pub const SLASH_BPS_PARAM: &str = "bridge.watcher_slash_bps";
/// Genesis value of [`SLASH_BPS_PARAM`]: one percent.
pub const DEFAULT_SLASH_BPS: u64 = 100;
/// Governed: the least bonded stake a watcher holds, whole TNZO.
pub const MIN_STAKE_PARAM: &str = "bridge.watcher_min_stake_tnzo";
/// Genesis value of [`MIN_STAKE_PARAM`].
pub const DEFAULT_MIN_STAKE_TNZO: u64 = 1_000;
/// Governed: how long a bond must have been held to count, ms.
pub const MIN_BOND_AGE_PARAM: &str = "bridge.watcher_min_bond_age_ms";
/// Genesis value of [`MIN_BOND_AGE_PARAM`]: one day.
pub const DEFAULT_MIN_BOND_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// Topic of the log every operation emits.
pub const WATCHER_TOPIC: &[u8] = b"BridgeWatcher";

/// One operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Pause a route for the governed time on an anomaly.
    Signal {
        /// The route's bridge protocol.
        adapter: BridgeRouteAdapter,
        /// The route's external chain.
        source_chain: String,
        /// SHA-256 of the anomaly evidence, hex.
        evidence_hash: String,
        /// Why.
        reason: String,
    },
    /// Judge a signal whose review time has passed.
    Settle {
        /// The route's bridge protocol.
        adapter: BridgeRouteAdapter,
        /// The route's external chain.
        source_chain: String,
    },
}

/// A watcher's signal as chain state records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherSignal {
    /// The watcher, hex.
    pub watcher: String,
    /// Evidence hash, hex.
    pub evidence_hash: String,
    /// Block time the pause began, ms.
    pub start_ms: i64,
    /// Block time it lifts, ms.
    pub expires_ms: i64,
    /// Block time it may be judged, ms.
    pub review_until_ms: i64,
    /// Block time a new watcher pause may start, ms.
    pub cooloff_until_ms: i64,
    /// Slash share fixed when it was signalled, basis points.
    pub slash_bps: u16,
    /// Already judged.
    pub settled: bool,
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(format!("bridge watcher: {}", msg.into()))
}

fn route_id(adapter: BridgeRouteAdapter, chain: &str) -> String {
    super::bridge_circuit::circuit_key(adapter, chain).replace("bridge_circuit:", "")
}

fn signal_key(adapter: BridgeRouteAdapter, chain: &str) -> String {
    format!("bridge_watcher:{}", route_id(adapter, chain))
}

fn open_key(watcher: &[u8]) -> String {
    format!("bridge_watcher_open:{}", hex::encode(watcher))
}

fn used_key(evidence: &str) -> String {
    format!("bridge_watcher_used:{}", evidence.to_ascii_lowercase())
}

/// The recorded signal of a route.
pub fn read_signal(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
) -> Option<WatcherSignal> {
    let raw = state.get_storage(&SYSTEM_ADDRESS, signal_key(adapter, chain).as_bytes())?;
    if raw.is_empty() {
        return None;
    }
    serde_json::from_slice(&raw).ok()
}

/// The pause a watcher holds on the route at block time `now_ms`, if any.
pub fn stop_at(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    now_ms: i64,
) -> Option<(BridgeRouteMode, String)> {
    let s = read_signal(state, adapter, chain)?;
    (!s.settled && now_ms >= s.start_ms && now_ms < s.expires_ms).then(|| {
        (
            BridgeRouteMode::Paused,
            format!("paused by a bonded watcher until {}", s.expires_ms),
        )
    })
}

fn put(state: &mut dyn VmState, key: &str, value: Vec<u8>, changes: &mut Vec<StateChange>) {
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        previous,
        Some(value),
    ));
}

fn check_route_name(chain: &str) -> Result<()> {
    if chain.is_empty() || chain.len() > 64 || !chain.is_ascii() {
        return Err(refuse("the route's chain name is 1 to 64 ASCII characters"));
    }
    Ok(())
}

/// Whether anything but the watcher stopped the route after `since_ms`.
fn confirmed(state: &dyn VmState, adapter: BridgeRouteAdapter, chain: &str, since_ms: i64) -> bool {
    if super::bridge_circuit::read_bridge_circuit(state, adapter, chain)
        .is_some_and(|t| t.at_ms >= since_ms)
    {
        return true;
    }
    if crate::governance::bridge_adapter_status_key(adapter).is_some_and(|key| {
        !matches!(
            lever_status(state, key),
            crate::governance::LeverStatus::Enabled
        )
    }) {
        return true;
    }
    crate::invariant_monitor::frozen(state, crate::invariant_monitor::GuardedModule::Bridge)
        .is_some()
}

/// Applies one operation sent by `tx.from`.
pub fn apply(
    state: &mut dyn VmState,
    tx: &VmTransaction,
    op: &Op,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    match op {
        Op::Signal {
            adapter,
            source_chain,
            evidence_hash,
            reason,
        } => {
            check_route_name(source_chain)?;
            let chain = source_chain.to_ascii_lowercase();
            if evidence_hash.len() != 64 || !evidence_hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(refuse("the evidence is a SHA-256 hash, 64 hex characters"));
            }
            if reason.len() > 512 {
                return Err(refuse("the reason is at most 512 bytes"));
            }
            let min_stake =
                (network_param(state, MIN_STAKE_PARAM) as u128) * tenzro_types::constants::ONE_TNZO;
            let age = network_param(state, MIN_BOND_AGE_PARAM) as i64;
            if staking::bonded_stake_of(state, &tx.from) < min_stake
                || staking::bond_at(state, &tx.from, now_ms.saturating_sub(age)) < min_stake
            {
                return Err(refuse(
                    "a watcher holds the governed minimum bonded, and has held it for the governed time",
                ));
            }
            if state
                .get_storage(&SYSTEM_ADDRESS, open_key(&tx.from).as_bytes())
                .is_some_and(|v| !v.is_empty())
            {
                return Err(refuse("this watcher already has a signal open"));
            }
            if state
                .get_storage(&SYSTEM_ADDRESS, used_key(evidence_hash).as_bytes())
                .is_some_and(|v| !v.is_empty())
            {
                return Err(refuse("this evidence was already signalled"));
            }
            if let Some(prev) = read_signal(state, *adapter, &chain)
                && now_ms < prev.cooloff_until_ms
            {
                return Err(refuse("the route was paused by a watcher too recently"));
            }
            if super::bridge_circuit::bridge_route_stop_at(state, *adapter, &chain, now_ms)
                .is_some()
            {
                return Err(refuse("the route is already stopped"));
            }
            let pause = network_param(state, PAUSE_MS_PARAM) as i64;
            let signal = WatcherSignal {
                watcher: hex::encode(&tx.from),
                evidence_hash: evidence_hash.to_ascii_lowercase(),
                start_ms: now_ms,
                expires_ms: now_ms.saturating_add(pause),
                review_until_ms: now_ms.saturating_add(pause).saturating_add(network_param(
                    state,
                    REVIEW_MS_PARAM,
                )
                    as i64),
                cooloff_until_ms: now_ms.saturating_add(pause).saturating_add(network_param(
                    state,
                    COOLOFF_MS_PARAM,
                )
                    as i64),
                slash_bps: network_param(state, SLASH_BPS_PARAM).min(10_000) as u16,
                settled: false,
            };
            put(
                state,
                &signal_key(*adapter, &chain),
                serde_json::to_vec(&signal).expect("signal encodes"),
                &mut changes,
            );
            put(state, &open_key(&tx.from), vec![1], &mut changes);
            put(state, &used_key(evidence_hash), vec![1], &mut changes);
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![WATCHER_TOPIC.to_vec(), b"signalled".to_vec()],
                serde_json::to_vec(&signal).expect("signal encodes"),
            ));
        }
        Op::Settle {
            adapter,
            source_chain,
        } => {
            check_route_name(source_chain)?;
            let chain = source_chain.to_ascii_lowercase();
            let mut signal = read_signal(state, *adapter, &chain)
                .ok_or_else(|| refuse("no watcher signal on this route"))?;
            if signal.settled {
                return Err(refuse("this signal was already judged"));
            }
            if now_ms < signal.review_until_ms {
                return Err(refuse("the review time has not passed"));
            }
            let watcher = hex::decode(&signal.watcher).unwrap_or_default();
            let upheld = confirmed(state, *adapter, &chain, signal.start_ms);
            if !upheld {
                let taken = staking::slash_to_insurance(
                    state,
                    &watcher,
                    SlashedStake::Validator,
                    signal.slash_bps,
                    &mut changes,
                )?;
                logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![WATCHER_TOPIC.to_vec(), b"slashed".to_vec()],
                    taken.to_le_bytes().to_vec(),
                ));
            } else {
                logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![WATCHER_TOPIC.to_vec(), b"confirmed".to_vec()],
                    signal.watcher.as_bytes().to_vec(),
                ));
            }
            signal.settled = true;
            put(
                state,
                &signal_key(*adapter, &chain),
                serde_json::to_vec(&signal).expect("signal encodes"),
                &mut changes,
            );
            put(state, &open_key(&watcher), Vec::new(), &mut changes);
        }
    }
    Ok((changes, logs))
}
