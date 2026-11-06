//! Large bridge exits wait out a governed delay before they leave.
//!
//! An exit larger than `bridge.exit_delay_threshold_bps` of its outflow
//! bucket's capacity is not sent at once. The value moves from the sender to
//! the exit escrow and the exit is queued for `bridge.exit_delay_ms`:
//!
//! - the sender may withdraw it at any time;
//! - a seated guardian may cancel it during the delay;
//! - anyone may cancel it once a proven committee fault on its route (an
//!   equivocation or a wrong handover) has emptied the route's committees
//!   since it was queued, and it can then no longer be released.
//!
//! A cancelled exit returns the value to the sender. Once the delay has
//! passed anyone may release the exit: it then leaves exactly as an
//! immediate exit would, against the route's rate limits and the network
//! outflow cap in force at that moment.
//!
//! An exit the network outflow cap cannot carry in the current epoch queues
//! the same way with no delay: anyone may release it once an epoch has room.
//! It queues only while the exits already queued in its unit come to less
//! than `bridge.queue_max_epochs` epochs of the unit's effective cap, so a
//! queued exit leaves within about that many epochs; past that it is
//! refused and may be sent later.
//!
//! Records live in consensus state, readable over RPC:
//! - `bridge_exit_seq`: the last exit id (u64).
//! - `bridge_exit:<id>`: the queued exit, removed when released or cancelled.
//! - `bridge_exit_queued:<unit>`: the amount queued in a unit (u128).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_bridge::route::BridgeRoute;
use tenzro_types::bridge_route::CarriedAsset;

use super::bridge::deposit_asset;
use super::funding::{move_balance, read_json, refuse, write_json};
use super::*;

/// Key of the last exit id.
pub const EXIT_SEQ_KEY: &str = "bridge_exit_seq";

/// Key of the amount queued in `unit`.
pub fn queued_key(unit: &str) -> String {
    format!("bridge_exit_queued:{unit}")
}

/// The amount queued in `unit`, smallest units.
pub fn queued(state: &dyn VmState, unit: &str) -> u128 {
    read_json::<String>(state, &queued_key(unit))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn add_queued(
    state: &mut dyn VmState,
    unit: &str,
    amount: u128,
    add: bool,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let now = queued(state, unit);
    let next = if add {
        now.saturating_add(amount)
    } else {
        now.saturating_sub(amount)
    };
    write_json(state, &queued_key(unit), &next.to_string(), changes)?;
    Ok(())
}

/// Refuse an exit over the outflow cap when the queue in its unit already
/// holds `bridge.queue_max_epochs` epochs of the unit's effective cap.
pub fn check_queue_room(state: &dyn VmState, unit: &str, amount: u128) -> Result<()> {
    let cap = super::security::outflow_limits_in_force(state)
        .and_then(|l| l.per_epoch(unit))
        .unwrap_or(0);
    let epochs = network_param(state, super::security::QUEUE_MAX_EPOCHS_PARAM);
    let room = cap.saturating_mul(u128::from(epochs));
    if queued(state, unit).saturating_add(amount) > room {
        return Err(refuse(format!(
            "the network outflow cap on {unit} is spent this epoch and the exit queue already \
             holds {epochs} epochs of it; send the exit later"
        )));
    }
    Ok(())
}

/// Key of a queued exit.
pub fn exit_key(id: u64) -> String {
    format!("bridge_exit:{id}")
}

/// The account queued exits hold their value in.
pub fn exit_escrow() -> Vec<u8> {
    Sha256::new()
        .chain_update(b"tenzro/bridge/exit-escrow")
        .finalize()
        .to_vec()
}

/// An exit waiting out its delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExit {
    /// The exit's id.
    pub id: u64,
    /// The Tenzro account the value came from and returns to on cancel.
    #[serde(with = "hex::serde")]
    pub sender: Vec<u8>,
    /// The chain the value leaves for.
    pub target_chain: String,
    /// The recipient on that chain.
    #[serde(with = "hex::serde")]
    pub recipient: Vec<u8>,
    /// Smallest units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    /// The carried asset's symbol, or none for the route's own value.
    pub asset: Option<String>,
    /// The token the escrow holds, or none for native TNZO: the value comes
    /// back by this, whatever later happens to the route.
    pub token: Option<[u8; 32]>,
    /// The route it was queued on.
    pub route: String,
    /// The unit it counts in against the network outflow caps.
    pub unit: String,
    /// When it was queued, unix ms.
    pub queued_at_ms: i64,
    /// When anyone may release it, unix ms.
    pub release_at_ms: i64,
}

/// A queued exit, if `id` names one.
pub fn read_exit(state: &dyn VmState, id: u64) -> Option<PendingExit> {
    read_json(state, &exit_key(id))
}

/// The last exit id handed out.
pub fn last_exit_id(state: &dyn VmState) -> u64 {
    read_json(state, EXIT_SEQ_KEY).unwrap_or(0)
}

/// Whether an exit of `amount` from a bucket of `capacity` waits.
pub fn waits(state: &dyn VmState, amount: u128, capacity: u128) -> bool {
    tenzro_types::bridge_route::exit_waits(
        amount,
        capacity,
        network_param(state, crate::governance::BRIDGE_EXIT_DELAY_THRESHOLD_PARAM),
    )
}

/// The token an exit's value is held in: None for TNZO, the representation
/// of a carried asset or of a deposit route's native asset otherwise.
fn token(route: &BridgeRoute, asset: Option<&CarriedAsset>) -> Result<Option<[u8; 32]>> {
    if let Some(a) = asset {
        return Ok(Some(a.representation_id()));
    }
    if route.adapter != tenzro_types::bridge_route::BridgeRouteAdapter::Deposit {
        return Ok(None);
    }
    deposit_asset(route.family)
        .map(|d| Some(d.token_id))
        .ok_or_else(|| refuse("the route's family has no deposit asset"))
}

/// Move `amount` of the exit's value from `from` to `to`.
fn hold(
    state: &mut dyn VmState,
    token: Option<[u8; 32]>,
    from: &[u8],
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    match token {
        None => move_balance(state, from, to, amount, changes),
        Some(id) => {
            changes.extend(
                crate::token_ledger::transfer(state, &id, from, to, amount, now_ms)?
                    .unwrap_or_default(),
            );
            Ok(())
        }
    }
}

/// Queue an exit: move its value into escrow and record it. `delayed` is a
/// large exit waiting out the exit delay; otherwise it is an exit over the
/// outflow cap, releasable at once.
#[allow(clippy::too_many_arguments)]
pub(super) fn queue(
    state: &mut dyn VmState,
    route: &BridgeRoute,
    asset: Option<&CarriedAsset>,
    sender: &[u8],
    target_chain: &str,
    recipient: &[u8],
    amount: u128,
    now_ms: i64,
    delayed: bool,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let delay = if delayed {
        network_param(state, crate::governance::BRIDGE_EXIT_DELAY_PARAM)
    } else {
        0
    };
    let held_token = token(route, asset)?;
    let unit = tenzro_bridge::route::exit_unit(route, asset).map_err(|e| refuse(e.to_string()))?;
    let id = last_exit_id(state)
        .checked_add(1)
        .ok_or_else(|| refuse("exit ids exhausted"))?;
    let exit = PendingExit {
        id,
        sender: sender.to_vec(),
        target_chain: target_chain.to_string(),
        recipient: recipient.to_vec(),
        amount,
        asset: asset.map(|a| a.symbol.clone()),
        token: held_token,
        route: route.storage_key(),
        unit: unit.clone(),
        queued_at_ms: now_ms,
        release_at_ms: now_ms.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX)),
    };
    hold(
        state,
        held_token,
        sender,
        &exit_escrow(),
        amount,
        now_ms,
        changes,
    )?;
    write_json(state, EXIT_SEQ_KEY, &id, changes)?;
    write_json(state, &exit_key(id), &exit, changes)?;
    add_queued(state, &unit, amount, true, changes)?;
    Ok(serde_json::to_value(&exit).unwrap_or_default())
}

/// Whether a proven committee fault on the exit's route has emptied its
/// committees since the exit was queued.
pub fn faulted_since_queued(state: &dyn VmState, exit: &PendingExit) -> bool {
    super::bridge_committee::last_fault_ms(state, &exit.route)
        .is_some_and(|at| at >= exit.queued_at_ms)
}

fn take(state: &mut dyn VmState, id: u64, changes: &mut Vec<StateChange>) -> Result<PendingExit> {
    let exit = read_exit(state, id).ok_or_else(|| refuse(format!("no exit {id} is queued")))?;
    let key = exit_key(id);
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(Vec::new()),
    ));
    add_queued(state, &exit.unit, exit.amount, false, changes)?;
    Ok(exit)
}

/// Return the exit's value from escrow to its sender, in the token the
/// escrow took.
fn refund(
    state: &mut dyn VmState,
    exit: &PendingExit,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    hold(
        state,
        exit.token,
        &exit_escrow(),
        &exit.sender,
        exit.amount,
        now_ms,
        changes,
    )
}

fn route_of(state: &dyn VmState, exit: &PendingExit) -> Result<BridgeRoute> {
    state
        .get_storage(&SYSTEM_ADDRESS, exit.route.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| refuse(format!("route {} is no longer installed", exit.route)))
}

/// Cancel exit `id` on behalf of `by`, returning its value to the sender.
pub(super) fn cancel(
    state: &mut dyn VmState,
    id: u64,
    by: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let exit = read_exit(state, id).ok_or_else(|| refuse(format!("no exit {id} is queued")))?;
    let authority = if by == exit.sender.as_slice() {
        "sender"
    } else if faulted_since_queued(state, &exit) {
        "committee_fault"
    } else if now_ms < exit.release_at_ms
        && super::guardian::active_role(state, by, now_ms).is_some()
    {
        "guardian"
    } else {
        return Err(refuse(format!(
            "exit {id} may be cancelled by its sender, by a seated guardian until {}, or by \
             anyone after a proven fault of its route's committee",
            exit.release_at_ms
        )));
    };
    let exit = take(state, id, changes)?;
    refund(state, &exit, now_ms, changes)?;
    Ok(serde_json::json!({
        "id": id,
        "by": authority,
        "sender": hex::encode(&exit.sender),
        "amount": exit.amount.to_string(),
        "asset": exit.asset,
    }))
}

/// Take exit `id` out of the queue for release, returning its value to the
/// sender so the release can send it as an immediate exit.
pub(super) fn release(
    state: &mut dyn VmState,
    id: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<PendingExit> {
    let exit = read_exit(state, id).ok_or_else(|| refuse(format!("no exit {id} is queued")))?;
    if now_ms < exit.release_at_ms {
        return Err(refuse(format!(
            "exit {id} may be released from {}",
            exit.release_at_ms
        )));
    }
    if faulted_since_queued(state, &exit) {
        return Err(refuse(format!(
            "a fault of route {}'s committee was proven after exit {id} was queued; it can only \
             be cancelled",
            exit.route
        )));
    }
    route_of(state, &exit)?;
    let exit = take(state, id, changes)?;
    refund(state, &exit, now_ms, changes)?;
    Ok(exit)
}
