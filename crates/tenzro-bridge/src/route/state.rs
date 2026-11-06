//! The chain state the framework reads and writes.
//!
//! Every value lives in Tenzro's consensus state, so every node applies and
//! anyone can audit the same nonces, epoch totals and supply records:
//!
//! - `bridge_nonce:<route>:<nonce>`: present once the nonce is used.
//! - `bridge_msg_nonce:<route>:<nonce>`: the same for attested data messages:
//!   `1` once a native consumer acted on it, or `2` and the body's hash while
//!   it is only published.
//! - `bridge_mint_epoch:<route>`: epoch (u64) and amount minted in it (u128).
//! - `bridge_outflow_epoch:<unit>`: epoch (u64) and amount of the unit sent
//!   out over every route together in it (u128).
//! - `bridge_supply:<route>`: TNZO locked on Tenzro for the route (u128) and
//!   the representation outstanding on the external chain (u128).
//! - `bridge_out_seq:<route>`: the last outbound sequence number (u64).
//! - `bridge_out:<route>:<seq>`: the encoded outbound transfer, for relayers.
//! - `bridge_out_msg_seq:<route>` / `bridge_out_msg:<route>:<seq>`: the same
//!   for outbound data messages.

use serde::Serialize;

use super::{BridgeRoute, BridgeRouteAdapter, BridgeRouteMode, MintRateLimit};
use crate::error::{BridgeError, Result};
use tenzro_types::bridge_route::{CarriedAsset, NetworkOutflowLimits};

/// The chain state view the framework works against.
pub trait RouteState {
    /// This chain's id.
    fn local_chain_id(&self) -> u64;
    /// Current block time, unix ms.
    fn now_ms(&self) -> i64;
    /// Current epoch.
    fn epoch(&self) -> u64;
    /// The governed route for `(adapter, chain)`, if installed.
    fn route(&self, adapter: BridgeRouteAdapter, chain: &str) -> Option<BridgeRoute>;
    /// The mode the route's circuit breaker holds it in, and why, if it
    /// holds it disabled or paused.
    fn stopped(&self, route: &BridgeRoute) -> Option<(BridgeRouteMode, String)>;
    /// The network-wide mint limits, if set.
    fn network_limit(&self, route: &BridgeRoute) -> Option<MintRateLimit>;
    /// The network-wide outflow limits, if set.
    fn outflow_limits(&self) -> Option<NetworkOutflowLimits>;
    /// Read a framework value.
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// Write framework values, all or none.
    fn apply(&mut self, writes: Vec<(String, Vec<u8>)>) -> Result<()>;
}

/// Key marking `nonce` used on `route`.
pub fn nonce_key(route: &BridgeRoute, nonce: u64) -> String {
    format!("bridge_nonce:{}:{nonce}", route.storage_key())
}

/// Key marking a data-message `nonce` used on `route`.
pub fn message_nonce_key(route: &BridgeRoute, nonce: u64) -> String {
    format!("bridge_msg_nonce:{}:{nonce}", route.storage_key())
}

/// Value of a message nonce whose delivery a native consumer acted on.
pub const CONSUMED_MESSAGE: [u8; 1] = [1];

/// Value of a message nonce whose delivery was published but not yet acted
/// on: a tag byte, then the hash of the body published.
pub fn published_message(body: &[u8]) -> Vec<u8> {
    let mut v = vec![2u8];
    v.extend_from_slice(&super::attestation::body_hash(body));
    v
}

/// Key of the route's epoch mint total.
pub fn epoch_key(route: &BridgeRoute) -> String {
    format!("bridge_mint_epoch:{}", route.storage_key())
}

/// Key of the route's supply record.
pub fn supply_key(route: &BridgeRoute) -> String {
    format!("bridge_supply:{}", route.storage_key())
}

/// Key of a carried asset's epoch mint total on `route`.
pub fn asset_epoch_key(route: &BridgeRoute, asset: &CarriedAsset) -> String {
    format!("{}:{}", epoch_key(route), asset.symbol)
}

/// Key of a carried asset's supply record on `route`: `locked` is what the
/// route's vault on the external chain holds, `bridged` the representation
/// issued on Tenzro against it.
pub fn asset_supply_key(route: &BridgeRoute, asset: &CarriedAsset) -> String {
    format!("{}:{}", supply_key(route), asset.symbol)
}

/// Key of the route's outbound sequence.
pub fn sequence_key(route: &BridgeRoute) -> String {
    format!("bridge_out_seq:{}", route.storage_key())
}

/// Key of the route's outbound data-message sequence.
pub fn message_sequence_key(route: &BridgeRoute) -> String {
    format!("bridge_out_msg_seq:{}", route.storage_key())
}

/// Key holding outbound transfer `sequence`'s encoding for relayers.
pub fn outbound_key(route: &BridgeRoute, sequence: u64) -> String {
    format!("bridge_out:{}:{sequence}", route.storage_key())
}

/// Key holding outbound data message `sequence`'s encoding for relayers.
pub fn outbound_message_key(route: &BridgeRoute, sequence: u64) -> String {
    format!("bridge_out_msg:{}:{sequence}", route.storage_key())
}

/// A big-endian u64 value, zero when absent.
pub fn read_u64(state: &dyn RouteState, key: &str) -> u64 {
    state
        .get(key)
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// What a route has minted in an epoch, against the limits that apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EpochUsage {
    /// Smallest units minted through the route this epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub minted: u128,
    /// Smallest units the route may still mint this epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub remaining: u128,
    /// The limits in force: the tighter of the route's and the network's.
    pub limit: MintRateLimit,
}

fn minted_in(state: &dyn RouteState, route: &BridgeRoute, epoch: u64) -> u128 {
    minted_at(state, &epoch_key(route), epoch)
}

fn minted_at(state: &dyn RouteState, key: &str, epoch: u64) -> u128 {
    let Some(b) = state.get(key) else {
        return 0;
    };
    if b.len() != 24 || b[..8] != epoch.to_be_bytes() {
        return 0;
    }
    let mut minted = [0u8; 16];
    minted.copy_from_slice(&b[8..]);
    u128::from_be_bytes(minted)
}

/// What `route` has minted this epoch, without drawing on it.
pub fn epoch_usage(
    state: &dyn RouteState,
    route: &BridgeRoute,
    network: MintRateLimit,
) -> EpochUsage {
    let limit = route.mint_limit.tightest(network);
    let minted = minted_in(state, route, state.epoch());
    EpochUsage {
        minted,
        remaining: limit.per_epoch.saturating_sub(minted),
        limit,
    }
}

/// Check a mint of `amount` against the caps and return the write that
/// records it. Nothing is written here.
pub fn consume_epoch(
    state: &dyn RouteState,
    route: &BridgeRoute,
    network: MintRateLimit,
    amount: u128,
) -> Result<(String, Vec<u8>, EpochUsage)> {
    consume_at(
        state,
        epoch_key(route),
        &route.storage_key(),
        route.mint_limit.tightest(network),
        amount,
    )
}

/// [`consume_epoch`] for a carried asset, against the asset's own limits in
/// its base units.
pub fn consume_asset_epoch(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: &CarriedAsset,
    amount: u128,
) -> Result<(String, Vec<u8>, EpochUsage)> {
    let what = format!("{} {}", route.storage_key(), asset.symbol);
    consume_at(
        state,
        asset_epoch_key(route, asset),
        &what,
        asset.mint_limit,
        amount,
    )
}

fn consume_at(
    state: &dyn RouteState,
    key: String,
    what: &str,
    limit: MintRateLimit,
    amount: u128,
) -> Result<(String, Vec<u8>, EpochUsage)> {
    if amount > limit.per_mint {
        return Err(BridgeError::TransferFailed(format!(
            "mint of {amount} exceeds the {what} route's cap of {} per mint",
            limit.per_mint
        )));
    }
    let epoch = state.epoch();
    let minted = minted_at(state, &key, epoch);
    let Some(after) = mint_admitted(minted, amount, limit) else {
        return Err(BridgeError::TransferFailed(format!(
            "mint of {amount} would take the {what} route past its limit of {} this epoch \
             ({minted} minted); retry next epoch",
            limit.per_epoch
        )));
    };
    let mut value = epoch.to_be_bytes().to_vec();
    value.extend_from_slice(&after.to_be_bytes());
    Ok((
        key,
        value,
        EpochUsage {
            minted: after,
            remaining: limit.per_epoch - after,
            limit,
        },
    ))
}

/// A route's supply record. The invariant `bridged <= locked` holds after
/// every operation, and every operation checks it.
/// The epoch total after `amount` more, when it fits under `cap`; None when
/// it would pass the cap (or overflow).
pub fn within_epoch_cap(used: u128, amount: u128, cap: u128) -> Option<u128> {
    used.checked_add(amount).filter(|after| *after <= cap)
}

/// The route's epoch mint total after a mint of `amount` on top of
/// `minted`, when the mint is within the per-mint cap and the total within
/// the per-epoch limit.
pub fn mint_admitted(minted: u128, amount: u128, limit: MintRateLimit) -> Option<u128> {
    if amount > limit.per_mint {
        return None;
    }
    within_epoch_cap(minted, amount, limit.per_epoch)
}

/// Key of the network-wide total of `unit` sent out this epoch, over every
/// route: epoch (u64) and amount (u128).
pub fn outflow_key(unit: &str) -> String {
    format!("bridge_outflow_epoch:{unit}")
}

/// How much of a unit has left Tenzro over all routes this epoch, against
/// the network-wide cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutflowUsage {
    /// The unit.
    pub unit: String,
    /// Smallest units sent out this epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub sent: u128,
    /// Smallest units that may still leave this epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub remaining: u128,
    /// The cap per epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub per_epoch: u128,
}

/// What has left this epoch in `unit`, or None when no cap names the unit.
pub fn outflow_usage(state: &dyn RouteState, unit: &str) -> Option<OutflowUsage> {
    let per_epoch = state.outflow_limits()?.per_epoch(unit)?;
    let sent = minted_at(state, &outflow_key(unit), state.epoch());
    Some(OutflowUsage {
        unit: unit.to_string(),
        sent,
        remaining: per_epoch.saturating_sub(sent),
        per_epoch,
    })
}

/// Count `amount` of `unit` against the network-wide outflow cap for this
/// epoch. Refused when no cap names the unit or the epoch total would pass
/// it; otherwise the write to record.
pub fn consume_outflow(
    state: &dyn RouteState,
    unit: &str,
    amount: u128,
) -> Result<(String, Vec<u8>)> {
    let usage = outflow_usage(state, unit).ok_or_else(|| {
        BridgeError::TransferFailed(format!(
            "no network outflow cap names {unit}; nothing in it may leave"
        ))
    })?;
    let after = within_epoch_cap(usage.sent, amount, usage.per_epoch).ok_or_else(|| {
        BridgeError::TransferFailed(format!(
            "sending {amount} {unit} would take the network past its outflow cap of {} this \
             epoch ({} sent over all routes); retry next epoch",
            usage.per_epoch, usage.sent
        ))
    })?;
    let mut value = state.epoch().to_be_bytes().to_vec();
    value.extend_from_slice(&after.to_be_bytes());
    Ok((outflow_key(unit), value))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SupplyRecord {
    /// TNZO locked on Tenzro for the route.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub locked: u128,
    /// The representation outstanding on the external chain.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub bridged: u128,
}

fn invariant(route: &BridgeRoute, what: &str) -> BridgeError {
    BridgeError::TransferFailed(format!(
        "supply invariant: {what} on route {}; refused",
        route.storage_key()
    ))
}

impl SupplyRecord {
    /// Fixed 32-byte encoding: locked, then bridged, big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.locked.to_be_bytes().to_vec();
        out.extend_from_slice(&self.bridged.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut locked = [0u8; 16];
        let mut bridged = [0u8; 16];
        locked.copy_from_slice(&bytes[..16]);
        bridged.copy_from_slice(&bytes[16..]);
        Some(Self {
            locked: u128::from_be_bytes(locked),
            bridged: u128::from_be_bytes(bridged),
        })
    }

    /// The record after `amount` more is locked on Tenzro and minted on the
    /// external chain; None when a total would overflow.
    pub fn after_lock(self, amount: u128) -> Option<Self> {
        Some(Self {
            locked: self.locked.checked_add(amount)?,
            bridged: self.bridged.checked_add(amount)?,
        })
        .filter(|r| r.bridged <= r.locked)
    }

    /// The record after `amount` comes back and is released; None when more
    /// comes back than is outstanding or locked.
    pub fn after_release(self, amount: u128) -> Option<Self> {
        Some(Self {
            locked: self.locked.checked_sub(amount)?,
            bridged: self.bridged.checked_sub(amount)?,
        })
        .filter(|r| r.bridged <= r.locked)
    }

    /// [`Self::after_lock`], refused with the route named.
    pub fn lock_and_mint(self, amount: u128, route: &BridgeRoute) -> Result<Self> {
        self.after_lock(amount)
            .ok_or_else(|| invariant(route, &format!("locking {amount} more overflows")))
    }

    /// [`Self::after_release`], refused with the route named.
    pub fn release(self, amount: u128, route: &BridgeRoute) -> Result<Self> {
        self.after_release(amount).ok_or_else(|| {
            invariant(
                route,
                &format!(
                    "{amount} exceeds the {} outstanding on the external chain",
                    self.bridged
                ),
            )
        })
    }
}

pub fn read_asset_supply(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: &CarriedAsset,
) -> SupplyRecord {
    state
        .get(&asset_supply_key(route, asset))
        .and_then(|b| SupplyRecord::decode(&b))
        .unwrap_or_default()
}

/// The route's supply record; an unreadable record reads as a route with
/// nothing locked, which refuses every release.
pub fn read_supply(state: &dyn RouteState, route: &BridgeRoute) -> SupplyRecord {
    state
        .get(&supply_key(route))
        .and_then(|b| SupplyRecord::decode(&b))
        .unwrap_or_default()
}
