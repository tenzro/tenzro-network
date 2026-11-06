//! Token-bucket rate limits on a route's lanes, enforced on Tenzro's side.
//!
//! A bucket holds at most `capacity`, refills at `rate` per whole second, and
//! a transfer takes its amount out or is refused. Every route and every
//! carried asset has an outbound bucket ([`BridgeRoute::outflow`],
//! [`CarriedAsset::outflow`]): nothing leaves Tenzro without one. A CCIP route
//! also has an inbound bucket ([`super::CcipLane`]), the same limit its token
//! pool on the external chain is configured with. The framework keeps one
//! bucket per direction in chain state beside the route's other records. The
//! lane limits apply on top of the route's per-mint cap and per-epoch limit:
//! a transfer must pass both.

use serde::Serialize;
use tenzro_types::bridge_route::{BridgeRoute, CarriedAsset, LaneRateLimit};

use super::state::RouteState;
use crate::error::{BridgeError, Result};

/// Which way a transfer crosses the lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneDirection {
    /// From the external chain to Tenzro.
    Inbound,
    /// From Tenzro to the external chain.
    Outbound,
}

impl LaneDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Key of the route's bucket for `direction`.
pub fn lane_key(route: &BridgeRoute, direction: LaneDirection) -> String {
    format!("bridge_lane:{}:{}", direction.as_str(), route.storage_key())
}

/// A lane bucket as it stands now, in the shape a CCIP pool reports it
/// (`getCurrentInboundRateLimiterState` / `getCurrentOutboundRateLimiterState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LaneBucket {
    /// What the bucket holds now, in the smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub tokens: u128,
    /// Most it holds.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub capacity: u128,
    /// Refill per second.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub rate: u128,
    /// Unix second of the last update.
    pub last_updated: u64,
}

impl LaneBucket {
    fn encode(&self) -> Vec<u8> {
        let mut out = self.tokens.to_be_bytes().to_vec();
        out.extend_from_slice(&self.last_updated.to_be_bytes());
        out
    }
}

fn limit(route: &BridgeRoute, direction: LaneDirection) -> Option<LaneRateLimit> {
    match direction {
        LaneDirection::Inbound => route.lane_limits.map(|l| l.inbound),
        LaneDirection::Outbound => Some(route.outflow),
    }
}

fn now_secs(state: &dyn RouteState) -> u64 {
    u64::try_from(state.now_ms() / 1000).unwrap_or(0)
}

/// The route's bucket for `direction`, refilled to now. `None` only inbound,
/// on a route without inbound lane limits. A bucket never used starts full; a stored bucket
/// above a capacity governance has since lowered is cut to it.
pub fn lane_bucket(
    state: &dyn RouteState,
    route: &BridgeRoute,
    direction: LaneDirection,
) -> Option<LaneBucket> {
    bucket_at(state, &lane_key(route, direction), limit(route, direction)?)
}

/// Key of a carried asset's bucket for `direction` on `route`.
pub fn asset_lane_key(
    route: &BridgeRoute,
    asset: &CarriedAsset,
    direction: LaneDirection,
) -> String {
    format!("{}:{}", lane_key(route, direction), asset.symbol)
}

fn asset_limit(asset: &CarriedAsset, direction: LaneDirection) -> Option<LaneRateLimit> {
    match direction {
        LaneDirection::Inbound => asset.lane.map(|l| l.inbound),
        LaneDirection::Outbound => Some(asset.outflow),
    }
}

/// A carried asset's bucket for `direction`, refilled to now; `None` only
/// inbound, when the asset has no inbound lane limits.
pub fn asset_lane_bucket(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: &CarriedAsset,
    direction: LaneDirection,
) -> Option<LaneBucket> {
    bucket_at(
        state,
        &asset_lane_key(route, asset, direction),
        asset_limit(asset, direction)?,
    )
}

/// Check `amount` against a carried asset's bucket for `direction` and
/// return the write that draws it down. Nothing is written here.
pub fn consume_asset_lane(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: &CarriedAsset,
    direction: LaneDirection,
    amount: u128,
) -> Result<Option<(String, Vec<u8>)>> {
    let Some(bucket) = asset_lane_bucket(state, route, asset, direction) else {
        return Ok(None);
    };
    draw(
        bucket,
        amount,
        direction,
        &format!("{} {}", route.storage_key(), asset.symbol),
    )
    .map(|b| Some((asset_lane_key(route, asset, direction), b.encode())))
}

fn bucket_at(state: &dyn RouteState, key: &str, limit: LaneRateLimit) -> Option<LaneBucket> {
    let stored = match state.get(key) {
        Some(b) if b.len() == 24 => {
            let mut t = [0u8; 16];
            t.copy_from_slice(&b[..16]);
            let mut l = [0u8; 8];
            l.copy_from_slice(&b[16..]);
            Some((u128::from_be_bytes(t), u64::from_be_bytes(l)))
        }
        _ => None,
    };
    Some(LaneBucket::refill(stored, now_secs(state), limit))
}

impl LaneBucket {
    /// The bucket at `now` (unix seconds), from what was stored (tokens and
    /// the second they were counted) under `limit`: refilled at the rate for
    /// the time since, and never above the capacity, so a capacity lowered
    /// by governance cuts a fuller bucket at once. Nothing stored is a full
    /// bucket.
    pub fn refill(stored: Option<(u128, u64)>, now: u64, limit: LaneRateLimit) -> LaneBucket {
        let (tokens, last) = stored.unwrap_or((limit.capacity, now));
        let elapsed = u128::from(now.saturating_sub(last));
        let tokens = tokens
            .saturating_add(elapsed.saturating_mul(limit.rate))
            .min(limit.capacity);
        LaneBucket {
            tokens,
            capacity: limit.capacity,
            rate: limit.rate,
            last_updated: now.max(last),
        }
    }

    /// The bucket after `amount` is taken out of it, or None when it holds
    /// less (or `amount` exceeds the capacity).
    pub fn take(self, amount: u128) -> Option<LaneBucket> {
        if amount > self.capacity {
            return None;
        }
        let tokens = self.tokens.checked_sub(amount)?;
        Some(LaneBucket { tokens, ..self })
    }
}

/// Check `amount` against the route's bucket for `direction` and return the
/// write that draws it down, or `None` for a route without lane limits.
/// Nothing is written here.
pub fn consume_lane(
    state: &dyn RouteState,
    route: &BridgeRoute,
    direction: LaneDirection,
    amount: u128,
) -> Result<Option<(String, Vec<u8>)>> {
    let Some(bucket) = lane_bucket(state, route, direction) else {
        return Ok(None);
    };
    draw(bucket, amount, direction, &route.storage_key())
        .map(|b| Some((lane_key(route, direction), b.encode())))
}

fn draw(
    bucket: LaneBucket,
    amount: u128,
    direction: LaneDirection,
    what: &str,
) -> Result<LaneBucket> {
    if amount > bucket.capacity {
        return Err(BridgeError::TransferFailed(format!(
            "{amount} exceeds the {} lane capacity of {} on route {what}",
            direction.as_str(),
            bucket.capacity,
        )));
    }
    bucket.take(amount).ok_or_else(|| {
        let wait = amount
            .saturating_sub(bucket.tokens)
            .div_ceil(bucket.rate.max(1));
        BridgeError::TransferFailed(format!(
            "the {} lane of route {what} holds {} now; retry in {wait} s",
            direction.as_str(),
            bucket.tokens
        ))
    })
}
