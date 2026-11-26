//! CCIP 2.0 transfers sent before the sending chain's finality.
//!
//! A CCIP 2.0 message carries the finality its sender asked for, encoded as
//! the CCIP contracts' `FinalityCodec` encodes it: zero waits for the sending
//! chain's finality; the low 16 bits are a block depth; bit 16 waits for the
//! sending chain's `safe` head; the other high bits are flags not yet
//! assigned. A token pool keeps the finality it allows (`allowedFinality`)
//! and a separate bucket the transfers below finality draw on instead of its
//! ordinary inbound bucket.
//!
//! A route here does the same once `feature.ccip_finality_policy` is live: a
//! transfer that waited for finality draws on the lane as before; any other
//! is refused unless the route (or the carried asset) has a
//! [`CcipFinalityPolicy`] that allows it, and then draws on the policy's
//! bucket. Whether any route accepts a transfer before its sending chain's
//! finality is decided by governance; the network starts with no policy.
//! Until the gate is live the finality a message carries is not read.

use serde::{Deserialize, Serialize};
use tenzro_types::bridge_route::LaneRateLimit;

use super::BridgeRoute;
use super::lane::{self, LaneDirection};
use super::state::RouteState;
use crate::error::{BridgeError, Result};

/// The finality a CCIP 2.0 message asks for, as the message carries it.
pub type CcipFinality = [u8; 4];

/// Wait for the sending chain's finality.
pub const WAIT_FOR_FINALITY: CcipFinality = [0; 4];

/// Bits of a [`CcipFinality`] that hold a block depth.
const DEPTH_BITS: u32 = 16;

/// The lowest finality a route accepts below the sending chain's own, and the
/// bucket those transfers draw on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcipFinalityPolicy {
    /// What the route allows: the smallest block depth, the `safe` flag, or
    /// both, encoded as a [`CcipFinality`].
    pub allowed: CcipFinality,
    /// The bucket a transfer below finality draws on instead of the lane's
    /// inbound bucket.
    pub fast_inbound: LaneRateLimit,
}

impl CcipFinalityPolicy {
    /// A policy that allows something below finality, limits it, and is set
    /// on a route whose messages carry a finality: a CCIP 2.0 lane admitted on
    /// attestations. A route with a light client proves each delivery final
    /// on its sending chain, so nothing below finality can reach it.
    pub fn validate(&self, route: &BridgeRoute) -> Result<()> {
        if self.allowed == WAIT_FOR_FINALITY {
            return Err(BridgeError::InvalidParameter(
                "a finality policy must allow a block depth or the safe head".into(),
            ));
        }
        self.fast_inbound
            .validate("fast-finality inbound")
            .map_err(|e| BridgeError::InvalidParameter(e.to_string()))?;
        let v2_0 = route
            .lane_limits
            .is_some_and(|l| l.version == tenzro_types::bridge_route::CcipLaneVersion::V2_0);
        if !v2_0 {
            return Err(BridgeError::InvalidParameter(format!(
                "route {} is not a CCIP 2.0 lane: its messages carry no finality",
                route.storage_key()
            )));
        }
        if route.light_client.is_some() {
            return Err(BridgeError::InvalidParameter(format!(
                "route {} proves every delivery final on its sending chain; a finality \
                 policy cannot apply to it",
                route.storage_key()
            )));
        }
        Ok(())
    }
}

/// `requested` is allowed by `allowed`, as `FinalityCodec`'s
/// `_ensureRequestedFinalityAllowed` decides it. Finality is always allowed.
/// Any other request holds exactly one mode, a flag or a block depth; a flag
/// it shares with `allowed` is allowed, and a block depth is allowed when
/// `allowed` names a depth no greater than it.
pub fn ensure_allowed(requested: CcipFinality, allowed: CcipFinality) -> Result<()> {
    let requested = u32::from_be_bytes(requested);
    let allowed = u32::from_be_bytes(allowed);
    if requested == 0 {
        return Ok(());
    }
    let depth_mask = (1u32 << DEPTH_BITS) - 1;
    let modes = (requested >> DEPTH_BITS).count_ones() + u32::from(requested & depth_mask != 0);
    if modes != 1 {
        return Err(BridgeError::InvalidParameter(format!(
            "requested finality {requested:#010x} names more than one mode"
        )));
    }
    if (requested >> DEPTH_BITS) & (allowed >> DEPTH_BITS) != 0 {
        return Ok(());
    }
    let wanted = requested & depth_mask;
    let least = allowed & depth_mask;
    if least == 0 || wanted < least {
        return Err(BridgeError::InvalidParameter(format!(
            "requested finality {requested:#010x} is below what the route allows \
             ({allowed:#010x})"
        )));
    }
    Ok(())
}

fn suffix(asset: Option<&str>) -> String {
    asset.map(|a| format!(":{a}")).unwrap_or_default()
}

/// Key of the finality policy of `route`, or of the carried `asset` on it.
pub fn policy_key(route: &BridgeRoute, asset: Option<&str>) -> String {
    format!(
        "bridge_finality_policy:{}{}",
        route.storage_key(),
        suffix(asset)
    )
}

/// Key of the bucket transfers below finality draw on.
pub fn fast_lane_key(route: &BridgeRoute, asset: Option<&str>) -> String {
    format!(
        "bridge_fast_lane:inbound:{}{}",
        route.storage_key(),
        suffix(asset)
    )
}

/// The finality policy in force for `route` (or the carried `asset`), if one
/// is set.
pub fn read_policy(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: Option<&str>,
) -> Option<CcipFinalityPolicy> {
    state
        .get(&policy_key(route, asset))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The bucket a delivery asking for `requested` draws on instead of the
/// lane's inbound bucket: `None` while the finality policy gate is dormant or
/// for a delivery that waited for finality, otherwise the write that draws
/// `amount` from the policy's bucket. A request below finality on a route
/// without a policy that allows it is refused.
pub fn consume_fast_inbound(
    state: &dyn RouteState,
    route: &BridgeRoute,
    asset: Option<&str>,
    requested: CcipFinality,
    amount: u128,
) -> Result<Option<(String, Vec<u8>)>> {
    if !state.finality_policy_live() || requested == WAIT_FOR_FINALITY {
        return Ok(None);
    }
    let what = format!("{}{}", route.storage_key(), suffix(asset));
    let policy = read_policy(state, route, asset).ok_or_else(|| {
        BridgeError::TransferFailed(format!(
            "route {what} accepts no transfer before its sending chain's finality"
        ))
    })?;
    ensure_allowed(requested, policy.allowed)?;
    let key = fast_lane_key(route, asset);
    let bucket = lane::bucket_at(state, &key, policy.fast_inbound);
    let drawn = lane::draw(bucket, amount, LaneDirection::Inbound, &what)?;
    Ok(Some((key, drawn.encode())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH_12: CcipFinality = [0, 0, 0, 12];
    const SAFE: CcipFinality = [0, 1, 0, 0];
    const SAFE_OR_DEPTH_12: CcipFinality = [0, 1, 0, 12];

    /// The cases `FinalityCodec` distinguishes.
    #[test]
    fn requested_finality_is_checked_as_the_ccip_codec_checks_it() {
        // Finality is allowed whatever the route allows.
        assert!(ensure_allowed(WAIT_FOR_FINALITY, WAIT_FOR_FINALITY).is_ok());
        assert!(ensure_allowed(WAIT_FOR_FINALITY, DEPTH_12).is_ok());
        // A depth at or above the allowed one.
        assert!(ensure_allowed(DEPTH_12, DEPTH_12).is_ok());
        assert!(ensure_allowed([0, 0, 0, 40], DEPTH_12).is_ok());
        // A depth below it, or a route that allows no depth.
        assert!(ensure_allowed([0, 0, 0, 11], DEPTH_12).is_err());
        assert!(ensure_allowed(DEPTH_12, SAFE).is_err());
        // The safe flag when the route allows it, alone or with a depth.
        assert!(ensure_allowed(SAFE, SAFE).is_ok());
        assert!(ensure_allowed(SAFE, SAFE_OR_DEPTH_12).is_ok());
        assert!(ensure_allowed(DEPTH_12, SAFE_OR_DEPTH_12).is_ok());
        assert!(ensure_allowed(SAFE, DEPTH_12).is_err());
        // A request names exactly one mode.
        assert!(ensure_allowed(SAFE_OR_DEPTH_12, SAFE_OR_DEPTH_12).is_err());
        assert!(ensure_allowed([0, 3, 0, 0], [0, 3, 0, 0]).is_err());
        // An unassigned flag the route does not name is refused.
        assert!(ensure_allowed([0, 2, 0, 0], SAFE).is_err());
    }
}
