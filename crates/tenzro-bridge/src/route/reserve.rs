//! Proof of Reserve for bridged TNZO, cross-checked with the route's own
//! supply record.
//!
//! A reserve feed for a route reports the TNZO held on Tenzro behind the
//! representation on the external chain, as an independent oracle network
//! observes it. The framework's supply record holds the same quantity as
//! Tenzro's chain state sees it (`locked`), with `bridged <= locked` enforced
//! on every transfer. Two independent views of one number must agree.
//!
//! They can differ legitimately only by what moved since the feed's round:
//! inbound releases are bounded by the route's per-epoch limit, outbound
//! locks by the lane's outbound bucket (its capacity plus what it refilled
//! since the round). A difference beyond that allowance is anomaly evidence,
//! and validators that see it flag the route's circuit breaker.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::state::SupplyRecord;
use super::{BridgeRoute, MintRateLimit};
use crate::chainlink_por::PorReading;
use crate::error::{BridgeError, Result};

/// Decimals of TNZO's smallest unit.
pub const TNZO_DECIMALS: u8 = 18;

/// The reserve feed asset id for `route`, under which its feed is
/// registered.
pub fn reserve_asset_id(route: &BridgeRoute) -> String {
    format!("tnzo:{}", route.storage_key())
}

/// One reserve reading set against the route's supply record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReserveCheck {
    /// The route.
    pub route: String,
    /// The feed's round.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub round_id: u128,
    /// The reserve the feed reports, in TNZO's smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub reserve: u128,
    /// TNZO locked on Tenzro for the route.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub locked: u128,
    /// The representation outstanding on the external chain.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub bridged: u128,
    /// How far the two may differ from movement since the round.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub allowance: u128,
    /// Whether the reserve agrees with the supply record.
    pub holds: bool,
}

impl ReserveCheck {
    /// SHA-256 of the evidence, hex: the route, the round and the reserve it
    /// reports. Validators reading the same round name the same evidence,
    /// so their findings add up.
    pub fn evidence_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"tenzro/bridge/reserve-evidence");
        h.update(self.route.as_bytes());
        h.update(self.round_id.to_be_bytes());
        h.update(self.reserve.to_be_bytes());
        hex::encode(h.finalize())
    }

    /// Why the route should pause, worded from the round alone so every
    /// validator flagging it states the same finding.
    pub fn reason(&self) -> String {
        format!(
            "proof of reserve round {} reports {} locked for {}, outside what the route's supply record allows",
            self.round_id, self.reserve, self.route
        )
    }
}

fn to_tnzo_units(value: u128, decimals: u8) -> Result<u128> {
    let overflow = || BridgeError::InvalidParameter("reserve does not fit TNZO units".into());
    if decimals <= TNZO_DECIMALS {
        let scale = 10u128
            .checked_pow(u32::from(TNZO_DECIMALS - decimals))
            .ok_or_else(overflow)?;
        value.checked_mul(scale).ok_or_else(overflow)
    } else {
        let scale = 10u128
            .checked_pow(u32::from(decimals - TNZO_DECIMALS))
            .ok_or_else(overflow)?;
        Ok(value / scale)
    }
}

/// Set `reading` against the route's supply record at `now_secs`.
pub fn cross_check(
    route: &BridgeRoute,
    supply: &SupplyRecord,
    network: MintRateLimit,
    reading: &PorReading,
    now_secs: u64,
) -> Result<ReserveCheck> {
    let reserve = to_tnzo_units(reading.reserve, reading.decimals)?;
    let age = u128::from(now_secs.saturating_sub(reading.updated_at));
    let outbound = route
        .outflow
        .capacity
        .saturating_add(route.outflow.rate.saturating_mul(age));
    let allowance = route
        .mint_limit
        .tightest(network)
        .per_epoch
        .saturating_add(outbound);
    Ok(ReserveCheck {
        route: route.storage_key(),
        round_id: reading.round_id,
        reserve,
        locked: supply.locked,
        bridged: supply.bridged,
        allowance,
        holds: reserve.abs_diff(supply.locked) <= allowance,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::committee;
    use super::super::{BridgeRouteAdapter, CcipLane, CcipLaneVersion, ChainFamily, LaneRateLimit};
    use super::*;

    fn route() -> BridgeRoute {
        BridgeRoute {
            adapter: BridgeRouteAdapter::Ccip,
            family: ChainFamily::Evm,
            source_chain: "ethereum".into(),
            source_chain_id: 5_009_297_550_715_157_269,
            local_selector: 7_777,
            peer: [1; 32],
            ramp: [2; 32],
            local_endpoint: [3; 32],
            remote_token: [4; 32],
            verifiers: committee(1, 5, 3).1,
            blessing: Some(committee(40, 5, 3).1),
            light_client: None,
            mint_limit: MintRateLimit {
                per_mint: 100,
                per_epoch: 1_000,
            },
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
            outflow: LaneRateLimit {
                capacity: 500,
                rate: 1,
            },
            lane_limits: Some(CcipLane {
                version: CcipLaneVersion::V1_6,
                off_ramp: [0u8; 20],
                ccv_and_executor_hash: [0u8; 32],
                inbound: LaneRateLimit {
                    capacity: 1_000,
                    rate: 1,
                },
            }),
        }
    }

    fn reading(reserve: u128, decimals: u8, updated_at: u64) -> PorReading {
        PorReading {
            reserve,
            updated_at,
            round_id: 9,
            decimals,
        }
    }

    const NETWORK: MintRateLimit = MintRateLimit {
        per_mint: u128::MAX,
        per_epoch: u128::MAX,
    };

    fn supply(locked: u128, bridged: u128) -> SupplyRecord {
        SupplyRecord { locked, bridged }
    }

    #[test]
    fn a_reserve_within_recent_movement_holds() {
        let now = 1_000;
        // Allowance: one epoch (1 000) plus the outbound bucket (500 + 10 s).
        let check = cross_check(
            &route(),
            &supply(5_000, 5_000),
            NETWORK,
            &reading(3_490, 18, now - 10),
            now,
        )
        .unwrap();
        assert_eq!(check.allowance, 1_510);
        assert!(check.holds);
        let scaled = cross_check(
            &route(),
            &supply(5_000, 5_000),
            NETWORK,
            &reading(5, 15, now),
            now,
        )
        .unwrap();
        assert_eq!(scaled.reserve, 5_000);
        assert!(scaled.holds);
    }

    #[test]
    fn a_reserve_the_supply_record_cannot_explain_is_a_finding() {
        let now = 1_000;
        let short = cross_check(
            &route(),
            &supply(5_000, 4_000),
            NETWORK,
            &reading(3_400, 18, now),
            now,
        )
        .unwrap();
        assert!(!short.holds, "reserve far below what is locked");
        let over = cross_check(
            &route(),
            &supply(5_000, 4_000),
            NETWORK,
            &reading(6_600, 18, now),
            now,
        )
        .unwrap();
        assert!(!over.holds, "reserve far above what is locked");

        // Validators reading the same round name the same evidence, whatever
        // their view of the supply record when they read it.
        let later = cross_check(
            &route(),
            &supply(5_100, 4_100),
            NETWORK,
            &reading(3_400, 18, now),
            now,
        )
        .unwrap();
        assert_eq!(short.evidence_hash(), later.evidence_hash());
        assert_eq!(short.reason(), later.reason());
        assert_ne!(short.evidence_hash(), over.evidence_hash());
    }
}
