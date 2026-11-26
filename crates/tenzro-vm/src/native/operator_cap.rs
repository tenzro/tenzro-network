//! One operator's and one region's share of the committee.
//!
//! Once [`GATE`] is in force, every node stages the next committee so that
//! the validators behind one root identity (a machine's controller, or the
//! identity itself) hold at most [`CAP_PARAM`] of its seats; once
//! [`REGION_GATE`] is, so that the validators of approved operators that
//! declared one region hold at most [`REGION_CAP_PARAM`], so losing any one
//! region leaves a quorum. The rule that scales the stakes is
//! `tenzro_consensus::committee::cap_group_stakes`; the node applies it at
//! each epoch boundary from the registry and this state.
//!
//! The caps bind what the chain knows. An operator who runs validators
//! under separate root identities is counted once per root. A region is
//! what an approved operator declared when it was approved: a validator
//! with no approval, or a false declaration, is not held to any region.

use super::*;

/// Gate of the operator cap.
pub const GATE: &str = "feature.operator_weight_cap.activation_epoch";

/// Governed key: most of the committee's seats one operator may hold, bps.
pub const CAP_PARAM: &str = "consensus.operator_weight_max_bps";

/// Gate of the region cap.
pub const REGION_GATE: &str = "feature.region_weight_cap.activation_epoch";

/// Governed key: most of the committee's seats the validators declared in
/// one region may hold, bps.
pub const REGION_CAP_PARAM: &str = "consensus.region_weight_max_bps";

/// The region validator `account`'s operator approval declared, lowercased;
/// `None` for a validator with no approval or an empty declaration.
pub fn declared_region(state: &dyn VmState, account: &[u8]) -> Option<String> {
    let region = super::payout_gates::operator_approval(state, account)?
        .criteria
        .region
        .trim()
        .to_lowercase();
    (!region.is_empty()).then_some(region)
}

/// The region cap in force, bps, or `None` while [`REGION_GATE`] is dormant.
pub fn region_cap_in_force(state: &dyn VmState) -> Option<u32> {
    crate::feature_gate::is_live_now(state, REGION_GATE).then(|| {
        u32::try_from(network_param(state, REGION_CAP_PARAM).min(10_000)).unwrap_or(10_000)
    })
}

/// The root identity behind validator `account`: its machine identity's
/// controller, or the identity itself; `None` for an account with no
/// identity, which counts as an operator of its own.
pub fn operator_root(state: &dyn VmState, account: &[u8]) -> Option<String> {
    super::economy::root_of(state, account)
}

/// The cap in force, bps, or `None` while [`GATE`] is dormant.
pub fn cap_in_force(state: &dyn VmState) -> Option<u32> {
    crate::feature_gate::is_live_now(state, GATE)
        .then(|| u32::try_from(network_param(state, CAP_PARAM).min(10_000)).unwrap_or(10_000))
}
