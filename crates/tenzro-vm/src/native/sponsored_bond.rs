//! Governance-sponsored validator bonds.
//!
//! An enacted [`crate::governance::ProposalAction::SponsorValidatorBond`]
//! moves existing TNZO from the treasury into the staking vault as part of a
//! registered validator's bond. Nothing is issued: the TNZO was already in
//! supply and only changes which network-held account holds it. The
//! sponsored part:
//!
//! - counts toward the validator's bond, and is slashed with it in
//!   proportion, into the insurance pool like any bond;
//! - never votes in governance and is not counted in the quorum;
//! - is never paid to the validator: on recall
//!   ([`crate::governance::ProposalAction::RecallSponsoredBond`]) or on the
//!   validator's exit it unbonds for the governed period and then returns to
//!   the treasury, by a [`SponsoredBondOp::Release`] anyone may send or with
//!   the validator's own withdrawal;
//! - earns nothing: rewards follow recorded work, never stake, so a sponsored
//!   bond neither earns a reward nor moves one.
//!
//! It covers the bond only; running costs are paid by
//! [`crate::governance::ProposalAction::SponsorOperatorRunningCost`]. The
//! validator must be an approved operator ([`super::payout_gates`]), and the
//! sponsored amount counts against the yearly sponsorship caps. All governed
//! caps start at zero, so no bond can be sponsored until governance sets
//! them.

use serde::{Deserialize, Serialize};

use super::funding::{move_balance, refuse, treasury_outflow};
use super::staking;
use super::{STAKING_VAULT_ADDRESS, SYSTEM_ADDRESS, derive_treasury_address, network_param};
use crate::error::Result;
use crate::traits::VmState;
use crate::types::{Log, StateChange};
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SponsoredBondOp;

/// Gas for one sponsored-bond operation.
pub const GAS_SPONSORED_BOND: u64 = 60_000;
/// Governed key: most sponsored stake one validator may hold, bonded and
/// unbonding, whole TNZO. Zero disables sponsorship.
pub const MAX_PER_VALIDATOR_PARAM: &str = "validator.sponsored_bond_max_tnzo";
/// Governed key: most sponsored stake out of the treasury network-wide,
/// bonded and unbonding, whole TNZO. Zero disables sponsorship.
pub const MAX_TOTAL_PARAM: &str = "validator.sponsored_bond_total_max_tnzo";
/// Log topic: treasury TNZO bonded on a validator's behalf.
pub const SPONSORED_TOPIC: &[u8] = b"ValidatorBondSponsored";
/// Log topic: sponsored stake recalled into unbonding.
pub const RECALLED_TOPIC: &[u8] = b"SponsoredBondRecalled";
/// Log topic: sponsored stake returned to the treasury.
pub const RETURNED_TOPIC: &[u8] = b"SponsoredBondReturned";

const ONE_TNZO: u128 = tenzro_types::constants::ONE_TNZO;

/// What each sponsored-bond log carries, JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredBondEvent {
    /// The validator.
    pub validator: Address,
    /// How much this event sponsored, recalled or returned.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    /// The sponsored part of its bond afterwards.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub sponsored_bond: u128,
    /// Its sponsored stake unbonding afterwards.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub sponsored_unbonding: u128,
    /// When unbonding sponsored stake can return to the treasury.
    pub release_at_ms: Option<i64>,
}

fn event(
    state: &dyn VmState,
    topic: &[u8],
    validator: &[u8],
    amount: u128,
    release: Option<i64>,
) -> Log {
    let mut a = [0u8; 32];
    let n = validator.len().min(32);
    a[..n].copy_from_slice(&validator[..n]);
    let e = SponsoredBondEvent {
        validator: Address::new(a),
        amount,
        sponsored_bond: staking::sponsored_bond_of(state, validator),
        sponsored_unbonding: staking::sponsored_unbonding_of(state, validator),
        release_at_ms: release,
    };
    Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![topic.to_vec()],
        serde_json::to_vec(&e).unwrap_or_default(),
    )
}

fn whole_tnzo(state: &dyn VmState, key: &str) -> u128 {
    u128::from(network_param(state, key)).saturating_mul(ONE_TNZO)
}

/// Whether `amount` more may be sponsored for `validator`: it must be a
/// registered validator with a live bond, and the sponsored stake it and the
/// network would hold must stay within the governed caps.
pub fn check_sponsor(state: &dyn VmState, validator: &[u8], amount: u128) -> Result<()> {
    if amount == 0 {
        return Err(refuse("a sponsored bond must be greater than zero"));
    }
    super::payout_gates::check_sponsored_bond_operator(state, validator)?;
    let marker = format!("validator_register:{}", hex::encode(validator));
    let registered = state
        .get_storage(&SYSTEM_ADDRESS, marker.as_bytes())
        .is_some_and(|b| !b.is_empty());
    if !registered || staking::bonded_stake_of(state, validator) == 0 {
        return Err(refuse(format!(
            "{} is not a registered validator with a live bond",
            hex::encode(validator)
        )));
    }
    let per = whole_tnzo(state, MAX_PER_VALIDATOR_PARAM);
    let total = whole_tnzo(state, MAX_TOTAL_PARAM);
    if per == 0 || total == 0 {
        return Err(refuse(format!(
            "sponsored bonds are disabled: governance has not set {MAX_PER_VALIDATOR_PARAM} \
             and {MAX_TOTAL_PARAM}"
        )));
    }
    let held = staking::sponsored_bond_of(state, validator)
        .saturating_add(staking::sponsored_unbonding_of(state, validator))
        .saturating_add(amount);
    if held > per {
        return Err(refuse(format!(
            "{} would hold {held} sponsored stake, above the {per} one validator may hold",
            hex::encode(validator)
        )));
    }
    let out = staking::total_sponsored_outstanding(state).saturating_add(amount);
    if out > total {
        return Err(refuse(format!(
            "{out} sponsored stake would be out of the treasury, above the {total} cap"
        )));
    }
    Ok(())
}

/// Whether `amount` of `validator`'s sponsored bond can be recalled.
pub fn check_recall(state: &dyn VmState, validator: &[u8], amount: u128) -> Result<()> {
    let sponsored = staking::sponsored_bond_of(state, validator);
    if amount == 0 || amount > sponsored {
        return Err(refuse(format!(
            "{} has {sponsored} sponsored bond; {amount} cannot be recalled",
            hex::encode(validator)
        )));
    }
    Ok(())
}

/// Enacts a sponsorship: moves `amount` of existing treasury TNZO into the
/// staking vault as sponsored bond of `validator`. Counts against the
/// treasury's outflow caps; pays nothing to anyone.
pub(super) fn sponsor_bond(
    state: &mut dyn VmState,
    proposal_id: &str,
    validator: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    check_sponsor(state, validator, amount)?;
    super::payout_gates::record_bond_sponsorship(
        state,
        proposal_id,
        validator,
        amount,
        now_ms,
        changes,
        logs,
    )?;
    treasury_outflow(state, amount, amount, now_ms, changes)?;
    move_balance(
        state,
        derive_treasury_address().as_bytes(),
        &STAKING_VAULT_ADDRESS,
        amount,
        changes,
    )?;
    staking::add_sponsored_bond(state, validator, amount, now_ms)?;
    logs.push(event(state, SPONSORED_TOPIC, validator, amount, None));
    Ok(())
}

/// Enacts a recall: `amount` of `validator`'s sponsored bond unbonds, still
/// slashable, and returns to the treasury once the period has passed.
pub(super) fn recall_bond(
    state: &mut dyn VmState,
    validator: &[u8],
    amount: u128,
    now_ms: i64,
    logs: &mut Vec<Log>,
) -> Result<()> {
    check_recall(state, validator, amount)?;
    let unbonding = staking::recall_sponsored_bond(state, validator, amount, now_ms)?;
    logs.push(event(
        state,
        RECALLED_TOPIC,
        validator,
        amount,
        Some(unbonding.release_at_ms),
    ));
    Ok(())
}

/// The log of sponsored stake a validator's own withdrawal returned to the
/// treasury.
pub(super) fn returned_log(state: &dyn VmState, validator: &[u8], amount: u128) -> Log {
    event(state, RETURNED_TOPIC, validator, amount, None)
}

/// `SponsoredBond(op)`: return a validator's matured unbonding sponsored
/// stake to the treasury. Anyone may send it; it moves value only from the
/// staking vault back to the treasury.
pub fn execute(
    state: &mut dyn VmState,
    _from: &[u8],
    payload: &[u8],
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let op: SponsoredBondOp = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("invalid SponsoredBond payload: {e}")))?;
    match op {
        SponsoredBondOp::Release { validator } => {
            let returned = staking::release_recalled(state, validator.as_bytes(), now_ms)?;
            Ok((
                Vec::new(),
                vec![returned_log(state, validator.as_bytes(), returned)],
            ))
        }
    }
}
