//! The RPC-provider leg of a settlement.
//!
//! A node that serves without validating relies on a validator for the
//! chain it settles on. Its payee names that validator with a native call
//! ([`tenzro_native_ops::rpc_provider::RpcProviderOp`]); the named account
//! must hold a validator bond, and the payee may not name itself. Once
//! [`GATE`] is in force, a TNZO settlement to a payee that holds no
//! validator bond and has named one whose bond stands pays that validator
//! [`RATE_PARAM`] of what is left after the settlement fee and the treasury
//! leg, out of the payee's credit. A payee that names no one pays no leg.
//! A settlement plan pays it out of the line that takes the remainder (its
//! primary payee), and records it under `plan_rpc_leg:{plan}` so what the
//! primary is reported to have been paid is what it received.
//!
//! Records, under `SYSTEM_ADDRESS`:
//! - `rpc_provider_of:{payee}` — the named validator, hex.
//! - `rpc_provider_leg_paid:{validator}` — TNZO paid to it by the leg in all.

use super::funding::{delete_record, read_json, refuse, write_json};
use super::*;

/// The gate of the leg and of naming a provider.
pub const GATE: &str = "feature.rpc_provider_leg.activation_epoch";

/// Governed key: the leg, bps of what a settlement leaves its payee after
/// the fee and the treasury leg.
pub const RATE_PARAM: &str = "fees.rpc_provider_leg_bps";

pub use tenzro_native_ops::SELECTOR_RPC_PROVIDER;

/// Gas for naming a provider.
pub const GAS_RPC_PROVIDER: u64 = 30_000;

/// Topic of the log a naming emits.
pub const RPC_PROVIDER_NAMED_TOPIC: &[u8] = b"RpcProviderNamed";

fn named_key(payee: &[u8]) -> String {
    format!("rpc_provider_of:{}", hex::encode(payee))
}

fn paid_key(provider: &[u8]) -> String {
    format!("rpc_provider_leg_paid:{}", hex::encode(provider))
}

/// The validator `payee` named, if any.
pub fn named_provider(state: &dyn VmState, payee: &[u8]) -> Option<Vec<u8>> {
    read_json::<String>(state, &named_key(payee)).and_then(|h| hex::decode(h).ok())
}

/// TNZO the leg has paid `provider` in all.
pub fn leg_paid(state: &dyn VmState, provider: &[u8]) -> u128 {
    read_json::<String>(state, &paid_key(provider))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Name, or with an all-zero account clear, the validator `from` relies on.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse(
            "the RPC-provider leg is not in force on this chain yet",
        ));
    }
    let op: tenzro_native_ops::rpc_provider::RpcProviderOp = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("Invalid RPC provider payload: {e}")))?;
    op.validate().map_err(refuse)?;
    let mut changes = Vec::new();
    if op.clears() {
        delete_record(state, &named_key(from), &mut changes);
    } else {
        if op.provider == from {
            return Err(refuse("a payee does not name itself as its RPC provider"));
        }
        if super::staking::bonded_stake_of(state, &op.provider) == 0 {
            return Err(refuse(format!(
                "{} holds no validator bond; an RPC provider is a bonded validator",
                hex::encode(&op.provider)
            )));
        }
        write_json(
            state,
            &named_key(from),
            &hex::encode(&op.provider),
            &mut changes,
        )?;
    }
    let data = serde_json::to_vec(&serde_json::json!({
        "payee": hex::encode(from),
        "provider": (!op.clears()).then(|| hex::encode(&op.provider)),
    }))
    .map_err(|e| VmError::Internal(format!("encode RPC provider log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![RPC_PROVIDER_NAMED_TOPIC.to_vec()],
            data,
        )],
    ))
}

/// The validator `payee` named and the leg owed it on `left`, what a
/// settlement leaves the payee after the fee and the treasury leg; `None`
/// when the leg is dormant, the payee validates, names no one, names a
/// validator whose bond no longer stands, or the leg rounds to nothing.
fn owed(state: &dyn VmState, payee: &[u8], left: u128) -> Option<(Vec<u8>, u128)> {
    if !crate::feature_gate::is_live_now(state, GATE)
        || super::staking::bonded_stake_of(state, payee) > 0
    {
        return None;
    }
    let provider = named_provider(state, payee)?;
    if super::staking::bonded_stake_of(state, &provider) == 0 {
        return None;
    }
    let leg = super::funding::bps_of(left, network_param(state, RATE_PARAM).min(10_000));
    (leg > 0).then_some((provider, leg))
}

fn record_paid(
    state: &mut dyn VmState,
    provider: &[u8],
    leg: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let paid = leg_paid(state, provider).saturating_add(leg);
    write_json(state, &paid_key(provider), &paid.to_string(), changes)?;
    Ok(())
}

/// Pay the leg on `left` to the validator `payee` named, and return it. The
/// caller has already taken the settlement's value from the payer, so the
/// leg is credited here and the caller credits the payee `left` less it.
pub(super) fn pay(
    state: &mut dyn VmState,
    payee: &[u8],
    left: u128,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let Some((provider, leg)) = owed(state, payee, left) else {
        return Ok(0);
    };
    let old = state.get_balance(&provider);
    let new = old
        .checked_add(leg)
        .ok_or_else(|| VmError::Internal("RPC provider balance overflow".into()))?;
    state.set_balance(&provider, new);
    changes.push(StateChange::new(
        provider.clone(),
        b"balance".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some(new.to_le_bytes().to_vec()),
    ));
    record_paid(state, &provider, leg, changes)?;
    Ok(leg)
}

/// [`pay`] for value still held in `from`, a plan's vault: the leg moves
/// from it to the validator, and the caller moves the payee `left` less it.
pub(super) fn pay_from(
    state: &mut dyn VmState,
    from: &[u8],
    payee: &[u8],
    left: u128,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let Some((provider, leg)) = owed(state, payee, left) else {
        return Ok(0);
    };
    super::funding::move_balance(state, from, &provider, leg, changes)?;
    record_paid(state, &provider, leg, changes)?;
    Ok(leg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use tenzro_native_ops::rpc_provider::RpcProviderOp;

    const TNZO: u128 = 1_000_000_000_000_000_000;
    const PAYER: [u8; 32] = [1; 32];
    const PAYEE: [u8; 32] = [2; 32];
    const VALIDATOR: [u8; 32] = [3; 32];

    fn chain(live: bool) -> StateAdapter {
        let mut state = StateAdapter::new();
        super::super::staking::add_bond(&mut state, &VALIDATOR, 1_000 * TNZO, 0).unwrap();
        if live {
            set_governed_param_for_test(&mut state, GATE, 0);
        }
        state
    }

    fn name(state: &mut StateAdapter, from: &[u8], provider: &[u8]) -> Result<()> {
        let op = RpcProviderOp {
            provider: provider.to_vec(),
        };
        apply(state, from, &tenzro_native_ops::encode(&op)).map(|_| ())
    }

    fn settle(state: &mut StateAdapter, payee: &[u8]) -> super::super::economy::Payout {
        super::super::economy::settle_payout(
            state,
            &PAYER,
            payee,
            100 * TNZO,
            &super::super::economy::Earning::default(),
            &mut Vec::new(),
        )
        .unwrap()
    }

    /// Dormant, a payee cannot name a provider and a settlement pays as it
    /// did, even with a naming already in state.
    #[test]
    fn a_dormant_leg_leaves_a_settlement_as_it_was() {
        let mut state = chain(false);
        assert!(name(&mut state, &PAYEE, &VALIDATOR).is_err());
        let plain = settle(&mut chain(false), &PAYEE);
        write_json(
            &mut state,
            &named_key(&PAYEE),
            &hex::encode(VALIDATOR),
            &mut Vec::new(),
        )
        .unwrap();
        let before = state.get_balance(&VALIDATOR);
        assert_eq!(settle(&mut state, &PAYEE), plain);
        assert_eq!(plain.rpc_leg, 0);
        assert_eq!(state.get_balance(&VALIDATOR), before);
    }

    /// Live, the named validator is paid the governed share of what the
    /// payee is left after the fee and the treasury leg, out of the payee's
    /// credit, and the total it was paid is recorded.
    #[test]
    fn a_live_leg_pays_the_named_validator_from_the_payees_credit() {
        let plain = settle(&mut chain(true), &PAYEE);
        let mut state = chain(true);
        name(&mut state, &PAYEE, &VALIDATOR).unwrap();
        assert_eq!(named_provider(&state, &PAYEE), Some(VALIDATOR.to_vec()));
        let before = state.get_balance(&VALIDATOR);
        let paid = settle(&mut state, &PAYEE);
        let leg = super::super::funding::bps_of(plain.credit, 1_000);
        assert!(leg > 0);
        assert_eq!(paid.rpc_leg, leg);
        assert_eq!(paid.credit + paid.rpc_leg, plain.credit);
        assert_eq!(paid.treasury_leg, plain.treasury_leg);
        assert_eq!(state.get_balance(&VALIDATOR) - before, leg);
        assert_eq!(leg_paid(&state, &VALIDATOR), leg);
        settle(&mut state, &PAYEE);
        assert_eq!(leg_paid(&state, &VALIDATOR), 2 * leg);
    }

    /// A payee that validates itself pays no leg, nor does one whose named
    /// validator's bond no longer stands, nor one that cleared its naming.
    #[test]
    fn no_leg_without_a_standing_provider_for_a_non_validator() {
        let mut state = chain(true);
        name(&mut state, &PAYEE, &VALIDATOR).unwrap();
        super::super::staking::add_bond(&mut state, &PAYEE, TNZO, 0).unwrap();
        assert_eq!(settle(&mut state, &PAYEE).rpc_leg, 0);

        let mut state = chain(true);
        let gone = [4u8; 32];
        write_json(
            &mut state,
            &named_key(&PAYEE),
            &hex::encode(gone),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(settle(&mut state, &PAYEE).rpc_leg, 0);

        let mut state = chain(true);
        name(&mut state, &PAYEE, &VALIDATOR).unwrap();
        name(&mut state, &PAYEE, &[0; 32]).unwrap();
        assert_eq!(named_provider(&state, &PAYEE), None);
        assert_eq!(settle(&mut state, &PAYEE).rpc_leg, 0);
    }

    /// A payee names a bonded validator other than itself.
    #[test]
    fn a_payee_names_a_bonded_validator_other_than_itself() {
        let mut state = chain(true);
        assert!(name(&mut state, &PAYEE, &[4; 32]).is_err());
        assert!(name(&mut state, &VALIDATOR, &VALIDATOR).is_err());
        assert!(name(&mut state, &PAYEE, &[3; 31]).is_err());
        assert_eq!(named_provider(&state, &PAYEE), None);
    }
}
