//! A transaction needs a registered sender (layer 2 at execution).
//!
//! Tenzro has no participants without an identity and a wallet. The mempool
//! already refuses a transaction from an account with no registered identity
//! (node-local policy); this is the same rule as a state-transition rule, so
//! a block that carries such a transaction fails it on every validator the
//! same way. It changes what blocks do, so it ships dormant and is switched
//! on at one epoch for every node by a governance vote
//! ([`crate::feature_gate`]): `feature.identity_required.activation_epoch`,
//! [`crate::feature_gate::NEVER`] until a vote sets it.
//!
//! What is admitted from an account with no registered identity:
//! - the transactions that are how an identity is registered
//!   (`RegisterIdentity`, `AccountKeys`: the registration enrols the key);
//! - a record the protocol asks a validator to make (it pays no fee and the
//!   handler checks the bond);
//! - anything from an account that already holds a validator bond, so the
//!   chain keeps running through the activation.
//!
//! An in-process call with no signing digest (a read-only call) is never
//! refused, as for [`crate::tx_validity`].
//!
//! Once live, the rule's epoch is final, so the rule carries its own governed
//! mode beside the gate, [`MODE_KEY`]: `0` enforce (the genesis value), `1`
//! audit (nothing is refused; what enforce would refuse is logged), `2` off.
//! A `parameter_change` moves it with no new genesis and no release: relaxing
//! applies at the next epoch, and a change to audit runs on the expedited
//! track like a pause; going back to enforce waits out the tightening grace
//! window. The node's own admission layers (peer gate, mempool, edge) read
//! the same mode, so a vote relaxes the whole gate at once.

use crate::VmType;
use crate::error::{Result, VmError};
use crate::feature_gate;
use crate::native::{
    SELECTOR_IDENTITY_REGISTER, bonded_stake_of, identity_of_wallet, is_identity_revoked,
    network_param,
};
use crate::traits::VmState;
use crate::types::VmTransaction;

/// The gate of the rule.
pub const KEY: &str = "feature.identity_required.activation_epoch";

/// The governed mode of the rule once it is live (see [`Mode`]).
pub const MODE_KEY: &str = "feature.identity_required.mode";

/// What the identity rule does with a transaction or peer it would refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Mode {
    /// Refuse it.
    Enforce = 0,
    /// Admit it and log what enforce would have refused.
    Audit = 1,
    /// Admit it without a check.
    Off = 2,
}

impl Mode {
    /// The mode a stored value names. A value outside the three is
    /// unreachable through the registry bounds and reads as enforce.
    pub fn from_value(value: u64) -> Self {
        match value {
            1 => Self::Audit,
            2 => Self::Off,
            _ => Self::Enforce,
        }
    }

    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Audit => "audit",
            Self::Off => "off",
        }
    }
}

/// The mode in force: what governance last set, else enforce.
pub fn mode(state: &dyn VmState) -> Mode {
    Mode::from_value(network_param(state, MODE_KEY))
}

/// Whether `tx` is part of registering an identity, or a protocol record.
pub fn is_registration_path(tx: &VmTransaction) -> bool {
    if tx.vm_type != VmType::Tenzro || tx.data.len() < 4 {
        return false;
    }
    let selector: [u8; 4] = [tx.data[0], tx.data[1], tx.data[2], tx.data[3]];
    selector == SELECTOR_IDENTITY_REGISTER
        || selector == crate::account_keys::SELECTOR_ACCOUNT_KEYS
        || crate::native::pays_no_fee(tx)
}

/// Refuses a transaction whose sender has no registered identity, once the
/// rule is live and its mode is enforce. Reads only chain state and the
/// block's epoch.
pub fn check(tx: &VmTransaction, state: &dyn VmState) -> Result<()> {
    if tx.signing_digest.is_none() || !feature_gate::is_live_now(state, KEY) {
        return Ok(());
    }
    if is_registration_path(tx) {
        return Ok(());
    }
    match mode(state) {
        Mode::Enforce => enforce(tx, state),
        Mode::Off => Ok(()),
        Mode::Audit => {
            if let Err(e) = enforce(tx, state) {
                tracing::warn!(
                    target: "tenzro_vm::identity_required",
                    sender = %hex::encode(&tx.from),
                    reason = %e,
                    action = "audit",
                    "would refuse a transaction from a sender with no registered identity"
                );
            }
            Ok(())
        }
    }
}

fn enforce(tx: &VmTransaction, state: &dyn VmState) -> Result<()> {
    match identity_of_wallet(state, &tx.from) {
        Some(did) if is_identity_revoked(state, &did) => Err(VmError::InvalidTransaction(format!(
            "{did} was revoked: its account may not transact"
        ))),
        Some(_) => Ok(()),
        None if bonded_stake_of(state, &tx.from) > 0 => Ok(()),
        None => Err(VmError::InvalidTransaction(format!(
            "{} has no registered identity; register one first (RegisterIdentity)",
            hex::encode(&tx.from)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{SYSTEM_ADDRESS, set_governed_param_for_test};
    use crate::state_adapter::StateAdapter;

    fn tx(from: u8, data: Vec<u8>) -> VmTransaction {
        let mut tx = VmTransaction::new(
            vec![from; 32],
            Some(vec![9; 32]),
            1,
            data,
            100_000,
            1,
            0,
            VmType::Tenzro,
            1337,
        );
        tx.signing_digest = Some(vec![1; 32]);
        tx
    }

    fn register(state: &mut StateAdapter, who: u8) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("identity_wallet:{}", hex::encode(vec![who; 32])).as_bytes(),
            b"did:tenzro:machine:aa".to_vec(),
        );
    }

    #[test]
    fn dormant_until_a_vote_sets_its_epoch() {
        let state = StateAdapter::new();
        assert!(
            check(&tx(5, vec![]), &state).is_ok(),
            "dormant: today's behaviour"
        );
    }

    #[test]
    fn live_it_refuses_a_sender_with_no_identity_and_admits_the_registered() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        let err = check(&tx(5, vec![]), &state).unwrap_err();
        assert!(err.to_string().contains("no registered identity"), "{err}");
        register(&mut state, 6);
        assert!(check(&tx(6, vec![]), &state).is_ok());
    }

    #[test]
    fn live_it_refuses_a_revoked_identity() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        register(&mut state, 6);
        state.set_storage(
            &SYSTEM_ADDRESS,
            b"identity_revoked:did:tenzro:machine:aa",
            vec![1],
        );
        let err = check(&tx(6, vec![]), &state).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    #[test]
    fn live_it_still_admits_registration_and_keys() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        assert!(check(&tx(5, SELECTOR_IDENTITY_REGISTER.to_vec()), &state).is_ok());
        assert!(
            check(
                &tx(5, crate::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec()),
                &state
            )
            .is_ok()
        );
    }

    #[test]
    fn live_it_lets_a_bonded_validator_through_and_ignores_unsigned_calls() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        crate::native::staking::add_bond(&mut state, &vec![7u8; 32], 1_000, 0).unwrap();
        assert!(check(&tx(7, vec![]), &state).is_ok());
        let mut read_only = tx(5, vec![]);
        read_only.signing_digest = None;
        assert!(check(&read_only, &state).is_ok());
    }

    #[test]
    fn the_mode_defaults_to_enforce_and_audit_or_off_admit_the_unregistered() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, KEY, 0);
        assert_eq!(mode(&state), Mode::Enforce, "enforce with no vote");
        register(&mut state, 6);
        assert!(check(&tx(6, vec![]), &state).is_ok(), "registered passes");
        assert!(
            check(&tx(5, vec![]), &state).is_err(),
            "unregistered refused"
        );

        set_governed_param_for_test(&mut state, MODE_KEY, Mode::Audit as u64);
        assert_eq!(mode(&state), Mode::Audit);
        assert!(
            check(&tx(5, vec![]), &state).is_ok(),
            "audit admits and logs"
        );
        assert!(check(&tx(6, vec![]), &state).is_ok());

        set_governed_param_for_test(&mut state, MODE_KEY, Mode::Off as u64);
        assert!(check(&tx(5, vec![]), &state).is_ok(), "off admits");

        set_governed_param_for_test(&mut state, MODE_KEY, Mode::Enforce as u64);
        assert!(check(&tx(5, vec![]), &state).is_err(), "enforce again");
    }

    #[test]
    fn the_mode_is_a_governed_parameter_whose_audit_is_a_pause() {
        use crate::governance::{Tighten, governed_param, is_pause_only};
        let p = governed_param(MODE_KEY).expect("registered");
        assert!(feature_gate::follows_convention(p));
        assert!(!feature_gate::is_activation_key(MODE_KEY));
        assert_eq!((p.min, p.max, p.genesis), (0, 2, Mode::Enforce as u64));
        assert_eq!(p.tighten, Tighten::Down);
        // Relaxing applies at the next epoch; returning to enforce waits the
        // tightening grace window.
        assert!(!p.tighten.tightens(0, 1) && !p.tighten.tightens(0, 2));
        assert!(p.tighten.tightens(1, 0) && p.tighten.tightens(2, 0));
        assert!(
            is_pause_only(MODE_KEY, Mode::Audit as u64),
            "audit is expedited"
        );
        assert!(!is_pause_only(MODE_KEY, Mode::Off as u64));
        assert!(!is_pause_only(MODE_KEY, Mode::Enforce as u64));
        for v in 0..=3 {
            assert_eq!(Mode::from_value(v) as u64, if v > 2 { 0 } else { v });
        }
    }

    #[test]
    fn the_gate_is_a_registered_governed_parameter_following_the_convention() {
        let p = crate::governance::governed_param(KEY).expect("registered");
        assert!(feature_gate::follows_convention(p));
        assert_eq!(p.genesis, feature_gate::NEVER, "dormant on a running chain");
    }
}
