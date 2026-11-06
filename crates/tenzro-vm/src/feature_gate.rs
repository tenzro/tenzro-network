//! Activation-epoch gates for new state-transition rules.
//!
//! A rule that changes how blocks execute cannot simply ship in a binary: a
//! node running it and a node not running it disagree on the state root of
//! the first block it touches. A gated rule ships dormant in the binary and
//! is switched on for every node at the same epoch by a governance vote.
//!
//! ## The convention
//!
//! A gated rule `<name>` is governed by the parameter
//! `feature.<name>.activation_epoch` ([`activation_key`]): the first epoch
//! whose blocks run the rule. Its registry entry is built with
//! [`registry_entry`]: bounds `0..=`[`NEVER`], tightening direction
//! `Neither`, and a genesis value of
//!
//! - [`NEVER`] for a rule added to a chain that has run without it: the rule
//!   is dormant until a vote sets an epoch;
//! - `0` for a rule a new chain has always had.
//!
//! Any other tunable of the rule is `feature.<name>.<parameter>`. Execution
//! code asks [`is_live`] with the epoch of the block it executes:
//!
//! ```ignore
//! if feature_gate::is_live(state, KEY, epoch) {
//!     /* new rule */
//! } else {
//!     /* the rule in force before it */
//! }
//! ```
//!
//! ## What a vote may do
//!
//! The activation epoch moves by an ordinary `parameter_change` proposal,
//! subject to [`change_allowed`]: while the rule is dormant it may be set to
//! an epoch at least [`MIN_NOTICE_EPOCHS`] ahead, or back to [`NEVER`]; once
//! it is live its epoch is final. A rule that needs an off switch after it is
//! live carries a status lever of its own beside the gate.
//!
//! ## The genesis root
//!
//! Keys in the `feature.` namespace are left out of the genesis state root
//! and out of the genesis state unless the genesis file names them
//! ([`in_genesis_root`]); a key that is absent reads as its registry genesis
//! value. So a release that adds a gate, or a tunable of one, does not change
//! the root an existing data directory stored, and its nodes start
//! (docs/GENESIS-ROOT-UPGRADES.md).

use crate::error::Result;
use crate::governance::{GovernanceError, GovernedParam, Tighten, governed_param};
use crate::native::{params_epoch, stored_param};
use crate::traits::VmState;

/// Prefix of every key in the feature namespace.
pub const NAMESPACE: &str = "feature.";

/// Suffix of a gate's activation key.
pub const ACTIVATION_SUFFIX: &str = ".activation_epoch";

/// The activation epoch of a rule no vote has switched on. The registry's
/// highest bound: no chain reaches it.
pub const NEVER: u64 = 1 << 62;

/// Epochs of notice a vote must give: a dormant rule can be set to an epoch
/// no earlier than this many after the epoch the change is checked in, so
/// every validator sees the new epoch before it applies.
pub const MIN_NOTICE_EPOCHS: u64 = 2;

/// The key of the gate for the rule `name`.
pub fn activation_key(name: &str) -> String {
    format!("{NAMESPACE}{name}{ACTIVATION_SUFFIX}")
}

/// Whether `key` is in the feature namespace.
pub fn is_feature_key(key: &str) -> bool {
    key.starts_with(NAMESPACE)
}

/// The rule name a gate key `feature.<name>.activation_epoch` names.
pub fn gate_name(key: &str) -> Option<&str> {
    let name = key
        .strip_prefix(NAMESPACE)?
        .strip_suffix(ACTIVATION_SUFFIX)?;
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    valid.then_some(name)
}

/// Whether `key` is a gate's activation key.
pub fn is_activation_key(key: &str) -> bool {
    gate_name(key).is_some()
}

/// The registry entry of a gate. `genesis` is [`NEVER`] for a rule added to
/// a running chain and `0` for one a new chain has always had.
pub const fn registry_entry(
    key: &'static str,
    genesis: u64,
    description: &'static str,
) -> GovernedParam {
    GovernedParam {
        key,
        min: 0,
        max: NEVER,
        genesis,
        tighten: Tighten::Neither,
        description,
    }
}

/// Whether a registry entry in the feature namespace follows the convention:
/// a gate is named `feature.<name>.activation_epoch`, bounded `0..=NEVER`,
/// starts at `0` or [`NEVER`], and tightens neither way; any other key is
/// `feature.<name>.<parameter>`.
pub fn follows_convention(p: &GovernedParam) -> bool {
    let Some(rest) = p.key.strip_prefix(NAMESPACE) else {
        return false;
    };
    let mut parts = rest.split('.');
    let (Some(name), Some(parameter), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    if !token(name) || !token(parameter) {
        return false;
    }
    if is_activation_key(p.key) {
        p.min == 0
            && p.max == NEVER
            && (p.genesis == 0 || p.genesis == NEVER)
            && p.tighten == Tighten::Neither
    } else {
        true
    }
}

/// Whether the genesis state root and the genesis state carry `key`.
/// `named_in_genesis_file` is whether the genesis file's `[network_params]`
/// names it. Keys outside the feature namespace are always carried.
pub fn in_genesis_root(key: &str, named_in_genesis_file: bool) -> bool {
    !is_feature_key(key) || named_in_genesis_file
}

/// The activation epoch in force for the gate `key`: what governance last
/// set, else the registry's genesis value, else [`NEVER`] for a key the
/// registry does not know.
pub fn activation_epoch(state: &dyn VmState, key: &str) -> u64 {
    stored_param(state, key)
        .unwrap_or_else(|| governed_param(key).map_or(NEVER, |p| p.genesis))
}

/// Whether the rule gated by `key` runs in a block of `epoch`.
pub fn is_live(state: &dyn VmState, key: &str, epoch: u64) -> bool {
    epoch >= activation_epoch(state, key)
}

/// [`is_live`] for the epoch of the block being executed.
pub fn is_live_now(state: &dyn VmState, key: &str) -> bool {
    is_live(state, key, params_epoch(state))
}

/// Checks a change of `key` to `value` against the rules for a gate, with
/// `in_force` the activation epoch in force and `epoch` the epoch the change
/// is checked in. Any key that is not a gate passes.
pub fn change_allowed(
    key: &str,
    in_force: u64,
    value: u64,
    epoch: u64,
) -> std::result::Result<(), GovernanceError> {
    if !is_activation_key(key) {
        return Ok(());
    }
    if in_force <= epoch {
        return Err(GovernanceError::InvalidPolicy(format!(
            "{key} is live since epoch {in_force} and its epoch is final; the rule is paused \
             with its status lever or changed by a protocol upgrade"
        )));
    }
    if value != NEVER && value < epoch.saturating_add(MIN_NOTICE_EPOCHS) {
        return Err(GovernanceError::InvalidPolicy(format!(
            "{key} must be set at least {MIN_NOTICE_EPOCHS} epochs ahead of epoch {epoch}, or \
             to {NEVER} for never"
        )));
    }
    Ok(())
}

/// [`change_allowed`] as the executor reports it.
pub(crate) fn check_change(state: &dyn VmState, key: &str, value: u64) -> Result<()> {
    change_allowed(
        key,
        activation_epoch(state, key),
        value,
        params_epoch(state),
    )
    .map_err(|e| crate::error::VmError::InvalidTransaction(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::set_governed_param_for_test;
    use crate::state_adapter::StateAdapter;

    const RULE: &str = "feature.double_fee.activation_epoch";

    /// A state-transition rule as execution code writes it: the fee doubles
    /// from the epoch the gate names.
    fn fee(state: &dyn VmState, epoch: u64, base: u64) -> u64 {
        if is_live(state, RULE, epoch) {
            base * 2
        } else {
            base
        }
    }

    #[test]
    fn a_gated_rule_is_dormant_before_its_epoch_and_live_from_it() {
        let mut state = StateAdapter::new();
        // No vote has set it: the registry does not know the key, so it is
        // dormant at every epoch.
        assert_eq!(activation_epoch(&state, RULE), NEVER);
        assert_eq!(fee(&state, 0, 10), 10);
        assert_eq!(fee(&state, 1 << 40, 10), 10);

        set_governed_param_for_test(&mut state, RULE, 50);
        assert_eq!(activation_epoch(&state, RULE), 50);
        assert_eq!(fee(&state, 49, 10), 10, "dormant the epoch before");
        assert_eq!(fee(&state, 50, 10), 20, "live at its epoch");
        assert_eq!(fee(&state, 51, 10), 20, "live after");
    }

    #[test]
    fn the_rule_follows_the_epoch_of_the_block_being_executed() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, RULE, 7);
        crate::native::begin_block_params(&mut state, 6).unwrap();
        assert!(!is_live_now(&state, RULE));
        crate::native::begin_block_params(&mut state, 7).unwrap();
        assert!(is_live_now(&state, RULE));
    }

    #[test]
    fn a_dormant_gate_is_set_ahead_or_back_to_never_and_a_live_one_is_final() {
        let key = RULE;
        // Dormant, checked in epoch 10.
        assert!(change_allowed(key, NEVER, 12, 10).is_ok());
        assert!(
            change_allowed(key, NEVER, 11, 10).is_err(),
            "too little notice"
        );
        assert!(change_allowed(key, NEVER, 0, 10).is_err(), "already past");
        assert!(change_allowed(key, 40, NEVER, 10).is_ok(), "called off");
        assert!(
            change_allowed(key, 40, 12, 10).is_ok(),
            "moved earlier, still ahead"
        );
        // Live since epoch 10: nothing moves it.
        assert!(change_allowed(key, 10, NEVER, 10).is_err());
        assert!(change_allowed(key, 10, 500, 20).is_err());
        // Not a gate: untouched by these rules.
        assert!(change_allowed("fees.settlement_fee_bps", 5, 1, 100).is_ok());
        assert!(change_allowed("feature.double_fee.rate", 5, 1, 100).is_ok());
    }

    #[test]
    fn keys_follow_the_naming_convention() {
        assert_eq!(activation_key("double_fee"), RULE);
        assert_eq!(gate_name(RULE), Some("double_fee"));
        assert!(is_activation_key(RULE));
        for bad in [
            "feature..activation_epoch",
            "feature.Double.activation_epoch",
            "feature.a.b.activation_epoch",
            "double_fee.activation_epoch",
            "feature.double_fee.activation",
        ] {
            assert!(!is_activation_key(bad), "{bad}");
        }
        let gate = registry_entry("feature.double_fee.activation_epoch", NEVER, "x");
        assert!(follows_convention(&gate));
        let tunable = registry_entry("feature.double_fee.rate_bps", 100, "x");
        assert!(follows_convention(&tunable));
        let wrong_bounds = GovernedParam { max: 10, ..gate };
        assert!(!follows_convention(&wrong_bounds));
        let wrong_genesis = GovernedParam { genesis: 5, ..gate };
        assert!(!follows_convention(&wrong_genesis));
        let tightening = GovernedParam {
            tighten: Tighten::Up,
            ..gate
        };
        assert!(!follows_convention(&tightening));
    }

    #[test]
    fn every_registry_entry_in_the_namespace_follows_the_convention() {
        for p in crate::governance::GOVERNED_PARAMS
            .iter()
            .filter(|p| is_feature_key(p.key))
        {
            assert!(follows_convention(p), "{}", p.key);
        }
    }

    #[test]
    fn the_namespace_stays_out_of_the_genesis_root_unless_the_file_names_it() {
        assert!(!in_genesis_root(RULE, false));
        assert!(in_genesis_root(RULE, true));
        assert!(in_genesis_root("fees.settlement_fee_bps", false));
    }
}
