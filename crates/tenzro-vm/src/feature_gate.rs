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
//! ```text
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
//! it is live its epoch is final. From the release floor 0.2.2 on, a
//! scheduled epoch also moves or is called off only while it is at least
//! [`MIN_NOTICE_EPOCHS`] ahead: the change then applies before that epoch
//! starts, so whatever is built for an epoch at its start (a consensus core)
//! and rebuilt in it after a restart reads the same answer. A rule that needs an off switch after it is
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
use crate::governance::{
    GovernanceError, GovernedParam, RELEASE_0_2_1, RELEASE_0_2_2, RELEASE_FLOOR_PARAM, Tighten,
    governed_param,
};
use crate::native::{network_param, params_epoch, stored_param};
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
/// names it. A key is carried when it existed in 0.2.1 (no `KEYS_SINCE` row
/// dates it later) and is outside the feature namespace; every key newer than
/// 0.2.1 (a gate, a new bound, the release floor) takes its registry value
/// unless the genesis file names it. So adding a governed key never changes
/// the genesis block of a network that was started before it: a fresh node
/// builds the same block 0 the live chain has.
pub fn in_genesis_root(key: &str, named_in_genesis_file: bool) -> bool {
    (!is_feature_key(key) && crate::governance::key_since(key) == RELEASE_0_2_1)
        || named_in_genesis_file
}

/// The activation epoch in force for the gate `key`: what governance last
/// set, else the registry's genesis value, else [`NEVER`] for a key the
/// registry does not know.
pub fn activation_epoch(state: &dyn VmState, key: &str) -> u64 {
    stored_param(state, key).unwrap_or_else(|| governed_param(key).map_or(NEVER, |p| p.genesis))
}

/// Whether the rule gated by `key` runs in a block of `epoch`.
pub fn is_live(state: &dyn VmState, key: &str, epoch: u64) -> bool {
    epoch >= activation_epoch(state, key)
}

/// [`is_live`] for the epoch of the block being executed.
pub fn is_live_now(state: &dyn VmState, key: &str) -> bool {
    is_live(state, key, params_epoch(state))
}

/// [`is_live_now`] through any reader of committed system storage, for code
/// that does not hold the chain state itself.
pub fn is_live_through(mut system: impl FnMut(&[u8]) -> Option<Vec<u8>>, key: &str) -> bool {
    let mut word = |storage_key: &[u8]| {
        system(storage_key)
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_le_bytes)
    };
    let epoch = word(crate::native::PARAMS_EPOCH_KEY.as_bytes()).unwrap_or(0);
    let activation = crate::native::stored_param_through(&mut system, key)
        .unwrap_or_else(|| governed_param(key).map_or(NEVER, |p| p.genesis));
    epoch >= activation
}

/// Checks a change of `key` to `value` against the rules for a gate, with
/// `in_force` the activation epoch in force, `epoch` the epoch the change is
/// checked in and `floor` the network's release floor. Any key that is not a
/// gate passes.
pub fn change_allowed(
    key: &str,
    in_force: u64,
    value: u64,
    epoch: u64,
    floor: u64,
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
    // Below the floor a node of the release before accepts what this rule
    // refuses, so it binds only once every validator runs a release with it.
    if floor >= RELEASE_0_2_2
        && in_force != NEVER
        && in_force < epoch.saturating_add(MIN_NOTICE_EPOCHS)
    {
        return Err(GovernanceError::InvalidPolicy(format!(
            "{key} is scheduled for epoch {in_force}, and a scheduled epoch moves or is called \
             off at least {MIN_NOTICE_EPOCHS} epochs ahead of it, not in epoch {epoch}"
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
        network_param(state, RELEASE_FLOOR_PARAM),
    )
    .map_err(|e| crate::error::VmError::InvalidTransaction(e.to_string()))
}

/// Transaction kinds appended to the wire after a running chain started,
/// each with the gate it waits for. Every lane that appends a kind adds one
/// line here.
const DORMANT_KINDS: &[(
    fn(&tenzro_types::transaction::TransactionType) -> bool,
    &str,
)] = &[(
    |t| {
        matches!(
            t,
            tenzro_types::transaction::TransactionType::NativeCall { .. }
        )
    },
    crate::native::native_call::GATE,
)];

/// Policy changes appended after a running chain started, each with the gate
/// it waits for. Every lane that appends a `PolicyUpdate` variant adds one
/// line here.
const DORMANT_POLICIES: &[(fn(&tenzro_types::token::PolicyUpdate) -> bool, &str)] = &[
    (
        |u| {
            matches!(
                u,
                tenzro_types::token::PolicyUpdate::ProtocolUpgradePlatforms { .. }
            )
        },
        crate::native::upgrade::PLATFORMS_GATE,
    ),
    (
        |u| {
            matches!(
                u,
                tenzro_types::token::PolicyUpdate::WebauthnRootsSet { .. }
            )
        },
        crate::native::registration_attestation::GATE,
    ),
    (
        |u| matches!(u, tenzro_types::token::PolicyUpdate::NrasJwksSet { .. }),
        crate::native::gateway_sets::NRAS_JWKS_GATE,
    ),
    (
        |u| matches!(u, tenzro_types::token::PolicyUpdate::BootNodesSet { .. }),
        crate::native::gateway_sets::BOOT_NODES_GATE,
    ),
    (
        |u| {
            matches!(
                u,
                tenzro_types::token::PolicyUpdate::UpdateNoticeKeysSet { .. }
            )
        },
        crate::native::gateway_sets::UPDATE_NOTICE_KEYS_GATE,
    ),
];

/// The gate `tx_type`'s kind waits for, if its kind was appended after the
/// chain started.
pub fn dormant_kind_gate(
    tx_type: &tenzro_types::transaction::TransactionType,
) -> Option<&'static str> {
    gate_of(DORMANT_KINDS, tx_type)
}

/// Proposal actions appended after a running chain started, each with the
/// gate it waits for. Every lane that appends a `ProposalAction` variant adds
/// one line here.
const DORMANT_ACTIONS: &[(fn(&crate::governance::ProposalAction) -> bool, &str)] = &[
    (
        |a| {
            matches!(
                a,
                crate::governance::ProposalAction::SetBridgeFinalityPolicy { .. }
            )
        },
        crate::native::bridge::CCIP_FINALITY_POLICY_KEY,
    ),
    (
        |a| matches!(a, crate::governance::ProposalAction::SetAffiliation { .. }),
        crate::native::affiliated_share::GATE,
    ),
];

/// The gate a proposal action waits for, if its variant was appended after
/// the chain started.
pub fn dormant_action_gate(action: &crate::governance::ProposalAction) -> Option<&'static str> {
    gate_of(DORMANT_ACTIONS, action)
}

/// The gate a policy change waits for, if its variant was appended after the
/// chain started.
pub fn dormant_policy_gate(update: &tenzro_types::token::PolicyUpdate) -> Option<&'static str> {
    gate_of(DORMANT_POLICIES, update)
}

fn gate_of<T>(list: &[(fn(&T) -> bool, &'static str)], item: &T) -> Option<&'static str> {
    list.iter().find(|(is, _)| is(item)).map(|(_, gate)| *gate)
}

fn refused_while_dormant(
    state: &dyn VmState,
    gate: Option<&str>,
    what: &str,
) -> std::result::Result<(), String> {
    match gate {
        Some(gate) if !is_live_now(state, gate) => Err(format!(
            "this {what} is not in force on this chain yet (it waits for {gate})"
        )),
        _ => Ok(()),
    }
}

/// Refuse `tx_type` while the gate of its kind is dormant. A node calls this
/// at every path a transaction enters it by: a kind that reached the network
/// would reach nodes of the previous release, which cannot decode it and
/// ban the sender.
pub fn refuse_dormant_kind(
    state: &dyn VmState,
    tx_type: &tenzro_types::transaction::TransactionType,
) -> std::result::Result<(), String> {
    refused_while_dormant(state, dormant_kind_gate(tx_type), "transaction kind")?;
    if let tenzro_types::transaction::TransactionType::NativeCall { selector, data } = tx_type {
        crate::native::native_call::admit(state, *selector, data)?;
    }
    // A proof no block can carry is sent to validators directly once their
    // verdicts record proofs; one still offered in a transaction is turned
    // away with where to send it.
    if matches!(
        tx_type,
        tenzro_types::transaction::TransactionType::AttestZkProof { .. }
    ) && is_live_now(state, crate::native::zk_verdict::GATE)
    {
        return Err(
            "a proof is not carried in a transaction: send it to validators over the \
             tenzro/zk-proof protocol, and their verdicts record it"
                .to_string(),
        );
    }
    if let tenzro_types::transaction::TransactionType::GovernancePropose { proposal } = tx_type
        && let Ok(action) = serde_json::from_slice(proposal)
    {
        refuse_dormant_action(state, &action)?;
        // The VM refuses it at the proposal and again at enactment; the
        // node says so before it reaches a block.
        if let crate::governance::ProposalAction::ParameterChange { key, .. } = &action {
            crate::governance::change_released(
                key,
                crate::native::network_param(state, crate::governance::RELEASE_FLOOR_PARAM),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Refuse a proposal whose action, or whose policy change, waits for a gate
/// that is dormant. Checked when a proposal is submitted and again when it
/// is enacted.
pub fn refuse_dormant_action(
    state: &dyn VmState,
    action: &crate::governance::ProposalAction,
) -> std::result::Result<(), String> {
    refused_while_dormant(state, dormant_action_gate(action), "proposal")?;
    if let crate::governance::ProposalAction::PolicyUpdate { update, .. } = action {
        refuse_dormant_policy(state, update)?;
    }
    Ok(())
}

/// Refuse a proposal carrying `update` while the gate of its variant is
/// dormant. The VM calls this when the proposal is made and when it is
/// enacted: nodes of the previous release cannot read the variant, and
/// accepting it on new nodes alone would split the chain.
pub fn refuse_dormant_policy(
    state: &dyn VmState,
    update: &tenzro_types::token::PolicyUpdate,
) -> std::result::Result<(), String> {
    refused_while_dormant(state, dormant_policy_gate(update), "policy change")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::set_governed_param_for_test;
    use crate::state_adapter::StateAdapter;

    const RULE: &str = "feature.double_fee.activation_epoch";

    #[test]
    fn a_proposal_for_a_key_above_the_release_floor_is_refused_at_admission() {
        use crate::governance::{
            ProposalAction, RELEASE_0_2_1, RELEASE_FLOOR_PARAM, TIMELOCK_PARAM, VOTING_PERIOD_PARAM,
        };
        let propose = |key: &str| tenzro_types::transaction::TransactionType::GovernancePropose {
            proposal: serde_json::to_vec(&ProposalAction::ParameterChange {
                key: key.into(),
                value: 1,
                memo: String::new(),
            })
            .unwrap(),
        };
        let mut state = StateAdapter::new();
        assert!(refuse_dormant_kind(&state, &propose(TIMELOCK_PARAM)).is_ok());
        set_governed_param_for_test(&mut state, RELEASE_FLOOR_PARAM, RELEASE_0_2_1);
        let refused = refuse_dormant_kind(&state, &propose(TIMELOCK_PARAM)).unwrap_err();
        assert!(refused.contains("release floor"), "{refused}");
        // A key from 0.2.1 is still open to a proposal.
        assert!(refuse_dormant_kind(&state, &propose(VOTING_PERIOD_PARAM)).is_ok());
    }

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
    fn the_broadcast_fault_bound_gate_is_registered_and_dormant() {
        let key = crate::governance::RBC_WHOLE_MEMBER_FAULT_BOUND_KEY;
        let p = governed_param(key).expect("registered");
        assert!(follows_convention(p));
        assert_eq!(p.genesis, NEVER, "dormant on a running chain");
        assert!(!in_genesis_root(key, false));
    }

    #[test]
    fn a_dormant_gate_is_set_ahead_or_back_to_never_and_a_live_one_is_final() {
        let key = RULE;
        const OLD: u64 = crate::governance::RELEASE_0_2_1;
        // Dormant, checked in epoch 10.
        assert!(change_allowed(key, NEVER, 12, 10, OLD).is_ok());
        assert!(
            change_allowed(key, NEVER, 11, 10, OLD).is_err(),
            "too little notice"
        );
        assert!(
            change_allowed(key, NEVER, 0, 10, OLD).is_err(),
            "already past"
        );
        assert!(
            change_allowed(key, 40, NEVER, 10, OLD).is_ok(),
            "called off"
        );
        assert!(
            change_allowed(key, 40, 12, 10, OLD).is_ok(),
            "moved earlier, still ahead"
        );
        // Live since epoch 10: nothing moves it.
        assert!(change_allowed(key, 10, NEVER, 10, OLD).is_err());
        assert!(change_allowed(key, 10, 500, 20, OLD).is_err());
        // Not a gate: untouched by these rules.
        assert!(change_allowed("fees.settlement_fee_bps", 5, 1, 100, OLD).is_ok());
        assert!(change_allowed("feature.double_fee.rate", 5, 1, 100, OLD).is_ok());
    }

    /// From the release floor 0.2.2, a scheduled epoch moves or is called
    /// off only with the notice it was set with; below it the rule of the
    /// release before holds.
    #[test]
    fn a_scheduled_epoch_is_not_called_off_inside_its_notice() {
        let key = RULE;
        const OLD: u64 = crate::governance::RELEASE_0_2_1;
        // Scheduled for epoch 12, checked in epoch 11: its first block would
        // apply the change after the cores of epoch 12 were built with 12.
        assert!(change_allowed(key, 12, NEVER, 11, RELEASE_0_2_2).is_err());
        assert!(change_allowed(key, 12, 20, 11, RELEASE_0_2_2).is_err());
        assert!(change_allowed(key, 12, NEVER, 11, OLD).is_ok());
        assert!(change_allowed(key, 12, 20, 11, OLD).is_ok());
        // Two epochs ahead it still moves and is still called off.
        assert!(change_allowed(key, 12, NEVER, 10, RELEASE_0_2_2).is_ok());
        assert!(change_allowed(key, 12, 20, 10, RELEASE_0_2_2).is_ok());
        assert!(
            change_allowed(key, 12, 11, 10, RELEASE_0_2_2).is_err(),
            "too little notice"
        );
        // A dormant gate is set as before.
        assert!(change_allowed(key, NEVER, 12, 10, RELEASE_0_2_2).is_ok());
        assert!(change_allowed(key, NEVER, NEVER, 10, RELEASE_0_2_2).is_ok());
    }

    /// The executor reads the floor from chain state.
    #[test]
    fn the_executor_checks_a_cancel_against_the_floor_in_state() {
        let mut state = StateAdapter::new();
        let set = |state: &mut StateAdapter, key: &str, value: u64| {
            state.set_storage(
                &crate::native::SYSTEM_ADDRESS,
                crate::native::governed_param_key(key).as_bytes(),
                value.to_le_bytes().to_vec(),
            );
        };
        set(
            &mut state,
            RELEASE_FLOOR_PARAM,
            crate::governance::RELEASE_0_2_1,
        );
        let scheduled = params_epoch(&state) + 1;
        set(
            &mut state,
            crate::governance::RBC_WHOLE_MEMBER_FAULT_BOUND_KEY,
            scheduled,
        );
        let key = crate::governance::RBC_WHOLE_MEMBER_FAULT_BOUND_KEY;
        assert!(check_change(&state, key, NEVER).is_ok());
        set(&mut state, RELEASE_FLOOR_PARAM, RELEASE_0_2_2);
        assert!(check_change(&state, key, NEVER).is_err());
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
        // The release floor joined after the public network's genesis block, so a genesis file
        // that does not name it must not change block 0.
        assert!(!in_genesis_root(RELEASE_FLOOR_PARAM, false));
        assert!(in_genesis_root(RELEASE_FLOOR_PARAM, true));
    }

    /// The governed keys the genesis root carries are exactly those of 0.2.1: outside the feature
    /// namespace and with no `KEYS_SINCE` row dating them later. A key added in a later release
    /// without its row would be carried, change block 0 and keep a fresh node from following the
    /// live chain, so the carried set is pinned by digest. The release floor is among the keys
    /// the root leaves out.
    const CARRIED_KEYS_DIGEST: &str =
        "309b37745485975299f81def6b641deda9d9f0fb3bdbd2bef4edc3282eeeece6";

    #[test]
    fn the_genesis_root_carries_exactly_the_governed_keys_of_0_2_1() {
        use sha2::{Digest, Sha256};
        let mut carried: Vec<&str> = Vec::new();
        for p in crate::governance::GOVERNED_PARAMS.iter() {
            let old =
                !is_feature_key(p.key) && crate::governance::key_since(p.key) == RELEASE_0_2_1;
            assert_eq!(
                in_genesis_root(p.key, false),
                old,
                "{} is carried in the genesis root only when it existed in 0.2.1",
                p.key
            );
            if old {
                carried.push(p.key);
            }
        }
        assert!(!in_genesis_root(RELEASE_FLOOR_PARAM, false));
        carried.sort_unstable();
        let digest = hex::encode(Sha256::digest(carried.join("\n")));
        assert_eq!(
            digest,
            CARRIED_KEYS_DIGEST,
            "the governed keys carried by the genesis root changed ({} keys): a key new in this release needs its \
             KEYS_SINCE row (then it stays out of the root and a fresh node still builds the live block 0); a key \
             of 0.2.1 must not get one. Accepting a different carried set is a genesis flag day: repin this digest \
             and the genesis pins together",
            carried.len()
        );
    }

    /// A chain whose genesis did not carry the release floor reads the registry's genesis value
    /// for it, which is the binary's `RELEASE_0_2_2`. Changing that constant (or the registry's
    /// value) in a later release would move the floor of every such chain without a vote, so it
    /// is pinned here: a later release raises the floor through a governed change or a value
    /// stored in state, never by editing this constant.
    #[test]
    fn the_release_floor_of_a_chain_that_never_stored_it_stays_at_0_2_2() {
        assert_eq!(RELEASE_0_2_2, 2_002);
        let p = governed_param(RELEASE_FLOOR_PARAM).expect("the release floor is registered");
        assert_eq!(p.genesis, 2_002);
        assert_eq!(
            p.min, 2_002,
            "the floor is never lowered below this release"
        );
    }

    /// The lists start empty: nothing is refused until a kind is
    /// registered, and every registered kind waits for its own gate.
    #[test]
    fn a_registered_kind_waits_for_its_gate_and_others_pass() {
        use tenzro_types::transaction::TransactionType;
        let state = crate::StateAdapter::new();
        assert!(refuse_dormant_kind(&state, &TransactionType::ExitValidator).is_ok());
        let list: &[(fn(&TransactionType) -> bool, &str)] = &[(
            |t| matches!(t, TransactionType::ExitValidator),
            "feature.example.activation_epoch",
        )];
        assert_eq!(
            gate_of(list, &TransactionType::ExitValidator),
            Some("feature.example.activation_epoch")
        );
        assert!(
            refused_while_dormant(
                &state,
                gate_of(list, &TransactionType::ExitValidator),
                "kind"
            )
            .is_err()
        );
    }

    /// A native call is refused at admission while its kind's gate or its
    /// operation's gate is dormant, and admitted once both are in force; one
    /// naming an operation that is not listed is refused either way.
    #[test]
    fn a_native_call_waits_for_both_gates_at_admission() {
        use tenzro_types::transaction::TransactionType;
        let attest = TransactionType::NativeCall {
            selector: tenzro_native_ops::SELECTOR_BUILD_ATTESTATION,
            data: tenzro_native_ops::encode(
                &tenzro_native_ops::build_attestation::BuildAttestationOp {
                    version: "0.2.2".into(),
                    platform: "x86_64-unknown-linux-gnu".into(),
                    code_hash: vec![1; 32],
                },
            ),
        };
        let governance = TransactionType::NativeCall {
            selector: crate::native::SELECTOR_GOVERNANCE_EXECUTE,
            data: b"{}".to_vec(),
        };
        let mut state = crate::StateAdapter::new();
        assert!(refuse_dormant_kind(&state, &attest).is_err());
        assert!(refuse_dormant_kind(&state, &governance).is_err());
        crate::native::set_governed_param_for_test(&mut state, crate::native::native_call::GATE, 0);
        assert!(refuse_dormant_kind(&state, &attest).is_err());
        crate::native::set_governed_param_for_test(
            &mut state,
            crate::native::build_attestation::GATE,
            0,
        );
        assert!(refuse_dormant_kind(&state, &attest).is_ok());
        assert!(refuse_dormant_kind(&state, &governance).is_err());
    }
}
