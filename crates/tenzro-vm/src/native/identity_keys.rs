//! An identity's key history on its root's authority (see
//! [`tenzro_native_ops::identity_keys`]).
//!
//! The record of the keys an identity signs with: each key with its version
//! and the block time it took effect, a compromise declaration against a
//! recorded key, and the delegations the identity revoked. The approval goes
//! through the one root-approval check every root-signed operation uses, so a
//! relaying node records nothing the identity's root did not approve.
//!
//! A key update names the version it takes, one above the latest, so an
//! approval applies once. When the latest key committed to its successor the
//! update must reveal exactly that key; the commitment is a hash, so it still
//! decides the next key when the key in force is broken. One case lifts it:
//! the approving root's account completed a recovery after the commitment
//! was made, so the committed key may be on a device that is gone.
//!
//! [`record_event`] keeps the head of each identity's chain of logs: every
//! log about an identity (registration, a keystore change, revocation, a key
//! change) advances it.

use tenzro_crypto::identity_key::next_key_commitment;
use tenzro_native_ops::identity_keys::{
    IdentityHead, IdentityKeyChange, IdentityKeyEpoch, IdentityKeyEvent, IdentityKeyHistory,
    IdentityKeyOp, OP_IDENTITY_KEYS, delegation_revoked_slot, identity_head_slot,
    identity_keys_slot, identity_recovered_slot,
};

use super::agent_terms::verify_root_approval;
use super::funding::{read_json, refuse, write_json};
use super::identity_revocation::is_root_of;
use super::*;

/// The gate of the identity key history: from its epoch the chain accepts
/// key changes (a `NativeCall` under [`SELECTOR_IDENTITY_KEYS`]) and keeps
/// each identity's head.
pub const GATE: &str = "feature.identity_keys.activation_epoch";

/// From this epoch a node signs the records it answers with (jurisdiction
/// receipts) with its identity key at the version this history records, and
/// verifiers check such a record against the history. Node behaviour only:
/// no block reads it.
pub const ROOT_SIGNATURES_GATE: &str = "feature.root_signatures.activation_epoch";

/// How far a verifier's view of this history may lag its clock, and how far
/// ahead of it a record's signing time may be, in milliseconds.
pub const ROOT_SIGNATURES_MAX_GAP_PARAM: &str = "feature.root_signatures.max_gap_ms";

pub use tenzro_native_ops::SELECTOR_IDENTITY_KEYS;

/// Gas for one key change: a root approval check and its records.
pub const GAS_IDENTITY_KEYS: u64 = 60_000;

/// The most keys one identity's history holds. A change rewrites the whole
/// history at the flat [`GAS_IDENTITY_KEYS`], so the history is bounded for
/// that gas to cover its cost; an identity at the bound succeeds to a new
/// root instead.
pub const MAX_KEY_EPOCHS: usize = 64;

/// The keys the chain records for `did`: empty before its first update.
pub fn read_identity_keys(state: &dyn VmState, did: &str) -> IdentityKeyHistory {
    read_json(state, &identity_keys_slot(did)).unwrap_or_default()
}

/// Block time (ms) `did` revoked the delegation `delegation_id`, if it did.
pub fn delegation_revoked_at_ms(
    state: &dyn VmState,
    did: &str,
    delegation_id: &[u8; 32],
) -> Option<u64> {
    state
        .get_storage(
            &SYSTEM_ADDRESS,
            delegation_revoked_slot(did, delegation_id).as_bytes(),
        )
        .and_then(|v| v.as_slice().try_into().ok())
        .map(u64::from_be_bytes)
}

/// The head of `did`'s chain of logs: zero before its first.
pub fn read_identity_head(state: &dyn VmState, did: &str) -> IdentityHead {
    read_json(state, &identity_head_slot(did)).unwrap_or_default()
}

/// Advance `did`'s head over the log with `topic` and `data`. Called where
/// each log about an identity is emitted; writes nothing before the key
/// history is in force, so a head covers the logs from that epoch on.
pub(crate) fn record_event(
    state: &mut dyn VmState,
    did: &str,
    topic: &[u8],
    data: &[u8],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Ok(());
    }
    let head = read_identity_head(state, did).advanced(did, topic, data);
    write_json(state, &identity_head_slot(did), &head, changes).map(|_| ())
}

/// Record that the account of `did` completed a recovery at `at_ms`.
/// Writes nothing before the key history is in force.
pub(crate) fn record_recovery(
    state: &mut dyn VmState,
    did: &str,
    at_ms: u64,
    changes: &mut Vec<StateChange>,
) {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return;
    }
    let key = identity_recovered_slot(did).into_bytes();
    let value = at_ms.to_be_bytes().to_vec();
    let previous = state.get_storage(&SYSTEM_ADDRESS, &key);
    state.set_storage(&SYSTEM_ADDRESS, &key, value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key,
        previous,
        Some(value),
    ));
}

/// Block time (ms) the account of `did` last completed a recovery.
fn recovered_at_ms(state: &dyn VmState, did: &str) -> Option<u64> {
    state
        .get_storage(&SYSTEM_ADDRESS, identity_recovered_slot(did).as_bytes())
        .and_then(|v| v.as_slice().try_into().ok())
        .map(u64::from_be_bytes)
}

/// Check the change against the identity's history without writing.
/// `approver_did` is the root that approves it.
fn check_change(
    state: &dyn VmState,
    did: &str,
    approver_did: &str,
    history: &IdentityKeyHistory,
    change: &IdentityKeyChange,
) -> Result<()> {
    match change {
        IdentityKeyChange::Update {
            version,
            ed25519,
            ml_dsa,
            ..
        } => {
            if history.epochs.len() >= MAX_KEY_EPOCHS {
                return Err(refuse(format!(
                    "{did} holds {MAX_KEY_EPOCHS} keys already: it succeeds to a new root"
                )));
            }
            let latest = history.epochs.last();
            let expected = latest.map_or(1, |e| e.version + 1);
            if *version != expected {
                return Err(refuse(format!(
                    "the next key of {did} takes version {expected}, not {version}"
                )));
            }
            if let Some(latest) = latest {
                if latest.ed25519 == *ed25519 && latest.ml_dsa == *ml_dsa {
                    return Err(refuse(
                        "a key update names a key other than the one in force",
                    ));
                }
                // A root recovered after the commitment was made may no
                // longer hold the committed key, and names another.
                let recovered_since = recovered_at_ms(state, approver_did)
                    .is_some_and(|at| at >= latest.effective_from_ms);
                if let Some(committed) = latest.next_commitment
                    && committed != next_key_commitment(ed25519, ml_dsa)
                    && !recovered_since
                {
                    return Err(refuse(
                        "the key in force committed to its successor, and this is not that key",
                    ));
                }
            }
        }
        IdentityKeyChange::Compromised { version } => {
            let epoch = history
                .epochs
                .iter()
                .find(|e| e.version == *version)
                .ok_or_else(|| refuse(format!("{did} has no key of version {version}")))?;
            if epoch.compromised_from_ms.is_some() {
                return Err(refuse("that key is already declared compromised"));
            }
        }
        IdentityKeyChange::RevokeDelegation { delegation_id } => {
            if delegation_revoked_at_ms(state, did, delegation_id).is_some() {
                return Err(refuse("that delegation is already revoked"));
            }
        }
    }
    Ok(())
}

/// Check that `op` may be applied at `now_ms` without writing anything: the
/// identity is known and not revoked, the approver is its root, the change
/// follows the identity's history, and the root's approval verifies against
/// keys in chain state. Every validator runs it in [`apply`].
pub fn authorize(
    state: &dyn VmState,
    op: &IdentityKeyOp,
    now_ms: i64,
) -> Result<IdentityKeyHistory> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse(
            "the identity key history is not in force on this chain yet",
        ));
    }
    op.validate().map_err(refuse)?;
    let did = op.did.as_str();
    if is_identity_revoked(state, did) {
        return Err(refuse(format!("identity {did} is revoked")));
    }
    if !is_root_of(state, did, &op.approver_did)? {
        return Err(refuse(format!(
            "{} may not change the keys of {did}: a root acts for itself, a delegated agent \
             answers to the controller its terms name, and a delegated machine to the root its \
             DID is derived under",
            op.approver_did
        )));
    }
    let history = read_identity_keys(state, did);
    check_change(state, did, &op.approver_did, &history, &op.change)?;
    verify_root_approval(
        state,
        &op.approver_did,
        OP_IDENTITY_KEYS,
        &op.target(),
        &op.approval,
        now_ms.max(0) as u64,
    )
    .map_err(refuse)?;
    Ok(history)
}

/// Apply one key change approved by the identity's root.
pub fn apply(
    state: &mut dyn VmState,
    op: &IdentityKeyOp,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let mut history = authorize(state, op, now_ms)?;
    let did = op.did.as_str();
    let at_ms = now_ms.max(0) as u64;
    let mut changes = Vec::new();
    match &op.change {
        IdentityKeyChange::Update {
            version,
            ed25519,
            ml_dsa,
            next_commitment,
        } => history.epochs.push(IdentityKeyEpoch {
            version: *version,
            ed25519: *ed25519,
            ml_dsa: ml_dsa.clone(),
            effective_from_ms: at_ms,
            compromised_from_ms: None,
            next_commitment: *next_commitment,
        }),
        IdentityKeyChange::Compromised { version } => {
            for epoch in history.epochs.iter_mut().filter(|e| e.version == *version) {
                epoch.compromised_from_ms = Some(at_ms);
            }
        }
        IdentityKeyChange::RevokeDelegation { delegation_id } => {
            let key = delegation_revoked_slot(did, delegation_id).into_bytes();
            let value = at_ms.to_be_bytes().to_vec();
            state.set_storage(&SYSTEM_ADDRESS, &key, value.clone());
            changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                key,
                None,
                Some(value),
            ));
        }
    }
    let event = IdentityKeyEvent {
        did: did.to_string(),
        change: op.change.clone(),
        approver_did: op.approver_did.clone(),
        at_ms,
    };
    write_json(state, &identity_keys_slot(did), &history, &mut changes)?;
    let body = serde_json::to_vec(&event)
        .map_err(|e| VmError::Internal(format!("cannot serialise the key event: {e}")))?;
    record_event(state, did, op.change.topic(), &body, &mut changes)?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![op.change.topic().to_vec(), did.as_bytes().to_vec()],
        body,
    );
    Ok((changes, vec![log]))
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_history_at_its_bound_takes_no_further_key() {
        let epoch = |version: u64| IdentityKeyEpoch {
            version,
            ed25519: [version as u8; 32],
            ml_dsa: Vec::new(),
            effective_from_ms: 0,
            compromised_from_ms: None,
            next_commitment: None,
        };
        let history = IdentityKeyHistory {
            epochs: (1..=MAX_KEY_EPOCHS as u64).map(epoch).collect(),
        };
        let next = IdentityKeyChange::Update {
            version: MAX_KEY_EPOCHS as u64 + 1,
            ed25519: [200; 32],
            ml_dsa: Vec::new(),
            next_commitment: None,
        };
        let err = check_change(
            &crate::StateAdapter::new(),
            "did:tenzro:human:aa",
            "did:tenzro:human:aa",
            &history,
            &next,
        )
        .unwrap_err();
        assert!(err.to_string().contains("succeeds to a new root"), "{err}");
    }
    use super::super::agent_terms::tests::{controller_approval, enroll, passkey};
    use super::*;
    use proptest::prelude::*;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_native_ops::identity_keys::{
        IDENTITY_DELEGATION_REVOKED_TOPIC, IDENTITY_KEY_COMPROMISED_TOPIC,
        IDENTITY_KEY_UPDATED_TOPIC, ML_DSA_65_PUBLIC_KEY_LEN,
    };

    fn human_did(key: &TestHybridSigner) -> String {
        format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(&key.public_key().p256)
        )
    }

    /// A state in which the key history is in force and the human behind
    /// `passkey()` is registered.
    fn registered() -> (crate::StateAdapter, String) {
        let mut state = crate::StateAdapter::new();
        set_governed_param_for_test(&mut state, GATE, 0);
        let did = human_did(&passkey());
        state.set_storage(&SYSTEM_ADDRESS, &identity_storage_key(&did), b"{}".to_vec());
        enroll(&mut state, &passkey());
        (state, did)
    }

    /// The key a test identity holds at `n`.
    fn key(n: u8) -> ([u8; 32], Vec<u8>) {
        ([n; 32], vec![n; ML_DSA_65_PUBLIC_KEY_LEN])
    }

    fn update(version: u64, n: u8, commit_to: Option<u8>) -> IdentityKeyChange {
        let (ed25519, ml_dsa) = key(n);
        IdentityKeyChange::Update {
            version,
            ed25519,
            ml_dsa,
            next_commitment: commit_to.map(|next| {
                let (ed, ml) = key(next);
                next_key_commitment(&ed, &ml)
            }),
        }
    }

    fn signed(did: &str, change: IdentityKeyChange, signer: &TestHybridSigner) -> IdentityKeyOp {
        let mut op = IdentityKeyOp {
            did: did.to_string(),
            change,
            approver_did: human_did(signer),
            // Replaced below: the approval covers the target, which does not
            // cover the approval.
            approval: tenzro_types::agent_terms::AgentTermsApproval {
                account: Vec::new(),
                nonce: [0; 16],
                root_public_key: Vec::new(),
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        op.approval = controller_approval(OP_IDENTITY_KEYS, &op.target(), signer);
        op
    }

    fn op(did: &str, change: IdentityKeyChange) -> IdentityKeyOp {
        signed(did, change, &passkey())
    }

    #[test]
    fn keys_are_recorded_in_order_with_the_time_each_took_effect() {
        let (mut state, did) = registered();
        assert!(read_identity_keys(&state, &did).epochs.is_empty());
        assert!(
            apply(&mut state, &op(&did, update(2, 1, None)), 10).is_err(),
            "the first key takes version 1"
        );
        let (_, logs) = apply(&mut state, &op(&did, update(1, 1, None)), 10).unwrap();
        assert_eq!(logs[0].topics[0], IDENTITY_KEY_UPDATED_TOPIC);
        assert_eq!(logs[0].topics[1], did.as_bytes());
        // The same approved update does not apply twice.
        assert!(apply(&mut state, &op(&did, update(1, 1, None)), 11).is_err());
        assert!(
            apply(&mut state, &op(&did, update(2, 1, None)), 11).is_err(),
            "the key in force is not its own successor"
        );
        apply(&mut state, &op(&did, update(2, 2, None)), 20).unwrap();
        let history = read_identity_keys(&state, &did);
        assert_eq!(
            history
                .epochs
                .iter()
                .map(|e| (e.version, e.ed25519, e.effective_from_ms))
                .collect::<Vec<_>>(),
            vec![(1, [1; 32], 10), (2, [2; 32], 20)]
        );
        assert_eq!(read_identity_head(&state, &did).sequence, 2);
    }

    #[test]
    fn a_committed_successor_is_the_only_key_that_follows() {
        let (mut state, did) = registered();
        apply(&mut state, &op(&did, update(1, 1, Some(2))), 10).unwrap();
        assert!(
            apply(&mut state, &op(&did, update(2, 3, None)), 20).is_err(),
            "not the committed key"
        );
        // Declaring the key in force compromised does not lift its commitment.
        apply(
            &mut state,
            &op(&did, IdentityKeyChange::Compromised { version: 1 }),
            21,
        )
        .unwrap();
        assert!(apply(&mut state, &op(&did, update(2, 3, None)), 22).is_err());
        apply(&mut state, &op(&did, update(2, 2, None)), 23).unwrap();
        // The second key committed to nothing: any other key follows it.
        apply(&mut state, &op(&did, update(3, 9, None)), 24).unwrap();
    }

    #[test]
    fn a_root_recovered_after_a_commitment_names_another_successor() {
        let (mut state, did) = registered();
        apply(&mut state, &op(&did, update(1, 1, Some(2))), 10).unwrap();
        // A recovery from before the commitment lifts nothing.
        record_recovery(&mut state, &did, 9, &mut Vec::new());
        assert!(apply(&mut state, &op(&did, update(2, 3, None)), 20).is_err());
        // One completed since does: the committed key may be gone with the
        // devices the recovery retired.
        record_recovery(&mut state, &did, 15, &mut Vec::new());
        apply(&mut state, &op(&did, update(2, 3, Some(4))), 21).unwrap();
        // The new key's own commitment binds again.
        assert!(apply(&mut state, &op(&did, update(3, 5, None)), 22).is_err());
        apply(&mut state, &op(&did, update(3, 4, None)), 23).unwrap();
    }

    #[test]
    fn a_compromise_is_declared_once_against_a_recorded_key() {
        let (mut state, did) = registered();
        apply(&mut state, &op(&did, update(1, 1, None)), 10).unwrap();
        let declare = |v| op(&did, IdentityKeyChange::Compromised { version: v });
        assert!(apply(&mut state, &declare(2), 11).is_err(), "no such key");
        let (_, logs) = apply(&mut state, &declare(1), 12).unwrap();
        assert_eq!(logs[0].topics[0], IDENTITY_KEY_COMPROMISED_TOPIC);
        assert_eq!(
            read_identity_keys(&state, &did).epochs[0].compromised_from_ms,
            Some(12)
        );
        assert!(apply(&mut state, &declare(1), 13).is_err());
    }

    #[test]
    fn a_delegation_is_revoked_once_by_the_identity_that_issued_it() {
        let (mut state, did) = registered();
        let revoke = |id| {
            op(
                &did,
                IdentityKeyChange::RevokeDelegation { delegation_id: id },
            )
        };
        assert_eq!(delegation_revoked_at_ms(&state, &did, &[7; 32]), None);
        let (_, logs) = apply(&mut state, &revoke([7; 32]), 30).unwrap();
        assert_eq!(logs[0].topics[0], IDENTITY_DELEGATION_REVOKED_TOPIC);
        assert_eq!(delegation_revoked_at_ms(&state, &did, &[7; 32]), Some(30));
        assert!(apply(&mut state, &revoke([7; 32]), 31).is_err());
        assert_eq!(delegation_revoked_at_ms(&state, &did, &[7; 32]), Some(30));
        // The record is the identity's own: another identity revoking the
        // same identifier writes beside it.
        let other = TestHybridSigner::hybrid(0x42);
        let other_did = human_did(&other);
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(&other_did),
            b"{}".to_vec(),
        );
        enroll(&mut state, &other);
        let theirs = signed(
            &other_did,
            IdentityKeyChange::RevokeDelegation {
                delegation_id: [7; 32],
            },
            &other,
        );
        apply(&mut state, &theirs, 40).unwrap();
        assert_eq!(
            delegation_revoked_at_ms(&state, &other_did, &[7; 32]),
            Some(40)
        );
        assert_eq!(delegation_revoked_at_ms(&state, &did, &[7; 32]), Some(30));
    }

    #[test]
    fn only_the_identitys_root_changes_its_keys() {
        let (mut state, did) = registered();
        let stranger = TestHybridSigner::hybrid(0x42);
        let stranger_did = human_did(&stranger);
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(&stranger_did),
            b"{}".to_vec(),
        );
        enroll(&mut state, &stranger);
        // The stranger names itself as approver.
        assert!(apply(&mut state, &signed(&did, update(1, 1, None), &stranger), 1).is_err());
        // The stranger signs while the root is named as approver.
        let mut forged = signed(&did, update(1, 1, None), &stranger);
        forged.approver_did = did.clone();
        assert!(apply(&mut state, &forged, 1).is_err());
        // A genuine approval does not cover another change.
        let mut moved = op(&did, update(1, 1, None));
        moved.change = update(1, 2, None);
        assert!(apply(&mut state, &moved, 1).is_err());
        // An identity the chain does not know has no keys to change.
        let unknown = TestHybridSigner::hybrid(0x43);
        assert!(
            apply(
                &mut state,
                &signed(&human_did(&unknown), update(1, 1, None), &unknown),
                1
            )
            .is_err()
        );
        assert!(read_identity_keys(&state, &did).epochs.is_empty());
        assert_eq!(read_identity_head(&state, &did), IdentityHead::default());
    }

    #[test]
    fn until_the_key_history_is_voted_in_nothing_is_accepted_or_recorded() {
        let mut state = crate::StateAdapter::new();
        let did = human_did(&passkey());
        state.set_storage(&SYSTEM_ADDRESS, &identity_storage_key(&did), b"{}".to_vec());
        enroll(&mut state, &passkey());
        let err = apply(&mut state, &op(&did, update(1, 1, None)), 10).unwrap_err();
        assert!(err.to_string().contains("not in force"), "{err}");
        // The logs other handlers emit move no head, and a recovery leaves
        // no mark.
        let mut changes = Vec::new();
        record_event(&mut state, &did, b"IdentityRegister", b"{}", &mut changes).unwrap();
        record_recovery(&mut state, &did, 5, &mut changes);
        assert!(changes.is_empty());
        assert_eq!(read_identity_head(&state, &did), IdentityHead::default());
        assert_eq!(recovered_at_ms(&state, &did), None);

        // From the epoch of the vote the same calls take effect.
        set_governed_param_for_test(&mut state, GATE, 0);
        apply(&mut state, &op(&did, update(1, 1, None)), 11).unwrap();
        assert_eq!(read_identity_head(&state, &did).sequence, 1);
    }

    #[test]
    fn a_revoked_identity_changes_no_keys() {
        let (mut state, did) = registered();
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_revocation_key(&did),
            b"{}".to_vec(),
        );
        assert!(apply(&mut state, &op(&did, update(1, 1, None)), 1).is_err());
    }

    /// One step of an identity's life, as a client might send it: valid or
    /// not.
    #[derive(Debug, Clone)]
    enum Step {
        /// The next key, optionally committing to the one after it.
        Rotate {
            commit: bool,
        },
        /// A key other than the one the key in force committed to.
        RotateToAnotherKey,
        /// An update naming a version other than the next.
        RotateAtVersion(u64),
        Compromise(u64),
        Revoke(u8),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            any::<bool>().prop_map(|commit| Step::Rotate { commit }),
            Just(Step::RotateToAnotherKey),
            (0u64..6).prop_map(Step::RotateAtVersion),
            (0u64..6).prop_map(Step::Compromise),
            (0u8..4).prop_map(Step::Revoke),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Whatever order rotations, compromise declarations and revocations
        /// arrive in, the chain's record equals a plain model of the rules,
        /// and its events link from the first to the head.
        #[test]
        fn any_order_of_changes_leaves_the_history_the_rules_describe(
            steps in proptest::collection::vec(step(), 1..14)
        ) {
            let (mut state, did) = registered();
            // The model: (key number, effective, compromised, committed key).
            let mut model: Vec<(u8, u64, Option<u64>, Option<u8>)> = Vec::new();
            let mut revoked: std::collections::BTreeMap<u8, u64> = Default::default();
            let mut emitted: Vec<Log> = Vec::new();
            // Every key the steps name is one no earlier step named.
            let mut unused = 0u8;
            let mut fresh = || {
                unused += 1;
                unused
            };
            for (i, step) in steps.iter().enumerate() {
                let at = 100 + i as u64;
                let next_version = model.len() as u64 + 1;
                let committed = model.last().and_then(|m| m.3);
                let (change, valid) = match step {
                    Step::Rotate { commit } => {
                        let n = committed.unwrap_or_else(&mut fresh);
                        let commit_to = commit.then(&mut fresh);
                        model.push((n, at, None, commit_to));
                        (update(next_version, n, commit_to), true)
                    }
                    Step::RotateToAnotherKey => {
                        let n = fresh();
                        let valid = committed.is_none();
                        if valid {
                            model.push((n, at, None, None));
                        }
                        (update(next_version, n, None), valid)
                    }
                    Step::RotateAtVersion(v) => {
                        let n = committed.unwrap_or_else(&mut fresh);
                        let valid = *v == next_version;
                        if valid {
                            model.push((n, at, None, None));
                        }
                        (update(*v, n, None), valid)
                    }
                    Step::Compromise(v) => {
                        let slot = model.get_mut((*v as usize).wrapping_sub(1));
                        let valid = matches!(slot, Some((_, _, None, _)));
                        if let Some(m) = slot.filter(|_| valid) {
                            m.2 = Some(at);
                        }
                        (IdentityKeyChange::Compromised { version: *v }, valid)
                    }
                    Step::Revoke(id) => {
                        let valid = !revoked.contains_key(id);
                        if valid {
                            revoked.insert(*id, at);
                        }
                        (
                            IdentityKeyChange::RevokeDelegation { delegation_id: [*id; 32] },
                            valid,
                        )
                    }
                };
                let result = apply(&mut state, &op(&did, change), at as i64);
                prop_assert_eq!(result.is_ok(), valid, "step {:?}", step);
                if let Ok((_, logs)) = result {
                    emitted.extend(logs);
                }
            }
            let history = read_identity_keys(&state, &did);
            let recorded: Vec<_> = history
                .epochs
                .iter()
                .map(|e| {
                    (
                        e.version,
                        e.ed25519,
                        e.effective_from_ms,
                        e.compromised_from_ms,
                        e.next_commitment,
                    )
                })
                .collect();
            let expected: Vec<_> = model
                .iter()
                .enumerate()
                .map(|(i, (n, from, compromised, commit))| {
                    (
                        i as u64 + 1,
                        [*n; 32],
                        *from,
                        *compromised,
                        commit.map(|c| {
                            let (ed, ml) = key(c);
                            next_key_commitment(&ed, &ml)
                        }),
                    )
                })
                .collect();
            prop_assert_eq!(recorded, expected);
            for (id, at) in &revoked {
                prop_assert_eq!(delegation_revoked_at_ms(&state, &did, &[*id; 32]), Some(*at));
            }
            // The head in state is the logs folded in the order they came.
            let folded = emitted.iter().fold(IdentityHead::default(), |head, log| {
                head.advanced(&did, &log.topics[0], &log.data)
            });
            prop_assert_eq!(read_identity_head(&state, &did), folded);
            prop_assert_eq!(folded.sequence, emitted.len() as u64);
        }
    }
}
