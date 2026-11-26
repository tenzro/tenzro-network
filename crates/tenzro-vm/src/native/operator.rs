//! One derivation of the operator behind an identity.
//!
//! Rules that count parties (limits per root, distinct payers, who may vote
//! for a validator, whether two sides of a payment are one party) need the
//! same answer to "who stands behind this identity". The answer is
//! [`rewards::root_identity`]: the identity followed through the controllers
//! its agent terms name, then the root its DID is derived under.
//! [`operator_did`] is that root as a DID.
//!
//! Two older derivations answered the question from the DID's text alone:
//! one named every delegated identity's root a human, also when a machine
//! rooted it; the other kept an identity of another class whole where
//! [`rewards::root_identity`] takes its id. Replacing them changes what
//! blocks execute to for those identities, so the single derivation ships
//! dormant behind [`KEY`] ([`crate::feature_gate`]).

use super::*;

/// The gate of the rule.
pub const KEY: &str = "feature.one_operator.activation_epoch";

/// The DID of the root behind `did`: `did` followed through its agent
/// terms, then the root a delegated DID (`did:tenzro:machine:{root}:{id}`)
/// is derived under, as the machine root registered under that id or else
/// the human one; an identity delegated by nobody is its own root.
pub fn operator_did(state: &dyn VmState, did: &str) -> String {
    let did = rewards::self_controlled(state, did);
    match tenzro_types::identity::delegated_root_id(&did) {
        Some(root) => {
            let machine = format!("did:tenzro:machine:{root}");
            let registered = state
                .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(&machine))
                .is_some_and(|b| !b.is_empty());
            if registered {
                machine
            } else {
                format!("did:tenzro:human:{root}")
            }
        }
        None => did,
    }
}

/// The root DID a rule counts `did` against in the block being executed:
/// [`operator_did`] once the single derivation is live, and before that the
/// root read from the DID's text.
pub fn root_did_in_force(state: &dyn VmState, did: &str) -> String {
    if crate::feature_gate::is_live_now(state, KEY) {
        operator_did(state, did)
    } else {
        crate::funding::root_did(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn register(state: &mut StateAdapter, did: &str) {
        state.set_storage(&SYSTEM_ADDRESS, &identity_storage_key(did), b"{}".to_vec());
    }

    #[test]
    fn a_delegated_identitys_root_is_the_registered_root_of_its_kind() {
        let mut state = StateAdapter::new();
        register(&mut state, "did:tenzro:machine:aa");
        assert_eq!(
            operator_did(&state, "did:tenzro:machine:aa:m1"),
            "did:tenzro:machine:aa"
        );
        assert_eq!(
            operator_did(&state, "did:tenzro:machine:bb:m1"),
            "did:tenzro:human:bb"
        );
        for own in [
            "did:tenzro:human:bb",
            "did:tenzro:machine:aa",
            "did:tenzro:institution:cc",
        ] {
            assert_eq!(operator_did(&state, own), own);
        }
        // The id every other rule compares is the last part of that DID.
        for did in [
            "did:tenzro:machine:aa:m1",
            "did:tenzro:machine:bb:m1",
            "did:tenzro:human:bb",
            "did:tenzro:institution:cc",
        ] {
            let root = operator_did(&state, did);
            assert_eq!(
                rewards::root_identity(&state, did),
                root.rsplit(':').next().unwrap()
            );
        }
    }

    #[test]
    fn the_root_a_rule_counts_against_changes_only_at_the_gates_epoch() {
        let mut state = StateAdapter::new();
        register(&mut state, "did:tenzro:machine:aa");
        set_governed_param_for_test(&mut state, KEY, 5);
        let machine_rooted = "did:tenzro:machine:aa:m1";
        let same_both_sides = [
            ("did:tenzro:machine:bb:m1", "did:tenzro:human:bb"),
            ("did:tenzro:human:bb", "did:tenzro:human:bb"),
            ("did:tenzro:machine:aa", "did:tenzro:machine:aa"),
            ("did:tenzro:institution:cc", "did:tenzro:institution:cc"),
        ];

        begin_block_params(&mut state, 4).unwrap();
        assert_eq!(
            root_did_in_force(&state, machine_rooted),
            "did:tenzro:human:aa",
            "dormant: the root is read from the text"
        );
        for (did, root) in same_both_sides {
            assert_eq!(root_did_in_force(&state, did), root, "dormant {did}");
        }

        begin_block_params(&mut state, 5).unwrap();
        assert_eq!(
            root_did_in_force(&state, machine_rooted),
            "did:tenzro:machine:aa"
        );
        for (did, root) in same_both_sides {
            assert_eq!(root_did_in_force(&state, did), root, "live {did}");
        }
    }
}
