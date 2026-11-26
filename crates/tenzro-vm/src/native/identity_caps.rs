//! How many identities one root may stand behind.
//!
//! A root delegates agents and registers machines under its own DID, and each
//! of them holds a wallet. Without a ceiling one root backs any number of
//! identities: a single person or machine appears as a crowd. Once [`GATE`]
//! is in force a root holds at most [`PER_ROOT_PARAM`] delegated identities:
//! the agents it delegated and the machines registered under its DID,
//! counted together. A revoked identity still counts: revocation does not
//! give the slot back, or revoking and delegating again would lift the
//! ceiling.

use super::funding::{read_json, refuse, write_json};
use super::*;

/// The gate of the ceiling.
pub const GATE: &str = "feature.identity_caps.activation_epoch";

/// Most delegated identities one root may stand behind.
pub const PER_ROOT_PARAM: &str = "feature.identity_caps.per_root";

fn machines_key(root_did: &str) -> String {
    format!("machines_of:{root_did}")
}

/// The machines registered under `root_did`'s DID, in order of registration.
pub fn delegated_machines(state: &dyn VmState, root_did: &str) -> Vec<String> {
    read_json(state, &machines_key(root_did)).unwrap_or_default()
}

/// The delegated identities `root_did` stands behind: its agents and the
/// machines registered under it.
pub fn delegated_count(state: &dyn VmState, root_did: &str) -> usize {
    super::identity_revocation::read_delegated_agents(state, root_did).len()
        + delegated_machines(state, root_did).len()
}

/// Refuse one more delegated identity under `root_did` once the ceiling is in
/// force and reached.
pub(super) fn require_room(state: &dyn VmState, root_did: &str) -> Result<()> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Ok(());
    }
    let cap = network_param(state, PER_ROOT_PARAM) as usize;
    let held = delegated_count(state, root_did);
    if held >= cap {
        return Err(refuse(format!(
            "{root_did} already stands behind {held} delegated identities; a root stands \
             behind at most {cap}"
        )));
    }
    Ok(())
}

/// Record a first registration of the delegated machine `did`, refused once
/// the root it is derived under has reached its ceiling. A DID that is not
/// delegated, and a re-registration, record nothing.
pub(super) fn note_machine_registration(
    state: &mut dyn VmState,
    did: &str,
    first: bool,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(root_id) = tenzro_types::identity::delegated_root_id(did) else {
        return Ok(());
    };
    if !first || !crate::feature_gate::is_live_now(state, GATE) {
        return Ok(());
    }
    // The root is the human or machine whose id the DID carries.
    let root = ["did:tenzro:human:", "did:tenzro:machine:"]
        .iter()
        .map(|p| format!("{p}{root_id}"))
        .find(|r| {
            state
                .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(r))
                .is_some_and(|b| !b.is_empty())
        })
        .ok_or_else(|| {
            refuse(format!(
                "{did} is derived under a root that is not registered"
            ))
        })?;
    require_room(state, &root)?;
    let mut machines = delegated_machines(state, &root);
    machines.push(did.to_string());
    write_json(state, &machines_key(&root), &machines, changes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    const ROOT: &str = "did:tenzro:human:root";

    fn with_root() -> StateAdapter {
        let mut state = StateAdapter::new();
        state.set_storage(&SYSTEM_ADDRESS, &identity_storage_key(ROOT), b"{}".to_vec());
        state
    }

    fn agent(state: &mut StateAdapter, n: u32) {
        super::super::identity_revocation::index_delegated_agent(
            state,
            ROOT,
            &format!("did:tenzro:machine:root:agent{n}"),
            &mut Vec::new(),
        )
        .unwrap();
    }

    #[test]
    fn dormant_a_root_stands_behind_any_number() {
        let mut state = with_root();
        for n in 0..100 {
            agent(&mut state, n);
        }
        require_room(&state, ROOT).unwrap();
        let mut changes = Vec::new();
        note_machine_registration(&mut state, "did:tenzro:machine:root:m1", true, &mut changes)
            .unwrap();
        assert!(changes.is_empty(), "nothing is counted before the vote");
    }

    #[test]
    fn live_agents_and_machines_share_one_ceiling() {
        let mut state = with_root();
        set_governed_param_for_test(&mut state, GATE, 0);
        set_governed_param_for_test(&mut state, PER_ROOT_PARAM, 3);
        agent(&mut state, 0);
        agent(&mut state, 1);
        let mut changes = Vec::new();
        note_machine_registration(&mut state, "did:tenzro:machine:root:m1", true, &mut changes)
            .unwrap();
        assert_eq!(delegated_count(&state, ROOT), 3);
        // Full: a fourth of either kind is refused.
        assert!(require_room(&state, ROOT).is_err());
        assert!(
            note_machine_registration(&mut state, "did:tenzro:machine:root:m2", true, &mut changes)
                .is_err()
        );
        // A re-registration takes no new slot, and another root is not affected.
        note_machine_registration(
            &mut state,
            "did:tenzro:machine:root:m1",
            false,
            &mut changes,
        )
        .unwrap();
        require_room(&state, "did:tenzro:human:other").unwrap();
        // An identity that is not delegated is not counted anywhere.
        note_machine_registration(&mut state, "did:tenzro:machine:solo", true, &mut changes)
            .unwrap();
        assert_eq!(delegated_count(&state, ROOT), 3);
    }

    #[test]
    fn live_a_machine_under_an_unregistered_root_is_refused() {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, GATE, 0);
        assert!(
            note_machine_registration(
                &mut state,
                "did:tenzro:machine:ghost:m1",
                true,
                &mut Vec::new()
            )
            .is_err()
        );
    }
}
