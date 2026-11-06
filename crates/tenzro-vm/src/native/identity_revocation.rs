//! Identity revocation on the identity's root's authority (see
//! [`tenzro_types::identity::IdentityRevocationOp`]).
//!
//! A root revokes itself; a delegated agent is revoked by the controller its
//! terms in chain state name. The approval goes through the one root-approval
//! check every root-signed operation uses, against keys chain state holds, so
//! a relaying node cannot revoke anything its owner did not approve. A
//! machine a root registered has no terms on chain and is revoked by the
//! root its DID is derived under. Revoking
//! a root revokes every agent it delegated, found through the controller's
//! agent index. Each revocation writes the `identity_revoked:<did>` marker
//! and an `IdentityRevoked` log, the same record a governance revocation
//! writes, which every node's read model follows.

use tenzro_types::agent_terms::RootKind;
use tenzro_types::identity::{
    IdentityRevocationOp, IdentityRevokedLog, OP_REVOKE_IDENTITY, is_delegated_under,
};

use super::agent_terms::{read_agent_terms, verify_root_approval};
use super::funding::{read_json, refuse, write_json};
use super::*;

/// Selector of a `RevokeIdentity` transaction.
pub const SELECTOR_IDENTITY_REVOKE: [u8; 4] = [0x01, 0x00, 0x00, 0xD6];

/// Gas for one revocation: a root approval check and its records.
pub const GAS_IDENTITY_REVOKE: u64 = 60_000;

/// Gas for each delegated agent a revocation reaches.
pub const GAS_IDENTITY_REVOKE_PER_AGENT: u64 = 20_000;

fn agents_key(controller_did: &str) -> String {
    format!("agents_of:{controller_did}")
}

/// The agents `controller_did` has delegated, in the order they were created.
pub fn read_delegated_agents(state: &dyn VmState, controller_did: &str) -> Vec<String> {
    read_json(state, &agents_key(controller_did)).unwrap_or_default()
}

/// Add `agent_did` to its controller's agent index.
pub(super) fn index_delegated_agent(
    state: &mut dyn VmState,
    controller_did: &str,
    agent_did: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut agents = read_delegated_agents(state, controller_did);
    if agents.iter().any(|a| a == agent_did) {
        return Ok(());
    }
    agents.push(agent_did.to_string());
    write_json(state, &agents_key(controller_did), &agents, changes).map(|_| ())
}

/// Gas `op` costs: the revocation and every agent it reaches.
pub fn gas(state: &dyn VmState, op: &IdentityRevocationOp) -> u64 {
    let agents = read_delegated_agents(state, &op.did).len() as u64;
    GAS_IDENTITY_REVOKE.saturating_add(GAS_IDENTITY_REVOKE_PER_AGENT.saturating_mul(agents))
}

/// Check that `op` may be applied at `now_ms` without writing anything: the
/// identity is known and not yet revoked, the approver is its root, and the
/// root's approval verifies against keys in chain state. Returns the
/// approved challenge digest. A node runs this before admitting a
/// revocation; every validator runs it again in [`apply`].
pub fn authorize(state: &dyn VmState, op: &IdentityRevocationOp, now_ms: i64) -> Result<[u8; 32]> {
    op.validate().map_err(refuse)?;
    let did = op.did.as_str();
    if is_identity_revoked(state, did) {
        return Err(refuse(format!("identity {did} is already revoked")));
    }
    let registered = state
        .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
        .is_some_and(|b| !b.is_empty());
    let terms = read_agent_terms(state, did);
    // A machine a root registered has no terms on chain; its DID is derived
    // under that root, which is the one root that may revoke it.
    let under_approver = terms.is_none() && is_delegated_under(did, &op.approver_did);
    if !registered && terms.is_none() && !under_approver {
        return Err(refuse(format!(
            "identity {did} is neither registered nor delegated on this chain"
        )));
    }
    let authorized = if op.approver_did == did {
        RootKind::of(did).is_some()
    } else if let Some(t) = terms.as_ref() {
        t.terms.controller_did == op.approver_did
    } else {
        under_approver
    };
    if !authorized {
        return Err(refuse(format!(
            "{} may not revoke {did}: a root revokes itself, a delegated agent is revoked by \
             the controller its terms name, and a delegated machine by the root its DID is \
             derived under",
            op.approver_did
        )));
    }
    verify_root_approval(
        state,
        &op.approver_did,
        OP_REVOKE_IDENTITY,
        &op.target(),
        &op.approval,
        now_ms.max(0) as u64,
    )
    .map_err(refuse)
}

/// Apply one revocation approved by the identity's root.
pub fn apply(
    state: &mut dyn VmState,
    op: &IdentityRevocationOp,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let digest = authorize(state, op, now_ms)?;
    let did = op.did.as_str();
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    revoke_one(
        state,
        did,
        &op.reason,
        &op.approver_did,
        &digest,
        now_ms,
        &mut changes,
        &mut logs,
    )?;
    for agent in read_delegated_agents(state, did) {
        if is_identity_revoked(state, &agent) {
            continue;
        }
        revoke_one(
            state,
            &agent,
            &format!("cascaded from {did}"),
            &op.approver_did,
            &digest,
            now_ms,
            &mut changes,
            &mut logs,
        )?;
    }
    Ok((changes, logs))
}

#[allow(clippy::too_many_arguments)]
fn revoke_one(
    state: &mut dyn VmState,
    did: &str,
    reason: &str,
    approver_did: &str,
    digest: &[u8; 32],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let record = IdentityRevokedLog {
        did: did.to_string(),
        reason: reason.to_string(),
        revoked_by: approver_did.to_string(),
        proposal_id: None,
    };
    let blob = serde_json::to_vec(&record)
        .map_err(|e| VmError::Internal(format!("cannot serialise the revocation record: {e}")))?;
    let key = identity_revocation_key(did);
    let previous = state.get_storage(&SYSTEM_ADDRESS, &key);
    state.set_storage(&SYSTEM_ADDRESS, &key, blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key,
        previous,
        Some(blob.clone()),
    ));
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"IdentityRevoked".to_vec()],
        blob,
    ));
    if let Some(terms) = read_agent_terms(state, did) {
        let already =
            super::agent_audit::read_agent_quarantine(state, did).is_some_and(|q| q.revoked);
        if !already {
            super::agent_audit::mark_revoked(
                state,
                did,
                &terms.terms.controller_did,
                approver_did.to_string(),
                digest,
                now_ms,
                changes,
                logs,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::agent_terms::tests::{Agent, controller_approval, machine_approval, passkey};
    use super::*;
    use tenzro_types::agent_terms::{AgentTermsApproval, TermsScope};

    fn xy(key: &tenzro_crypto::composite::testing::TestHybridSigner) -> Vec<u8> {
        use tenzro_crypto::composite::HybridSigner as _;
        key.public_key().p256.clone()
    }

    fn human_did(key: &tenzro_crypto::composite::testing::TestHybridSigner) -> String {
        format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(&xy(key))
        )
    }

    /// Registers `did` and enrolls the ML-DSA-65 key of the controller's
    /// passkey.
    fn register(state: &mut dyn VmState, did: &str) {
        state.set_storage(&SYSTEM_ADDRESS, &identity_storage_key(did), b"{}".to_vec());
        super::super::agent_terms::tests::enroll(state, &passkey());
    }

    fn op(did: &str, approver: &str, approval: AgentTermsApproval) -> IdentityRevocationOp {
        IdentityRevocationOp {
            did: did.to_string(),
            reason: "key lost".to_string(),
            approver_did: approver.to_string(),
            approval,
        }
    }

    fn approved_by(
        did: &str,
        approver: &str,
        signer: &tenzro_crypto::composite::testing::TestHybridSigner,
    ) -> IdentityRevocationOp {
        let target = tenzro_types::identity::revocation_target(did, "key lost");
        op(
            did,
            approver,
            controller_approval(OP_REVOKE_IDENTITY, &target, signer),
        )
    }

    fn revoked_record(state: &dyn VmState, did: &str) -> Option<IdentityRevokedLog> {
        state
            .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did))
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    #[test]
    fn a_human_revokes_itself_with_its_passkey() {
        let mut state = crate::StateAdapter::new();
        let did = human_did(&passkey());
        register(&mut state, &did);
        let (_, logs) = apply(&mut state, &approved_by(&did, &did, &passkey()), 1).unwrap();
        let record = revoked_record(&state, &did).expect("revocation written to chain state");
        assert_eq!(record.revoked_by, did);
        assert_eq!(record.reason, "key lost");
        assert_eq!(record.proposal_id, None);
        assert!(
            logs.iter().any(
                |l| l.topics.first().map(|t| t.as_slice()) == Some(b"IdentityRevoked".as_ref())
            )
        );
        assert!(apply(&mut state, &approved_by(&did, &did, &passkey()), 2).is_err());
    }

    #[test]
    fn a_strangers_revocation_is_refused() {
        let mut state = crate::StateAdapter::new();
        let did = human_did(&passkey());
        register(&mut state, &did);
        let stranger = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(0x42);

        // The stranger signs with its own key while claiming to be the root.
        assert!(apply(&mut state, &approved_by(&did, &did, &stranger), 1).is_err());
        // The stranger names itself as the approver.
        let stranger_did = human_did(&stranger);
        register(&mut state, &stranger_did);
        assert!(apply(&mut state, &approved_by(&did, &stranger_did, &stranger), 1).is_err());
        // A genuine approval for another reason does not cover this one.
        let mut moved = approved_by(&did, &did, &passkey());
        moved.reason = "something else".into();
        assert!(apply(&mut state, &moved, 1).is_err());
        assert!(revoked_record(&state, &did).is_none());
    }

    #[test]
    fn an_identity_unknown_to_the_chain_is_refused() {
        let mut state = crate::StateAdapter::new();
        let did = human_did(&passkey());
        assert!(apply(&mut state, &approved_by(&did, &did, &passkey()), 1).is_err());
        assert!(revoked_record(&state, &did).is_none());
    }

    #[test]
    fn a_delegated_agent_is_revoked_by_its_named_controller() {
        let mut a = Agent::new(TermsScope::default());
        let controller = read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms
            .controller_did;
        let (_, logs) = apply(
            &mut a.state,
            &approved_by(&a.did, &controller, &passkey()),
            1,
        )
        .unwrap();
        assert_eq!(
            revoked_record(&a.state, &a.did).unwrap().revoked_by,
            controller
        );
        assert!(
            super::super::agent_audit::read_agent_quarantine(&a.state, &a.did)
                .is_some_and(|q| q.revoked),
            "every node refuses a revoked agent's actions"
        );
        assert!(logs.iter().any(|l| l.topics.first().map(|t| t.as_slice())
            == Some(super::super::agent_audit::AGENT_REVOKED_TOPIC)));
    }

    #[test]
    fn a_delegated_agent_cannot_be_revoked_by_another_root_or_itself() {
        let mut a = Agent::new(TermsScope::default());
        let other = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(0x43);
        let other_did = human_did(&other);
        register(&mut a.state, &other_did);
        assert!(apply(&mut a.state, &approved_by(&a.did, &other_did, &other), 1).is_err());
        assert!(apply(&mut a.state, &approved_by(&a.did, &a.did, &passkey()), 1).is_err());
        assert!(revoked_record(&a.state, &a.did).is_none());
    }

    #[test]
    fn a_delegated_machine_is_revoked_by_the_root_its_did_names() {
        let mut a = Agent::new(TermsScope::default());
        let controller = read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms
            .controller_did;
        let root_id = controller.rsplit(':').next().unwrap();
        let machine = format!("did:tenzro:machine:{root_id}:{}", "ab".repeat(32));
        assert!(read_agent_terms(&a.state, &machine).is_none());

        let other = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(0x44);
        let other_did = human_did(&other);
        register(&mut a.state, &other_did);
        assert!(apply(&mut a.state, &approved_by(&machine, &other_did, &other), 1).is_err());
        assert!(
            apply(
                &mut a.state,
                &approved_by(&machine, &machine, &passkey()),
                1
            )
            .is_err()
        );
        assert!(apply(&mut a.state, &approved_by(&machine, &controller, &other), 1).is_err());
        assert!(revoked_record(&a.state, &machine).is_none());

        apply(
            &mut a.state,
            &approved_by(&machine, &controller, &passkey()),
            1,
        )
        .unwrap();
        assert_eq!(
            revoked_record(&a.state, &machine).unwrap().revoked_by,
            controller
        );
    }

    #[test]
    fn revoking_a_root_revokes_every_agent_it_delegated() {
        let mut a = Agent::new(TermsScope::default());
        let controller = read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms
            .controller_did;
        register(&mut a.state, &controller);
        index_delegated_agent(&mut a.state, &controller, &a.did, &mut Vec::new()).unwrap();
        let revocation = approved_by(&controller, &controller, &passkey());
        assert_eq!(
            gas(&a.state, &revocation),
            GAS_IDENTITY_REVOKE + GAS_IDENTITY_REVOKE_PER_AGENT
        );
        apply(&mut a.state, &revocation, 1).unwrap();
        assert!(revoked_record(&a.state, &controller).is_some());
        let cascaded =
            revoked_record(&a.state, &a.did).expect("the agent is revoked with its root");
        assert_eq!(cascaded.reason, format!("cascaded from {controller}"));
        assert!(
            super::super::agent_audit::read_agent_quarantine(&a.state, &a.did)
                .is_some_and(|q| q.revoked)
        );
    }

    #[test]
    fn an_autonomous_machine_revokes_itself_with_its_hardware_key() {
        use tenzro_crypto::composite::HybridSigner;
        let mut state = crate::StateAdapter::new();
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(5);
        super::super::agent_terms::tests::enroll(&mut state, &signer);
        let p256 = signer.public_key().p256.clone();
        let did = tenzro_types::did_derivation::machine_did(&p256);
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: String::new(),
            controller_pubkey: p256.clone(),
            key_type: "P-256".into(),
            wallet_id: String::new(),
            wallet_address: tenzro_types::primitives::Address::default(),
            pq_verifying_key: signer.public_key().pq.clone().unwrap(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::TpmQuote {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(&did),
            serde_json::to_vec(&record).unwrap(),
        );
        let target = tenzro_types::identity::revocation_target(&did, "key lost");
        let ok = op(
            &did,
            &did,
            machine_approval(OP_REVOKE_IDENTITY, &target, &signer),
        );
        apply(&mut state, &ok, 1).unwrap();
        assert_eq!(revoked_record(&state, &did).unwrap().revoked_by, did);
    }
}
