//! A root's revocation in favour of a successor (see
//! [`tenzro_native_ops::identity_succession`]).
//!
//! The root approves its own revocation and names a successor. The root is
//! revoked as by `RevokeIdentity`. Each agent it delegated is quarantined
//! instead of revoked, and the chain records the successor as the one
//! identity that may reclaim what the agent's wallet holds. A quarantine
//! entered this way is not lifted: the agent never acts again, under the
//! revoked root or the successor.
//!
//! Dormant until governance sets [`GATE`]. While
//! [`SUCCESSOR_HUMAN_ONLY_PARAM`] is set, the successor is a human root.

use tenzro_native_ops::identity_succession::{
    IdentitySuccessionOp, OP_REVOKE_IDENTITY_TO, QUARANTINE_ROOT_SUCCEEDED, agent_successor_slot,
};
use tenzro_types::agent_terms::RootKind;

use super::agent_audit::{AgentQuarantine, impose};
use super::agent_terms::verify_root_approval;
use super::funding::refuse;
use super::identity_revocation::{read_delegated_agents, revoke_one};
use super::*;

/// The gate of succession: from its epoch the chain accepts
/// revocations in favour of a successor.
pub const GATE: &str = "feature.agent_succession.activation_epoch";

/// Whether a successor must be a human root: 1 at genesis.
pub const SUCCESSOR_HUMAN_ONLY_PARAM: &str = "feature.agent_succession.successor_human_only";

pub use tenzro_native_ops::SELECTOR_IDENTITY_SUCCESSION;

/// Gas for a succession: a root approval check and its records.
pub const GAS_IDENTITY_SUCCESSION: u64 = 60_000;

/// Gas for each delegated agent a succession reaches.
pub const GAS_IDENTITY_SUCCESSION_PER_AGENT: u64 = 30_000;

/// Topic of the log that names an agent's successor.
pub const AGENT_SUCCESSOR_SET_TOPIC: &[u8] = b"AgentSuccessorSet";

/// The identity that may reclaim what `agent_did`'s wallet holds because the
/// agent's root was revoked in its favour, if there is one.
pub fn agent_successor(state: &dyn VmState, agent_did: &str) -> Option<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, agent_successor_slot(agent_did).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| String::from_utf8(b).ok())
}

/// Gas `op` costs: the revocation and every agent it reaches. The executor
/// charges it against the transaction's gas limit before `apply` runs, so a
/// root with more agents than the limit pays for fails out of gas, and the
/// loop in `apply` never runs past the number of agents the limit covers.
pub fn gas(state: &dyn VmState, op: &IdentitySuccessionOp) -> u64 {
    let agents = read_delegated_agents(state, &op.did).len() as u64;
    GAS_IDENTITY_SUCCESSION.saturating_add(GAS_IDENTITY_SUCCESSION_PER_AGENT.saturating_mul(agents))
}

/// Check that `op` may be applied at `now_ms` without writing anything:
/// succession is in force, the identity is a registered root not yet
/// revoked, the successor is a registered root in good standing (a human
/// one while the governed rule says so), and the root's approval verifies
/// against keys in chain state. Returns the approved challenge digest.
pub fn authorize(state: &dyn VmState, op: &IdentitySuccessionOp, now_ms: i64) -> Result<[u8; 32]> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse(
            "revoking an identity in favour of a successor is not in force on this chain yet",
        ));
    }
    op.validate().map_err(refuse)?;
    let did = op.did.as_str();
    let successor = op.successor_did.as_str();
    let registered = |d: &str| {
        state
            .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(d))
            .is_some_and(|b| !b.is_empty())
    };
    if RootKind::of(did).is_none() || !registered(did) {
        return Err(refuse(format!(
            "{did} is not a registered root; only a root is revoked in favour of a successor"
        )));
    }
    if is_identity_revoked(state, did) {
        return Err(refuse(format!("identity {did} is already revoked")));
    }
    let Some(kind) = RootKind::of(successor) else {
        return Err(refuse(format!(
            "{successor} is not a root and cannot succeed one"
        )));
    };
    if network_param(state, SUCCESSOR_HUMAN_ONLY_PARAM) != 0 && kind != RootKind::Passkey {
        return Err(refuse(format!(
            "{successor} is not a human identity; a successor is a human root"
        )));
    }
    if !registered(successor) || is_identity_revoked(state, successor) {
        return Err(refuse(format!(
            "{successor} is not a registered identity in good standing"
        )));
    }
    verify_root_approval(
        state,
        did,
        OP_REVOKE_IDENTITY_TO,
        &op.target(),
        &op.approval,
        now_ms.max(0) as u64,
    )
    .map_err(refuse)
}

/// Apply one succession approved by the root it revokes.
pub fn apply(
    state: &mut dyn VmState,
    op: &IdentitySuccessionOp,
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
        did,
        &digest,
        now_ms,
        &mut changes,
        &mut logs,
    )?;
    for agent in read_delegated_agents(state, did) {
        // An agent its controller already revoked stays revoked; its wallet
        // still passes to the successor.
        impose(
            state,
            &agent,
            &AgentQuarantine {
                controller_did: op.successor_did.clone(),
                by: did.to_string(),
                reason_code: QUARANTINE_ROOT_SUCCEEDED,
                evidence_hash: Some(hex::encode(digest)),
                at_ms: now_ms,
                revoked: false,
            },
            &mut changes,
            &mut logs,
        )?;
        let key = agent_successor_slot(&agent).into_bytes();
        let value = op.successor_did.clone().into_bytes();
        let previous = state.get_storage(&SYSTEM_ADDRESS, &key);
        state.set_storage(&SYSTEM_ADDRESS, &key, value.clone());
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            key,
            previous,
            Some(value),
        ));
        let data = serde_json::to_vec(&serde_json::json!({
            "agent_did": agent,
            "root_did": did,
            "successor_did": op.successor_did,
        }))
        .map_err(|e| VmError::Internal(format!("encode successor log: {e}")))?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![AGENT_SUCCESSOR_SET_TOPIC.to_vec()],
            data,
        ));
    }
    Ok((changes, logs))
}
