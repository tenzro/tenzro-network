//! Per-epoch commitments to the audit trail of the agents a node supervises.
//!
//! Each node sends one `AgentAuditCommit` per epoch: the Merkle root over
//! `(session_id, MMR root, entry count)` for every agent session it
//! supervised in that epoch (see `tenzro_types::agent_audit`). The root is
//! recorded under the sending account and the epoch, once; a second
//! commitment for the same epoch is refused, so the history a node committed
//! cannot be replaced.
//!
//! A root stays recorded while an evidence pack may still prove entries
//! against it: `storage.audit_retention_seconds` after its epoch, plus the
//! commit window. Older roots are deleted, at most 64 epochs a block,
//! behind `agent_audit_pruned_below`, the first epoch still kept.

use serde::{Deserialize, Serialize};

use super::funding::{delete_record, read_json, refuse, write_json};
use super::*;

/// Gas for a commitment.
pub const GAS_AGENT_AUDIT_COMMIT: u64 = 30_000;
/// Epochs after its end that an epoch may still be committed.
pub const AGENT_AUDIT_COMMIT_WINDOW: u64 = 2;
/// Topic of the log a commitment emits.
pub const AGENT_AUDIT_TOPIC: &[u8] = b"AgentAuditCommitted";

/// A node's recorded commitment for one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuditRecord {
    /// Root over the epoch's session lines, hex.
    pub root: String,
    /// Sessions it covers.
    pub sessions: u64,
    /// DA reference of the epoch's entries; empty when held by the node.
    pub entries_ref: String,
    /// The machine's hardware attestation over `(epoch, root)`, hex; empty
    /// on a machine with no TPM.
    #[serde(default)]
    pub attestation: String,
    /// Block time it was recorded at, ms.
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct Payload {
    epoch: u64,
    root: String,
    sessions: u64,
    entries_ref: String,
    #[serde(default)]
    attestation: String,
}

/// System storage slot of a node's commitment for an epoch.
pub fn record_key(committer: &[u8], epoch: u64) -> String {
    format!("agent_audit:{}:{epoch:016x}", hex::encode(committer))
}

fn last_key(committer: &[u8]) -> String {
    format!("agent_audit_last:{}", hex::encode(committer))
}

/// The commitment `committer` recorded for `epoch`.
pub fn read_agent_audit(
    state: &dyn VmState,
    committer: &[u8],
    epoch: u64,
) -> Option<AgentAuditRecord> {
    read_json(state, &record_key(committer, epoch))
}

const COMMITTERS_KEY: &str = "agent_audit_committers";

/// Every account that has ever committed an audit root, hex, in the order
/// they first did: the set validators check each epoch.
pub fn agent_audit_committers(state: &dyn VmState) -> Vec<String> {
    read_json(state, COMMITTERS_KEY).unwrap_or_default()
}

/// The latest epoch `committer` has committed.
pub fn last_agent_audit_epoch(state: &dyn VmState, committer: &[u8]) -> Option<u64> {
    read_json(state, &last_key(committer))
}

/// Key of the first epoch whose roots are still recorded.
const PRUNED_BELOW_KEY: &str = "agent_audit_pruned_below";

/// Most epochs one block deletes the roots of.
const MAX_PRUNED_EPOCHS_PER_BLOCK: u64 = 64;

/// Epochs a root stays recorded after its own: the governed audit retention
/// in epochs of the reward schedule, rounded up, plus the commit window and
/// the epoch it closes in. `None` before genesis wrote a schedule.
pub fn kept_audit_epochs(state: &dyn VmState) -> Option<u64> {
    let schedule = rewards::read_reward_schedule(state).ok()?;
    let epoch_ms = tenzro_token::rewards::SCHEDULE_YEAR_MS / schedule.epochs_per_year.max(1);
    let retention_ms =
        network_param(state, crate::governance::AUDIT_RETENTION_PARAM).saturating_mul(1_000);
    Some(
        retention_ms
            .div_ceil(epoch_ms.max(1))
            .saturating_add(AGENT_AUDIT_COMMIT_WINDOW + 1),
    )
}

/// Deletes every committer's root of each epoch more than
/// [`kept_audit_epochs`] behind `current_epoch`. Such an epoch is long past
/// the commit window, so it cannot be committed again.
pub(super) fn prune(
    state: &mut dyn VmState,
    current_epoch: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(keep) = kept_audit_epochs(state) else {
        return Ok(());
    };
    let from: u64 = read_json(state, PRUNED_BELOW_KEY).unwrap_or(0);
    let to = current_epoch
        .saturating_sub(keep)
        .min(from.saturating_add(MAX_PRUNED_EPOCHS_PER_BLOCK));
    if to <= from {
        return Ok(());
    }
    let committers: Vec<Vec<u8>> = agent_audit_committers(state)
        .iter()
        .filter_map(|c| hex::decode(c).ok())
        .collect();
    for epoch in from..to {
        for committer in &committers {
            delete_record(state, &record_key(committer, epoch), changes);
        }
    }
    write_json(state, PRUNED_BELOW_KEY, &to, changes)?;
    Ok(())
}

/// Record one node's commitment for an epoch.
pub(super) fn commit(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let p: Payload = serde_json::from_slice(payload).map_err(|e| {
        VmError::InvalidTransaction(format!("Invalid AgentAuditCommit payload: {e}"))
    })?;
    let root = hex::decode(&p.root).map_err(|e| refuse(format!("root is not hex: {e}")))?;
    if root.len() != 32 {
        return Err(refuse("an audit root is 32 bytes"));
    }
    if p.sessions == 0 {
        return Err(refuse("a commitment covers at least one session"));
    }
    let current = rewards::read_reward_state(state)?.current_epoch;
    if p.epoch > current || current - p.epoch > AGENT_AUDIT_COMMIT_WINDOW {
        return Err(refuse(format!(
            "epoch {} cannot be committed in epoch {current}",
            p.epoch
        )));
    }
    let key = record_key(from, p.epoch);
    if state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()).is_some() {
        return Err(refuse(format!(
            "epoch {} is already committed by this account",
            p.epoch
        )));
    }
    let record = AgentAuditRecord {
        root: p.root.to_lowercase(),
        sessions: p.sessions,
        entries_ref: p.entries_ref,
        attestation: p.attestation,
        recorded_at_ms: now_ms,
    };
    let mut changes = Vec::new();
    write_json(state, &key, &record, &mut changes)?;
    if last_agent_audit_epoch(state, from).is_none() {
        let mut all = agent_audit_committers(state);
        all.push(hex::encode(from));
        write_json(state, COMMITTERS_KEY, &all, &mut changes)?;
    }
    if last_agent_audit_epoch(state, from).is_none_or(|e| e < p.epoch) {
        write_json(state, &last_key(from), &p.epoch, &mut changes)?;
    }
    let log_data = serde_json::to_vec(&serde_json::json!({
        "committer": hex::encode(from),
        "epoch": p.epoch,
        "root": record.root,
        "sessions": record.sessions,
    }))
    .map_err(|e| VmError::Internal(format!("encode audit commitment log: {e}")))?;
    let logs = vec![Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AGENT_AUDIT_TOPIC.to_vec()],
        log_data,
    )];
    Ok((changes, logs))
}

/// Gas for lifting a quarantine.
pub const GAS_LIFT_AGENT_QUARANTINE: u64 = 40_000;
/// Gas for a flag, before its findings.
pub const GAS_AGENT_AUDIT_FLAG: u64 = 40_000;
/// Gas per finding.
pub const GAS_AGENT_AUDIT_FINDING: u64 = 10_000;
/// Topic of the log a lifted quarantine emits.
pub const AGENT_QUARANTINE_LIFTED_TOPIC: &[u8] = b"AgentQuarantineLifted";
/// Topic of the log a finding emits when it takes effect.
pub const AGENT_AUDIT_FINDING_TOPIC: &[u8] = b"AgentAuditFinding";

/// An agent's quarantine as chain state records it. Every node refuses the
/// agent's actions while it is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentQuarantine {
    /// Owner or controller who alone may lift it.
    pub controller_did: String,
    /// Account that imposed it, hex; `validators` for a quorum finding.
    pub by: String,
    /// Reason code.
    pub reason_code: u16,
    /// SHA-256 of the evidence, hex.
    pub evidence_hash: Option<String>,
    /// Block time it was imposed at, ms.
    pub at_ms: i64,
    /// The controller revoked the agent. Permanent: a revoked agent is not
    /// lifted and a later quarantine does not replace the record.
    #[serde(default)]
    pub revoked: bool,
}

/// Gas for revoking a delegated agent.
pub const GAS_REVOKE_DELEGATED_AGENT: u64 = 40_000;
/// Topic of the log a revocation emits.
pub const AGENT_REVOKED_TOPIC: &[u8] = b"DelegatedAgentRevoked";

/// A finding that took effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuditVerdict {
    /// The finding.
    pub finding: tenzro_types::agent_audit::AuditFinding,
    /// Epoch it was made in.
    pub epoch: u64,
    /// Stake behind it, decimal.
    pub stake: String,
    /// Validators behind it.
    pub validators: usize,
    /// Block time it took effect, ms.
    pub at_ms: i64,
}

/// System storage slot of an agent's quarantine or revocation.
pub fn quarantine_key(agent_did: &str) -> String {
    format!("agent_quarantine:{agent_did}")
}

fn finding_key(id: &[u8; 32]) -> String {
    format!("agent_audit_finding:{}", hex::encode(id))
}

fn finding_subs_key(id: &[u8; 32]) -> String {
    format!("agent_audit_finding_sub:{}", hex::encode(id))
}

/// The quarantine chain state holds for `agent_did`.
pub fn read_agent_quarantine(state: &dyn VmState, agent_did: &str) -> Option<AgentQuarantine> {
    read_json(state, &quarantine_key(agent_did))
}

/// A finding that took effect, by its id.
pub fn read_agent_audit_verdict(state: &dyn VmState, id: &[u8; 32]) -> Option<AgentAuditVerdict> {
    read_json(state, &finding_key(id))
}

/// Record a quarantine. Called by the kill-switch quarantine once it is
/// authorized, and by a finding that takes effect.
pub(super) fn impose(
    state: &mut dyn VmState,
    agent_did: &str,
    quarantine: &AgentQuarantine,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    // A revocation is the stronger status and is never replaced.
    if read_agent_quarantine(state, agent_did).is_some_and(|q| q.revoked) {
        return Ok(());
    }
    write_json(state, &quarantine_key(agent_did), quarantine, changes)?;
    withdraw_authority(
        state,
        agent_did,
        quarantine.at_ms.max(0) as u64,
        changes,
        logs,
    )?;
    Ok(())
}

/// An action an agent's account on another chain reported, proven through
/// the chain's route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteActionEntry {
    /// The digest the serving nodes signed, hex.
    pub digest: String,
    /// What it moved of the grant's asset.
    pub amount: String,
    /// Block time it was recorded, ms.
    pub recorded_at_ms: i64,
}

pub fn remote_action_key(agent_did: &str, caip2: &str, seq: u64, nonce: u64) -> String {
    format!("agent_remote_action:{agent_did}:{caip2}:{seq}:{nonce}")
}

/// Add a proven remote action to the agent's audit trail at `key`
/// ([`remote_action_key`]), once.
pub(super) fn record_remote_action(
    state: &mut dyn VmState,
    key: &str,
    entry: &RemoteActionEntry,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if read_json::<RemoteActionEntry>(state, key).is_some() {
        return Err(refuse("that remote action is already recorded"));
    }
    write_json(state, key, entry, changes)?;
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct RevokePayload {
    agent_did: String,
    controller_did: String,
    approval_digest: String,
}

/// Revoke a delegated agent. Sent by its controller (see
/// [`super::authorize_agent_controller`]). A root's passkey approval relayed
/// by another account goes through RevokeIdentity, which verifies it.
pub(super) fn revoke(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
    at_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let p: RevokePayload = serde_json::from_slice(payload).map_err(|e| {
        VmError::InvalidTransaction(format!("Invalid RevokeDelegatedAgent payload: {e}"))
    })?;
    let digest = hex::decode(&p.approval_digest)
        .ok()
        .filter(|d| d.len() == 32)
        .ok_or_else(|| refuse("approval_digest must be 32 bytes, hex"))?;
    super::require_agent_controller(state, from, &p.agent_did, &p.controller_did)?;
    if read_agent_quarantine(state, &p.agent_did).is_some_and(|q| q.revoked) {
        return Err(refuse(format!("{} is already revoked", p.agent_did)));
    }
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    mark_revoked(
        state,
        &p.agent_did,
        &p.controller_did,
        hex::encode(from),
        &digest,
        at_ms,
        &mut changes,
        &mut logs,
    )?;
    Ok((changes, logs))
}

/// Record `agent_did` as revoked by its controller and withdraw its
/// authority. `by` names who sent or approved the revocation; `digest` is the
/// approval it rests on.
#[allow(clippy::too_many_arguments)]
pub(super) fn mark_revoked(
    state: &mut dyn VmState,
    agent_did: &str,
    controller_did: &str,
    by: String,
    digest: &[u8],
    at_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let record = AgentQuarantine {
        controller_did: controller_did.to_string(),
        by,
        reason_code: 0,
        evidence_hash: Some(hex::encode(digest)),
        at_ms,
        revoked: true,
    };
    write_json(state, &quarantine_key(agent_did), &record, changes)?;
    let log_data = serde_json::to_vec(&serde_json::json!({
        "agent_did": agent_did,
        "controller_did": controller_did,
        "approval_digest": hex::encode(digest),
    }))
    .map_err(|e| VmError::Internal(format!("encode revoke log: {e}")))?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AGENT_REVOKED_TOPIC.to_vec()],
        log_data,
    ));
    withdraw_authority(state, agent_did, at_ms.max(0) as u64, changes, logs)
}

#[derive(Debug, Clone, Deserialize)]
struct LiftPayload {
    agent_did: String,
    #[serde(default)]
    reason_text: Option<String>,
}

/// Lift a quarantine. Only the agent's controller on chain may; for an agent
/// with neither terms nor a bond, the controller the quarantine records.
pub(super) fn lift(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let p: LiftPayload = serde_json::from_slice(payload).map_err(|e| {
        VmError::InvalidTransaction(format!("Invalid LiftAgentQuarantine payload: {e}"))
    })?;
    let q = read_agent_quarantine(state, &p.agent_did)
        .ok_or_else(|| refuse(format!("{} is not quarantined", p.agent_did)))?;
    if q.revoked {
        return Err(refuse(format!(
            "{} was revoked by its controller; a revocation is not lifted",
            p.agent_did
        )));
    }
    if super::agent_controller_on_chain(state, &p.agent_did)?.is_some() {
        super::authorize_agent_controller(state, from, &p.agent_did)?;
    } else if super::identity_did_of(state, from).as_deref() != Some(q.controller_did.as_str()) {
        return Err(refuse(format!(
            "only {} may lift this quarantine, from the wallet its identity is registered with",
            q.controller_did
        )));
    }
    let key = quarantine_key(&p.agent_did);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
    let changes = vec![StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(Vec::new()),
    )];
    let log_data = serde_json::to_vec(&serde_json::json!({
        "agent_did": p.agent_did,
        "controller_did": q.controller_did,
        "reason_text": p.reason_text,
    }))
    .map_err(|e| VmError::Internal(format!("encode lift log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![AGENT_QUARANTINE_LIFTED_TOPIC.to_vec()],
            log_data,
        )],
    ))
}

#[derive(Debug, Clone, Deserialize)]
struct FlagPayload {
    epoch: u64,
    findings: Vec<tenzro_types::agent_audit::AuditFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingSub {
    validator: String,
    stake: String,
}

/// Gas a flag of `payload` costs, or a refusal when it is malformed.
pub(super) fn flag_gas(payload: &[u8]) -> Result<u64> {
    let p: FlagPayload = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid AgentAuditFlag payload: {e}")))?;
    if p.findings.is_empty() || p.findings.len() > tenzro_types::agent_audit::MAX_FINDINGS {
        return Err(refuse("a flag carries 1 to 256 findings"));
    }
    for finding in &p.findings {
        if let tenzro_types::agent_audit::AuditFinding::TripBridge { evidence_hash, .. } = finding
            && hex::decode(evidence_hash).map_or(true, |h| h.len() != 32)
        {
            return Err(refuse(
                "a bridge trip carries the SHA-256 of its evidence, hex",
            ));
        }
    }
    Ok(GAS_AGENT_AUDIT_FLAG + GAS_AGENT_AUDIT_FINDING * p.findings.len() as u64)
}

/// Record one validator's findings; each that validators holding two thirds
/// of bonded stake have made takes effect: a quarantine is imposed, the
/// bridge circuit breaker trips, and a finding about a node's roots is
/// recorded against it.
pub(super) fn flag(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    use tenzro_types::agent_audit::AuditFinding;
    let p: FlagPayload = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid AgentAuditFlag payload: {e}")))?;
    let current = rewards::read_reward_state(state)?.current_epoch;
    if p.epoch > current || current - p.epoch > AGENT_AUDIT_COMMIT_WINDOW {
        return Err(refuse(format!(
            "findings of epoch {} cannot be flagged in epoch {current}",
            p.epoch
        )));
    }
    let stake = bonded_stake_of(state, from);
    if stake == 0 {
        return Err(refuse("only accounts with bonded stake may flag findings"));
    }
    let me = hex::encode(from);
    let total = total_bonded_stake(state);
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    let mut recorded = 0usize;
    for finding in p.findings {
        let id = finding.id();
        if state
            .get_storage(&SYSTEM_ADDRESS, finding_key(&id).as_bytes())
            .is_some_and(|b| !b.is_empty())
        {
            continue;
        }
        let key = finding_subs_key(&id);
        let mut subs: Vec<FindingSub> = read_json(state, &key).unwrap_or_default();
        if subs.iter().any(|s| s.validator == me) {
            continue;
        }
        subs.push(FindingSub {
            validator: me.clone(),
            stake: stake.to_string(),
        });
        write_json(state, &key, &subs, &mut changes)?;
        recorded += 1;
        // Count each flagger's stake as bonded now, not as it was when it
        // flagged: stake that has since left must not count, and the same
        // stake re-bonded under another account must not count twice.
        let behind = subs.iter().fold(0u128, |acc, s| {
            let now = hex::decode(&s.validator)
                .map(|a| bonded_stake_of(state, &a))
                .unwrap_or(0);
            acc.saturating_add(now)
        });
        if total == 0 || behind.saturating_mul(3) < total.saturating_mul(2) {
            continue;
        }
        let verdict = AgentAuditVerdict {
            finding: finding.clone(),
            epoch: p.epoch,
            stake: behind.to_string(),
            validators: subs.len(),
            at_ms: now_ms,
        };
        write_json(state, &finding_key(&id), &verdict, &mut changes)?;
        match &finding {
            AuditFinding::QuarantineAgent {
                agent_did,
                controller_did,
                evidence_hash,
            } => {
                // The quarantine answers to the agent's controller on
                // chain, whatever controller the finding names.
                let controller_did = super::agent_controller_on_chain(state, agent_did)?
                    .unwrap_or_else(|| controller_did.clone());
                let q = AgentQuarantine {
                    controller_did,
                    by: "validators".into(),
                    reason_code: 0,
                    evidence_hash: Some(evidence_hash.clone()),
                    at_ms: now_ms,
                    revoked: false,
                };
                impose(state, agent_did, &q, &mut changes, &mut logs)?;
                // A violation validators verified costs the agent its whole
                // bond, which goes to the insurance pool.
                super::economy::slash_agent_bond(
                    state,
                    agent_did,
                    10_000,
                    &mut changes,
                    &mut logs,
                )?;
            }
            AuditFinding::TripBridge {
                adapter,
                source_chain,
                evidence_hash,
                reason,
            } => {
                let trip = super::bridge_circuit::BridgeCircuitTrip {
                    adapter: *adapter,
                    source_chain: source_chain.to_ascii_lowercase(),
                    mode: tenzro_types::bridge_route::BridgeRouteMode::Paused,
                    by: super::bridge_circuit::BridgeCircuitAuthority::Validators,
                    reason: reason.clone(),
                    evidence_hash: Some(evidence_hash.clone()),
                    epoch: p.epoch,
                    at_ms: now_ms,
                };
                super::bridge_circuit::trip(state, &trip, &mut changes, &mut logs)?;
            }
            AuditFinding::PolicyViolation { operator_did, .. } => {
                let penalty = super::inference_fault::penalty_due(state, 0);
                let (_, _, bond_log) = super::inference_fault::slash_compute_bond(
                    state,
                    operator_did,
                    None,
                    penalty,
                    &mut changes,
                )?;
                logs.extend(bond_log);
            }
            AuditFinding::MissingCommit { .. }
            | AuditFinding::AttestationInvalid { .. }
            | AuditFinding::ImageChanged { .. } => {}
        }
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![AGENT_AUDIT_FINDING_TOPIC.to_vec()],
            serde_json::to_vec(&serde_json::json!({
                "id": hex::encode(id),
                "finding": finding,
                "epoch": p.epoch,
            }))
            .map_err(|e| VmError::Internal(format!("encode finding log: {e}")))?,
        ));
    }
    if recorded == 0 {
        return Err(refuse(
            "nothing to record: every finding has taken effect or was already made by this validator",
        ));
    }
    Ok((changes, logs))
}

/// Everything an agent was authorised to do stops: its grants on other
/// chains are voided and its undecided settlement plans abort, refunding its
/// wallet. Run on revoke, pause, quarantine and terminate.
pub(super) fn withdraw_authority(
    state: &mut dyn VmState,
    agent_did: &str,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    super::remote_grant::void_all(state, agent_did, now_ms, changes, logs)?;
    super::payment_settlement::plan::abort_agent_plans(state, agent_did, now_ms, changes, logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    /// A root past the audit retention and the commit window is deleted;
    /// the ones an evidence pack may still prove against stay.
    #[test]
    fn roots_past_the_audit_retention_are_deleted() {
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        let keep = kept_audit_epochs(&state).unwrap();
        let committer = [7u8; 32];
        let payload = |epoch: u64| {
            serde_json::to_vec(&serde_json::json!({
                "epoch": epoch,
                "root": hex::encode([1u8; 32]),
                "sessions": 1,
                "entries_ref": "",
            }))
            .unwrap()
        };
        let last = keep + 5;
        for epoch in 0..=last {
            let at = epoch as i64 * 86_400_000 + 1;
            rewards::begin_block(&mut state, epoch, &Address::new([5; 32]), at).unwrap();
            commit(&mut state, &committer, at, &payload(epoch)).unwrap();
        }
        let kept_from = last - keep;
        for epoch in 0..kept_from {
            assert!(
                read_agent_audit(&state, &committer, epoch).is_none(),
                "root {epoch}"
            );
        }
        for epoch in kept_from..=last {
            assert!(
                read_agent_audit(&state, &committer, epoch).is_some(),
                "root {epoch}"
            );
        }
        assert_eq!(last_agent_audit_epoch(&state, &committer), Some(last));
    }
}
