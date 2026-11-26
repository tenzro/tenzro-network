//! Governance's approval of RPC providers.
//!
//! A bridge route names, for each verifier, the RPC provider it reads the
//! external chain through. Until `feature.rpc_provider_approval` is live any
//! label is accepted, as before. From that epoch a seat goes only to a
//! verifier reading through an RPC provider governance has approved and not revoked, one proposal at a
//! time ([`crate::governance::ProposalAction::ApproveRpcProvider`] and
//! [`crate::governance::ProposalAction::RevokeRpcProvider`]).
//!
//! The approval list is chain state, not a list in the code. It bites where
//! a committee is drawn (`bridge_committee`): a verifier whose bond names an
//! RPC provider that is not approved is not a candidate for a seat. A
//! revocation therefore takes effect at the route's next draw; the seats
//! already drawn stay until then.

use serde::{Deserialize, Serialize};

use super::SYSTEM_ADDRESS;
use super::funding::{read_json, refuse, write_json};
use crate::error::Result;
use crate::traits::VmState;
use crate::types::{Log, StateChange};

/// Gate: first epoch from which a bridge route may name only RPC providers
/// governance has approved.
pub const RPC_PROVIDER_APPROVAL_GATE: &str = "feature.rpc_provider_approval.activation_epoch";

/// Longest provider label, in bytes.
pub const MAX_PROVIDER_LABEL_LEN: usize = 64;

/// Topic of the log an approval emits.
pub const RPC_PROVIDER_APPROVED_TOPIC: &[u8] = b"RpcProviderApproved";
/// Topic of the log a revocation emits.
pub const RPC_PROVIDER_REVOKED_TOPIC: &[u8] = b"RpcProviderRevoked";

/// What governance recorded when it approved an RPC provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcProviderApproval {
    /// Block time of the approval.
    pub approved_ms: i64,
    /// The proposal that approved it.
    pub proposal_id: String,
    /// Whether a later proposal revoked it.
    pub revoked: bool,
}

fn key(label: &str) -> String {
    format!("approved_rpc_provider:{label}")
}

/// The label as stored: surrounding white space is not part of it, the same
/// as a route member's `rpc_provider`.
pub fn normalized(label: &str) -> &str {
    label.trim()
}

/// Refuses a label that is empty or longer than [`MAX_PROVIDER_LABEL_LEN`].
pub fn check_label(label: &str) -> Result<()> {
    let l = normalized(label);
    if l.is_empty() {
        return Err(refuse("an RPC provider label is empty"));
    }
    if l.len() > MAX_PROVIDER_LABEL_LEN {
        return Err(refuse(format!(
            "an RPC provider label is {} bytes, over the limit of {MAX_PROVIDER_LABEL_LEN}",
            l.len()
        )));
    }
    Ok(())
}

/// The recorded approval of `label`, revoked or not.
pub fn approval(state: &dyn VmState, label: &str) -> Option<RpcProviderApproval> {
    read_json(state, &key(normalized(label)))
}

/// Whether governance has approved `label` and not revoked it.
pub fn is_approved(state: &dyn VmState, label: &str) -> bool {
    approval(state, label).is_some_and(|a| !a.revoked)
}

/// Submission check for a revocation: the provider must be approved now.
pub fn check_revoke(state: &dyn VmState, label: &str) -> Result<()> {
    check_label(label)?;
    match approval(state, label) {
        Some(a) if !a.revoked => Ok(()),
        Some(_) => Err(refuse(format!(
            "RPC provider {} is already revoked",
            normalized(label)
        ))),
        None => Err(refuse(format!(
            "RPC provider {} was never approved",
            normalized(label)
        ))),
    }
}

/// Enact an approval, or renew a revoked one.
pub(super) fn approve(
    state: &mut dyn VmState,
    proposal_id: &str,
    label: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    check_label(label)?;
    let label = normalized(label);
    let record = RpcProviderApproval {
        approved_ms: now_ms,
        proposal_id: proposal_id.to_string(),
        revoked: false,
    };
    write_json(state, &key(label), &record, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![RPC_PROVIDER_APPROVED_TOPIC.to_vec()],
        label.as_bytes().to_vec(),
    ));
    Ok(())
}

/// Enact a revocation.
pub(super) fn revoke(
    state: &mut dyn VmState,
    label: &str,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    check_revoke(state, label)?;
    let label = normalized(label);
    let mut record = approval(state, label).ok_or_else(|| refuse("RPC provider not approved"))?;
    record.revoked = true;
    write_json(state, &key(label), &record, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![RPC_PROVIDER_REVOKED_TOPIC.to_vec()],
        label.as_bytes().to_vec(),
    ));
    Ok(())
}

/// Approve `label` with no proposal, for tests that draw committees.
#[cfg(test)]
pub(crate) fn approve_for_test(state: &mut dyn VmState, label: &str) {
    approve(state, "test", label, 1, &mut Vec::new(), &mut Vec::new()).unwrap();
}

/// Whether a committee draw is limited to approved RPC providers.
pub fn gate_live(state: &dyn VmState) -> bool {
    crate::feature_gate::is_live_now(state, RPC_PROVIDER_APPROVAL_GATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::set_governed_param_for_test;
    use crate::state_adapter::StateAdapter;

    fn approve_at(state: &mut StateAdapter, label: &str, id: &str) {
        approve(state, id, label, 1_000, &mut Vec::new(), &mut Vec::new()).unwrap();
    }

    #[test]
    fn a_label_is_kept_without_its_surrounding_white_space() {
        let mut state = StateAdapter::new();
        approve_at(&mut state, "  alchemy ", "p1");
        assert!(is_approved(&state, "alchemy"));
        assert!(is_approved(&state, " alchemy"));
        assert!(!is_approved(&state, "infura"));
    }

    #[test]
    fn an_empty_or_over_long_label_is_refused() {
        let mut state = StateAdapter::new();
        let empty = approve(&mut state, "p", "  ", 1, &mut Vec::new(), &mut Vec::new());
        assert!(empty.is_err());
        let long = "x".repeat(MAX_PROVIDER_LABEL_LEN + 1);
        assert!(check_label(&long).is_err());
        assert!(check_label(&"x".repeat(MAX_PROVIDER_LABEL_LEN)).is_ok());
    }

    #[test]
    fn a_revoke_needs_an_approval_that_stands() {
        let mut state = StateAdapter::new();
        assert!(check_revoke(&state, "alchemy").is_err(), "never approved");
        approve_at(&mut state, "alchemy", "p1");
        check_revoke(&state, "alchemy").unwrap();
        revoke(&mut state, "alchemy", &mut Vec::new(), &mut Vec::new()).unwrap();
        assert!(!is_approved(&state, "alchemy"));
        assert!(check_revoke(&state, "alchemy").is_err(), "already revoked");
        assert!(approval(&state, "alchemy").unwrap().revoked);
    }

    #[test]
    fn approving_again_undoes_a_revoke_and_records_the_new_proposal() {
        let mut state = StateAdapter::new();
        approve_at(&mut state, "alchemy", "p1");
        revoke(&mut state, "alchemy", &mut Vec::new(), &mut Vec::new()).unwrap();
        approve_at(&mut state, "alchemy", "p2");
        let a = approval(&state, "alchemy").unwrap();
        assert!(!a.revoked);
        assert_eq!(a.proposal_id, "p2");
    }

    #[test]
    fn approve_and_revoke_each_record_one_change_and_one_log() {
        let mut state = StateAdapter::new();
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        approve(&mut state, "p1", "alchemy", 7, &mut changes, &mut logs).unwrap();
        assert_eq!((changes.len(), logs.len()), (1, 1));
        revoke(&mut state, "alchemy", &mut changes, &mut logs).unwrap();
        assert_eq!((changes.len(), logs.len()), (2, 2));
        assert_eq!(logs[1].data, b"alchemy".to_vec());
    }

    #[test]
    fn the_gate_is_dormant_until_governance_sets_an_epoch() {
        let mut state = StateAdapter::new();
        assert!(!gate_live(&state), "NEVER at genesis");
        set_governed_param_for_test(&mut state, RPC_PROVIDER_APPROVAL_GATE, 0);
        assert!(gate_live(&state));
    }
}
