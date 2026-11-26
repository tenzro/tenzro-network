//! A root's revocation that names who takes over its agents' funds.
//!
//! A root revoked with `RevokeIdentity` takes its delegated agents with it
//! for good, and what their wallets hold stays there: only an agent's
//! controller can reclaim it, and a revoked root signs nothing. An
//! `IdentitySuccessionOp`, carried by a `NativeCall` under
//! [`crate::SELECTOR_IDENTITY_SUCCESSION`], is the same revocation with a
//! successor: the root is revoked, its agents are quarantined rather than
//! revoked, and the successor alone may reclaim what
//! each agent's wallet holds. The successor cannot make an agent act: an
//! agent's DID is derived under the root that delegated it, so a new owner
//! delegates a new agent and funds it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tenzro_types::identity::{MAX_REVOCATION_DID_LEN, MAX_REVOCATION_REASON_LEN};

/// The custody operation a root signs to revoke itself in favour of a
/// successor.
pub const OP_REVOKE_IDENTITY_TO: &[u8] = b"revoke_identity_to";

/// Reason code of the quarantine an agent enters when its root is revoked in
/// favour of a successor.
pub const QUARANTINE_ROOT_SUCCEEDED: u16 = 300;

const TARGET_DOMAIN: &[u8] = b"tenzro/identity-succession/v1";

/// A root revoked on its own authority in favour of `successor_did`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySuccessionOp {
    /// The root being revoked. It approves its own succession.
    pub did: String,
    /// Why, recorded with the revocation. The approval covers it.
    pub reason: String,
    /// The root that may reclaim what the revoked root's agents hold.
    pub successor_did: String,
    /// The root's approval of [`Self::target`] under
    /// [`OP_REVOKE_IDENTITY_TO`].
    pub approval: tenzro_types::agent_terms::AgentTermsApproval,
}

impl IdentitySuccessionOp {
    /// What the approval covers:
    /// `SHA-256(domain ‖ did ‖ reason ‖ successor)`, each behind a 4-byte
    /// big-endian length.
    pub fn target(&self) -> [u8; 32] {
        let mut out = TARGET_DOMAIN.to_vec();
        for f in [&self.did, &self.reason, &self.successor_did] {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(f.as_bytes());
        }
        Sha256::digest(&out).into()
    }

    /// Refuse a succession no root could approve.
    pub fn validate(&self) -> Result<(), &'static str> {
        for did in [&self.did, &self.successor_did] {
            if did.is_empty() || did.len() > MAX_REVOCATION_DID_LEN || !did.starts_with("did:") {
                return Err("a succession names a DID and its successor, each at most 256 bytes");
            }
        }
        if self.did == self.successor_did {
            return Err("an identity does not succeed itself");
        }
        if self.reason.len() > MAX_REVOCATION_REASON_LEN {
            return Err("a revocation reason is at most 512 bytes");
        }
        self.approval.check_bounds()
    }
}

/// The system storage slot naming the successor that may reclaim what
/// `agent_did`'s wallet holds.
pub fn agent_successor_slot(agent_did: &str) -> String {
    format!("agent_successor:{agent_did}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::agent_terms::AgentTermsApproval;

    fn op() -> IdentitySuccessionOp {
        IdentitySuccessionOp {
            did: "did:tenzro:human:aa".into(),
            reason: "retiring".into(),
            successor_did: "did:tenzro:human:bb".into(),
            approval: AgentTermsApproval {
                account: vec![1; 32],
                nonce: [2; 16],
                root_public_key: vec![3; 64],
                signature: CompositeSignature::classical(ClassicalProof::Raw {
                    signature: vec![4; 64],
                }),
            },
        }
    }

    #[test]
    fn the_approval_covers_the_successor() {
        let base = op();
        let mut other = op();
        other.successor_did = "did:tenzro:human:cc".into();
        assert_ne!(base.target(), other.target());
        let mut reason = op();
        reason.reason = "something else".into();
        assert_ne!(base.target(), reason.target());
        // Fields do not trade bytes across their boundaries.
        let mut shifted = op();
        shifted.reason = "retiringd".into();
        shifted.successor_did = "id:tenzro:human:bb".into();
        assert_ne!(base.target(), shifted.target());
    }

    #[test]
    fn a_succession_names_another_identity_and_survives_both_encodings() {
        let op = op();
        op.validate().unwrap();
        let mut own = op.clone();
        own.successor_did = own.did.clone();
        assert!(own.validate().is_err());
        let mut none = op.clone();
        none.successor_did.clear();
        assert!(none.validate().is_err());
        let json: IdentitySuccessionOp =
            serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
        assert_eq!(json, op);
        let bin: IdentitySuccessionOp =
            bincode::deserialize(&bincode::serialize(&op).unwrap()).unwrap();
        assert_eq!(bin, op);
    }
}
