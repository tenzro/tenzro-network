//! Participants in a workflow — DIDs with roles and optional bond requirements.

use serde::{Deserialize, Serialize};

/// A participant DID and the roles it plays in the workflow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub did: String,
    pub roles: Vec<ParticipantRole>,
    /// Populated when workflow is mirrored to Canton — `did:tenzro:human:..` →
    /// `tenzro::1220abcd…` party hint registered with the synchronizer.
    pub canton_party_hint: Option<String>,
    /// Unix seconds when this participant was added to the workflow.
    pub joined_at: i64,
    /// Optional bond requirement (wei) — checked at signature collection.
    pub bond_required: Option<u128>,
}

impl Participant {
    pub fn new(did: impl Into<String>, roles: Vec<ParticipantRole>) -> Self {
        Self {
            did: did.into(),
            roles,
            canton_party_hint: None,
            joined_at: 0,
            bond_required: None,
        }
    }

    pub fn has_role(&self, role: &ParticipantRole) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Role a participant plays inside a workflow.
///
/// Multiple roles may be held simultaneously (e.g. a treasurer can also be a
/// counterparty). Roles drive routing for approval gates and visibility for
/// privacy domains.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParticipantRole {
    Initiator,
    Counterparty,
    Approver,
    /// Read-only observer — receives unredacted receipts via privacy-domain
    /// envelopes.
    Auditor,
    /// Controls fee splits + escrow release.
    Treasurer,
    /// Holds collateral.
    Custodian,
    /// Attests external state (e.g. delivery confirmation).
    OracleProvider,
    Custom(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_matching() {
        let p = Participant::new("did:tenzro:human:alice:1", vec![
            ParticipantRole::Initiator,
            ParticipantRole::Treasurer,
        ]);
        assert!(p.has_role(&ParticipantRole::Initiator));
        assert!(p.has_role(&ParticipantRole::Treasurer));
        assert!(!p.has_role(&ParticipantRole::Auditor));
    }

    #[test]
    fn custom_role_distinct() {
        let r1 = ParticipantRole::Custom("buyer".into());
        let r2 = ParticipantRole::Custom("seller".into());
        let r3 = ParticipantRole::Custom("buyer".into());
        assert_ne!(r1, r2);
        assert_eq!(r1, r3);
    }
}
