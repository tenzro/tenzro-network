//! Service entries of DID documents, held in consensus state.
//!
//! A DID document's `service` list comes from chain state, so every node
//! returns the same document for a DID. Each change is an
//! [`IdentityServiceOp`] in an `IdentityServices` transaction, approved by
//! the DID's root through the one root-approval check every root-signed
//! operation uses: for a human, a passkey its keystore links (any linked
//! device, as its policy allows); for an autonomous machine, the hardware key
//! its registration binds. The approval signs [`IdentityServiceOp::target`],
//! which names the DID, the version of its service list being changed and
//! the change, so an approval applies once.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_terms::AgentTermsApproval;

/// The custody operation a root signs to change its DID's services.
pub const OP_DID_SERVICE: &[u8] = b"did_service";

/// Most service entries one DID publishes.
pub const MAX_DID_SERVICES: usize = 16;

/// Longest service id fragment and service type.
pub const MAX_SERVICE_FIELD_LEN: usize = 64;

/// Longest DID a change names.
pub const MAX_DID_LEN: usize = 256;

const TARGET_DOMAIN: &[u8] = b"tenzro/did-service/v1";

/// One service entry of a DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidServiceEntry {
    /// The fragment of its id: the document lists it as `<did>#<id>`.
    /// Letters, digits, `-` and `_`.
    pub id: String,
    /// Its type, for example `LinkedDomains` or `MessagingService`.
    pub service_type: String,
    /// Where it is served: an http, https, ws or wss URL.
    pub endpoint: String,
}

impl DidServiceEntry {
    /// Refuse an entry a DID document cannot carry.
    pub fn check(&self) -> Result<(), &'static str> {
        if !fragment(&self.id) {
            return Err("a service id is 1 to 64 letters, digits, '-' or '_'");
        }
        if !fragment(&self.service_type) {
            return Err("a service type is 1 to 64 letters, digits, '-' or '_'");
        }
        crate::validation::validate_service_endpoint_url(&self.endpoint)
            .map_err(|_| "a service endpoint is an http, https, ws or wss URL")
    }
}

fn fragment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SERVICE_FIELD_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A change to a DID's service list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidServiceChange {
    /// Publish `service`, replacing an entry with the same id.
    Set {
        /// The entry.
        service: DidServiceEntry,
    },
    /// Remove the entry with this id fragment.
    Remove {
        /// Its id fragment.
        id: String,
    },
}

impl DidServiceChange {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Set { service } => {
                out.push(1);
                field(out, service.id.as_bytes());
                field(out, service.service_type.as_bytes());
                field(out, service.endpoint.as_bytes());
            }
            Self::Remove { id } => {
                out.push(2);
                field(out, id.as_bytes());
            }
        }
    }
}

/// A change to a DID's services and its root's approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityServiceOp {
    /// The DID whose document changes.
    pub did: String,
    /// The version of its service list this change applies to (0 before the
    /// first). A change applies only to the version it names.
    pub version: u64,
    /// The change.
    pub change: DidServiceChange,
    /// The DID root's approval of [`Self::target`] under [`OP_DID_SERVICE`].
    pub approval: AgentTermsApproval,
}

impl IdentityServiceOp {
    /// What the root's approval covers:
    /// `SHA-256(domain ‖ did ‖ version ‖ change)`.
    pub fn target(&self) -> [u8; 32] {
        service_change_target(&self.did, self.version, &self.change)
    }

    /// Refuse a change no DID root could approve.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.did.is_empty() || self.did.len() > MAX_DID_LEN || !self.did.starts_with("did:") {
            return Err("a service change names a DID");
        }
        match &self.change {
            DidServiceChange::Set { service } => service.check()?,
            DidServiceChange::Remove { id } => {
                if !fragment(id) {
                    return Err("a service id is 1 to 64 letters, digits, '-' or '_'");
                }
            }
        }
        self.approval.check_bounds()
    }
}

/// What a root signs to make `change` to `did`'s services at `version`.
pub fn service_change_target(did: &str, version: u64, change: &DidServiceChange) -> [u8; 32] {
    let mut out = Vec::new();
    out.extend_from_slice(TARGET_DOMAIN);
    field(&mut out, did.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    change.encode(&mut out);
    Sha256::digest(&out).into()
}

/// A DID's service list as consensus state holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidServices {
    /// One more per change; 0 before the first.
    pub version: u64,
    /// The entries, ordered by id.
    pub services: Vec<DidServiceEntry>,
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(endpoint: &str) -> DidServiceEntry {
        DidServiceEntry {
            id: "inbox".into(),
            service_type: "MessagingService".into(),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn the_target_binds_the_did_version_and_change() {
        let set = DidServiceChange::Set {
            service: entry("https://a.example/inbox"),
        };
        let t = service_change_target("did:tenzro:human:aa", 0, &set);
        assert_ne!(t, service_change_target("did:tenzro:human:bb", 0, &set));
        assert_ne!(t, service_change_target("did:tenzro:human:aa", 1, &set));
        assert_ne!(
            t,
            service_change_target(
                "did:tenzro:human:aa",
                0,
                &DidServiceChange::Set {
                    service: entry("https://b.example/inbox")
                }
            )
        );
        assert_ne!(
            t,
            service_change_target(
                "did:tenzro:human:aa",
                0,
                &DidServiceChange::Remove { id: "inbox".into() }
            )
        );
    }

    #[test]
    fn entries_a_document_cannot_carry_are_refused() {
        assert!(entry("https://a.example/inbox").check().is_ok());
        assert!(entry("javascript:alert(1)").check().is_err());
        assert!(
            DidServiceEntry {
                id: "a b".into(),
                ..entry("https://a.example")
            }
            .check()
            .is_err()
        );
        assert!(
            DidServiceEntry {
                service_type: String::new(),
                ..entry("https://a.example")
            }
            .check()
            .is_err()
        );
    }
}
