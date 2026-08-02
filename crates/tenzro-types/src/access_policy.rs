//! Access control shared by every served resource — databases and file-storage
//! objects alike.
//!
//! A served resource (a database on the local machine, across a LAN segment, or
//! sharded across the network; a stored object's shards) carries an
//! [`AccessPolicy`] that declares who may read and administer it. Placement
//! changes *where* the data lives, never *who* may reach it — the same policy
//! gates all tiers.
//!
//! This crate is auth-primitive-agnostic: it stores the policy; adjudication is
//! a node-layer concern that links `tenzro-auth` and matches the caller's
//! capability against the policy before touching the engine or the shards.
//!
//! Two layers, composable:
//!
//! 1. **[`AccessPolicy`]** — the default gate for every tier. It names the
//!    authorization model (public, owner-only, an explicit DID allow-list, or a
//!    capability the caller must present) plus the AAP action strings a node
//!    adjudicates against.
//! 2. **[`ConfidentialSeal`]** — an opt-in second layer for network-tier data.
//!    When present the on-holder bytes are ciphertext; the data key is wrapped
//!    once per authorized DID (HPKE, same envelope shape as the training
//!    sealed-shard pipeline). A holder never sees plaintext, so a capability
//!    check is belt-and-braces rather than the only defence. Wrapping and
//!    unwrapping happen in the node/client layer that links the crypto; this
//!    crate only records the envelopes.

use serde::{Deserialize, Serialize};

/// The default AAP action a reader must be authorized for.
pub const DEFAULT_READ_ACTION: &str = "database.query";

/// The default AAP action an administrator (create / drop / grant) must be
/// authorized for.
pub const DEFAULT_WRITE_ACTION: &str = "database.admin";

/// The HPKE suite used to wrap a confidential resource's data key per DID —
/// byte-identical to the training sealed-shard pipeline so a node reuses one
/// unwrap path for both.
pub const WRAP_ALG: &str = "hpke-x25519-hkdf-sha256-aes-256-gcm";

/// Who may read and administer a resource. Enforced identically across the
/// local, LAN-cluster, and network tiers — placement changes *where* the data
/// lives, never *who* may reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessPolicy {
    /// Anyone may read; only the owner may administer. Reads bypass the
    /// capability check. Use for openly-shared reference data.
    Public {
        /// DID that created the resource and may drop / re-policy it.
        owner_did: String,
    },
    /// Only the owner DID may read or administer. The strictest single-holder
    /// policy; no capability grants are consulted.
    OwnerOnly {
        /// The sole DID permitted to read and administer.
        owner_did: String,
    },
    /// The owner plus an explicit allow-list of reader DIDs. Reads are permitted
    /// for any DID in `readers`; administration stays owner-only.
    DidAllowlist {
        /// DID that owns and administers the resource.
        owner_did: String,
        /// DIDs permitted to read, in addition to the owner.
        readers: Vec<String>,
    },
    /// Reads require the caller to present an AAP capability for `read_action`
    /// whose `allowed_resources` names this resource id; administration requires
    /// `write_action`. This is the tier that composes with delegation and
    /// attenuated token exchange — a controller can mint a read-only,
    /// time-bound, single-resource capability for an agent.
    CapabilityRequired {
        /// DID that owns and administers the resource.
        owner_did: String,
        /// AAP action string a reader must be authorized for
        /// (default [`DEFAULT_READ_ACTION`]).
        read_action: String,
        /// AAP action string an administrator must be authorized for
        /// (default [`DEFAULT_WRITE_ACTION`]).
        write_action: String,
    },
}

impl AccessPolicy {
    /// Owner-only policy for `owner_did`.
    pub fn owner_only(owner_did: impl Into<String>) -> Self {
        AccessPolicy::OwnerOnly {
            owner_did: owner_did.into(),
        }
    }

    /// Public-read policy owned by `owner_did`.
    pub fn public(owner_did: impl Into<String>) -> Self {
        AccessPolicy::Public {
            owner_did: owner_did.into(),
        }
    }

    /// Capability-gated policy with the default read/write actions.
    pub fn capability_required(owner_did: impl Into<String>) -> Self {
        AccessPolicy::CapabilityRequired {
            owner_did: owner_did.into(),
            read_action: DEFAULT_READ_ACTION.to_string(),
            write_action: DEFAULT_WRITE_ACTION.to_string(),
        }
    }

    /// The DID that owns and administers the resource under any policy variant.
    pub fn owner_did(&self) -> &str {
        match self {
            AccessPolicy::Public { owner_did }
            | AccessPolicy::OwnerOnly { owner_did }
            | AccessPolicy::DidAllowlist { owner_did, .. }
            | AccessPolicy::CapabilityRequired { owner_did, .. } => owner_did,
        }
    }

    /// Adjudicates a read by `caller_did` where `has_read_capability` reports
    /// whether the caller presented a valid AAP capability for the policy's read
    /// action naming this resource (evaluated by the node layer; always `false`
    /// for tiers that do not consult capabilities).
    ///
    /// Returns `true` if the read is permitted by the policy alone. A
    /// confidential seal, when present, is an additional independent layer —
    /// this method does not consider it.
    pub fn permits_read(&self, caller_did: &str, has_read_capability: bool) -> bool {
        match self {
            AccessPolicy::Public { .. } => true,
            AccessPolicy::OwnerOnly { owner_did } => caller_did == owner_did,
            AccessPolicy::DidAllowlist { owner_did, readers } => {
                caller_did == owner_did || readers.iter().any(|d| d == caller_did)
            }
            AccessPolicy::CapabilityRequired { owner_did, .. } => {
                caller_did == owner_did || has_read_capability
            }
        }
    }

    /// Adjudicates administration (create / drop / re-policy) by `caller_did`.
    /// `has_write_capability` reports whether the caller presented a valid AAP
    /// capability for the policy's write action naming this resource. The owner
    /// always passes; other DIDs pass only under `CapabilityRequired` with a
    /// valid write capability.
    pub fn permits_admin(&self, caller_did: &str, has_write_capability: bool) -> bool {
        if caller_did == self.owner_did() {
            return true;
        }
        matches!(self, AccessPolicy::CapabilityRequired { .. }) && has_write_capability
    }

    /// The read action a caller must be authorized for under a capability
    /// policy, if this policy consults capabilities.
    pub fn read_action(&self) -> Option<&str> {
        match self {
            AccessPolicy::CapabilityRequired { read_action, .. } => Some(read_action),
            _ => None,
        }
    }

    /// The write action a caller must be authorized for under a capability
    /// policy, if this policy consults capabilities.
    pub fn write_action(&self) -> Option<&str> {
        match self {
            AccessPolicy::CapabilityRequired { write_action, .. } => Some(write_action),
            _ => None,
        }
    }
}

/// One authorized DID's wrapped copy of a confidential resource's data key.
/// The key is wrapped to the DID's enclave/public key with [`WRAP_ALG`]; only
/// that holder can unwrap it and decrypt the on-holder ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDataKey {
    /// DID this envelope is wrapped for.
    pub did: String,
    /// The recipient public key the data key was wrapped to (hex).
    pub recipient_pubkey_hex: String,
    /// The HPKE-wrapped data key bytes.
    pub wrapped_key: Vec<u8>,
}

/// Opt-in encryption-at-rest for a network-tier resource. When set, holders
/// store ciphertext and the data key is wrapped once per authorized DID. This
/// crate records the envelopes; the node/client layer performs the wrapping and
/// the AES-256-GCM encrypt/decrypt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSeal {
    /// The wrap suite (always [`WRAP_ALG`] for now — carried explicitly so the
    /// unwrap path is self-describing).
    pub wrap_alg: String,
    /// SHA-256 of the plaintext data key, so a holder can verify an unwrap
    /// produced the right key without exposing it.
    pub data_key_hash: [u8; 32],
    /// One wrapped copy of the data key per authorized DID.
    pub wrapped_keys: Vec<WrappedDataKey>,
}

impl ConfidentialSeal {
    /// A seal with the default wrap suite over `data_key_hash`, granting the
    /// listed wrapped keys.
    pub fn new(data_key_hash: [u8; 32], wrapped_keys: Vec<WrappedDataKey>) -> Self {
        Self {
            wrap_alg: WRAP_ALG.to_string(),
            data_key_hash,
            wrapped_keys,
        }
    }

    /// Whether `did` has a wrapped copy of the data key (and therefore can
    /// decrypt). A caller lacking a wrapped key can still be denied even if the
    /// [`AccessPolicy`] would permit the read — the two layers are independent.
    pub fn grants(&self, did: &str) -> bool {
        self.wrapped_keys.iter().any(|w| w.did == did)
    }

    /// The wrapped envelope for `did`, if any.
    pub fn envelope_for(&self, did: &str) -> Option<&WrappedDataKey> {
        self.wrapped_keys.iter().find(|w| w.did == did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_permits_any_reader_owner_only_admin() {
        let p = AccessPolicy::public("did:tenzro:human:alice");
        assert!(p.permits_read("did:tenzro:machine:bob", false));
        assert!(p.permits_admin("did:tenzro:human:alice", false));
        assert!(!p.permits_admin("did:tenzro:machine:bob", false));
    }

    #[test]
    fn owner_only_gates_both() {
        let p = AccessPolicy::owner_only("did:tenzro:human:alice");
        assert!(p.permits_read("did:tenzro:human:alice", false));
        assert!(!p.permits_read("did:tenzro:machine:bob", true)); // capability ignored
        assert!(p.permits_admin("did:tenzro:human:alice", false));
        assert!(!p.permits_admin("did:tenzro:machine:bob", true));
    }

    #[test]
    fn allowlist_permits_listed_readers_only() {
        let p = AccessPolicy::DidAllowlist {
            owner_did: "did:tenzro:human:alice".into(),
            readers: vec!["did:tenzro:machine:bob".into()],
        };
        assert!(p.permits_read("did:tenzro:machine:bob", false));
        assert!(!p.permits_read("did:tenzro:machine:carol", false));
        assert!(!p.permits_admin("did:tenzro:machine:bob", true));
    }

    #[test]
    fn capability_required_consults_capability() {
        let p = AccessPolicy::capability_required("did:tenzro:human:alice");
        assert!(!p.permits_read("did:tenzro:machine:bob", false));
        assert!(p.permits_read("did:tenzro:machine:bob", true));
        assert!(p.permits_admin("did:tenzro:machine:bob", true));
        assert!(!p.permits_admin("did:tenzro:machine:bob", false));
        assert_eq!(p.read_action(), Some(DEFAULT_READ_ACTION));
        assert_eq!(p.write_action(), Some(DEFAULT_WRITE_ACTION));
    }

    #[test]
    fn confidential_seal_grants_only_wrapped_dids() {
        let seal = ConfidentialSeal::new(
            [7u8; 32],
            vec![WrappedDataKey {
                did: "did:tenzro:machine:bob".into(),
                recipient_pubkey_hex: "ab".repeat(32),
                wrapped_key: vec![1, 2, 3],
            }],
        );
        assert!(seal.grants("did:tenzro:machine:bob"));
        assert!(!seal.grants("did:tenzro:machine:carol"));
        assert_eq!(seal.wrap_alg, WRAP_ALG);
        assert!(seal.envelope_for("did:tenzro:machine:bob").is_some());
    }
}
