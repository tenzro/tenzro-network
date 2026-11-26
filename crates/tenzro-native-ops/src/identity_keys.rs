//! An identity's key history in consensus state.
//!
//! An identity signs what it issues (delegations, batch roots, receipts)
//! with an Ed25519 and an ML-DSA-65 key. Those keys change: a machine derives
//! new ones when its software changes, and an identity replaces a key it no
//! longer trusts. The chain records each key with a rising version and the
//! block time it took effect, so a verifier judges a record by the key in
//! force when the record was made.
//!
//! Three changes exist, each approved by the identity's root and carried by
//! a `NativeCall` under [`crate::SELECTOR_IDENTITY_KEYS`] ([`IdentityKeyOp`]):
//!
//! * [`IdentityKeyChange::Update`] records the next key. It may commit to the
//!   key after it ([`tenzro_crypto::identity_key::next_key_commitment`]);
//!   the following update must then reveal exactly that key. A commitment
//!   is a hash, so it holds when the key in force is broken.
//! * [`IdentityKeyChange::Compromised`] declares a recorded key compromised
//!   from the block that carries the declaration.
//! * [`IdentityKeyChange::RevokeDelegation`] revokes one delegation the
//!   identity issued, named by its identifier.
//!
//! Every change is one [`IdentityKeyEvent`], the body of the log it emits.
//!
//! The chain also keeps one [`IdentityHead`] per identity. Each log about an
//! identity (its registration, a change to its passkeys including a
//! recovery, its revocation, a change to its keys) advances the head by
//! [`identity_event_digest`], which covers the log and the head before it.
//! The logs of one identity therefore form a chain, and one proof of the
//! head in state fixes all of them in order.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tenzro_types::agent_audit::{hex_bytes, hex32};

use crate::hex_array32_opt;

/// The custody operation a root signs to change an identity's keys.
pub const OP_IDENTITY_KEYS: &[u8] = b"identity_keys";

/// Length of an ML-DSA-65 public key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Longest DID a key change names.
pub const MAX_IDENTITY_KEY_DID_LEN: usize = 256;

/// Topic of the log a key update emits.
pub const IDENTITY_KEY_UPDATED_TOPIC: &[u8] = b"IdentityKeyUpdated";
/// Topic of the log a compromise declaration emits.
pub const IDENTITY_KEY_COMPROMISED_TOPIC: &[u8] = b"IdentityKeyCompromised";
/// Topic of the log a delegation revocation emits.
pub const IDENTITY_DELEGATION_REVOKED_TOPIC: &[u8] = b"IdentityDelegationRevoked";

const TARGET_DOMAIN: &[u8] = b"tenzro/identity-keys/change/v1";
const EVENT_DOMAIN: &[u8] = b"tenzro/identity/event/v1";

/// One identity key and when it was in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKeyEpoch {
    /// The key's version: 1 for the first, rising by one.
    pub version: u64,
    /// The Ed25519 public key.
    #[serde(with = "hex32")]
    pub ed25519: [u8; 32],
    /// The ML-DSA-65 public key.
    #[serde(with = "hex_bytes")]
    pub ml_dsa: Vec<u8>,
    /// Block time (ms) the chain recorded the key.
    pub effective_from_ms: u64,
    /// Block time (ms) the identity declared the key compromised.
    pub compromised_from_ms: Option<u64>,
    /// [`tenzro_crypto::identity_key::next_key_commitment`] of the key that
    /// must replace this one.
    #[serde(with = "hex_array32_opt")]
    pub next_commitment: Option<[u8; 32]>,
}

/// An identity's keys, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IdentityKeyHistory {
    /// The keys, versions rising by one from 1.
    pub epochs: Vec<IdentityKeyEpoch>,
}

/// The head of an identity's chain of logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IdentityHead {
    /// Logs recorded for the identity so far.
    pub sequence: u64,
    /// [`identity_event_digest`] of the latest log; zero before the first.
    #[serde(with = "hex32")]
    pub head: [u8; 32],
    /// The head before the latest log; zero for the first.
    #[serde(with = "hex32")]
    pub previous: [u8; 32],
}

impl IdentityHead {
    /// The head after the log with `topic` and `data` about `did`.
    pub fn advanced(&self, did: &str, topic: &[u8], data: &[u8]) -> Self {
        let sequence = self.sequence + 1;
        Self {
            sequence,
            head: identity_event_digest(did, sequence, &self.head, topic, data),
            previous: self.head,
        }
    }
}

/// The digest of the `sequence`-th log about `did`, from 1:
/// `SHA-256(domain ‖ len(did) ‖ did ‖ sequence ‖ previous ‖ len(topic) ‖
/// topic ‖ SHA-256(data))`, where `previous` is the digest of the log before
/// it (zero for the first), `topic` the log's first topic and `data` its
/// body. Lengths are 4 bytes and the sequence 8 bytes, big-endian.
pub fn identity_event_digest(
    did: &str,
    sequence: u64,
    previous: &[u8; 32],
    topic: &[u8],
    data: &[u8],
) -> [u8; 32] {
    let mut out = EVENT_DOMAIN.to_vec();
    put_did(&mut out, did);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(previous);
    out.extend_from_slice(&(topic.len() as u32).to_be_bytes());
    out.extend_from_slice(topic);
    out.extend_from_slice(&Sha256::digest(data));
    Sha256::digest(&out).into()
}

/// One change to an identity's keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKeyChange {
    /// Record the identity's next key.
    Update {
        /// The version the key takes: one above the latest, or 1.
        version: u64,
        /// The Ed25519 public key.
        #[serde(with = "hex32")]
        ed25519: [u8; 32],
        /// The ML-DSA-65 public key.
        #[serde(with = "hex_bytes")]
        ml_dsa: Vec<u8>,
        /// [`tenzro_crypto::identity_key::next_key_commitment`] of the key that
        /// will replace this one.
        #[serde(with = "hex_array32_opt")]
        next_commitment: Option<[u8; 32]>,
    },
    /// Declare the key of `version` compromised from this block on.
    Compromised {
        /// The key's version.
        version: u64,
    },
    /// Revoke a delegation the identity issued.
    RevokeDelegation {
        /// The delegation's identifier.
        #[serde(with = "hex32")]
        delegation_id: [u8; 32],
    },
}

impl IdentityKeyChange {
    /// The topic of the log this change emits.
    pub fn topic(&self) -> &'static [u8] {
        match self {
            Self::Update { .. } => IDENTITY_KEY_UPDATED_TOPIC,
            Self::Compromised { .. } => IDENTITY_KEY_COMPROMISED_TOPIC,
            Self::RevokeDelegation { .. } => IDENTITY_DELEGATION_REVOKED_TOPIC,
        }
    }

    /// The change as bytes: a tag, then its fields, variable ones behind a
    /// 4-byte big-endian length.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Update {
                version,
                ed25519,
                ml_dsa,
                next_commitment,
            } => {
                out.push(1);
                out.extend_from_slice(&version.to_be_bytes());
                out.extend_from_slice(ed25519);
                out.extend_from_slice(&(ml_dsa.len() as u32).to_be_bytes());
                out.extend_from_slice(ml_dsa);
                match next_commitment {
                    Some(c) => {
                        out.push(1);
                        out.extend_from_slice(c);
                    }
                    None => out.push(0),
                }
            }
            Self::Compromised { version } => {
                out.push(2);
                out.extend_from_slice(&version.to_be_bytes());
            }
            Self::RevokeDelegation { delegation_id } => {
                out.push(3);
                out.extend_from_slice(delegation_id);
            }
        }
    }
}

fn put_did(out: &mut Vec<u8>, did: &str) {
    out.extend_from_slice(&(did.len() as u32).to_be_bytes());
    out.extend_from_slice(did.as_bytes());
}

/// A change to an identity's keys approved by the identity's root, carried
/// by a `NativeCall` and checked by every validator.
///
/// The approver is the identity itself when it is a root (a human, whose
/// passkey signs, or an autonomous machine, whose hardware key signs), the
/// controller chain state names for a delegated agent, or the root a
/// delegated machine's DID is derived under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKeyOp {
    /// The identity whose keys change.
    pub did: String,
    /// The change.
    pub change: IdentityKeyChange,
    /// The root that approves.
    pub approver_did: String,
    /// The approver's approval of [`Self::target`] under
    /// [`OP_IDENTITY_KEYS`].
    pub approval: tenzro_types::agent_terms::AgentTermsApproval,
}

impl IdentityKeyOp {
    /// What the approval covers: `SHA-256(domain ‖ did ‖ change)`.
    pub fn target(&self) -> [u8; 32] {
        let mut out = TARGET_DOMAIN.to_vec();
        put_did(&mut out, &self.did);
        self.change.encode(&mut out);
        Sha256::digest(&out).into()
    }

    /// Refuse a change no root could approve.
    pub fn validate(&self) -> Result<(), &'static str> {
        for did in [&self.did, &self.approver_did] {
            if did.is_empty() || did.len() > MAX_IDENTITY_KEY_DID_LEN || !did.starts_with("did:") {
                return Err("a key change names a DID and its approver, each at most 256 bytes");
            }
        }
        if let IdentityKeyChange::Update { ml_dsa, .. } = &self.change
            && ml_dsa.len() != ML_DSA_65_PUBLIC_KEY_LEN
        {
            return Err("an identity's ML-DSA-65 public key is 1952 bytes");
        }
        self.approval.check_bounds()
    }
}

/// One recorded change, the body of the log it emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKeyEvent {
    /// The identity.
    pub did: String,
    /// The change.
    pub change: IdentityKeyChange,
    /// The root whose approval the chain verified.
    pub approver_did: String,
    /// Block time (ms) the change took effect.
    pub at_ms: u64,
}

/// The system storage slot of `did`'s [`IdentityHead`].
pub fn identity_head_slot(did: &str) -> String {
    format!("identity_head:{did}")
}

/// The system storage slot holding the block time (ms, 8 bytes big-endian)
/// `did`'s account last completed a recovery.
pub fn identity_recovered_slot(did: &str) -> String {
    format!("identity_recovered:{did}")
}

/// The system storage slot of `did`'s key history.
pub fn identity_keys_slot(did: &str) -> String {
    format!("identity_keys:{did}")
}

/// The system storage slot recording when `did` revoked `delegation_id`.
pub fn delegation_revoked_slot(did: &str, delegation_id: &[u8; 32]) -> String {
    format!(
        "identity_delegation_revoked:{did}:{}",
        hex::encode(delegation_id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::agent_terms::AgentTermsApproval;

    fn op(change: IdentityKeyChange) -> IdentityKeyOp {
        IdentityKeyOp {
            did: "did:tenzro:machine:aa".to_string(),
            change,
            approver_did: "did:tenzro:machine:aa".to_string(),
            approval: AgentTermsApproval {
                account: vec![1; 20],
                nonce: [2; 16],
                root_public_key: vec![3; 64],
                signature: CompositeSignature::classical(ClassicalProof::Raw {
                    signature: vec![4; 64],
                }),
            },
        }
    }

    fn update(version: u64, next: Option<[u8; 32]>) -> IdentityKeyChange {
        IdentityKeyChange::Update {
            version,
            ed25519: [5; 32],
            ml_dsa: vec![6; ML_DSA_65_PUBLIC_KEY_LEN],
            next_commitment: next,
        }
    }

    #[test]
    fn every_field_of_a_change_moves_its_target() {
        let base = op(update(1, None)).target();
        assert_ne!(base, op(update(2, None)).target());
        assert_ne!(base, op(update(1, Some([0; 32]))).target());
        assert_ne!(
            op(IdentityKeyChange::Compromised { version: 1 }).target(),
            op(IdentityKeyChange::Compromised { version: 2 }).target()
        );
        assert_ne!(
            op(IdentityKeyChange::RevokeDelegation {
                delegation_id: [1; 32]
            })
            .target(),
            op(IdentityKeyChange::RevokeDelegation {
                delegation_id: [2; 32]
            })
            .target()
        );
        let mut other = op(update(1, None));
        other.did = "did:tenzro:machine:ab".to_string();
        assert_ne!(base, other.target());
    }

    #[test]
    fn a_change_survives_json_and_bincode() {
        for change in [
            update(1, None),
            update(2, Some([7; 32])),
            IdentityKeyChange::Compromised { version: 1 },
            IdentityKeyChange::RevokeDelegation {
                delegation_id: [8; 32],
            },
        ] {
            let op = op(change);
            let json: IdentityKeyOp =
                serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
            assert_eq!(json, op);
            let bin: IdentityKeyOp =
                bincode::deserialize(&bincode::serialize(&op).unwrap()).unwrap();
            assert_eq!(bin, op);
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let mut bad = op(update(1, None));
        if let IdentityKeyChange::Update { ml_dsa, .. } = &mut bad.change {
            ml_dsa.pop();
        }
        assert!(bad.validate().is_err());
        assert!(op(update(1, None)).validate().is_ok());
    }

    #[test]
    fn a_head_binds_every_log_and_its_order() {
        let did = "did:tenzro:machine:aa";
        let first = IdentityHead::default().advanced(did, b"A", b"one");
        assert_eq!(first.sequence, 1);
        assert_eq!(first.previous, [0; 32]);
        let second = first.advanced(did, b"B", b"two");
        assert_eq!(second.sequence, 2);
        assert_eq!(second.previous, first.head);
        // Another order, another topic, another body or another identity
        // ends at another head.
        let swapped = IdentityHead::default()
            .advanced(did, b"B", b"two")
            .advanced(did, b"A", b"one");
        assert_ne!(second.head, swapped.head);
        assert_ne!(
            first.head,
            IdentityHead::default().advanced(did, b"B", b"one").head
        );
        assert_ne!(
            first.head,
            IdentityHead::default().advanced(did, b"A", b"two").head
        );
        assert_ne!(
            first.head,
            IdentityHead::default()
                .advanced("did:tenzro:machine:ab", b"A", b"one")
                .head
        );
        // A topic and a body do not trade bytes.
        assert_ne!(
            IdentityHead::default().advanced(did, b"AB", b"c").head,
            IdentityHead::default().advanced(did, b"A", b"Bc").head
        );
    }
}
