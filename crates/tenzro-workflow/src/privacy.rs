//! Privacy domains.
//!
//! A `PrivacyDomain` is a named recipient set with X25519 public keys. Workflow
//! receipts that opt into a domain are wrapped in an `EncryptedReceipt`: the
//! payload is encrypted once per recipient via per-recipient envelope-encryption
//! (the existing `tenzro_crypto::envelope_encrypt` helper), and the public chain
//! sees only a SHA-256 commitment + the recipient public-key set.
//!
//! ### What this gives you
//!
//! - **Confidentiality:** receipt payloads are unreadable to anyone outside the
//!   recipient set. Validators see commitments and can verify that the same
//!   payload was encrypted to every named recipient (commitment binding).
//! - **Per-domain audit:** auditors with the right private key can decrypt
//!   every receipt in a domain. Useful for compliance / regulators / treasury.
//! - **Freezing:** a domain can be `frozen` — no new receipts may be added but
//!   existing receipts remain decryptable.
//!
//! ### What this does NOT give you
//!
//! - **Sub-transaction privacy** — that requires the Canton Merkle-tree-of-views
//!   model and is delivered when the workflow is mirrored to Canton.
//!   Privacy domains are the Tenzro-native primitive for receipt confidentiality
//!   and ACL gating; they are *complementary* to Canton's sub-transaction model,
//!   not a replacement.
//! - **Forward secrecy** — recipient keys are long-lived. If a recipient's key
//!   is compromised, all prior receipts they could decrypt are exposed. We can
//!   layer key rotation on top in a follow-up; not currently.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::encryption::{
    envelope_decrypt, envelope_encrypt, EncryptedEnvelope, X25519KeyPair, X25519PublicKey,
};
use tenzro_storage::kv::{KvStore, WriteOp, CF_SETTLEMENTS};
use tenzro_types::primitives::Hash;
use tracing::{debug, info};

use crate::error::{Result, WorkflowError};
use crate::workflow::PrivacyDomainId;

/// One recipient in a privacy domain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyRecipient {
    pub did: String,
    /// X25519 public key the recipient holds the private half of.
    pub x25519_public_key: [u8; 32],
}

/// A named recipient set with optional auditor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyDomain {
    pub domain_id: PrivacyDomainId,
    pub label: String,
    pub recipients: Vec<PrivacyRecipient>,
    /// Optional auditor — receives a copy of every encryption (typical:
    /// regulator, treasurer, compliance officer). Identical wire shape to a
    /// recipient; the role is logical, not cryptographic.
    pub auditor: Option<PrivacyRecipient>,
    /// When `true`, no new receipts may be added; existing ones remain
    /// decryptable.
    pub frozen: bool,
    pub created_at: i64,
}

impl PrivacyDomain {
    pub fn derive_id(label: &str, created_at: i64) -> PrivacyDomainId {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/privacy/id");
        h.update((label.len() as u32).to_le_bytes());
        h.update(label.as_bytes());
        h.update(created_at.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// Total number of envelopes that will be produced per receipt
    /// (recipients + auditor if present).
    pub fn envelope_count(&self) -> usize {
        self.recipients.len() + usize::from(self.auditor.is_some())
    }

    /// Returns `true` if the given DID is in the recipient set or is the
    /// auditor.
    pub fn is_recipient(&self, did: &str) -> bool {
        self.recipients.iter().any(|r| r.did == did)
            || self.auditor.as_ref().is_some_and(|a| a.did == did)
    }
}

/// One encrypted copy of a payload, addressed to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressedEnvelope {
    /// Recipient DID. Canonical reference; the public key is bound below.
    pub recipient_did: String,
    /// X25519 public key of the recipient (snapshot at encryption time).
    pub recipient_public_key: [u8; 32],
    pub envelope: EncryptedEnvelope,
}

/// A receipt encrypted to every member of a privacy domain.
///
/// The public chain stores this whole struct; the only field validators can
/// verify is `payload_commitment` — they cannot read `envelopes`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedReceipt {
    pub domain_id: PrivacyDomainId,
    /// SHA-256 over the canonical plaintext bytes. Public — every recipient,
    /// when they decrypt their envelope, recomputes this hash and rejects
    /// mismatches. Binds all recipients to the same payload.
    pub payload_commitment: Hash,
    /// One envelope per `(recipient ∪ auditor)`. Order is significant only
    /// for audit replay; lookup is by DID.
    pub envelopes: Vec<AddressedEnvelope>,
    /// Plaintext byte length — useful for fee calculation and audit without
    /// decryption.
    pub plaintext_len: u64,
}

impl EncryptedReceipt {
    /// Encrypt `plaintext` to every recipient (and auditor) of `domain`.
    pub fn seal(domain: &PrivacyDomain, plaintext: &[u8]) -> Result<Self> {
        if domain.frozen {
            return Err(WorkflowError::DomainFrozen(hex::encode(
                domain.domain_id.as_bytes(),
            )));
        }
        if domain.recipients.is_empty() {
            return Err(WorkflowError::Invalid(format!(
                "privacy domain {} has no recipients",
                hex::encode(domain.domain_id.as_bytes())
            )));
        }
        let payload_commitment: [u8; 32] = Sha256::digest(plaintext).into();

        let mut envelopes = Vec::with_capacity(domain.envelope_count());
        for r in &domain.recipients {
            let pk = X25519PublicKey::from(r.x25519_public_key);
            let env = envelope_encrypt(&pk, plaintext)
                .map_err(|e| WorkflowError::Encryption(e.to_string()))?;
            envelopes.push(AddressedEnvelope {
                recipient_did: r.did.clone(),
                recipient_public_key: r.x25519_public_key,
                envelope: env,
            });
        }
        if let Some(a) = &domain.auditor {
            let pk = X25519PublicKey::from(a.x25519_public_key);
            let env = envelope_encrypt(&pk, plaintext)
                .map_err(|e| WorkflowError::Encryption(e.to_string()))?;
            envelopes.push(AddressedEnvelope {
                recipient_did: a.did.clone(),
                recipient_public_key: a.x25519_public_key,
                envelope: env,
            });
        }
        Ok(Self {
            domain_id: domain.domain_id,
            payload_commitment: Hash::from(payload_commitment),
            envelopes,
            plaintext_len: plaintext.len() as u64,
        })
    }

    /// Open the envelope addressed to a specific recipient. Returns the
    /// plaintext if and only if the recovered hash matches the public
    /// commitment (cross-recipient binding check).
    pub fn open(&self, recipient_did: &str, recipient_kp: &X25519KeyPair) -> Result<Vec<u8>> {
        let env = self
            .envelopes
            .iter()
            .find(|e| e.recipient_did == recipient_did)
            .ok_or_else(|| WorkflowError::RecipientNotInDomain(recipient_did.to_string()))?;
        let plaintext = envelope_decrypt(recipient_kp, &env.envelope)
            .map_err(|e| WorkflowError::Decryption(e.to_string()))?;
        let recovered: [u8; 32] = Sha256::digest(&plaintext).into();
        if Hash::from(recovered) != self.payload_commitment {
            return Err(WorkflowError::Decryption(
                "payload commitment mismatch — receipt is not honestly bound".into(),
            ));
        }
        Ok(plaintext)
    }
}

/// Authorization decision for a subscriber requesting an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /// Subscriber is in the recipient set; deliver the encrypted envelope
    /// (subscriber decrypts client-side).
    Allow,
    /// Subscriber is not authorized; do not deliver, do not even surface
    /// the existence of the receipt (avoids existence-leak side-channels).
    Deny,
    /// Public event with no privacy domain — deliver as plaintext.
    Plaintext,
}

/// The primitive ACL check: given a subscriber DID and an optional domain,
/// decide what to deliver.
pub fn acl_check(subscriber_did: Option<&str>, domain: Option<&PrivacyDomain>) -> AclDecision {
    match (subscriber_did, domain) {
        (_, None) => AclDecision::Plaintext,
        (Some(did), Some(d)) if d.is_recipient(did) => AclDecision::Allow,
        _ => AclDecision::Deny,
    }
}

/// In-memory + persistent registry of privacy domains.
///
/// Persistence layout (`CF_SETTLEMENTS`):
/// - `wf_pd:<domain_id>` → bincode `PrivacyDomain`
pub struct PrivacyDomainRegistry {
    domains: DashMap<PrivacyDomainId, PrivacyDomain>,
    storage: Option<Arc<dyn KvStore>>,
}

impl PrivacyDomainRegistry {
    pub fn new() -> Self {
        Self { domains: DashMap::new(), storage: None }
    }

    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let reg = Self { domains: DashMap::new(), storage: Some(storage) };
        reg.hydrate()?;
        Ok(reg)
    }

    fn hydrate(&self) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let mut count = 0usize;
        for (_, value) in store.scan_prefix(CF_SETTLEMENTS, b"wf_pd:")? {
            let d: PrivacyDomain = bincode::deserialize(&value)?;
            self.domains.insert(d.domain_id, d);
            count += 1;
        }
        info!(domains = count, "PrivacyDomainRegistry hydrated from storage");
        Ok(())
    }

    fn persist(&self, d: &PrivacyDomain) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let key = domain_key(&d.domain_id);
        let payload = bincode::serialize(d)?;
        store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key,
            value: payload,
        }])?;
        Ok(())
    }

    /// Register a new domain. Returns `Err(Invalid)` on duplicate id.
    pub fn register(&self, mut d: PrivacyDomain) -> Result<PrivacyDomainId> {
        if d.domain_id == Hash::default() {
            d.domain_id = PrivacyDomain::derive_id(&d.label, d.created_at);
        }
        if d.recipients.is_empty() {
            return Err(WorkflowError::Invalid(
                "privacy domain must have at least one recipient".into(),
            ));
        }
        if self.domains.contains_key(&d.domain_id) {
            return Err(WorkflowError::Invalid(format!(
                "privacy domain {} already exists",
                hex::encode(d.domain_id.as_bytes())
            )));
        }
        self.persist(&d)?;
        let id = d.domain_id;
        self.domains.insert(id, d);
        debug!(domain_id = %hex::encode(id.as_bytes()), "privacy domain registered");
        Ok(id)
    }

    /// Freeze a domain — no new encryptions will succeed.
    pub fn freeze(&self, id: &PrivacyDomainId) -> Result<()> {
        let mut entry = self.domains.get_mut(id).ok_or_else(|| {
            WorkflowError::PrivacyDomainNotFound(hex::encode(id.as_bytes()))
        })?;
        entry.frozen = true;
        let snap = entry.clone();
        drop(entry);
        self.persist(&snap)?;
        Ok(())
    }

    pub fn get(&self, id: &PrivacyDomainId) -> Option<PrivacyDomain> {
        self.domains.get(id).map(|d| d.clone())
    }

    /// Find every domain a DID belongs to (recipient or auditor). Linear scan
    /// — domains are typically O(10s); fan out to a secondary index when this
    /// becomes hot.
    pub fn list_for_did(&self, did: &str) -> Vec<PrivacyDomain> {
        self.domains
            .iter()
            .filter(|d| d.is_recipient(did))
            .map(|d| d.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

impl Default for PrivacyDomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn domain_key(id: &PrivacyDomainId) -> Vec<u8> {
    let mut k = Vec::with_capacity(6 + 32);
    k.extend_from_slice(b"wf_pd:");
    k.extend_from_slice(id.as_bytes());
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_recipient(did: &str) -> (PrivacyRecipient, X25519KeyPair) {
        let kp = X25519KeyPair::generate();
        let r = PrivacyRecipient {
            did: did.into(),
            x25519_public_key: kp.public_key_bytes(),
        };
        (r, kp)
    }

    #[test]
    fn seal_open_round_trip() {
        let (alice, alice_kp) = mk_recipient("did:tenzro:human:alice:1");
        let (bob, bob_kp) = mk_recipient("did:tenzro:human:bob:1");
        let label = "deal-room-1";
        let domain = PrivacyDomain {
            domain_id: PrivacyDomain::derive_id(label, 100),
            label: label.into(),
            recipients: vec![alice.clone(), bob.clone()],
            auditor: None,
            frozen: false,
            created_at: 100,
        };
        let plaintext = b"settle 1000 USDC vs 0.5 ETH @ block 12345";
        let receipt = EncryptedReceipt::seal(&domain, plaintext).unwrap();
        assert_eq!(receipt.envelopes.len(), 2);
        let alice_pt = receipt.open(&alice.did, &alice_kp).unwrap();
        let bob_pt = receipt.open(&bob.did, &bob_kp).unwrap();
        assert_eq!(alice_pt, plaintext);
        assert_eq!(bob_pt, plaintext);
    }

    #[test]
    fn frozen_domain_refuses_new_encryption() {
        let (alice, _) = mk_recipient("alice");
        let mut domain = PrivacyDomain {
            domain_id: PrivacyDomain::derive_id("d", 0),
            label: "d".into(),
            recipients: vec![alice],
            auditor: None,
            frozen: false,
            created_at: 0,
        };
        domain.frozen = true;
        let err = EncryptedReceipt::seal(&domain, b"x").unwrap_err();
        assert!(matches!(err, WorkflowError::DomainFrozen(_)));
    }

    #[test]
    fn open_with_wrong_did_fails() {
        let (alice, _) = mk_recipient("alice");
        let (bob, bob_kp) = mk_recipient("bob");
        let domain = PrivacyDomain {
            domain_id: PrivacyDomain::derive_id("d", 0),
            label: "d".into(),
            recipients: vec![alice],
            auditor: None,
            frozen: false,
            created_at: 0,
        };
        let r = EncryptedReceipt::seal(&domain, b"x").unwrap();
        let err = r.open(&bob.did, &bob_kp).unwrap_err();
        assert!(matches!(err, WorkflowError::RecipientNotInDomain(_)));
    }

    #[test]
    fn auditor_can_decrypt() {
        let (alice, _) = mk_recipient("alice");
        let (auditor, auditor_kp) = mk_recipient("auditor");
        let domain = PrivacyDomain {
            domain_id: PrivacyDomain::derive_id("d", 0),
            label: "d".into(),
            recipients: vec![alice],
            auditor: Some(auditor.clone()),
            frozen: false,
            created_at: 0,
        };
        let r = EncryptedReceipt::seal(&domain, b"sensitive").unwrap();
        assert_eq!(r.envelopes.len(), 2);
        let pt = r.open(&auditor.did, &auditor_kp).unwrap();
        assert_eq!(pt, b"sensitive");
    }

    #[test]
    fn acl_check_semantics() {
        let (alice, _) = mk_recipient("alice");
        let domain = PrivacyDomain {
            domain_id: PrivacyDomain::derive_id("d", 0),
            label: "d".into(),
            recipients: vec![alice],
            auditor: None,
            frozen: false,
            created_at: 0,
        };
        assert_eq!(acl_check(None, None), AclDecision::Plaintext);
        assert_eq!(acl_check(Some("alice"), None), AclDecision::Plaintext);
        assert_eq!(acl_check(Some("alice"), Some(&domain)), AclDecision::Allow);
        assert_eq!(acl_check(Some("eve"), Some(&domain)), AclDecision::Deny);
        assert_eq!(acl_check(None, Some(&domain)), AclDecision::Deny);
    }

    #[test]
    fn registry_register_and_lookup() {
        let reg = PrivacyDomainRegistry::new();
        let (alice, _) = mk_recipient("alice");
        let (bob, _) = mk_recipient("bob");
        let label = "deal-room";
        let id = reg
            .register(PrivacyDomain {
                domain_id: Hash::default(),
                label: label.into(),
                recipients: vec![alice, bob],
                auditor: None,
                frozen: false,
                created_at: 100,
            })
            .unwrap();
        assert!(reg.get(&id).is_some());
        assert_eq!(reg.list_for_did("alice").len(), 1);
        assert_eq!(reg.list_for_did("eve").len(), 0);
    }

    #[test]
    fn registry_freeze_blocks_seal() {
        let reg = PrivacyDomainRegistry::new();
        let (alice, _) = mk_recipient("alice");
        let id = reg
            .register(PrivacyDomain {
                domain_id: Hash::default(),
                label: "d".into(),
                recipients: vec![alice],
                auditor: None,
                frozen: false,
                created_at: 100,
            })
            .unwrap();
        reg.freeze(&id).unwrap();
        let d = reg.get(&id).unwrap();
        let err = EncryptedReceipt::seal(&d, b"x").unwrap_err();
        assert!(matches!(err, WorkflowError::DomainFrozen(_)));
    }

    #[test]
    fn empty_recipient_set_rejected() {
        let reg = PrivacyDomainRegistry::new();
        let err = reg
            .register(PrivacyDomain {
                domain_id: Hash::default(),
                label: "d".into(),
                recipients: vec![],
                auditor: None,
                frozen: false,
                created_at: 0,
            })
            .unwrap_err();
        assert!(matches!(err, WorkflowError::Invalid(_)));
    }
}
