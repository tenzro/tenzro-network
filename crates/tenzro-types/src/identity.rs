//! Identity types for the Tenzro Decentralized Identity Protocol (TDIP)
//!
//! This module defines foundation types used by the `tenzro-identity` crate
//! and throughout the Tenzro Network for unified human and machine identity.

use serde::{Deserialize, Serialize};

/// KYC (Know Your Customer) verification tiers for identities
///
/// Tiers are ordered by verification strength. `PartialOrd` enables
/// comparisons like `tier >= KycTier::Enhanced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KycTier {
    /// No verification performed (Tier 0)
    Unverified = 0,
    /// Basic email verification (Tier 1)
    Basic = 1,
    /// Enhanced verification with ID document (Tier 2)
    Enhanced = 2,
    /// Full verification with biometric + institutional verification (Tier 3)
    Full = 3,
}

impl KycTier {
    /// Returns the tier as a human-readable string
    pub fn as_str(&self) -> &str {
        match self {
            KycTier::Unverified => "unverified",
            KycTier::Basic => "basic",
            KycTier::Enhanced => "enhanced",
            KycTier::Full => "full",
        }
    }

    /// Returns the numeric tier level
    pub fn level(&self) -> u8 {
        *self as u8
    }

    /// The tier at numeric `level`; a level above the highest is the highest.
    pub fn from_level(level: u8) -> KycTier {
        match level {
            0 => KycTier::Unverified,
            1 => KycTier::Basic,
            2 => KycTier::Enhanced,
            _ => KycTier::Full,
        }
    }

    /// The tier a certification grade names: `basic`, `enhanced` or `full`.
    pub fn from_grade(grade: &str) -> Option<KycTier> {
        match grade {
            "basic" => Some(KycTier::Basic),
            "enhanced" => Some(KycTier::Enhanced),
            "full" => Some(KycTier::Full),
            _ => None,
        }
    }
}

/// Payment protocol identifiers for supported payment rails
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentProtocolId {
    /// Machine Payments Protocol (Stripe/Tempo)
    Mpp,
    /// x402 protocol (Coinbase)
    X402,
    /// Direct on-chain settlement (Tenzro native)
    Direct,
    /// Micropayment channel (off-chain)
    Channel,
    /// Custom protocol
    Custom(String),
}

impl PaymentProtocolId {
    /// Returns the protocol name as a string
    pub fn as_str(&self) -> &str {
        match self {
            PaymentProtocolId::Mpp => "mpp",
            PaymentProtocolId::X402 => "x402",
            PaymentProtocolId::Direct => "direct",
            PaymentProtocolId::Channel => "channel",
            PaymentProtocolId::Custom(name) => name,
        }
    }
}

impl std::fmt::Display for PaymentProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Type of identity in the Tenzro Decentralized Identity Protocol.
///
/// The protocol recognises three identity classes — the enum collapses
/// the two machine classes into a single tag, distinguished at runtime
/// by the `controller_did` field on `IdentityData::Machine`:
///
/// - **Human** (`did:tenzro:human:{uuid}`)
/// - **Delegated agent** — machine with a human controller
///   (`did:tenzro:machine:{controller}:{uuid}`)
/// - **Autonomous agent** — machine with no controller
///   (`did:tenzro:machine:{uuid}`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// Human identity
    Human,
    /// Machine/Agent identity (delegated or autonomous)
    Machine,
    /// Institution identity (`did:tenzro:institution:<lei>:<uuid>`).
    Institution,
}

impl IdentityType {
    /// Returns the type as a string
    pub fn as_str(&self) -> &str {
        match self {
            IdentityType::Human => "human",
            IdentityType::Machine => "machine",
            IdentityType::Institution => "institution",
        }
    }
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Wire payload for a `RegisterIdentity` native transaction.
///
/// Carries the **replicable** portion of an identity record — the DID, its
/// public keys, wallet bindings, and display metadata — so an identity
/// created on one node becomes consensus-state that every node re-executes
/// and converges on. Key MATERIAL (TEE-sealed / hardware-held signing keys)
/// stays node-local by design; only this public record replicates.
///
/// The event-loop tx encoder serializes it as JSON into `tx.data[4..]` after
/// `SELECTOR_IDENTITY_REGISTER`, the VM decodes it, enforces DID uniqueness
/// against `SYSTEM_ADDRESS` storage, and re-emits it verbatim as the
/// `IdentityRevoked` log body the node-side registry mirror consumes.
///
/// Emitted when an identity is revoked: by a carried governance proposal, or
/// by a `RevokeIdentity` transaction whose root approval every validator
/// verified. Every node re-executed the same ordered transaction and wrote the
/// same `identity_revoked:<did>` marker, so this log is not evidence a node
/// has to verify — it is consensus telling the local read model what
/// consensus already decided. That is why it carries no signature: there is
/// no author here to distrust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRevokedLog {
    /// The DID that was revoked.
    pub did: String,
    /// The reason recorded with the proposal. The evidence.
    pub reason: String,
    /// Who revoked it: the root DID whose approval the chain verified, or a
    /// DID-shaped string naming the proposal, so an auditor reading the
    /// revocation can find the approval or the vote that produced it.
    pub revoked_by: String,
    /// The proposal that carried, for a governance revocation; `None` when
    /// the identity's root revoked it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
}

/// The custody operation a root signs to revoke an identity.
pub const OP_REVOKE_IDENTITY: &[u8] = b"revoke_identity";

/// The reason a revocation records when its approver gives none.
pub const DEFAULT_REVOCATION_REASON: &str = "revoked by its root";

/// Longest reason a revocation records.
pub const MAX_REVOCATION_REASON_LEN: usize = 512;

/// Longest DID a revocation names.
pub const MAX_REVOCATION_DID_LEN: usize = 256;

const REVOCATION_TARGET_DOMAIN: &[u8] = b"tenzro/identity-revocation/v1";

/// An identity revoked on its root's authority, carried by an
/// `RevokeIdentity` transaction and checked by every validator.
///
/// The approver is the identity itself when it is a root (a human, whose
/// passkey signs, or an autonomous machine, whose hardware key signs), or
/// the controller chain state names for a delegated agent. The approval goes
/// through the one root-approval check every root-signed operation uses, so
/// the keys it is verified against come from chain state, never from the
/// transaction. Revoking a root also revokes every agent it delegated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRevocationOp {
    /// The DID being revoked.
    pub did: String,
    /// Why, recorded with the revocation. The approval covers it.
    pub reason: String,
    /// The root that approves: `did` itself, or the agent's controller.
    pub approver_did: String,
    /// The approver's approval of [`Self::target`] under
    /// [`OP_REVOKE_IDENTITY`].
    pub approval: crate::agent_terms::AgentTermsApproval,
}

impl IdentityRevocationOp {
    /// What the approval covers: `SHA-256(domain ‖ did ‖ reason)`.
    pub fn target(&self) -> [u8; 32] {
        revocation_target(&self.did, &self.reason)
    }

    /// Refuse a revocation no root could approve.
    pub fn validate(&self) -> Result<(), &'static str> {
        for did in [&self.did, &self.approver_did] {
            if did.is_empty() || did.len() > MAX_REVOCATION_DID_LEN || !did.starts_with("did:") {
                return Err("a revocation names a DID and its approver, each at most 256 bytes");
            }
        }
        if self.reason.len() > MAX_REVOCATION_REASON_LEN {
            return Err("a revocation reason is at most 512 bytes");
        }
        self.approval.check_bounds()
    }
}

/// The root id a delegated DID is derived under: `{root_id}` of
/// `did:tenzro:machine:{root_id}:{id}`. Agents a root delegated and
/// machines a root registered both carry it, so the DID itself names the
/// root that may revoke it.
pub fn delegated_root_id(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:tenzro:machine:")?;
    let (root, id) = rest.split_once(':')?;
    (!root.is_empty() && !id.is_empty() && !id.contains(':')).then_some(root)
}

/// Whether `root_did` is the root (a human or an autonomous machine) the
/// delegated DID `did` is derived under.
pub fn is_delegated_under(did: &str, root_did: &str) -> bool {
    crate::agent_terms::RootKind::of(root_did).is_some()
        && delegated_root_id(did).is_some_and(|root| root_did.rsplit(':').next() == Some(root))
}

/// What a root signs to revoke `did` for `reason`. Length-prefixed, so no
/// two (did, reason) pairs share a target.
pub fn revocation_target(did: &str, reason: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = Vec::new();
    out.extend_from_slice(REVOCATION_TARGET_DOMAIN);
    for f in [did.as_bytes(), reason.as_bytes()] {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    Sha256::digest(&out).into()
}

/// The system storage slot of `did`'s registration record.
pub fn identity_slot(did: &str) -> String {
    format!("identity:{did}")
}

/// `IdentityRegistered` log body the node-side registry mirror consumes.
///
/// Field ordering is fixed and the map is a `BTreeMap` so the JSON body is
/// deterministic across nodes — the record is part of consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterIdentityPayload {
    /// The DID being registered. Uniqueness is consensus-enforced on this key.
    pub did: String,
    /// Identity class: `"human"` | `"machine"` | `"institution"`.
    pub identity_type: String,
    /// Human-readable display / legal name.
    pub display_name: String,
    /// Classical controller public key (Ed25519 / Secp256k1) — becomes
    /// `public_keys[0]` on the reconstructed identity record.
    pub controller_pubkey: Vec<u8>,
    /// Key type string for `controller_pubkey` (`"Ed25519"` / `"Secp256k1"`).
    pub key_type: String,
    /// Wallet ID bound to the identity's primary wallet.
    pub wallet_id: String,
    /// On-chain address of the identity's primary wallet.
    pub wallet_address: crate::primitives::Address,
    /// ML-DSA-65 (FIPS 204) verifying key. Empty when unset.
    #[serde(default)]
    pub pq_verifying_key: Vec<u8>,
    /// Additional public metadata. `BTreeMap` for deterministic ordering.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// Proof that whoever submitted this holds the controller key.
    pub proof: RegistrationProof,
}

/// Proof of possession of the controller key a registration binds.
///
/// A public key is public, so deriving the DID from it shows only that the
/// submitter knew the key — not that they hold it. Without this, anyone who
/// can read a passkey's public half registers that person's DID first and
/// chooses its wallet address, its post-quantum key and its metadata. The
/// signature is over [`registration_statement`], which commits to every field
/// an attacker would want to choose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationProof {
    /// A signature by the controller key over [`registration_statement`]:
    /// the P-256 leg (raw from a TPM or Secure Enclave, or a passkey
    /// assertion) and, when the controller has one enrolled in state, the
    /// hardware ML-DSA-65 leg.
    Hardware {
        /// The composite signature, context `IdentityRegistration`.
        signature: crate::account_signature::CompositeSignature,
    },
    /// A TPM-admitted machine: the DID derives from the TPM attestation key,
    /// whose quote in the record's `tpm_attestation` metadata vouches for the
    /// controller key. The quote names only the DID and that key, so the
    /// controller key also signs [`registration_statement`]; without that
    /// signature anyone who saw the quote could register the DID with their
    /// own wallet, post-quantum key or metadata.
    TpmQuote {
        /// The controller key's composite signature, context
        /// `IdentityRegistration`.
        signature: crate::account_signature::CompositeSignature,
    },
}

/// The bytes a [`RegistrationProof`] signs.
///
/// Commits to every field of the registration except the proof itself, so a
/// captured signature cannot be replayed onto a record with a different wallet
/// address, a different post-quantum key or different metadata. Length-prefixed
/// throughout: concatenation without lengths lets two different registrations
/// produce one statement.
pub fn registration_statement(payload: &RegisterIdentityPayload) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    fn field(h: &mut Sha256, bytes: &[u8]) {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    let mut h = Sha256::new();
    h.update(b"tenzro/identity/registration");
    field(&mut h, payload.did.as_bytes());
    field(&mut h, payload.identity_type.as_bytes());
    field(&mut h, payload.display_name.as_bytes());
    field(&mut h, &payload.controller_pubkey);
    field(&mut h, payload.key_type.as_bytes());
    field(&mut h, payload.wallet_id.as_bytes());
    field(&mut h, payload.wallet_address.as_bytes());
    field(&mut h, &payload.pq_verifying_key);
    h.update((payload.metadata.len() as u64).to_le_bytes());
    for (k, v) in &payload.metadata {
        field(&mut h, k.as_bytes());
        field(&mut h, v.as_bytes());
    }
    h.finalize().into()
}

/// Longest TPM attestation an attach carries, as JSON.
pub const MAX_ATTACHED_ATTESTATION_LEN: usize = 64 * 1024;

const ATTACH_STATEMENT_DOMAIN: &[u8] = b"tenzro/identity/attach-machine-attestation/v1";
const ATTACH_NONCE_DOMAIN: &[u8] = b"tenzro/identity/attach-machine-attestation-nonce/v1";

/// A TPM attestation attached to a machine root that was registered without
/// one, carried by an `AttachMachineAttestation` transaction.
///
/// The machine root's identity key signs [`attach_attestation_statement`],
/// and the root's wallet sends it. The attestation is the evidence a machine
/// root registration records: credential activation and a quote over the
/// admission challenge for the DID and its identity key, whose nonce is the
/// chain challenge [`attach_attestation_nonce`] of the sending account's
/// current nonce, so a quote answers one attach only and cannot be prepared
/// in advance. An attestation attaches once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachMachineAttestationOp {
    /// The machine root the attestation attaches to.
    pub did: String,
    /// The TPM attestation, as the JSON the identity record keeps under its
    /// `tpm_attestation` metadata key.
    pub attestation: String,
    /// The identity key's composite signature over
    /// [`attach_attestation_statement`].
    pub signature: crate::account_signature::CompositeSignature,
}

impl AttachMachineAttestationOp {
    /// What the identity key signs.
    pub fn statement(&self) -> [u8; 32] {
        attach_attestation_statement(&self.did, &self.attestation)
    }

    /// Refuse an attach no machine root could send.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.did.starts_with("did:tenzro:machine:") || self.did.len() > MAX_REVOCATION_DID_LEN {
            return Err("an attestation attaches to a machine DID of at most 256 bytes");
        }
        if self.attestation.is_empty() || self.attestation.len() > MAX_ATTACHED_ATTESTATION_LEN {
            return Err("an attached attestation is 1 byte to 64 KiB of JSON");
        }
        Ok(())
    }
}

/// `SHA-256(domain || len did || did || len attestation || attestation)`: the
/// statement a machine root's identity key signs to attach `attestation`.
pub fn attach_attestation_statement(did: &str, attestation: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ATTACH_STATEMENT_DOMAIN);
    h.update((did.len() as u64).to_le_bytes());
    h.update(did.as_bytes());
    h.update((attestation.len() as u64).to_le_bytes());
    h.update(attestation.as_bytes());
    h.finalize().into()
}

/// The chain challenge an attach's quote answers: bound to the machine root,
/// the account that sends the attach and that account's nonce when it
/// executes, so the quote is fresh and answers one transaction only.
pub fn attach_attestation_nonce(did: &str, sender: &[u8], account_nonce: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ATTACH_NONCE_DOMAIN);
    h.update((did.len() as u64).to_le_bytes());
    h.update(did.as_bytes());
    h.update((sender.len() as u64).to_le_bytes());
    h.update(sender);
    h.update(account_nonce.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use crate::account_signature::{ClassicalProof, CompositeSignature};
    use crate::agent_terms::AgentTermsApproval;

    fn op(signature: CompositeSignature) -> IdentityRevocationOp {
        IdentityRevocationOp {
            did: "did:tenzro:human:aa".into(),
            reason: "passkey lost".into(),
            approver_did: "did:tenzro:human:aa".into(),
            approval: AgentTermsApproval {
                account: vec![1u8; 32],
                nonce: [2u8; 16],
                root_public_key: vec![3u8; 64],
                signature,
            },
        }
    }

    /// The same revocation arrives as JSON in a transaction and as bincode
    /// on the wire; both decode to what was signed, for a raw hardware
    /// signature, a passkey assertion and a hybrid with an ML-DSA-65 leg.
    #[test]
    fn a_revocation_round_trips_in_json_and_bincode_for_every_signature_shape() {
        let raw = ClassicalProof::Raw {
            signature: vec![4u8; 64],
        };
        let passkey = ClassicalProof::WebAuthn {
            authenticator_data: vec![5u8; 37],
            client_data_json: br#"{"type":"webauthn.get"}"#.to_vec(),
            signature: vec![6u8; 70],
        };
        for signature in [
            CompositeSignature::classical(raw.clone()),
            CompositeSignature::classical(passkey),
            CompositeSignature::hybrid(raw, vec![7u8; 3309]),
        ] {
            let op = op(signature);
            op.validate().expect("a well-formed revocation");
            let json: IdentityRevocationOp =
                serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
            assert_eq!(json, op);
            let bin: IdentityRevocationOp =
                bincode::deserialize(&bincode::serialize(&op).unwrap()).unwrap();
            assert_eq!(bin, op);
            assert_eq!(bin.target(), op.target());
        }
    }

    /// The approval covers the DID and the reason; neither moves without a
    /// new signature.
    /// The vector every SDK checks its own `revocation_target` against.
    #[test]
    fn the_revocation_target_matches_the_sdk_vector() {
        assert_eq!(
            hex::encode(revocation_target("did:tenzro:human:aa", "passkey lost")),
            "9fae58244604f04767ff22e0809efecc7f459c45eccc23b9e61499488acb170a"
        );
    }

    #[test]
    fn the_target_binds_the_did_and_the_reason() {
        let t = revocation_target("did:tenzro:human:aa", "passkey lost");
        assert_ne!(t, revocation_target("did:tenzro:human:ab", "passkey lost"));
        assert_ne!(t, revocation_target("did:tenzro:human:aa", "fraud"));
        assert_ne!(
            revocation_target("did:tenzro:human:a", "aX"),
            revocation_target("did:tenzro:human:aa", "X")
        );
    }

    #[test]
    fn a_revocation_no_root_could_approve_is_refused() {
        let mut bad = op(CompositeSignature::classical(ClassicalProof::Raw {
            signature: vec![4u8; 64],
        }));
        bad.reason = "x".repeat(MAX_REVOCATION_REASON_LEN + 1);
        assert!(bad.validate().is_err());
        bad.reason.clear();
        bad.approver_did = "not-a-did".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn a_delegated_did_names_the_root_it_is_derived_under() {
        let agent = "did:tenzro:machine:aa:bb";
        assert_eq!(delegated_root_id(agent), Some("aa"));
        assert!(is_delegated_under(agent, "did:tenzro:human:aa"));
        assert!(is_delegated_under(agent, "did:tenzro:machine:aa"));
        assert!(!is_delegated_under(agent, "did:tenzro:human:cc"));
        assert!(!is_delegated_under(agent, "did:tenzro:machine:aa:bb"));
        assert!(!is_delegated_under(agent, agent));
        assert_eq!(delegated_root_id("did:tenzro:machine:aa"), None);
        assert_eq!(delegated_root_id("did:tenzro:human:aa"), None);
        assert_eq!(delegated_root_id("did:tenzro:machine:aa:bb:cc"), None);
        assert_eq!(delegated_root_id("did:tenzro:machine::bb"), None);
    }
}
