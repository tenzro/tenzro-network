//! Identifiable-abort evidence packets for the slashing pipeline.
//!
//! DKLS23 distinguishes two abort severities (see `dkls23_core::protocols`):
//!
//! - `Recoverable` — protocol failed but no long-term state was compromised;
//!   the session can be retried with the same parties.
//! - `BanCounterparty(PartyIndex)` — the identified counterparty cheated in a
//!   way that leaks OT state. The DKLS23 paper mandates that this party
//!   **MUST** be permanently excluded from all future signing and refresh
//!   sessions; otherwise repeated interaction enables full private-key
//!   extraction over multiple sessions.
//!
//! `MpcAbortEvidence` is the quorum-required packet validators submit on-chain
//! to drive [`tenzro_token::staking`] slashing for the offending operator. A
//! single witness report is insufficient — the evidence must carry at least
//! `threshold` signatures from session participants to be admissible.
//!
//! The slashing dispatch surface is the sync [`MpcSlashingCallback`] trait
//! (mirroring `tenzro_consensus::SlashingCallback`). Session drivers
//! ([`crate::mpc::keygen::KeygenSession`], [`crate::mpc::sign::SignSession`],
//! [`crate::mpc::refresh::RefreshSession`]) detect a `dkls23_core::protocols::
//! Abort`, project it via [`MpcAbortEvidence::from_protocol_abort`], sign the
//! preimage locally, and gossip the evidence packet. Witnesses re-emit
//! signatures on the same packet. Once a packet carries `parameters.threshold`
//! valid signatures, the node bridge admits it via [`admit_evidence`] and
//! dispatches `MpcSlashingCallback::report_abort`.

use std::collections::HashMap;

use dkls23_core::protocols::{Abort, AbortKind, AbortReason};
use serde::{Deserialize, Serialize};
use tenzro_crypto::{signatures::Signature, PublicKey};
#[cfg(test)]
use tenzro_crypto::KeyType;
use thiserror::Error;

use crate::mpc::setup::{InstanceId, MpcParameters};

/// Maximum permitted `MpcAbortEvidence::context` byte length. Enforced at
/// admission time so a misbehaving witness cannot inflate evidence size.
pub const MAX_EVIDENCE_CONTEXT_BYTES: usize = 256;

/// Domain-separation tag for the `MpcAbortEvidence` signing preimage.
pub const ABORT_EVIDENCE_DOMAIN_TAG: &[u8] = b"tenzro/mpc/abort-evidence";

/// Local view of DKLS23 `AbortKind`, decoupled from the upstream type so the
/// on-chain evidence schema does not depend on the dkls23-core crate version.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbortSeverity {
    /// Session can be retried with the same parties; no slashing.
    Recoverable,
    /// The named counterparty must be permanently excluded from all future
    /// sessions and slashed. Carries the 1-based DKLS23 party index.
    BanCounterparty {
        /// Offending counterparty party index (DKLS23 1-based).
        party_index: u8,
    },
}

/// Categorical reason for the abort, projected from
/// `dkls23_core::protocols::AbortReason` into a stable on-chain enum. Stable
/// across dkls23-core revisions so historical evidence remains decodable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AbortCategory {
    /// Schnorr / commitment / polynomial proof verification failed.
    ProofVerificationFailed,
    /// Commitment did not open to the expected value.
    CommitmentMismatch,
    /// Polynomial values inconsistent across rounds.
    PolynomialInconsistency,
    /// Trivial / identity point submitted where non-trivial required.
    TrivialPoint,
    /// OT (oblivious transfer) consistency check failed — the *only* class
    /// that mandates `BanCounterparty` per the DKLS23 paper.
    OtConsistencyCheckFailed,
    /// Two-party multiplication output did not verify.
    MultiplicationVerificationFailed,
    /// Gamma/U cross-check inconsistency during signing.
    GammaUInconsistency,
    /// Final aggregated signature failed verification against the group key.
    SignatureVerificationFailed,
    /// Zero-share decommitment failed during signing.
    ZeroShareDecommitFailed,
    /// Chain-code commitment failed during BIP-32 derivation.
    ChainCodeCommitmentFailed,
    /// Input validation / routing / state-machine error not attributable to a
    /// cheating party (recoverable). Retained for evidence completeness.
    ProtocolError,
}

/// Quorum-required evidence packet describing a DKLS23 session abort
/// attributable to a specific counterparty.
///
/// `signers` must be a subset of session participants whose Ed25519 signatures
/// over the canonical preimage are individually verifiable. The on-chain
/// admission rule (task #21) requires `signers.len() >= parameters.threshold`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcAbortEvidence {
    /// Session this evidence refers to.
    pub instance_id: InstanceId,
    /// Session parameters (curve + t-of-n shape). Stamped so a stale verifier
    /// rejects on shape mismatch without consulting external state.
    pub parameters: MpcParameters,
    /// Severity classification.
    pub severity: AbortSeverity,
    /// Categorical reason.
    pub category: AbortCategory,
    /// DID of the counterparty being accused (matches `severity` party index).
    pub accused_did: String,
    /// Free-form context (e.g. round name, message index) for forensic review.
    /// Bounded to 256 bytes; longer values are rejected at admission time.
    pub context: String,
    /// Ed25519/Secp256k1 signatures from witnesses over the canonical
    /// preimage (see [`MpcAbortEvidence::signing_preimage`]).
    pub signers: Vec<EvidenceSigner>,
}

/// A single witness signature on an abort-evidence packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSigner {
    /// DID of the witness.
    pub witness_did: String,
    /// Witness signature over [`MpcAbortEvidence::signing_preimage`].
    pub signature: Signature,
}

impl MpcAbortEvidence {
    /// Canonical signing preimage — domain-separated tag plus serialized
    /// (instance_id, parameters, severity, category, accused_did, context).
    /// The `signers` field is **not** included so multiple witnesses produce
    /// identical preimages over the same evidence.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(ABORT_EVIDENCE_DOMAIN_TAG);
        buf.extend_from_slice(self.instance_id.as_bytes());
        // Parameters: curve byte + threshold + total
        buf.push(match self.parameters.curve {
            crate::mpc::setup::MpcCurve::Secp256k1 => 0x01,
        });
        buf.push(self.parameters.threshold);
        buf.push(self.parameters.total_parties);
        // Severity
        match &self.severity {
            AbortSeverity::Recoverable => buf.push(0x00),
            AbortSeverity::BanCounterparty { party_index } => {
                buf.push(0x01);
                buf.push(*party_index);
            }
        }
        // Category as a single discriminant byte
        buf.push(self.category.discriminant());
        // Lengths are encoded as 2-byte LE to keep the preimage canonical.
        let accused = self.accused_did.as_bytes();
        buf.extend_from_slice(&(accused.len() as u16).to_le_bytes());
        buf.extend_from_slice(accused);
        let context = self.context.as_bytes();
        buf.extend_from_slice(&(context.len() as u16).to_le_bytes());
        buf.extend_from_slice(context);
        buf
    }
}

impl MpcAbortEvidence {
    /// Project a `dkls23_core::protocols::Abort` into our stable on-chain
    /// evidence type. The `did_for_party` closure resolves a DKLS23 1-based
    /// party index to the operator DID used in slashing dispatch — the caller
    /// (session driver) injects its participant DID map.
    ///
    /// Returns `None` if the abort's accused party index cannot be resolved
    /// (e.g. evidence references a party not in the session participant set —
    /// always an internal bug, never normal flow).
    ///
    /// The returned packet carries no signatures; the caller is expected to
    /// sign [`Self::signing_preimage`] locally and gossip the result.
    pub fn from_protocol_abort(
        abort: &Abort,
        instance_id: InstanceId,
        parameters: MpcParameters,
        did_for_party: impl Fn(u8) -> Option<String>,
    ) -> Option<Self> {
        let severity = AbortSeverity::from(&abort.kind);
        let accused_party = match &severity {
            AbortSeverity::BanCounterparty { party_index } => *party_index,
            AbortSeverity::Recoverable => {
                // Recoverable aborts don't directly accuse a single party. Use
                // the abort.index (the party that *raised* the abort) so the
                // evidence still names someone; admission will reject if
                // severity is Recoverable in slashing-only paths.
                abort.index.as_u8()
            }
        };
        let accused_did = did_for_party(accused_party)?;
        Some(Self {
            instance_id,
            parameters,
            severity,
            category: AbortCategory::from(&abort.reason),
            accused_did,
            context: abort.reason.to_string(),
            signers: Vec::new(),
        })
    }
}

impl From<&AbortKind> for AbortSeverity {
    fn from(k: &AbortKind) -> Self {
        match k {
            AbortKind::Recoverable => Self::Recoverable,
            AbortKind::BanCounterparty(pi) => Self::BanCounterparty {
                party_index: pi.as_u8(),
            },
        }
    }
}

impl From<&AbortReason> for AbortCategory {
    fn from(r: &AbortReason) -> Self {
        match r {
            AbortReason::ProofVerificationFailed { .. } => Self::ProofVerificationFailed,
            AbortReason::CommitmentMismatch { .. } => Self::CommitmentMismatch,
            AbortReason::PolynomialInconsistency => Self::PolynomialInconsistency,
            AbortReason::TrivialInstancePoint { .. }
            | AbortReason::TrivialPublicKey
            | AbortReason::TrivialKeyShare => Self::TrivialPoint,
            AbortReason::OtConsistencyCheckFailed { .. } => Self::OtConsistencyCheckFailed,
            AbortReason::MultiplicationVerificationFailed { .. } => {
                Self::MultiplicationVerificationFailed
            }
            AbortReason::GammaUInconsistency { .. } => Self::GammaUInconsistency,
            AbortReason::SignatureVerificationFailed => Self::SignatureVerificationFailed,
            AbortReason::ZeroShareDecommitFailed { .. } => Self::ZeroShareDecommitFailed,
            AbortReason::ChainCodeCommitmentFailed { .. } => Self::ChainCodeCommitmentFailed,
            // Input validation, message routing, signature assembly arithmetic
            // failures, BIP derivation parse errors, and out-of-order phase
            // calls are all recoverable input/state-machine errors not
            // attributable to a cheating counterparty.
            _ => Self::ProtocolError,
        }
    }
}

/// Slashing dispatch surface for admissible `MpcAbortEvidence` packets.
///
/// Implementers (e.g. the node-side bridge to `tenzro_token::staking`) own the
/// actual stake-burn logic. Mirrors the sync pattern used by
/// `tenzro_consensus::SlashingCallback`.
pub trait MpcSlashingCallback: Send + Sync {
    /// Report an admitted abort. The implementer MUST treat this as
    /// authoritative: by the time it is called, [`admit_evidence`] has already
    /// verified the quorum, the signatures, and the evidence well-formedness.
    fn report_abort(&self, evidence: &MpcAbortEvidence);
}

/// Local-witness evidence-emission surface used by session drivers.
///
/// When a `KeygenSession` / `SignSession` / `RefreshSession` detects a
/// `dkls23_core::protocols::Abort` it converts it via
/// [`MpcAbortEvidence::from_protocol_abort`] and then calls
/// `report_local_observation` on its installed reporter. The reporter is
/// responsible for: (1) locally signing [`MpcAbortEvidence::signing_preimage`]
/// with this node's operator key, (2) appending the signature to
/// `evidence.signers`, (3) gossiping the packet on the `tenzro/mpc/abort` topic
/// so other witnesses can aggregate their signatures, and (4) admitting +
/// dispatching to [`MpcSlashingCallback`] once `parameters.threshold` distinct
/// valid signatures have been collected.
///
/// Sessions take an `Option<Arc<dyn MpcAbortReporter>>` so unit tests and
/// non-validator participants can run without a reporter installed; in that
/// case the abort just propagates as a `ProtocolAbort` error to the caller.
pub trait MpcAbortReporter: Send + Sync {
    /// Report a locally-observed abort. The reporter takes ownership of the
    /// gossip + aggregation + admission lifecycle.
    fn report_local_observation(&self, evidence: MpcAbortEvidence);
}

/// Errors returned by [`admit_evidence`] when an evidence packet cannot be
/// promoted to slashing dispatch.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// Quorum of valid witness signatures was not reached.
    #[error("insufficient witnesses: got {got}, required at least {required}")]
    InsufficientWitnesses {
        /// Distinct, valid witness signatures present.
        got: usize,
        /// Required count (= `parameters.threshold`).
        required: usize,
    },
    /// Evidence carries Recoverable severity — not a slashable event.
    #[error("evidence is recoverable severity; nothing to slash")]
    NotSlashable,
    /// `context` exceeded [`MAX_EVIDENCE_CONTEXT_BYTES`].
    #[error("evidence context too large: {got} > {max} bytes")]
    ContextTooLarge {
        /// Actual context length in bytes.
        got: usize,
        /// Maximum permitted ([`MAX_EVIDENCE_CONTEXT_BYTES`]).
        max: usize,
    },
    /// Witness DID has no registered pubkey in the lookup map.
    #[error("unknown witness DID: {0}")]
    UnknownWitness(String),
    /// Witness signature failed verification against the preimage.
    #[error("invalid signature from witness: {0}")]
    BadSignature(String),
    /// Same witness DID appeared in the signers list more than once. Replay
    /// guard so a single witness cannot vote `threshold` times.
    #[error("duplicate witness DID: {0}")]
    DuplicateWitness(String),
}

/// Admit an `MpcAbortEvidence` packet for slashing dispatch.
///
/// The caller supplies `witness_pubkeys`, a map from witness DID to the
/// operator pubkey used to verify their signature. The map MUST be the
/// participant set of the session referenced by `evidence.instance_id` —
/// signatures from non-participants are rejected.
///
/// On success the caller may invoke
/// [`MpcSlashingCallback::report_abort(evidence)`].
///
/// Rules enforced:
/// 1. `severity = BanCounterparty` (Recoverable aborts are not slashable).
/// 2. `context.len() ≤ MAX_EVIDENCE_CONTEXT_BYTES`.
/// 3. Every witness DID resolves to a pubkey via `witness_pubkeys`.
/// 4. Every signature verifies against [`MpcAbortEvidence::signing_preimage`].
/// 5. Witness DIDs are unique (single witness cannot vote multiple times).
/// 6. Count of valid, unique witnesses ≥ `evidence.parameters.threshold`.
pub fn admit_evidence(
    evidence: &MpcAbortEvidence,
    witness_pubkeys: &HashMap<String, PublicKey>,
) -> Result<(), AdmissionError> {
    if !matches!(evidence.severity, AbortSeverity::BanCounterparty { .. }) {
        return Err(AdmissionError::NotSlashable);
    }
    if evidence.context.len() > MAX_EVIDENCE_CONTEXT_BYTES {
        return Err(AdmissionError::ContextTooLarge {
            got: evidence.context.len(),
            max: MAX_EVIDENCE_CONTEXT_BYTES,
        });
    }

    let preimage = evidence.signing_preimage();
    let mut seen = std::collections::HashSet::with_capacity(evidence.signers.len());
    for signer in &evidence.signers {
        if !seen.insert(signer.witness_did.clone()) {
            return Err(AdmissionError::DuplicateWitness(signer.witness_did.clone()));
        }
        let pk = witness_pubkeys
            .get(&signer.witness_did)
            .ok_or_else(|| AdmissionError::UnknownWitness(signer.witness_did.clone()))?;
        tenzro_crypto::signatures::verify(pk, &preimage, &signer.signature)
            .map_err(|_| AdmissionError::BadSignature(signer.witness_did.clone()))?;
    }

    let required = evidence.parameters.threshold as usize;
    if seen.len() < required {
        return Err(AdmissionError::InsufficientWitnesses {
            got: seen.len(),
            required,
        });
    }
    Ok(())
}

impl AbortCategory {
    /// Stable single-byte discriminant used in the signing preimage.
    pub fn discriminant(&self) -> u8 {
        match self {
            AbortCategory::ProofVerificationFailed => 0x10,
            AbortCategory::CommitmentMismatch => 0x11,
            AbortCategory::PolynomialInconsistency => 0x12,
            AbortCategory::TrivialPoint => 0x13,
            AbortCategory::OtConsistencyCheckFailed => 0x20,
            AbortCategory::MultiplicationVerificationFailed => 0x21,
            AbortCategory::GammaUInconsistency => 0x22,
            AbortCategory::SignatureVerificationFailed => 0x30,
            AbortCategory::ZeroShareDecommitFailed => 0x31,
            AbortCategory::ChainCodeCommitmentFailed => 0x32,
            AbortCategory::ProtocolError => 0xF0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::setup::{MpcCurve, MpcParameters, SESSION_NONCE_LEN};
    use tenzro_types::Hash;

    fn sample_instance() -> InstanceId {
        let block = Hash::from_bytes(&[1u8; 32]).unwrap();
        InstanceId::derive(&block, &[2u8; 32], &[3u8; SESSION_NONCE_LEN])
    }

    fn sample_evidence() -> MpcAbortEvidence {
        MpcAbortEvidence {
            instance_id: sample_instance(),
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            severity: AbortSeverity::BanCounterparty { party_index: 2 },
            category: AbortCategory::OtConsistencyCheckFailed,
            accused_did: "did:tenzro:machine:validator-002".to_string(),
            context: "round=phase2 msg=3".to_string(),
            signers: Vec::new(),
        }
    }

    #[test]
    fn preimage_is_deterministic() {
        let e = sample_evidence();
        assert_eq!(e.signing_preimage(), e.signing_preimage());
    }

    #[test]
    fn preimage_excludes_signers() {
        // Mutating the signers list must not change the preimage so all
        // witnesses produce identical signatures over the same evidence.
        let mut e1 = sample_evidence();
        let e2 = sample_evidence();
        let p1 = e1.signing_preimage();
        e1.signers.push(EvidenceSigner {
            witness_did: "did:tenzro:machine:witness-001".to_string(),
            signature: Signature::new(KeyType::Ed25519, vec![0u8; 64]),
        });
        let p1_after = e1.signing_preimage();
        let p2 = e2.signing_preimage();
        assert_eq!(p1, p1_after);
        assert_eq!(p1, p2);
    }

    #[test]
    fn preimage_changes_with_severity() {
        let mut e = sample_evidence();
        let p_ban = e.signing_preimage();
        e.severity = AbortSeverity::Recoverable;
        let p_rec = e.signing_preimage();
        assert_ne!(p_ban, p_rec);
    }

    #[test]
    fn preimage_changes_with_category() {
        let mut e = sample_evidence();
        let p_a = e.signing_preimage();
        e.category = AbortCategory::SignatureVerificationFailed;
        let p_b = e.signing_preimage();
        assert_ne!(p_a, p_b);
    }

    #[test]
    fn category_discriminants_are_unique() {
        let all = [
            AbortCategory::ProofVerificationFailed,
            AbortCategory::CommitmentMismatch,
            AbortCategory::PolynomialInconsistency,
            AbortCategory::TrivialPoint,
            AbortCategory::OtConsistencyCheckFailed,
            AbortCategory::MultiplicationVerificationFailed,
            AbortCategory::GammaUInconsistency,
            AbortCategory::SignatureVerificationFailed,
            AbortCategory::ZeroShareDecommitFailed,
            AbortCategory::ChainCodeCommitmentFailed,
            AbortCategory::ProtocolError,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in all {
            assert!(seen.insert(c.discriminant()));
        }
    }

    use dkls23_core::protocols::PartyIndex;
    use std::sync::Mutex;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_crypto::KeyPair;

    fn ed25519_keypair() -> KeyPair {
        KeyPair::generate(KeyType::Ed25519).unwrap()
    }

    fn sign_evidence(evidence: &MpcAbortEvidence, signer: &Ed25519SignerImpl, did: &str) -> EvidenceSigner {
        let sig = signer.sign(&evidence.signing_preimage()).unwrap();
        EvidenceSigner {
            witness_did: did.to_string(),
            signature: sig,
        }
    }

    #[test]
    fn from_protocol_abort_projects_ot_failure_to_ban_severity() {
        let abort = Abort {
            index: PartyIndex::new(1).unwrap(),
            kind: AbortKind::BanCounterparty(PartyIndex::new(2).unwrap()),
            reason: AbortReason::OtConsistencyCheckFailed {
                counterparty: PartyIndex::new(2).unwrap(),
            },
        };
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();
        let did_for = |pi: u8| -> Option<String> {
            match pi {
                1 => Some("did:tenzro:machine:p1".into()),
                2 => Some("did:tenzro:machine:p2".into()),
                3 => Some("did:tenzro:machine:p3".into()),
                _ => None,
            }
        };
        let evidence = MpcAbortEvidence::from_protocol_abort(
            &abort,
            sample_instance(),
            parameters,
            did_for,
        )
        .unwrap();
        assert_eq!(
            evidence.severity,
            AbortSeverity::BanCounterparty { party_index: 2 }
        );
        assert_eq!(evidence.category, AbortCategory::OtConsistencyCheckFailed);
        assert_eq!(evidence.accused_did, "did:tenzro:machine:p2");
        assert!(evidence.signers.is_empty());
    }

    #[test]
    fn from_protocol_abort_collapses_input_validation_to_protocol_error() {
        let abort = Abort {
            index: PartyIndex::new(1).unwrap(),
            kind: AbortKind::Recoverable,
            reason: AbortReason::WrongMessageCount {
                expected: 3,
                got: 2,
            },
        };
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();
        let evidence = MpcAbortEvidence::from_protocol_abort(
            &abort,
            sample_instance(),
            parameters,
            |_| Some("did:tenzro:machine:p1".into()),
        )
        .unwrap();
        assert_eq!(evidence.category, AbortCategory::ProtocolError);
        assert_eq!(evidence.severity, AbortSeverity::Recoverable);
    }

    #[test]
    fn from_protocol_abort_returns_none_when_did_lookup_fails() {
        let abort = Abort {
            index: PartyIndex::new(1).unwrap(),
            kind: AbortKind::BanCounterparty(PartyIndex::new(2).unwrap()),
            reason: AbortReason::OtConsistencyCheckFailed {
                counterparty: PartyIndex::new(2).unwrap(),
            },
        };
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();
        let result = MpcAbortEvidence::from_protocol_abort(
            &abort,
            sample_instance(),
            parameters,
            |_| None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn admit_evidence_accepts_threshold_quorum() {
        let mut evidence = sample_evidence();
        let kp_a = ed25519_keypair();
        let kp_b = ed25519_keypair();
        let pk_a = kp_a.public_key().clone();
        let pk_b = kp_b.public_key().clone();
        let signer_a = Ed25519SignerImpl::new(kp_a).unwrap();
        let signer_b = Ed25519SignerImpl::new(kp_b).unwrap();
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_a, "did:tenzro:machine:w1"));
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_b, "did:tenzro:machine:w2"));

        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk_a);
        map.insert("did:tenzro:machine:w2".to_string(), pk_b);
        assert!(admit_evidence(&evidence, &map).is_ok());
    }

    #[test]
    fn admit_evidence_rejects_insufficient_witnesses() {
        let mut evidence = sample_evidence();
        let kp = ed25519_keypair();
        let pk = kp.public_key().clone();
        let signer = Ed25519SignerImpl::new(kp).unwrap();
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer, "did:tenzro:machine:w1"));

        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk);
        // threshold = 2 but only one witness
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::InsufficientWitnesses { got: 1, required: 2 }));
    }

    #[test]
    fn admit_evidence_rejects_duplicate_witness() {
        let mut evidence = sample_evidence();
        let kp = ed25519_keypair();
        let pk = kp.public_key().clone();
        let signer = Ed25519SignerImpl::new(kp).unwrap();
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer, "did:tenzro:machine:w1"));
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer, "did:tenzro:machine:w1"));

        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk);
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::DuplicateWitness(_)));
    }

    #[test]
    fn admit_evidence_rejects_unknown_witness() {
        let mut evidence = sample_evidence();
        let kp_a = ed25519_keypair();
        let kp_b = ed25519_keypair();
        let pk_a = kp_a.public_key().clone();
        let signer_a = Ed25519SignerImpl::new(kp_a).unwrap();
        let signer_b = Ed25519SignerImpl::new(kp_b).unwrap();
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_a, "did:tenzro:machine:w1"));
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_b, "did:tenzro:machine:w2"));

        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk_a);
        // w2 missing from registry
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::UnknownWitness(ref d) if d == "did:tenzro:machine:w2"));
    }

    #[test]
    fn admit_evidence_rejects_bad_signature() {
        let mut evidence = sample_evidence();
        let kp = ed25519_keypair();
        let pk = kp.public_key().clone();
        // Signature over wrong bytes won't verify.
        evidence.signers.push(EvidenceSigner {
            witness_did: "did:tenzro:machine:w1".to_string(),
            signature: Signature::new(KeyType::Ed25519, vec![0u8; 64]),
        });
        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk);
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::BadSignature(_)));
    }

    #[test]
    fn admit_evidence_rejects_recoverable_severity() {
        let mut evidence = sample_evidence();
        evidence.severity = AbortSeverity::Recoverable;
        let map = HashMap::new();
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::NotSlashable));
    }

    #[test]
    fn admit_evidence_rejects_oversized_context() {
        let mut evidence = sample_evidence();
        evidence.context = "x".repeat(MAX_EVIDENCE_CONTEXT_BYTES + 1);
        let map = HashMap::new();
        let err = admit_evidence(&evidence, &map).unwrap_err();
        assert!(matches!(err, AdmissionError::ContextTooLarge { got, max }
            if got == MAX_EVIDENCE_CONTEXT_BYTES + 1 && max == MAX_EVIDENCE_CONTEXT_BYTES));
    }

    /// In-test impl of [`MpcSlashingCallback`] capturing reported evidence.
    struct CapturingCallback {
        captured: Mutex<Vec<MpcAbortEvidence>>,
    }
    impl MpcSlashingCallback for CapturingCallback {
        fn report_abort(&self, evidence: &MpcAbortEvidence) {
            self.captured.lock().unwrap().push(evidence.clone());
        }
    }

    #[test]
    fn callback_receives_admitted_evidence() {
        let mut evidence = sample_evidence();
        let kp_a = ed25519_keypair();
        let kp_b = ed25519_keypair();
        let pk_a = kp_a.public_key().clone();
        let pk_b = kp_b.public_key().clone();
        let signer_a = Ed25519SignerImpl::new(kp_a).unwrap();
        let signer_b = Ed25519SignerImpl::new(kp_b).unwrap();
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_a, "did:tenzro:machine:w1"));
        evidence.signers.push(sign_evidence(&evidence.clone(), &signer_b, "did:tenzro:machine:w2"));

        let mut map = HashMap::new();
        map.insert("did:tenzro:machine:w1".to_string(), pk_a);
        map.insert("did:tenzro:machine:w2".to_string(), pk_b);
        admit_evidence(&evidence, &map).unwrap();

        let cb = CapturingCallback {
            captured: Mutex::new(Vec::new()),
        };
        cb.report_abort(&evidence);
        let captured = cb.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].accused_did, "did:tenzro:machine:validator-002");
    }
}
