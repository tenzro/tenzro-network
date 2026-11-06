//! How much of an inference result its requester can check.

use serde::{Deserialize, Serialize};

/// The verification a requester asks for, per request.
///
/// - `None`: no evidence is required.
/// - `Receipt`: a signed receipt binding the catalog model hash, the engine,
///   the serving machine and the input and output commitments.
/// - `Optimistic`: a receipt from a bonded provider, sampled for re-execution
///   by other providers serving the same model; a mismatch upheld within the
///   challenge window slashes the provider's bond and refunds the requester.
/// - `Tee`: a receipt carrying a confidential-compute attestation whose
///   report data binds the model hash and the input and output commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    #[default]
    None,
    Receipt,
    Optimistic,
    Tee,
}

impl VerificationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Receipt => "receipt",
            Self::Optimistic => "optimistic",
            Self::Tee => "tee",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "receipt" => Some(Self::Receipt),
            "optimistic" => Some(Self::Optimistic),
            "tee" => Some(Self::Tee),
            _ => None,
        }
    }

    /// Whether the answer must come with a receipt the requester can check.
    pub fn requires_receipt(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Largest dispute blob a fault may carry: the original receipt, the request
/// the provider was given and the output it returned.
pub const MAX_FAULT_DISPUTE_BYTES: usize = 64 * 1024;

/// Domain tag an inference receipt's signed preimage begins with.
pub const INFERENCE_RECEIPT_DOMAIN: &[u8] = b"tenzro/inference-receipt";

/// Appends `b` to a receipt preimage, length-prefixed (u64 LE).
pub fn put_receipt_field(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
    buf.extend_from_slice(b);
}

/// The tail every receipt preimage ends with: when it was signed, then the
/// signer's hardware identity key (P-256 point, then its ML-DSA-65 key or
/// nothing).
pub fn receipt_preimage_tail(signed_at_ms: u64, p256: &[u8], pq: Option<&[u8]>) -> Vec<u8> {
    let mut tail = signed_at_ms.to_le_bytes().to_vec();
    put_receipt_field(&mut tail, p256);
    put_receipt_field(&mut tail, pq.unwrap_or_default());
    tail
}

/// The serving machine a receipt preimage names: its fourth field, after the
/// model id, model hash and engine. `None` when the bytes are not a receipt.
pub fn receipt_preimage_machine(preimage: &[u8]) -> Option<&str> {
    let mut rest = preimage.strip_prefix(INFERENCE_RECEIPT_DOMAIN)?;
    let mut field = &[][..];
    for _ in 0..4 {
        let len = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?) as usize;
        field = rest.get(8..8usize.checked_add(len)?)?;
        rest = &rest[8 + len..];
    }
    std::str::from_utf8(field).ok()
}

/// Evidence for an inference fault: everything consensus needs to check that
/// the provider's machine identity signed the disputed receipt in a hardware
/// batch, and for validators to re-execute the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceFaultEvidence {
    /// Hex SHA-256 of `receipt_preimage`.
    pub receipt_digest: String,
    /// The provider's machine DID: the compute bond it serves under, and the
    /// identity whose registered hardware key signed the receipt.
    pub provider_did: String,
    /// Hex of the receipt's signed preimage. It names `provider_did` as the
    /// serving machine and ends with `served_at_ms` and the signer's identity
    /// key.
    pub receipt_preimage: String,
    /// Hex of the JSON of the batched signature over the preimage.
    pub batched: String,
    /// Hex address refunded when the fault is upheld: whoever paid for the
    /// answer.
    pub requester: String,
    /// What the requester paid, refunded from the provider's bond.
    #[serde(with = "crate::primitives::u128_serde")]
    pub refund: u128,
    /// When the receipt was signed, ms since the Unix epoch.
    pub served_at_ms: u64,
    /// JSON: `{receipt, request, output}`, everything a validator needs to
    /// re-execute the request on other providers and compare.
    pub dispute: String,
}

impl InferenceFaultEvidence {
    /// The fault's identity: SHA-256 over the receipt digest (which commits to
    /// the whole signed receipt), the bond, the requester, the refund and the
    /// serving time, length-prefixed. Attesters agree on a fault only when
    /// they agree on all of it.
    pub fn fault_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/inference-fault");
        for s in [
            self.receipt_digest.as_str(),
            self.provider_did.as_str(),
            self.requester.as_str(),
        ] {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s.as_bytes());
        }
        h.update(self.refund.to_le_bytes());
        h.update(self.served_at_ms.to_le_bytes());
        hex::encode(h.finalize())
    }
}

/// Evidence that a catalog entry pins bytes its source does not hold: the
/// signed entry as its publisher published it, and which of its components
/// to check. The signature names the publisher, so nobody can file against
/// an entry a publisher did not sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogFaultEvidence {
    /// The signed catalog entry document as published, JSON text. Carried
    /// as text so the transaction encodes the same way in every codec;
    /// at most [`MAX_FAULT_DISPUTE_BYTES`].
    pub document: String,
    /// Index of the component whose bytes are disputed.
    pub component: u32,
}

/// The id of a catalog fault: the signed document's canonical digest (hex
/// SHA-256, as its catalog record names it) and the component.
pub fn catalog_fault_id(document_digest: &str, component: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/catalog-fault");
    h.update(document_digest.to_ascii_lowercase().as_bytes());
    h.update(component.to_le_bytes());
    hex::encode(h.finalize())
}

/// One operation on an inference fault held in consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceFaultOp {
    /// Open a fault within the challenge window after the receipt was signed.
    File { evidence: InferenceFaultEvidence },
    /// Open a fault against a catalog entry whose pinned SHA-256 or size does
    /// not match the bytes at its source. Validators fetch the component and
    /// attest with [`InferenceFaultOp::Attest`]; upheld, the publisher's
    /// model provider stake is slashed.
    FileCatalog { evidence: CatalogFaultEvidence },
    /// A bonded validator's verdict after re-executing the request: `upheld`
    /// means the provider's answer does not match.
    Attest { fault_id: String, upheld: bool },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fault_id_covers_every_claimed_fact_but_not_the_dispute_blob() {
        let e = InferenceFaultEvidence {
            receipt_digest: "aa".repeat(32),
            provider_did: "did:tenzro:machine:p".into(),
            receipt_preimage: "ee".into(),
            batched: "ff".into(),
            requester: "cc".repeat(32),
            refund: 5,
            served_at_ms: 1,
            dispute: "{}".into(),
        };
        let id = e.fault_id();
        let mut other = e.clone();
        other.dispute = "{\"x\":1}".into();
        assert_eq!(other.fault_id(), id);
        for edit in [
            |e: &mut InferenceFaultEvidence| e.refund = 6,
            |e: &mut InferenceFaultEvidence| e.served_at_ms = 2,
            |e: &mut InferenceFaultEvidence| e.requester = "dd".repeat(32),
            |e: &mut InferenceFaultEvidence| e.provider_did.push('x'),
        ] {
            let mut changed = e.clone();
            edit(&mut changed);
            assert_ne!(changed.fault_id(), id);
        }
    }

    #[test]
    fn every_level_round_trips_by_name() {
        for l in [
            VerificationLevel::None,
            VerificationLevel::Receipt,
            VerificationLevel::Optimistic,
            VerificationLevel::Tee,
        ] {
            assert_eq!(VerificationLevel::parse(l.as_str()), Some(l));
            assert_eq!(
                serde_json::to_value(l).unwrap(),
                serde_json::Value::String(l.as_str().to_string())
            );
        }
        assert_eq!(VerificationLevel::parse("TEE"), None);
    }

    #[test]
    fn a_receipt_preimage_names_its_machine_and_ends_with_its_signer() {
        let mut p = INFERENCE_RECEIPT_DOMAIN.to_vec();
        for f in ["model", "hash", "engine", "did:tenzro:machine:m", "nonce"] {
            put_receipt_field(&mut p, f.as_bytes());
        }
        p.extend_from_slice(&receipt_preimage_tail(42, &[4; 64], None));
        assert_eq!(receipt_preimage_machine(&p), Some("did:tenzro:machine:m"));
        assert!(p.ends_with(&receipt_preimage_tail(42, &[4; 64], None)));
        assert!(!p.ends_with(&receipt_preimage_tail(43, &[4; 64], None)));
        assert!(!p.ends_with(&receipt_preimage_tail(42, &[4; 64], Some(&[1; 8]))));
        assert_eq!(receipt_preimage_machine(&p[..40]), None);
        assert_eq!(receipt_preimage_machine(b"tenzro/other"), None);
    }
}
