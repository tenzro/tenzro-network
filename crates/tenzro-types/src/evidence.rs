//! Evidence the chain can check against its own state.
//!
//! An application that pays on delivery (a task market, a purchase, a
//! dispute panel) needs to know whether a piece of evidence holds: an audit
//! entry reaches the epoch root its node committed, an agent holds terms, a
//! settlement was recorded, a device signed a reading with its registered
//! hardware key, a finality proof verifies against the governed finality
//! program. `tenzro_verifyEvidence` answers that for a list of [`Evidence`]
//! items; documents held off chain are bound by digest only.

use serde::{Deserialize, Serialize};

use crate::agent_audit::{AuditProof, hex32};

/// Most evidence items one check may carry.
pub const MAX_EVIDENCE_PER_CHECK: usize = 16;

/// Longest ML-DSA-65 leg a sensor reading's signature carries.
pub const MAX_SENSOR_PQ_SIG_LEN: usize = 3309;

/// What an off-chain document bound by its digest is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    /// A payment mandate the payer issued.
    Mandate,
    /// A receipt for work or goods.
    Receipt,
    /// A compliance evidence pack, which verifies offline.
    EvidencePack,
    /// The delivered work itself.
    Delivery,
}

/// One item of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// An audit or attested-telemetry entry with its proof to the epoch root
    /// its node committed. Checked against that commitment.
    Audit(Box<AuditProof>),
    /// The terms an agent holds on chain, by DID. The check returns the
    /// digest of the terms in force.
    Terms {
        /// The agent's DID.
        agent_did: String,
    },
    /// An HTTP-402 settlement the chain recorded, by payment id.
    Settlement {
        /// The payment id it settled under.
        payment_id: String,
    },
    /// A reading signed by the device that measured it: the composite
    /// signature over [`sensor_reading_digest`] is checked against the
    /// hardware key the device's identity registered.
    SensorData {
        /// The measuring device's DID.
        device_did: String,
        /// SHA-256 of the reading's payload.
        #[serde(with = "hex32")]
        payload_digest: [u8; 32],
        /// When it was measured, ms since the Unix epoch.
        measured_at_ms: u64,
        /// The device's hardware composite signature over the reading digest.
        signature: crate::account_signature::CompositeSignature,
    },
    /// A finality proof: the journal the finality program committed for one
    /// checkpoint and a proof that it did, checked against the finality
    /// program governance set. It carries exactly one proof: `stark`, the
    /// program's succinct STARK receipt (hash-based and quantum-safe, the
    /// canonical form), or `seal`, its 256-byte Groth16 wrap over BN254 (a
    /// compact form for chains that need one, and not quantum-safe).
    FinalityProof {
        /// The journal, as the finality program encodes it.
        #[serde(with = "crate::agent_audit::hex_bytes")]
        journal: Vec<u8>,
        /// The succinct STARK receipt, or empty.
        #[serde(default, with = "crate::agent_audit::hex_bytes")]
        stark: Vec<u8>,
        /// The 256-byte Groth16 seal, or empty.
        #[serde(default, with = "crate::agent_audit::hex_bytes")]
        seal: Vec<u8>,
    },
    /// A document held off chain, bound by its SHA-256.
    Document {
        /// What it is.
        kind: DocumentKind,
        /// SHA-256 of its bytes.
        #[serde(with = "hex32")]
        digest: [u8; 32],
    },
}

impl Evidence {
    /// Bounds a check enforces before touching state.
    pub fn validate(items: &[Evidence]) -> Result<(), &'static str> {
        if items.is_empty() || items.len() > MAX_EVIDENCE_PER_CHECK {
            return Err("a check carries 1 to 16 evidence items");
        }
        for item in items {
            if let Evidence::FinalityProof { stark, seal, .. } = item
                && stark.is_empty() == seal.is_empty()
            {
                return Err("a finality proof carries exactly one of a stark and a seal");
            }
            if let Evidence::SensorData {
                device_did,
                signature,
                ..
            } = item
                && (device_did.is_empty()
                    || device_did.len() > 256
                    || signature
                        .pq
                        .as_ref()
                        .is_some_and(|pq| pq.len() > MAX_SENSOR_PQ_SIG_LEN))
            {
                return Err(
                    "a sensor reading names a 1 to 256 byte DID and an ML-DSA-65 leg of at most 3309 bytes",
                );
            }
        }
        Ok(())
    }
}

/// Domain of the digest a device signs over one reading.
pub const SENSOR_READING_DOMAIN: &[u8] = b"tenzro/sensor-reading";

/// The 32 bytes a device signs to attest one reading.
pub fn sensor_reading_digest(
    device_did: &str,
    payload_digest: &[u8; 32],
    measured_at_ms: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(SENSOR_READING_DOMAIN)
        .chain_update((device_did.len() as u32).to_le_bytes())
        .chain_update(device_did.as_bytes())
        .chain_update(payload_digest)
        .chain_update(measured_at_ms.to_le_bytes())
        .finalize()
        .into()
}

/// The digest a verified finality proof checks to: the checkpoint it proves
/// under the committee it names.
pub fn finality_proof_digest(checkpoint_digest: &[u8; 32], committee_root: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/evidence/finality-proof");
    h.update(checkpoint_digest);
    h.update(committee_root);
    h.finalize().into()
}

/// The result of checking one evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedEvidence {
    /// `audit`, `terms`, `settlement`, `sensor_data`, `finality_proof` (a
    /// quantum-safe STARK), `finality_proof_groth16` (the classical Groth16
    /// wrap), or the document kind.
    pub kind: String,
    /// What the item checks to: SHA-256 of the item as submitted, the terms
    /// in force, the reading digest, the finality proof digest, or a
    /// document's own digest.
    #[serde(with = "hex32")]
    pub digest: [u8; 32],
    /// The chain checked it against its own records. A document is never
    /// checked: it is bound by digest only.
    pub verified_on_chain: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_round_trips_and_is_bounded() {
        let doc = Evidence::Document {
            kind: DocumentKind::Receipt,
            digest: [7; 32],
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert_eq!(serde_json::from_str::<Evidence>(&json).unwrap(), doc);
        assert!(Evidence::validate(std::slice::from_ref(&doc)).is_ok());
        assert!(Evidence::validate(&[]).is_err());
        assert!(Evidence::validate(&vec![doc; MAX_EVIDENCE_PER_CHECK + 1]).is_err());
    }

    #[test]
    fn a_finality_proof_carries_exactly_one_form() {
        let stark: Evidence =
            serde_json::from_str(r#"{"finality_proof":{"journal":"01","stark":"02"}}"#).unwrap();
        assert!(Evidence::validate(std::slice::from_ref(&stark)).is_ok());
        let seal: Evidence =
            serde_json::from_str(r#"{"finality_proof":{"journal":"01","seal":"03"}}"#).unwrap();
        assert!(Evidence::validate(std::slice::from_ref(&seal)).is_ok());
        let both: Evidence =
            serde_json::from_str(r#"{"finality_proof":{"journal":"01","stark":"02","seal":"03"}}"#)
                .unwrap();
        assert!(Evidence::validate(&[both]).is_err());
        let neither: Evidence =
            serde_json::from_str(r#"{"finality_proof":{"journal":"01"}}"#).unwrap();
        assert!(Evidence::validate(&[neither]).is_err());
    }

    #[test]
    fn digests_are_domain_separated() {
        assert_ne!(
            sensor_reading_digest("d", &[1; 32], 5),
            sensor_reading_digest("d", &[1; 32], 6)
        );
        assert_ne!(
            finality_proof_digest(&[1; 32], &[2; 32]),
            finality_proof_digest(&[2; 32], &[1; 32])
        );
    }
}
