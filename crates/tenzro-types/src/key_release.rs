//! Attestation-bound release of a private model's content key.
//!
//! A provider's weights are encrypted under one content key and stay
//! encrypted at rest and in transit. The key is handed to an operator only
//! wrapped to a key that an attested environment made for that one release,
//! and only after the environment's evidence verifies:
//!
//! - the operator's machine identity, admitted on chain with its TPM, quotes
//!   the release binding with that same attestation key, and its measured
//!   boot (the quote's PCR digest) is one the model's policy accepts;
//! - when the policy names confidential VM measurements, a TDX or SEV-SNP
//!   report carries the binding as its user data and one of those launch
//!   measurements;
//! - when the policy requires a GPU, the GPU's report answers the binding as
//!   its nonce, its device chain ends at a GPU root governance recognises,
//!   and its measurements match the GPU reference values governance sets.
//!
//! The binding ([`release_binding`]) commits to the model, the provider's
//! fresh challenge, the job's terms, the operator's machine identity and the
//! environment's release key, so evidence made for one release cannot be
//! replayed for another operator, job or key.
//!
//! The policy is opt-in per model: a model with no registered policy is
//! released through nothing here. Each release is an on-chain event; after
//! the owner revokes the policy no further release is accepted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tee::{AttestationReport, TeeVendor};
use std::collections::BTreeMap;

/// Domain of [`release_binding`].
pub const RELEASE_BINDING_DOMAIN: &[u8] = b"tenzro/key-release/binding/v1\0";

/// Domain of [`HybridPublicKey::fingerprint`].
pub const RELEASE_KEY_DOMAIN: &[u8] = b"tenzro/key-release/hybrid-key/v1\0";

/// Domain of [`ReleaseEvidence::digest`].
pub const RELEASE_EVIDENCE_DOMAIN: &[u8] = b"tenzro/key-release/evidence/v1\0";

/// Bytes of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_EK_BYTES: usize = 1184;

/// Longest model id a policy may name.
pub const MAX_MODEL_ID_LEN: usize = 128;

/// Most measurements of one kind a policy may accept.
pub const MAX_POLICY_MEASUREMENTS: usize = 32;

/// Longest revocation reason.
pub const MAX_REASON_LEN: usize = 256;

/// The public half of a key an attested environment made in memory for one
/// release: an X25519 key and an ML-KEM-768 encapsulation key. A content key
/// sealed to it needs both key exchanges broken to be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

impl HybridPublicKey {
    /// Bytes of [`Self::encode`]: the X25519 key then the ML-KEM-768
    /// encapsulation key.
    pub const ENCODED_LEN: usize = 32 + ML_KEM_768_EK_BYTES;

    /// The key as one byte string: X25519 key, then ML-KEM-768 encapsulation
    /// key.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ml_kem.len());
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.ml_kem);
        out
    }

    /// Reads a key from [`Self::encode`]'s form; `None` for any other length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let (x25519, ml_kem) = bytes.split_at(32);
        Some(Self {
            x25519: x25519.try_into().ok()?,
            ml_kem: ml_kem.to_vec(),
        })
    }

    /// SHA-256 over both halves, domain separated.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(RELEASE_KEY_DOMAIN);
        h.update(self.x25519);
        h.update((self.ml_kem.len() as u32).to_le_bytes());
        h.update(&self.ml_kem);
        h.finalize().into()
    }
}

/// A confidential VM launch measurement a policy accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvmMeasurement {
    pub vendor: TeeVendor,
    /// The launch measurement, hex: TDX `MRTD`, SEV-SNP `MEASUREMENT`.
    pub measurement: String,
}

/// What a model's owner requires of an environment before its content key
/// is released there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyReleasePolicy {
    /// SHA-256 of the encrypted weights' manifest the key opens, hex.
    pub manifest_hash: String,
    /// TPM PCR composite digests (hex) of the measured boots accepted. Empty
    /// accepts any measured boot, and then a confidential VM measurement is
    /// required instead.
    #[serde(default)]
    pub pcr_digests: Vec<String>,
    /// Confidential VM launch measurements accepted. Empty requires no
    /// confidential VM report.
    #[serde(default)]
    pub cvm_measurements: Vec<CvmMeasurement>,
    /// Whether the environment must include a GPU attested against the
    /// governed GPU roots and reference values.
    #[serde(default)]
    pub require_gpu: bool,
}

#[cfg(test)]
mod hybrid_key_tests {
    use super::*;

    #[test]
    fn a_hybrid_key_round_trips_through_its_encoding_and_refuses_other_lengths() {
        let key = HybridPublicKey {
            x25519: [7; 32],
            ml_kem: vec![9; ML_KEM_768_EK_BYTES],
        };
        let bytes = key.encode();
        assert_eq!(bytes.len(), HybridPublicKey::ENCODED_LEN);
        assert_eq!(HybridPublicKey::decode(&bytes), Some(key));
        assert!(HybridPublicKey::decode(&bytes[1..]).is_none());
        assert!(HybridPublicKey::decode(&[0u8; 32]).is_none());
    }
}

fn is_hex_digest(s: &str, min: usize, max: usize) -> bool {
    (min * 2..=max * 2).contains(&s.len())
        && s.len().is_multiple_of(2)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl KeyReleasePolicy {
    /// Refuse a policy that measures nothing or is malformed.
    pub fn validate(&self) -> Result<(), String> {
        if !is_hex_digest(&self.manifest_hash, 32, 32) {
            return Err("the manifest hash is 32 bytes of hex".into());
        }
        if self.pcr_digests.is_empty() && self.cvm_measurements.is_empty() {
            return Err(
                "a policy must accept at least one measured boot or confidential VM measurement"
                    .into(),
            );
        }
        if self.pcr_digests.len() > MAX_POLICY_MEASUREMENTS
            || self.cvm_measurements.len() > MAX_POLICY_MEASUREMENTS
        {
            return Err(format!(
                "a policy accepts at most {MAX_POLICY_MEASUREMENTS} measurements of each kind"
            ));
        }
        for d in &self.pcr_digests {
            if !is_hex_digest(d, 32, 64) {
                return Err(format!("PCR digest {d} is not 32 to 64 bytes of hex"));
            }
        }
        for m in &self.cvm_measurements {
            if !matches!(m.vendor, TeeVendor::IntelTdx | TeeVendor::AmdSevSnp) {
                return Err(format!(
                    "{} is not a confidential VM vendor",
                    m.vendor.as_str()
                ));
            }
            if !is_hex_digest(&m.measurement, 32, 64) {
                return Err(format!(
                    "measurement {} is not 32 to 64 bytes of hex",
                    m.measurement
                ));
            }
        }
        Ok(())
    }

    /// Whether `measurement` of `vendor` is one this policy accepts.
    pub fn accepts_cvm(&self, vendor: TeeVendor, measurement: &[u8]) -> bool {
        let hex = hex::encode(measurement);
        self.cvm_measurements
            .iter()
            .any(|m| m.vendor == vendor && m.measurement.eq_ignore_ascii_case(&hex))
    }

    /// Whether `pcr_digest` is a measured boot this policy accepts.
    pub fn accepts_pcr_digest(&self, pcr_digest: &[u8]) -> bool {
        if self.pcr_digests.is_empty() {
            return true;
        }
        let hex = hex::encode(pcr_digest);
        self.pcr_digests
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&hex))
    }
}

/// A GPU's signed measurement report and its device certificate chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// SPDM `GET_MEASUREMENTS` request then response, as the driver returns
    /// it.
    pub report: Vec<u8>,
    /// The device certificate chain, concatenated DER or PEM.
    pub chain: Vec<u8>,
}

/// A confidential VM's report, in a form every node encodes the same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvmEvidence {
    /// `IntelTdx` or `AmdSevSnp`.
    pub vendor: TeeVendor,
    /// The raw TDX quote or SEV-SNP report.
    pub report: Vec<u8>,
    /// For SEV-SNP, the `[VCEK, ASK]` chain (DER).
    #[serde(default)]
    pub certificates: Vec<Vec<u8>>,
    /// Vendor collateral by name: a TDX quote's DCAP collateral, an SNP CRL.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl CvmEvidence {
    /// The report as the verifiers take it.
    pub fn to_report(&self) -> AttestationReport {
        AttestationReport {
            vendor: self.vendor,
            attestation_data: self.report.clone(),
            certificates: self.certificates.clone(),
            metadata: self
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            ..Default::default()
        }
    }
}

/// An environment's evidence for one release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvidence {
    /// The operator's machine identity (`did:tenzro:machine:...`), admitted
    /// on chain with its TPM attestation key.
    pub operator_did: String,
    /// `TPMS_ATTEST` of a quote by that attestation key over the binding.
    pub quote: Vec<u8>,
    /// Its raw `r || s` P-256 signature.
    pub quote_signature: Vec<u8>,
    /// A TDX or SEV-SNP report whose user data packs the binding.
    #[serde(default)]
    pub cvm: Option<CvmEvidence>,
    /// A GPU report whose nonce is the binding.
    #[serde(default)]
    pub gpu: Option<GpuEvidence>,
}

impl ReleaseEvidence {
    /// SHA-256 over every piece of evidence, length prefixed.
    pub fn digest(&self) -> [u8; 32] {
        fn put(h: &mut Sha256, b: &[u8]) {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        let mut h = Sha256::new();
        h.update(RELEASE_EVIDENCE_DOMAIN);
        put(&mut h, self.operator_did.as_bytes());
        put(&mut h, &self.quote);
        put(&mut h, &self.quote_signature);
        match &self.cvm {
            Some(r) => {
                h.update([1]);
                put(&mut h, r.vendor.as_str().as_bytes());
                put(&mut h, &r.report);
                for c in &r.certificates {
                    put(&mut h, c);
                }
                for (k, v) in &r.metadata {
                    put(&mut h, k.as_bytes());
                    put(&mut h, v.as_bytes());
                }
            }
            None => h.update([0]),
        }
        match &self.gpu {
            Some(g) => {
                h.update([1]);
                put(&mut h, &g.report);
                put(&mut h, &g.chain);
            }
            None => h.update([0]),
        }
        h.finalize().into()
    }
}

/// A request for one release of a model's content key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub model_id: String,
    /// The provider's fresh challenge for this release.
    pub challenge: [u8; 32],
    /// Digest of the job's terms the release is for.
    pub terms_digest: [u8; 32],
    /// The key the environment made for this release.
    pub release_key: HybridPublicKey,
    pub evidence: ReleaseEvidence,
}

impl ReleaseRequest {
    /// The binding every piece of evidence must answer.
    pub fn binding(&self) -> [u8; 32] {
        release_binding(
            &self.model_id,
            &self.challenge,
            &self.terms_digest,
            &self.evidence.operator_did,
            &self.release_key,
        )
    }
}

/// SHA-256 over the model, the challenge, the job's terms, the operator's
/// machine identity and the release key's fingerprint.
pub fn release_binding(
    model_id: &str,
    challenge: &[u8; 32],
    terms_digest: &[u8; 32],
    operator_did: &str,
    release_key: &HybridPublicKey,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RELEASE_BINDING_DOMAIN);
    h.update((model_id.len() as u32).to_le_bytes());
    h.update(model_id.as_bytes());
    h.update(challenge);
    h.update(terms_digest);
    h.update((operator_did.len() as u32).to_le_bytes());
    h.update(operator_did.as_bytes());
    h.update(release_key.fingerprint());
    h.finalize().into()
}

/// A key-release transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyReleaseOp {
    /// Opt a model in, or replace its policy. The sender owns the model's
    /// release policy from then on.
    Register {
        model_id: String,
        policy: KeyReleasePolicy,
    },
    /// Record one release, verified against the policy and governed values
    /// at the block's time. Only the policy's owner sends it, before it hands
    /// over the wrapped key.
    Release { request: ReleaseRequest },
    /// Stop every further release of the model's key.
    Revoke { model_id: String, reason: String },
}

impl KeyReleaseOp {
    /// The model the operation is about.
    pub fn model_id(&self) -> &str {
        match self {
            Self::Register { model_id, .. } | Self::Revoke { model_id, .. } => model_id,
            Self::Release { request } => &request.model_id,
        }
    }

    /// Refuse a malformed operation before any state is read.
    pub fn validate(&self) -> Result<(), String> {
        let id = self.model_id();
        if id.is_empty() || id.len() > MAX_MODEL_ID_LEN {
            return Err(format!("a model id is 1..={MAX_MODEL_ID_LEN} bytes"));
        }
        match self {
            Self::Register { policy, .. } => policy.validate(),
            Self::Release { request } => {
                if request.release_key.ml_kem.len() != ML_KEM_768_EK_BYTES {
                    return Err(format!(
                        "the release key's ML-KEM-768 half is {ML_KEM_768_EK_BYTES} bytes"
                    ));
                }
                if !request
                    .evidence
                    .operator_did
                    .starts_with("did:tenzro:machine:")
                {
                    return Err("a release names the operator's machine identity".into());
                }
                Ok(())
            }
            Self::Revoke { reason, .. } => {
                if reason.trim().is_empty() || reason.len() > MAX_REASON_LEN {
                    return Err(format!(
                        "a revocation says why in 1..={MAX_REASON_LEN} bytes"
                    ));
                }
                Ok(())
            }
        }
    }
}

/// A model's release policy as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelKeyRelease {
    /// The owning account, hex.
    pub owner: String,
    pub policy: KeyReleasePolicy,
    /// Releases recorded so far.
    pub releases: u64,
    /// When the owner revoked the policy, unix milliseconds.
    #[serde(default)]
    pub revoked_at_ms: Option<i64>,
}

/// One recorded release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvent {
    pub model_id: String,
    /// Zero-based release number for the model.
    pub index: u64,
    pub operator_did: String,
    /// Hex of the job's terms digest.
    pub terms_digest: String,
    /// Hex of the release key's fingerprint.
    pub release_key: String,
    /// Hex of [`release_binding`].
    pub binding: String,
    /// Hex of [`ReleaseEvidence::digest`].
    pub evidence: String,
    /// Hex of the quoted PCR digest.
    pub pcr_digest: String,
    /// Hex of the confidential VM launch measurement, when one was required.
    #[serde(default)]
    pub cvm_measurement: Option<String>,
    /// The GPU's device id, when one was required.
    #[serde(default)]
    pub gpu_device: Option<String>,
    pub at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> HybridPublicKey {
        HybridPublicKey {
            x25519: [b; 32],
            ml_kem: vec![b; ML_KEM_768_EK_BYTES],
        }
    }

    #[test]
    fn the_binding_commits_to_every_part() {
        let base = release_binding("m", &[1; 32], &[2; 32], "did:tenzro:machine:a", &key(3));
        assert_ne!(
            base,
            release_binding("n", &[1; 32], &[2; 32], "did:tenzro:machine:a", &key(3))
        );
        assert_ne!(
            base,
            release_binding("m", &[9; 32], &[2; 32], "did:tenzro:machine:a", &key(3))
        );
        assert_ne!(
            base,
            release_binding("m", &[1; 32], &[9; 32], "did:tenzro:machine:a", &key(3))
        );
        assert_ne!(
            base,
            release_binding("m", &[1; 32], &[2; 32], "did:tenzro:machine:b", &key(3))
        );
        assert_ne!(
            base,
            release_binding("m", &[1; 32], &[2; 32], "did:tenzro:machine:a", &key(4))
        );
    }

    #[test]
    fn a_policy_that_measures_nothing_is_refused() {
        let mut p = KeyReleasePolicy {
            manifest_hash: "ab".repeat(32),
            pcr_digests: vec![],
            cvm_measurements: vec![],
            require_gpu: true,
        };
        assert!(p.validate().is_err());
        p.pcr_digests.push("cd".repeat(32));
        assert!(p.validate().is_ok());
        p.cvm_measurements.push(CvmMeasurement {
            vendor: TeeVendor::NvidiaGpu,
            measurement: "ef".repeat(48),
        });
        assert!(p.validate().is_err());
    }
}
