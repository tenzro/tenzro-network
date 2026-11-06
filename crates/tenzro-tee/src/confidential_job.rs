//! Attested units of confidential work, ready to settle.
//!
//! A confidential workload runs outside Tenzro, in a cloud confidential VM
//! or an on-premises one, with or without a GPU in confidential mode.
//! Tenzro does not run it; it checks the hardware's statement about it and
//! pays for the work that statement covers:
//!
//! 1. [`verify_job_evidence`] verifies the workload's attestation: a TDX
//!    quote or SEV-SNP report against the vendor's pinned roots and
//!    collateral, or an NVIDIA GPU's signed measurements against the GPU
//!    roots and reference values governance sets. The report must answer the
//!    job's challenge.
//! 2. Each completed unit becomes an [`AttestedUnitReceipt`] committing to
//!    the job, the unit, what the attestation proved and the unit's output.
//! 3. The payer chains the receipts and signs a cumulative voucher bound to
//!    the chain head for every unit it verified; the chain settles exactly
//!    the vouchered amount. Work whose attestation does not verify gets no
//!    receipt and no voucher.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::key_release::GpuEvidence;
use tenzro_types::tee::{AttestationReport, TeeVendor};

use crate::error::{Result, TeeError};
use crate::verify::{VerifiedAttestation, VerifyPolicy, verify_report};
use crate::x509::Cert;

const RECEIPT_DOMAIN: &[u8] = b"tenzro/confidential-job/unit-receipt/v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"tenzro/confidential-job/evidence/v1\0";
const GPU_MEASUREMENT_DOMAIN: &[u8] = b"tenzro/confidential-job/gpu-measurements/v1\0";

/// A workload's attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobEvidence {
    /// A TDX quote (with its DCAP collateral in the report's metadata) or
    /// an SEV-SNP report (with its `[VCEK, ASK]` chain).
    Cvm(AttestationReport),
    /// An NVIDIA GPU's signed measurements and device chain.
    Gpu(GpuEvidence),
}

impl JobEvidence {
    /// SHA-256 over the evidence, length prefixed.
    pub fn digest(&self) -> [u8; 32] {
        fn put(h: &mut Sha256, b: &[u8]) {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        let mut h = Sha256::new();
        h.update(EVIDENCE_DOMAIN);
        match self {
            Self::Cvm(r) => {
                h.update([0]);
                put(&mut h, r.vendor.as_str().as_bytes());
                put(&mut h, &r.attestation_data);
                for c in &r.certificates {
                    put(&mut h, c);
                }
            }
            Self::Gpu(g) => {
                h.update([1]);
                put(&mut h, &g.report);
                put(&mut h, &g.chain);
            }
        }
        h.finalize().into()
    }
}

/// What the evidence is checked against.
pub struct JobAttestationPolicy<'a> {
    /// The job's challenge: the exact user data a CVM report must carry, or
    /// the 32-byte nonce a GPU report must answer.
    pub challenge: &'a [u8],
    /// GPU device roots governance recognises.
    pub gpu_roots: &'a [Cert],
    /// GPU reference values governance sets.
    pub gpu_references: &'a [(u8, Vec<Vec<u8>>)],
    /// Verification time, unix seconds.
    pub now: u64,
}

/// Verify a workload's attestation against `policy`.
pub fn verify_job_evidence(
    evidence: &JobEvidence,
    policy: &JobAttestationPolicy<'_>,
) -> Result<VerifiedAttestation> {
    match evidence {
        JobEvidence::Cvm(report) => {
            if !matches!(report.vendor, TeeVendor::IntelTdx | TeeVendor::AmdSevSnp) {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "{} is not a confidential VM report",
                    report.vendor.as_str()
                )));
            }
            verify_report(
                report,
                &VerifyPolicy {
                    now: policy.now,
                    expected_user_data: policy.challenge.to_vec(),
                    max_age_secs: 600,
                    nvidia_jwks: None,
                },
            )
        }
        JobEvidence::Gpu(gpu) => {
            let nonce: &[u8; 32] = policy.challenge.try_into().map_err(|_| {
                TeeError::AttestationVerificationFailed(
                    "a GPU job's challenge is a 32-byte nonce".into(),
                )
            })?;
            let chain = crate::nvidia_device::parse_chain(&gpu.chain)?;
            let device = crate::nvidia_device::verify_device_report(
                &gpu.report,
                &chain,
                policy.gpu_roots,
                policy.now,
                nonce,
            )?;
            crate::nvidia_device::check_reference_values(&gpu.report, policy.gpu_references)?;
            let measured = crate::nvidia_device::measurements(&gpu.report)?;
            let mut h = Sha256::new();
            h.update(GPU_MEASUREMENT_DOMAIN);
            for (index, value) in &measured {
                h.update([*index]);
                h.update((value.len() as u32).to_le_bytes());
                h.update(value);
            }
            let mut details = BTreeMap::new();
            details.insert("measurements".to_string(), measured.len().to_string());
            Ok(VerifiedAttestation {
                vendor: TeeVendor::NvidiaGpu,
                measurement: h.finalize().to_vec(),
                user_data: nonce.to_vec(),
                tcb_status: "ReferenceValuesMatched".to_string(),
                platform_id: device.device_id.into_bytes(),
                measurements: Vec::new(),
                details,
            })
        }
    }
}

/// One completed unit of an attested job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedUnitReceipt {
    pub job_id: String,
    /// Zero-based unit number.
    pub unit: u64,
    pub vendor: TeeVendor,
    /// Hex of the verified launch measurement (for a GPU, of its
    /// measurement blocks).
    pub measurement: String,
    /// Hex of the verified platform id: SNP `CHIP_ID`, TDX PPID, GPU device.
    pub platform_id: String,
    /// Hex of [`JobEvidence::digest`].
    pub evidence: String,
    /// Hex of the unit's output hash.
    pub output_hash: String,
}

impl AttestedUnitReceipt {
    /// The receipt for unit `unit` of `job_id`, whose output hashes to
    /// `output_hash`, under the verified attestation.
    pub fn new(
        job_id: &str,
        unit: u64,
        verified: &VerifiedAttestation,
        evidence: &JobEvidence,
        output_hash: &[u8; 32],
    ) -> Self {
        Self {
            job_id: job_id.to_string(),
            unit,
            vendor: verified.vendor,
            measurement: hex::encode(&verified.measurement),
            platform_id: hex::encode(&verified.platform_id),
            evidence: hex::encode(evidence.digest()),
            output_hash: hex::encode(output_hash),
        }
    }

    /// SHA-256 over every field, length prefixed: the leaf a payer chains.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(RECEIPT_DOMAIN);
        for s in [
            self.job_id.as_str(),
            self.vendor.as_str(),
            self.measurement.as_str(),
            self.platform_id.as_str(),
            self.evidence.as_str(),
            self.output_hash.as_str(),
        ] {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s.as_bytes());
        }
        h.update(self.unit.to_le_bytes());
        h.finalize().into()
    }
}
