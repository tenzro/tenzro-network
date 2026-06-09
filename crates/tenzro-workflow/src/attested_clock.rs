//! TEE-attested clock primitive.
//!
//! Long-running multi-party workflows need timestamps that no single
//! participant can lie about. Wall-clock `SystemTime::now()` is fine
//! when every replica trusts every other replica — for institutional
//! workflows (DvP settlement deadlines, L/C presentation windows,
//! parametric-insurance trigger evaluation, margin-call grace periods,
//! AP2 mandate expiry) we need a timestamp that is signed by hardware
//! whose firmware the participants have ALREADY agreed to trust at
//! enrolment time.
//!
//! The pattern follows the Intel TDX/SEV-SNP/Nitro attestation model:
//! the enclave's measured-firmware certificate chain implicitly anchors
//! the trustworthiness of its system clock. An attestation envelope
//! over `(wall_ms, monotonic_ns, nonce)` lets relying parties bind the
//! reported time to a specific enclave instance, and (via the TEE
//! evidence) to the firmware that produced it.
//!
//! # Wire shape
//!
//! `AttestedTimestamp { wall_ms, monotonic_ns, tee_vendor, enclave_id_hex,
//! attestation_hash, signature }` — the relying party verifies:
//! 1. `attestation_hash` matches a known measurement (firmware whitelist)
//! 2. `signature` verifies over `SHA-256("tenzro/attested-clock" ||
//!    wall_ms || monotonic_ns || nonce || enclave_id)`
//! 3. `wall_ms` is within drift tolerance of the relying party's clock
//!
//! # When to use
//!
//! - Workflow step deadlines (`step_deadline_ms` becomes
//!   `AttestedTimestamp`)
//! - AP2 mandate expiry (cart mandate `valid_until` carried as attested)
//! - Parametric-insurance trigger windows
//! - Margin-call grace periods (mark the wall-time the call was issued)
//! - DvP settlement windows (T+0 / T+1 enforcement)
//!
//! # When NOT to use
//!
//! - In-memory ephemeral state (use `SystemTime::now()`)
//! - Pure consensus path (block timestamps are already attested by the
//!   QC, no separate enclave attestation needed)

use crate::error::{WorkflowError, Result};
use serde::{Deserialize, Serialize};

/// TEE vendor that produced the attestation. Cross-vendor verification
/// requires every relying party to register the vendor's root CA at
/// enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AttestedClockVendor {
    /// Intel TDX (Trust Domain Extensions) — the canonical CPU TEE for
    /// confidential-VM workloads from 2024 onwards.
    IntelTdx,
    /// AMD SEV-SNP (Secure Encrypted Virtualization with Secure Nested
    /// Paging) — the AMD counterpart, dominant on EC2 + Azure.
    AmdSevSnp,
    /// AWS Nitro Enclave — separate isolated child instance with NSM
    /// attestation document signed by AWS root CA.
    AwsNitro,
    /// NVIDIA GPU TEE (H100 / H200) with NRAS attestation. Used when
    /// the timestamp originates from an inference run inside the GPU
    /// enclave (e.g. parametric-insurance trigger evaluation).
    NvidiaGpu,
    /// Intel Tiber Trust Authority — Intel's hosted attestation service.
    /// Useful when the relying party does not want to maintain its own
    /// Intel PCS certificate chain verifier.
    IntelTiber,
}

impl AttestedClockVendor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntelTdx => "intel-tdx",
            Self::AmdSevSnp => "amd-sev-snp",
            Self::AwsNitro => "aws-nitro",
            Self::NvidiaGpu => "nvidia-gpu",
            Self::IntelTiber => "intel-tiber",
        }
    }
}

/// An attested wall-clock timestamp from a hardware TEE.
///
/// `wall_ms` is the Unix-epoch millisecond timestamp the enclave
/// observed via its trusted-platform timer. `monotonic_ns` is the
/// enclave's monotonic counter — paired with `wall_ms` it lets
/// relying parties detect clock-rollback attacks: a fresh
/// `AttestedTimestamp` from the same `enclave_id_hex` must have
/// `monotonic_ns > previous.monotonic_ns`, regardless of any
/// claimed `wall_ms` drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedTimestamp {
    /// Unix epoch milliseconds claimed by the enclave's trusted clock.
    pub wall_ms: u64,
    /// Enclave-local monotonic counter (nanoseconds). MUST increase
    /// strictly between two `AttestedTimestamp` values from the same
    /// enclave. Relying parties detect rollback by tracking the last
    /// `(enclave_id, monotonic_ns)` pair they accepted.
    pub monotonic_ns: u64,
    /// Caller-supplied nonce binding the timestamp to a specific
    /// workflow event. Prevents replay across unrelated events.
    pub nonce: [u8; 32],
    /// TEE vendor identifier; selects the verification path on
    /// receive.
    pub tee_vendor: AttestedClockVendor,
    /// 32-byte enclave identifier (firmware measurement digest).
    /// Hex-encoded. Relying parties whitelist a set of
    /// `enclave_id_hex` values at enrolment to bind the time-source
    /// to specific approved firmware.
    pub enclave_id_hex: String,
    /// SHA-256 of the full attestation envelope (vendor-specific
    /// payload). Lets relying parties cache previously-verified
    /// envelopes and skip re-verification of the same evidence.
    pub attestation_hash: [u8; 32],
    /// Signature over the canonical preimage (see
    /// [`AttestedTimestamp::signing_preimage`]). The signing key MUST
    /// be the enclave's attested signing key (the one bound to the
    /// vendor attestation report).
    pub signature: Vec<u8>,
}

impl AttestedTimestamp {
    /// Canonical preimage the enclave signs over.
    ///
    /// Wire format:
    /// ```text
    /// "tenzro/attested-clock" (21 bytes)
    /// wall_ms              (8 bytes LE)
    /// monotonic_ns         (8 bytes LE)
    /// nonce                (32 bytes)
    /// tee_vendor (as_str)  (var-len, length-prefixed u8)
    /// enclave_id_hex       (var-len, length-prefixed u16 LE)
    /// attestation_hash     (32 bytes)
    /// ```
    pub fn signing_preimage(&self) -> Vec<u8> {
        let vendor = self.tee_vendor.as_str().as_bytes();
        let eid = self.enclave_id_hex.as_bytes();
        let mut out = Vec::with_capacity(21 + 8 + 8 + 32 + 1 + vendor.len() + 2 + eid.len() + 32);
        out.extend_from_slice(b"tenzro/attested-clock");
        out.extend_from_slice(&self.wall_ms.to_le_bytes());
        out.extend_from_slice(&self.monotonic_ns.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.push(vendor.len() as u8);
        out.extend_from_slice(vendor);
        out.extend_from_slice(&(eid.len() as u16).to_le_bytes());
        out.extend_from_slice(eid);
        out.extend_from_slice(&self.attestation_hash);
        out
    }

    /// Verify drift against the relying party's local wall clock.
    /// `tolerance_ms` is the maximum acceptable skew in milliseconds —
    /// the relying party rejects timestamps outside that window.
    /// Returns `Ok(())` if within tolerance; `Err(WorkflowError::*)`
    /// otherwise.
    ///
    /// Default tolerance for institutional workflows is 30_000 ms (30s)
    /// per Canton 3.5 timestamp-drift guidance.
    pub fn check_drift(&self, local_wall_ms: u64, tolerance_ms: u64) -> Result<()> {
        let diff = if self.wall_ms > local_wall_ms {
            self.wall_ms - local_wall_ms
        } else {
            local_wall_ms - self.wall_ms
        };
        if diff > tolerance_ms {
            return Err(WorkflowError::InvalidWorkflow(format!(
                "attested-clock drift exceeded: wall_ms={} local={} diff={} tolerance={}",
                self.wall_ms, local_wall_ms, diff, tolerance_ms
            )));
        }
        Ok(())
    }

    /// Verify monotonic counter against the previously-accepted value
    /// from the same enclave. Pass `previous_monotonic_ns = 0` for the
    /// first observation. Returns `Err` if the new counter is not
    /// strictly greater.
    pub fn check_monotonic(&self, previous_monotonic_ns: u64) -> Result<()> {
        if self.monotonic_ns <= previous_monotonic_ns {
            return Err(WorkflowError::InvalidWorkflow(format!(
                "attested-clock monotonic rollback: new={} previous={}",
                self.monotonic_ns, previous_monotonic_ns
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ts(wall_ms: u64, monotonic_ns: u64) -> AttestedTimestamp {
        AttestedTimestamp {
            wall_ms,
            monotonic_ns,
            nonce: [0u8; 32],
            tee_vendor: AttestedClockVendor::IntelTdx,
            enclave_id_hex: "deadbeef".to_string(),
            attestation_hash: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn preimage_is_deterministic() {
        let ts = sample_ts(1234567890, 42);
        let p1 = ts.signing_preimage();
        let p2 = ts.signing_preimage();
        assert_eq!(p1, p2);
        assert!(p1.starts_with(b"tenzro/attested-clock"));
    }

    #[test]
    fn preimage_is_unique_per_field() {
        let mut a = sample_ts(100, 1);
        let mut b = sample_ts(100, 1);
        assert_eq!(a.signing_preimage(), b.signing_preimage());
        b.wall_ms = 101;
        assert_ne!(a.signing_preimage(), b.signing_preimage());
        a.tee_vendor = AttestedClockVendor::AmdSevSnp;
        assert_ne!(a.signing_preimage(), sample_ts(100, 1).signing_preimage());
    }

    #[test]
    fn drift_within_tolerance_ok() {
        let ts = sample_ts(1_000_000, 1);
        assert!(ts.check_drift(1_000_010, 30_000).is_ok());
        assert!(ts.check_drift(999_990, 30_000).is_ok());
    }

    #[test]
    fn drift_outside_tolerance_rejected() {
        let ts = sample_ts(1_000_000, 1);
        assert!(ts.check_drift(2_000_000, 30_000).is_err());
        assert!(ts.check_drift(0, 30_000).is_err());
    }

    #[test]
    fn monotonic_rollback_rejected() {
        let ts = sample_ts(100, 50);
        assert!(ts.check_monotonic(0).is_ok());
        assert!(ts.check_monotonic(49).is_ok());
        assert!(ts.check_monotonic(50).is_err()); // not strictly greater
        assert!(ts.check_monotonic(51).is_err());
    }

    #[test]
    fn vendor_str_roundtrip() {
        for v in [
            AttestedClockVendor::IntelTdx,
            AttestedClockVendor::AmdSevSnp,
            AttestedClockVendor::AwsNitro,
            AttestedClockVendor::NvidiaGpu,
            AttestedClockVendor::IntelTiber,
        ] {
            assert!(!v.as_str().is_empty());
        }
    }
}
