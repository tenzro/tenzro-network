//! Verification of confidential-computing attestation evidence.
//!
//! A report is accepted only when every one of these holds:
//!
//! - the report is signed by a key the hardware vendor certified, and that
//!   certification chains *by signature* to a vendor root this crate pins
//!   (Intel's SGX root, AMD's ARKs, AWS's Nitro root) or, for NVIDIA, to the
//!   attestation service key set the verifier was configured with;
//! - the vendor's own collateral says the platform is current: TCB info, QE
//!   identity and CRLs for TDX, the VCEK's TCB values for SEV-SNP;
//! - the workload is not debuggable (TDX debug attribute, SNP policy debug
//!   bit, an all-zero Nitro PCR0, NVIDIA `dbgstat`), and SNP runs at VMPL 0;
//! - the report's user data equals exactly what the verifier asked for.
//!
//! The last point is how freshness is proven. The verifier issues a nonce
//! ([`nonce::NonceIssuer`]), the attester puts a commitment to it (and to
//! whatever else it wants to bind, such as a key or a facility claim) in the
//! report's user data, and the verifier recomputes that commitment. A report's
//! own timestamp is never trusted for freshness.
//!
//! There is no "simulated" report that verifies. Evidence produced without
//! hardware carries no vendor signature and fails the first check.

pub mod facility;
pub mod nonce;
pub mod transparency;

#[cfg(feature = "intel-tdx")]
pub mod tdx;

#[cfg(feature = "amd-sev-snp")]
pub mod snp;

#[cfg(feature = "aws-nitro")]
pub mod nitro;

#[cfg(feature = "nvidia-gpu")]
pub mod nvidia;

use std::collections::BTreeMap;

use tenzro_types::tee::{AttestationReport, Measurement, TeeVendor};

use crate::error::{Result, TeeError};

pub(crate) fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

/// What the verifier requires of a report.
#[derive(Clone, Debug)]
pub struct VerifyPolicy {
    /// Verification time, unix seconds. Certificates, CRLs and collateral must
    /// be valid at this instant.
    pub now: u64,
    /// The exact user data the report must carry: for TDX and SEV-SNP the
    /// 64-byte `REPORT_DATA`, for Nitro the document's `user_data`, for an
    /// NVIDIA composite report the CPU leg's report data.
    pub expected_user_data: Vec<u8>,
    /// Oldest acceptable self-timestamped document (Nitro), in seconds.
    pub max_age_secs: u64,
    /// The NVIDIA attestation service's signing keys (a JWKS document).
    /// NVIDIA evidence is refused when this is `None`.
    pub nvidia_jwks: Option<String>,
}

/// The NVIDIA attestation service key set this process verifies GPU evidence
/// against outside block execution: the one governance put on chain, or until
/// there is one the operator's own. Block execution takes the chain's set
/// explicitly and never reads this.
static NVIDIA_JWKS: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

fn nvidia_jwks_in_force() -> Option<String> {
    NVIDIA_JWKS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Configure the NVIDIA attestation service's signing keys for this process.
///
/// Until this is called, [`VerifyPolicy::now`] carries no key set and every
/// NVIDIA report is refused — which is the right default, but it means a
/// deployment that wants GPU evidence verified has to supply the keys. The
/// node reads them from its configuration at startup.
///
/// Returns whether this call set them: one already in force is kept.
pub fn configure_nvidia_jwks(jwks: String) -> bool {
    let mut slot = NVIDIA_JWKS.write().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return false;
    }
    *slot = Some(jwks);
    true
}

/// Replace the key set this process verifies GPU evidence against with the
/// one governance put on chain (`None` when it put none, which leaves GPU
/// evidence refused). A node calls it as it applies each enacted policy.
pub fn replace_nvidia_jwks(jwks: Option<String>) {
    *NVIDIA_JWKS.write().unwrap_or_else(|e| e.into_inner()) = jwks;
}

impl VerifyPolicy {
    /// A policy requiring `expected_user_data`, evaluated now, with a
    /// ten-minute bound on self-timestamped evidence.
    ///
    /// Carries the NVIDIA key set this process was configured with, so every
    /// call site verifies GPU evidence the same way rather than each deciding
    /// for itself.
    pub fn now(expected_user_data: Vec<u8>) -> Self {
        Self {
            now: chrono::Utc::now().timestamp().max(0) as u64,
            expected_user_data,
            max_age_secs: 600,
            nvidia_jwks: nvidia_jwks_in_force(),
        }
    }
}

/// A report that passed verification, and what it proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub vendor: TeeVendor,
    /// The launch measurement: MRTD, SNP `MEASUREMENT`, Nitro PCR0, or for a
    /// composite GPU report, the CPU leg's measurement.
    pub measurement: Vec<u8>,
    /// The user data the report carried (equal to the policy's).
    pub user_data: Vec<u8>,
    /// The vendor's TCB verdict for the platform.
    pub tcb_status: String,
    /// A per-platform identifier: SNP `CHIP_ID`, TDX PPID, Nitro module id,
    /// NVIDIA `ueid`.
    pub platform_id: Vec<u8>,
    pub measurements: Vec<Measurement>,
    pub details: BTreeMap<String, String>,
}

/// Verify `report` against `policy`, dispatching on its vendor.
pub fn verify_report(
    report: &AttestationReport,
    policy: &VerifyPolicy,
) -> Result<VerifiedAttestation> {
    match report.vendor {
        #[cfg(feature = "intel-tdx")]
        TeeVendor::IntelTdx => tdx::verify(report, policy),
        #[cfg(feature = "amd-sev-snp")]
        TeeVendor::AmdSevSnp => snp::verify(report, policy),
        #[cfg(feature = "aws-nitro")]
        TeeVendor::AwsNitro | TeeVendor::AWSNitro => nitro::verify(report, policy),
        #[cfg(feature = "nvidia-gpu")]
        TeeVendor::NvidiaGpu => nvidia::verify_composite(report, policy),
        other => Err(fail(format!("no verifier for {} evidence", other.as_str()))),
    }
}

/// Constant-time equality for report data.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_key_set_on_chain_replaces_the_operators_and_clearing_it_refuses_gpu_evidence() {
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _held = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        replace_nvidia_jwks(None);
        assert!(configure_nvidia_jwks("operator".into()));
        assert!(!configure_nvidia_jwks("second".into()));
        assert_eq!(
            VerifyPolicy::now(vec![]).nvidia_jwks.as_deref(),
            Some("operator")
        );
        replace_nvidia_jwks(Some("chain".into()));
        assert_eq!(
            VerifyPolicy::now(vec![]).nvidia_jwks.as_deref(),
            Some("chain")
        );
        replace_nvidia_jwks(None);
        assert_eq!(VerifyPolicy::now(vec![]).nvidia_jwks, None);
    }
    use super::*;

    #[test]
    fn an_unverifiable_vendor_is_refused() {
        let report = AttestationReport {
            vendor: TeeVendor::Generic,
            ..Default::default()
        };
        assert!(verify_report(&report, &VerifyPolicy::now(vec![0; 64])).is_err());
    }

    #[test]
    fn a_self_described_report_with_no_evidence_is_refused() {
        // Every field a forger controls is filled in; nothing is signed.
        for vendor in [
            TeeVendor::IntelTdx,
            TeeVendor::AmdSevSnp,
            TeeVendor::AwsNitro,
            TeeVendor::NvidiaGpu,
        ] {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("simulated".to_string(), "false".to_string());
            let report = AttestationReport {
                vendor,
                attestation_data: vec![0xAA; 1184],
                measurement: vec![1; 48],
                user_data: vec![0; 64],
                metadata,
                ..Default::default()
            };
            assert!(
                verify_report(&report, &VerifyPolicy::now(vec![0; 64])).is_err(),
                "{vendor:?} accepted unsigned evidence"
            );
        }
    }
}
