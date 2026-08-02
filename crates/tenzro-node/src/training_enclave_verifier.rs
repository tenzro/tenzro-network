//! Bridge from `tenzro_training::EnclaveIdentityVerifier` to the hardware
//! attestation verifier in `tenzro-tee`.
//!
//! `tenzro-training` states what Confidential-tier admission requires — a
//! trainer's attestation report must verify against a pinned vendor root and
//! must commit to the enclave public key the sponsor wrapped the shard data
//! key to — but it depends on neither `tenzro-tee` nor any vendor code, so it
//! declares the requirement as a trait and takes an implementation from its
//! caller. `tenzro-node` is the only crate that depends on both, so the
//! implementation lives here.
//!
//! What a check does, in order:
//!
//! 1. Decode `report_hex` into an [`AttestationReport`]. The wire form is hex
//!    of the report's JSON serialization — the same encoding
//!    `tenzro_verifyTeeAttestation` accepts.
//! 2. Require the vendor the trainer declared in `TrainingAttestation.vendor`
//!    to match the vendor inside the report. A report is evidence about one
//!    vendor's hardware; a disagreement means the two halves describe
//!    different things.
//! 3. Verify the report with [`AttestationVerifier::verify_report_strict`],
//!    which refuses simulated reports and reports whose certificate chain does
//!    not reach a pinned vendor root.
//! 4. Confirm the report commits to `expected_enclave_pubkey`. TDX and SEV-SNP
//!    reports carry a digest rather than the raw payload, so the expected key
//!    is re-packed for the report's vendor via
//!    [`pack_user_data_for_vendor`] and compared against `report.user_data` in
//!    constant time — the same shape as `verify_agent_key_binding`.
//!
//! Only then is the report's measurement handed back for the manifest
//! comparison. Steps 3 and 4 are independent: a genuine report about a
//! different enclave key passes step 3 and fails step 4.

use tenzro_tee::{AttestationVerifier, pack_user_data_for_vendor};
use tenzro_training::{
    EnclaveIdentityVerifier, Result as TrainingResult, TrainingAttestation, TrainingError,
    VerifiedEnclaveIdentity,
};
use tenzro_types::tee::{AttestationReport, TeeVendor};

/// `EnclaveIdentityVerifier` impl backed by `tenzro_tee::AttestationVerifier`.
/// See module docs.
pub struct TeeEnclaveIdentityVerifier {
    verifier: AttestationVerifier,
}

impl Default for TeeEnclaveIdentityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeEnclaveIdentityVerifier {
    /// Builds a verifier over the default pinned vendor roots.
    pub fn new() -> Self {
        Self {
            verifier: AttestationVerifier::new(),
        }
    }
}

/// Maps a `TrainingAttestation.vendor` tag onto the enum the report carries.
///
/// The training wire uses `nvidia-cc` where the TEE crate uses `NvidiaGpu`;
/// the rest line up with the spellings `tenzro_verifyTeeAttestation` accepts.
fn vendor_from_tag(raw: &str) -> Option<TeeVendor> {
    match raw.to_lowercase().as_str() {
        "intel-tdx" | "tdx" | "intel_tdx" => Some(TeeVendor::IntelTdx),
        "intel-sgx" | "sgx" | "intel_sgx" => Some(TeeVendor::IntelSGX),
        "amd-sev-snp" | "sev-snp" | "amd_sev_snp" | "sev_snp" => Some(TeeVendor::AmdSevSnp),
        "amd-sev" | "amd_sev" => Some(TeeVendor::AMDSEV),
        "aws-nitro" | "nitro" | "aws_nitro" => Some(TeeVendor::AWSNitro),
        "nvidia-cc" | "nvidia-gpu" | "nvidia" | "nvidia_gpu" => Some(TeeVendor::NvidiaGpu),
        _ => None,
    }
}

fn rejected(trainer_did: &str, reason: impl Into<String>) -> TrainingError {
    TrainingError::AttestationVerificationFailed {
        trainer_did: trainer_did.to_string(),
        reason: reason.into(),
    }
}

/// Constant-time equality including length: a `user_data` that is a prefix of
/// the expected packing is not the same commitment.
fn commits_to(report: &AttestationReport, expected_pubkey: &[u8]) -> bool {
    let packed = pack_user_data_for_vendor(report.vendor, expected_pubkey);
    packed.len() == report.user_data.len()
        && packed
            .iter()
            .zip(report.user_data.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

impl EnclaveIdentityVerifier for TeeEnclaveIdentityVerifier {
    fn verify(
        &self,
        trainer_did: &str,
        attestation: &TrainingAttestation,
        expected_enclave_pubkey: &[u8],
    ) -> TrainingResult<VerifiedEnclaveIdentity> {
        let declared = vendor_from_tag(&attestation.vendor).ok_or_else(|| {
            rejected(
                trainer_did,
                format!("unknown TEE vendor tag `{}`", attestation.vendor),
            )
        })?;

        let raw = hex::decode(&attestation.report_hex)
            .map_err(|e| rejected(trainer_did, format!("report_hex is not hex: {e}")))?;
        let report: AttestationReport = serde_json::from_slice(&raw).map_err(|e| {
            rejected(
                trainer_did,
                format!("report_hex does not decode to an attestation report: {e}"),
            )
        })?;

        if report.vendor != declared {
            return Err(rejected(
                trainer_did,
                format!(
                    "declared vendor `{}` disagrees with the vendor inside the report ({:?})",
                    attestation.vendor, report.vendor
                ),
            ));
        }

        self.verifier
            .verify_report_strict(&report)
            .map_err(|e| rejected(trainer_did, e.to_string()))?;

        if !commits_to(&report, expected_enclave_pubkey) {
            return Err(rejected(
                trainer_did,
                "report does not commit to the enclave public key the sponsor sealed to",
            ));
        }

        Ok(VerifiedEnclaveIdentity {
            vendor: attestation.vendor.clone(),
            measurement_hex: hex::encode(&report.measurement),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::Hash;

    fn attestation(vendor: &str, report: &AttestationReport) -> TrainingAttestation {
        TrainingAttestation {
            vendor: vendor.to_string(),
            report_hex: hex::encode(serde_json::to_vec(report).unwrap()),
            program_hash: Hash::default(),
            shard_hash: Hash::default(),
        }
    }

    fn report_committing_to(vendor: TeeVendor, pubkey: &[u8]) -> AttestationReport {
        AttestationReport {
            vendor,
            user_data: pack_user_data_for_vendor(vendor, pubkey),
            measurement: vec![0xab; 32],
            ..Default::default()
        }
    }

    #[test]
    fn unknown_vendor_tag_is_refused() {
        let v = TeeEnclaveIdentityVerifier::new();
        let pubkey = [0x11u8; 32];
        let report = report_committing_to(TeeVendor::IntelTdx, &pubkey);
        let err = v
            .verify(
                "did:tenzro:machine:t",
                &attestation("acme-tee", &report),
                &pubkey,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TrainingError::AttestationVerificationFailed { .. }
        ));
    }

    #[test]
    fn declared_vendor_must_match_the_report() {
        let v = TeeEnclaveIdentityVerifier::new();
        let pubkey = [0x11u8; 32];
        let report = report_committing_to(TeeVendor::IntelTdx, &pubkey);
        let err = v
            .verify(
                "did:tenzro:machine:t",
                &attestation("amd-sev-snp", &report),
                &pubkey,
            )
            .unwrap_err();
        match err {
            TrainingError::AttestationVerificationFailed { reason, .. } => {
                assert!(reason.contains("disagrees"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_report_hex_is_refused() {
        let v = TeeEnclaveIdentityVerifier::new();
        let att = TrainingAttestation {
            vendor: "intel-tdx".to_string(),
            report_hex: "not-hex".to_string(),
            program_hash: Hash::default(),
            shard_hash: Hash::default(),
        };
        let err = v
            .verify("did:tenzro:machine:t", &att, &[0u8; 32])
            .unwrap_err();
        match err {
            TrainingError::AttestationVerificationFailed { reason, .. } => {
                assert!(reason.contains("not hex"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn packing_binds_the_expected_key_not_a_neighbour() {
        let mine = [0x11u8; 32];
        let theirs = [0x22u8; 32];
        let report = report_committing_to(TeeVendor::IntelTdx, &mine);
        assert!(commits_to(&report, &mine));
        assert!(!commits_to(&report, &theirs));
    }

    #[test]
    fn a_prefix_of_the_packing_is_not_the_same_commitment() {
        let pubkey = [0x11u8; 32];
        let mut report = report_committing_to(TeeVendor::AWSNitro, &pubkey);
        report.user_data.truncate(16);
        assert!(!commits_to(&report, &pubkey));
    }
}
