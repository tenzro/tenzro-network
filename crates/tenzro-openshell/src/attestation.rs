//! The host a sandbox runs on, verified through `tenzro-tee`.
//!
//! OpenShell isolates the workload but says nothing verifiable about the
//! machine it runs on. Before the extensions act, the host presents evidence
//! over a challenge that names the serving node's hardware identity and a
//! fresh nonce: a TPM quote, or a TDX, SEV-SNP, Nitro or NVIDIA GPU report.
//! `tenzro-tee` verifies it; the result is a [`HostBinding`] that every
//! record carries in its `image` field and that the gateway interceptor
//! writes onto every sandbox it admits. Without a verified binding no
//! sandbox is created, so a sandbox runs anywhere and Tenzro still knows
//! what it ran on.

use tenzro_crypto::composite::CompositePublicKey;
use tenzro_tee::tpm_attest::TpmEvidence;
use tenzro_types::tee::AttestationReport;

/// Evidence about the host.
#[derive(Debug, Clone)]
pub enum HostEvidence {
    /// A TPM 2.0 quote.
    Tpm(TpmEvidence),
    /// A confidential-computing report (TDX, SEV-SNP, Nitro, NVIDIA GPU).
    Report(AttestationReport),
}

/// What a verified host proved, and the binding records carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBinding {
    /// `tpm`, or the TEE vendor.
    pub kind: String,
    /// The platform: the TPM's endorsement key name or the TEE's platform id.
    pub platform: String,
    /// The measurement: the quoted PCR digest or the launch measurement.
    pub measurement: String,
    /// `tee:<kind>:<digest>`, the value records and sandboxes carry.
    pub binding: String,
}

/// The challenge the host's evidence must carry: the serving node's
/// identity and a fresh nonce.
pub fn challenge(identity: &CompositePublicKey, nonce: &[u8; 32]) -> [u8; 32] {
    crate::digest(b"tenzro/openshell/host/v1", &[&identity.p256, nonce])
}

fn bind(kind: &str, platform: &[u8], measurement: &[u8], challenge: &[u8; 32]) -> HostBinding {
    let d = crate::digest(
        b"tenzro/openshell/host-binding/v1",
        &[kind.as_bytes(), platform, measurement, challenge],
    );
    HostBinding {
        kind: kind.to_string(),
        platform: hex::encode(platform),
        measurement: hex::encode(measurement),
        binding: format!("tee:{kind}:{}", hex::encode(d)),
    }
}

/// Verify `evidence` over `challenge`.
pub fn verify_host(evidence: &HostEvidence, challenge: &[u8; 32]) -> Result<HostBinding, String> {
    match evidence {
        HostEvidence::Tpm(e) => {
            let q =
                tenzro_tee::tpm_attest::verify_quote(e, challenge).map_err(|e| e.to_string())?;
            Ok(bind("tpm", &q.ek_name, &q.pcr_digest, challenge))
        }
        HostEvidence::Report(r) => {
            // TDX and SEV-SNP report data is 64 bytes: the challenge, then zeros.
            let mut user_data = challenge.to_vec();
            user_data.resize(64, 0);
            let policy = tenzro_tee::VerifyPolicy::now(user_data);
            let v = tenzro_tee::verify_report(r, &policy).map_err(|e| e.to_string())?;
            Ok(bind(
                v.vendor.as_str(),
                &v.platform_id,
                &v.measurement,
                challenge,
            ))
        }
    }
}

/// Quote this machine's TPM over the challenge and verify the quote.
#[cfg(target_os = "linux")]
pub fn attest_local_tpm(
    identity: &CompositePublicKey,
    nonce: &[u8; 32],
) -> Result<(HostEvidence, HostBinding), String> {
    let c = challenge(identity, nonce);
    let (_, evidence) =
        tenzro_tee::tpm_attest::quote_local_machine(&c).map_err(|e| e.to_string())?;
    let evidence = HostEvidence::Tpm(evidence);
    let binding = verify_host(&evidence, &c)?;
    Ok((evidence, binding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::tee::TeeVendor;

    fn identity() -> CompositePublicKey {
        TestHybridSigner::p256_only(1).public_key().clone()
    }

    #[test]
    fn a_report_that_does_not_verify_binds_nothing() {
        let c = challenge(&identity(), &[1; 32]);
        for vendor in [
            TeeVendor::IntelTdx,
            TeeVendor::AmdSevSnp,
            TeeVendor::NvidiaGpu,
            TeeVendor::AwsNitro,
        ] {
            let r = AttestationReport {
                vendor,
                user_data: c.to_vec(),
                quote: vec![0; 64],
                measurement: vec![7; 48],
                ..Default::default()
            };
            assert!(
                verify_host(&HostEvidence::Report(r), &c).is_err(),
                "{vendor:?} verified"
            );
        }
    }

    #[test]
    fn the_challenge_names_the_identity_and_the_nonce() {
        let other = TestHybridSigner::p256_only(2).public_key().clone();
        assert_ne!(
            challenge(&identity(), &[1; 32]),
            challenge(&other, &[1; 32])
        );
        assert_ne!(
            challenge(&identity(), &[1; 32]),
            challenge(&identity(), &[2; 32])
        );
    }

    /// Needs this machine's TPM: run with `TENZRO_TEST_TPM=1` on a host
    /// whose `/dev/tpmrm0` the test user can open. Without it the test
    /// fails rather than passing unrun.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a TPM: run with TENZRO_TEST_TPM=1 -- --ignored"]
    fn a_tpm_quote_binds_the_host_and_only_for_its_challenge() {
        assert_eq!(
            std::env::var("TENZRO_TEST_TPM").as_deref(),
            Ok("1"),
            "TENZRO_TEST_TPM=1 is required"
        );
        let id = identity();
        let (evidence, binding) = attest_local_tpm(&id, &[3; 32]).unwrap();
        assert_eq!(binding.kind, "tpm");
        assert!(binding.binding.starts_with("tee:tpm:"));
        // The same evidence does not verify for another challenge.
        assert!(verify_host(&evidence, &challenge(&id, &[4; 32])).is_err());
        // A quote whose signature was altered is refused.
        let HostEvidence::Tpm(mut e) = evidence else {
            unreachable!()
        };
        let last = e.quote_signature.len() - 1;
        e.quote_signature[last] ^= 1;
        assert!(verify_host(&HostEvidence::Tpm(e), &challenge(&id, &[3; 32])).is_err());
    }
}
