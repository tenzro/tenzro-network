//! Bridge from `tenzro_model::RecipientEnclaveAttester` to the local TEE
//! provider and the hardware attestation verifier in `tenzro-tee`.
//!
//! A sealed-model manifest may pin a recipient to an enclave measurement.
//! `tenzro-model` states that requirement but depends on no vendor code, so
//! it declares the proof step as a trait and takes an implementation from
//! its caller. `tenzro-node` is the only crate that holds both the model
//! crate and a live [`TeeProvider`], so the implementation lives here.
//!
//! The installing node *is* the recipient — it holds the X25519 secret key
//! whose public half the manifest names. That is what makes a fresh report
//! meaningful: no caller supplies the evidence, so there is nothing to
//! replay or echo back.
//!
//! What a proof does, in order:
//!
//! 1. Require a TEE provider. Without one the node cannot prove anything and
//!    the install is refused rather than allowed through unchecked.
//! 2. Generate a fresh report whose user data commits to
//!    `SHA-256("tenzro/model/sealed-recipient" || did || x25519_pubkey)`,
//!    packed for the provider's vendor.
//! 3. Verify that report with [`AttestationVerifier::verify_report_strict`],
//!    which refuses simulated reports and reports whose certificate chain
//!    does not reach a pinned vendor root.
//! 4. Confirm the verified report commits to the binding from step 2, by
//!    re-packing and comparing in constant time — the report a provider
//!    hands back is not assumed to carry the user data it was asked for.
//!
//! Only then is the measurement returned. Returning a measurement is not
//! approval: `unseal_model_to_file` compares it against the one the sealer
//! recorded and refuses on mismatch.

use tenzro_model::RecipientEnclaveAttester;
use tenzro_model::error::{ModelError, Result as ModelResult};
use tenzro_tee::{AttestationVerifier, TeeProvider, pack_user_data_for_vendor};
use tenzro_types::tee::AttestationReport;

/// Domain tag for the sealed-model recipient binding.
const RECIPIENT_BINDING_DOMAIN: &[u8] = b"tenzro/model/sealed-recipient";

/// `RecipientEnclaveAttester` impl backed by the node's TEE provider. See
/// module docs.
pub struct TeeRecipientAttester<'a> {
    provider: &'a dyn TeeProvider,
    verifier: AttestationVerifier,
}

impl<'a> TeeRecipientAttester<'a> {
    /// Builds an attester over the node's provider and the default pinned
    /// vendor roots.
    pub fn new(provider: &'a dyn TeeProvider) -> Self {
        Self {
            provider,
            verifier: AttestationVerifier::new(),
        }
    }
}

/// The value a recipient's report must commit to: the DID and the X25519
/// public key together, so a report bound to one recipient entry cannot be
/// presented for another.
fn recipient_binding(recipient_did: &str, x25519_pubkey: &[u8; 32]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(RECIPIENT_BINDING_DOMAIN);
    h.update((recipient_did.len() as u32).to_le_bytes());
    h.update(recipient_did.as_bytes());
    h.update(x25519_pubkey);
    h.finalize().to_vec()
}

/// Constant-time equality including length: a `user_data` that is a prefix of
/// the expected packing is not the same commitment.
fn commits_to(report: &AttestationReport, binding: &[u8]) -> bool {
    let packed = pack_user_data_for_vendor(report.vendor, binding);
    packed.len() == report.user_data.len()
        && packed
            .iter()
            .zip(report.user_data.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[async_trait::async_trait]
impl RecipientEnclaveAttester for TeeRecipientAttester<'_> {
    async fn attest(&self, recipient_did: &str, x25519_pubkey: &[u8; 32]) -> ModelResult<String> {
        let binding = recipient_binding(recipient_did, x25519_pubkey);
        let user_data = pack_user_data_for_vendor(self.provider.vendor(), &binding);

        let report = self
            .provider
            .generate_attestation(&user_data)
            .await
            .map_err(|e| {
                ModelError::SealedModel(format!(
                    "local enclave could not produce an attestation report for '{}': {}",
                    recipient_did, e
                ))
            })?;

        self.verifier.verify_report_strict(&report).map_err(|e| {
            ModelError::SealedModel(format!(
                "local enclave attestation for '{}' did not verify: {}",
                recipient_did, e
            ))
        })?;

        if !commits_to(&report, &binding) {
            return Err(ModelError::SealedModel(format!(
                "local enclave attestation for '{}' does not commit to the recipient \
                 key in the manifest",
                recipient_did
            )));
        }

        Ok(hex::encode(&report.measurement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::tee::TeeVendor;

    fn report_committing_to(vendor: TeeVendor, binding: &[u8]) -> AttestationReport {
        AttestationReport {
            vendor,
            user_data: pack_user_data_for_vendor(vendor, binding),
            measurement: vec![0xab; 32],
            ..Default::default()
        }
    }

    #[test]
    fn binding_covers_the_did_not_just_the_key() {
        let key = [0x11u8; 32];
        let a = recipient_binding("did:tenzro:machine:a", &key);
        let b = recipient_binding("did:tenzro:machine:b", &key);
        assert_ne!(a, b);
    }

    #[test]
    fn binding_covers_the_key_not_just_the_did() {
        let did = "did:tenzro:machine:a";
        let a = recipient_binding(did, &[0x11u8; 32]);
        let b = recipient_binding(did, &[0x22u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefix_stops_did_key_boundary_confusion() {
        let key = [0u8; 32];
        assert_ne!(
            recipient_binding("ab", &key),
            recipient_binding("a", &key),
            "a shorter DID must not collide with a longer one"
        );
    }

    #[test]
    fn packing_binds_the_expected_binding_not_a_neighbour() {
        let mine = recipient_binding("did:tenzro:machine:a", &[0x11u8; 32]);
        let theirs = recipient_binding("did:tenzro:machine:b", &[0x11u8; 32]);
        let report = report_committing_to(TeeVendor::IntelTdx, &mine);
        assert!(commits_to(&report, &mine));
        assert!(!commits_to(&report, &theirs));
    }

    #[test]
    fn a_prefix_of_the_packing_is_not_the_same_commitment() {
        let binding = recipient_binding("did:tenzro:machine:a", &[0x11u8; 32]);
        let mut report = report_committing_to(TeeVendor::AWSNitro, &binding);
        report.user_data.truncate(16);
        assert!(!commits_to(&report, &binding));
    }
}
