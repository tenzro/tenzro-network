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
//!    `SHA-256("tenzro/model/sealed-recipient" || did || recipient key fingerprint)`,
//!    packed for the provider's vendor.
//! 3. Verify that report with [`tenzro_tee::verify_report`], requiring its
//!    hardware-signed user data to be exactly the packing from step 2 — the
//!    report a provider hands back is not assumed to carry the user data it
//!    was asked for.
//!
//! Only then is the measurement returned. Returning a measurement is not
//! approval: `unseal_model_to_file` compares it against the one the sealer
//! recorded and refuses on mismatch.

use tenzro_model::RecipientEnclaveAttester;
use tenzro_model::error::{ModelError, Result as ModelResult};
use tenzro_tee::TeeProvider;
use tenzro_types::tee::pack_user_data_for_vendor;

/// Domain tag for the sealed-model recipient binding.
const RECIPIENT_BINDING_DOMAIN: &[u8] = b"tenzro/model/sealed-recipient";

/// `RecipientEnclaveAttester` impl backed by the node's TEE provider. See
/// module docs.
pub struct TeeRecipientAttester<'a> {
    provider: &'a dyn TeeProvider,
}

impl<'a> TeeRecipientAttester<'a> {
    /// Builds an attester over the node's provider.
    pub fn new(provider: &'a dyn TeeProvider) -> Self {
        Self { provider }
    }
}

/// The value a recipient's report must commit to: the DID and the hybrid
/// public key (its fingerprint over both halves) together, so a report bound
/// to one recipient entry cannot be presented for another.
fn recipient_binding(
    recipient_did: &str,
    recipient_key: &tenzro_crypto::hybrid_seal::HybridPublicKey,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(RECIPIENT_BINDING_DOMAIN);
    h.update((recipient_did.len() as u32).to_le_bytes());
    h.update(recipient_did.as_bytes());
    h.update(recipient_key.fingerprint());
    h.finalize().to_vec()
}

#[async_trait::async_trait]
impl RecipientEnclaveAttester for TeeRecipientAttester<'_> {
    async fn attest(
        &self,
        recipient_did: &str,
        recipient_key: &tenzro_crypto::hybrid_seal::HybridPublicKey,
    ) -> ModelResult<String> {
        let binding = recipient_binding(recipient_did, recipient_key);
        let expected = pack_user_data_for_vendor(self.provider.vendor(), &binding);

        let report = self
            .provider
            .generate_attestation(&binding)
            .await
            .map_err(|e| {
                ModelError::SealedModel(format!(
                    "local enclave could not produce an attestation report for '{}': {}",
                    recipient_did, e
                ))
            })?;

        let verified = tenzro_tee::verify_report(&report, &tenzro_tee::VerifyPolicy::now(expected))
            .map_err(|e| {
                ModelError::SealedModel(format!(
                    "local enclave attestation for '{}' did not verify: {}",
                    recipient_did, e
                ))
            })?;

        Ok(hex::encode(&verified.measurement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::hybrid_seal::HybridPublicKey;

    fn key_of(x25519: u8, ml_kem: u8) -> HybridPublicKey {
        HybridPublicKey {
            x25519: [x25519; 32],
            ml_kem: vec![ml_kem; 1184],
        }
    }

    #[test]
    fn binding_covers_the_did_not_just_the_key() {
        let key = key_of(0x11, 1);
        let a = recipient_binding("did:tenzro:machine:a", &key);
        let b = recipient_binding("did:tenzro:machine:b", &key);
        assert_ne!(a, b);
    }

    #[test]
    fn binding_covers_the_key_not_just_the_did() {
        let did = "did:tenzro:machine:a";
        let a = recipient_binding(did, &key_of(0x11, 1));
        let b = recipient_binding(did, &key_of(0x22, 1));
        assert_ne!(a, b);
        // The ML-KEM half is covered as well.
        let c = recipient_binding(did, &key_of(0x11, 2));
        assert_ne!(a, c);
    }

    #[test]
    fn length_prefix_stops_did_key_boundary_confusion() {
        let key = key_of(0, 0);
        assert_ne!(
            recipient_binding("ab", &key),
            recipient_binding("a", &key),
            "a shorter DID must not collide with a longer one"
        );
    }
}
