//! [`PqCompanion`] — an ML-DSA-65 post-quantum signing key that rides alongside
//! the Secure Enclave P-256 passkey.
//!
//! The hybrid passkey custody scheme (`WebAuthnValidator` on tenzro-network)
//! requires every enrolled account to carry a companion ML-DSA-65 verifying key
//! and to produce an ML-DSA-65 signature leg on every operation, so a future
//! cryptographically-relevant quantum computer cannot forge the P-256 leg alone.
//!
//! ## Why the seed is sealed to more than the enclave key
//!
//! ML-DSA-65 has no hardware backing on current Apple silicon, so the seed must
//! live somewhere. It is sealed into a [`crate::SealedSecret`] — a
//! `tenzro-envelope/v2` addressed to this device's enclave **and** to a recovery
//! recipient the operator holds.
//!
//! Sealing it to the enclave alone would be indefensible here specifically: the
//! verifying key derived from this seed is **enrolled on-chain as a permanent
//! identity**, so losing the seed does not lose a cache — it strands the
//! account, with no way to produce the PQ signature leg every operation
//! requires. A dead logic board would be terminal. Of everything this crate
//! holds, this is the secret least able to tolerate a single point of failure.
//!
//! The plaintext seed exists only transiently in memory and is zeroized on drop.
//!
//! ## Lifecycle
//!
//! - **Enrol:** generate a fresh ML-DSA-65 seed and seal it to the enclave plus
//!   the caller's recovery recipient. Sealing needs no hardware and prompts for
//!   nothing. Returns the verifying key for on-chain enrollment.
//! - **Open / sign:** open the envelope with the enclave, rebuild the signing key.
//! - **Recover:** [`Self::open_with`] takes any recipient, so a machine whose
//!   enclave is gone can still rebuild the identity from the recovery code.

use std::path::{Path, PathBuf};

use tenzro_crypto::pq::{ML_DSA_65_VK_LEN, MlDsaSigningKey};

use crate::envelope::{Decapsulator, Recipient};
use crate::{DeviceKeyError, Result, SealedSecret};

/// Default device-key label used to seal the ML-DSA companion seed. Distinct
/// from the keystore-unlock label so the two ciphertexts bind to separate keys.
pub const DEFAULT_PQ_LABEL: &str = "tenzro-pq-companion";

/// An ML-DSA-65 companion key whose seed is sealed to a Secure Enclave key.
pub struct PqCompanion {
    label: String,
    ciphertext_path: PathBuf,
    signing_key: MlDsaSigningKey,
}

impl PqCompanion {
    /// Generate a fresh companion key and seal its seed to this device's
    /// enclave **and** `recovery`.
    ///
    /// `recovery` is not optional and is not generated for you: the operator has
    /// to keep the matching recovery code. A code minted here and discarded
    /// would look like redundancy while providing none — worse than none, since
    /// it would stop anyone asking the question again.
    ///
    /// Returns the live companion; call [`Self::verifying_key_bytes`] for the
    /// 1952-byte ML-DSA-65 public key to hand to `tenzro_enrollPasskey`.
    pub fn enrol(
        label: impl Into<String>,
        ciphertext_path: impl Into<PathBuf>,
        recovery: &Recipient,
    ) -> Result<Self> {
        let label = label.into();
        let ciphertext_path = ciphertext_path.into();

        let signing_key = MlDsaSigningKey::generate();
        let sealed = SealedSecret::new(label.clone(), ciphertext_path.clone());
        // Sealing is public-key-only: no enclave round-trip, no biometric prompt.
        // `false` keeps the enclave key usable from a headless node.
        sealed.enrol(signing_key.seed_bytes(), recovery, false)?;

        Ok(Self {
            label,
            ciphertext_path,
            signing_key,
        })
    }

    /// Reopen a previously-created companion by unsealing its seed. Triggers the
    /// Touch ID prompt (the unwrap is a private-key operation). Fails with
    /// [`DeviceKeyError::NotFound`] if no ciphertext exists or the SE key is no
    /// longer in the keychain (e.g. a different machine or a reset login keychain).
    pub fn open(label: impl Into<String>, ciphertext_path: impl Into<PathBuf>) -> Result<Self> {
        let label = label.into();
        let ciphertext_path = ciphertext_path.into();
        let sealed = SealedSecret::new(label.clone(), ciphertext_path.clone());
        let seed = sealed.open()?;
        Self::from_seed(label, ciphertext_path, &seed)
    }

    /// Rebuild the companion using any recipient — in practice the recovery key,
    /// on a machine whose enclave is gone. This is the path that makes an
    /// on-chain identity survive hardware death.
    pub fn open_with(
        label: impl Into<String>,
        ciphertext_path: impl Into<PathBuf>,
        d: &dyn Decapsulator,
    ) -> Result<Self> {
        let label = label.into();
        let ciphertext_path = ciphertext_path.into();
        let sealed = SealedSecret::new(label.clone(), ciphertext_path.clone());
        let seed = sealed.open_with(d)?;
        Self::from_seed(label, ciphertext_path, &seed)
    }

    /// Re-seal the seed to this device's enclave plus `recovery`, with a fresh
    /// CEK. Use after re-enrolling on new hardware, or to retire a recovery code.
    /// The ML-DSA identity is unchanged — only the envelope around it.
    pub fn rotate(&self, opener: &dyn Decapsulator, recovery: &Recipient) -> Result<()> {
        SealedSecret::new(self.label.clone(), self.ciphertext_path.clone())
            .rotate(opener, recovery, false)
    }

    fn from_seed(label: String, ciphertext_path: PathBuf, seed: &[u8]) -> Result<Self> {
        let signing_key = MlDsaSigningKey::from_seed(seed)
            .map_err(|e| DeviceKeyError::Enclave(format!("rebuild ML-DSA key: {e}")))?;
        Ok(Self {
            label,
            ciphertext_path,
            signing_key,
        })
    }

    /// Convenience: seal the companion seed as `pq-companion.seed.enc` under
    /// `data_dir` with the default label.
    pub fn enrol_under_data_dir(data_dir: impl AsRef<Path>, recovery: &Recipient) -> Result<Self> {
        Self::enrol(DEFAULT_PQ_LABEL, companion_path(data_dir), recovery)
    }

    /// Convenience: reopen the companion sealed by [`Self::create_under_data_dir`].
    pub fn open_under_data_dir(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open(DEFAULT_PQ_LABEL, companion_path(data_dir))
    }

    /// The 1952-byte ML-DSA-65 verifying key (FIPS-204 §4 Table 2). This is the
    /// `ml_dsa_public_key_hex` value `tenzro_enrollPasskey` expects.
    pub fn verifying_key_bytes(&self) -> &[u8] {
        debug_assert_eq!(
            self.signing_key.verifying_key_bytes().len(),
            ML_DSA_65_VK_LEN
        );
        self.signing_key.verifying_key_bytes()
    }

    /// Sign `msg` with the companion key, returning the 3309-byte ML-DSA-65
    /// signature for the PQ leg of `tenzro_signWithPasskey`.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg)
    }

    /// The device-key label this companion's seed is sealed to.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The on-disk path of the wrapped seed.
    pub fn ciphertext_path(&self) -> &Path {
        &self.ciphertext_path
    }
}

fn companion_path(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join("pq-companion.seed.enc")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::{ML_DSA_65_SIG_LEN, ml_dsa_verify};

    // Constructs a companion directly from a seed, bypassing the Secure Enclave
    // so the seed-sealing path (which needs hardware) isn't exercised here. This
    // covers the crypto surface the enrollment flow depends on: the verifying
    // key is the right length and signatures verify against it.
    fn companion_from_seed(seed: &[u8]) -> PqCompanion {
        PqCompanion {
            label: "test".into(),
            ciphertext_path: PathBuf::from("/dev/null"),
            signing_key: MlDsaSigningKey::from_seed(seed).unwrap(),
        }
    }

    #[test]
    fn verifying_key_is_ml_dsa_65_length() {
        let c = companion_from_seed(&[7u8; 32]);
        assert_eq!(c.verifying_key_bytes().len(), ML_DSA_65_VK_LEN);
    }

    #[test]
    fn sign_produces_verifiable_ml_dsa_signature() {
        let c = companion_from_seed(&[9u8; 32]);
        let msg = b"tenzro_signWithPasskey pq leg";
        let sig = c.sign(msg);
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
        ml_dsa_verify(c.verifying_key_bytes(), msg, &sig).unwrap();
    }

    #[test]
    fn seed_is_deterministic_across_companions() {
        // Re-deriving from the same sealed seed must reproduce the same identity,
        // otherwise an account enrolled with one vk couldn't sign after reopen.
        let a = companion_from_seed(&[3u8; 32]);
        let b = companion_from_seed(&[3u8; 32]);
        assert_eq!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }
}
