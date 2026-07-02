//! [`PqCompanion`] — an ML-DSA-65 post-quantum signing key that rides alongside
//! the Secure Enclave P-256 passkey.
//!
//! The hybrid passkey custody scheme (`WebAuthnValidator` on tenzro-network)
//! requires every enrolled account to carry a companion ML-DSA-65 verifying key
//! and to produce an ML-DSA-65 signature leg on every operation, so a future
//! cryptographically-relevant quantum computer cannot forge the P-256 leg alone.
//!
//! ## Why the seed is sealed to the enclave key
//!
//! ML-DSA-65 has no hardware backing on current Apple silicon, so the seed must
//! live somewhere. Rather than store it in plaintext, we ECIES-wrap the 32-byte
//! FIPS-204 seed to the device's Secure Enclave key (the same `wrap_secret` /
//! `unwrap_secret` primitive [`SecureEnclaveUnlocker`] uses for the keystore
//! password). The wrapped ciphertext is written to disk next to the wallet
//! keystore; the plaintext seed only ever exists transiently in memory and is
//! zeroized on drop.
//!
//! ## Lifecycle
//!
//! - **Create:** generate a fresh ML-DSA-65 seed, `wrap_secret` it to the SE key
//!   (no biometric prompt — encryption only needs the public key), persist the
//!   ciphertext, return the verifying key for on-chain enrollment.
//! - **Open / sign:** read the ciphertext, [`crate::open`] the SE key (reopened
//!   by label from the file keychain — see crate docs), `unwrap_secret` (Touch
//!   ID) to recover the seed, rebuild the signing key.
//!
//! Persistence matches [`SecureEnclaveUnlocker`]: a plain Developer-ID build
//! persists the SE key in the file keychain and reopens it across restarts. If
//! the key is gone (different machine / reset login keychain), a later `open`
//! returns [`DeviceKeyError::NotFound`].

use std::path::{Path, PathBuf};

use tenzro_crypto::pq::{MlDsaSigningKey, ML_DSA_65_VK_LEN};

use crate::{DeviceKeyError, Result};

/// Default device-key label used to seal the ML-DSA companion seed. Distinct
/// from the keystore-unlock label so the two ciphertexts bind to separate keys.
pub const DEFAULT_PQ_LABEL: &str = "tenzro-pq-companion";

/// Deterministic credential id for a passkey: the SHA-256 of its device-key
/// label. Stable across runs so `signWithPasskey` can locate the credential
/// without persisting an extra identifier. Re-exported so embedders don't need
/// a direct `tenzro-crypto` dependency just to compute it.
pub fn credential_id_for_label(label: &str) -> [u8; 32] {
    tenzro_crypto::sha256(label.as_bytes()).to_bytes()
}

/// An ML-DSA-65 companion key whose seed is sealed to a Secure Enclave key.
pub struct PqCompanion {
    label: String,
    ciphertext_path: PathBuf,
    signing_key: MlDsaSigningKey,
}

impl PqCompanion {
    /// Generate a fresh companion key, seal its seed to the SE key tagged
    /// `label`, and persist the wrapped seed at `ciphertext_path`.
    ///
    /// Returns the live companion; call [`Self::verifying_key_bytes`] for the
    /// 1952-byte ML-DSA-65 public key to hand to `tenzro_enrollPasskey`.
    pub fn create(label: impl Into<String>, ciphertext_path: impl Into<PathBuf>) -> Result<Self> {
        let label = label.into();
        let ciphertext_path = ciphertext_path.into();

        let signing_key = MlDsaSigningKey::generate();
        let key = crate::create(&label)?;
        // wrap_secret encrypts to the SE key's public key — no biometric prompt.
        let ct = key.wrap_secret(signing_key.seed_bytes())?;
        write_ciphertext(&ciphertext_path, &ct)?;

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

        let ct = std::fs::read(&ciphertext_path).map_err(|e| {
            DeviceKeyError::NotFound(format!(
                "no ML-DSA companion ciphertext at {}: {e}",
                ciphertext_path.display()
            ))
        })?;
        let key = crate::open(&label)?;
        let seed = key.unwrap_secret(&ct)?;
        let signing_key = MlDsaSigningKey::from_seed(&seed)
            .map_err(|e| DeviceKeyError::Enclave(format!("rebuild ML-DSA key: {e}")))?;

        Ok(Self {
            label,
            ciphertext_path,
            signing_key,
        })
    }

    /// Convenience: seal the companion seed as `pq-companion.seed.enc` under
    /// `data_dir` with the default label.
    pub fn create_under_data_dir(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::create(DEFAULT_PQ_LABEL, companion_path(data_dir))
    }

    /// Convenience: reopen the companion sealed by [`Self::create_under_data_dir`].
    pub fn open_under_data_dir(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open(DEFAULT_PQ_LABEL, companion_path(data_dir))
    }

    /// The 1952-byte ML-DSA-65 verifying key (FIPS-204 §4 Table 2). This is the
    /// `ml_dsa_public_key_hex` value `tenzro_enrollPasskey` expects.
    pub fn verifying_key_bytes(&self) -> &[u8] {
        debug_assert_eq!(self.signing_key.verifying_key_bytes().len(), ML_DSA_65_VK_LEN);
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

fn write_ciphertext(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| DeviceKeyError::Enclave(format!("create dir: {e}")))?;
    }
    std::fs::write(path, bytes)
        .map_err(|e| DeviceKeyError::Enclave(format!("write companion ciphertext: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::{ml_dsa_verify, ML_DSA_65_SIG_LEN};

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
