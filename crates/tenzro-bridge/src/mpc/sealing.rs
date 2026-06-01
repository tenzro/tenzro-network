//! TEE-rooted sealing for DKLS23 share material.
//!
//! [`KeygenSession::run`](crate::mpc::keygen::KeygenSession::run) hands the
//! finalised `Party<C>` payload to a [`KeyshareSealer`] before persisting it
//! through [`KeyshareStore`](crate::mpc::store::KeyshareStore). The sealer is
//! injectable so the keygen driver itself stays free of `tenzro_tee` Cargo
//! features (TDX / SEV-SNP / Nitro / NVIDIA GPU) — production node startup
//! picks the right backend via [`KeyshareSealer::derive_auto`] and tests
//! inject a deterministic in-memory backend.
//!
//! ## Wire format
//!
//! The on-disk `sealed_payload` is the AES-256-GCM envelope:
//!
//! ```text
//! sealed_payload = nonce(12) || ciphertext || tag(16)
//! ```
//!
//! Mirrors the format used by `tenzro_tee::enclave_crypto`. The key is
//! derived per `(group_id, party_index)` via HKDF-SHA256 from a TEE root
//! (SNP `SNP_GET_DERIVED_KEY` or TDX MRTD) so that:
//!
//! - The same physical node redeploying the same image recovers the same
//!   key and can unseal its share without out-of-band recovery.
//! - Another tenant's VM, a tampered image, or an OS-level memory read
//!   cannot recover the key — only this exact enclave can unseal.
//! - Two distinct `(group_id, party_index)` pairs derive unrelated keys
//!   so a leak of one share envelope cannot help an attacker recover any
//!   other share on the same node.
//!
//! ## No simulation
//!
//! Per Tenzro's no-simulation-on-testnet policy,
//! [`KeyshareSealer::derive_auto`] returns
//! `KeyshareSealerError::TeeNotAvailable` on dev machines instead of
//! fabricating a deterministic in-memory key. Tests opt into
//! [`InMemoryKeyshareSealer`] explicitly.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::mpc::store::GroupId;

/// HKDF info string for the per-(group, party) AES-256 key derivation.
const HKDF_INFO: &[u8] = b"tenzro/mpc/keyshare/seal";

/// Salt prefix used when deriving the per-(group, party) seal key. The full
/// HKDF salt is `KEYSHARE_LABEL || group_id || party_index_byte` so two
/// shares on the same node have unrelated keys.
const KEYSHARE_LABEL: &[u8] = b"tenzro/mpc/keyshare";

/// AES-GCM nonce length (12 bytes per RFC 5116).
const NONCE_LEN: usize = 12;

/// Errors raised by [`KeyshareSealer`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum KeyshareSealerError {
    /// No TEE backend available on this host (dev machine, CI without
    /// hardware, etc.). Production node startup must surface this as a
    /// startup failure, not silently fall back to a deterministic key.
    #[error("no TEE backend available for keyshare sealing")]
    TeeNotAvailable,
    /// AES-GCM seal failed (should be unreachable — surfaces underlying
    /// `aead` errors for diagnostics).
    #[error("AES-256-GCM seal failed: {0}")]
    Seal(String),
    /// AES-GCM unseal failed — typically a corrupt envelope or wrong
    /// `(group_id, party_index)` derivation context.
    #[error("AES-256-GCM unseal failed: {0}")]
    Unseal(String),
    /// HKDF expansion produced an unusable key (should be unreachable).
    #[error("HKDF key derivation failed: {0}")]
    KeyDerivation(String),
    /// Sealed envelope is shorter than `NONCE_LEN + tag_len`. Indicates
    /// truncated storage.
    #[error("sealed envelope too short ({0} bytes)")]
    TruncatedEnvelope(usize),
    /// Underlying TEE / OS error from the platform provider.
    #[error("TEE backend error: {0}")]
    Backend(String),
}

/// Seals and unseals arbitrary plaintext bytes (typically a bincode-encoded
/// `Party<C>`) under a TEE-rooted key derived per `(group_id, party_index)`.
///
/// Implementations are pure with respect to `(group_id, party_index)` —
/// repeated seal of the same plaintext under the same context produces a
/// fresh ciphertext (different nonce), but unseal always recovers the
/// original.
#[async_trait::async_trait]
pub trait KeyshareSealer: Send + Sync {
    /// Seal `plaintext` for `(group_id, party_index)`. Output is the
    /// `nonce(12) || ciphertext || tag(16)` envelope.
    async fn seal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError>;

    /// Unseal `sealed` for `(group_id, party_index)`. Returns the original
    /// plaintext.
    async fn unseal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError>;
}

/// In-memory sealer used by unit and integration tests. The root IKM is
/// supplied at construction; production code must NOT use this with a
/// fixed IKM.
///
/// Marked `#[doc(hidden)]` so it does not surface in the public API but
/// remains accessible from `#[cfg(test)]` blocks across the crate.
#[doc(hidden)]
pub struct InMemoryKeyshareSealer {
    ikm: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for InMemoryKeyshareSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose IKM material in Debug output.
        f.debug_struct("InMemoryKeyshareSealer")
            .field("ikm", &"<redacted>")
            .finish()
    }
}

impl InMemoryKeyshareSealer {
    /// Construct from an explicit 32-byte IKM. Tests use a deterministic
    /// IKM so repeated runs are reproducible; production code uses
    /// [`TeeKeyshareSealer`] which sources its IKM from the TEE provider.
    pub fn new(ikm: [u8; 32]) -> Self {
        Self {
            ikm: Zeroizing::new(ikm),
        }
    }

    /// Convenience constructor: seeds a fresh `OsRng` IKM. Useful in
    /// single-process integration tests where reproducibility across runs
    /// is not required.
    pub fn fresh() -> Self {
        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        Self::new(ikm)
    }

    fn derive_key(
        &self,
        group_id: &GroupId,
        party_index: u8,
    ) -> Result<Zeroizing<[u8; 32]>, KeyshareSealerError> {
        let mut salt = Vec::with_capacity(KEYSHARE_LABEL.len() + 32 + 1);
        salt.extend_from_slice(KEYSHARE_LABEL);
        salt.extend_from_slice(group_id.as_bytes());
        salt.push(party_index);

        let hk = Hkdf::<Sha256>::new(Some(&salt), self.ikm.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO, okm.as_mut())
            .map_err(|e| KeyshareSealerError::KeyDerivation(e.to_string()))?;
        Ok(okm)
    }
}

#[async_trait::async_trait]
impl KeyshareSealer for InMemoryKeyshareSealer {
    async fn seal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError> {
        let key = self.derive_key(group_id, party_index)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| KeyshareSealerError::Seal(e.to_string()))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KeyshareSealerError::Seal(e.to_string()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    async fn unseal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError> {
        if sealed.len() < NONCE_LEN + 16 {
            return Err(KeyshareSealerError::TruncatedEnvelope(sealed.len()));
        }
        let key = self.derive_key(group_id, party_index)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| KeyshareSealerError::Unseal(e.to_string()))?;
        let nonce = Nonce::from_slice(&sealed[..NONCE_LEN]);
        cipher
            .decrypt(nonce, &sealed[NONCE_LEN..])
            .map_err(|e| KeyshareSealerError::Unseal(e.to_string()))
    }
}

/// TEE-rooted sealer for production node startup.
///
/// Derives its IKM at construction from the available TEE provider via
/// `tenzro_tee::SealedSecp256k1Key`-style HKDF chains:
///
/// - **AMD SEV-SNP** — `SNP_GET_DERIVED_KEY(MEASUREMENT | IMAGE_ID | GUEST_SVN)`
/// - **Intel TDX** — MRTD as IKM
///
/// Per-share AES keys are then derived from this IKM via a second HKDF
/// pass salted by `(group_id, party_index)` (see [`InMemoryKeyshareSealer`]
/// for the salt format — both backends share the same per-share derivation
/// path so the only difference is the source of the 32-byte root IKM).
///
/// Concrete platform bindings land alongside the `tenzro-tee`
/// `intel-tdx` / `amd-sev-snp` features. Until those features are turned
/// on at the bridge layer, [`derive_auto`](Self::derive_auto) returns
/// `KeyshareSealerError::TeeNotAvailable`.
#[derive(Debug)]
pub struct TeeKeyshareSealer {
    inner: InMemoryKeyshareSealer,
}

impl TeeKeyshareSealer {
    /// Auto-detect the TEE platform and derive the 32-byte IKM.
    ///
    /// Returns `KeyshareSealerError::TeeNotAvailable` if no TEE backend
    /// is enabled at compile time or no hardware is present at runtime.
    /// Per the no-simulation policy, this is a startup-time failure for
    /// any node that must hold MPC share material.
    pub async fn derive_auto() -> Result<Self, KeyshareSealerError> {
        // The TEE-rooted IKM extraction is gated behind the same Cargo
        // features that `tenzro-tee::SealedSecp256k1Key` uses. When those
        // features are off, fail closed.
        #[cfg(any(feature = "intel-tdx", feature = "amd-sev-snp"))]
        {
            // Future wiring: pull a 32-byte IKM via
            // `tenzro_tee::SealedSecp256k1Key::derive_auto(b"tenzro/mpc/keyshare")`
            // and feed it into `InMemoryKeyshareSealer::new(ikm)`. The
            // public API surface defined here does not change.
            return Err(KeyshareSealerError::TeeNotAvailable);
        }

        #[cfg(not(any(feature = "intel-tdx", feature = "amd-sev-snp")))]
        Err(KeyshareSealerError::TeeNotAvailable)
    }

    /// Test-only constructor that pretends to be TEE-rooted. **Never call
    /// this from production code paths.**
    #[doc(hidden)]
    pub fn from_ikm_for_test(ikm: [u8; 32]) -> Self {
        Self {
            inner: InMemoryKeyshareSealer::new(ikm),
        }
    }
}

#[async_trait::async_trait]
impl KeyshareSealer for TeeKeyshareSealer {
    async fn seal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError> {
        self.inner.seal(group_id, party_index, plaintext).await
    }

    async fn unseal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyshareSealerError> {
        self.inner.unseal(group_id, party_index, sealed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_group() -> GroupId {
        GroupId([7u8; 32])
    }

    #[tokio::test]
    async fn seal_unseal_roundtrip() {
        let sealer = InMemoryKeyshareSealer::new([0x11; 32]);
        let g = sample_group();
        let pt = b"hello dkls share".to_vec();
        let sealed = sealer.seal(&g, 1, &pt).await.unwrap();
        let recovered = sealer.unseal(&g, 1, &sealed).await.unwrap();
        assert_eq!(pt, recovered);
    }

    #[tokio::test]
    async fn unseal_wrong_party_index_fails() {
        let sealer = InMemoryKeyshareSealer::new([0x11; 32]);
        let g = sample_group();
        let sealed = sealer.seal(&g, 1, b"abc").await.unwrap();
        // Party index is part of the key-derivation salt, so a different
        // index produces a different AES key and unseal must fail with a
        // GCM tag mismatch.
        let err = sealer.unseal(&g, 2, &sealed).await.unwrap_err();
        assert!(matches!(err, KeyshareSealerError::Unseal(_)));
    }

    #[tokio::test]
    async fn unseal_wrong_group_id_fails() {
        let sealer = InMemoryKeyshareSealer::new([0x11; 32]);
        let g1 = sample_group();
        let g2 = GroupId([8u8; 32]);
        let sealed = sealer.seal(&g1, 1, b"abc").await.unwrap();
        let err = sealer.unseal(&g2, 1, &sealed).await.unwrap_err();
        assert!(matches!(err, KeyshareSealerError::Unseal(_)));
    }

    #[tokio::test]
    async fn two_seals_produce_different_ciphertexts() {
        // Each seal must use a fresh random nonce so identical plaintext
        // under identical context still produces distinct envelopes —
        // guards against nonce reuse if a caller seals the same share
        // twice (e.g. retry after a transient storage failure).
        let sealer = InMemoryKeyshareSealer::new([0x11; 32]);
        let g = sample_group();
        let pt = b"same plaintext";
        let s1 = sealer.seal(&g, 1, pt).await.unwrap();
        let s2 = sealer.seal(&g, 1, pt).await.unwrap();
        assert_ne!(s1, s2);
    }

    #[tokio::test]
    async fn truncated_envelope_rejected() {
        let sealer = InMemoryKeyshareSealer::new([0x11; 32]);
        let g = sample_group();
        let short = vec![0u8; 10];
        let err = sealer.unseal(&g, 1, &short).await.unwrap_err();
        assert!(matches!(err, KeyshareSealerError::TruncatedEnvelope(10)));
    }

    #[tokio::test]
    async fn tee_derive_auto_off_hardware_fails() {
        // No simulation on testnet — derive_auto must NEVER silently
        // fabricate a key from thin air on a non-TEE host.
        let err = TeeKeyshareSealer::derive_auto().await.unwrap_err();
        assert!(matches!(err, KeyshareSealerError::TeeNotAvailable));
    }
}
