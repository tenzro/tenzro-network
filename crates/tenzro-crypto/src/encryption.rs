//! Encryption primitives for Tenzro Network.
//!
//! Provides AES-256-GCM for symmetric encryption and X25519 for key exchange.
//!
//! Every X25519 exchange feeds HKDF-SHA256 before the result reaches a cipher.
//! The raw scalar-multiplication output is a curve point with algebraic
//! structure, not a uniformly distributed key, and RFC 7748 §6.1 requires the
//! hash step. Envelope encryption additionally salts the derivation with the
//! `(ephemeral, recipient)` public-key transcript, in the manner of the HPKE
//! KEM context (RFC 9180 §4.1), so one exchange cannot be replayed against a
//! different recipient.

use crate::error::{CryptoError, Result};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
pub use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::{SharedSecret, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Size of AES-256 key in bytes
pub const AES_KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// HKDF `info` for the general-purpose key derived from an X25519 exchange.
const DH_HKDF_INFO: &[u8] = b"tenzro/x25519/shared-key";

/// HKDF-SHA256 extract-then-expand (RFC 5869) down to a 32-byte AEAD key.
///
/// An empty `salt` selects HKDF's all-zero default rather than a zero-length
/// salt string; the two are the same value but only the former is what RFC
/// 5869 §2.2 specifies for "salt not provided".
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; AES_KEY_SIZE] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; AES_KEY_SIZE];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand rejects lengths above 255*32 bytes; 32 is not one");
    okm
}

/// Symmetric encryption key for Tenzro Network (zeroized on drop).
#[derive(Clone)]
pub struct SymmetricKey {
    key: [u8; AES_KEY_SIZE],
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SymmetricKey {
    /// Generate a new random symmetric key
    pub fn generate() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AES_KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid key size: expected {}, got {}",
                AES_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Get key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; AES_KEY_SIZE] {
        self.key
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.key));

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(CryptoError::InvalidCiphertext(
                "Ciphertext too short".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.key));

        // Extract nonce and ciphertext
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&ciphertext[..NONCE_SIZE]);
        let nonce = Nonce::from(nonce_bytes);
        let ct = &ciphertext[NONCE_SIZE..];

        // Decrypt
        let plaintext = cipher
            .decrypt(&nonce, ct)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// X25519 key exchange keypair for Tenzro Network.
pub struct X25519KeyPair {
    secret: X25519StaticSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new X25519 keypair
    pub fn generate() -> Self {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from secret bytes
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidSecretKey(format!(
                "Invalid X25519 secret key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(bytes);
        let secret = X25519StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Get the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Raw X25519 scalar multiplication.
    ///
    /// The result is a curve point, not a uniformly distributed 256-bit
    /// string, so RFC 7748 §6.1 requires it to pass through a hash before it
    /// can act as a key. This stays private for that reason — callers reach
    /// it through [`Self::diffie_hellman`] or the envelope helpers, both of
    /// which apply HKDF.
    fn dh_raw(&self, their_public: &X25519PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }

    /// Perform a Diffie-Hellman exchange and derive a symmetric key from it.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SymmetricKey {
        let shared = self.dh_raw(their_public);
        SymmetricKey {
            key: hkdf_sha256(shared.as_bytes(), &[], DH_HKDF_INFO),
        }
    }
}

/// Version of [`EncryptedEnvelope`]: the data key is sealed to an X25519 +
/// ML-KEM-768 hybrid key ([`crate::hybrid_seal`]).
pub const ENVELOPE_VERSION: u8 = 2;

/// Context the data key of an envelope is sealed under.
const ENVELOPE_CONTEXT: &[u8] = b"tenzro/envelope/v2/data-key";

/// Encrypted envelope: a data key sealed to the recipient's hybrid key, and
/// the data under that key.
///
/// The data key's wrapping key is HKDF-SHA256 over the X25519 and ML-KEM-768
/// shared secrets, salted with a transcript of the recipient key, the
/// sender's X25519 share, the ML-KEM-768 ciphertext and the envelope's
/// context. Reading the data needs both exchanges broken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// [`ENVELOPE_VERSION`].
    pub version: u8,
    /// The data key, sealed to the recipient's hybrid key.
    pub sealed_key: crate::hybrid_seal::HybridSealed,
    /// The data, encrypted with the data key.
    pub encrypted_data: Vec<u8>,
}

/// Encrypt data to the hybrid key `recipient` using envelope encryption.
pub fn envelope_encrypt(
    recipient: &crate::hybrid_seal::HybridPublicKey,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope> {
    let data_key = SymmetricKey::generate();
    let encrypted_data = data_key.encrypt(plaintext)?;
    let sealed_key = crate::hybrid_seal::seal(recipient, ENVELOPE_CONTEXT, &data_key.to_bytes())?;
    Ok(EncryptedEnvelope {
        version: ENVELOPE_VERSION,
        sealed_key,
        encrypted_data,
    })
}

/// Decrypt data using envelope encryption. Refuses an envelope of another
/// version.
pub fn envelope_decrypt(
    recipient: &dyn crate::hybrid_seal::HybridRecipient,
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>> {
    if envelope.version != ENVELOPE_VERSION {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope version {} is not {ENVELOPE_VERSION}",
            envelope.version
        )));
    }
    let data_key_bytes =
        crate::hybrid_seal::open_with(recipient, &envelope.sealed_key, ENVELOPE_CONTEXT)?;
    let data_key = SymmetricKey::from_bytes(&data_key_bytes)?;
    data_key.decrypt(&envelope.encrypted_data)
}

/// Encrypt bytes with AES-256-GCM using a symmetric key.
pub fn encrypt_aes(key: &SymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    key.encrypt(plaintext)
}

/// Decrypt bytes with AES-256-GCM using a symmetric key.
pub fn decrypt_aes(key: &SymmetricKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    key.decrypt(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_encryption() {
        let key = SymmetricKey::generate();
        let plaintext = b"Tenzro Network confidential data";

        let ciphertext = key.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_symmetric_key_from_bytes() {
        let key1 = SymmetricKey::generate();
        let bytes = key1.to_bytes();
        let key2 = SymmetricKey::from_bytes(&bytes).unwrap();

        let plaintext = b"test";
        let ciphertext = key1.encrypt(plaintext).unwrap();
        let decrypted = key2.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        // Both should derive the same shared secret
        assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());
    }

    #[test]
    fn test_dh_key_is_not_the_raw_curve_point() {
        // Guards the RFC 7748 §6.1 hash step. Handing the scalar-multiplication
        // output straight to AES-GCM is the failure this asserts against, and
        // it is invisible at runtime: the raw point is 32 bytes and encrypts
        // and decrypts perfectly well.
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let raw = alice.dh_raw(bob.public_key());
        let derived = alice.diffie_hellman(bob.public_key());

        assert_ne!(*raw.as_bytes(), derived.to_bytes());
    }

    use crate::hybrid_seal::{HybridPublicKey, HybridRecipient, HybridSecretKey};
    use zeroize::Zeroizing;

    #[test]
    fn test_envelope_encryption() {
        let recipient = HybridSecretKey::generate();
        let plaintext = b"Tenzro Network secret message";

        let envelope = envelope_encrypt(recipient.public(), plaintext).unwrap();
        assert_eq!(envelope.version, ENVELOPE_VERSION);
        let decrypted = envelope_decrypt(&recipient, &envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_envelope_wrong_recipient() {
        let recipient1 = HybridSecretKey::generate();
        let recipient2 = HybridSecretKey::generate();

        let envelope = envelope_encrypt(recipient1.public(), b"secret").unwrap();

        assert!(envelope_decrypt(&recipient2, &envelope).is_err());
    }

    /// Every part of an envelope is bound: a changed version, X25519 share,
    /// ML-KEM-768 ciphertext, sealed key or data is refused.
    #[test]
    fn test_envelope_tamper_cases() {
        let recipient = HybridSecretKey::generate();
        let envelope = envelope_encrypt(recipient.public(), b"secret").unwrap();
        envelope_decrypt(&recipient, &envelope).unwrap();

        let mut version = envelope.clone();
        version.version = 1;
        assert!(envelope_decrypt(&recipient, &version).is_err());

        let mut share = envelope.clone();
        share.sealed_key.x25519_share = HybridSecretKey::generate().public().x25519;
        assert!(envelope_decrypt(&recipient, &share).is_err());

        let mut kem = envelope.clone();
        kem.sealed_key.ml_kem_ciphertext[7] ^= 0x80;
        assert!(envelope_decrypt(&recipient, &kem).is_err());

        let mut short_kem = envelope.clone();
        short_kem.sealed_key.ml_kem_ciphertext.pop();
        assert!(envelope_decrypt(&recipient, &short_kem).is_err());

        let mut wrapped = envelope.clone();
        let last = wrapped.sealed_key.ciphertext.len() - 1;
        wrapped.sealed_key.ciphertext[last] ^= 1;
        assert!(envelope_decrypt(&recipient, &wrapped).is_err());

        let mut data = envelope.clone();
        let last = data.encrypted_data.len() - 1;
        data.encrypted_data[last] ^= 1;
        assert!(envelope_decrypt(&recipient, &data).is_err());
    }

    /// A recipient whose two exchanges are given separately, to model an
    /// attacker who has broken one.
    struct SplitRecipient<'a> {
        public: HybridPublicKey,
        x25519: &'a dyn HybridRecipient,
        ml_kem: Option<&'a dyn HybridRecipient>,
    }

    impl HybridRecipient for SplitRecipient<'_> {
        fn public_key(&self) -> HybridPublicKey {
            self.public.clone()
        }
        fn agree_x25519(&self, share: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
            self.x25519.agree_x25519(share)
        }
        fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            match self.ml_kem {
                Some(kem) => kem.decapsulate(ciphertext),
                // The attacker has no ML-KEM secret and guesses one.
                None => Ok(Zeroizing::new([0u8; 32])),
            }
        }
    }

    /// Either leg alone cannot recover the key: with the real X25519 secret
    /// (a broken classical leg) and a guessed ML-KEM secret, or the real
    /// ML-KEM secret and a guessed X25519 secret, the envelope stays shut.
    #[test]
    fn test_either_leg_alone_cannot_open_an_envelope() {
        let recipient = HybridSecretKey::generate();
        let envelope = envelope_encrypt(recipient.public(), b"content key").unwrap();

        let classical_broken = SplitRecipient {
            public: recipient.public().clone(),
            x25519: &recipient,
            ml_kem: None,
        };
        assert!(envelope_decrypt(&classical_broken, &envelope).is_err());

        // The ML-KEM leg alone: a different key's X25519 half.
        let stranger = HybridSecretKey::generate();
        let pq_only = SplitRecipient {
            public: recipient.public().clone(),
            x25519: &stranger,
            ml_kem: Some(&recipient),
        };
        assert!(envelope_decrypt(&pq_only, &envelope).is_err());

        // Both legs together open it.
        let both = SplitRecipient {
            public: recipient.public().clone(),
            x25519: &recipient,
            ml_kem: Some(&recipient),
        };
        assert_eq!(envelope_decrypt(&both, &envelope).unwrap(), b"content key");
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let key = SymmetricKey::generate();
        let invalid = b"invalid ciphertext";

        let result = key.decrypt(invalid);
        assert!(result.is_err());
    }
}
