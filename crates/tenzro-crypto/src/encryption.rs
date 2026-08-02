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

/// HKDF `info` for the key-wrapping key of an [`EncryptedEnvelope`].
const ENVELOPE_HKDF_INFO: &[u8] = b"tenzro/x25519/envelope/key-wrap";

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

/// Derive the key that wraps an envelope's data key.
///
/// The HKDF salt is the exchange transcript — ephemeral public key then
/// recipient public key, in that order — so a shared secret computed for one
/// (sender, recipient) pair cannot be replayed against a different pair. Both
/// sides can reconstruct it: the sender from its own ephemeral key, the
/// recipient from `EncryptedEnvelope::sender_public_key` and its own key.
/// This mirrors the KEM context in HPKE (RFC 9180 §4.1).
fn envelope_wrap_key(
    shared: &SharedSecret,
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> SymmetricKey {
    let mut transcript = [0u8; 64];
    transcript[..32].copy_from_slice(ephemeral_public);
    transcript[32..].copy_from_slice(recipient_public);
    SymmetricKey {
        key: hkdf_sha256(shared.as_bytes(), &transcript, ENVELOPE_HKDF_INFO),
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public", &hex::encode(self.public.as_bytes()))
            .finish()
    }
}

/// Encrypted envelope containing encrypted data and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Encrypted data key (encrypted with recipient's public key)
    pub encrypted_key: Vec<u8>,
    /// Encrypted data (encrypted with the data key)
    pub encrypted_data: Vec<u8>,
    /// Sender's ephemeral public key
    pub sender_public_key: [u8; 32],
}

/// Encrypt data using envelope encryption.
///
/// Generates a random data key and encrypts the plaintext with it, then wraps
/// that data key under [`envelope_wrap_key`] — an ephemeral-static X25519
/// exchange against the recipient, run through HKDF-SHA256 salted with the
/// exchange transcript.
pub fn envelope_encrypt(
    recipient_public_key: &X25519PublicKey,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope> {
    let ephemeral = X25519KeyPair::generate();
    let wrap_key = envelope_wrap_key(
        &ephemeral.dh_raw(recipient_public_key),
        &ephemeral.public_key_bytes(),
        recipient_public_key.as_bytes(),
    );

    let data_key = SymmetricKey::generate();
    let encrypted_data = data_key.encrypt(plaintext)?;
    let encrypted_key = wrap_key.encrypt(&data_key.to_bytes())?;

    Ok(EncryptedEnvelope {
        encrypted_key,
        encrypted_data,
        sender_public_key: ephemeral.public_key_bytes(),
    })
}

/// Decrypt data using envelope encryption.
pub fn envelope_decrypt(
    recipient_keypair: &X25519KeyPair,
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>> {
    let sender_public = X25519PublicKey::from(envelope.sender_public_key);
    let wrap_key = envelope_wrap_key(
        &recipient_keypair.dh_raw(&sender_public),
        &envelope.sender_public_key,
        &recipient_keypair.public_key_bytes(),
    );

    let mut data_key_bytes = wrap_key.decrypt(&envelope.encrypted_key)?;
    let data_key = SymmetricKey::from_bytes(&data_key_bytes)?;
    data_key_bytes.zeroize();

    let plaintext = data_key.decrypt(&envelope.encrypted_data)?;

    Ok(plaintext)
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

    #[test]
    fn test_envelope_wrap_key_binds_the_transcript() {
        // The same shared secret salted with a different recipient must not
        // produce the same wrapping key, otherwise an envelope addressed to
        // one party could be re-pointed at another.
        let ephemeral = X25519KeyPair::generate();
        let recipient = X25519KeyPair::generate();
        let other = X25519KeyPair::generate();

        let shared = ephemeral.dh_raw(recipient.public_key());
        let bound = envelope_wrap_key(
            &shared,
            &ephemeral.public_key_bytes(),
            recipient.public_key().as_bytes(),
        );
        let rebound = envelope_wrap_key(
            &shared,
            &ephemeral.public_key_bytes(),
            other.public_key().as_bytes(),
        );

        assert_ne!(bound.to_bytes(), rebound.to_bytes());
    }

    #[test]
    fn test_envelope_rejects_substituted_sender_key() {
        // Swapping the ephemeral public key changes the transcript, so the
        // recipient derives a different wrapping key and the AEAD tag fails.
        let recipient = X25519KeyPair::generate();
        let mut envelope = envelope_encrypt(recipient.public_key(), b"secret").unwrap();

        envelope.sender_public_key = X25519KeyPair::generate().public_key_bytes();

        assert!(envelope_decrypt(&recipient, &envelope).is_err());
    }

    #[test]
    fn test_envelope_encryption() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"Tenzro Network secret message";

        let envelope = envelope_encrypt(recipient.public_key(), plaintext).unwrap();
        let decrypted = envelope_decrypt(&recipient, &envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_envelope_wrong_recipient() {
        let recipient1 = X25519KeyPair::generate();
        let recipient2 = X25519KeyPair::generate();
        let plaintext = b"secret";

        let envelope = envelope_encrypt(recipient1.public_key(), plaintext).unwrap();
        let result = envelope_decrypt(&recipient2, &envelope);

        // Should fail to decrypt with wrong key
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let key = SymmetricKey::generate();
        let invalid = b"invalid ciphertext";

        let result = key.decrypt(invalid);
        assert!(result.is_err());
    }
}
