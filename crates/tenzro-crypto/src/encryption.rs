//! Encryption primitives for Tenzro Network.
//!
//! Provides AES-256-GCM for symmetric encryption and X25519 for key exchange.

use crate::error::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
pub use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::StaticSecret as X25519StaticSecret;
use zeroize::Zeroize;

/// Size of AES-256 key in bytes
pub const AES_KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes
pub const NONCE_SIZE: usize = 12;

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

    /// Perform Diffie-Hellman key exchange to derive a shared secret
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SymmetricKey {
        let shared_secret = self.secret.diffie_hellman(their_public);
        SymmetricKey {
            key: shared_secret.to_bytes(),
        }
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
/// This creates a random data key, encrypts the data with it,
/// then encrypts the data key using Diffie-Hellman with the recipient's public key.
pub fn envelope_encrypt(
    recipient_public_key: &X25519PublicKey,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope> {
    // Generate ephemeral keypair for this encryption
    let ephemeral = X25519KeyPair::generate();

    // Derive shared secret
    let shared_secret = ephemeral.diffie_hellman(recipient_public_key);

    // Generate random data key
    let data_key = SymmetricKey::generate();

    // Encrypt the plaintext with the data key
    let encrypted_data = data_key.encrypt(plaintext)?;

    // Encrypt the data key with the shared secret
    let encrypted_key = shared_secret.encrypt(&data_key.to_bytes())?;

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
    // Parse sender's public key
    let sender_public = X25519PublicKey::from(envelope.sender_public_key);

    // Derive shared secret
    let shared_secret = recipient_keypair.diffie_hellman(&sender_public);

    // Decrypt the data key
    let data_key_bytes = shared_secret.decrypt(&envelope.encrypted_key)?;
    let data_key = SymmetricKey::from_bytes(&data_key_bytes)?;

    // Decrypt the data
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
