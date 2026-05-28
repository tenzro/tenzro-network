//! Key management for Tenzro Network.
//!
//! Supports Ed25519 (for native signatures) and Secp256k1 (for EVM compatibility).

use crate::error::{CryptoError, Result};
use crate::hash::keccak256;
use ed25519_dalek::{
    SigningKey as Ed25519SigningKey,
    SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH,
};
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key type supported by Tenzro Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 signature scheme (native)
    Ed25519,
    /// Secp256k1 signature scheme (EVM compatible)
    Secp256k1,
}

/// Public key for Tenzro Network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    key_type: KeyType,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Create a new public key
    pub fn new(key_type: KeyType, bytes: Vec<u8>) -> Self {
        Self { key_type, bytes }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from hex string
    pub fn from_hex(key_type: KeyType, s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self::new(key_type, bytes))
    }

    /// Derive an address from this public key.
    ///
    /// For Ed25519: first 20 bytes of the SHA-256 hash of the public key.
    /// For Secp256k1: last 20 bytes of the Keccak-256 hash of the public key
    /// (Ethereum-style).
    pub fn to_address(&self) -> Address {
        match self.key_type {
            KeyType::Ed25519 => {
                let hash = crate::hash::sha256(&self.bytes);
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&hash.as_bytes()[..20]);
                Address::new(addr_bytes)
            }
            KeyType::Secp256k1 => {
                // Ethereum-style address: last 20 bytes of Keccak-256 hash
                let hash = keccak256(&self.bytes);
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&hash.as_bytes()[12..]);
                Address::new(addr_bytes)
            }
        }
    }
}

/// Secret key for Tenzro Network (zeroized on drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    key_type: KeyType,
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Create a new secret key
    pub fn new(key_type: KeyType, bytes: Vec<u8>) -> Self {
        Self { key_type, bytes }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes (use with caution)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Convert to hex string (use with caution)
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from hex string
    pub fn from_hex(key_type: KeyType, s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self::new(key_type, bytes))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("key_type", &self.key_type)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Address derived from a public key (20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address([u8; 20]);

impl Address {
    /// Create a new address
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 20 {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid address length: expected 20, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get as array
    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    /// Convert to hex string (with 0x prefix)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A keypair for Tenzro Network.
pub struct KeyPair {
    key_type: KeyType,
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new keypair of the specified type.
    pub fn generate(key_type: KeyType) -> Result<Self> {
        match key_type {
            KeyType::Ed25519 => {
                let signing_key = Ed25519SigningKey::generate(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                let secret_key = SecretKey::new(
                    KeyType::Ed25519,
                    signing_key.to_bytes().to_vec(),
                );
                let public_key = PublicKey::new(
                    KeyType::Ed25519,
                    verifying_key.to_bytes().to_vec(),
                );

                Ok(Self {
                    key_type,
                    secret_key,
                    public_key,
                })
            }
            KeyType::Secp256k1 => {
                let signing_key = Secp256k1SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                let secret_key = SecretKey::new(
                    KeyType::Secp256k1,
                    signing_key.to_bytes().to_vec(),
                );

                // Use uncompressed public key (65 bytes)
                let public_key_point = verifying_key.to_encoded_point(false);
                let public_key = PublicKey::new(
                    KeyType::Secp256k1,
                    public_key_point.as_bytes().to_vec(),
                );

                Ok(Self {
                    key_type,
                    secret_key,
                    public_key,
                })
            }
        }
    }

    /// Create a keypair from a secret key.
    pub fn from_secret_key(secret_key: SecretKey) -> Result<Self> {
        let key_type = secret_key.key_type();

        match key_type {
            KeyType::Ed25519 => {
                if secret_key.bytes.len() != ED25519_SECRET_KEY_LENGTH {
                    return Err(CryptoError::InvalidSecretKey(format!(
                        "Invalid Ed25519 secret key length: expected {}, got {}",
                        ED25519_SECRET_KEY_LENGTH,
                        secret_key.bytes.len()
                    )));
                }

                let secret_bytes: [u8; ED25519_SECRET_KEY_LENGTH] = secret_key.bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidSecretKey("Invalid length".to_string()))?;

                let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
                let verifying_key = signing_key.verifying_key();

                let public_key = PublicKey::new(
                    KeyType::Ed25519,
                    verifying_key.to_bytes().to_vec(),
                );

                Ok(Self {
                    key_type,
                    secret_key,
                    public_key,
                })
            }
            KeyType::Secp256k1 => {
                if secret_key.bytes.len() != 32 {
                    return Err(CryptoError::InvalidSecretKey(format!(
                        "Invalid Secp256k1 secret key length: expected 32, got {}",
                        secret_key.bytes.len()
                    )));
                }

                let secret_bytes: [u8; 32] = secret_key.bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidSecretKey("Invalid length".to_string()))?;

                let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                let verifying_key = signing_key.verifying_key();

                // Use uncompressed public key (65 bytes)
                let public_key_point = verifying_key.to_encoded_point(false);
                let public_key = PublicKey::new(
                    KeyType::Secp256k1,
                    public_key_point.as_bytes().to_vec(),
                );

                Ok(Self {
                    key_type,
                    secret_key,
                    public_key,
                })
            }
        }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Get the address derived from the public key
    pub fn address(&self) -> Address {
        self.public_key.to_address()
    }

    /// Export the keypair to bytes (secret key only, public key can be derived)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes()
    }

    /// Import a keypair from bytes
    pub fn from_bytes(key_type: KeyType, bytes: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::new(key_type, bytes.to_vec());
        Self::from_secret_key(secret_key)
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("key_type", &self.key_type)
            .field("public_key", &self.public_key)
            .field("address", &self.address())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_keypair() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Ed25519);
        assert_eq!(keypair.public_key().as_bytes().len(), 32); // Ed25519 public key is 32 bytes
        assert_eq!(keypair.secret_key().as_bytes().len(), ED25519_SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_generate_secp256k1_keypair() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Secp256k1);
        assert_eq!(keypair.public_key().as_bytes().len(), 65); // Uncompressed
        assert_eq!(keypair.secret_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_address_derivation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = keypair.address();
        assert_eq!(address.as_bytes().len(), 20);
    }

    #[test]
    fn test_address_hex() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let address = keypair.address();
        let hex = address.to_hex();
        assert!(hex.starts_with("0x"));
        let decoded = Address::from_hex(&hex).unwrap();
        assert_eq!(address, decoded);
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.to_bytes();
        let restored = KeyPair::from_bytes(KeyType::Ed25519, &bytes).unwrap();
        assert_eq!(keypair.public_key(), restored.public_key());
        assert_eq!(keypair.address(), restored.address());
    }
}
