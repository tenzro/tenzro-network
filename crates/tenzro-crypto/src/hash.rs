//! Hashing primitives for Tenzro Network.
//!
//! Provides SHA-256 for general use and Keccak-256 for EVM compatibility.

use crate::error::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256 as Sha2_256};
use sha3::Keccak256 as Keccak256_;

/// Hash output size (32 bytes for both SHA-256 and Keccak-256)
pub const HASH_SIZE: usize = 32;

/// A 32-byte hash output for Tenzro Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Create a hash from a byte array
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create a hash from a slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HASH_SIZE {
            return Err(CryptoError::HashError(format!(
                "Invalid hash length: expected {}, got {}",
                HASH_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the hash as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the hash as a byte array
    pub fn to_bytes(&self) -> [u8; HASH_SIZE] {
        self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; HASH_SIZE]> for Hash {
    fn from(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Trait for hashing algorithms used in Tenzro Network.
pub trait Hasher {
    /// Hash a single input
    fn hash(data: &[u8]) -> Hash;
}

/// SHA-256 hasher for general use in Tenzro Network.
pub struct Sha256;

impl Hasher for Sha256 {
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Sha2_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Hash::new(result.into())
    }
}

/// Keccak-256 hasher for EVM compatibility in Tenzro Network.
pub struct Keccak256;

impl Hasher for Keccak256 {
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Keccak256_::new();
        hasher.update(data);
        let result = hasher.finalize();
        Hash::new(result.into())
    }
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Hash {
    Sha256::hash(data)
}

/// Compute Keccak-256 hash
pub fn keccak256(data: &[u8]) -> Hash {
    Keccak256::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Tenzro Network";
        let hash = sha256(data);
        assert_eq!(hash.as_bytes().len(), HASH_SIZE);
    }

    #[test]
    fn test_keccak256() {
        let data = b"Tenzro Network";
        let hash = keccak256(data);
        assert_eq!(hash.as_bytes().len(), HASH_SIZE);
    }

    #[test]
    fn test_hash_hex() {
        let hash = sha256(b"test");
        let hex = hash.to_hex();
        let decoded = Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, decoded);
    }
}
