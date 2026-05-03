//! Hashing primitives for Tenzro Network.
//!
//! Provides SHA-256 for general use and Keccak-256 for EVM compatibility.

use crate::error::{CryptoError, Result};
use sha2::{Digest as Sha2Digest, Sha256 as Sha2_256};
use sha3::Keccak256 as Keccak256_;
use serde::{Deserialize, Serialize};

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

    /// Hash multiple inputs concatenated together
    fn hash_concat(inputs: &[&[u8]]) -> Hash {
        let mut combined = Vec::new();
        for input in inputs {
            combined.extend_from_slice(input);
        }
        Self::hash(&combined)
    }

    /// Hash a pair of inputs (useful for Merkle trees)
    fn hash_pair(left: &[u8], right: &[u8]) -> Hash {
        Self::hash_concat(&[left, right])
    }
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

/// Compute Merkle root from a list of hashes.
///
/// Uses SHA-256 for hashing pairs. If the list has an odd number of elements,
/// the last element is duplicated.
pub fn merkle_root(leaves: &[Hash]) -> Result<Hash> {
    if leaves.is_empty() {
        return Err(CryptoError::HashError(
            "Cannot compute Merkle root of empty list".to_string(),
        ));
    }

    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }

    let mut current_level = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                // Duplicate last element if odd number
                &current_level[i]
            };

            let parent = Sha256::hash_pair(left.as_bytes(), right.as_bytes());
            next_level.push(parent);
        }

        current_level = next_level;
    }

    Ok(current_level[0])
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
    fn test_hash_concat() {
        let hash1 = Sha256::hash_concat(&[b"Tenzro", b" ", b"Network"]);
        let hash2 = Sha256::hash(b"Tenzro Network");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_merkle_root_single() {
        let leaf = sha256(b"test");
        let root = merkle_root(&[leaf]).unwrap();
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_multiple() {
        let leaves = vec![
            sha256(b"leaf1"),
            sha256(b"leaf2"),
            sha256(b"leaf3"),
            sha256(b"leaf4"),
        ];
        let root = merkle_root(&leaves).unwrap();
        assert_eq!(root.as_bytes().len(), HASH_SIZE);
    }

    #[test]
    fn test_hash_hex() {
        let hash = sha256(b"test");
        let hex = hash.to_hex();
        let decoded = Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, decoded);
    }
}
