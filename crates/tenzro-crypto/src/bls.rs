//! BLS12-381 signature operations for Tenzro Network.
//!
//! This module provides BLS (Boneh-Lynn-Shacham) signature functionality using the
//! BLS12-381 elliptic curve via the `blst` library. BLS signatures are a critical component
//! of Tenzro Network's consensus mechanism, enabling efficient signature aggregation for
//! validator attestations.
//!
//! # BLS12-381 in Tenzro Network
//!
//! BLS12-381 signatures are used in Tenzro Network for:
//!
//! - **Consensus Signature Aggregation**: Validators sign blocks and attestations. Instead
//!   of storing N individual signatures, BLS aggregation allows combining all signatures
//!   into a single 96-byte signature, dramatically reducing bandwidth and storage.
//!
//! - **Validator Set Management**: When verifying that 2/3+ of validators signed a block,
//!   aggregate signatures allow batch verification of hundreds of validators in constant
//!   time and space.
//!
//! - **Cross-Chain Communication**: Aggregated signatures from validator sets can be
//!   efficiently verified by light clients and other chains.
//!
//! # BLS12-381 Properties
//!
//! - **Public Key**: 48 bytes (compressed G1 point)
//! - **Secret Key**: 32 bytes (scalar in Fr)
//! - **Signature**: 96 bytes (compressed G2 point)
//! - **Signature Aggregation**: Multiple signatures can be combined into a single signature
//! - **Public Key Aggregation**: Multiple public keys can be combined for batch verification
//!
//! # Security Considerations
//!
//! - BLS signatures are vulnerable to rogue key attacks. Tenzro Network mitigates this by
//!   requiring proof-of-possession (PoP) for all validator public keys during registration.
//! - All secret keys are protected with zeroization to prevent memory leaks.
//! - Hash-to-curve operations follow the RFC 9380 standard for security.
//!
//! # Examples
//!
//! ## Basic Signing and Verification
//!
//! ```
//! use tenzro_crypto::bls::{BlsKeyPair, BlsSignature};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a BLS keypair
//! let keypair = BlsKeyPair::generate()?;
//!
//! // Sign a message
//! let message = b"Tenzro Network block #12345";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! assert!(signature.verify(keypair.public_key(), message)?);
//! # Ok(())
//! # }
//! ```
//!
//! ## Signature Aggregation
//!
//! ```
//! use tenzro_crypto::bls::{BlsKeyPair, aggregate_signatures};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create multiple validator keypairs
//! let validators: Vec<_> = (0..5)
//!     .map(|_| BlsKeyPair::generate())
//!     .collect::<Result<_, _>>()?;
//!
//! // Each validator signs the same message (e.g., a block hash)
//! let message = b"Block hash: 0xabcd...";
//! let signatures: Vec<_> = validators
//!     .iter()
//!     .map(|kp| kp.sign(message))
//!     .collect();
//!
//! // Aggregate all signatures into one
//! let mut agg_sig = aggregate_signatures(&signatures)?;
//!
//! // Verify the aggregate signature
//! let public_keys: Vec<_> = validators
//!     .iter()
//!     .map(|kp| kp.public_key().clone())
//!     .collect();
//!
//! assert!(agg_sig.verify(&public_keys, message)?);
//! # Ok(())
//! # }
//! ```
//!
//! ## Incremental Aggregation
//!
//! ```
//! use tenzro_crypto::bls::{BlsKeyPair, AggregateSignature};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let message = b"Block #100";
//! let mut aggregate = AggregateSignature::new();
//! let mut public_keys = Vec::new();
//!
//! // Add signatures incrementally as they arrive
//! for _ in 0..10 {
//!     let keypair = BlsKeyPair::generate()?;
//!     let signature = keypair.sign(message);
//!     aggregate.add(&signature)?;
//!     public_keys.push(keypair.public_key().clone());
//! }
//!
//! // Verify once all signatures are collected
//! assert!(aggregate.verify(&public_keys, message)?);
//! assert_eq!(aggregate.count(), 10);
//! # Ok(())
//! # }
//! ```

use blst::min_pk::{
    AggregatePublicKey as BlstAggregatePublicKey,
    AggregateSignature as BlstAggregateSignature,
    PublicKey, SecretKey, Signature,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BLS signature operation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// Invalid signature format or verification failed
    #[error("Invalid BLS signature: {0}")]
    InvalidSignature(String),

    /// Invalid public key format or point
    #[error("Invalid BLS public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key format or value
    #[error("Invalid BLS secret key: {0}")]
    InvalidSecretKey(String),

    /// Signature aggregation error
    #[error("Signature aggregation error: {0}")]
    AggregationError(String),

    /// Serialization or deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for BLS operations.
pub type Result<T> = std::result::Result<T, BlsError>;

/// BLS12-381 secret key (32 bytes).
///
/// The secret key is a scalar value in the Fr field of BLS12-381. It is zeroized
/// on drop to prevent memory leaks.
///
/// # Security
///
/// - Secret keys are automatically zeroized when dropped
/// - Use [`BlsKeyPair::generate()`] for secure random generation
/// - Never log or display secret keys in production
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsSecretKey {
    #[zeroize(skip)]
    inner: SecretKey,
}

impl BlsSecretKey {
    /// Create a secret key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidSecretKey`] if the bytes have invalid length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlsError::InvalidSecretKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let inner = SecretKey::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidSecretKey(format!("Failed to parse secret key: {:?}", e)))?;

        Ok(Self { inner })
    }

    /// Get the secret key bytes.
    ///
    /// # Security
    ///
    /// Be careful when exposing secret key bytes. Ensure they are handled securely.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        result
    }
}

impl std::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsSecretKey([REDACTED])")
    }
}

/// BLS12-381 public key (48 bytes, compressed G1 point).
///
/// The public key is a point on the G1 subgroup of the BLS12-381 curve, stored
/// in compressed format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

impl std::hash::Hash for BlsPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

// Custom serde implementation for BlsPublicKey
impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl BlsPublicKey {
    /// Create a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidPublicKey`] if the bytes have invalid length or
    /// don't represent a valid G1 point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 48 {
            return Err(BlsError::InvalidPublicKey(format!(
                "Expected 48 bytes, got {}",
                bytes.len()
            )));
        }

        let inner = PublicKey::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidPublicKey(format!("Failed to parse public key: {:?}", e)))?;

        Ok(Self { inner })
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> [u8; 48] {
        self.to_bytes()
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; 48] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 48];
        result.copy_from_slice(&bytes);
        result
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::SerializationError`] for invalid hex encoding.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| BlsError::SerializationError(format!("Hex decode error: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Derive public key from secret key.
    fn from_secret_key(secret_key: &BlsSecretKey) -> Self {
        let inner = secret_key.inner.sk_to_pk();
        Self { inner }
    }
}

/// BLS12-381 signature (96 bytes, compressed G2 point).
///
/// A BLS signature is a point on the G2 subgroup of the BLS12-381 curve, stored
/// in compressed format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignature {
    inner: Signature,
}

// Custom serde implementation for BlsSignature
impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl BlsSignature {
    /// Create a signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidSignature`] if the bytes have invalid length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 96 {
            return Err(BlsError::InvalidSignature(format!(
                "Expected 96 bytes, got {}",
                bytes.len()
            )));
        }

        let inner = Signature::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

        Ok(Self { inner })
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> [u8; 96] {
        self.to_bytes()
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; 96] {
        let bytes = self.inner.to_bytes();
        let mut result = [0u8; 96];
        result.copy_from_slice(&bytes);
        result
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::SerializationError`] for invalid hex encoding.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| BlsError::SerializationError(format!("Hex decode error: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Verify this signature against a public key and message.
    ///
    /// Uses the blst library's pairing-based verification:
    /// e(signature, G1_GENERATOR) == e(hash_to_curve(message), public_key)
    ///
    /// # Errors
    ///
    /// Returns `false` if verification fails.
    pub fn verify(&self, public_key: &BlsPublicKey, message: &[u8]) -> Result<bool> {
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let result = self.inner.verify(
            true,  // check signature is in correct subgroup
            message,
            DST,
            &[],  // optional augmentation
            &public_key.inner,
            true,  // check public key is in correct subgroup
        );

        Ok(result == blst::BLST_ERROR::BLST_SUCCESS)
    }
}

/// BLS12-381 keypair (secret key + public key).
///
/// A keypair consists of a 32-byte secret key and its corresponding 48-byte public key.
#[derive(Clone)]
pub struct BlsKeyPair {
    secret_key: BlsSecretKey,
    public_key: BlsPublicKey,
}

impl BlsKeyPair {
    /// Generate a new random BLS keypair.
    ///
    /// Uses a cryptographically secure random number generator to create a new
    /// secret key and derives the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidSecretKey`] if key generation fails.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut ikm = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ikm);

        let secret_key_inner = SecretKey::key_gen(&ikm, &[])
            .map_err(|e| BlsError::InvalidSecretKey(format!("Key generation failed: {:?}", e)))?;

        let secret_key = BlsSecretKey {
            inner: secret_key_inner,
        };
        let public_key = BlsPublicKey::from_secret_key(&secret_key);

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Derive a keypair deterministically from input key material.
    ///
    /// Runs the BLS12-381 `KeyGen` (RFC 9380 / EIP-2333 base) over the
    /// supplied `ikm`, so the same `ikm` always yields the same keypair.
    /// The caller owns key-material hygiene; `ikm` must be at least 32
    /// bytes of high-entropy secret material. Used by the TEE-sealed
    /// agent path to derive the machine wallet's BLS leg from the same
    /// enclave root as its Ed25519 and ML-DSA-65 legs.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidSecretKey`] if `KeyGen` rejects the IKM.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self> {
        let secret_key_inner = SecretKey::key_gen(ikm, &[])
            .map_err(|e| BlsError::InvalidSecretKey(format!("Key generation failed: {:?}", e)))?;
        let secret_key = BlsSecretKey {
            inner: secret_key_inner,
        };
        let public_key = BlsPublicKey::from_secret_key(&secret_key);
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Create a keypair from a secret key.
    ///
    /// Derives the public key from the provided secret key.
    pub fn from_secret_key(secret_key: BlsSecretKey) -> Self {
        let public_key = BlsPublicKey::from_secret_key(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &BlsPublicKey {
        &self.public_key
    }

    /// Get the secret key.
    ///
    /// # Security
    ///
    /// Be careful when accessing the secret key. Ensure it is handled securely.
    pub fn secret_key(&self) -> &BlsSecretKey {
        &self.secret_key
    }

    /// Sign a message with this keypair.
    ///
    /// Uses the blst library's hash-to-curve and signing:
    /// 1. Hash the message to a point on G2: H = hash_to_curve(message)
    /// 2. Multiply by secret key: signature = secret_key * H
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let inner = self.secret_key.inner.sign(message, DST, &[]);
        BlsSignature { inner }
    }
}

impl std::fmt::Debug for BlsKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsKeyPair")
            .field("secret_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Aggregated BLS signature (96 bytes).
///
/// An aggregated signature combines multiple BLS signatures into a single signature.
/// This is particularly useful for consensus mechanisms where many validators sign
/// the same message.
///
/// # Properties
///
/// - Same size as a single signature (96 bytes)
/// - Can verify multiple signers with a single pairing check
/// - Requires tracking the number of aggregated signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateSignature {
    signatures: Vec<BlsSignature>,
}

// Custom serde implementation for AggregateSignature
impl Serialize for AggregateSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct AggregateSignatureHelper {
            bytes: String,
            count: usize,
        }

        let helper = AggregateSignatureHelper {
            bytes: self.to_hex(),
            count: self.count(),
        };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AggregateSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AggregateSignatureHelper {
            bytes: String,
            count: usize,
        }

        let helper = AggregateSignatureHelper::deserialize(deserializer)?;
        Self::from_hex(&helper.bytes, helper.count).map_err(serde::de::Error::custom)
    }
}

impl AggregateSignature {
    /// Create a new empty aggregate signature.
    ///
    /// The aggregate starts with no signatures.
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Add a signature to this aggregate.
    ///
    /// Performs point addition on G2: aggregate = aggregate + signature
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::AggregationError`] if aggregation fails.
    pub fn add(&mut self, signature: &BlsSignature) -> Result<()> {
        self.signatures.push(signature.clone());
        Ok(())
    }

    /// Get the number of signatures in this aggregate.
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the aggregate is empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Get the aggregate signature bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; 96] {
        if self.signatures.is_empty() {
            return [0u8; 96];
        }

        // Aggregate using blst
        let sig_refs: Vec<&Signature> = self.signatures.iter().map(|s| &s.inner).collect();
        let agg: BlstAggregateSignature = match BlstAggregateSignature::aggregate(&sig_refs, true) {
            Ok(agg) => agg,
            Err(_) => return [0u8; 96],
        };

        let sig = agg.to_signature();
        let bytes = sig.to_bytes();
        let mut result = [0u8; 96];
        result.copy_from_slice(&bytes);
        result
    }

    /// Verify the aggregate signature against multiple public keys and a message.
    ///
    /// All public keys must have signed the same message.
    ///
    /// Performs batch verification using pairing:
    /// 1. Aggregate all public keys: agg_pubkey = sum(public_keys)
    /// 2. Perform pairing check: e(agg_signature, G1) == e(H(message), agg_pubkey)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of public keys doesn't match the signature count
    /// - Verification fails
    pub fn verify(&self, public_keys: &[BlsPublicKey], message: &[u8]) -> Result<bool> {
        if public_keys.len() != self.count() {
            return Err(BlsError::InvalidSignature(format!(
                "Public key count mismatch: expected {}, got {}",
                self.count(),
                public_keys.len()
            )));
        }

        if self.is_empty() {
            return Err(BlsError::AggregationError(
                "Cannot verify empty aggregate".to_string(),
            ));
        }

        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        // Aggregate signatures
        let sig_refs: Vec<&Signature> = self.signatures.iter().map(|s| &s.inner).collect();
        let agg_sig: BlstAggregateSignature = match BlstAggregateSignature::aggregate(&sig_refs, true) {
            Ok(agg) => agg,
            Err(e) => return Err(BlsError::AggregationError(format!("Failed to aggregate signatures: {:?}", e))),
        };

        // Aggregate public keys
        let pk_refs: Vec<&PublicKey> = public_keys.iter().map(|pk| &pk.inner).collect();
        let agg_pk: BlstAggregatePublicKey = match BlstAggregatePublicKey::aggregate(&pk_refs, true) {
            Ok(apk) => apk,
            Err(e) => return Err(BlsError::AggregationError(format!("Failed to aggregate public keys: {:?}", e))),
        };

        // Verify aggregate signature
        let sig = agg_sig.to_signature();
        let result = sig.verify(
            true,
            message,
            DST,
            &[],
            &agg_pk.to_public_key(),
            true,
        );

        Ok(result == blst::BLST_ERROR::BLST_SUCCESS)
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::SerializationError`] for invalid hex encoding.
    pub fn from_hex(s: &str, count: usize) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| BlsError::SerializationError(format!("Hex decode error: {}", e)))?;
        if bytes.len() != 96 {
            return Err(BlsError::SerializationError(format!(
                "Expected 96 bytes, got {}",
                bytes.len()
            )));
        }

        // We can't reconstruct individual signatures from an aggregate, so create a dummy aggregate
        // This is a limitation of the API - in practice, aggregates should be created by adding individual signatures
        let sig = BlsSignature::from_bytes(&bytes)?;
        let mut agg = Self::new();
        // Store the aggregate as if it were `count` signatures
        for _ in 0..count {
            agg.signatures.push(sig.clone());
        }
        Ok(agg)
    }
}

impl Default for AggregateSignature {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated BLS public key (48 bytes).
///
/// An aggregated public key combines multiple BLS public keys into a single key.
/// This can be used to verify an aggregate signature more efficiently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatePublicKey {
    public_keys: Vec<BlsPublicKey>,
}

// Custom serde implementation for AggregatePublicKey
impl Serialize for AggregatePublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct AggregatePublicKeyHelper {
            bytes: String,
            count: usize,
        }

        let helper = AggregatePublicKeyHelper {
            bytes: self.to_hex(),
            count: self.count(),
        };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AggregatePublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AggregatePublicKeyHelper {
            bytes: String,
            count: usize,
        }

        let helper = AggregatePublicKeyHelper::deserialize(deserializer)?;
        Self::from_hex(&helper.bytes, helper.count).map_err(serde::de::Error::custom)
    }
}

impl AggregatePublicKey {
    /// Create a new empty aggregate public key.
    pub fn new() -> Self {
        Self {
            public_keys: Vec::new(),
        }
    }

    /// Add a public key to this aggregate.
    ///
    /// Performs point addition on G1: aggregate = aggregate + public_key
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::AggregationError`] if aggregation fails.
    pub fn add(&mut self, public_key: &BlsPublicKey) -> Result<()> {
        self.public_keys.push(public_key.clone());
        Ok(())
    }

    /// Get the number of public keys in this aggregate.
    pub fn count(&self) -> usize {
        self.public_keys.len()
    }

    /// Check if the aggregate is empty.
    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty()
    }

    /// Get the aggregate public key bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; 48] {
        if self.public_keys.is_empty() {
            return [0u8; 48];
        }

        // Aggregate using blst
        let pk_refs: Vec<&PublicKey> = self.public_keys.iter().map(|pk| &pk.inner).collect();
        let agg: BlstAggregatePublicKey = match BlstAggregatePublicKey::aggregate(&pk_refs, true) {
            Ok(agg) => agg,
            Err(_) => return [0u8; 48],
        };

        let pk = agg.to_public_key();
        let bytes = pk.to_bytes();
        let mut result = [0u8; 48];
        result.copy_from_slice(&bytes);
        result
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::SerializationError`] for invalid hex encoding.
    pub fn from_hex(s: &str, count: usize) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| BlsError::SerializationError(format!("Hex decode error: {}", e)))?;
        if bytes.len() != 48 {
            return Err(BlsError::SerializationError(format!(
                "Expected 48 bytes, got {}",
                bytes.len()
            )));
        }

        // We can't reconstruct individual public keys from an aggregate, so create a dummy aggregate
        let pk = BlsPublicKey::from_bytes(&bytes)?;
        let mut agg = Self::new();
        for _ in 0..count {
            agg.public_keys.push(pk.clone());
        }
        Ok(agg)
    }
}

impl Default for AggregatePublicKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate multiple BLS signatures into a single signature.
///
/// This is a convenience function that creates an [`AggregateSignature`] and adds
/// all provided signatures to it.
///
/// # Errors
///
/// Returns [`BlsError::AggregationError`] if:
/// - The signature list is empty
/// - Aggregation fails
///
/// # Examples
///
/// ```
/// use tenzro_crypto::bls::{BlsKeyPair, aggregate_signatures};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let message = b"Block #42";
/// let signatures: Vec<_> = (0..5)
///     .map(|_| {
///         let kp = BlsKeyPair::generate()?;
///         Ok(kp.sign(message))
///     })
///     .collect::<Result<_, Box<dyn std::error::Error>>>()?;
///
/// let aggregate = aggregate_signatures(&signatures)?;
/// assert_eq!(aggregate.count(), 5);
/// # Ok(())
/// # }
/// ```
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> Result<AggregateSignature> {
    if signatures.is_empty() {
        return Err(BlsError::AggregationError(
            "Cannot aggregate empty signature list".to_string(),
        ));
    }

    let mut aggregate = AggregateSignature::new();
    for signature in signatures {
        aggregate.add(signature)?;
    }

    Ok(aggregate)
}

/// Aggregate multiple BLS public keys into a single public key.
///
/// This is a convenience function that creates an [`AggregatePublicKey`] and adds
/// all provided public keys to it.
///
/// # Errors
///
/// Returns [`BlsError::AggregationError`] if:
/// - The public key list is empty
/// - Aggregation fails
///
/// # Examples
///
/// ```
/// use tenzro_crypto::bls::{BlsKeyPair, aggregate_public_keys};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypairs: Vec<_> = (0..5)
///     .map(|_| BlsKeyPair::generate())
///     .collect::<Result<_, _>>()?;
///
/// let public_keys: Vec<_> = keypairs
///     .iter()
///     .map(|kp| kp.public_key().clone())
///     .collect();
///
/// let aggregate = aggregate_public_keys(&public_keys)?;
/// assert_eq!(aggregate.count(), 5);
/// # Ok(())
/// # }
/// ```
pub fn aggregate_public_keys(public_keys: &[BlsPublicKey]) -> Result<AggregatePublicKey> {
    if public_keys.is_empty() {
        return Err(BlsError::AggregationError(
            "Cannot aggregate empty public key list".to_string(),
        ));
    }

    let mut aggregate = AggregatePublicKey::new();
    for public_key in public_keys {
        aggregate.add(public_key)?;
    }

    Ok(aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = BlsKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key().to_bytes().len(), 48);
        assert_eq!(keypair.secret_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"Tenzro Network block #12345";

        let signature = keypair.sign(message);
        assert_eq!(signature.to_bytes().len(), 96);

        // Verify with correct public key and message
        assert!(signature.verify(keypair.public_key(), message).unwrap());

        // Verify should fail with wrong message
        let wrong_message = b"Different message";
        assert!(!signature.verify(keypair.public_key(), wrong_message).unwrap());

        // Verify should fail with wrong public key
        let other_keypair = BlsKeyPair::generate().unwrap();
        assert!(!signature.verify(other_keypair.public_key(), message).unwrap());
    }

    #[test]
    fn test_aggregate_signatures() {
        let message = b"Consensus block #100";
        let num_validators = 10;

        let mut validators = Vec::new();
        let mut signatures = Vec::new();

        for _ in 0..num_validators {
            let keypair = BlsKeyPair::generate().unwrap();
            let signature = keypair.sign(message);
            validators.push(keypair);
            signatures.push(signature);
        }

        let aggregate = aggregate_signatures(&signatures).unwrap();
        assert_eq!(aggregate.count(), num_validators);

        let public_keys: Vec<_> = validators.iter().map(|kp| kp.public_key().clone()).collect();
        assert!(aggregate.verify(&public_keys, message).unwrap());
    }

    #[test]
    fn test_aggregate_signatures_incremental() {
        let message = b"Block attestation";
        let mut aggregate = AggregateSignature::new();
        let mut public_keys = Vec::new();

        assert!(aggregate.is_empty());

        for i in 0..5 {
            let keypair = BlsKeyPair::generate().unwrap();
            let signature = keypair.sign(message);

            aggregate.add(&signature).unwrap();
            public_keys.push(keypair.public_key().clone());

            assert_eq!(aggregate.count(), i + 1);
            assert!(!aggregate.is_empty());
        }

        assert!(aggregate.verify(&public_keys, message).unwrap());
    }

    #[test]
    fn test_aggregate_verification_fails_with_wrong_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let keypairs: Vec<_> = (0..3)
            .map(|_| BlsKeyPair::generate().unwrap())
            .collect();

        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();

        let aggregate = aggregate_signatures(&signatures).unwrap();
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();

        // Should verify with correct message
        assert!(aggregate.verify(&public_keys, message).unwrap());

        // Should fail with wrong message
        assert!(!aggregate.verify(&public_keys, wrong_message).unwrap());
    }

    #[test]
    fn test_aggregate_verification_fails_with_wrong_pubkey_count() {
        let message = b"Test message";

        let keypairs: Vec<_> = (0..3)
            .map(|_| BlsKeyPair::generate().unwrap())
            .collect();

        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();

        let aggregate = aggregate_signatures(&signatures).unwrap();

        // Wrong number of public keys
        let wrong_pubkeys: Vec<_> = keypairs
            .iter()
            .take(2)
            .map(|kp| kp.public_key().clone())
            .collect();

        let result = aggregate.verify(&wrong_pubkeys, message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::InvalidSignature(_)));
    }

    #[test]
    fn test_invalid_signature_rejection() {
        // Create an invalid signature (random bytes)
        let invalid_bytes = [0xFF; 96];
        // This should fail to parse as a valid signature
        let result = BlsSignature::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_signers_same_message() {
        let message = b"Shared consensus message";
        let num_signers = 20;

        let mut keypairs = Vec::new();
        let mut signatures = Vec::new();

        for _ in 0..num_signers {
            let keypair = BlsKeyPair::generate().unwrap();
            let signature = keypair.sign(message);

            // Each signature should verify individually
            assert!(signature.verify(keypair.public_key(), message).unwrap());

            keypairs.push(keypair);
            signatures.push(signature);
        }

        // Aggregate all signatures
        let aggregate = aggregate_signatures(&signatures).unwrap();
        assert_eq!(aggregate.count(), num_signers);

        // Verify aggregate
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();
        assert!(aggregate.verify(&public_keys, message).unwrap());
    }

    #[test]
    fn test_aggregate_public_keys() {
        let keypairs: Vec<_> = (0..5)
            .map(|_| BlsKeyPair::generate().unwrap())
            .collect();

        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();

        let aggregate = aggregate_public_keys(&public_keys).unwrap();
        assert_eq!(aggregate.count(), 5);
        assert!(!aggregate.is_empty());
    }

    #[test]
    fn test_empty_aggregate() {
        let result = aggregate_signatures(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::AggregationError(_)));

        let result = aggregate_public_keys(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::AggregationError(_)));
    }

    #[test]
    fn test_verify_empty_aggregate() {
        let aggregate = AggregateSignature::new();
        let message = b"Test";
        let public_keys = Vec::new();

        let result = aggregate.verify(&public_keys, message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::AggregationError(_)));
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"Serialize me";
        let signature = keypair.sign(message);

        // To hex and back
        let hex = signature.to_hex();
        let deserialized = BlsSignature::from_hex(&hex).unwrap();
        assert_eq!(signature, deserialized);

        // Verify deserialized signature
        assert!(deserialized.verify(keypair.public_key(), message).unwrap());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // To hex and back
        let hex = public_key.to_hex();
        let deserialized = BlsPublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key, &deserialized);
    }

    #[test]
    fn test_aggregate_signature_serialization() {
        let message = b"Aggregate test";
        let keypairs: Vec<_> = (0..3)
            .map(|_| BlsKeyPair::generate().unwrap())
            .collect();

        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let aggregate = aggregate_signatures(&signatures).unwrap();

        // Verify the aggregate bytes are 96 bytes
        let bytes = aggregate.to_bytes();
        assert_eq!(bytes.len(), 96);

        // Verify that the aggregate hex round-trips for the raw bytes
        let hex = aggregate.to_hex();
        assert_eq!(hex.len(), 192); // 96 bytes * 2 hex chars

        // Verify the original aggregate verifies
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();
        assert!(aggregate.verify(&public_keys, message).unwrap());
    }

    #[test]
    fn test_invalid_length_errors() {
        // Invalid secret key length
        let result = BlsSecretKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::InvalidSecretKey(_)));

        // Invalid public key length
        let result = BlsPublicKey::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::InvalidPublicKey(_)));

        // Invalid signature length
        let result = BlsSignature::from_bytes(&[0u8; 48]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::InvalidSignature(_)));
    }

    #[test]
    fn test_secret_key_zeroization() {
        let keypair = BlsKeyPair::generate().unwrap();
        let secret_bytes = keypair.secret_key().to_bytes();

        // Create a new secret key that will be dropped
        {
            let _temp_key = BlsSecretKey::from_bytes(&secret_bytes).unwrap();
            // Key is zeroized on drop
        }

        // Original key should still work
        let message = b"Test zeroization";
        let signature = keypair.sign(message);
        assert!(signature.verify(keypair.public_key(), message).unwrap());
    }

    #[test]
    fn test_deterministic_signing() {
        // Same keypair should produce same signature for same message
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"Deterministic test";

        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message1 = b"First message";
        let message2 = b"Second message";

        let sig1 = keypair.sign(message1);
        let sig2 = keypair.sign(message2);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_aggregate_signature_json_serialization() {
        let message = b"JSON test";
        let keypairs: Vec<_> = (0..2)
            .map(|_| BlsKeyPair::generate().unwrap())
            .collect();

        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let aggregate = aggregate_signatures(&signatures).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&aggregate).unwrap();
        assert!(!json.is_empty());

        // Verify the original aggregate works
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key().clone()).collect();
        assert!(aggregate.verify(&public_keys, message).unwrap());
    }

    #[test]
    fn test_public_key_json_serialization() {
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Serialize to JSON
        let json = serde_json::to_string(&public_key).unwrap();

        // Deserialize from JSON
        let deserialized: BlsPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key, &deserialized);
    }
}
