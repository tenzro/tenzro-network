//! Signature operations for Tenzro Network.
//!
//! Provides signing and verification for both Ed25519 and Secp256k1.

use crate::error::{CryptoError, Result};
use crate::keys::{Address, KeyPair, KeyType, PublicKey};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer,
    SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey, SIGNATURE_LENGTH,
};
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
// ed25519-dalek 2 brings `signature::Signer`/`Verifier` v2.x into scope via
// its re-exports above. k256 0.14 / ecdsa 0.17-rc.18 implements the v3.x
// traits. Import the v3 traits under disambiguating aliases so the Secp256k1
// signer/verifier call sites resolve unambiguously without breaking the
// Ed25519 sites that still need v2.
use signature::{Signer as Sigv3Signer, Verifier as Sigv3Verifier};
use serde::{Deserialize, Serialize};

/// A signature in Tenzro Network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    key_type: KeyType,
    bytes: Vec<u8>,
}

impl Signature {
    /// Create a new signature
    pub fn new(key_type: KeyType, bytes: Vec<u8>) -> Self {
        Self { key_type, bytes }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the signature bytes
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
}

/// Trait for signing messages in Tenzro Network.
pub trait Signer {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Signature>;

    /// Get the public key
    fn public_key(&self) -> &PublicKey;

    /// Get the address
    fn address(&self) -> Address {
        self.public_key().to_address()
    }
}

/// Trait for verifying signatures in Tenzro Network.
pub trait Verifier {
    /// Verify a signature on a message
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()>;

    /// Get the public key
    fn public_key(&self) -> &PublicKey;
}

/// Ed25519 signer for Tenzro Network.
pub struct Ed25519SignerImpl {
    keypair: KeyPair,
    signing_key: Ed25519SigningKey,
}

impl Ed25519SignerImpl {
    /// Create a new Ed25519 signer from a keypair
    pub fn new(keypair: KeyPair) -> Result<Self> {
        if keypair.key_type() != KeyType::Ed25519 {
            return Err(CryptoError::InvalidKey(
                "Expected Ed25519 keypair".to_string(),
            ));
        }

        let secret_bytes: [u8; 32] = keypair
            .secret_key()
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKey("Invalid length".to_string()))?;

        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);

        Ok(Self {
            keypair,
            signing_key,
        })
    }

    /// Generate a new Ed25519 signer
    pub fn generate() -> Result<Self> {
        let keypair = KeyPair::generate(KeyType::Ed25519)?;
        Self::new(keypair)
    }
}

impl Signer for Ed25519SignerImpl {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let signature = self.signing_key.sign(message);
        Ok(Signature::new(
            KeyType::Ed25519,
            signature.to_bytes().to_vec(),
        ))
    }

    fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }
}

/// Ed25519 verifier for Tenzro Network.
pub struct Ed25519VerifierImpl {
    public_key: PublicKey,
    verifying_key: Ed25519VerifyingKey,
}

impl Ed25519VerifierImpl {
    /// Create a new Ed25519 verifier from a public key
    pub fn new(public_key: PublicKey) -> Result<Self> {
        if public_key.key_type() != KeyType::Ed25519 {
            return Err(CryptoError::InvalidKey(
                "Expected Ed25519 public key".to_string(),
            ));
        }

        let public_bytes: [u8; 32] = public_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey("Invalid length".to_string()))?;

        let verifying_key = Ed25519VerifyingKey::from_bytes(&public_bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            public_key,
            verifying_key,
        })
    }
}

impl Verifier for Ed25519VerifierImpl {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        if signature.key_type() != KeyType::Ed25519 {
            return Err(CryptoError::InvalidSignature(
                "Expected Ed25519 signature".to_string(),
            ));
        }

        if signature.as_bytes().len() != SIGNATURE_LENGTH {
            return Err(CryptoError::InvalidSignature(format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_LENGTH,
                signature.as_bytes().len()
            )));
        }

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature("Invalid length".to_string()))?;

        let sig = Ed25519Signature::from_bytes(&sig_bytes);

        // SECURITY (Issue #7 - RESOLVED): ed25519-dalek's verify() uses constant-time
        // comparison internally via the `subtle` crate to prevent timing side-channel
        // attacks during signature verification. No additional constant-time checks needed.
        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)?;

        Ok(())
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Secp256k1 signer for Tenzro Network (EVM compatible).
pub struct Secp256k1SignerImpl {
    keypair: KeyPair,
    signing_key: Secp256k1SigningKey,
}

impl Secp256k1SignerImpl {
    /// Create a new Secp256k1 signer from a keypair
    pub fn new(keypair: KeyPair) -> Result<Self> {
        if keypair.key_type() != KeyType::Secp256k1 {
            return Err(CryptoError::InvalidKey(
                "Expected Secp256k1 keypair".to_string(),
            ));
        }

        let secret_bytes: [u8; 32] = keypair
            .secret_key()
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKey("Invalid length".to_string()))?;

        let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())
            .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;

        Ok(Self {
            keypair,
            signing_key,
        })
    }

    /// Generate a new Secp256k1 signer
    pub fn generate() -> Result<Self> {
        let keypair = KeyPair::generate(KeyType::Secp256k1)?;
        Self::new(keypair)
    }
}

impl Signer for Secp256k1SignerImpl {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let signature: Secp256k1Signature = Sigv3Signer::sign(&self.signing_key, message);
        Ok(Signature::new(
            KeyType::Secp256k1,
            signature.to_bytes().to_vec(),
        ))
    }

    fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }
}

/// Secp256k1 verifier for Tenzro Network (EVM compatible).
pub struct Secp256k1VerifierImpl {
    public_key: PublicKey,
    verifying_key: Secp256k1VerifyingKey,
}

impl Secp256k1VerifierImpl {
    /// Create a new Secp256k1 verifier from a public key
    pub fn new(public_key: PublicKey) -> Result<Self> {
        if public_key.key_type() != KeyType::Secp256k1 {
            return Err(CryptoError::InvalidKey(
                "Expected Secp256k1 public key".to_string(),
            ));
        }

        // Support both compressed (33 bytes) and uncompressed (65 bytes) public keys
        let verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(public_key.as_bytes())
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            public_key,
            verifying_key,
        })
    }
}

impl Verifier for Secp256k1VerifierImpl {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        if signature.key_type() != KeyType::Secp256k1 {
            return Err(CryptoError::InvalidSignature(
                "Expected Secp256k1 signature".to_string(),
            ));
        }

        let sig = Secp256k1Signature::try_from(signature.as_bytes())
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

        // SECURITY (Issue #7 - RESOLVED): k256's verify() uses constant-time comparison
        // internally via the `subtle` crate to prevent timing side-channel attacks during
        // signature verification. No additional constant-time checks needed.
        Sigv3Verifier::verify(&self.verifying_key, message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)?;

        Ok(())
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Verify a signature on a message using a public key.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    match public_key.key_type() {
        KeyType::Ed25519 => {
            let verifier = Ed25519VerifierImpl::new(public_key.clone())?;
            verifier.verify(message, signature)
        }
        KeyType::Secp256k1 => {
            let verifier = Secp256k1VerifierImpl::new(public_key.clone())?;
            verifier.verify(message, signature)
        }
    }
}

/// Simple signature aggregation (concatenation-based).
///
/// This is a basic implementation for demonstration. Production systems
/// should use proper BLS or other aggregate signature schemes.
pub fn aggregate_signatures(signatures: &[Signature]) -> Result<Vec<u8>> {
    if signatures.is_empty() {
        return Err(CryptoError::InvalidSignature(
            "Cannot aggregate empty signature list".to_string(),
        ));
    }

    // Ensure all signatures are of the same type
    let key_type = signatures[0].key_type();
    for sig in signatures.iter().skip(1) {
        if sig.key_type() != key_type {
            return Err(CryptoError::InvalidSignature(
                "All signatures must be of the same type".to_string(),
            ));
        }
    }

    // Simple concatenation
    let mut aggregated = Vec::new();
    for sig in signatures {
        aggregated.extend_from_slice(sig.as_bytes());
    }

    Ok(aggregated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let message = b"Tenzro Network transaction";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.key_type(), KeyType::Ed25519);

        let verifier = Ed25519VerifierImpl::new(signer.public_key().clone()).unwrap();
        verifier.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_ed25519_verify_invalid_signature() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let message = b"Tenzro Network transaction";
        let wrong_message = b"Wrong message";

        let signature = signer.sign(message).unwrap();

        let verifier = Ed25519VerifierImpl::new(signer.public_key().clone()).unwrap();
        let result = verifier.verify(wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_secp256k1_sign_verify() {
        let signer = Secp256k1SignerImpl::generate().unwrap();
        let message = b"Tenzro Network transaction";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.key_type(), KeyType::Secp256k1);

        let verifier = Secp256k1VerifierImpl::new(signer.public_key().clone()).unwrap();
        verifier.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_verify_function() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let message = b"test";

        let signature = signer.sign(message).unwrap();
        verify(signer.public_key(), message, &signature).unwrap();
    }

    #[test]
    fn test_aggregate_signatures() {
        let signer1 = Ed25519SignerImpl::generate().unwrap();
        let signer2 = Ed25519SignerImpl::generate().unwrap();
        let message = b"test";

        let sig1 = signer1.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();

        let aggregated = aggregate_signatures(&[sig1, sig2]).unwrap();
        assert_eq!(aggregated.len(), 64 * 2); // Two 64-byte Ed25519 signatures
    }
}
