//! Cryptographic primitives for Tenzro Network.
//!
//! This crate provides cryptographic operations for the Tenzro Network blockchain,
//! including:
//!
//! - **Key Management**: Ed25519 and Secp256k1 keypairs with address derivation
//! - **Signatures**: Digital signature creation and verification
//! - **Hashing**: SHA-256 and Keccak-256 (for EVM compatibility)
//! - **Encryption**: AES-256-GCM symmetric encryption and X25519 key exchange
//! - **MPC**: Multi-party computation and threshold signatures for auto-provisioned wallets
//!
//! # Examples
//!
//! ## Generating a keypair and signing
//!
//! ```
//! use tenzro_crypto::{KeyPair, KeyType};
//! use tenzro_crypto::signatures::{Signer, Ed25519SignerImpl};
//!
//! # fn main() -> tenzro_crypto::Result<()> {
//! // Generate an Ed25519 keypair
//! let keypair = KeyPair::generate(KeyType::Ed25519)?;
//! let address = keypair.address();
//!
//! // Sign a message
//! let signer = Ed25519SignerImpl::new(keypair)?;
//! let message = b"Tenzro Network transaction";
//! let signature = signer.sign(message)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Hashing
//!
//! ```
//! use tenzro_crypto::hash::{sha256, keccak256};
//!
//! let data = b"Tenzro Network";
//! let sha_hash = sha256(data);
//! let keccak_hash = keccak256(data);
//! ```
//!
//! ## Encryption
//!
//! ```
//! use tenzro_crypto::encryption::{SymmetricKey, X25519KeyPair, envelope_encrypt, envelope_decrypt};
//!
//! # fn main() -> tenzro_crypto::Result<()> {
//! // Symmetric encryption
//! let key = SymmetricKey::generate();
//! let plaintext = b"secret data";
//! let ciphertext = key.encrypt(plaintext)?;
//! let decrypted = key.decrypt(&ciphertext)?;
//!
//! // Envelope encryption (asymmetric)
//! let recipient = X25519KeyPair::generate();
//! let envelope = envelope_encrypt(recipient.public_key(), plaintext)?;
//! let decrypted = envelope_decrypt(&recipient, &envelope)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## MPC Threshold Signatures
//!
//! ```
//! use tenzro_crypto::mpc::{ThresholdConfig, generate_key_shares, create_partial_signature, combine_signatures_with_message, MpcKeyShare};
//! use tenzro_crypto::KeyType;
//!
//! # fn main() -> tenzro_crypto::Result<()> {
//! // Create a 2-of-3 threshold configuration
//! let config = ThresholdConfig::new(2, 3)?;
//!
//! // Generate key shares
//! let shares = generate_key_shares(KeyType::Ed25519, config)?;
//!
//! // Create partial signatures
//! let message = b"Tenzro Network MPC transaction";
//! let partial_sigs: Vec<_> = shares.iter()
//!     .take(2)
//!     .map(|share| create_partial_signature(share, message))
//!     .collect::<Result<_, _>>()?;
//!
//! // Reconstruct master key from shares and produce a real signature
//! let share_refs: Vec<&MpcKeyShare> = shares.iter().take(2).collect();
//! let signature = combine_signatures_with_message(&share_refs, &partial_sigs, message)?;
//! # Ok(())
//! # }
//! ```

pub mod bls;
pub mod composite;
pub mod encryption;
pub mod error;
pub mod hash;
pub mod keys;
pub mod mpc;
pub mod pq;
pub mod rng;
pub mod signatures;
pub mod vrf;

// Re-export commonly used types
pub use composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, HybridVerifier, InMemoryHybridSigner,
    StandardHybridVerifier,
};
pub use error::{CryptoError, Result};
pub use hash::{sha256, keccak256, Hash, Hasher, Keccak256, Sha256};
pub use keys::{Address, KeyPair, KeyType, PublicKey, SecretKey};
pub use pq::{
    ml_dsa_verify, ml_kem_encapsulate, MlDsaSigningKey, MlKemDecapsulationKey,
    ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN, ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, ML_KEM_SS_LEN,
};
pub use signatures::{Signature, Signer, Verifier};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end_ed25519() {
        use signatures::{Ed25519SignerImpl, Ed25519VerifierImpl};

        // Generate keypair
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = keypair.address();

        // Create signer
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        // Sign message
        let message = b"Tenzro Network test";
        let signature = signer.sign(message).unwrap();

        // Verify signature
        let verifier = Ed25519VerifierImpl::new(signer.public_key().clone()).unwrap();
        verifier.verify(message, &signature).unwrap();

        println!("Address: {}", address);
    }

    #[test]
    fn test_end_to_end_secp256k1() {
        use signatures::{Secp256k1SignerImpl, Secp256k1VerifierImpl};

        // Generate keypair
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let address = keypair.address();

        // Create signer
        let signer = Secp256k1SignerImpl::new(keypair).unwrap();

        // Sign message
        let message = b"Tenzro Network EVM transaction";
        let signature = signer.sign(message).unwrap();

        // Verify signature
        let verifier = Secp256k1VerifierImpl::new(signer.public_key().clone()).unwrap();
        verifier.verify(message, &signature).unwrap();

        println!("EVM Address: {}", address);
    }

    #[test]
    fn test_hash_and_verify() {
        use signatures::Ed25519SignerImpl;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        // Hash data
        let data = b"Tenzro Network data";
        let hash = sha256(data);

        // Sign the hash
        let signature = signer.sign(hash.as_bytes()).unwrap();

        // Verify
        use signatures::verify;
        verify(signer.public_key(), hash.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn test_encryption_workflow() {
        use encryption::{SymmetricKey, X25519KeyPair, envelope_encrypt, envelope_decrypt};

        // Symmetric encryption
        let sym_key = SymmetricKey::generate();
        let plaintext = b"Tenzro Network confidential data";
        let ciphertext = sym_key.encrypt(plaintext).unwrap();
        let decrypted = sym_key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Envelope encryption
        let recipient = X25519KeyPair::generate();
        let envelope = envelope_encrypt(recipient.public_key(), plaintext).unwrap();
        let decrypted = envelope_decrypt(&recipient, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mpc_workflow() {
        use mpc::{ThresholdConfig, generate_key_shares, create_partial_signature, combine_signatures_with_message, MpcKeyShare};

        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();

        let message = b"Tenzro Network MPC test";
        let partial_sigs: Vec<_> = shares
            .iter()
            .take(2)
            .map(|share| create_partial_signature(share, message).unwrap())
            .collect();

        let share_refs: Vec<&MpcKeyShare> = shares.iter().take(2).collect();
        let signature = combine_signatures_with_message(&share_refs, &partial_sigs, message).unwrap();
        assert_eq!(signature.key_type(), KeyType::Ed25519);
    }
}
