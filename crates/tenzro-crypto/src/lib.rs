//! Cryptographic primitives for Tenzro Network.
//!
//! This crate provides cryptographic operations for the Tenzro Network blockchain,
//! including:
//!
//! - **Key Management**: Ed25519, Secp256k1, and Secp256r1 (P-256) keypairs with address derivation
//! - **Signatures**: Digital signature creation and verification
//! - **WebAuthn**: FIDO2 / passkey assertion verification, the device-side primitive for self-custody
//! - **Hashing**: SHA-256 and Keccak-256 (for EVM compatibility)
//! - **Encryption**: AES-256-GCM symmetric encryption and X25519 key exchange
//!
//! # Examples
//!
//! ## Keys
//!
//! A node holds no private key in software: identity and signing keys live in
//! the machine's TPM or Secure Enclave, or at a provider reached through the key
//! holder. This crate verifies signatures and builds the records they cover.
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
//! use tenzro_crypto::encryption::{SymmetricKey, envelope_encrypt, envelope_decrypt};
//! use tenzro_crypto::hybrid_seal::HybridSecretKey;
//!
//! # fn main() -> tenzro_crypto::Result<()> {
//! // Symmetric encryption
//! let key = SymmetricKey::generate();
//! let plaintext = b"secret data";
//! let ciphertext = key.encrypt(plaintext)?;
//! let decrypted = key.decrypt(&ciphertext)?;
//!
//! // Envelope encryption (asymmetric, X25519 + ML-KEM-768)
//! let recipient = HybridSecretKey::generate();
//! let envelope = envelope_encrypt(recipient.public(), plaintext)?;
//! let decrypted = envelope_decrypt(&recipient, &envelope)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod batch;
pub mod composite;
#[cfg(any(test, feature = "test-keys"))]
pub use composite::testing;
pub mod encryption;
pub mod error;
pub mod hash;
pub mod hash_voucher;
pub mod hybrid_seal;
pub mod keys;
pub mod ml_kem768;
pub mod p256;
pub mod pq;
pub mod rng;
pub mod session;
pub mod signatures;
pub mod vrf;
pub mod webauthn;

// Re-export commonly used types
pub use composite::{
    ClassicalProof, CompositePublicKey, CompositeSignature, HybridSigner, PqPolicy,
    SignatureContext, VerifiedLegs, account_address, account_slot, controls_account,
    signing_digest, verify_classical_component, verify_classical_component_for, verify_composite,
    verify_composite_for, verify_pq_component, webauthn_challenge,
};
pub use error::{CryptoError, Result};
pub use hash::{Hash, Hasher, Keccak256, Sha256, keccak256, sha256};
pub use keys::{Address, KeyPair, KeyType, PublicKey, SecretKey};
pub use p256::{
    P256_PUBLIC_KEY_LEN, P256_PUBLIC_KEY_SEC1_LEN, P256_SIGNATURE_LEN, P256Signature, P256Verifier,
    build_p256verify_input,
};
#[cfg(any(test, feature = "test-keys"))]
pub use p256::{P256KeyPair, P256Signer};
pub use pq::{ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN, MlDsaSigningKey, ml_dsa_verify};
pub use signatures::{Signature, Signer, Verifier};
pub use webauthn::{
    WebAuthnAssertion, WebAuthnCeremonyType, WebAuthnRelyingParty, unwrap_der_signature,
    verify_webauthn_assertion, webauthn_signed_hash, webauthn_signed_payload,
};

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
        use encryption::{SymmetricKey, envelope_decrypt, envelope_encrypt};
        use hybrid_seal::HybridSecretKey;

        // Symmetric encryption
        let sym_key = SymmetricKey::generate();
        let plaintext = b"Tenzro Network confidential data";
        let ciphertext = sym_key.encrypt(plaintext).unwrap();
        let decrypted = sym_key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Envelope encryption
        let recipient = HybridSecretKey::generate();
        let envelope = envelope_encrypt(recipient.public(), plaintext).unwrap();
        let decrypted = envelope_decrypt(&recipient, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
