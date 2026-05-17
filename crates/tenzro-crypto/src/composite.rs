//! Hybrid (composite) signature primitives for the Tenzro post-quantum migration.
//!
//! Per `docs/security/quantum-resistance-migration-plan.md` the network signs
//! every consensus-critical message with **both** a classical curve (Ed25519 or
//! Secp256k1, owning EVM-compat) and ML-DSA-65 (the FIPS 204 PQ digital
//! signature). Verification requires *both* signatures to validate — i.e. the
//! adversary must break the classical AND the lattice scheme to forge.
//!
//! # Wire format
//!
//! Both fields are mandatory `Vec<u8>`. The classical leg is 64 bytes
//! (Ed25519 or Secp256k1 raw, no DER) and the PQ leg is 3309 bytes (ML-DSA-65).
//! There is no classical-only fallback: payloads carrying an empty PQ leg are
//! rejected at admission. After the 2030 NIST SP 800-227 transition the
//! classical leg may be retired with a flag-day swap of the verifier.

use crate::error::{CryptoError, Result};
use crate::keys::{KeyType, PublicKey};
use crate::pq::{ml_dsa_verify, MlDsaSigningKey};
use crate::signatures::{verify as verify_classical, Signature, Signer};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// A composite (classical + post-quantum) signature.
///
/// `classical` is the raw signature bytes from the legacy primitive (Ed25519 64
/// bytes / Secp256k1 64 bytes DER-less). `pq` is the ML-DSA-65 signature
/// (3309 bytes). Both legs are mandatory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// Classical curve signature (Ed25519 or Secp256k1).
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature (3309 bytes).
    pub pq: Vec<u8>,
}

impl CompositeSignature {
    /// Construct a composite signature from raw bytes for both legs.
    pub fn new(classical: Vec<u8>, pq: Vec<u8>) -> Self {
        Self { classical, pq }
    }
}

/// A composite (classical + post-quantum) public key, suitable for embedding in
/// `tenzro-types::transaction::Transaction`, validator registries, and DID
/// documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositePublicKey {
    /// Classical public key.
    pub classical: PublicKey,
    /// ML-DSA-65 verifying key bytes (1952 bytes).
    pub pq: Vec<u8>,
}

impl CompositePublicKey {
    /// Construct from already-encoded parts.
    pub fn new(classical: PublicKey, pq: Vec<u8>) -> Self {
        Self { classical, pq }
    }

    /// The classical key type (Ed25519 / Secp256k1).
    pub fn key_type(&self) -> KeyType {
        self.classical.key_type()
    }
}

/// Trait implemented by signers that produce both legs of a composite signature.
///
/// Implementors hold *both* a classical `Signer` and an [`MlDsaSigningKey`]
/// internally; callers see only the `sign` / `public_key` surface. Tenzro-Wallet
/// owns the canonical implementation; bridges, identity, and consensus consume
/// `dyn HybridSigner` references so they don't need to know about the keystore.
pub trait HybridSigner: Send + Sync {
    /// Produce a composite signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature>;
    /// Composite public key (classical + ML-DSA-65 verifying key).
    fn public_key(&self) -> &CompositePublicKey;
}

/// Trait implemented by verifiers that check both legs of a composite signature.
pub trait HybridVerifier: Send + Sync {
    /// Verify a composite signature; both legs MUST validate. Returns
    /// `Err(VerificationFailed)` if either leg fails.
    fn verify(&self, msg: &[u8], sig: &CompositeSignature) -> Result<()>;
    /// Composite public key being verified against.
    fn public_key(&self) -> &CompositePublicKey;
}

// ---------------------------------------------------------------------------
// Default implementation
// ---------------------------------------------------------------------------

/// Default in-memory hybrid signer. Wraps any classical [`Signer`] plus an
/// [`MlDsaSigningKey`] and emits a [`CompositeSignature`] per call.
///
/// `tenzro-wallet` builds one of these per key entry; bridge/identity/agent
/// crates can construct ad-hoc instances for ephemeral session keys.
pub struct InMemoryHybridSigner {
    classical: Box<dyn Signer + Send + Sync>,
    pq: MlDsaSigningKey,
    composite_pk: CompositePublicKey,
}

impl InMemoryHybridSigner {
    /// Build a hybrid signer from an already-constructed classical signer plus a
    /// freshly-generated (or rehydrated) PQ signing key. Callers are responsible
    /// for persisting the PQ secret material in the same keystore that backs
    /// the classical key.
    pub fn new(classical: Box<dyn Signer + Send + Sync>, pq: MlDsaSigningKey) -> Self {
        let composite_pk = CompositePublicKey::new(
            classical.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
        );
        Self {
            classical,
            pq,
            composite_pk,
        }
    }
}

impl HybridSigner for InMemoryHybridSigner {
    fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        let classical_sig: Signature = self.classical.sign(msg)?;
        let pq_sig = self.pq.sign(msg);
        Ok(CompositeSignature::new(classical_sig.to_bytes(), pq_sig))
    }

    fn public_key(&self) -> &CompositePublicKey {
        &self.composite_pk
    }
}

/// Default verifier that runs both legs of a composite check.
pub struct StandardHybridVerifier {
    public_key: CompositePublicKey,
}

impl StandardHybridVerifier {
    /// Build a verifier bound to a composite public key.
    pub fn new(public_key: CompositePublicKey) -> Self {
        Self { public_key }
    }
}

impl HybridVerifier for StandardHybridVerifier {
    fn verify(&self, msg: &[u8], sig: &CompositeSignature) -> Result<()> {
        // 1. Classical leg.
        let classical_sig =
            Signature::new(self.public_key.key_type(), sig.classical.clone());
        verify_classical(&self.public_key.classical, msg, &classical_sig)?;

        // 2. PQ leg — both halves are mandatory, no downgrade path.
        if sig.pq.is_empty() {
            return Err(CryptoError::InvalidSignature(
                "composite signature missing ML-DSA-65 leg (downgrade rejected)".to_string(),
            ));
        }
        if self.public_key.pq.is_empty() {
            return Err(CryptoError::InvalidSignature(
                "composite public key missing ML-DSA-65 verifying key".to_string(),
            ));
        }
        ml_dsa_verify(&self.public_key.pq, msg, &sig.pq)?;
        Ok(())
    }

    fn public_key(&self) -> &CompositePublicKey {
        &self.public_key
    }
}

// Marker so `Drop` zeroizes any future secret-bearing fields we add (the PQ key
// inside `MlDsaSigningKey` already lives inside `ml_dsa::SigningKey`, which
// zeroizes itself on drop via the `module-lattice` crate).
impl ZeroizeOnDrop for InMemoryHybridSigner {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyPair, KeyType};
    use crate::signatures::Ed25519SignerImpl;

    fn fresh_hybrid_signer() -> InMemoryHybridSigner {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let signer = fresh_hybrid_signer();
        let msg = b"hybrid-signed payload";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(sig.classical.len(), 64);
        assert_eq!(sig.pq.len(), 3309);

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    fn hybrid_rejects_tampered_classical_leg() {
        let signer = fresh_hybrid_signer();
        let msg = b"abc";
        let mut sig = signer.sign(msg).unwrap();
        let last = sig.classical.len() - 1;
        sig.classical[last] ^= 0x01;

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        assert!(verifier.verify(msg, &sig).is_err());
    }

    #[test]
    fn hybrid_rejects_tampered_pq_leg() {
        let signer = fresh_hybrid_signer();
        let msg = b"abc";
        let mut sig = signer.sign(msg).unwrap();
        sig.pq[100] ^= 0x01;

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        assert!(verifier.verify(msg, &sig).is_err());
    }

    #[test]
    fn hybrid_rejects_empty_pq_leg() {
        let signer = fresh_hybrid_signer();
        let msg = b"abc";
        let mut sig = signer.sign(msg).unwrap();
        sig.pq.clear();

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        let err = verifier.verify(msg, &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
    }
}
