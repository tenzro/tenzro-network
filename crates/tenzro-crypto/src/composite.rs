//! Hybrid (composite) signature primitives for the Tenzro post-quantum migration.
//!
//! Per `docs/security/quantum-resistance-migration-plan.md` the network signs
//! every consensus-critical message with **both** a classical curve (Ed25519 or
//! Secp256k1, owning EVM-compat) and ML-DSA-65 (the FIPS 204 PQ digital
//! signature). Verification requires *both* signatures to validate — i.e. the
//! adversary must break the classical AND the lattice scheme to forge.
//!
//! The classical half stays mandatory until the 2030 flag-day (NIST SP 800-227
//! transition guidance); after that the wire format keeps the field but pure-PQ
//! deployments may set `classical = vec![]` and validators flip a global flag
//! to skip the classical leg.
//!
//! # Wire format
//!
//! The `pq` field is `Option<Vec<u8>>` so existing callsites (genesis seeds,
//! pre-migration test vectors, raw classical-only transactions in CI) keep
//! deserialising during the rollout window. After the cutover, validators
//! reject any `Transaction` with `pq_signature: None` at admission.

use crate::error::{CryptoError, Result};
use crate::keys::{KeyType, PublicKey};
use crate::pq::{ml_dsa_verify, MlDsaSigningKey};
use crate::signatures::{verify as verify_classical, Signature, Signer};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// A composite (classical + post-quantum) signature.
///
/// `classical` is the raw signature bytes from the legacy primitive (Ed25519 64
/// bytes / Secp256k1 64 bytes DER-less). `pq` is the optional ML-DSA-65
/// signature (3309 bytes when present). Both fields are length-prefixed by the
/// outer `bincode`/`serde_json` encoder, so no manual length tagging is needed
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// Classical curve signature (Ed25519 or Secp256k1). Always present during
    /// the hybrid window.
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature. `Some` for hybrid-signed payloads, `None` for
    /// pre-migration messages still in the gossip cache.
    pub pq: Option<Vec<u8>>,
}

impl CompositeSignature {
    /// Construct a composite signature from raw bytes for both legs.
    pub fn new(classical: Vec<u8>, pq: Option<Vec<u8>>) -> Self {
        Self { classical, pq }
    }

    /// Returns true if this composite carries a PQ leg.
    pub fn is_hybrid(&self) -> bool {
        self.pq.is_some()
    }
}

/// A composite (classical + post-quantum) public key, suitable for embedding in
/// `tenzro-types::transaction::Transaction`, validator registries, and DID
/// documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositePublicKey {
    /// Classical public key.
    pub classical: PublicKey,
    /// ML-DSA-65 verifying key bytes (1952 bytes when present).
    pub pq: Option<Vec<u8>>,
}

impl CompositePublicKey {
    /// Construct from already-encoded parts.
    pub fn new(classical: PublicKey, pq: Option<Vec<u8>>) -> Self {
        Self { classical, pq }
    }

    /// Returns true if this composite carries a PQ leg.
    pub fn is_hybrid(&self) -> bool {
        self.pq.is_some()
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
    /// Verify a composite signature; both legs must validate when both are
    /// present. Returns `Err(VerificationFailed)` if either leg fails.
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
            Some(pq.verifying_key_bytes().to_vec()),
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
        Ok(CompositeSignature::new(
            classical_sig.to_bytes(),
            Some(pq_sig),
        ))
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
        // 1. Classical leg — always required during the hybrid window.
        let classical_sig =
            Signature::new(self.public_key.key_type(), sig.classical.clone());
        verify_classical(&self.public_key.classical, msg, &classical_sig)?;

        // 2. PQ leg — required iff the composite public key advertises one. If
        //    the verifier was constructed from a PQ-bearing public key then the
        //    signature MUST also carry a PQ leg; we refuse a downgrade to
        //    classical-only.
        match (&self.public_key.pq, &sig.pq) {
            (Some(vk_bytes), Some(sig_bytes)) => {
                ml_dsa_verify(vk_bytes, msg, sig_bytes)?;
                Ok(())
            }
            (Some(_), None) => Err(CryptoError::InvalidSignature(
                "composite public key advertises PQ leg but signature is classical-only \
                 (downgrade rejected)"
                    .to_string(),
            )),
            (None, Some(_)) => Err(CryptoError::InvalidSignature(
                "composite signature carries PQ leg but public key has none".to_string(),
            )),
            (None, None) => Ok(()),
        }
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
        assert!(sig.is_hybrid());

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    fn hybrid_rejects_tampered_classical_leg() {
        let signer = fresh_hybrid_signer();
        let msg = b"abc";
        let mut sig = signer.sign(msg).unwrap();
        // Flip the last byte of the classical signature.
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
        // Flip a byte deep inside the PQ signature.
        let pq = sig.pq.as_mut().unwrap();
        pq[100] ^= 0x01;

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        assert!(verifier.verify(msg, &sig).is_err());
    }

    #[test]
    fn hybrid_rejects_downgrade_to_classical_only() {
        let signer = fresh_hybrid_signer();
        let msg = b"abc";
        let mut sig = signer.sign(msg).unwrap();
        sig.pq = None; // strip the PQ leg

        let verifier = StandardHybridVerifier::new(signer.public_key().clone());
        let err = verifier.verify(msg, &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
    }

    #[test]
    fn classical_only_pubkey_accepts_classical_only_sig() {
        // Pre-migration messages: PK has no PQ leg, signature has no PQ leg.
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical_signer = Ed25519SignerImpl::new(kp).unwrap();
        let msg = b"legacy-tx";
        let classical_sig = classical_signer.sign(msg).unwrap();

        let composite_pk = CompositePublicKey::new(classical_signer.public_key().clone(), None);
        let composite_sig = CompositeSignature::new(classical_sig.to_bytes(), None);

        let verifier = StandardHybridVerifier::new(composite_pk);
        verifier.verify(msg, &composite_sig).unwrap();
    }

    #[test]
    fn classical_only_pubkey_rejects_pq_bearing_sig() {
        // Defence in depth: a classical-only PK must not be tricked into
        // accepting a forged PQ-bearing signature whose PQ leg might decode.
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical_signer = Ed25519SignerImpl::new(kp).unwrap();
        let msg = b"abc";
        let classical_sig = classical_signer.sign(msg).unwrap();

        let composite_pk = CompositePublicKey::new(classical_signer.public_key().clone(), None);
        let composite_sig =
            CompositeSignature::new(classical_sig.to_bytes(), Some(vec![0u8; 3309]));

        let verifier = StandardHybridVerifier::new(composite_pk);
        let err = verifier.verify(msg, &composite_sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
    }
}
