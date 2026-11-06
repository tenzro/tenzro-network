//! Moving a hardware-derived identity's authority to a post-quantum key
//! without changing its DID.
//!
//! A DID is a function of the P-256 key that rooted it (a passkey or a
//! TPM/Secure Enclave device key), and that stays true forever: the DID is
//! never recomputed. What a rotation changes is which key *governs* the
//! identity from now on. A [`PqRotation`] names an ML-DSA-65 verifying key
//! and is signed twice over the same statement:
//!
//! - by the key that currently governs the identity: the P-256 root key for
//!   the first rotation, the ML-DSA key installed by the previous rotation
//!   after that;
//! - by the new ML-DSA key, proving its holder has it.
//!
//! After the first rotation the P-256 key no longer governs, so an attacker
//! who can forge P-256 signatures cannot take the identity: every later
//! rotation needs an ML-DSA signature by the current authority.
//!
//! Each rotation carries a sequence number one above the last, so an old
//! rotation cannot be replayed, and states where the new key lives. Only a
//! key in the Secure Enclave or a TPM is hardware-held; a software key is
//! accepted and labelled as software, never presented as hardware.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{IdentityError, Result};

/// Domain tag for the rotation statement.
const ROTATION_DOMAIN: &[u8] = b"tenzro/identity/pq-rotation/v1\0";

pub use tenzro_crypto::ML_DSA_65_VK_LEN;

/// Metadata keys a rotation records on the identity.
pub const META_PQ_AUTHORITY: &str = "pq_authority_key";
pub const META_PQ_SEQUENCE: &str = "pq_rotation_sequence";
pub const META_PQ_BACKEND: &str = "pq_authority_backend";

/// Where the new post-quantum key is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqKeyBackend {
    /// Apple Secure Enclave (CryptoKit ML-DSA).
    SecureEnclave,
    /// A TPM implementing the post-quantum algorithms.
    Tpm,
    /// A key held in software. Accepted, and labelled as such.
    Software,
}

impl PqKeyBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure_enclave",
            Self::Tpm => "tpm",
            Self::Software => "software",
        }
    }
}

/// A signed rotation of an identity's governing key to ML-DSA-65.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRotation {
    pub did: String,
    pub new_pq_key: Vec<u8>,
    pub backend: PqKeyBackend,
    /// One above the identity's last rotation (the first is 1).
    pub sequence: u64,
    /// Signature over [`PqRotation::statement`] by the governing key: raw
    /// `r || s` P-256 for the first rotation, ML-DSA-65 after that.
    pub authority_signature: Vec<u8>,
    /// ML-DSA-65 signature over the statement by `new_pq_key`.
    pub new_key_signature: Vec<u8>,
}

/// Who currently governs an identity.
pub enum Authority<'a> {
    /// The P-256 key the DID derives from (no rotation yet). Raw `x || y` or
    /// SEC1.
    RootKey(&'a [u8]),
    /// The ML-DSA-65 key installed by the last rotation.
    PqKey(&'a [u8]),
}

impl PqRotation {
    /// The bytes both keys sign.
    pub fn statement(
        did: &str,
        new_pq_key: &[u8],
        backend: PqKeyBackend,
        sequence: u64,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ROTATION_DOMAIN);
        h.update((did.len() as u32).to_be_bytes());
        h.update(did.as_bytes());
        h.update((new_pq_key.len() as u32).to_be_bytes());
        h.update(new_pq_key);
        h.update(backend.as_str().as_bytes());
        h.update(sequence.to_be_bytes());
        h.finalize().into()
    }

    /// Verify this rotation against the identity's current authority and
    /// last sequence number.
    pub fn verify(&self, authority: Authority<'_>, last_sequence: u64) -> Result<()> {
        let refuse = |m: &str| {
            IdentityError::PermissionDenied(format!("post-quantum rotation refused: {m}"))
        };
        if self.new_pq_key.len() != ML_DSA_65_VK_LEN {
            return Err(refuse("the new key is not an ML-DSA-65 verifying key"));
        }
        if self.sequence != last_sequence.saturating_add(1) {
            return Err(refuse(
                "the sequence number does not follow the last rotation",
            ));
        }
        let statement = Self::statement(&self.did, &self.new_pq_key, self.backend, self.sequence);
        match authority {
            Authority::RootKey(key) => {
                if !tenzro_types::did_derivation::did_derives_from_key(&self.did, key) {
                    return Err(refuse("the DID does not derive from the governing key"));
                }
                let raw = if key.len() == 65 { &key[1..] } else { key };
                let verifier = tenzro_crypto::P256Verifier::from_public_key_bytes(raw)
                    .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
                let sig = tenzro_crypto::P256Signature::from_slice(&self.authority_signature)
                    .map_err(|e| IdentityError::PermissionDenied(e.to_string()))?;
                if verifier.verify_sha256(&statement, &sig).is_err() {
                    return Err(refuse("the governing P-256 key did not sign it"));
                }
            }
            Authority::PqKey(key) => {
                if tenzro_crypto::pq::ml_dsa_verify(
                    key,
                    tenzro_crypto::pq::context::PQ_ROTATION,
                    &statement,
                    &self.authority_signature,
                )
                .is_err()
                {
                    return Err(refuse("the governing ML-DSA key did not sign it"));
                }
            }
        }
        if tenzro_crypto::pq::ml_dsa_verify(
            &self.new_pq_key,
            tenzro_crypto::pq::context::PQ_ROTATION,
            &statement,
            &self.new_key_signature,
        )
        .is_err()
        {
            return Err(refuse(
                "the new key did not sign it, so possession is not proven",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    pub(crate) fn root(seed: u8) -> (SigningKey, Vec<u8>) {
        let k = SigningKey::from_slice(&[seed; 32]).unwrap();
        let raw = k.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec();
        (k, raw)
    }

    pub(crate) fn pq(seed: u8) -> tenzro_crypto::pq::MlDsaSigningKey {
        tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[seed; 32]).unwrap()
    }

    pub(crate) fn rotation_by_root(
        root_key: &SigningKey,
        did: &str,
        new: &tenzro_crypto::pq::MlDsaSigningKey,
        seq: u64,
    ) -> PqRotation {
        let vk = new.verifying_key_bytes().to_vec();
        let st = PqRotation::statement(did, &vk, PqKeyBackend::SecureEnclave, seq);
        let sig: p256::ecdsa::Signature = root_key.sign(&st);
        PqRotation {
            did: did.to_string(),
            new_key_signature: new.sign(tenzro_crypto::pq::context::PQ_ROTATION, &st),
            new_pq_key: vk,
            backend: PqKeyBackend::SecureEnclave,
            sequence: seq,
            authority_signature: sig.to_bytes().to_vec(),
        }
    }

    fn human(raw: &[u8]) -> String {
        format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(raw)
        )
    }

    #[test]
    fn the_root_key_rotates_to_ml_dsa_and_then_loses_authority() {
        let (rk, raw) = root(1);
        let did = human(&raw);
        let first = pq(2);
        let r1 = rotation_by_root(&rk, &did, &first, 1);
        r1.verify(Authority::RootKey(&raw), 0).unwrap();

        // A second rotation signed by the P-256 root is refused once the
        // ML-DSA key governs.
        let r2 = rotation_by_root(&rk, &did, &pq(3), 2);
        assert!(r2.verify(Authority::PqKey(&r1.new_pq_key), 1).is_err());

        // Signed by the governing ML-DSA key it is accepted.
        let next = pq(3);
        let vk = next.verifying_key_bytes().to_vec();
        let st = PqRotation::statement(&did, &vk, PqKeyBackend::Software, 2);
        let r2 = PqRotation {
            did: did.clone(),
            new_key_signature: next.sign(tenzro_crypto::pq::context::PQ_ROTATION, &st),
            new_pq_key: vk,
            backend: PqKeyBackend::Software,
            sequence: 2,
            authority_signature: first.sign(tenzro_crypto::pq::context::PQ_ROTATION, &st),
        };
        r2.verify(Authority::PqKey(&r1.new_pq_key), 1).unwrap();
    }

    #[test]
    fn replay_foreign_roots_and_unproven_keys_are_refused() {
        let (rk, raw) = root(1);
        let did = human(&raw);
        let r = rotation_by_root(&rk, &did, &pq(2), 1);
        assert!(
            r.verify(Authority::RootKey(&raw), 1).is_err(),
            "replayed sequence"
        );
        let (_, other) = root(9);
        assert!(
            r.verify(Authority::RootKey(&other), 0).is_err(),
            "a key the DID does not derive from"
        );
        let mut unproven = r.clone();
        unproven.new_key_signature = pq(5).sign(
            tenzro_crypto::pq::context::PQ_ROTATION,
            &PqRotation::statement(&did, &r.new_pq_key, r.backend, 1),
        );
        assert!(
            unproven.verify(Authority::RootKey(&raw), 0).is_err(),
            "new key possession not proven"
        );
        let mut relabelled = r;
        relabelled.backend = PqKeyBackend::Tpm;
        assert!(
            relabelled.verify(Authority::RootKey(&raw), 0).is_err(),
            "the backend label is signed"
        );
    }
}
