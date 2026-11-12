//! A node's Ed25519, ML-DSA-65, X25519 and ML-KEM-768 keys, derived on demand
//! from this machine's hardware.
//!
//! None of these key types can be held by a TPM or the Secure Enclave, so none
//! of them is generated, stored or sealed. Each is derived from the machine's
//! non-exportable hardware key ([`tenzro_device_key::DerivationRoot`]) at the
//! moment it signs or agrees, used for that one operation and wiped. The same
//! machine always derives the same keys, so their public halves are stable and
//! can be registered once (genesis, staking, the model-recipient directory).
//!
//! A machine with neither a TPM nor a Secure Enclave has no derivation root,
//! and [`NodeKeys::open`] refuses with [`KeygenError::KeyMissing`]. There is
//! nothing to provision beyond the hardware root itself: no `init` writes key
//! files, because there are none.
//!
//! Keys the hardware holds natively (P-256) are not here; they are created and
//! used inside it through `tenzro_device_key::signer`.
//!
//! # Genesis
//!
//! [`ValidatorPubkeys::to_genesis_toml`] renders the two validator public
//! keys as a `[[validators]]` stanza.

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use tenzro_crypto::hybrid_seal::{HybridPublicKey, HybridRecipient};
use tenzro_crypto::signatures::{Signature, Signer};
use tenzro_crypto::vrf::{VrfProof, VrfProver, VrfPublicKey};
use tenzro_crypto::{CryptoError, KeyType, PublicKey};
use tenzro_device_key::DerivationRoot;

/// What can go wrong reaching a node's keys.
#[derive(Debug, Error)]
pub enum KeygenError {
    /// This machine has no hardware root to derive the key from.
    #[error("{kind} unavailable ({path}): {hint}")]
    KeyMissing {
        /// Which key, in words.
        kind: &'static str,
        /// Where it would have come from, and why it did not.
        path: String,
        /// What the operator can do.
        hint: &'static str,
    },

    /// Anything else, with its own message.
    #[error("{0}")]
    Other(String),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, KeygenError>;

/// Label of the validator Ed25519 key.
pub const VALIDATOR_ED25519_LABEL: &str = "tenzro/validator/ed25519";
/// Label of the validator VRF key: an Ed25519-curve key of its own, so a VRF
/// proof and a signature never share a secret or a nonce.
pub const VALIDATOR_VRF_LABEL: &str = "tenzro/validator/vrf";
/// Label of the validator ML-DSA-65 key.
pub const VALIDATOR_ML_DSA_LABEL: &str = "tenzro/validator/ml-dsa-65";
/// Label of the X25519 key sealed model shards are wrapped to.
pub const MODEL_RECIPIENT_LABEL: &str = "tenzro/node/model-recipient";
/// Label of the X25519 key machine images and secrets are sealed to.
pub const MACHINE_SEALING_LABEL: &str = "tenzro/node/machine-sealing";
/// Label of the P-256 key the node signs its access tokens with (ES256).
pub const ACCESS_TOKEN_LABEL: &str = "tenzro/node/access-token";

fn other(e: impl std::fmt::Display) -> KeygenError {
    KeygenError::Other(e.to_string())
}

/// This machine's derivation root, shared by every signer handed out.
///
/// Holds no private key: the root's private half stays in hardware, and every
/// derived key lives only for the call that uses it.
#[derive(Clone)]
pub struct NodeKeys {
    root: Arc<DerivationRoot>,
}

impl NodeKeys {
    /// The keys of the node whose data directory is `data_dir`.
    ///
    /// In a release build the data directory does not enter the derivation:
    /// the keys belong to the machine. Refuses when the machine has no TPM or
    /// Secure Enclave, or its TPM root authorization is not provisioned.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_root(data_dir).map(|root| Self { root })
    }

    /// The machine's root, opened once per process and shared, so the
    /// hardware loads it once rather than on every open.
    #[cfg(not(any(test, feature = "test-keys")))]
    fn open_root(_data_dir: &Path) -> Result<Arc<DerivationRoot>> {
        static ROOT: std::sync::Mutex<Option<Arc<DerivationRoot>>> = std::sync::Mutex::new(None);
        let mut slot = ROOT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(root) = slot.as_ref() {
            return Ok(root.clone());
        }
        let root = Arc::new(DerivationRoot::open_or_create().map_err(|e| {
            KeygenError::KeyMissing {
                kind: "node keys",
                path: format!("hardware derivation root: {e}"),
                hint: "run the node on a machine with a TPM 2.0 provisioned with `tenzro-node tpm \
                       provision` (its attestation key authorises the root) or a Secure Enclave",
            }
        })?);
        *slot = Some(root.clone());
        Ok(root)
    }

    /// Tests only: a software root per data directory, so several test nodes
    /// in one process have distinct keys.
    #[cfg(any(test, feature = "test-keys"))]
    fn open_root(data_dir: &Path) -> Result<Arc<DerivationRoot>> {
        use sha2::{Digest, Sha256};
        let ikm: [u8; 32] = Sha256::digest(data_dir.as_os_str().as_encoded_bytes()).into();
        Ok(Arc::new(DerivationRoot::for_tests(ikm)))
    }

    /// The public halves of the validator keys.
    pub fn validator_pubkeys(&self) -> Result<ValidatorPubkeys> {
        let ed25519 = self
            .root
            .ed25519_public(VALIDATOR_ED25519_LABEL)
            .map_err(other)?
            .to_vec();
        let ml_dsa_65 = self.ml_dsa_verifying_key()?;
        Ok(ValidatorPubkeys { ed25519, ml_dsa_65 })
    }

    /// The validator Ed25519 public key.
    pub fn ed25519_public_key(&self) -> Result<PublicKey> {
        self.root
            .ed25519_public(VALIDATOR_ED25519_LABEL)
            .map(|k| PublicKey::new(KeyType::Ed25519, k.to_vec()))
            .map_err(other)
    }

    /// A [`Signer`] for the validator Ed25519 key: every signature derives the
    /// key, signs, and wipes it.
    pub fn ed25519_signer(&self) -> Result<DerivedEd25519Signer> {
        Ok(DerivedEd25519Signer {
            public: self.ed25519_public_key()?,
            keys: self.clone(),
        })
    }

    /// The raw `x || y` public key access tokens verify under.
    pub fn access_token_public_key(&self) -> Result<[u8; 64]> {
        self.root.p256_public(ACCESS_TOKEN_LABEL).map_err(other)
    }

    /// Sign an access token's SHA-256 prehash with the access-token key:
    /// the key is derived, signs once, and is wiped.
    pub fn sign_access_token(&self, prehash: &[u8; 32]) -> Result<[u8; 64]> {
        self.root
            .p256_sign_prehash(ACCESS_TOKEN_LABEL, prehash)
            .map_err(other)
    }

    /// The validator VRF key's public half (32 bytes): the key its VRF
    /// proofs verify under, registered beside the node key.
    pub fn vrf_public_key(&self) -> Result<[u8; 32]> {
        self.root.ed25519_public(VALIDATOR_VRF_LABEL).map_err(other)
    }

    /// A [`VrfProver`] over the validator VRF key, which is not the
    /// validator Ed25519 signing key.
    pub fn vrf_prover(&self) -> Result<DerivedVrfProver> {
        Ok(DerivedVrfProver {
            public: VrfPublicKey(self.vrf_public_key()?),
            keys: self.clone(),
        })
    }

    /// The validator ML-DSA-65 verifying key (1952 bytes).
    pub fn ml_dsa_verifying_key(&self) -> Result<Vec<u8>> {
        self.root
            .ml_dsa65_public(VALIDATOR_ML_DSA_LABEL)
            .map_err(other)
    }

    /// The hybrid X25519 + ML-KEM-768 key sealed model shards are wrapped
    /// to, as an envelope recipient.
    pub fn model_recipient(&self) -> Result<DerivedHybridRecipient> {
        self.hybrid_recipient(MODEL_RECIPIENT_LABEL)
    }

    /// The hybrid X25519 + ML-KEM-768 key machine images and secrets are
    /// sealed to, as an envelope recipient.
    pub fn machine_sealing(&self) -> Result<DerivedHybridRecipient> {
        self.hybrid_recipient(MACHINE_SEALING_LABEL)
    }

    fn hybrid_recipient(&self, label: &'static str) -> Result<DerivedHybridRecipient> {
        let public = HybridPublicKey {
            x25519: self.root.x25519_public(label).map_err(other)?,
            ml_kem: self.root.ml_kem768_public(label).map_err(other)?,
        };
        Ok(DerivedHybridRecipient {
            label,
            public,
            keys: self.clone(),
        })
    }

    fn sign_ed25519(&self, message: &[u8]) -> tenzro_crypto::Result<[u8; 64]> {
        self.root
            .ed25519_sign(VALIDATOR_ED25519_LABEL, message)
            .map_err(|e| CryptoError::Other(format!("derived Ed25519 signature: {e}")))
    }

    /// An ML-DSA-65 signature by the validator key under the FIPS 204 context
    /// string `ctx`.
    pub fn sign_ml_dsa(
        &self,
        ctx: &'static [u8],
        message: &[u8],
    ) -> tenzro_crypto::Result<Vec<u8>> {
        self.root
            .ml_dsa65_sign(VALIDATOR_ML_DSA_LABEL, ctx, message)
            .map_err(|e| CryptoError::Other(format!("derived ML-DSA-65 signature: {e}")))
    }
}

/// The validator Ed25519 key as a [`Signer`]. Holds only the public key.
#[derive(Clone)]
pub struct DerivedEd25519Signer {
    public: PublicKey,
    keys: NodeKeys,
}

impl Signer for DerivedEd25519Signer {
    fn sign(&self, message: &[u8]) -> tenzro_crypto::Result<Signature> {
        let sig = self.keys.sign_ed25519(message)?;
        Ok(Signature::new(KeyType::Ed25519, sig.to_vec()))
    }

    fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

/// The validator VRF key as a [`VrfProver`]. Holds only the public key.
#[derive(Clone)]
pub struct DerivedVrfProver {
    public: VrfPublicKey,
    keys: NodeKeys,
}

impl VrfProver for DerivedVrfProver {
    fn public_key(&self) -> VrfPublicKey {
        self.public
    }

    fn prove(&self, alpha: &[u8]) -> tenzro_crypto::Result<VrfProof> {
        self.keys
            .root
            .vrf_prove(VALIDATOR_VRF_LABEL, alpha)
            .map_err(|e| CryptoError::Other(format!("derived VRF key: {e}")))
    }
}

/// One of the node's hybrid X25519 + ML-KEM-768 keys as a
/// [`HybridRecipient`]. Holds only the public key; each agreement and each
/// decapsulation derives its key and wipes it.
#[derive(Clone)]
pub struct DerivedHybridRecipient {
    label: &'static str,
    public: HybridPublicKey,
    keys: NodeKeys,
}

impl HybridRecipient for DerivedHybridRecipient {
    fn public_key(&self) -> HybridPublicKey {
        self.public.clone()
    }

    fn agree_x25519(
        &self,
        share: &[u8; 32],
    ) -> tenzro_crypto::Result<zeroize::Zeroizing<[u8; 32]>> {
        self.keys
            .root
            .x25519_agree(self.label, share)
            .map_err(|e| CryptoError::DecryptionFailed(format!("derived X25519 agreement: {e}")))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> tenzro_crypto::Result<zeroize::Zeroizing<[u8; 32]>> {
        self.keys
            .root
            .ml_kem768_decapsulate(self.label, ciphertext)
            .map_err(|e| {
                CryptoError::DecryptionFailed(format!("derived ML-KEM-768 decapsulation: {e}"))
            })
    }
}

/// The public halves of a validator's keys. Safe to print and serialize.
#[derive(Clone)]
pub struct ValidatorPubkeys {
    /// 32-byte Ed25519 public key
    pub ed25519: Vec<u8>,
    /// 1952-byte ML-DSA-65 verifying key
    pub ml_dsa_65: Vec<u8>,
}

impl ValidatorPubkeys {
    /// Render this validator's pubkeys as a `[[validators]]` TOML stanza
    /// suitable for direct concatenation into a genesis file.
    ///
    /// `stake` is denominated in the smallest TNZO unit the genesis parser
    /// expects (`GenesisValidator::stake: u64`).
    pub fn to_genesis_toml(&self, stake: u64) -> String {
        let mut s = String::new();
        s.push_str("[[validators]]\n");
        s.push_str(&format!(
            "public_key = \"0x{}\"\n",
            hex::encode(&self.ed25519)
        ));
        s.push_str(&format!(
            "pq_public_key = \"0x{}\"\n",
            hex::encode(&self.ml_dsa_65)
        ));
        s.push_str(&format!("stake = {}\n", stake));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::{Ed25519VerifierImpl, Verifier};

    fn keys(dir: &str) -> NodeKeys {
        NodeKeys::open(Path::new(dir)).unwrap()
    }

    #[test]
    fn the_same_node_always_derives_the_same_keys() {
        let a = keys("/n1").validator_pubkeys().unwrap();
        let b = keys("/n1").validator_pubkeys().unwrap();
        assert_eq!(a.ed25519, b.ed25519);
        assert_eq!(a.ml_dsa_65, b.ml_dsa_65);
        assert_eq!(a.ml_dsa_65.len(), tenzro_crypto::ML_DSA_65_VK_LEN);
        let c = keys("/n2").validator_pubkeys().unwrap();
        assert_ne!(a.ed25519, c.ed25519);
    }

    #[test]
    fn the_derived_signer_verifies_under_the_published_key() {
        let k = keys("/n1");
        let signer = k.ed25519_signer().unwrap();
        let sig = signer.sign(b"announce").unwrap();
        let verifier = Ed25519VerifierImpl::new(signer.public_key().clone()).unwrap();
        assert!(verifier.verify(b"announce", &sig).is_ok());
        assert!(verifier.verify(b"other", &sig).is_err());
        assert_eq!(
            signer.public_key().as_bytes(),
            &k.validator_pubkeys().unwrap().ed25519[..]
        );
    }

    #[test]
    fn model_recipient_and_machine_sealing_are_different_keys() {
        let k = keys("/n1");
        let a = k.model_recipient().unwrap();
        let b = k.machine_sealing().unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.public_key().ml_kem, b.public_key().ml_kem);
        assert_eq!(a.public_key(), k.model_recipient().unwrap().public_key());
    }

    #[test]
    fn an_envelope_to_the_derived_recipient_opens_and_another_does_not() {
        use tenzro_crypto::encryption::{envelope_decrypt, envelope_encrypt};
        let k = keys("/n1");
        let r = k.model_recipient().unwrap();
        let env = envelope_encrypt(&r.public_key(), b"shard key").unwrap();
        assert_eq!(envelope_decrypt(&r, &env).unwrap(), b"shard key");
        assert!(envelope_decrypt(&k.machine_sealing().unwrap(), &env).is_err());
    }

    #[test]
    fn the_vrf_prover_verifies_under_its_own_key() {
        let k = keys("/n1");
        let p = k.vrf_prover().unwrap();
        let proof = p.prove(b"alpha").unwrap();
        assert!(tenzro_crypto::vrf::verify(&p.public_key(), b"alpha", &proof).is_ok());
        assert!(tenzro_crypto::vrf::verify(&p.public_key(), b"beta", &proof).is_err());
        assert_ne!(
            &p.public_key().0[..],
            &k.validator_pubkeys().unwrap().ed25519[..],
            "the VRF key is not the signing key"
        );
        assert_eq!(p.public_key().0, k.vrf_public_key().unwrap());
    }

    /// RFC 9381 encode_to_curve (try and increment) for Edwards25519, as the
    /// prover computes it: the point whose encoding the prover's nonce is
    /// derived from.
    fn vrf_h_string(pk: &[u8; 32], alpha: &[u8]) -> [u8; 32] {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use sha2::{Digest, Sha512};
        for ctr in 0u8..=255 {
            let mut h = Sha512::new();
            h.update([0x04, 0x01]);
            h.update(pk);
            h.update(alpha);
            h.update([ctr, 0x00]);
            let h = h.finalize();
            let candidate: [u8; 32] = h[..32].try_into().unwrap();
            if let Some(p) = CompressedEdwardsY(candidate).decompress() {
                return p.mul_by_cofactor().compress().to_bytes();
            }
        }
        unreachable!()
    }

    #[test]
    fn a_vrf_proof_and_a_signature_never_reveal_the_signing_key() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest, Sha512};

        let k = keys("/tmp/tenzro-keygen-test-vrf-recovery");
        let prover = k.vrf_prover().unwrap();
        let alpha = b"beacon round 7";
        let proof = prover.prove(alpha).unwrap();
        let pi = proof.as_bytes();

        // The message a signer would be asked to sign: the VRF's own
        // hashed-to-curve input, from which the VRF nonce is derived.
        let h_string = vrf_h_string(&prover.public_key().0, alpha);
        let signer = k.ed25519_signer().unwrap();
        let sig = signer.sign(&h_string).unwrap();
        let sig = sig.as_bytes();
        let pk: [u8; 32] = k
            .ed25519_public_key()
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();

        let mut c = [0u8; 32];
        c[..16].copy_from_slice(&pi[32..48]);
        let c = Scalar::from_bytes_mod_order(c);
        let s = Scalar::from_bytes_mod_order(pi[48..80].try_into().unwrap());
        let big_s = Scalar::from_bytes_mod_order(sig[32..64].try_into().unwrap());
        let hram = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(&sig[..32])
                .chain_update(pk)
                .chain_update(h_string)
                .finalize()
                .into(),
        );
        // With one shared key and nonce, s - S = (c - hram) x.
        let x = (s - big_s) * (c - hram).invert();
        assert_ne!(
            (ED25519_BASEPOINT_POINT * x).compress().to_bytes(),
            pk,
            "the validator signing key was recovered from a VRF proof and one signature"
        );
        assert_ne!(prover.public_key().0, pk, "the VRF key is the signing key");
    }

    #[test]
    fn genesis_toml_has_both_pubkeys() {
        let s = keys("/n1").validator_pubkeys().unwrap().to_genesis_toml(10);
        for field in ["public_key", "pq_public_key", "stake = 10"] {
            assert!(s.contains(field), "{s}");
        }
    }

    #[test]
    fn nothing_is_written_to_the_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let k = NodeKeys::open(dir.path()).unwrap();
        k.validator_pubkeys().unwrap();
        k.ed25519_signer().unwrap().sign(b"x").unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
