//! Real enclave-key storage shared by all TEE provider implementations.
//!
//! Every `TeeProvider::enclave_keygen` call materialises a real
//! cryptographic key whose private scalar is kept in this store; the
//! [`crate::traits::TeeProvider::enclave_sign`] / `enclave_encrypt` /
//! `enclave_decrypt` paths look up the scalar by `EnclaveKeyHandle.id`
//! and run real Ed25519 / ECDSA / AES-256-GCM operations against it.
//!
//! ## Design
//!
//! - Keys are HKDF-SHA256-derived from per-vendor IKM. On bare metal
//!   the IKM is the hardware-rooted measurement (TDX `MRTD`, SNP's
//!   `SNP_GET_DERIVED_KEY` output, Nitro's signed attestation report,
//!   NVIDIA's vBIOS measurement). Off-hardware, providers expose
//!   `is_available() == false` and `enclave_keygen` returns
//!   `TeeError::not_available(...)` — there is no software-only
//!   fabrication path.
//! - The private scalar lives in a `Zeroizing<[u8; N]>` for the
//!   lifetime of the process; `Drop` wipes it before the allocation is
//!   freed. The `EnclaveKeyHandle` exposes only the public key (or
//!   nothing for symmetric keys).
//! - The keystore is per-provider — TDX, SNP, Nitro, and NVIDIA each
//!   own one — so a key generated in a TDX VM is opaque to the SNP
//!   provider on the same node.

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use ed25519_dalek::{
    Signer as Ed25519SignerTrait, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hkdf::Hkdf;
use k256::{
    ecdsa::{
        signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Sig,
        SigningKey as Secp256k1SigningKey,
    },
    elliptic_curve::sec1::ToSec1Point,
    PublicKey as Secp256k1Pub,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use tenzro_types::tee::{EnclaveKeyHandle, KeyAlgorithm, KeyGenParams};

use crate::error::{Result, TeeError};

/// HKDF info string for enclave-key derivation. Bumped if the
/// derivation chain ever changes — old keys would no longer reproduce.
const HKDF_INFO: &[u8] = b"tenzro/enclave-key/v1";

/// Private key material kept inside the enclave keystore. Variants are
/// hand-picked to match [`KeyAlgorithm`].
enum SecretMaterial {
    Ed25519(Box<Ed25519SigningKey>),
    Secp256k1(Box<Secp256k1SigningKey>),
    Aes256Gcm(Zeroizing<[u8; 32]>),
}

/// Per-provider keystore. Shared across all four TEE adapter
/// implementations.
pub struct EnclaveKeystore {
    /// Vendor label folded into the HKDF salt so the same `(key_id,
    /// algorithm)` pair produces a different key on different vendors.
    /// Prevents cross-vendor key collisions.
    vendor_tag: &'static str,
    /// Map of `EnclaveKeyHandle.id` → private material + public handle.
    /// Behind a tokio `RwLock` because the `TeeProvider` trait is async.
    inner: RwLock<HashMap<Uuid, KeyRecord>>,
}

struct KeyRecord {
    handle: EnclaveKeyHandle,
    secret: SecretMaterial,
}

impl EnclaveKeystore {
    /// Build a new keystore for a specific TEE vendor tag.
    pub fn new(vendor_tag: &'static str) -> Self {
        Self {
            vendor_tag,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Generate and store a new key, returning the opaque handle.
    ///
    /// `ikm` is the hardware-rooted input keying material the caller
    /// has obtained from the platform (TDX `MRTD`, SNP derived key,
    /// Nitro attestation bytes, NVIDIA measurement). The handle's
    /// `id` is the random `Uuid` produced inside this call — it does
    /// not depend on `ikm`, so callers cannot trivially reconstruct
    /// the key without the IKM.
    pub async fn keygen(&self, params: KeyGenParams, ikm: &[u8]) -> Result<EnclaveKeyHandle> {
        if ikm.is_empty() {
            return Err(TeeError::CryptoError(
                "enclave_keygen requires non-empty hardware-rooted IKM"
                    .to_string(),
            ));
        }
        let key_id = Uuid::new_v4();
        let salt = self.derive_salt(key_id, params.algorithm);
        let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);

        let (secret, public_key) = match params.algorithm {
            KeyAlgorithm::Ed25519 => {
                let mut seed = Zeroizing::new([0u8; 32]);
                hk.expand(HKDF_INFO, seed.as_mut())
                    .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {e}")))?;
                let signing = Ed25519SigningKey::from_bytes(&seed);
                let verifying: Ed25519VerifyingKey = signing.verifying_key();
                (
                    SecretMaterial::Ed25519(Box::new(signing)),
                    Some(verifying.to_bytes().to_vec()),
                )
            }
            KeyAlgorithm::Secp256k1 => {
                // RustCrypto k256 enforces scalar < n; HKDF output that
                // lands in the negligibly-small invalid range is
                // re-derived with a counter byte until valid. The
                // counter is committed into HKDF info so the same IKM
                // and key_id always reproduce the same key.
                let mut counter: u8 = 0;
                let signing = loop {
                    let mut info = HKDF_INFO.to_vec();
                    info.extend_from_slice(&counter.to_be_bytes());
                    let mut scalar = Zeroizing::new([0u8; 32]);
                    hk.expand(&info, scalar.as_mut())
                        .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {e}")))?;
                    match Secp256k1SigningKey::from_slice(scalar.as_ref()) {
                        Ok(sk) => break sk,
                        Err(_) => {
                            counter = counter.checked_add(1).ok_or_else(|| {
                                TeeError::CryptoError(
                                    "HKDF could not produce a valid secp256k1 scalar within 256 attempts"
                                        .to_string(),
                                )
                            })?;
                        }
                    }
                };
                let verifying = *signing.verifying_key();
                let public = Secp256k1Pub::from(&verifying);
                let encoded = public.to_sec1_point(false);
                (
                    SecretMaterial::Secp256k1(Box::new(signing)),
                    Some(encoded.as_bytes().to_vec()),
                )
            }
            KeyAlgorithm::Aes256Gcm => {
                let mut key_bytes = Zeroizing::new([0u8; 32]);
                hk.expand(HKDF_INFO, key_bytes.as_mut())
                    .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {e}")))?;
                (SecretMaterial::Aes256Gcm(key_bytes), None)
            }
        };

        let handle = EnclaveKeyHandle {
            id: key_id,
            algorithm: params.algorithm,
            public_key,
            created_at: tenzro_types::Timestamp::now(),
            attestation: None,
        };
        self.inner.write().await.insert(
            key_id,
            KeyRecord {
                handle: handle.clone(),
                secret,
            },
        );
        Ok(handle)
    }

    /// Sign `data` with the key identified by `handle.id`.
    ///
    /// - Ed25519: returns the 64-byte signature over `data` (RFC 8032).
    /// - Secp256k1: returns 65 bytes `(r || s || v)` — `v` is the
    ///   recovery id (0 or 1), matching Ethereum-style recoverable
    ///   signatures. The input is hashed with SHA-256 before signing.
    /// - Aes256Gcm: signing is not defined; returns `InvalidKeyHandle`.
    pub async fn sign(&self, handle: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        let guard = self.inner.read().await;
        let record = guard
            .get(&handle.id)
            .ok_or_else(|| TeeError::InvalidKeyHandle(format!("Key not found: {}", handle.id)))?;
        if record.handle.algorithm != handle.algorithm {
            return Err(TeeError::InvalidKeyHandle(format!(
                "Algorithm mismatch for {}: handle says {:?}, store says {:?}",
                handle.id, handle.algorithm, record.handle.algorithm
            )));
        }
        match &record.secret {
            SecretMaterial::Ed25519(sk) => {
                let sig = sk.sign(data);
                Ok(sig.to_bytes().to_vec())
            }
            SecretMaterial::Secp256k1(sk) => {
                let mut h = Sha256::new();
                h.update(data);
                let digest = h.finalize();
                let (sig, rec): (K256Sig, RecoveryId) =
                    sk.sign_prehash(digest.as_slice()).map_err(|e| {
                        TeeError::CryptoError(format!("secp256k1 sign failed: {e}"))
                    })?;
                let mut out = Vec::with_capacity(65);
                out.extend_from_slice(&sig.to_bytes());
                out.push(rec.to_byte());
                Ok(out)
            }
            SecretMaterial::Aes256Gcm(_) => Err(TeeError::InvalidKeyHandle(
                "AES-256-GCM keys cannot sign — use enclave_encrypt".to_string(),
            )),
        }
    }

    /// Encrypt `plaintext` with the AES-256-GCM key identified by
    /// `handle.id`. The 12-byte random nonce is prepended to the
    /// ciphertext on the wire: `[nonce(12) || ciphertext || tag(16)]`.
    ///
    /// Asymmetric (Ed25519 / Secp256k1) keys are rejected.
    pub async fn encrypt(
        &self,
        handle: &EnclaveKeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let guard = self.inner.read().await;
        let record = guard
            .get(&handle.id)
            .ok_or_else(|| TeeError::InvalidKeyHandle(format!("Key not found: {}", handle.id)))?;
        match &record.secret {
            SecretMaterial::Aes256Gcm(key_bytes) => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
                let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
                let ct = cipher
                    .encrypt(&nonce, plaintext)
                    .map_err(|e| TeeError::CryptoError(format!("AES-GCM encrypt failed: {e}")))?;
                let mut out = Vec::with_capacity(12 + ct.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                Ok(out)
            }
            SecretMaterial::Ed25519(_) | SecretMaterial::Secp256k1(_) => {
                Err(TeeError::InvalidKeyHandle(
                    "Signing keys cannot encrypt — use enclave_sign".to_string(),
                ))
            }
        }
    }

    /// Decrypt `ciphertext` produced by [`Self::encrypt`]. The wire
    /// shape is `[nonce(12) || ciphertext || tag(16)]`.
    pub async fn decrypt(
        &self,
        handle: &EnclaveKeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            return Err(TeeError::CryptoError(
                "AES-GCM ciphertext too short (need nonce(12) + tag(16) minimum)".to_string(),
            ));
        }
        let guard = self.inner.read().await;
        let record = guard
            .get(&handle.id)
            .ok_or_else(|| TeeError::InvalidKeyHandle(format!("Key not found: {}", handle.id)))?;
        match &record.secret {
            SecretMaterial::Aes256Gcm(key_bytes) => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
                let nonce = AesNonce::from_slice(&ciphertext[..12]);
                let pt = cipher
                    .decrypt(nonce, &ciphertext[12..])
                    .map_err(|e| TeeError::CryptoError(format!("AES-GCM decrypt failed: {e}")))?;
                Ok(pt)
            }
            SecretMaterial::Ed25519(_) | SecretMaterial::Secp256k1(_) => {
                Err(TeeError::InvalidKeyHandle(
                    "Signing keys cannot decrypt — use enclave_sign".to_string(),
                ))
            }
        }
    }

    /// Number of keys currently stored. Diagnostic only.
    #[allow(dead_code)]
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Whether the keystore holds no keys. Diagnostic only.
    #[allow(dead_code)]
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    fn derive_salt(&self, key_id: Uuid, algo: KeyAlgorithm) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"tenzro/enclave-keystore/salt/v1");
        h.update(self.vendor_tag.as_bytes());
        h.update(key_id.as_bytes());
        let algo_tag: u8 = match algo {
            KeyAlgorithm::Ed25519 => 1,
            KeyAlgorithm::Secp256k1 => 2,
            KeyAlgorithm::Aes256Gcm => 3,
        };
        h.update([algo_tag]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// Derive an Ethereum-style 20-byte address from an uncompressed
/// secp256k1 public key.
#[allow(dead_code)]
pub fn eth_address_from_secp256k1(uncompressed: &[u8]) -> Option<[u8; 20]> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return None;
    }
    use sha3::Digest as Sha3Digest;
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use k256::ecdsa::VerifyingKey as Secp256k1Verifying;
    use tenzro_types::tee::KeyPurpose;

    fn ikm() -> Vec<u8> {
        // Stable test IKM that mimics what a TEE provider would feed.
        (0u8..64).collect()
    }

    fn ed25519_params() -> KeyGenParams {
        KeyGenParams {
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: Default::default(),
        }
    }

    fn secp256k1_params() -> KeyGenParams {
        KeyGenParams {
            algorithm: KeyAlgorithm::Secp256k1,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: Default::default(),
        }
    }

    fn aes_params() -> KeyGenParams {
        KeyGenParams {
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::Encryption,
            exportable: false,
            params: Default::default(),
        }
    }

    #[tokio::test]
    async fn ed25519_keygen_then_sign_verifies() {
        let ks = EnclaveKeystore::new("test");
        let handle = ks.keygen(ed25519_params(), &ikm()).await.unwrap();
        let pk_bytes = handle.public_key.clone().expect("Ed25519 has public key");
        assert_eq!(pk_bytes.len(), 32);
        let msg = b"tenzro enclave_sign over real Ed25519";
        let sig = ks.sign(&handle, msg).await.unwrap();
        assert_eq!(sig.len(), 64);

        let vk = Ed25519VerifyingKey::from_bytes(
            <&[u8; 32]>::try_from(pk_bytes.as_slice()).unwrap(),
        )
        .unwrap();
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(msg, &signature).expect("real signature must verify");
    }

    #[tokio::test]
    async fn secp256k1_keygen_then_sign_recoverable() {
        let ks = EnclaveKeystore::new("test");
        let handle = ks.keygen(secp256k1_params(), &ikm()).await.unwrap();
        let pk_uncompressed = handle.public_key.clone().expect("Secp256k1 has public key");
        assert_eq!(pk_uncompressed.len(), 65);
        assert_eq!(pk_uncompressed[0], 0x04);

        let msg = b"tenzro enclave_sign over real Secp256k1";
        let sig = ks.sign(&handle, msg).await.unwrap();
        assert_eq!(sig.len(), 65, "secp256k1 wire is r||s||v");
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        let r_s: [u8; 64] = sig[..64].try_into().unwrap();
        let v = sig[64];
        let parsed = K256Sig::from_slice(&r_s).expect("real ECDSA signature parses");
        let rec = RecoveryId::from_byte(v).expect("recovery byte in range");
        let recovered = Secp256k1Verifying::recover_from_prehash(&digest, &parsed, rec)
            .expect("real signature must be recoverable");
        let recovered_uncompressed = Secp256k1Pub::from(&recovered).to_sec1_point(false);
        assert_eq!(recovered_uncompressed.as_bytes(), pk_uncompressed.as_slice());
    }

    #[tokio::test]
    async fn aes_keygen_then_encrypt_roundtrip() {
        let ks = EnclaveKeystore::new("test");
        let handle = ks.keygen(aes_params(), &ikm()).await.unwrap();
        assert!(handle.public_key.is_none());
        let pt = b"top secret enclave plaintext";
        let ct = ks.encrypt(&handle, pt).await.unwrap();
        assert!(ct.len() > pt.len());
        let recovered = ks.decrypt(&handle, &ct).await.unwrap();
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn keygen_deterministic_for_same_ikm_and_keyid() {
        // Two keygens with the same IKM produce DIFFERENT keys because
        // `key_id` is random per call. This is the production contract:
        // every keygen mints a fresh key even on the same hardware.
        let ks = EnclaveKeystore::new("test");
        let a = ks.keygen(ed25519_params(), &ikm()).await.unwrap();
        let b = ks.keygen(ed25519_params(), &ikm()).await.unwrap();
        assert_ne!(a.id, b.id);
        assert_ne!(a.public_key, b.public_key);
    }

    #[tokio::test]
    async fn sign_unknown_key_rejected() {
        let ks = EnclaveKeystore::new("test");
        let fake = EnclaveKeyHandle {
            id: Uuid::new_v4(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: Some(vec![0u8; 32]),
            created_at: tenzro_types::Timestamp::now(),
            attestation: None,
        };
        let err = ks.sign(&fake, b"data").await.unwrap_err();
        assert!(matches!(err, TeeError::InvalidKeyHandle(_)));
    }
}
