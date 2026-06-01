//! Secp256r1 / NIST P-256 primitives for Tenzro Network.
//!
//! P-256 is the curve every modern platform authenticator uses for passkeys —
//! Apple Secure Enclave, Android StrongBox, Microsoft Pluton / Windows Hello,
//! TPM 2.0, YubiKey FIDO2. This module provides the keypair, signer, and
//! verifier surface the rest of the workspace consumes for WebAuthn-bound
//! self-custody flows. The on-chain counterpart is the `0x100` precompile
//! (EIP-7951 / RIP-7212), which verifies signatures produced here.
//!
//! # Wire format
//!
//! - **Public key:** uncompressed SEC1, 65 bytes, prefix `0x04` followed by
//!   32-byte big-endian `x` and 32-byte big-endian `y`. The 64-byte raw
//!   `x ‖ y` form is what the precompile consumes; both are accepted on the
//!   parsing path.
//! - **Signature:** raw `r ‖ s`, 64 bytes, big-endian. DER and ASN.1
//!   signatures (as produced by some WebAuthn authenticators) are unwrapped
//!   in the [`webauthn`](crate::webauthn) module.
//!
//! # Examples
//!
//! ```
//! use tenzro_crypto::p256::{P256KeyPair, P256Signer, P256Verifier};
//! # fn main() -> tenzro_crypto::Result<()> {
//! let kp = P256KeyPair::generate();
//! let signer = P256Signer::from_keypair(&kp);
//! let verifier = P256Verifier::from_public_key_bytes(&kp.public_key_bytes())?;
//!
//! let hash = [0u8; 32];
//! let sig = signer.sign_prehash(&hash);
//! verifier.verify_prehash(&hash, &sig)?;
//! # Ok(())
//! # }
//! ```

use crate::error::{CryptoError, Result};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
// See `keys.rs` for the rand_core 0.9 vs rand 0.8 split rationale —
// `RandCoreOsRng` is the `TryCryptoRng` from rand_core 0.9 that, once lifted
// via `.unwrap_err()`, satisfies the `CryptoRng` bound on
// `ecdsa::signing::SigningKey::random` in the RustCrypto 0.14-RC line.
use getrandom_0_4::{rand_core::UnwrapErr, SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

/// Length in bytes of a raw P-256 signature (`r ‖ s`).
pub const P256_SIGNATURE_LEN: usize = 64;

/// Length in bytes of a P-256 public key in raw `x ‖ y` form (no SEC1 prefix).
pub const P256_PUBLIC_KEY_LEN: usize = 64;

/// Length in bytes of a P-256 public key in SEC1 uncompressed form (`0x04 ‖ x ‖ y`).
pub const P256_PUBLIC_KEY_SEC1_LEN: usize = 65;

/// A P-256 keypair held in process memory.
///
/// The secret scalar is wrapped in a type that zeroizes on drop. For
/// hardware-backed keys (Secure Enclave, StrongBox, TPM) the secret never
/// leaves the device — see the `tenzro-wallet` device-storage layer; this
/// in-memory keypair is only used for tests, ephemeral session keys, and
/// software-only flows where no platform authenticator is available.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P256KeyPair {
    signing_key: SigningKey,
}

impl P256KeyPair {
    /// Generate a fresh P-256 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        // p256 0.14-rc's `SigningKey::random` is deprecated; use the `Generate`
        // trait (re-exported via `elliptic_curve::Generate`). `SysRng` is the
        // rand_core 0.10 entropy source.
        use ::p256::elliptic_curve::Generate;
        Self {
            signing_key: SigningKey::generate_from_rng(&mut UnwrapErr(SysRng)),
        }
    }

    /// Reconstruct a keypair from a 32-byte big-endian secret scalar.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(CryptoError::InvalidSecretKey(format!(
                "P-256 secret must be 32 bytes, got {}",
                secret.len()
            )));
        }
        let signing_key = SigningKey::from_slice(secret)
            .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// 32-byte big-endian secret scalar.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// 64-byte raw public key (`x ‖ y`).
    pub fn public_key_bytes(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        let encoded = self.signing_key.verifying_key().to_sec1_point(false);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(bytes.len(), P256_PUBLIC_KEY_SEC1_LEN);
        debug_assert_eq!(bytes[0], 0x04);
        let mut out = [0u8; P256_PUBLIC_KEY_LEN];
        out.copy_from_slice(&bytes[1..]);
        out
    }

    /// 65-byte SEC1 uncompressed public key (`0x04 ‖ x ‖ y`).
    pub fn public_key_sec1(&self) -> [u8; P256_PUBLIC_KEY_SEC1_LEN] {
        let encoded = self.signing_key.verifying_key().to_sec1_point(false);
        let mut out = [0u8; P256_PUBLIC_KEY_SEC1_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }
}

/// In-memory P-256 signer for software flows (tests, ephemeral session keys).
///
/// Production human flows use a hardware-backed signer (Secure Enclave /
/// StrongBox / TPM) reached via the `tenzro-wallet` device layer; production
/// autonomous-machine flows use a TEE-resident signer. This type exists so
/// the trait surface is testable without a hardware authenticator attached.
#[derive(Clone)]
pub struct P256Signer {
    keypair: P256KeyPair,
}

impl P256Signer {
    /// Build a signer from an in-memory keypair.
    pub fn from_keypair(keypair: &P256KeyPair) -> Self {
        Self {
            keypair: keypair.clone(),
        }
    }

    /// 64-byte raw public key (`x ‖ y`).
    pub fn public_key_bytes(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        self.keypair.public_key_bytes()
    }

    /// 65-byte SEC1 uncompressed public key (`0x04 ‖ x ‖ y`).
    pub fn public_key_sec1(&self) -> [u8; P256_PUBLIC_KEY_SEC1_LEN] {
        self.keypair.public_key_sec1()
    }

    /// Sign a 32-byte prehash. Output is a raw 64-byte `r ‖ s` signature
    /// that the `0x100` precompile accepts directly.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> P256Signature {
        let sig: Signature = self
            .keypair
            .signing_key
            .sign_prehash(hash)
            .expect("P-256 signing of a 32-byte prehash never fails");
        P256Signature::from_signature(&sig)
    }

    /// Sign an arbitrary message by SHA-256-hashing it first.
    pub fn sign_sha256(&self, message: &[u8]) -> P256Signature {
        let hash: [u8; 32] = Sha256::digest(message).into();
        self.sign_prehash(&hash)
    }
}

/// A 64-byte raw P-256 signature (`r ‖ s`, big-endian, low-S not enforced).
///
/// EIP-7951 / RIP-7212 do not require low-S normalization, but we expose
/// [`Self::normalize_s`] for callers that want to match the precompile
/// behavior exactly when comparing against an EVM-side signature.
///
/// Stored as `Vec<u8>` for serde compatibility (const-generic byte arrays
/// don't implement `Deserialize` for sizes >32 in serde 1.x); the
/// constructors enforce the 64-byte invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P256Signature {
    bytes: Vec<u8>,
}

impl P256Signature {
    /// Build from a raw 64-byte `r ‖ s` payload.
    pub fn from_bytes(bytes: [u8; P256_SIGNATURE_LEN]) -> Self {
        Self { bytes: bytes.to_vec() }
    }

    /// Build from a slice of length 64.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P256_SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignature(format!(
                "P-256 raw signature must be 64 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Build from a `p256::ecdsa::Signature`.
    pub fn from_signature(sig: &Signature) -> Self {
        let bytes = sig.to_bytes();
        Self { bytes: bytes.to_vec() }
    }

    /// Raw 64-byte `r ‖ s` view.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Big-endian `r` component.
    pub fn r(&self) -> &[u8] {
        &self.bytes[..32]
    }

    /// Big-endian `s` component.
    pub fn s(&self) -> &[u8] {
        &self.bytes[32..]
    }

    /// Return a copy with `s` normalized to its low half (so `s ≤ n/2`),
    /// matching the canonical low-S form many verifiers accept.
    pub fn normalize_s(&self) -> Result<Self> {
        let sig = Signature::from_slice(&self.bytes)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        // k256/p256 0.14: `normalize_s()` returns `Signature` directly (no
        // `Option`). It's a no-op when `s` is already in the low half.
        let normalized = sig.normalize_s();
        Ok(Self::from_signature(&normalized))
    }
}

/// In-process P-256 verifier.
///
/// Mirrors the on-chain `0x100` precompile's verification path so a signer
/// produced here verifies under both the Rust verifier and the EVM
/// precompile without further normalization.
#[derive(Clone)]
pub struct P256Verifier {
    verifying_key: VerifyingKey,
}

impl P256Verifier {
    /// Build a verifier from a 64-byte raw `x ‖ y` public key.
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != P256_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidPublicKey(format!(
                "P-256 raw public key must be 64 bytes, got {}",
                public_key.len()
            )));
        }
        let mut sec1 = [0u8; P256_PUBLIC_KEY_SEC1_LEN];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Build a verifier from a 65-byte SEC1 uncompressed public key.
    pub fn from_sec1_bytes(public_key: &[u8]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// 64-byte raw public key (`x ‖ y`).
    pub fn public_key_bytes(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        let encoded = self.verifying_key.to_sec1_point(false);
        let bytes = encoded.as_bytes();
        let mut out = [0u8; P256_PUBLIC_KEY_LEN];
        out.copy_from_slice(&bytes[1..]);
        out
    }

    /// Verify a raw P-256 signature against a 32-byte prehash.
    pub fn verify_prehash(&self, hash: &[u8; 32], signature: &P256Signature) -> Result<()> {
        let sig = Signature::from_slice(signature.as_bytes())
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        self.verifying_key
            .verify_prehash(hash, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// Verify a raw P-256 signature against an arbitrary message
    /// (SHA-256-hashed first).
    pub fn verify_sha256(&self, message: &[u8], signature: &P256Signature) -> Result<()> {
        let hash: [u8; 32] = Sha256::digest(message).into();
        self.verify_prehash(&hash, signature)
    }
}

/// Build the exact 160-byte calldata that the `0x100` precompile consumes.
///
/// Layout: `hash(32) ‖ r(32) ‖ s(32) ‖ x(32) ‖ y(32)`.
///
/// This is the canonical helper for any caller (validator module, RPC
/// handler, off-chain signer) that needs to produce precompile input from
/// a hash + signature + public-key triple.
pub fn build_p256verify_input(
    hash: &[u8; 32],
    signature: &P256Signature,
    public_key: &[u8; P256_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(hash);
    out.extend_from_slice(signature.as_bytes());
    out.extend_from_slice(public_key);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sign_and_verify() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let verifier = P256Verifier::from_public_key_bytes(&kp.public_key_bytes()).unwrap();

        let hash = [42u8; 32];
        let sig = signer.sign_prehash(&hash);
        verifier.verify_prehash(&hash, &sig).unwrap();
    }

    #[test]
    fn round_trip_sign_sha256_and_verify() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let verifier = P256Verifier::from_public_key_bytes(&kp.public_key_bytes()).unwrap();

        let msg = b"tenzro p256 webauthn round trip";
        let sig = signer.sign_sha256(msg);
        verifier.verify_sha256(msg, &sig).unwrap();
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let kp_a = P256KeyPair::generate();
        let kp_b = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp_a);
        let verifier = P256Verifier::from_public_key_bytes(&kp_b.public_key_bytes()).unwrap();

        let hash = [7u8; 32];
        let sig = signer.sign_prehash(&hash);
        assert!(matches!(
            verifier.verify_prehash(&hash, &sig),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn rejects_tampered_message() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let verifier = P256Verifier::from_public_key_bytes(&kp.public_key_bytes()).unwrap();

        let hash = [0xAAu8; 32];
        let sig = signer.sign_prehash(&hash);
        let tampered = [0xBBu8; 32];
        assert!(verifier.verify_prehash(&tampered, &sig).is_err());
    }

    #[test]
    fn public_key_round_trips_raw_and_sec1() {
        let kp = P256KeyPair::generate();
        let raw = kp.public_key_bytes();
        let sec1 = kp.public_key_sec1();

        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..], &raw[..]);

        let v_raw = P256Verifier::from_public_key_bytes(&raw).unwrap();
        let v_sec1 = P256Verifier::from_sec1_bytes(&sec1).unwrap();
        assert_eq!(v_raw.public_key_bytes(), v_sec1.public_key_bytes());
    }

    #[test]
    fn keypair_round_trips_via_secret_bytes() {
        let kp = P256KeyPair::generate();
        let secret = kp.secret_bytes();
        let restored = P256KeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn signature_from_slice_validates_length() {
        assert!(P256Signature::from_slice(&[0u8; 64]).is_ok());
        assert!(P256Signature::from_slice(&[0u8; 63]).is_err());
        assert!(P256Signature::from_slice(&[0u8; 65]).is_err());
    }

    #[test]
    fn build_p256verify_input_layout() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let hash = [1u8; 32];
        let sig = signer.sign_prehash(&hash);
        let input = build_p256verify_input(&hash, &sig, &kp.public_key_bytes());

        assert_eq!(input.len(), 160);
        assert_eq!(&input[..32], &hash[..]);
        assert_eq!(&input[32..96], sig.as_bytes());
        assert_eq!(&input[96..160], &kp.public_key_bytes()[..]);
    }

    #[test]
    fn signature_normalize_s_is_idempotent() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let sig = signer.sign_prehash(&[9u8; 32]);
        let normalized = sig.normalize_s().unwrap();
        let normalized_again = normalized.normalize_s().unwrap();
        assert_eq!(normalized.as_bytes(), normalized_again.as_bytes());
    }

    #[test]
    fn rejects_wrong_length_public_key() {
        assert!(P256Verifier::from_public_key_bytes(&[0u8; 63]).is_err());
        assert!(P256Verifier::from_public_key_bytes(&[0u8; 65]).is_err());
    }

    #[test]
    fn rejects_wrong_length_secret() {
        assert!(P256KeyPair::from_secret_bytes(&[0u8; 31]).is_err());
        assert!(P256KeyPair::from_secret_bytes(&[0u8; 33]).is_err());
    }
}
