//! Verifiable Random Function (VRF) for Tenzro Network.
//!
//! Implements the ECVRF-EDWARDS25519-SHA512-TAI ciphersuite defined in
//! [RFC 9381](https://datatracker.ietf.org/doc/rfc9381/) §5.4.1.1 (suite
//! string `0x04`). This reuses the Ed25519 keypairs that are already the
//! native signing identity for Tenzro validators and agents.
//!
//! # Overview
//!
//! A VRF is a cryptographic primitive that lets the holder of a secret key
//! compute a pseudorandom output from an input message together with a proof
//! that the output was computed correctly. Anyone with the corresponding
//! public key can verify the proof; without the secret key, the output
//! cannot be predicted. This is the same primitive used by Chainlink VRF
//! v2.5 to provide provably-fair on-chain randomness for NFT reveals,
//! lotteries, and randomized trait assignment.
//!
//! # Ciphersuite
//!
//! - **Curve**: Edwards25519 (same as Ed25519 signatures).
//! - **Hash**: SHA-512.
//! - **Encode-to-curve**: try-and-increment (TAI, §5.4.1.1).
//! - **Suite string**: `0x04`.
//!
//! # Proof layout (80 bytes)
//!
//! Per RFC 9381 §5.5, an ECVRF proof is serialized as:
//!
//! ```text
//!   Gamma   (32 bytes, compressed Edwards point)
//!   c       (16 bytes, truncated SHA-512 challenge scalar)
//!   s       (32 bytes, little-endian scalar mod L)
//! ```
//!
//! # Output (64 bytes)
//!
//! `proof_to_hash(pi) = SHA-512(suite_string || 0x03 || encode(cofactor * Gamma) || 0x00)`.
//!
//! # Security
//!
//! This implementation satisfies the "full uniqueness", "trusted collision
//! resistance", and "full pseudorandomness" properties of RFC 9381 §3 when
//! used with the Edwards25519 group and correctly validated public keys.
//!
//! **Do not** use TAI encoding with secret inputs — the loop in
//! `encode_to_curve_try_and_increment` is data-dependent and can leak
//! information through timing. For public inputs (block hashes, request
//! IDs, NFT mint nonces) this is fine.

use crate::error::{CryptoError, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// ECVRF suite string for ECVRF-EDWARDS25519-SHA512-TAI per RFC 9381 §5.5.
const SUITE_STRING: u8 = 0x04;

/// Cofactor of the Edwards25519 curve (RFC 9381 §5.5).
const COFACTOR: u8 = 8;

/// Length of a VRF proof (Gamma || c || s) in bytes.
pub const PROOF_LEN: usize = 32 + 16 + 32;

/// Length of the VRF output hash (proof_to_hash result).
pub const OUTPUT_LEN: usize = 64;

/// Length of a challenge scalar after truncation per §5.4.3.
const CHALLENGE_LEN: usize = 16;

/// A VRF secret key, reusing the Ed25519 32-byte seed format.
///
/// This is byte-compatible with an Ed25519 signing key, so a validator's
/// existing Ed25519 identity key can also serve as its VRF key.
#[derive(Clone)]
pub struct VrfSecretKey(pub [u8; 32]);

/// A VRF public key (compressed Edwards point, 32 bytes).
///
/// Byte-compatible with an Ed25519 verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfPublicKey(pub [u8; 32]);

/// A VRF proof (80 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub [u8; PROOF_LEN]);

/// A VRF output hash (64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; OUTPUT_LEN]);

impl VrfSecretKey {
    /// Derives the public key from this secret key.
    pub fn public_key(&self) -> VrfPublicKey {
        let (x, _) = expand_secret(&self.0);
        let y = ED25519_BASEPOINT_POINT * x;
        VrfPublicKey(y.compress().to_bytes())
    }
}

impl VrfProof {
    /// Serializes the proof as an 80-byte array.
    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }

    /// Constructs a proof from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PROOF_LEN {
            return Err(CryptoError::InvalidSignature(format!(
                "VRF proof must be {} bytes, got {}",
                PROOF_LEN,
                bytes.len()
            )));
        }
        let mut buf = [0u8; PROOF_LEN];
        buf.copy_from_slice(bytes);
        Ok(VrfProof(buf))
    }
}

impl VrfOutput {
    /// Serializes the output as a 64-byte array.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_LEN] {
        &self.0
    }

    /// Truncates the output to a `u64` for use as a bounded random index.
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("64-byte output"))
    }

    /// Returns the output in the range `[0, modulus)` via rejection-free
    /// modular reduction of the first 128 bits.
    ///
    /// This is biased by at most `2^-64` for any `modulus <= 2^64`, which is
    /// acceptable for NFT trait assignment and raffle selection.
    pub fn bounded(&self, modulus: u128) -> u128 {
        assert!(modulus > 0, "modulus must be positive");
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[..16]);
        u128::from_be_bytes(buf) % modulus
    }
}

/// Expands an Ed25519 32-byte seed into the scalar `x` and the nonce-derivation
/// prefix, following RFC 8032 §5.1.5.
fn expand_secret(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&h[..32]);
    // Clamp per RFC 8032 §5.1.5.
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(scalar_bytes);

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (x, prefix)
}

/// RFC 9381 §5.4.1.1: `ECVRF_encode_to_curve_try_and_increment(Y, alpha)`.
///
/// Hashes `(Y || alpha)` with a counter appended until the result decodes
/// to a valid curve point, then multiplies by the cofactor to land in the
/// prime-order subgroup.
fn encode_to_curve(pk: &[u8; 32], alpha: &[u8]) -> Result<EdwardsPoint> {
    for ctr in 0u8..=255 {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING, 0x01]);
        hasher.update(pk);
        hasher.update(alpha);
        hasher.update([ctr, 0x00]);
        let h = hasher.finalize();

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&h[..32]);
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            return Ok(point.mul_by_cofactor());
        }
    }
    Err(CryptoError::Other(
        "ECVRF encode_to_curve: no valid point after 256 attempts".to_string(),
    ))
}

/// RFC 9381 §5.4.3: `ECVRF_challenge_generation(P1,...,P5)`.
fn challenge_generation(points: [&EdwardsPoint; 5]) -> [u8; CHALLENGE_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x02]);
    for p in points.iter() {
        hasher.update(p.compress().to_bytes());
    }
    hasher.update([0x00]);
    let h = hasher.finalize();
    let mut c = [0u8; CHALLENGE_LEN];
    c.copy_from_slice(&h[..CHALLENGE_LEN]);
    c
}

/// Converts a 16-byte truncated challenge into a full 32-byte little-endian
/// scalar. Per RFC 9381, the challenge is zero-padded on the most-significant
/// side before reduction mod L.
fn challenge_to_scalar(c: &[u8; CHALLENGE_LEN]) -> Scalar {
    let mut s = [0u8; 32];
    s[..CHALLENGE_LEN].copy_from_slice(c);
    Scalar::from_bytes_mod_order(s)
}

/// RFC 9381 §5.4.2.2 nonce generation for Edwards25519: derives `k` from
/// SHA-512(prefix || H_string), reduced mod L.
fn nonce_generation(prefix: &[u8; 32], h_bytes: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(h_bytes);
    let h = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// RFC 9381 §5.1: `ECVRF_prove(SK, alpha_string)`.
///
/// Produces a VRF proof `pi = (Gamma || c || s)` for the message `alpha`.
pub fn prove(sk: &VrfSecretKey, alpha: &[u8]) -> Result<VrfProof> {
    let (x, prefix) = expand_secret(&sk.0);
    let y_point = ED25519_BASEPOINT_POINT * x;
    let pk_bytes = y_point.compress().to_bytes();

    let h = encode_to_curve(&pk_bytes, alpha)?;
    let h_bytes = h.compress().to_bytes();

    let gamma = h * x;
    let k = nonce_generation(&prefix, &h_bytes);
    let k_b = ED25519_BASEPOINT_POINT * k;
    let k_h = h * k;

    let c_trunc = challenge_generation([&y_point, &h, &gamma, &k_b, &k_h]);
    let c = challenge_to_scalar(&c_trunc);
    let s = k + c * x;

    let mut proof = [0u8; PROOF_LEN];
    proof[..32].copy_from_slice(&gamma.compress().to_bytes());
    proof[32..48].copy_from_slice(&c_trunc);
    proof[48..].copy_from_slice(&s.to_bytes());
    Ok(VrfProof(proof))
}

/// Decodes a serialized proof into `(Gamma, c, s)`.
fn decode_proof(pi: &VrfProof) -> Result<(EdwardsPoint, [u8; CHALLENGE_LEN], Scalar)> {
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi.0[..32]);
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidSignature("VRF Gamma is not on curve".to_string()))?;

    let mut c = [0u8; CHALLENGE_LEN];
    c.copy_from_slice(&pi.0[32..48]);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pi.0[48..]);
    // s must be canonical (< L). `from_canonical_bytes` rejects non-canonical encodings.
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or_else(|| CryptoError::InvalidSignature("VRF scalar s is non-canonical".to_string()))?;

    Ok((gamma, c, s))
}

/// RFC 9381 §5.3: `ECVRF_verify(PK, pi_string, alpha_string)`.
///
/// Returns `Ok(output_hash)` on success, `Err(VerificationFailed)` otherwise.
pub fn verify(pk: &VrfPublicKey, alpha: &[u8], pi: &VrfProof) -> Result<VrfOutput> {
    let y_point = CompressedEdwardsY(pk.0)
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey("VRF public key not on curve".to_string()))?;

    // Rejecting low-order public keys gives "full uniqueness" under
    // malicious key generation (RFC 9381 §3).
    if y_point.is_small_order() {
        return Err(CryptoError::InvalidPublicKey(
            "VRF public key is low-order".to_string(),
        ));
    }

    let (gamma, c_trunc, s) = decode_proof(pi)?;
    let c = challenge_to_scalar(&c_trunc);

    let h = encode_to_curve(&pk.0, alpha)?;

    // U = s*B - c*Y
    let u = ED25519_BASEPOINT_POINT * s - y_point * c;
    // V = s*H - c*Gamma
    let v = h * s - gamma * c;

    let c_prime = challenge_generation([&y_point, &h, &gamma, &u, &v]);
    if c_prime != c_trunc {
        return Err(CryptoError::VerificationFailed);
    }

    Ok(proof_to_hash(&gamma))
}

/// RFC 9381 §5.2: `ECVRF_proof_to_hash(pi_string)`.
///
/// Computed as `SHA-512(suite_string || 0x03 || encode(cofactor * Gamma) || 0x00)`.
fn proof_to_hash(gamma: &EdwardsPoint) -> VrfOutput {
    let cofactor_gamma = gamma * Scalar::from(COFACTOR as u64);
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x03]);
    hasher.update(cofactor_gamma.compress().to_bytes());
    hasher.update([0x00]);
    let h = hasher.finalize();
    let mut out = [0u8; OUTPUT_LEN];
    out.copy_from_slice(&h);
    VrfOutput(out)
}

/// Extracts the VRF output from a proof without performing full verification.
///
/// **This does not authenticate the proof.** Only use after `verify()` has
/// succeeded, or when the proof source is trusted.
pub fn proof_output(pi: &VrfProof) -> Result<VrfOutput> {
    let (gamma, _, _) = decode_proof(pi)?;
    Ok(proof_to_hash(&gamma))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::random_array;

    fn gen_keypair() -> (VrfSecretKey, VrfPublicKey) {
        let sk = VrfSecretKey(random_array::<32>());
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let (sk, pk) = gen_keypair();
        let alpha = b"tenzro mint request 42";
        let pi = prove(&sk, alpha).unwrap();
        let out = verify(&pk, alpha, &pi).unwrap();
        let out2 = proof_output(&pi).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn test_proof_is_deterministic() {
        let (sk, _) = gen_keypair();
        let alpha = b"deterministic input";
        let pi1 = prove(&sk, alpha).unwrap();
        let pi2 = prove(&sk, alpha).unwrap();
        assert_eq!(pi1, pi2, "VRF must be deterministic for a given (sk, alpha)");
    }

    #[test]
    fn test_different_messages_different_outputs() {
        let (sk, pk) = gen_keypair();
        let pi_a = prove(&sk, b"alpha").unwrap();
        let pi_b = prove(&sk, b"beta").unwrap();
        let out_a = verify(&pk, b"alpha", &pi_a).unwrap();
        let out_b = verify(&pk, b"beta", &pi_b).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn test_verify_rejects_wrong_alpha() {
        let (sk, pk) = gen_keypair();
        let pi = prove(&sk, b"alpha").unwrap();
        let err = verify(&pk, b"beta", &pi).unwrap_err();
        matches!(err, CryptoError::VerificationFailed);
    }

    #[test]
    fn test_verify_rejects_wrong_pubkey() {
        let (sk, _pk) = gen_keypair();
        let (_, wrong_pk) = gen_keypair();
        let pi = prove(&sk, b"alpha").unwrap();
        let err = verify(&wrong_pk, b"alpha", &pi).unwrap_err();
        matches!(err, CryptoError::VerificationFailed);
    }

    #[test]
    fn test_verify_rejects_tampered_proof() {
        let (sk, pk) = gen_keypair();
        let mut pi = prove(&sk, b"alpha").unwrap();
        pi.0[0] ^= 0x01;
        let err = verify(&pk, b"alpha", &pi).unwrap_err();
        matches!(err, CryptoError::VerificationFailed | CryptoError::InvalidSignature(_));
    }

    #[test]
    fn test_proof_serialization() {
        let (sk, _) = gen_keypair();
        let pi = prove(&sk, b"serialize me").unwrap();
        let bytes = pi.as_bytes();
        assert_eq!(bytes.len(), PROOF_LEN);
        let pi2 = VrfProof::from_bytes(bytes).unwrap();
        assert_eq!(pi, pi2);
    }

    #[test]
    fn test_output_bounded() {
        let (sk, pk) = gen_keypair();
        let pi = prove(&sk, b"bound me").unwrap();
        let out = verify(&pk, b"bound me", &pi).unwrap();
        for modulus in [10u128, 100, 1000, 1_000_000, u64::MAX as u128] {
            let v = out.bounded(modulus);
            assert!(v < modulus);
        }
    }

    #[test]
    fn test_output_u64_nonzero_with_overwhelming_prob() {
        let (sk, pk) = gen_keypair();
        let pi = prove(&sk, b"u64 output").unwrap();
        let out = verify(&pk, b"u64 output", &pi).unwrap();
        assert_ne!(out.as_u64(), 0);
    }

    #[test]
    fn test_reject_malformed_proof_length() {
        let err = VrfProof::from_bytes(&[0u8; 10]).unwrap_err();
        matches!(err, CryptoError::InvalidSignature(_));
    }
}
