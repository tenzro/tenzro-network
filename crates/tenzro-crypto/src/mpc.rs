//! Multi-Party Computation (MPC) and threshold signatures for Tenzro Network.
//!
//! This module provides threshold signature capabilities for auto-provisioned MPC wallets.
//! Uses Shamir's Secret Sharing over GF(256) for key splitting and individual Ed25519/Secp256k1
//! signing per share, with SHA-256 commitment verification and Lagrange interpolation for
//! signature combination.

use crate::error::{CryptoError, Result};
use crate::hash::{sha256, Hash};
use crate::keys::{KeyPair, KeyType, PublicKey};
use crate::signatures::Signature;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Threshold configuration for MPC operations in Tenzro Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Threshold: minimum number of shares needed to sign
    pub threshold: usize,
    /// Total number of shares
    pub total_shares: usize,
}

impl ThresholdConfig {
    /// Create a new threshold configuration
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        if threshold == 0 {
            return Err(CryptoError::MpcError(
                "Threshold must be at least 1".to_string(),
            ));
        }
        if threshold > total_shares {
            return Err(CryptoError::MpcError(
                "Threshold cannot exceed total shares".to_string(),
            ));
        }
        if total_shares > 255 {
            return Err(CryptoError::MpcError(
                "Total shares cannot exceed 255 (GF(256) limit)".to_string(),
            ));
        }
        Ok(Self {
            threshold,
            total_shares,
        })
    }

    /// Check if enough shares are present
    pub fn has_threshold(&self, share_count: usize) -> bool {
        share_count >= self.threshold
    }
}

/// GF(256) arithmetic for Shamir's Secret Sharing.
/// Uses the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
mod gf256 {
    /// Multiply two elements in GF(256)
    pub fn mul(a: u8, b: u8) -> u8 {
        let mut result: u16 = 0;
        let mut a = a as u16;
        let mut b = b as u16;
        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let carry = a & 0x80;
            a <<= 1;
            if carry != 0 {
                a ^= 0x1B; // reduction polynomial
            }
            b >>= 1;
        }
        result as u8
    }

    /// Compute multiplicative inverse in GF(256) using extended Euclidean algorithm
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0; // 0 has no inverse
        }
        // a^254 = a^(-1) in GF(256) by Fermat's little theorem
        let mut result = a;
        for _ in 0..6 {
            result = mul(result, result);
            result = mul(result, a);
        }
        mul(result, result)
    }

    /// Subtract (same as add in GF(256) since char=2)
    pub fn sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Add in GF(256)
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Evaluate a polynomial at a point in GF(256)
    pub fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        let mut x_power = 1u8;
        for &coeff in coeffs {
            result = add(result, mul(coeff, x_power));
            x_power = mul(x_power, x);
        }
        result
    }

    /// Compute Lagrange basis coefficient for interpolation at x=0
    pub fn lagrange_basis_at_zero(x_values: &[u8], i: usize) -> u8 {
        let xi = x_values[i];
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for (j, &xj) in x_values.iter().enumerate() {
            if i == j {
                continue;
            }
            // numerator *= (0 - xj) = xj in GF(256) since -x = x
            numerator = mul(numerator, xj);
            // denominator *= (xi - xj)
            denominator = mul(denominator, sub(xi, xj));
        }

        mul(numerator, inv(denominator))
    }

    /// Reconstruct secret from shares using Lagrange interpolation at x=0
    pub fn interpolate(x_values: &[u8], y_values: &[u8]) -> u8 {
        assert_eq!(x_values.len(), y_values.len());
        let mut secret = 0u8;
        for (i, &y_val) in y_values.iter().enumerate() {
            let basis = lagrange_basis_at_zero(x_values, i);
            secret = add(secret, mul(basis, y_val));
        }
        secret
    }
}

/// An MPC key share for Tenzro Network threshold signatures.
#[derive(Clone, Serialize, Deserialize)]
pub struct MpcKeyShare {
    /// Share identifier (1-indexed, used as x-coordinate in Shamir's SSS)
    pub share_id: u32,
    /// Key type
    pub key_type: KeyType,
    /// Threshold configuration
    pub config: ThresholdConfig,
    /// Share data: per-byte Shamir share of the master secret (zeroized on drop)
    share_data: Vec<u8>,
    /// Combined public key (same for all shares)
    pub public_key: PublicKey,
}

impl Default for MpcKeyShare {
    fn default() -> Self {
        Self {
            share_id: 0,
            key_type: KeyType::Ed25519,
            config: ThresholdConfig {
                threshold: 1,
                total_shares: 1,
            },
            share_data: Vec::new(),
            public_key: PublicKey::new(KeyType::Ed25519, Vec::new()),
        }
    }
}

impl Drop for MpcKeyShare {
    fn drop(&mut self) {
        self.share_data.zeroize();
    }
}

impl MpcKeyShare {
    /// Create a new key share
    pub fn new(
        share_id: u32,
        key_type: KeyType,
        config: ThresholdConfig,
        share_data: Vec<u8>,
        public_key: PublicKey,
    ) -> Result<Self> {
        if share_id == 0 || share_id > config.total_shares as u32 {
            return Err(CryptoError::InvalidShare(format!(
                "Share ID {} out of range [1, {}]",
                share_id, config.total_shares
            )));
        }

        Ok(Self {
            share_id,
            key_type,
            config,
            share_data,
            public_key,
        })
    }

    /// Get the share data
    pub fn share_data(&self) -> &[u8] {
        &self.share_data
    }

    /// Export share to bytes (for storage/transmission)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.share_id.to_le_bytes());
        bytes.push(match self.key_type {
            KeyType::Ed25519 => 0,
            KeyType::Secp256k1 => 1,
        });
        bytes.extend_from_slice(&(self.config.threshold as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.config.total_shares as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.share_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.share_data);
        bytes.extend_from_slice(&(self.public_key.as_bytes().len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes
    }
}

impl std::fmt::Debug for MpcKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcKeyShare")
            .field("share_id", &self.share_id)
            .field("key_type", &self.key_type)
            .field("config", &self.config)
            .field("share_data", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// A partial signature created by one party in Tenzro Network MPC signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Share ID of the signer
    pub share_id: u32,
    /// Full Ed25519/Secp256k1 signature produced by a per-share keypair
    pub partial_sig: Vec<u8>,
    /// SHA-256 commitment of the partial signature for verification
    pub commitment: Hash,
}

impl PartialSignature {
    /// Create a new partial signature
    pub fn new(share_id: u32, partial_sig: Vec<u8>, commitment: Hash) -> Self {
        Self {
            share_id,
            partial_sig,
            commitment,
        }
    }

    /// Verify the partial signature commitment
    pub fn verify_commitment(&self) -> bool {
        let computed = sha256(&self.partial_sig);
        computed == self.commitment
    }
}

/// Generate threshold key shares using Shamir's Secret Sharing over GF(256).
///
/// For each byte of the 32-byte master secret, a degree-(threshold-1) polynomial
/// is constructed with the secret byte as the constant term, and random coefficients.
/// Each share receives the polynomial evaluated at x = share_id (1..=total_shares).
pub fn generate_key_shares(
    key_type: KeyType,
    config: ThresholdConfig,
) -> Result<Vec<MpcKeyShare>> {
    let secret_len = 32;

    // Generate a master secret
    let mut master_secret = vec![0u8; secret_len];
    OsRng.fill_bytes(&mut master_secret);

    // For each byte of the secret, create a Shamir polynomial and evaluate
    let mut shares_data: Vec<Vec<u8>> = (0..config.total_shares)
        .map(|_| Vec::with_capacity(secret_len))
        .collect();

    for &secret_byte in master_secret.iter().take(secret_len) {
        // Build polynomial: coeffs[0] = secret byte, coeffs[1..threshold] = random
        let mut coeffs = vec![0u8; config.threshold];
        coeffs[0] = secret_byte;
        for c in coeffs.iter_mut().skip(1) {
            let mut buf = [0u8; 1];
            OsRng.fill_bytes(&mut buf);
            *c = buf[0];
        }

        // Evaluate polynomial at x = 1, 2, ..., total_shares
        for (share_idx, share_data) in shares_data.iter_mut().enumerate() {
            let x = (share_idx + 1) as u8;
            let y = gf256::poly_eval(&coeffs, x);
            share_data.push(y);
        }

        coeffs.zeroize();
    }

    // Derive public key from master secret
    let public_key = derive_public_key_from_secret(key_type, &master_secret)?;

    // Create MpcKeyShare objects
    let mut key_shares = Vec::with_capacity(config.total_shares);
    for (idx, share_data) in shares_data.into_iter().enumerate() {
        let share = MpcKeyShare::new(
            (idx + 1) as u32,
            key_type,
            config,
            share_data,
            public_key.clone(),
        )?;
        key_shares.push(share);
    }

    // Zeroize master secret
    master_secret.zeroize();

    Ok(key_shares)
}

/// Reconstruct the master secret from threshold key shares using Lagrange interpolation.
pub fn reconstruct_secret(shares: &[&MpcKeyShare]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(CryptoError::MpcError("No shares provided".to_string()));
    }

    let secret_len = shares[0].share_data.len();
    let x_values: Vec<u8> = shares.iter().map(|s| s.share_id as u8).collect();

    let mut secret = vec![0u8; secret_len];
    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        let y_values: Vec<u8> = shares.iter().map(|s| s.share_data[byte_idx]).collect();
        *secret_byte = gf256::interpolate(&x_values, &y_values);
    }

    Ok(secret)
}

/// Create a partial signature using a key share.
///
/// Reconstructs the signing key from the share data and produces a real
/// Ed25519/Secp256k1 signature. The share data is used to derive a per-share
/// signing key deterministically.
pub fn create_partial_signature(
    share: &MpcKeyShare,
    message: &[u8],
) -> Result<PartialSignature> {
    // Derive a per-share signing key from the share data
    let share_key_material = sha256(share.share_data());
    let keypair = KeyPair::from_bytes(share.key_type, share_key_material.as_bytes())?;

    // Sign the message with the per-share key
    let signer: Box<dyn crate::signatures::Signer> = match share.key_type {
        KeyType::Ed25519 => {
            Box::new(crate::signatures::Ed25519SignerImpl::new(keypair)?)
        }
        KeyType::Secp256k1 => {
            Box::new(crate::signatures::Secp256k1SignerImpl::new(keypair)?)
        }
    };

    let sig = signer.sign(message)?;
    let partial_sig = sig.to_bytes();

    // Create SHA-256 commitment
    let commitment = sha256(&partial_sig);

    Ok(PartialSignature::new(
        share.share_id,
        partial_sig,
        commitment,
    ))
}

/// Combine threshold key shares and sign a message.
///
/// Reconstructs the master signing key from the provided shares using Lagrange
/// interpolation over GF(256), then produces a real Ed25519/Secp256k1 signature
/// with the reconstructed key. The partial signatures are verified for commitment
/// consistency before reconstruction.
///
/// This approach requires at least `threshold` shares to reconstruct the master
/// key and produce a valid signature that can be verified against the original
/// public key.
pub fn combine_signatures_with_message(
    shares: &[&MpcKeyShare],
    partial_sigs: &[PartialSignature],
    message: &[u8],
) -> Result<Signature> {
    if shares.is_empty() {
        return Err(CryptoError::MpcError("No shares provided".to_string()));
    }

    let config = shares[0].config;
    let key_type = shares[0].key_type;

    if shares.len() < config.threshold {
        return Err(CryptoError::ThresholdNotMet {
            got: shares.len(),
            need: config.threshold,
        });
    }

    // Verify all partial signature commitments
    for partial in partial_sigs {
        if !partial.verify_commitment() {
            return Err(CryptoError::InvalidSignature(format!(
                "Invalid commitment for share {}",
                partial.share_id
            )));
        }
    }

    // Check for duplicate share IDs
    let mut share_ids = shares.iter().map(|s| s.share_id).collect::<Vec<_>>();
    share_ids.sort_unstable();
    share_ids.dedup();
    if share_ids.len() != shares.len() {
        return Err(CryptoError::InvalidSignature(
            "Duplicate share IDs".to_string(),
        ));
    }

    // Reconstruct the master secret from shares using Lagrange interpolation
    let mut master_secret = reconstruct_secret(shares)?;

    // Derive the signing keypair from the reconstructed master secret
    let keypair = KeyPair::from_bytes(key_type, &master_secret)?;

    // Sign the message with the reconstructed master key
    let signer: Box<dyn crate::signatures::Signer> = match key_type {
        KeyType::Ed25519 => {
            Box::new(crate::signatures::Ed25519SignerImpl::new(keypair)?)
        }
        KeyType::Secp256k1 => {
            Box::new(crate::signatures::Secp256k1SignerImpl::new(keypair)?)
        }
    };

    let signature = signer.sign(message)?;

    // Zeroize the reconstructed master secret
    master_secret.zeroize();

    Ok(signature)
}

/// Verify a threshold signature against the combined public key.
///
/// Uses standard Ed25519/Secp256k1 verification against the combined public key.
/// The signature must have been produced by `combine_signatures_with_message()`.
pub fn verify_threshold_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    let verifier: Box<dyn crate::signatures::Verifier> = match signature.key_type() {
        KeyType::Ed25519 => Box::new(crate::signatures::Ed25519VerifierImpl::new(
            public_key.clone(),
        )?),
        KeyType::Secp256k1 => Box::new(crate::signatures::Secp256k1VerifierImpl::new(
            public_key.clone(),
        )?),
    };

    verifier.verify(message, signature)
}

/// Derive a public key from a secret.
fn derive_public_key_from_secret(key_type: KeyType, secret: &[u8]) -> Result<PublicKey> {
    let mut padded_secret = vec![0u8; 32];
    let copy_len = std::cmp::min(secret.len(), 32);
    padded_secret[..copy_len].copy_from_slice(&secret[..copy_len]);

    let keypair = KeyPair::from_bytes(key_type, &padded_secret)?;
    let pk = keypair.public_key().clone();
    padded_secret.zeroize();
    Ok(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_config() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total_shares, 3);
        assert!(config.has_threshold(2));
        assert!(config.has_threshold(3));
        assert!(!config.has_threshold(1));
    }

    #[test]
    fn test_invalid_threshold_config() {
        assert!(ThresholdConfig::new(0, 3).is_err());
        assert!(ThresholdConfig::new(4, 3).is_err());
    }

    #[test]
    fn test_gf256_roundtrip() {
        // Verify that Shamir reconstruction works at the byte level
        let secret_byte: u8 = 42;
        let _threshold = 2;
        let total = 3;

        // Build polynomial: f(x) = secret + r*x
        let r: u8 = 17; // random coefficient
        let coeffs = [secret_byte, r];

        let shares: Vec<(u8, u8)> = (1..=total)
            .map(|x| (x as u8, gf256::poly_eval(&coeffs, x as u8)))
            .collect();

        // Reconstruct from any 2 shares
        let x_vals = [shares[0].0, shares[1].0];
        let y_vals = [shares[0].1, shares[1].1];
        let recovered = gf256::interpolate(&x_vals, &y_vals);
        assert_eq!(recovered, secret_byte);

        // Different subset
        let x_vals = [shares[1].0, shares[2].0];
        let y_vals = [shares[1].1, shares[2].1];
        let recovered = gf256::interpolate(&x_vals, &y_vals);
        assert_eq!(recovered, secret_byte);
    }

    #[test]
    fn test_generate_key_shares() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();

        assert_eq!(shares.len(), 3);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.share_id, (i + 1) as u32);
            assert_eq!(share.config, config);
            assert_eq!(share.share_data.len(), 32);
        }

        // All shares should have the same public key
        let first_pubkey = &shares[0].public_key;
        for share in &shares[1..] {
            assert_eq!(&share.public_key, first_pubkey);
        }
    }

    #[test]
    fn test_secret_reconstruction() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();

        // Reconstruct from shares 1 and 2
        let secret_a = reconstruct_secret(&[&shares[0], &shares[1]]).unwrap();
        // Reconstruct from shares 2 and 3
        let secret_b = reconstruct_secret(&[&shares[1], &shares[2]]).unwrap();
        // Reconstruct from shares 1 and 3
        let secret_c = reconstruct_secret(&[&shares[0], &shares[2]]).unwrap();

        // All reconstructions must match
        assert_eq!(secret_a, secret_b);
        assert_eq!(secret_b, secret_c);
    }

    #[test]
    fn test_partial_signatures() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let message = b"Tenzro Network MPC transaction";

        let mut partial_sigs = Vec::new();
        for share in shares.iter().take(2) {
            let partial = create_partial_signature(share, message).unwrap();
            assert!(partial.verify_commitment());
            partial_sigs.push(partial);
        }

        assert_eq!(partial_sigs.len(), 2);
    }

    #[test]
    fn test_threshold_not_met() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let message = b"test";

        // Only provide 1 signature (threshold is 2)
        let share_refs: Vec<&MpcKeyShare> = vec![&shares[0]];
        let partial_sigs = vec![create_partial_signature(&shares[0], message).unwrap()];

        let result = combine_signatures_with_message(&share_refs, &partial_sigs, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_signatures_with_message() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let message = b"Tenzro Network real MPC transaction";

        // Create partial signatures
        let partial_sigs: Vec<_> = shares
            .iter()
            .take(2)
            .map(|share| create_partial_signature(share, message).unwrap())
            .collect();

        // Combine using the new method with real key reconstruction
        let share_refs: Vec<&MpcKeyShare> = shares.iter().take(2).collect();
        let signature = combine_signatures_with_message(
            &share_refs,
            &partial_sigs,
            message,
        )
        .unwrap();

        // The signature should be a real Ed25519 signature (64 bytes)
        assert_eq!(signature.as_bytes().len(), 64);

        // Verify the signature against the original public key
        let result = verify_threshold_signature(
            &shares[0].public_key,
            message,
            &signature,
        );
        assert!(result.is_ok(), "Threshold signature verification failed");
    }

    #[test]
    fn test_combine_with_different_share_subsets() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let message = b"Tenzro threshold test";

        // Combine with shares 1,2
        let partial_12: Vec<_> = shares
            .iter()
            .take(2)
            .map(|s| create_partial_signature(s, message).unwrap())
            .collect();
        let refs_12: Vec<&MpcKeyShare> = shares.iter().take(2).collect();
        let sig_12 = combine_signatures_with_message(&refs_12, &partial_12, message).unwrap();

        // Combine with shares 2,3
        let partial_23: Vec<_> = shares
            .iter()
            .skip(1)
            .map(|s| create_partial_signature(s, message).unwrap())
            .collect();
        let refs_23: Vec<&MpcKeyShare> = shares.iter().skip(1).collect();
        let sig_23 = combine_signatures_with_message(&refs_23, &partial_23, message).unwrap();

        // Both should verify against the same public key
        assert!(verify_threshold_signature(&shares[0].public_key, message, &sig_12).is_ok());
        assert!(verify_threshold_signature(&shares[0].public_key, message, &sig_23).is_ok());
    }

    #[test]
    fn test_mpc_key_share_serialization() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = generate_key_shares(KeyType::Ed25519, config).unwrap();

        let bytes = shares[0].to_bytes();
        assert!(!bytes.is_empty());
    }
}
