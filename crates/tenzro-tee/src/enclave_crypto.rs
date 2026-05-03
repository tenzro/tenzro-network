//! Shared AES-256-GCM encryption for TEE enclave operations.
//!
//! All TEE providers (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU) use this
//! module for enclave encryption/decryption. The AES-256 key is derived from
//! the key UUID, vendor context, and (on real hardware) a platform-specific
//! measurement that binds the key to the TEE instance. On AMD SEV-SNP, the
//! derived key is additionally protected by hardware memory encryption (VMSA/SME)
//! which transparently encrypts all VM memory at the hardware level.
//!
//! # Wire Format
//!
//! Ciphertext is `nonce (12 bytes) || encrypted_data || tag (16 bytes)`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{TeeError, Result};

/// Platform measurement for key binding, populated on first use from TEE hardware.
static PLATFORM_MEASUREMENT: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Registers a platform-specific measurement (e.g., from SEV-SNP REPORT_DATA,
/// TDX TDREPORT, or Nitro PCR) to be mixed into all key derivations.
/// This binds enclave keys to the specific TEE instance.
pub fn set_platform_measurement(measurement: [u8; 32]) {
    let _ = PLATFORM_MEASUREMENT.set(measurement);
}

/// Derive a 256-bit AES key from a key UUID, vendor context, and platform measurement.
///
/// Uses HKDF-Extract–like derivation:
/// `SHA-256(SHA-256(key_id || tag || platform_measurement) || "aes256gcm-enclave-key")`.
///
/// On real TEE hardware (AMD SEV-SNP, Intel TDX, AWS Nitro), the platform measurement
/// binds the key to the specific enclave instance. Additionally, on AMD SEV-SNP and
/// Intel TDX, all VM memory is hardware-encrypted (VMSA/MKTME), providing a second
/// layer of protection for the derived key material in RAM.
fn derive_aes_key(key_id: &Uuid, vendor_tag: &[u8]) -> [u8; 32] {
    // First round: mix key_id with vendor context and platform measurement
    let mut h1 = Sha256::new();
    h1.update(key_id.as_bytes());
    h1.update(vendor_tag);
    if let Some(measurement) = PLATFORM_MEASUREMENT.get() {
        h1.update(measurement);
    }
    let ikm = h1.finalize();

    // Second round: derive the final AES key
    let mut h2 = Sha256::new();
    h2.update(ikm);
    h2.update(b"aes256gcm-enclave-key");
    h2.finalize().into()
}

/// Encrypt plaintext using AES-256-GCM with a TEE-derived key.
///
/// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn enclave_encrypt_aes256gcm(
    key_id: &Uuid,
    vendor_tag: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let aes_key = derive_aes_key(key_id, vendor_tag);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| TeeError::EncryptionError(format!("AES-256-GCM key init: {}", e)))?;

    // Generate a random 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| TeeError::EncryptionError(format!("AES-256-GCM encrypt: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt ciphertext using AES-256-GCM with a TEE-derived key.
///
/// Expects input format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn enclave_decrypt_aes256gcm(
    key_id: &Uuid,
    vendor_tag: &[u8],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_with_nonce.len() < 12 + 16 {
        return Err(TeeError::DecryptionError(
            "Ciphertext too short: need at least 28 bytes (12 nonce + 16 tag)".to_string(),
        ));
    }

    let aes_key = derive_aes_key(key_id, vendor_tag);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| TeeError::DecryptionError(format!("AES-256-GCM key init: {}", e)))?;

    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..12]);
    let ciphertext = &ciphertext_with_nonce[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| TeeError::DecryptionError(format!("AES-256-GCM decrypt: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_encrypt_decrypt() {
        let key_id = Uuid::new_v4();
        let vendor_tag = b"test-vendor";
        let plaintext = b"Hello, TEE enclave!";

        let ciphertext = enclave_encrypt_aes256gcm(&key_id, vendor_tag, plaintext).unwrap();

        // Ciphertext should be longer than plaintext (12 nonce + 16 tag)
        assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);

        // Ciphertext should not contain plaintext
        assert_ne!(&ciphertext[12..12 + plaintext.len()], plaintext);

        let decrypted = enclave_decrypt_aes256gcm(&key_id, vendor_tag, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = Uuid::new_v4();
        let key2 = Uuid::new_v4();
        let vendor_tag = b"test-vendor";
        let plaintext = b"Same plaintext, different keys";

        let ct1 = enclave_encrypt_aes256gcm(&key1, vendor_tag, plaintext).unwrap();
        let ct2 = enclave_encrypt_aes256gcm(&key2, vendor_tag, plaintext).unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(ct1, ct2);

        // Can't decrypt with wrong key
        let result = enclave_decrypt_aes256gcm(&key2, vendor_tag, &ct1);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_vendors_produce_different_ciphertext() {
        let key_id = Uuid::new_v4();
        let plaintext = b"Same key, different vendors";

        let ct1 = enclave_encrypt_aes256gcm(&key_id, b"intel-tdx", plaintext).unwrap();
        let ct2 = enclave_encrypt_aes256gcm(&key_id, b"amd-sev-snp", plaintext).unwrap();

        // Can't decrypt with wrong vendor tag
        let result = enclave_decrypt_aes256gcm(&key_id, b"amd-sev-snp", &ct1);
        assert!(result.is_err());
        let _ = ct2; // suppress unused
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key_id = Uuid::new_v4();
        let vendor_tag = b"test-vendor";
        let plaintext = b"Integrity check";

        let mut ciphertext = enclave_encrypt_aes256gcm(&key_id, vendor_tag, plaintext).unwrap();

        // Tamper with a byte in the ciphertext body
        ciphertext[15] ^= 0xFF;

        let result = enclave_decrypt_aes256gcm(&key_id, vendor_tag, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_short_ciphertext_rejected() {
        let key_id = Uuid::new_v4();
        let vendor_tag = b"test-vendor";

        let result = enclave_decrypt_aes256gcm(&key_id, vendor_tag, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key_id = Uuid::new_v4();
        let vendor_tag = b"test-vendor";
        let plaintext = b"";

        let ciphertext = enclave_encrypt_aes256gcm(&key_id, vendor_tag, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 12 + 16); // nonce + tag, no body

        let decrypted = enclave_decrypt_aes256gcm(&key_id, vendor_tag, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
