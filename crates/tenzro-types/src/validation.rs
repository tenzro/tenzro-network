//! Deserialization bounds and validation helpers for Tenzro Network
//!
//! This module provides serde-compatible helpers that enforce upper bounds
//! on `Vec<T>` and `String` fields when deserializing untrusted payloads.
//!
//! # Why
//!
//! Without bounds, an attacker can send a JSON or bincode payload that
//! claims a 4 GB Vec, forcing the receiver to allocate gigabytes of memory
//! and crash the node (HIGH #69 in the audit). The helpers in this module
//! reject any vector or string longer than `MAX_DESERIALIZED_*` constants
//! defined in [`crate::constants`].
//!
//! # Usage
//!
//! ```ignore
//! use serde::{Deserialize, Serialize};
//! use tenzro_types::validation::bounded_vec_bytes;
//!
//! #[derive(Serialize, Deserialize)]
//! struct Message {
//!     #[serde(deserialize_with = "bounded_vec_bytes")]
//!     payload: Vec<u8>,
//! }
//! ```

use crate::constants::{
    CHAIN_ID_MAX, CHAIN_ID_MIN, MAX_DESERIALIZED_BYTES, MAX_DESERIALIZED_PEER_COUNT,
    MAX_DESERIALIZED_STRING_LEN, MAX_DESERIALIZED_TX_COUNT, MAX_DESERIALIZED_VALIDATOR_COUNT,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES,
};
use crate::primitives::ChainId;
use serde::{Deserialize, Deserializer};

/// Validates that a [`ChainId`] falls within the allowed range.
///
/// Returns `Ok(())` if the chain id is in `[CHAIN_ID_MIN, CHAIN_ID_MAX]`,
/// otherwise returns an error message describing the failure.
pub fn validate_chain_id(chain_id: ChainId) -> Result<(), crate::error::TenzroError> {
    let value = chain_id.0;
    if value < CHAIN_ID_MIN {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "ChainId must be >= {} (got {})",
            CHAIN_ID_MIN, value
        )))
    } else if value > CHAIN_ID_MAX {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "ChainId must be <= {} (got {}); see EIP-2294",
            CHAIN_ID_MAX, value
        )))
    } else {
        Ok(())
    }
}

/// Generic bounded `Vec<T>` deserializer.
///
/// Rejects payloads whose vector length exceeds `MAX`.
pub fn bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(deserializer)?;
    if v.len() > MAX {
        return Err(serde::de::Error::custom(format!(
            "vector too long: {} > {}",
            v.len(),
            MAX
        )));
    }
    Ok(v)
}

/// Generic bounded `String` deserializer.
///
/// Rejects strings longer than `MAX_DESERIALIZED_STRING_LEN` bytes.
pub fn bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_DESERIALIZED_STRING_LEN {
        return Err(serde::de::Error::custom(format!(
            "string too long: {} > {}",
            s.len(),
            MAX_DESERIALIZED_STRING_LEN
        )));
    }
    Ok(s)
}

/// Bounded `Vec<u8>` deserializer for arbitrary payload bytes.
pub fn bounded_vec_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Vec::<u8>::deserialize(deserializer)?;
    if v.len() > MAX_DESERIALIZED_BYTES {
        return Err(serde::de::Error::custom(format!(
            "byte vector too long: {} > {}",
            v.len(),
            MAX_DESERIALIZED_BYTES
        )));
    }
    Ok(v)
}

/// Bounded `Vec<u8>` deserializer for signature bytes.
pub fn bounded_signature_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Vec::<u8>::deserialize(deserializer)?;
    if v.len() > MAX_SIGNATURE_BYTES {
        return Err(serde::de::Error::custom(format!(
            "signature too long: {} > {}",
            v.len(),
            MAX_SIGNATURE_BYTES
        )));
    }
    Ok(v)
}

/// Bounded `Vec<u8>` deserializer for public key bytes.
pub fn bounded_public_key_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Vec::<u8>::deserialize(deserializer)?;
    if v.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(serde::de::Error::custom(format!(
            "public key too long: {} > {}",
            v.len(),
            MAX_PUBLIC_KEY_BYTES
        )));
    }
    Ok(v)
}

/// Strict deserializer for ML-DSA-65 signature bytes.
///
/// FIPS 204 fixes the ML-DSA-65 signature length at exactly **3309 bytes**.
/// Rejects any other length so a `SignedTransaction` cannot be constructed
/// without a valid PQ signature.
pub fn bounded_pq_signature_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    /// FIPS 204 ML-DSA-65 signature length in bytes. Mirrors
    /// `tenzro_crypto::pq::ML_DSA_65_SIG_LEN`.
    const ML_DSA_65_SIG_LEN: usize = 3309;

    let v = Vec::<u8>::deserialize(deserializer)?;
    if v.len() != ML_DSA_65_SIG_LEN {
        return Err(serde::de::Error::custom(format!(
            "ML-DSA-65 pq_signature has wrong length: expected {}, got {}",
            ML_DSA_65_SIG_LEN,
            v.len()
        )));
    }
    Ok(v)
}

/// Strict deserializer for ML-DSA-65 verifying key bytes.
///
/// FIPS 204 fixes the ML-DSA-65 verifying key length at exactly **1952 bytes**.
/// This deserializer rejects any other length — including the empty vector —
/// so a `Transaction` cannot be constructed without a valid PQ key. There is
/// no legacy fallback path: a payload that omits or mis-sizes this field is
/// not a Tenzro transaction.
pub fn bounded_pq_public_key_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    /// FIPS 204 ML-DSA-65 verifying key length in bytes. Mirrors
    /// `tenzro_crypto::pq::ML_DSA_65_VK_LEN`; duplicated as a numeric literal
    /// here so `tenzro-types` does not depend on `tenzro-crypto`.
    const ML_DSA_65_VK_LEN: usize = 1952;

    let v = Vec::<u8>::deserialize(deserializer)?;
    if v.len() != ML_DSA_65_VK_LEN {
        return Err(serde::de::Error::custom(format!(
            "ML-DSA-65 pq_public_key has wrong length: expected {}, got {}",
            ML_DSA_65_VK_LEN,
            v.len()
        )));
    }
    Ok(v)
}

/// Bounded `Vec<T>` deserializer for transaction lists in blocks.
pub fn bounded_tx_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(deserializer)?;
    if v.len() > MAX_DESERIALIZED_TX_COUNT {
        return Err(serde::de::Error::custom(format!(
            "too many transactions in block: {} > {}",
            v.len(),
            MAX_DESERIALIZED_TX_COUNT
        )));
    }
    Ok(v)
}

/// Bounded `Vec<T>` deserializer for validator sets.
pub fn bounded_validator_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(deserializer)?;
    if v.len() > MAX_DESERIALIZED_VALIDATOR_COUNT {
        return Err(serde::de::Error::custom(format!(
            "too many validators: {} > {}",
            v.len(),
            MAX_DESERIALIZED_VALIDATOR_COUNT
        )));
    }
    Ok(v)
}

/// Bounded `Vec<T>` deserializer for peer lists.
pub fn bounded_peer_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(deserializer)?;
    if v.len() > MAX_DESERIALIZED_PEER_COUNT {
        return Err(serde::de::Error::custom(format!(
            "too many peers: {} > {}",
            v.len(),
            MAX_DESERIALIZED_PEER_COUNT
        )));
    }
    Ok(v)
}

// ── API input validation helpers (MEDIUM #115) ──────────────────────

/// Maximum length for a display name string at API boundaries.
pub const MAX_DISPLAY_NAME_LEN: usize = 256;

/// Maximum length for a model ID string at API boundaries.
pub const MAX_MODEL_ID_LEN: usize = 512;

/// Maximum length for a description string at API boundaries.
pub const MAX_DESCRIPTION_LEN: usize = 4096;

/// Maximum number of chat messages in a single request.
pub const MAX_CHAT_MESSAGES: usize = 256;

/// Maximum length for a single chat message content field (1 MB).
pub const MAX_CHAT_MESSAGE_LEN: usize = 1_048_576;

/// Maximum max_tokens value for inference requests.
pub const MAX_INFERENCE_TOKENS: u64 = 1_000_000;

/// Maximum number of public inputs in a ZK proof verification request.
pub const MAX_ZK_PUBLIC_INPUTS: usize = 256;

/// Maximum number of certificates in a TEE attestation chain.
pub const MAX_CERTIFICATE_CHAIN: usize = 10;

/// Maximum length for a service endpoint URL (MEDIUM #128).
pub const MAX_SERVICE_ENDPOINT_URL_LEN: usize = 2048;

/// Validates that a string is within length bounds.
///
/// Returns `Ok(())` if the string's byte length is `<= max_len`,
/// otherwise returns an `Err` with a descriptive message.
pub fn validate_string_len(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), crate::error::TenzroError> {
    if value.len() > max_len {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "{} too long: {} bytes (max {})",
            field_name,
            value.len(),
            max_len
        )))
    } else {
        Ok(())
    }
}

/// Validates that a numeric value is within bounds.
pub fn validate_numeric_bound<T: std::fmt::Display + PartialOrd>(
    value: T,
    field_name: &str,
    max: T,
) -> Result<(), crate::error::TenzroError> {
    if value > max {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "{} exceeds maximum: {} (max {})",
            field_name, value, max
        )))
    } else {
        Ok(())
    }
}

/// Validates that a vector does not exceed a maximum number of items.
pub fn validate_vec_len<T>(
    vec: &[T],
    field_name: &str,
    max_items: usize,
) -> Result<(), crate::error::TenzroError> {
    if vec.len() > max_items {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "{} too many items: {} (max {})",
            field_name,
            vec.len(),
            max_items
        )))
    } else {
        Ok(())
    }
}

/// Validates a hex string and returns the decoded bytes.
///
/// Checks that:
/// 1. The string is valid hex
/// 2. The decoded length is within `[min_bytes, max_bytes]`
pub fn validate_hex_string(
    value: &str,
    field_name: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, crate::error::TenzroError> {
    let cleaned = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(cleaned).map_err(|e| {
        crate::error::TenzroError::InvalidConfig(format!("{} invalid hex: {}", field_name, e))
    })?;
    if bytes.len() < min_bytes {
        return Err(crate::error::TenzroError::InvalidConfig(format!(
            "{} too short: {} bytes (min {})",
            field_name,
            bytes.len(),
            min_bytes
        )));
    }
    if bytes.len() > max_bytes {
        return Err(crate::error::TenzroError::InvalidConfig(format!(
            "{} too long: {} bytes (max {})",
            field_name,
            bytes.len(),
            max_bytes
        )));
    }
    Ok(bytes)
}

/// Validates that a temperature value is within the standard range.
pub fn validate_temperature(value: f64) -> Result<(), crate::error::TenzroError> {
    if !(0.0..=2.0).contains(&value) {
        Err(crate::error::TenzroError::InvalidConfig(format!(
            "temperature out of range: {} (must be 0.0..=2.0)",
            value
        )))
    } else {
        Ok(())
    }
}

// ── Service endpoint URL validation (MEDIUM #128) ───────────────────

/// Allowed URL schemes for service endpoints.
const ALLOWED_SCHEMES: &[&str] = &["https://", "http://", "wss://", "ws://"];

/// Validates a service endpoint URL.
///
/// Checks:
/// 1. Length does not exceed `MAX_SERVICE_ENDPOINT_URL_LEN`
/// 2. Starts with an allowed scheme (http, https, ws, wss)
/// 3. Contains at least a host portion after the scheme
/// 4. Does not contain control characters
pub fn validate_service_endpoint_url(url: &str) -> Result<(), crate::error::TenzroError> {
    if url.len() > MAX_SERVICE_ENDPOINT_URL_LEN {
        return Err(crate::error::TenzroError::InvalidConfig(format!(
            "service endpoint URL too long: {} bytes (max {})",
            url.len(),
            MAX_SERVICE_ENDPOINT_URL_LEN
        )));
    }

    if url.is_empty() {
        return Err(crate::error::TenzroError::InvalidConfig(
            "service endpoint URL must not be empty".to_string(),
        ));
    }

    // Check for control characters (could be used for header injection)
    if url.bytes().any(|b| b < 0x20 && b != b'\t') {
        return Err(crate::error::TenzroError::InvalidConfig(
            "service endpoint URL contains control characters".to_string(),
        ));
    }

    // Check scheme
    let has_valid_scheme = ALLOWED_SCHEMES.iter().any(|s| url.starts_with(s));
    if !has_valid_scheme {
        return Err(crate::error::TenzroError::InvalidConfig(format!(
            "service endpoint URL must use http, https, ws, or wss scheme (got: {})",
            url.chars().take(20).collect::<String>()
        )));
    }

    // Check that there's a host after the scheme
    let after_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("wss://") {
        rest
    } else if let Some(rest) = url.strip_prefix("ws://") {
        rest
    } else {
        return Err(crate::error::TenzroError::InvalidConfig(
            "invalid URL scheme".to_string(),
        ));
    };

    if after_scheme.is_empty() {
        return Err(crate::error::TenzroError::InvalidConfig(
            "service endpoint URL must contain a host".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct WithBoundedBytes {
        #[serde(deserialize_with = "bounded_signature_bytes")]
        sig: Vec<u8>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct WithBoundedString {
        #[serde(deserialize_with = "bounded_string")]
        name: String,
    }

    #[test]
    fn test_chain_id_validation_ok() {
        assert!(validate_chain_id(ChainId::new(1)).is_ok());
        assert!(validate_chain_id(ChainId::new(1337)).is_ok());
        assert!(validate_chain_id(ChainId::MAINNET).is_ok());
        assert!(validate_chain_id(ChainId::TESTNET).is_ok());
        assert!(validate_chain_id(ChainId::new(CHAIN_ID_MAX)).is_ok());
    }

    #[test]
    fn test_chain_id_validation_zero_rejected() {
        assert!(validate_chain_id(ChainId::new(0)).is_err());
    }

    #[test]
    fn test_chain_id_validation_too_large_rejected() {
        assert!(validate_chain_id(ChainId::new(CHAIN_ID_MAX + 1)).is_err());
        assert!(validate_chain_id(ChainId::new(u64::MAX)).is_err());
    }

    #[test]
    fn test_bounded_signature_bytes_ok() {
        let v = WithBoundedBytes { sig: vec![0u8; 64] };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: WithBoundedBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sig.len(), 64);
    }

    #[test]
    fn test_bounded_signature_bytes_too_long() {
        // Manually craft an over-sized signature payload
        let oversized = vec![0u8; MAX_SIGNATURE_BYTES + 1];
        let json = serde_json::json!({ "sig": oversized });
        let result: Result<WithBoundedBytes, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_bounded_string_ok() {
        let v = WithBoundedString {
            name: "alice".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: WithBoundedString = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "alice");
    }

    #[test]
    fn test_bounded_string_too_long() {
        let oversized = "x".repeat(MAX_DESERIALIZED_STRING_LEN + 1);
        let json = serde_json::json!({ "name": oversized });
        let result: Result<WithBoundedString, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    // ── API input validation tests (MEDIUM #115) ────────────────────

    #[test]
    fn test_validate_string_len_ok() {
        assert!(validate_string_len("hello", "name", 256).is_ok());
        assert!(validate_string_len("", "name", 256).is_ok());
    }

    #[test]
    fn test_validate_string_len_too_long() {
        let long = "x".repeat(257);
        let err = validate_string_len(&long, "name", 256).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_numeric_bound_ok() {
        assert!(validate_numeric_bound(100u64, "tokens", 1_000_000u64).is_ok());
    }

    #[test]
    fn test_validate_numeric_bound_exceeded() {
        let err = validate_numeric_bound(2_000_000u64, "tokens", 1_000_000u64).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_vec_len_ok() {
        let v = vec![1, 2, 3];
        assert!(validate_vec_len(&v, "items", 10).is_ok());
    }

    #[test]
    fn test_validate_vec_len_too_many() {
        let v = vec![0u8; 300];
        let err = validate_vec_len(&v, "inputs", 256).unwrap_err();
        assert!(err.to_string().contains("too many items"));
    }

    #[test]
    fn test_validate_hex_string_ok() {
        let bytes = validate_hex_string("0xdeadbeef", "tx", 1, 64).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_validate_hex_string_no_prefix() {
        let bytes = validate_hex_string("deadbeef", "tx", 1, 64).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_validate_hex_string_too_short() {
        let err = validate_hex_string("ab", "key", 4, 64).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_validate_hex_string_too_long() {
        let long = "ab".repeat(100);
        let err = validate_hex_string(&long, "data", 1, 32).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_hex_string_invalid() {
        let err = validate_hex_string("not_hex!", "hash", 1, 32).unwrap_err();
        assert!(err.to_string().contains("invalid hex"));
    }

    #[test]
    fn test_validate_temperature_ok() {
        assert!(validate_temperature(0.0).is_ok());
        assert!(validate_temperature(0.7).is_ok());
        assert!(validate_temperature(2.0).is_ok());
    }

    #[test]
    fn test_validate_temperature_out_of_range() {
        assert!(validate_temperature(-0.1).is_err());
        assert!(validate_temperature(2.1).is_err());
    }

    // ── Service endpoint URL validation tests (MEDIUM #128) ─────────

    #[test]
    fn test_validate_url_valid_https() {
        assert!(validate_service_endpoint_url("https://example.com/api").is_ok());
    }

    #[test]
    fn test_validate_url_valid_http() {
        assert!(validate_service_endpoint_url("http://localhost:8080/test").is_ok());
    }

    #[test]
    fn test_validate_url_valid_wss() {
        assert!(validate_service_endpoint_url("wss://ws.example.com").is_ok());
    }

    #[test]
    fn test_validate_url_empty() {
        assert!(validate_service_endpoint_url("").is_err());
    }

    #[test]
    fn test_validate_url_invalid_scheme() {
        let err = validate_service_endpoint_url("ftp://files.example.com").unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[test]
    fn test_validate_url_no_host() {
        assert!(validate_service_endpoint_url("https://").is_err());
    }

    #[test]
    fn test_validate_url_too_long() {
        let long = format!(
            "https://example.com/{}",
            "a".repeat(MAX_SERVICE_ENDPOINT_URL_LEN)
        );
        assert!(validate_service_endpoint_url(&long).is_err());
    }

    #[test]
    fn test_validate_url_control_chars() {
        assert!(validate_service_endpoint_url("https://example.com/\x00").is_err());
    }

    #[test]
    fn test_validate_url_javascript_scheme() {
        assert!(validate_service_endpoint_url("javascript:alert(1)").is_err());
    }
}
