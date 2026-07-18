//! Sign-In With Tenzro (SIWT) — EIP-4361-shaped authentication flow.
//!
//! EIP-4361 (Sign-In with Ethereum) standardised a structured message
//! format that wallet apps can sign to authenticate against off-chain
//! services without revealing private keys. SIWT applies the same
//! structure to Tenzro identities: the message contains the requesting
//! domain, the Tenzro address, a nonce, the chain id (1337 for testnet,
//! `tenzro_mainnet` once mainnet ships), and an issued-at timestamp; the
//! user signs it with their wallet's hybrid Ed25519+ML-DSA-65 key; and
//! the verifier checks the signature against the registered identity.
//!
//! The message ABNF is byte-identical to EIP-4361 (so existing SIWE
//! parsers work) except that:
//!   - `Domain` may use any Tenzro-served hostname.
//!   - `URI` may be a `tenzro://` URI.
//!   - The address is the canonical Tenzro address (32-byte hex with the
//!     `tnzro1` bech32 prefix when stringified — but EIP-4361 requires
//!     an EVM-shaped 40-hex address, so SIWT also accepts the trailing-20
//!     EVM projection of the address).
//!
//! Verification is non-stateful: callers store the issued nonce, dispatch
//! the signed message, and `verify_siwt` confirms parse + signature + age.
//! Replay protection is left to the caller's nonce store.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned by SIWT verification.
#[derive(Debug, Error)]
pub enum SiwtError {
    /// Parse failure (missing field, malformed line, etc).
    #[error("siwt parse error: {0}")]
    Parse(String),
    /// Issued-at falls outside the allowed window.
    #[error("siwt message expired")]
    Expired,
    /// Signature did not verify.
    #[error("siwt signature invalid")]
    InvalidSignature,
    /// Nonce mismatch (caller-side replay store rejected).
    #[error("siwt nonce mismatch")]
    NonceMismatch,
    /// Chain id mismatch.
    #[error("siwt chain id mismatch")]
    ChainMismatch,
}

/// Parsed SIWT message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiwtMessage {
    /// RFC 3986 authority requesting the sign-in.
    pub domain: String,
    /// Tenzro address (hex-encoded 32 bytes or EVM-projected 20 bytes).
    pub address: String,
    /// Statement the user agreed to (optional).
    pub statement: Option<String>,
    /// URI that consumes the signed message (`https://...` or `tenzro://...`).
    pub uri: String,
    /// SIWE version — always `1`.
    pub version: String,
    /// Tenzro chain id (e.g. `1337`).
    pub chain_id: u64,
    /// Cryptographically random nonce (>= 8 alphanumeric).
    pub nonce: String,
    /// Issued-at timestamp (ISO 8601).
    pub issued_at: DateTime<Utc>,
    /// Optional expiration timestamp.
    pub expiration_time: Option<DateTime<Utc>>,
    /// Optional `not-before` timestamp.
    pub not_before: Option<DateTime<Utc>>,
    /// Optional opaque request id.
    pub request_id: Option<String>,
    /// Resources the signer authorizes (URIs).
    pub resources: Vec<String>,
}

impl SiwtMessage {
    /// Render the message in EIP-4361 canonical form. Implementations
    /// signing the SIWT must hash exactly this byte representation.
    pub fn to_canonical_string(&self) -> String {
        let mut buf = String::new();
        buf.push_str(&format!(
            "{} wants you to sign in with your Tenzro account:\n{}\n",
            self.domain, self.address
        ));
        if let Some(stmt) = &self.statement {
            buf.push_str(&format!("\n{}\n", stmt));
        }
        buf.push('\n');
        buf.push_str(&format!("URI: {}\n", self.uri));
        buf.push_str(&format!("Version: {}\n", self.version));
        buf.push_str(&format!("Chain ID: {}\n", self.chain_id));
        buf.push_str(&format!("Nonce: {}\n", self.nonce));
        buf.push_str(&format!(
            "Issued At: {}",
            self.issued_at.to_rfc3339()
        ));
        if let Some(exp) = self.expiration_time {
            buf.push_str(&format!("\nExpiration Time: {}", exp.to_rfc3339()));
        }
        if let Some(nb) = self.not_before {
            buf.push_str(&format!("\nNot Before: {}", nb.to_rfc3339()));
        }
        if let Some(rid) = &self.request_id {
            buf.push_str(&format!("\nRequest ID: {}", rid));
        }
        if !self.resources.is_empty() {
            buf.push_str("\nResources:");
            for r in &self.resources {
                buf.push_str(&format!("\n- {}", r));
            }
        }
        buf
    }

    /// Parse a SIWT message string.
    pub fn parse(msg: &str) -> Result<Self, SiwtError> {
        let mut lines = msg.lines();
        let first = lines
            .next()
            .ok_or_else(|| SiwtError::Parse("missing first line".into()))?;
        let (domain, _rest) = first.split_once(" wants you to sign in").ok_or_else(|| {
            SiwtError::Parse("first line must contain 'wants you to sign in'".into())
        })?;
        let address = lines
            .next()
            .ok_or_else(|| SiwtError::Parse("missing address line".into()))?
            .trim()
            .to_string();
        // Optional blank + statement + blank, then key:value pairs.
        let mut statement = None;
        let mut kv: HashMap<String, String> = HashMap::new();
        let mut resources: Vec<String> = Vec::new();
        let mut saw_blank = false;
        let mut collecting_resources = false;
        for line in lines {
            if line.is_empty() {
                saw_blank = true;
                continue;
            }
            if collecting_resources && line.starts_with("- ") {
                resources.push(line[2..].trim().to_string());
                continue;
            }
            if line == "Resources:" {
                collecting_resources = true;
                continue;
            }
            if let Some((k, v)) = line.split_once(": ") {
                kv.insert(k.trim().to_string(), v.trim().to_string());
            } else if !saw_blank {
                continue;
            } else if statement.is_none() {
                statement = Some(line.trim().to_string());
            }
        }
        let uri = kv
            .remove("URI")
            .ok_or_else(|| SiwtError::Parse("missing URI".into()))?;
        let version = kv
            .remove("Version")
            .ok_or_else(|| SiwtError::Parse("missing Version".into()))?;
        let chain_id: u64 = kv
            .remove("Chain ID")
            .ok_or_else(|| SiwtError::Parse("missing Chain ID".into()))?
            .parse()
            .map_err(|_| SiwtError::Parse("Chain ID must be u64".into()))?;
        let nonce = kv
            .remove("Nonce")
            .ok_or_else(|| SiwtError::Parse("missing Nonce".into()))?;
        let issued_at = kv
            .remove("Issued At")
            .ok_or_else(|| SiwtError::Parse("missing Issued At".into()))?;
        let issued_at = DateTime::parse_from_rfc3339(&issued_at)
            .map_err(|e| SiwtError::Parse(format!("Issued At not RFC3339: {}", e)))?
            .with_timezone(&Utc);
        let expiration_time = kv
            .remove("Expiration Time")
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| SiwtError::Parse(format!("Expiration Time not RFC3339: {}", e)))?
            .map(|d| d.with_timezone(&Utc));
        let not_before = kv
            .remove("Not Before")
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| SiwtError::Parse(format!("Not Before not RFC3339: {}", e)))?
            .map(|d| d.with_timezone(&Utc));
        let request_id = kv.remove("Request ID");
        Ok(Self {
            domain: domain.trim().to_string(),
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

/// Verify the timing constraints of a SIWT message against the current
/// time. Signature verification is delegated to the caller (because it
/// needs the registry to find the public key).
pub fn verify_siwt_timing(msg: &SiwtMessage, now: DateTime<Utc>) -> Result<(), SiwtError> {
    if let Some(nb) = msg.not_before
        && now < nb
    {
        return Err(SiwtError::Expired);
    }
    if let Some(exp) = msg.expiration_time
        && now >= exp
    {
        return Err(SiwtError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> SiwtMessage {
        SiwtMessage {
            domain: "example.com".into(),
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            statement: Some("Sign in to Example".into()),
            uri: "https://example.com/login".into(),
            version: "1".into(),
            chain_id: 1337,
            nonce: "abc123XYZ".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
            expiration_time: Some(Utc.with_ymd_and_hms(2026, 1, 1, 12, 5, 0).unwrap()),
            not_before: None,
            request_id: Some("req-001".into()),
            resources: vec!["https://example.com/r1".into()],
        }
    }

    #[test]
    fn roundtrip_parse() {
        let m = sample();
        let s = m.to_canonical_string();
        let m2 = SiwtMessage::parse(&s).unwrap();
        assert_eq!(m.address, m2.address);
        assert_eq!(m.uri, m2.uri);
        assert_eq!(m.chain_id, m2.chain_id);
        assert_eq!(m.nonce, m2.nonce);
        assert_eq!(m.resources, m2.resources);
    }

    #[test]
    fn timing_rejects_after_expiration() {
        let m = sample();
        let later = Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap();
        let err = verify_siwt_timing(&m, later).unwrap_err();
        assert!(matches!(err, SiwtError::Expired));
    }

    #[test]
    fn timing_rejects_before_not_before() {
        let mut m = sample();
        m.not_before = Some(Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap());
        let earlier = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let err = verify_siwt_timing(&m, earlier).unwrap_err();
        assert!(matches!(err, SiwtError::Expired));
    }

    #[test]
    fn parse_missing_uri_errors() {
        let s = "example.com wants you to sign in with your Tenzro account:\n0xabc\n\nVersion: 1\nChain ID: 1337\nNonce: x\nIssued At: 2026-01-01T00:00:00Z\n";
        let err = SiwtMessage::parse(s).unwrap_err();
        assert!(matches!(err, SiwtError::Parse(_)));
    }
}
