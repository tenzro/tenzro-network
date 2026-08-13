//! MicroVM Metadata Service (MMDS) parsing.
//!
//! The supervisor stages a JSON document into Firecracker's MMDS and the guest
//! reads it at `http://169.254.169.254`. The node's supervisor
//! ([`tenzro_node::machines`]) writes `{ "env": { NAME: VALUE, ... } }` with the
//! environment already unsealed host-side. A deployment may additionally deliver
//! `sealed_env` (envelopes the guest unseals itself, see [`crate::crypto`]).
//!
//! Firecracker's MMDS **v2** is token-authenticated: the guest first `PUT`s
//! `/latest/api/token` (with a TTL header) to obtain a session token, then
//! sends it as `X-metadata-token` on the `GET`. The token handshake and the raw
//! HTTP live in `main.rs` (they need a live link); the JSON *parsing* is here
//! and unit-tested.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::SealedEnvVar;

/// The link-local MMDS address Firecracker serves on (matches the supervisor's
/// `/mmds/config` `ipv4_address`).
pub const MMDS_ADDR: &str = "169.254.169.254";
/// MMDS v2 token endpoint.
pub const MMDS_TOKEN_PATH: &str = "/latest/api/token";
/// Default token TTL requested (seconds). Firecracker caps this at 6h.
pub const MMDS_TOKEN_TTL_SECS: u32 = 21_600;

/// The parsed metadata document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdsData {
    /// Plaintext environment injected by the supervisor (unsealed host-side).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional sealed environment for guest-side unsealing. Empty in the
    /// default node flow (which pre-unseals into `env`).
    #[serde(default)]
    pub sealed_env: Vec<SealedEnvVar>,
}

/// Parse an MMDS document.
///
/// Tolerant of the two shapes MMDS can return: the top-level object we write
/// (`{"env":{...}}`), and a bare `{}` when no metadata was staged. Unknown keys
/// are ignored so future metadata additions don't break older guests.
pub fn parse_mmds(bytes: &[u8]) -> Result<MmdsData, String> {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(MmdsData::default());
    }
    serde_json::from_slice(bytes).map_err(|e| format!("mmds decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_map() {
        let doc = br#"{"env":{"DATABASE_URL":"postgres://x","LOG_LEVEL":"info"}}"#;
        let data = parse_mmds(doc).unwrap();
        assert_eq!(data.env.get("DATABASE_URL").unwrap(), "postgres://x");
        assert_eq!(data.env.get("LOG_LEVEL").unwrap(), "info");
        assert!(data.sealed_env.is_empty());
    }

    #[test]
    fn empty_document_is_ok() {
        assert_eq!(parse_mmds(b"{}").unwrap(), MmdsData::default());
        assert_eq!(parse_mmds(b"   ").unwrap(), MmdsData::default());
        assert_eq!(parse_mmds(b"").unwrap(), MmdsData::default());
    }

    #[test]
    fn unknown_keys_ignored() {
        let doc = br#"{"env":{"A":"1"},"latest":{"meta-data":{}},"extra":42}"#;
        let data = parse_mmds(doc).unwrap();
        assert_eq!(data.env.get("A").unwrap(), "1");
    }

    #[test]
    fn parses_sealed_env_entries() {
        let doc = br#"{"env":{},"sealed_env":[{"name":"SECRET","sealed_value":{"a":1}}]}"#;
        let data = parse_mmds(doc).unwrap();
        assert_eq!(data.sealed_env.len(), 1);
        assert_eq!(data.sealed_env[0].name, "SECRET");
    }

    #[test]
    fn malformed_is_error() {
        assert!(parse_mmds(b"{not json").is_err());
    }
}
