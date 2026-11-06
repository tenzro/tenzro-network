//! `tenzro://` URI scheme — unified content + node addressing.
//!
//! All Tenzro-native URIs use the `tenzro://` scheme. The path prefix
//! dispatches to the right resolver (blobs, nodes, DIDs, models,
//! receipts). Transport details
//! (iroh-blobs, iroh-gossip, etc.) are deliberately hidden behind the scheme so
//! the underlying transport can be swapped without breaking URIs.
//!
//! # Canonical forms
//!
//! ```text
//! tenzro://blob/<blake3-hex>                            — content fetch (default: iroh-blobs)
//! tenzro://blob/<blake3-hex>?n=<node-id>                — content fetch with provider hint
//! tenzro://node/<node-id>                               — dial a node by key
//! tenzro://did/<did:tenzro:human|machine:...>           — dial by TDIP DID
//! tenzro://model/<model-id>@<blake3-hex>                — content-addressed model artifact
//! tenzro://receipt/<receipt-kind>/<blake3-hex>          — offloaded receipt
//! ```
//!
//! Parsing this module returns a `TenzroUri` enum whose variants match the
//! prefixes above. Resolvers (in `tenzro-iroh`, RPC handlers, etc.) match
//! on the variant and dispatch to the right backend.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The leading scheme expected on every Tenzro-native URI.
pub const TENZRO_URI_SCHEME: &str = "tenzro";

/// Parsed Tenzro URI.
///
/// Construct via `TenzroUri::parse(&str)` or the `FromStr` impl. The variants
/// carry parsed components rather than raw substrings; round-tripping via
/// `Display` always emits the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TenzroUri {
    /// `tenzro://blob/<blake3-hex>[?n=<node-id>]`
    Blob {
        /// 64-character lowercase hex BLAKE3 hash of the blob.
        hash: String,
        /// Optional provider hint — node-id (hex Ed25519 public key) of a
        /// peer believed to have the blob. The resolver MAY use this as a
        /// preferred dial target before falling back to discovery.
        provider_hint: Option<String>,
    },
    /// `tenzro://node/<node-id>` — dial a node by its iroh public key.
    Node {
        /// Hex-encoded node public key.
        node_id: String,
    },
    /// `tenzro://did/<did:tenzro:...>` — dial by TDIP DID. Resolution to a
    /// node-id happens via the on-chain identity registry.
    Did {
        /// Full DID string starting with `did:tenzro:`.
        did: String,
    },
    /// `tenzro://model/<model-id>@<blake3-hex>` — content-addressed model
    /// artifact. `model_id` is the human-readable identifier; the hash
    /// pins a specific binary representation.
    Model {
        /// Model registry identifier (e.g. `qwen3-0.6b`).
        model_id: String,
        /// 64-character lowercase hex BLAKE3 hash of the artifact.
        hash: String,
    },
    /// `tenzro://receipt/<receipt-kind>/<blake3-hex>` — offloaded receipt
    /// (settlement / inference / agent-message).
    Receipt {
        /// Receipt kind, matches `tenzro_storage::da::ReceiptKind` lowercase.
        kind: String,
        /// 64-character lowercase hex BLAKE3 hash of the canonical receipt payload.
        hash: String,
    },
}

/// Errors returned when parsing a `tenzro://` URI.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TenzroUriError {
    #[error("expected scheme `tenzro://`, got `{0}`")]
    WrongScheme(String),
    #[error("empty path after `tenzro://`")]
    EmptyPath,
    #[error("unknown path prefix `{0}` — expected one of blob, node, did, model, receipt")]
    UnknownPrefix(String),
    #[error("missing required segment in `{prefix}` URI: {detail}")]
    MissingSegment {
        prefix: &'static str,
        detail: &'static str,
    },
    #[error("invalid BLAKE3 hash `{0}` — expected 64 lowercase hex characters")]
    InvalidHash(String),
    #[error("invalid `?n=<node-id>` query in blob URI: {0}")]
    InvalidQuery(String),
}

impl TenzroUri {
    /// Parse a `tenzro://...` URI string.
    pub fn parse(input: &str) -> Result<Self, TenzroUriError> {
        let rest = input
            .strip_prefix("tenzro://")
            .ok_or_else(|| TenzroUriError::WrongScheme(input.to_string()))?;

        if rest.is_empty() {
            return Err(TenzroUriError::EmptyPath);
        }

        // Split path from optional query.
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };

        let mut segments = path.split('/');
        let prefix = segments.next().ok_or(TenzroUriError::EmptyPath)?;

        match prefix {
            "blob" => {
                let hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "blob",
                    detail: "BLAKE3 hash",
                })?;
                validate_blake3_hex(hash)?;
                let provider_hint = match query {
                    None => None,
                    Some(q) => Some(parse_node_query(q)?),
                };
                Ok(TenzroUri::Blob {
                    hash: hash.to_string(),
                    provider_hint,
                })
            }
            "node" => {
                let node_id = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "node",
                    detail: "node-id",
                })?;
                Ok(TenzroUri::Node {
                    node_id: node_id.to_string(),
                })
            }
            "did" => {
                // Reassemble: DID strings contain ':' which split('/') leaves intact
                // in the first segment. There should be exactly one segment.
                let did = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "did",
                    detail: "DID string",
                })?;
                if !did.starts_with("did:tenzro:") && !did.starts_with("did:pdis:") {
                    return Err(TenzroUriError::MissingSegment {
                        prefix: "did",
                        detail: "DID must start with `did:tenzro:` or `did:pdis:`",
                    });
                }
                Ok(TenzroUri::Did {
                    did: did.to_string(),
                })
            }
            "model" => {
                let spec = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "model",
                    detail: "<model-id>@<hash>",
                })?;
                let (model_id, hash) =
                    spec.split_once('@').ok_or(TenzroUriError::MissingSegment {
                        prefix: "model",
                        detail: "expected <model-id>@<hash>",
                    })?;
                validate_blake3_hex(hash)?;
                Ok(TenzroUri::Model {
                    model_id: model_id.to_string(),
                    hash: hash.to_string(),
                })
            }
            "receipt" => {
                let kind = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "receipt",
                    detail: "kind",
                })?;
                let hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "receipt",
                    detail: "hash",
                })?;
                validate_blake3_hex(hash)?;
                Ok(TenzroUri::Receipt {
                    kind: kind.to_string(),
                    hash: hash.to_string(),
                })
            }
            other => Err(TenzroUriError::UnknownPrefix(other.to_string())),
        }
    }
}

fn validate_blake3_hex(s: &str) -> Result<(), TenzroUriError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(TenzroUriError::InvalidHash(s.to_string()));
    }
    Ok(())
}

fn parse_node_query(q: &str) -> Result<String, TenzroUriError> {
    let (k, v) = q
        .split_once('=')
        .ok_or_else(|| TenzroUriError::InvalidQuery(q.to_string()))?;
    if k != "n" || v.is_empty() {
        return Err(TenzroUriError::InvalidQuery(q.to_string()));
    }
    Ok(v.to_string())
}

impl fmt::Display for TenzroUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenzroUri::Blob {
                hash,
                provider_hint,
            } => match provider_hint {
                None => write!(f, "tenzro://blob/{hash}"),
                Some(n) => write!(f, "tenzro://blob/{hash}?n={n}"),
            },
            TenzroUri::Node { node_id } => write!(f, "tenzro://node/{node_id}"),
            TenzroUri::Did { did } => write!(f, "tenzro://did/{did}"),
            TenzroUri::Model { model_id, hash } => write!(f, "tenzro://model/{model_id}@{hash}"),
            TenzroUri::Receipt { kind, hash } => write!(f, "tenzro://receipt/{kind}/{hash}"),
        }
    }
}

impl FromStr for TenzroUri {
    type Err = TenzroUriError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn roundtrip(uri: &str) -> TenzroUri {
        let parsed = TenzroUri::parse(uri).unwrap_or_else(|e| panic!("parse({uri}) failed: {e}"));
        assert_eq!(parsed.to_string(), uri, "round-trip mismatch");
        parsed
    }

    #[test]
    fn parses_blob() {
        let u = roundtrip(&format!("tenzro://blob/{ZERO_HASH}"));
        match u {
            TenzroUri::Blob {
                hash,
                provider_hint,
            } => {
                assert_eq!(hash, ZERO_HASH);
                assert!(provider_hint.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parses_blob_with_provider_hint() {
        let u = roundtrip(&format!("tenzro://blob/{ZERO_HASH}?n=abc123"));
        match u {
            TenzroUri::Blob { provider_hint, .. } => {
                assert_eq!(provider_hint.as_deref(), Some("abc123"))
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parses_node() {
        roundtrip("tenzro://node/12D3KooWGb6bkYsibMapPBMWjDTiTCGDnXZkkZK6mjzbx4HpaKC8");
    }

    #[test]
    fn parses_did() {
        roundtrip("tenzro://did/did:tenzro:human:00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn parses_did_pdis_secondary() {
        roundtrip("tenzro://did/did:pdis:guardian:00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn parses_model() {
        roundtrip(&format!("tenzro://model/qwen3-0.6b@{ZERO_HASH}"));
    }

    #[test]
    fn parses_receipt() {
        roundtrip(&format!("tenzro://receipt/settlement/{ZERO_HASH}"));
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(matches!(
            TenzroUri::parse("iroh://blob/abc"),
            Err(TenzroUriError::WrongScheme(_))
        ));
        assert!(matches!(
            TenzroUri::parse("http://example.com"),
            Err(TenzroUriError::WrongScheme(_))
        ));
    }

    #[test]
    fn rejects_unknown_prefix() {
        assert!(matches!(
            TenzroUri::parse("tenzro://unknownprefix/abc"),
            Err(TenzroUriError::UnknownPrefix(_))
        ));
    }

    #[test]
    fn rejects_bad_hash() {
        // Too short.
        assert!(matches!(
            TenzroUri::parse("tenzro://blob/abc"),
            Err(TenzroUriError::InvalidHash(_))
        ));
        // Uppercase letters rejected — canonical form is lowercase. Pick a
        // hash that actually contains letters so case matters (a pure-digit
        // hash like 0000... uppercases to itself).
        let mixed_lower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let mixed_upper = mixed_lower.to_uppercase();
        assert!(TenzroUri::parse(&format!("tenzro://blob/{mixed_lower}")).is_ok());
        assert!(matches!(
            TenzroUri::parse(&format!("tenzro://blob/{mixed_upper}")),
            Err(TenzroUriError::InvalidHash(_))
        ));
        // Non-hex characters rejected.
        let non_hex = "g".repeat(64);
        assert!(matches!(
            TenzroUri::parse(&format!("tenzro://blob/{non_hex}")),
            Err(TenzroUriError::InvalidHash(_))
        ));
    }

    #[test]
    fn rejects_empty_path() {
        assert!(matches!(
            TenzroUri::parse("tenzro://"),
            Err(TenzroUriError::EmptyPath)
        ));
    }

    #[test]
    fn rejects_bad_query() {
        // Unknown query parameter name.
        assert!(matches!(
            TenzroUri::parse(&format!("tenzro://blob/{ZERO_HASH}?x=abc")),
            Err(TenzroUriError::InvalidQuery(_))
        ));
        // Missing value.
        assert!(matches!(
            TenzroUri::parse(&format!("tenzro://blob/{ZERO_HASH}?n=")),
            Err(TenzroUriError::InvalidQuery(_))
        ));
    }
}
