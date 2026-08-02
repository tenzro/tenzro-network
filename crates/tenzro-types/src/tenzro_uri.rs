//! `tenzro://` URI scheme — unified content + node addressing.
//!
//! All Tenzro-native URIs use the `tenzro://` scheme. The path prefix
//! dispatches to the right resolver (blobs, nodes, DIDs, models, gradients,
//! sealed shards, manifests, agent memory, receipts). Transport details
//! (iroh-blobs, libp2p, etc.) are deliberately hidden behind the scheme so
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
//! tenzro://gradient/<run-id>/<round>/<blake3-hex>       — outer-gradient artifact (Tenzro Train)
//! tenzro://shard/<manifest-hash>/<envelope-hash>        — sealed shard (Confidential tier)
//! tenzro://manifest/<manifest-hash>                     — sealed-dataset manifest
//! tenzro://memory/<agent-did>/<record-uuid>             — agent-memory archived record
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
    /// `tenzro://node/<node-id>` — dial a node by its (iroh / libp2p) public key.
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
    /// `tenzro://gradient/<run-id>/<round>/<blake3-hex>` — Tenzro Train
    /// outer-gradient artifact.
    Gradient {
        /// Training run identifier.
        run_id: String,
        /// Sync round number.
        round: u64,
        /// 64-character lowercase hex BLAKE3 hash of the gradient blob.
        hash: String,
    },
    /// `tenzro://shard/<manifest-hash>/<envelope-hash>` — Confidential-tier
    /// sealed shard. `manifest_hash` binds it to its parent manifest.
    Shard {
        /// 64-character lowercase hex hash of the parent sealed manifest.
        manifest_hash: String,
        /// 64-character lowercase hex hash of the sealed envelope.
        envelope_hash: String,
    },
    /// `tenzro://manifest/<manifest-hash>` — sealed-dataset manifest. The
    /// signed manifest itself is distributed on the `tenzro/training`
    /// libp2p gossipsub topic (Phase B2, #217); this URI is the durable
    /// content-addressed identifier that pins the binding.
    Manifest {
        /// 64-character lowercase hex hash of the manifest.
        manifest_hash: String,
    },
    /// `tenzro://memory/<agent-did>/<record-uuid>` — agent-memory archived
    /// record (DA pointer).
    Memory {
        /// Owning agent's DID (`did:tenzro:machine:...`).
        agent_did: String,
        /// UUID v4 of the memory record.
        record_uuid: String,
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
    #[error(
        "unknown path prefix `{0}` — expected one of blob, node, did, model, gradient, shard, manifest, memory, receipt"
    )]
    UnknownPrefix(String),
    #[error("missing required segment in `{prefix}` URI: {detail}")]
    MissingSegment {
        prefix: &'static str,
        detail: &'static str,
    },
    #[error("invalid BLAKE3 hash `{0}` — expected 64 lowercase hex characters")]
    InvalidHash(String),
    #[error("invalid round number `{0}` in gradient URI: {1}")]
    InvalidRound(String, std::num::ParseIntError),
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
            "gradient" => {
                let run_id = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "gradient",
                    detail: "run-id",
                })?;
                let round_str = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "gradient",
                    detail: "round",
                })?;
                let round: u64 = round_str
                    .parse()
                    .map_err(|e| TenzroUriError::InvalidRound(round_str.to_string(), e))?;
                let hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "gradient",
                    detail: "hash",
                })?;
                validate_blake3_hex(hash)?;
                Ok(TenzroUri::Gradient {
                    run_id: run_id.to_string(),
                    round,
                    hash: hash.to_string(),
                })
            }
            "shard" => {
                let manifest_hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "shard",
                    detail: "manifest-hash",
                })?;
                let envelope_hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "shard",
                    detail: "envelope-hash",
                })?;
                validate_blake3_hex(manifest_hash)?;
                validate_blake3_hex(envelope_hash)?;
                Ok(TenzroUri::Shard {
                    manifest_hash: manifest_hash.to_string(),
                    envelope_hash: envelope_hash.to_string(),
                })
            }
            "manifest" => {
                let manifest_hash = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "manifest",
                    detail: "manifest-hash",
                })?;
                validate_blake3_hex(manifest_hash)?;
                Ok(TenzroUri::Manifest {
                    manifest_hash: manifest_hash.to_string(),
                })
            }
            "memory" => {
                let agent_did = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "memory",
                    detail: "agent-did",
                })?;
                let record_uuid = segments.next().ok_or(TenzroUriError::MissingSegment {
                    prefix: "memory",
                    detail: "record-uuid",
                })?;
                Ok(TenzroUri::Memory {
                    agent_did: agent_did.to_string(),
                    record_uuid: record_uuid.to_string(),
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
            TenzroUri::Gradient {
                run_id,
                round,
                hash,
            } => {
                write!(f, "tenzro://gradient/{run_id}/{round}/{hash}")
            }
            TenzroUri::Shard {
                manifest_hash,
                envelope_hash,
            } => write!(f, "tenzro://shard/{manifest_hash}/{envelope_hash}"),
            TenzroUri::Manifest { manifest_hash } => write!(f, "tenzro://manifest/{manifest_hash}"),
            TenzroUri::Memory {
                agent_did,
                record_uuid,
            } => {
                write!(f, "tenzro://memory/{agent_did}/{record_uuid}")
            }
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
    fn parses_gradient() {
        roundtrip(&format!("tenzro://gradient/run42/7/{ZERO_HASH}"));
    }

    #[test]
    fn parses_shard() {
        roundtrip(&format!("tenzro://shard/{ZERO_HASH}/{ZERO_HASH}"));
    }

    #[test]
    fn parses_manifest() {
        roundtrip(&format!("tenzro://manifest/{ZERO_HASH}"));
    }

    #[test]
    fn parses_memory() {
        roundtrip(
            "tenzro://memory/did:tenzro:machine:agent42/01234567-89ab-cdef-0123-456789abcdef",
        );
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
