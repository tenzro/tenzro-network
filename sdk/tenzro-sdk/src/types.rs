//! Core types for the Tenzro SDK
//!
//! Lightweight type definitions used across the SDK. These are self-contained
//! versions of the types from `tenzro-types` so the SDK can be published
//! standalone on crates.io without workspace path dependencies.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// A 32-byte on-chain address.
///
/// Serialises to / deserialises from a `"0x..."` hex string for JSON-RPC
/// compatibility.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Creates a new Address from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the zero address (all bytes `0x00`).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates an Address from a hex string (with or without `0x` prefix).
    ///
    /// Returns `None` if the string is not valid hex or is not exactly 32 bytes.
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(stripped).ok()?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(Self(arr))
        } else if bytes.len() == 20 {
            // EVM-style 20-byte address — widened left-aligned (20 significant
            // bytes then a zero tail), which is the key the node's token ledger
            // is written under. Right-aligning here produced an address that
            // serialized to a perfectly valid 64-hex string the node had no
            // entry for, so balances read 0 and transfers went nowhere
            // recoverable.
            let mut arr = [0u8; 32];
            arr[..20].copy_from_slice(&bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Returns the address as a `0x`-prefixed hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Address::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid address hex"))
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zero()
    }
}

// ---------------------------------------------------------------------------
// ModelInfo
// ---------------------------------------------------------------------------

/// Information about an AI model registered on Tenzro Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Unique model identifier (`id` in `tenzro_listModels`)
    #[serde(default, alias = "id")]
    pub model_id: String,
    /// Model name
    #[serde(default)]
    pub name: String,
    /// Model version
    #[serde(default)]
    pub version: String,
    /// Model description
    #[serde(default)]
    pub description: String,
    /// Model modality (e.g., "text", "image", "audio")
    #[serde(default)]
    pub modality: serde_json::Value,
    /// Model architecture
    #[serde(default)]
    pub architecture: String,
    /// Model provider address
    #[serde(default)]
    pub provider: serde_json::Value,
    /// Model hash for verification
    #[serde(default)]
    pub model_hash: serde_json::Value,
    /// Model parameters
    #[serde(default)]
    pub parameters: serde_json::Value,
    /// Model pricing
    #[serde(default)]
    pub pricing: serde_json::Value,
    /// Model status
    #[serde(default)]
    pub status: serde_json::Value,
    /// Model metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// Whether the model accepts image input (vision-language). When true,
    /// `mmproj` carries the projector filename llama.cpp loads via `--mmproj`.
    #[serde(default)]
    pub multimodal: bool,
    /// Multimodal projector filename for vision-capable models. `None` for
    /// text-only models. Populated from `tenzro_modelMetadata`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmproj: Option<MmprojSpec>,
    /// Catalog-recommended serving profile (sampler defaults, chat-template
    /// requirement, reasoning default). `None` when the source response
    /// didn't include it (e.g. a plain `tenzro_listModels` row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving: Option<ServingProfile>,
    /// BLAKE3 content hash of the model weights (32 bytes). Set once weights
    /// are content-addressed; a fetcher verifies downloaded bytes against this
    /// before load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<[u8; 32]>,
    /// Content-addressed locator for the weights, e.g.
    /// `tenzro://model/<id>@<blake3-hex>` or `tenzro://blob/<blake3-hex>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenzro_uri: Option<String>,
    /// Known peer locators for the weights, tried before falling back to the
    /// origin (e.g. HuggingFace Hub).
    #[serde(default)]
    pub peer_hints: Vec<PeerHintRecord>,
}

/// A peer locator for content-addressed model weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHintRecord {
    /// Content-addressed locator (`tenzro://blob/<hash>` or
    /// `tenzro://model/<id>@<hash>`).
    #[serde(default)]
    pub tenzro_uri: String,
    /// Optional SHA-256 of the referenced bytes (64-hex), used as a
    /// belt-and-braces check on top of the transport's BLAKE3 verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_hex: Option<String>,
}

/// Multimodal projector descriptor for a vision-capable model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmprojSpec {
    /// Projector filename within the model's HF repo (e.g. `mmproj-F16.gguf`).
    #[serde(default)]
    pub filename: String,
}

/// Catalog-recommended serving configuration for a model. Mirrors the
/// `serving` object returned by `tenzro_modelMetadata`. These are the
/// model author's recommended defaults; per-request parameters override them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServingProfile {
    /// Sampling temperature.
    #[serde(default)]
    pub temperature: f32,
    /// Nucleus (top-p) sampling cutoff.
    #[serde(default)]
    pub top_p: f32,
    /// Top-k cutoff (0 = disabled).
    #[serde(default)]
    pub top_k: u32,
    /// Min-p cutoff (0.0 = disabled).
    #[serde(default)]
    pub min_p: f32,
    /// Presence penalty (0.0 = disabled).
    #[serde(default)]
    pub presence_penalty: f32,
    /// Whether the chat template (`--jinja`) is required for correct output.
    #[serde(default)]
    pub jinja_required: bool,
    /// Whether reasoning/thinking mode is on by default for this model.
    #[serde(default)]
    pub reasoning_default: bool,
}

// ---------------------------------------------------------------------------
// AgentIdentity
// ---------------------------------------------------------------------------

/// Identity of an AI agent on Tenzro Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Unique agent identifier
    #[serde(default)]
    pub agent_id: String,
    /// Agent on-chain address
    #[serde(default)]
    pub address: serde_json::Value,
    /// Agent name
    #[serde(default)]
    pub name: String,
    /// Agent version
    #[serde(default)]
    pub version: String,
    /// Agent creator/owner address
    #[serde(default)]
    pub creator: serde_json::Value,
}

/// Reads a `u128` the node wrote as a JSON number below `u64::MAX` and as a
/// decimal string above it, and writes it back the same way.
pub(crate) mod u128_wire {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        if *value <= u64::MAX as u128 {
            serializer.serialize_u64(*value as u64)
        } else {
            serializer.serialize_str(&value.to_string())
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        struct U128Visitor;

        impl<'de> Visitor<'de> for U128Visitor {
            type Value = u128;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a non-negative integer or decimal string fitting in u128")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<u128, E> {
                Ok(v as u128)
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<u128, E> {
                Ok(v)
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<u128, E> {
                u128::try_from(v).map_err(|_| E::custom(format!("negative integer {v}")))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<u128, E> {
                s.parse::<u128>()
                    .map_err(|e| E::custom(format!("invalid u128 string {s:?}: {e}")))
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<u128, E> {
                self.visit_str(&s)
            }
        }

        deserializer.deserialize_any(U128Visitor)
    }
}

/// Where a list read from the event log starts and how much it returns.
/// Every field is optional; the default reads the first page from the oldest
/// held height.
#[derive(Debug, Clone, Default)]
pub struct PageRequest {
    /// Resume after this cursor (`height:tx_index:event_index`), as the
    /// previous page returned it.
    pub from_cursor: Option<String>,
    /// Start at this height instead. Not with `from_cursor`.
    pub from_height: Option<u64>,
    /// Stop at this cursor, inclusive.
    pub to_cursor: Option<String>,
    /// Most entries.
    pub limit: Option<u64>,
}

impl PageRequest {
    /// The page after `cursor`.
    pub fn after(cursor: impl Into<String>) -> Self {
        Self {
            from_cursor: Some(cursor.into()),
            ..Self::default()
        }
    }

    /// The page as JSON-RPC params: only the fields set.
    pub fn to_params(&self) -> serde_json::Value {
        let mut p = serde_json::Map::new();
        if let Some(c) = &self.from_cursor {
            p.insert("from_cursor".into(), c.clone().into());
        }
        if let Some(h) = self.from_height {
            p.insert("from_height".into(), h.into());
        }
        if let Some(c) = &self.to_cursor {
            p.insert("to_cursor".into(), c.clone().into());
        }
        if let Some(l) = self.limit {
            p.insert("limit".into(), l.into());
        }
        serde_json::Value::Object(p)
    }
}
