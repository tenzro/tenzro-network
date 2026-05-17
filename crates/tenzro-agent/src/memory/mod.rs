//! Agent memory tier (Phase B).
//!
//! Persistent, queryable memory for Tenzro agents. Every memory record is
//! double-indexed:
//!
//!   * a Lance-backed vector store ([`vector_backend::LanceVectorBackend`])
//!     for semantic kNN recall over embeddings produced by
//!     [`tenzro_model::TextEmbeddingRuntime`];
//!   * a Tantivy BM25 inverted index ([`text_backend::TantivyTextBackend`])
//!     for lexical recall.
//!
//! [`manager::MemoryManager`] composes the two backends and offers a
//! `recall()` API that may run vector-only, text-only, or hybrid (Reciprocal
//! Rank Fusion with `k=60`). It also wires a [`tenzro_storage::da::DaBackend`]
//! so cold records can be archived off-tier — the on-tier row keeps a
//! [`tenzro_storage::DaPointer`] so the payload remains addressable but stops
//! occupying hot search budget.
//!
//! Wire-up flows through [`crate::AgentRuntime::with_memory_manager`] at node
//! start (`init_ai_infrastructure` mounts the manager rooted at
//! `{data_dir}/agent_memory/`).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tenzro_storage::da::DaPointer;
use uuid::Uuid;

pub mod manager;
pub mod text_backend;
pub mod vector_backend;

pub use manager::{MemoryManager, MemoryManagerConfig};
pub use text_backend::TantivyTextBackend;
pub use vector_backend::LanceVectorBackend;

/// Provenance of a memory record.
///
/// `Granted` — the record was given to the agent by an external party
/// (controller, peer, tool); the agent did not author it.
/// `Recalled` — the record materialized from a prior `recall()` (used to
/// register strong matches as durable memory rather than transient context).
/// `SelfNoted` — the agent itself authored the record (e.g. a self-reflection
/// note during a planning loop).
/// `Archived` — the record has been moved to a [`DaBackend`]; only the
/// commitment + pointer remain hot-indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryKind {
    Granted,
    Recalled,
    SelfNoted,
    Archived,
}

impl MemoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryKind::Granted => "granted",
            MemoryKind::Recalled => "recalled",
            MemoryKind::SelfNoted => "self_noted",
            MemoryKind::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "granted" => Some(MemoryKind::Granted),
            "recalled" => Some(MemoryKind::Recalled),
            "self_noted" | "selfnoted" | "self-noted" => Some(MemoryKind::SelfNoted),
            "archived" => Some(MemoryKind::Archived),
            _ => None,
        }
    }
}

/// Origin of a memory record's text.
///
/// `Controller` — the human / DID that controls this agent.
/// `Tool` — an MCP tool, A2A peer agent invocation, or built-in skill.
/// `Peer` — another autonomous agent (A2A counterparty).
/// `Self_` — the agent itself (matches `MemoryKind::SelfNoted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemorySource {
    Controller,
    Tool,
    Peer,
    /// Trailing underscore avoids the `Self` keyword.
    Self_,
}

impl MemorySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemorySource::Controller => "controller",
            MemorySource::Tool => "tool",
            MemorySource::Peer => "peer",
            MemorySource::Self_ => "self",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "controller" => Some(MemorySource::Controller),
            "tool" => Some(MemorySource::Tool),
            "peer" => Some(MemorySource::Peer),
            "self" | "self_" => Some(MemorySource::Self_),
            _ => None,
        }
    }
}

/// A single memory row owned by an agent. Persisted in both Lance (with the
/// embedding column) and Tantivy (with the text column tokenized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// UUID v4. Stable across vector + text backends so RRF can dedup.
    pub id: String,
    /// The DID of the agent that owns the memory.
    pub agent_did: String,
    /// Creation timestamp in milliseconds since the Unix epoch.
    pub created_at_ms: i64,
    pub kind: MemoryKind,
    pub source: MemorySource,
    /// Free-form text payload — what the agent actually remembers.
    pub text: String,
    /// Embedding produced by [`tenzro_model::TextEmbeddingRuntime`]. `None`
    /// means the manager has not vector-indexed this row (recall by text only).
    pub embedding: Option<Vec<f32>>,
    /// Free-form metadata. Persisted as a JSON string in Tantivy and as the
    /// raw [`serde_json::Value`] (round-tripped via JSON) in Lance.
    pub metadata: serde_json::Value,
    /// Set once the record has been moved to a DA backend. The on-tier row
    /// keeps the pointer; callers fetch the bulk payload via the manager's
    /// configured [`tenzro_storage::da::DaBackend::fetch`] when needed.
    pub da_pointer: Option<DaPointer>,
}

impl MemoryRecord {
    /// Construct a hot record (no DA pointer). The id is a fresh UUID v4 and
    /// `created_at_ms` is set to wall-clock now.
    pub fn new(
        agent_did: impl Into<String>,
        kind: MemoryKind,
        source: MemorySource,
        text: impl Into<String>,
        embedding: Option<Vec<f32>>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent_did: agent_did.into(),
            created_at_ms: Utc::now().timestamp_millis(),
            kind,
            source,
            text: text.into(),
            embedding,
            metadata,
            da_pointer: None,
        }
    }
}

/// Filter clause used by recall and listing. Empty filter ⇒ scope to a single
/// agent only.
#[derive(Debug, Clone, Default)]
pub struct MemoryFilter {
    /// Required: scopes results to a single agent.
    pub agent_did: String,
    /// Optional: restrict to one kind.
    pub kind: Option<MemoryKind>,
    /// Optional: drop rows older than this (ms-since-epoch, inclusive).
    pub min_created_at_ms: Option<i64>,
    /// Optional: drop rows newer than this (ms-since-epoch, inclusive).
    pub max_created_at_ms: Option<i64>,
}

impl MemoryFilter {
    pub fn for_agent(agent_did: impl Into<String>) -> Self {
        Self {
            agent_did: agent_did.into(),
            kind: None,
            min_created_at_ms: None,
            max_created_at_ms: None,
        }
    }
}

bitflags::bitflags! {
    /// Which backends should `recall()` consult. `HYBRID` is `VECTOR | TEXT`
    /// and triggers Reciprocal Rank Fusion at `k=60`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SearchModes: u32 {
        const VECTOR = 0b0000_0001;
        const TEXT   = 0b0000_0010;
        const HYBRID = Self::VECTOR.bits() | Self::TEXT.bits();
    }
}

impl Default for SearchModes {
    fn default() -> Self {
        Self::HYBRID
    }
}

/// Errors surfaced by the memory tier.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("Vector backend error: {0}")]
    Vector(String),
    #[error("Text backend error: {0}")]
    Text(String),
    #[error("DA backend error: {0}")]
    Da(String),
    /// Returned by `MemoryManager::grant` when the manager was constructed
    /// without a [`tenzro_model::TextEmbeddingRuntime`] / model_id pair, or
    /// when the requested embedding model is not loaded. Callers should
    /// either load a text-embedding model first via
    /// `tenzro_loadTextEmbeddingModel` or omit vector indexing by skipping
    /// `MemoryManager::grant` and calling `text_backend().insert()` directly.
    #[error("No text embedder configured: {0}")]
    NoEmbedder(String),
    #[error("Record not found: {0}")]
    NotFound(String),
    #[error("Embedding dimension mismatch: expected {expected}, got {actual}")]
    DimMismatch { expected: usize, actual: usize },
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Serialization error: {0}")]
    Serde(String),
}

pub type Result<T> = std::result::Result<T, MemoryError>;

impl From<serde_json::Error> for MemoryError {
    fn from(e: serde_json::Error) -> Self {
        MemoryError::Serde(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_kind_round_trip() {
        for k in [
            MemoryKind::Granted,
            MemoryKind::Recalled,
            MemoryKind::SelfNoted,
            MemoryKind::Archived,
        ] {
            assert_eq!(MemoryKind::parse(k.as_str()), Some(k));
        }
    }

    #[test]
    fn memory_source_round_trip() {
        for s in [
            MemorySource::Controller,
            MemorySource::Tool,
            MemorySource::Peer,
            MemorySource::Self_,
        ] {
            assert_eq!(MemorySource::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn search_modes_hybrid_is_or() {
        assert!(SearchModes::HYBRID.contains(SearchModes::VECTOR));
        assert!(SearchModes::HYBRID.contains(SearchModes::TEXT));
    }

    #[test]
    fn record_new_has_uuid_and_now() {
        let r = MemoryRecord::new(
            "did:tenzro:machine:abc",
            MemoryKind::Granted,
            MemorySource::Controller,
            "hello",
            None,
            serde_json::json!({"k": "v"}),
        );
        assert_eq!(r.text, "hello");
        assert!(r.created_at_ms > 0);
        // UUID v4 is 36 chars with hyphens.
        assert_eq!(r.id.len(), 36);
        assert!(r.embedding.is_none());
        assert!(r.da_pointer.is_none());
    }
}
