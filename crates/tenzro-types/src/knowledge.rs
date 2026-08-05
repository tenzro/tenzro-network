//! Knowledge registry types for Tenzro Network.
//!
//! Operator-curated, queryable data resources: vector DBs, RAG
//! indices, document corpora, indexed historical datasets, real-time
//! data feeds (prices, oracles, indexers, weather, news, regulatory
//! filings, social signals), embedding stores. Discoverable via
//! `tenzro_listKnowledge` / `tenzro_searchKnowledge`, invokable via
//! `tenzro_useKnowledge`, settled in TNZO with the same commission
//! split as tools (5% to treasury, 95% to operator's creator_wallet).
//!
//! Distinguished from MCPs in that an MCP is a *protocol* (the
//! invocation method) and a knowledge resource is a *data resource*
//! (what the operator brokers). A datasource MCP IS a knowledge
//! resource — it can register under both registries. The
//! distinction is intent: registering as a knowledge resource
//! signals "this is queryable data with semantic discovery
//! metadata"; registering as a tool signals "this is an actionable
//! capability."

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// What kind of knowledge resource this is. Drives the suggested
/// `params` schema and lets the discovery surface filter by purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeKind {
    /// Vector index — semantic similarity search over an embedded
    /// corpus. Params: `{ query: string, top_k: u32, filter?: object }`.
    VectorIndex,
    /// Full-text document corpus (BM25 / Tantivy / Lucene). Params:
    /// `{ query: string, top_k: u32, filter?: object }`.
    DocumentCorpus,
    /// Pre-indexed historical dataset queryable by structured filter
    /// (SQL-ish / GraphQL / REST). Params: caller-defined.
    IndexedDataset,
    /// Real-time data feed (price feed, oracle, market data, news
    /// stream). Params: `{ subject: string, window?: object }`.
    Feed,
    /// Embedding store for retrieval-augmented generation. Params:
    /// `{ query: string | embedding: [f32], top_k: u32 }`.
    EmbeddingStore,
    /// Catch-all for resource shapes not yet captured. The discovery
    /// surface still routes by capability_tags; the kind is advisory.
    Other,
}

impl KnowledgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            KnowledgeKind::VectorIndex => "vector_index",
            KnowledgeKind::DocumentCorpus => "document_corpus",
            KnowledgeKind::IndexedDataset => "indexed_dataset",
            KnowledgeKind::Feed => "feed",
            KnowledgeKind::EmbeddingStore => "embedding_store",
            KnowledgeKind::Other => "other",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "vector_index" => Some(KnowledgeKind::VectorIndex),
            "document_corpus" => Some(KnowledgeKind::DocumentCorpus),
            "indexed_dataset" => Some(KnowledgeKind::IndexedDataset),
            "feed" => Some(KnowledgeKind::Feed),
            "embedding_store" => Some(KnowledgeKind::EmbeddingStore),
            "other" => Some(KnowledgeKind::Other),
            _ => None,
        }
    }
}

/// Status of a knowledge resource. Mirrors `ToolStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeStatus {
    #[default]
    Active,
    Inactive,
    Deprecated,
}

/// A knowledge resource published to the Tenzro Network knowledge
/// registry. Operators register resources they broker; tenants
/// discover via `tenzro_listKnowledge` and invoke via
/// `tenzro_useKnowledge`. The protocol settles TNZO via the same
/// commission split as the tools registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeRecord {
    /// Unique resource id (UUID v4).
    pub knowledge_id: String,

    /// Human-readable name (e.g. "us-equities-bloomberg-feed",
    /// "openai-text-embedding-3-large", "kbv2-pinecone-rag").
    pub name: String,

    /// Semantic version.
    pub version: String,

    /// What kind of resource this is.
    pub kind: KnowledgeKind,

    /// Invocation endpoint. URL for HTTP-style resources, opaque
    /// reference for stdio / MCP-tunnelled resources (the underlying
    /// transport is resolved via the corresponding tool entry when
    /// the operator co-registers).
    pub endpoint: String,

    /// Free-text description shown in the discovery surface.
    pub description: String,

    /// Capability tags for discovery filtering. E.g. `["prices",
    /// "us-equities", "real-time"]`, `["rag", "legal", "us-case-law"]`,
    /// `["embeddings", "text", "1024-dim"]`.
    pub capabilities: Vec<String>,

    /// Free-text category for the discovery UI. E.g. "finance",
    /// "compliance", "scientific", "code", "ml".
    pub category: String,

    /// DID of the operator who registered this resource.
    pub creator_did: Option<String>,

    /// Payout wallet for the creator's share of paid invocations.
    /// Required when `price_per_call > 0`.
    pub creator_wallet: Option<Address>,

    /// TNZO atto-token cost per invocation. The protocol takes 5% as
    /// network commission; the remaining 95% goes to `creator_wallet`.
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_per_call: u128,

    /// Resource status.
    pub status: KnowledgeStatus,

    /// Unix timestamp (seconds) at registration.
    pub created_at: u64,

    /// Monotonic invocation counter.
    pub invocation_count: u64,

    /// Last liveness heartbeat (seconds).
    #[serde(default = "default_last_seen")]
    pub last_seen_at: u64,

    /// JSON-Schema (or schema-like description) of the expected
    /// invocation params. The discovery surface returns this verbatim
    /// so the caller (LLM agent or developer) can construct a valid
    /// invocation without out-of-band docs. Optional — when `None`,
    /// the caller infers from `kind`.
    #[serde(default)]
    pub params_schema: Option<serde_json::Value>,

    /// JSON-Schema (or schema-like description) of the response shape
    /// returned by an invocation. Same purpose as `params_schema`.
    #[serde(default)]
    pub response_schema: Option<serde_json::Value>,

    /// Optional subject-level access list. When `Some(vec)`, only API
    /// keys whose `subject` appears in `vec` are permitted to invoke
    /// this resource. `None` means the resource is open to any key
    /// allowed by `AgentDelegation.allowed_knowledge`.
    #[serde(default)]
    pub allowed_to_subjects: Option<Vec<String>>,

    /// When `true`, this knowledge resource is backed by an
    /// underlying tool/MCP entry (the operator co-registered both).
    /// The `tool_id` references that tool. At `tenzro_useKnowledge`
    /// time, the node delegates dispatch through the tool pathway.
    /// When `false`, the endpoint is invoked directly via HTTP POST.
    #[serde(default)]
    pub backing_tool_id: Option<String>,
}

fn default_last_seen() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl KnowledgeRecord {
    pub fn new(
        name: String,
        version: String,
        kind: KnowledgeKind,
        endpoint: String,
        description: String,
        category: String,
    ) -> Self {
        let knowledge_id = uuid::Uuid::new_v4().to_string();
        let created_at = default_last_seen();
        Self {
            knowledge_id,
            name,
            version,
            kind,
            endpoint,
            description,
            capabilities: Vec::new(),
            category,
            creator_did: None,
            creator_wallet: None,
            price_per_call: 0,
            status: KnowledgeStatus::Active,
            created_at,
            invocation_count: 0,
            last_seen_at: created_at,
            params_schema: None,
            response_schema: None,
            allowed_to_subjects: None,
            backing_tool_id: None,
        }
    }

    pub fn is_paid(&self) -> bool {
        self.price_per_call > 0
    }

    pub fn validate_for_registration(&self) -> Result<(), &'static str> {
        if self.is_paid() && self.creator_wallet.is_none() {
            return Err("Paid knowledge resource requires a creator_wallet");
        }
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.status == KnowledgeStatus::Active
    }

    pub fn touch(&mut self) {
        self.last_seen_at = default_last_seen();
    }

    pub fn is_subject_allowed(&self, subject: Option<&str>) -> bool {
        match (&self.allowed_to_subjects, subject) {
            (None, _) => true,
            (Some(list), Some(s)) => list.iter().any(|x| x == s),
            (Some(_), None) => false,
        }
    }
}

/// Filter shape for list / search RPCs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeFilter {
    pub kind: Option<String>,
    pub category: Option<String>,
    pub status: Option<String>,
    pub creator_did: Option<String>,
    /// Free-text query — matches name, description, and capabilities.
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Result of a knowledge invocation. Same shape as
/// `ToolInvocationResult` so clients can dispatch on the
/// invocation_id without knowing which registry served the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeInvocationResult {
    pub knowledge_id: String,
    pub invocation_id: String,
    pub output: serde_json::Value,
    pub settlement_tx: Option<String>,
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount_paid: u128,
    pub completed_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_record_new() {
        let r = KnowledgeRecord::new(
            "test-feed".to_string(),
            "1.0.0".to_string(),
            KnowledgeKind::Feed,
            "https://feed.example.com/api/v1/prices".to_string(),
            "Live SOL/USD price feed".to_string(),
            "finance".to_string(),
        );
        assert!(!r.knowledge_id.is_empty());
        assert_eq!(r.kind, KnowledgeKind::Feed);
        assert!(r.is_available());
        assert_eq!(r.price_per_call, 0);
        assert!(!r.is_paid());
    }

    #[test]
    fn paid_without_wallet_fails() {
        let mut r = KnowledgeRecord::new(
            "p".to_string(),
            "1".to_string(),
            KnowledgeKind::VectorIndex,
            "e".to_string(),
            "d".to_string(),
            "c".to_string(),
        );
        r.price_per_call = 100;
        assert!(r.validate_for_registration().is_err());
    }

    #[test]
    fn subject_allowlist_enforcement() {
        let mut r = KnowledgeRecord::new(
            "n".to_string(),
            "1".to_string(),
            KnowledgeKind::Feed,
            "e".to_string(),
            "d".to_string(),
            "c".to_string(),
        );
        // No allow-list = open.
        assert!(r.is_subject_allowed(Some("anyone")));
        assert!(r.is_subject_allowed(None));
        // With allow-list = closed to listed subjects only.
        r.allowed_to_subjects = Some(vec!["alice".to_string()]);
        assert!(r.is_subject_allowed(Some("alice")));
        assert!(!r.is_subject_allowed(Some("bob")));
        assert!(!r.is_subject_allowed(None));
    }

    #[test]
    fn kind_str_roundtrip() {
        for k in [
            KnowledgeKind::VectorIndex,
            KnowledgeKind::DocumentCorpus,
            KnowledgeKind::IndexedDataset,
            KnowledgeKind::Feed,
            KnowledgeKind::EmbeddingStore,
            KnowledgeKind::Other,
        ] {
            assert_eq!(KnowledgeKind::parse_str(k.as_str()), Some(k));
        }
        assert_eq!(KnowledgeKind::parse_str("nonsense"), None);
    }
}
