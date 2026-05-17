//! Manager that composes the Lance vector backend, the Tantivy text
//! backend, and an optional [`tenzro_storage::da::DaBackend`] for archival.
//!
//! The manager is the only public surface most callers need. It exposes:
//!
//! * [`MemoryManager::grant`] — embed via [`tenzro_model::TextEmbeddingRuntime`],
//!   write into both backends so the record is recallable by either kNN or
//!   BM25.
//! * [`MemoryManager::recall`] — vector-only / text-only / hybrid search. Hybrid
//!   merges with Reciprocal Rank Fusion at `k=60`.
//! * [`MemoryManager::archive`] — push the canonical payload to the configured
//!   DA backend, replace the on-tier rows with `kind = Archived` carrying only
//!   the [`DaPointer`] in `da_pointer`. Hot search budget is freed; the bulk
//!   payload is fetched on demand via the manager's DA handle.
//! * [`MemoryManager::list`] — paginated newest-first walk for the listing RPC.
//!
//! The manager intentionally does not own the runtime that produced the
//! embeddings — callers attach a `TextEmbeddingRuntime` + the model id to use
//! at construction time. Without one, [`MemoryManager::grant`] returns
//! [`MemoryError::NoEmbedder`] and callers are expected to insert via the
//! text backend directly.

use std::collections::HashMap;
use std::sync::Arc;

use tenzro_model::text_embedding_runtime::{TextEmbedConfig, TextEmbeddingRuntime};
use tenzro_storage::da::{DaBackend, ReceiptKind};

use super::{
    text_backend::TantivyTextBackend, vector_backend::LanceVectorBackend, MemoryError,
    MemoryFilter, MemoryKind, MemoryRecord, MemorySource, Result, SearchModes,
};

/// Reciprocal Rank Fusion smoothing constant. The classic value (k=60) from
/// Cormack et al. balances vector and lexical recall in hybrid mode.
const RRF_K: f32 = 60.0;

/// Configuration for [`MemoryManager`].
#[derive(Clone)]
pub struct MemoryManagerConfig {
    /// Embedding model id resolved against the attached
    /// [`TextEmbeddingRuntime`]. `None` means grant() will return
    /// [`MemoryError::NoEmbedder`].
    pub embedder_model_id: Option<String>,
    /// L2-normalize embeddings before storage. Recommended on (matches the
    /// cosine assumption Lance uses for `nearest_to`).
    pub normalize_embeddings: bool,
    /// Optional Matryoshka truncation dim; passes through to the runtime.
    pub requested_dim: Option<u32>,
    /// DA namespace bytes used by [`MemoryManager::archive`]. Defaults to the
    /// ASCII bytes of `"tenzro/agent_memory"`.
    pub da_namespace: Vec<u8>,
}

impl Default for MemoryManagerConfig {
    fn default() -> Self {
        Self {
            embedder_model_id: None,
            normalize_embeddings: true,
            requested_dim: None,
            da_namespace: b"tenzro/agent_memory".to_vec(),
        }
    }
}

/// The agent memory manager.
pub struct MemoryManager {
    vector: Arc<LanceVectorBackend>,
    text: Arc<TantivyTextBackend>,
    da: Arc<dyn DaBackend>,
    embedder: Option<Arc<TextEmbeddingRuntime>>,
    config: MemoryManagerConfig,
}

impl MemoryManager {
    pub fn new(
        vector: Arc<LanceVectorBackend>,
        text: Arc<TantivyTextBackend>,
        da: Arc<dyn DaBackend>,
        embedder: Option<Arc<TextEmbeddingRuntime>>,
        config: MemoryManagerConfig,
    ) -> Self {
        Self {
            vector,
            text,
            da,
            embedder,
            config,
        }
    }

    pub fn vector_backend(&self) -> &LanceVectorBackend {
        &self.vector
    }

    pub fn text_backend(&self) -> &TantivyTextBackend {
        &self.text
    }

    pub fn config(&self) -> &MemoryManagerConfig {
        &self.config
    }

    /// Grant a memory to an agent. Embeds the text via the configured
    /// [`TextEmbeddingRuntime`]; if no runtime / model id is configured, the
    /// caller must use the backends directly.
    pub async fn grant(
        &self,
        agent_did: impl Into<String>,
        kind: MemoryKind,
        source: MemorySource,
        text: impl Into<String>,
        metadata: serde_json::Value,
    ) -> Result<MemoryRecord> {
        let text = text.into();
        let embedding = self.embed(&text).await?;
        let mut record = MemoryRecord::new(agent_did, kind, source, text, Some(embedding), metadata);
        self.vector.insert(&record).await?;
        self.text.insert(&record)?;
        // The text backend strips the embedding when reading back; keep the
        // hot-path return value carrying it for the caller.
        if record.embedding.is_none() {
            record.embedding = None;
        }
        Ok(record)
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let runtime = self
            .embedder
            .as_ref()
            .ok_or_else(|| MemoryError::NoEmbedder("no TextEmbeddingRuntime attached".into()))?;
        let model_id = self
            .config
            .embedder_model_id
            .as_deref()
            .ok_or_else(|| MemoryError::NoEmbedder("no embedder_model_id configured".into()))?;
        let cfg = TextEmbedConfig {
            requested_dim: self.config.requested_dim,
            normalize: self.config.normalize_embeddings,
        };
        let res = runtime
            .embed(model_id, vec![text.to_string()], cfg)
            .await
            .map_err(|e| MemoryError::NoEmbedder(format!("embed via {}: {}", model_id, e)))?;
        let mut emb = res
            .embeddings
            .into_iter()
            .next()
            .ok_or_else(|| MemoryError::NoEmbedder("embedder returned 0 vectors".into()))?;
        let want = self.vector.embedding_dim();
        if emb.len() != want {
            // Best-effort tail-truncate when the runtime returns the native dim
            // but the table was created with a Matryoshka-truncated width.
            if emb.len() > want {
                emb.truncate(want);
            } else {
                return Err(MemoryError::DimMismatch {
                    expected: want,
                    actual: emb.len(),
                });
            }
        }
        Ok(emb)
    }

    /// Recall memories for an agent. `modes` selects the backend(s):
    /// `VECTOR`, `TEXT`, or `HYBRID` (RRF k=60).
    pub async fn recall(
        &self,
        agent_did: impl Into<String>,
        query: impl Into<String>,
        k: usize,
        modes: SearchModes,
    ) -> Result<Vec<MemoryRecord>> {
        let agent_did = agent_did.into();
        let query = query.into();
        let filter = MemoryFilter::for_agent(&agent_did);
        let want_vector = modes.contains(SearchModes::VECTOR);
        let want_text = modes.contains(SearchModes::TEXT);
        if !want_vector && !want_text {
            return Err(MemoryError::InvalidArgument(
                "SearchModes must include VECTOR, TEXT, or both".into(),
            ));
        }

        let vector_hits = if want_vector {
            // Best-effort embed; if no embedder is configured, degrade to text-only.
            match self.embed(&query).await {
                Ok(q) => self.vector.search_by_vector(&q, k, &filter).await?,
                Err(MemoryError::NoEmbedder(_)) if want_text => Vec::new(),
                Err(e) => return Err(e),
            }
        } else {
            Vec::new()
        };
        let text_hits = if want_text {
            self.text.search_by_text(&query, k, &filter)?
        } else {
            Vec::new()
        };

        if want_vector && want_text {
            Ok(rrf_merge(vector_hits, text_hits, k))
        } else if want_vector {
            Ok(vector_hits)
        } else {
            Ok(text_hits)
        }
    }

    /// Newest-first listing across an agent's memory. Reads from the text
    /// backend (which stores the canonical metadata copy and supports
    /// `order_by_fast_field`). Embeddings are not surfaced here — list is for
    /// triage, not recall.
    pub fn list(&self, agent_did: impl Into<String>, limit: usize) -> Result<Vec<MemoryRecord>> {
        let agent_did = agent_did.into();
        let filter = MemoryFilter::for_agent(agent_did);
        self.text.list(&filter, limit)
    }

    /// Archive a memory: push the canonical payload to the DA backend, then
    /// rewrite the on-tier rows with `kind = Archived` and the resulting
    /// [`DaPointer`] embedded so callers can fetch on demand.
    pub async fn archive(&self, record_id: &str, agent_did: &str) -> Result<MemoryRecord> {
        // Source-of-truth row is the text backend (it stores everything except
        // the embedding bytes).
        let mut filter = MemoryFilter::for_agent(agent_did);
        filter.kind = None;
        let candidates = self.text.list(&filter, 10_000)?;
        let original = candidates
            .into_iter()
            .find(|r| r.id == record_id)
            .ok_or_else(|| MemoryError::NotFound(format!("memory {} not found", record_id)))?;

        let payload = serde_json::to_vec(&original)?;
        let pointer = self
            .da
            .submit(&self.config.da_namespace, &payload)
            .await
            .map_err(|e| MemoryError::Da(format!("DA submit: {}", e)))?;

        // The on-tier row keeps id/agent_did/text (so listing/recall still
        // surface a stub) but the kind flips to Archived and the pointer is
        // attached for fetch.
        let mut archived = original.clone();
        archived.kind = MemoryKind::Archived;
        archived.da_pointer = Some(pointer);
        // Re-attach the original embedding (if any) so the vector backend can
        // round-trip it. The text backend never read it — synthesize zeros if
        // missing so the FixedSizeList row stays valid.
        let dim = self.vector.embedding_dim();
        if archived.embedding.as_ref().map(|v| v.len()) != Some(dim) {
            archived.embedding = Some(vec![0.0; dim]);
        }
        self.vector.set_da_pointer(record_id, &archived).await?;
        self.text.set_da_pointer(&archived)?;
        Ok(archived)
    }

    /// Receipt kind under which agent-memory archives are filed at the DA
    /// layer. Exposed so the node can register the right kind with the
    /// receipt envelope policy.
    pub fn da_receipt_kind() -> ReceiptKind {
        ReceiptKind::AgentMessage
    }
}

/// Reciprocal Rank Fusion of two ranked lists. Records are deduplicated by
/// `id`; the merged list is truncated to `k`. The classic Cormack et al.
/// k=60 smoothing is hard-coded as [`RRF_K`].
fn rrf_merge(
    a: Vec<MemoryRecord>,
    b: Vec<MemoryRecord>,
    k: usize,
) -> Vec<MemoryRecord> {
    let mut scores: HashMap<String, f32> = HashMap::new();
    let mut by_id: HashMap<String, MemoryRecord> = HashMap::new();
    for (rank, rec) in a.into_iter().enumerate() {
        let s = 1.0 / (RRF_K + (rank as f32 + 1.0));
        *scores.entry(rec.id.clone()).or_insert(0.0) += s;
        by_id.entry(rec.id.clone()).or_insert(rec);
    }
    for (rank, rec) in b.into_iter().enumerate() {
        let s = 1.0 / (RRF_K + (rank as f32 + 1.0));
        *scores.entry(rec.id.clone()).or_insert(0.0) += s;
        by_id.entry(rec.id.clone()).or_insert(rec);
    }
    let mut ranked: Vec<(String, f32)> = scores.into_iter().collect();
    ranked.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut out: Vec<MemoryRecord> = Vec::with_capacity(ranked.len());
    for (id, _) in ranked.into_iter().take(k.max(1)) {
        if let Some(r) = by_id.remove(&id) {
            out.push(r);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tenzro_storage::da::InlineFallbackBackend;

    async fn make_manager(
        embedder: Option<Arc<TextEmbeddingRuntime>>,
        embedder_model_id: Option<&str>,
        dim: usize,
    ) -> (MemoryManager, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let v = Arc::new(LanceVectorBackend::new(dir.path(), dim).await.unwrap());
        let t = Arc::new(TantivyTextBackend::new(dir.path()).unwrap());
        let da: Arc<dyn DaBackend> = Arc::new(InlineFallbackBackend::new());
        let cfg = MemoryManagerConfig {
            embedder_model_id: embedder_model_id.map(|s| s.to_string()),
            ..Default::default()
        };
        (MemoryManager::new(v, t, da, embedder, cfg), dir)
    }

    #[tokio::test]
    async fn grant_without_embedder_errors() {
        let (mgr, _g) = make_manager(None, None, 4).await;
        let err = mgr
            .grant(
                "did:tenzro:machine:a",
                MemoryKind::Granted,
                MemorySource::Controller,
                "hello",
                serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MemoryError::NoEmbedder(_)));
    }

    #[tokio::test]
    async fn rrf_merge_dedups_by_id_and_orders_by_score() {
        let mut a = MemoryRecord::new(
            "did:tenzro:machine:a",
            MemoryKind::Granted,
            MemorySource::Controller,
            "first",
            None,
            serde_json::json!({}),
        );
        a.id = "id-A".into();
        let mut b = MemoryRecord::new(
            "did:tenzro:machine:a",
            MemoryKind::Granted,
            MemorySource::Controller,
            "second",
            None,
            serde_json::json!({}),
        );
        b.id = "id-B".into();
        let mut c = MemoryRecord::new(
            "did:tenzro:machine:a",
            MemoryKind::Granted,
            MemorySource::Controller,
            "third",
            None,
            serde_json::json!({}),
        );
        c.id = "id-C".into();

        // Vector list ranks A above B; text list ranks A above C — A should
        // win because it appears in both with rank 1.
        let vec_hits = vec![a.clone(), b.clone()];
        let txt_hits = vec![a.clone(), c.clone()];
        let merged = rrf_merge(vec_hits, txt_hits, 5);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].id, "id-A");
        // Order of B vs C is determined by their tied single-list rank-1 score.
        let rest: Vec<&str> = merged[1..].iter().map(|r| r.id.as_str()).collect();
        assert!(rest.contains(&"id-B"));
        assert!(rest.contains(&"id-C"));
    }

    #[tokio::test]
    async fn archive_replaces_with_pointer() {
        let (mgr, _g) = make_manager(None, None, 4).await;
        // Insert a record manually (no embedder configured).
        let mut rec = MemoryRecord::new(
            "did:tenzro:machine:a",
            MemoryKind::Granted,
            MemorySource::Controller,
            "to be archived",
            Some(vec![0.1, 0.2, 0.3, 0.4]),
            serde_json::json!({"k": "v"}),
        );
        rec.id = "id-archive".into();
        mgr.vector.insert(&rec).await.unwrap();
        mgr.text.insert(&rec).unwrap();

        let archived = mgr
            .archive("id-archive", "did:tenzro:machine:a")
            .await
            .unwrap();
        assert_eq!(archived.kind, MemoryKind::Archived);
        assert!(archived.da_pointer.is_some());

        // Listing now shows the archived stub with the pointer.
        let listed = mgr.list("did:tenzro:machine:a", 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "id-archive");
        assert_eq!(listed[0].kind, MemoryKind::Archived);
        assert!(listed[0].da_pointer.is_some());
    }
}
