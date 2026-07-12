//! Tantivy driver — embedded full-text index, in-process.
//!
//! Like Lance, Tantivy runs inside the node. Each partition is a Tantivy index
//! directory under `{root}/{database_id}_{partition_index}/`. `start_partition`
//! opens (creating the dir) the index; `stop_partition` drops the in-memory
//! handle (the on-disk index is left intact — dropping a partition's data is an
//! explicit `drop` op).
//!
//! The schema is fixed: `id: STRING+STORED` (primary key, idempotent overwrite),
//! `text: TEXT+STORED` (the BM25-searched body), `fields_json: STORED` (opaque
//! JSON the caller stores alongside the document). The query `body` is
//! `{ "op": "add" | "search" | "count", ... }`:
//! - `add`:    `{ "op": "add", "docs": [ {id, text, fields?}, ... ] }`
//! - `search`: `{ "op": "search", "query": "...", "limit": N }`
//! - `count`:  `{ "op": "count" }`

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use tantivy::collector::{Count, TopDocs};
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};
use tenzro_database::{
    catalog::engine_ids, DatabaseEngine, DatabaseError, PartitionHandle, PartitionHealth,
    QueryRequest, QueryResponse, Result,
};
use tokio::sync::Mutex;

/// Tantivy 0.26 recommends a writer heap >= 15 MB.
const WRITER_HEAP_BYTES: usize = 50 * 1024 * 1024;

/// An embedded Tantivy full-text store rooted at `root`.
pub struct TantivyEngine {
    root: PathBuf,
    /// Per-partition open indexes, keyed by index dir name.
    indexes: Mutex<HashMap<String, Arc<PartitionIndex>>>,
}

/// One partition's open index — the tantivy `Index`, its reader, a writer behind
/// a sync mutex (tantivy writers are `!Sync`-friendly only under exclusive
/// access), and the resolved schema fields.
struct PartitionIndex {
    index: Index,
    reader: IndexReader,
    writer: parking_lot::Mutex<IndexWriter>,
    fields: Fields,
}

#[derive(Clone, Copy)]
struct Fields {
    id: Field,
    text: Field,
    fields_json: Field,
}

impl TantivyEngine {
    /// Roots the store at `root` (`{data_dir}/databases/tantivy`). Partitions
    /// land in subdirectories under it.
    pub fn new(root: PathBuf) -> Self {
        Self { root, indexes: Mutex::new(HashMap::new()) }
    }

    fn partition_key(database_id: &str, partition_index: usize) -> String {
        format!("{database_id}_{partition_index}")
    }

    fn build_schema() -> Schema {
        let mut b = Schema::builder();
        b.add_text_field("id", STRING | STORED);
        b.add_text_field("text", TEXT | STORED);
        b.add_text_field("fields_json", STORED);
        b.build()
    }

    async fn open_index(&self, key: &str) -> Result<Arc<PartitionIndex>> {
        {
            let map = self.indexes.lock().await;
            if let Some(idx) = map.get(key) {
                return Ok(idx.clone());
            }
        }
        let dir = self.root.join(key);
        std::fs::create_dir_all(&dir)
            .map_err(|e| DatabaseError::Backend(format!("tantivy mkdir {dir:?}: {e}")))?;
        let schema = Self::build_schema();
        let index = match Index::open_in_dir(&dir) {
            Ok(idx) => idx,
            Err(_) => Index::create_in_dir(&dir, schema.clone())
                .map_err(|e| DatabaseError::Backend(format!("tantivy create_in_dir: {e}")))?,
        };
        let writer = index
            .writer(WRITER_HEAP_BYTES)
            .map_err(|e| DatabaseError::Backend(format!("tantivy writer: {e}")))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| DatabaseError::Backend(format!("tantivy reader: {e}")))?;
        let fields = Fields {
            id: schema.get_field("id").unwrap(),
            text: schema.get_field("text").unwrap(),
            fields_json: schema.get_field("fields_json").unwrap(),
        };
        let partition = Arc::new(PartitionIndex {
            index,
            reader,
            writer: parking_lot::Mutex::new(writer),
            fields,
        });
        self.indexes.lock().await.insert(key.to_string(), partition.clone());
        Ok(partition)
    }
}

#[async_trait]
impl DatabaseEngine for TantivyEngine {
    fn engine_id(&self) -> &str {
        engine_ids::TANTIVY
    }

    async fn start_partition(&self, handle: &PartitionHandle) -> Result<()> {
        // No config to validate — the schema is fixed. Opening the index
        // creates the dir so a broken path fails at partition-up, not first
        // query.
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        self.open_index(&key).await?;
        Ok(())
    }

    async fn stop_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        self.indexes.lock().await.remove(&key);
        Ok(())
    }

    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let op: TantivyOp = serde_json::from_value(request.body.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("tantivy op: {e}")))?;
        let key = Self::partition_key(&request.database_id, request.partition_index);
        let idx = self.open_index(&key).await?;

        match op {
            TantivyOp::Add { docs } => {
                if docs.is_empty() {
                    return Err(DatabaseError::InvalidRequest("tantivy add: no docs".into()));
                }
                let added = docs.len();
                {
                    let mut w = idx.writer.lock();
                    for d in &docs {
                        // Idempotent overwrite by primary key.
                        w.delete_term(Term::from_field_text(idx.fields.id, &d.id));
                        let fields_json = match &d.fields {
                            Some(v) => serde_json::to_string(v)
                                .map_err(|e| DatabaseError::InvalidRequest(format!("tantivy fields: {e}")))?,
                            None => String::new(),
                        };
                        w.add_document(doc!(
                            idx.fields.id => d.id.clone(),
                            idx.fields.text => d.text.clone(),
                            idx.fields.fields_json => fields_json,
                        ))
                        .map_err(|e| DatabaseError::Query(format!("tantivy add_document: {e}")))?;
                    }
                    w.commit()
                        .map_err(|e| DatabaseError::Query(format!("tantivy commit: {e}")))?;
                }
                idx.reader
                    .reload()
                    .map_err(|e| DatabaseError::Query(format!("tantivy reload: {e}")))?;
                Ok(QueryResponse { body: serde_json::json!({ "added": added }) })
            }
            TantivyOp::Search { query, limit } => {
                let searcher = idx.reader.searcher();
                let parser = QueryParser::for_index(&idx.index, vec![idx.fields.text]);
                let parsed = parser
                    .parse_query(&query)
                    .map_err(|e| DatabaseError::InvalidRequest(format!("tantivy parse_query: {e}")))?;
                let hits = searcher
                    .search(&parsed, &TopDocs::with_limit(limit.max(1)).order_by_score())
                    .map_err(|e| DatabaseError::Query(format!("tantivy search: {e}")))?;
                let mut rows = Vec::with_capacity(hits.len());
                for (score, addr) in hits {
                    let d: TantivyDocument = searcher
                        .doc(addr)
                        .map_err(|e| DatabaseError::Query(format!("tantivy fetch doc: {e}")))?;
                    rows.push(doc_to_json(&d, &idx.fields, score));
                }
                Ok(QueryResponse { body: serde_json::json!({ "rows": rows }) })
            }
            TantivyOp::Count => {
                let searcher = idx.reader.searcher();
                let count = searcher
                    .search(&tantivy::query::AllQuery, &Count)
                    .map_err(|e| DatabaseError::Query(format!("tantivy count: {e}")))?;
                Ok(QueryResponse { body: serde_json::json!({ "count": count }) })
            }
        }
    }

    async fn partition_health(&self, handle: &PartitionHandle) -> Result<PartitionHealth> {
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        match self.open_index(&key).await {
            Ok(_) => Ok(PartitionHealth::Serving),
            Err(_) => Ok(PartitionHealth::Down),
        }
    }
}

/// Renders one hit as `{ id, text, fields, score }`. `fields` decodes the stored
/// opaque JSON blob (null when the doc was added without one).
fn doc_to_json(doc: &TantivyDocument, fields: &Fields, score: f32) -> serde_json::Value {
    let id = first_text(doc, fields.id).unwrap_or_default();
    let text = first_text(doc, fields.text).unwrap_or_default();
    let extra = first_text(doc, fields.fields_json)
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    serde_json::json!({ "id": id, "text": text, "fields": extra, "score": score })
}

fn first_text(doc: &TantivyDocument, field: Field) -> Option<String> {
    doc.get_first(field).and_then(|v| v.as_str().map(|s| s.to_string()))
}

/// A single document to add: id, the BM25-searched text, and an opaque JSON
/// sidecar.
#[derive(Debug, Deserialize)]
struct TantivyDoc {
    id: String,
    text: String,
    #[serde(default)]
    fields: Option<serde_json::Value>,
}

/// A Tantivy query op.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum TantivyOp {
    /// Add documents to the partition's index (idempotent overwrite by id).
    Add { docs: Vec<TantivyDoc> },
    /// BM25 search over the `text` field.
    Search {
        query: String,
        #[serde(default = "default_limit")]
        limit: usize,
    },
    /// Document count.
    Count,
}

fn default_limit() -> usize {
    10
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn add_search_count_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = TantivyEngine::new(dir.path().to_path_buf());
        let handle = PartitionHandle {
            database_id: "kb".into(),
            engine_id: engine_ids::TANTIVY.into(),
            partition_index: 0,
            engine_config: serde_json::json!({}),
        };
        engine.start_partition(&handle).await.unwrap();

        let add = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            body: serde_json::json!({
                "op": "add",
                "docs": [
                    { "id": "a", "text": "the quick brown fox", "fields": {"tag": "animal"} },
                    { "id": "b", "text": "gardening and compost" }
                ]
            }),
        };
        let r = engine.query(&add).await.unwrap();
        assert_eq!(r.body["added"], 2);

        let search = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            body: serde_json::json!({ "op": "search", "query": "brown fox", "limit": 5 }),
        };
        let r = engine.query(&search).await.unwrap();
        let rows = r.body["rows"].as_array().unwrap();
        assert!(!rows.is_empty());
        assert_eq!(rows[0]["id"], "a");
        assert_eq!(rows[0]["fields"]["tag"], "animal");

        let count = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            body: serde_json::json!({ "op": "count" }),
        };
        let r = engine.query(&count).await.unwrap();
        assert_eq!(r.body["count"], 2);
    }

    #[tokio::test]
    async fn add_is_idempotent_by_id() {
        let dir = tempdir().unwrap();
        let engine = TantivyEngine::new(dir.path().to_path_buf());
        let handle = PartitionHandle {
            database_id: "kb".into(),
            engine_id: engine_ids::TANTIVY.into(),
            partition_index: 0,
            engine_config: serde_json::json!({}),
        };
        engine.start_partition(&handle).await.unwrap();

        for text in ["first version", "second version"] {
            let add = QueryRequest {
                database_id: "kb".into(),
                partition_index: 0,
                body: serde_json::json!({ "op": "add", "docs": [{ "id": "x", "text": text }] }),
            };
            engine.query(&add).await.unwrap();
        }
        let count = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            body: serde_json::json!({ "op": "count" }),
        };
        let r = engine.query(&count).await.unwrap();
        assert_eq!(r.body["count"], 1);

        let search = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            body: serde_json::json!({ "op": "search", "query": "version" }),
        };
        let r = engine.query(&search).await.unwrap();
        let rows = r.body["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["text"], "second version");
    }
}
