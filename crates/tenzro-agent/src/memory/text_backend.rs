//! Tantivy-backed full-text index for the agent memory tier.
//!
//! Indexes [`MemoryRecord`]s under `{index_path}/agent_memory_text/`. The
//! schema is:
//!
//! | field          | flags                               |
//! |----------------|-------------------------------------|
//! | id             | STRING + STORED                     |
//! | agent_did      | STRING + STORED + FAST              |
//! | text           | TEXT + STORED                       |
//! | kind           | STRING + STORED + FAST              |
//! | source         | STRING + STORED                     |
//! | created_at_ms  | I64 + STORED + FAST + INDEXED       |
//! | metadata_json  | STORED                              |
//! | da_pointer_json| STORED                              |
//!
//! Recall is BM25 over `text`, with a Boolean filter that pins the
//! `agent_did` and optionally narrows by `kind` / time bounds. Time bounds
//! use Tantivy's `RangeQuery` over the FAST `created_at_ms` field.

use std::path::PathBuf;

use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, QueryParser, RangeQuery, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

use super::{MemoryError, MemoryFilter, MemoryKind, MemoryRecord, MemorySource, Result};

pub const TEXT_INDEX_DIR: &str = "agent_memory_text";

/// Default writer heap size — Tantivy 0.26 recommends >= 15 MB.
const WRITER_HEAP_BYTES: usize = 50 * 1024 * 1024;

/// Tantivy-backed text index.
pub struct TantivyTextBackend {
    index: Index,
    reader: IndexReader,
    writer: parking_lot::Mutex<IndexWriter>,
    fields: Fields,
}

#[derive(Clone)]
struct Fields {
    id: Field,
    agent_did: Field,
    text: Field,
    kind: Field,
    source: Field,
    created_at_ms: Field,
    metadata_json: Field,
    da_pointer_json: Field,
}

impl TantivyTextBackend {
    /// Open (or create) the index at `{index_path}/agent_memory_text/`.
    pub fn new(index_path: impl Into<PathBuf>) -> Result<Self> {
        let mut path: PathBuf = index_path.into();
        path.push(TEXT_INDEX_DIR);
        std::fs::create_dir_all(&path).map_err(|e| {
            MemoryError::Text(format!("create_dir_all {:?}: {}", path, e))
        })?;

        let schema = Self::build_schema();
        let index = match Index::open_in_dir(&path) {
            Ok(idx) => idx,
            Err(_) => Index::create_in_dir(&path, schema.clone())
                .map_err(|e| MemoryError::Text(format!("create_in_dir: {}", e)))?,
        };

        let writer = index
            .writer(WRITER_HEAP_BYTES)
            .map_err(|e| MemoryError::Text(format!("writer: {}", e)))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| MemoryError::Text(format!("reader: {}", e)))?;

        let fields = Fields {
            id: schema.get_field("id").unwrap(),
            agent_did: schema.get_field("agent_did").unwrap(),
            text: schema.get_field("text").unwrap(),
            kind: schema.get_field("kind").unwrap(),
            source: schema.get_field("source").unwrap(),
            created_at_ms: schema.get_field("created_at_ms").unwrap(),
            metadata_json: schema.get_field("metadata_json").unwrap(),
            da_pointer_json: schema.get_field("da_pointer_json").unwrap(),
        };

        Ok(Self {
            index,
            reader,
            writer: parking_lot::Mutex::new(writer),
            fields,
        })
    }

    fn build_schema() -> Schema {
        let mut b = Schema::builder();
        b.add_text_field("id", STRING | STORED);
        b.add_text_field("agent_did", STRING | STORED | FAST);
        b.add_text_field("text", TEXT | STORED);
        b.add_text_field("kind", STRING | STORED | FAST);
        b.add_text_field("source", STRING | STORED);
        b.add_i64_field("created_at_ms", STORED | FAST | INDEXED);
        b.add_text_field("metadata_json", STORED);
        b.add_text_field("da_pointer_json", STORED);
        b.build()
    }

    /// Insert (or overwrite) a record. Overwrite is by `id` — we delete the
    /// existing doc by primary-key term first so the index never carries
    /// duplicates of the same memory.
    pub fn insert(&self, record: &MemoryRecord) -> Result<()> {
        let mut w = self.writer.lock();
        // Idempotent overwrite by primary key.
        w.delete_term(Term::from_field_text(self.fields.id, &record.id));
        let metadata = serde_json::to_string(&record.metadata)?;
        let da_pointer = match &record.da_pointer {
            Some(p) => serde_json::to_string(p)?,
            None => String::new(),
        };
        w.add_document(doc!(
            self.fields.id => record.id.clone(),
            self.fields.agent_did => record.agent_did.clone(),
            self.fields.text => record.text.clone(),
            self.fields.kind => record.kind.as_str().to_string(),
            self.fields.source => record.source.as_str().to_string(),
            self.fields.created_at_ms => record.created_at_ms,
            self.fields.metadata_json => metadata,
            self.fields.da_pointer_json => da_pointer,
        ))
        .map_err(|e| MemoryError::Text(format!("add_document: {}", e)))?;
        w.commit()
            .map_err(|e| MemoryError::Text(format!("commit: {}", e)))?;
        self.reader
            .reload()
            .map_err(|e| MemoryError::Text(format!("reload: {}", e)))?;
        Ok(())
    }

    /// BM25 search over `text` constrained by `filter`.
    pub fn search_by_text(
        &self,
        query: &str,
        limit: usize,
        filter: &MemoryFilter,
    ) -> Result<Vec<MemoryRecord>> {
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.fields.text]);
        let text_query = parser
            .parse_query(query)
            .map_err(|e| MemoryError::Text(format!("parse_query: {}", e)))?;

        let combined = self.combine_with_filter(text_query, filter);
        let docs = searcher
            .search(
                &combined,
                &TopDocs::with_limit(limit.max(1)).order_by_score(),
            )
            .map_err(|e| MemoryError::Text(format!("search: {}", e)))?;
        let mut out = Vec::with_capacity(docs.len());
        for (_score, addr) in docs {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| MemoryError::Text(format!("fetch doc: {}", e)))?;
            out.push(self.doc_to_record(&doc)?);
        }
        Ok(out)
    }

    /// Point-lookup a single record by `(agent_did, record_id)`. Returns
    /// `Ok(None)` if no row matches. Backs [`MemoryManager::get_by_id`] which
    /// is in turn used by the `tenzro://memory/...` URI resolver and by the
    /// archive path (replacing the prior O(n) `list` scan).
    pub fn get_by_id(&self, agent_did: &str, record_id: &str) -> Result<Option<MemoryRecord>> {
        let searcher = self.reader.searcher();
        let id_term = Term::from_field_text(self.fields.id, record_id);
        let did_term = Term::from_field_text(self.fields.agent_did, agent_did);
        let clauses: Vec<(Occur, Box<dyn Query>)> = vec![
            (
                Occur::Must,
                Box::new(TermQuery::new(id_term, IndexRecordOption::Basic)),
            ),
            (
                Occur::Must,
                Box::new(TermQuery::new(did_term, IndexRecordOption::Basic)),
            ),
        ];
        let q = BooleanQuery::new(clauses);
        let docs = searcher
            .search(&q, &TopDocs::with_limit(1).order_by_score())
            .map_err(|e| MemoryError::Text(format!("get_by_id search: {}", e)))?;
        match docs.into_iter().next() {
            Some((_score, addr)) => {
                let doc: TantivyDocument = searcher
                    .doc(addr)
                    .map_err(|e| MemoryError::Text(format!("fetch doc: {}", e)))?;
                Ok(Some(self.doc_to_record(&doc)?))
            }
            None => Ok(None),
        }
    }

    /// Walk the index and return up to `limit` records matching the filter,
    /// most-recent-first. Backs `tenzro_listMemoryRecords` when no embedder
    /// or query string is in play.
    pub fn list(&self, filter: &MemoryFilter, limit: usize) -> Result<Vec<MemoryRecord>> {
        let searcher = self.reader.searcher();
        // Build a filter-only query — no text component, just the boolean
        // filter the recall path uses.
        let filter_query = self.filter_query(filter);
        let docs = searcher
            .search(
                &filter_query,
                &TopDocs::with_limit(limit.max(1))
                    .order_by_fast_field::<i64>("created_at_ms", tantivy::Order::Desc),
            )
            .map_err(|e| MemoryError::Text(format!("list search: {}", e)))?;
        let mut out = Vec::with_capacity(docs.len());
        for (_ts, addr) in docs {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| MemoryError::Text(format!("fetch doc: {}", e)))?;
            out.push(self.doc_to_record(&doc)?);
        }
        Ok(out)
    }

    /// Update the `da_pointer_json` cell for a single id by re-indexing the
    /// full record. The caller passes the post-archive record (with
    /// `da_pointer = Some(...)` and `kind = Archived`).
    pub fn set_da_pointer(&self, record_after_archive: &MemoryRecord) -> Result<()> {
        // `insert` is idempotent — it deletes by id then re-adds.
        self.insert(record_after_archive)
    }

    fn combine_with_filter(&self, text_query: Box<dyn Query>, filter: &MemoryFilter) -> BooleanQuery {
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        clauses.push((Occur::Must, text_query));
        for (occur, q) in self.filter_clauses(filter) {
            clauses.push((occur, q));
        }
        BooleanQuery::new(clauses)
    }

    fn filter_query(&self, filter: &MemoryFilter) -> BooleanQuery {
        BooleanQuery::new(self.filter_clauses(filter))
    }

    fn filter_clauses(&self, filter: &MemoryFilter) -> Vec<(Occur, Box<dyn Query>)> {
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        let did_term = Term::from_field_text(self.fields.agent_did, &filter.agent_did);
        clauses.push((
            Occur::Must,
            Box::new(TermQuery::new(did_term, IndexRecordOption::Basic)),
        ));
        if let Some(kind) = filter.kind {
            let term = Term::from_field_text(self.fields.kind, kind.as_str());
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
            ));
        }
        // Range bounds: Tantivy's RangeQuery uses Term bounds.
        let lo = filter.min_created_at_ms.unwrap_or(i64::MIN);
        let hi = filter.max_created_at_ms.unwrap_or(i64::MAX);
        if filter.min_created_at_ms.is_some() || filter.max_created_at_ms.is_some() {
            let lo_term = Term::from_field_i64(self.fields.created_at_ms, lo);
            let hi_term = Term::from_field_i64(self.fields.created_at_ms, hi);
            clauses.push((
                Occur::Must,
                Box::new(RangeQuery::new(
                    std::ops::Bound::Included(lo_term),
                    std::ops::Bound::Included(hi_term),
                )),
            ));
        }
        clauses
    }

    fn doc_to_record(&self, doc: &TantivyDocument) -> Result<MemoryRecord> {
        let id = first_text(doc, self.fields.id)
            .ok_or_else(|| MemoryError::Text("doc missing id".into()))?;
        let agent_did = first_text(doc, self.fields.agent_did)
            .ok_or_else(|| MemoryError::Text("doc missing agent_did".into()))?;
        let text = first_text(doc, self.fields.text)
            .ok_or_else(|| MemoryError::Text("doc missing text".into()))?;
        let kind_s = first_text(doc, self.fields.kind)
            .ok_or_else(|| MemoryError::Text("doc missing kind".into()))?;
        let source_s = first_text(doc, self.fields.source)
            .ok_or_else(|| MemoryError::Text("doc missing source".into()))?;
        let kind = MemoryKind::parse(&kind_s)
            .ok_or_else(|| MemoryError::Text(format!("bad kind: {}", kind_s)))?;
        let source = MemorySource::parse(&source_s)
            .ok_or_else(|| MemoryError::Text(format!("bad source: {}", source_s)))?;
        let created_at_ms = first_i64(doc, self.fields.created_at_ms)
            .ok_or_else(|| MemoryError::Text("doc missing created_at_ms".into()))?;
        let metadata_s = first_text(doc, self.fields.metadata_json).unwrap_or_else(|| "{}".into());
        let metadata: serde_json::Value = serde_json::from_str(&metadata_s)?;
        let da_pointer_s = first_text(doc, self.fields.da_pointer_json).unwrap_or_default();
        let da_pointer = if da_pointer_s.is_empty() {
            None
        } else {
            Some(serde_json::from_str(&da_pointer_s)?)
        };
        Ok(MemoryRecord {
            id,
            agent_did,
            created_at_ms,
            kind,
            source,
            text,
            // The text backend does not persist the embedding bytes.
            embedding: None,
            metadata,
            da_pointer,
        })
    }

}

fn first_text(doc: &TantivyDocument, field: Field) -> Option<String> {
    use tantivy::schema::Value;
    doc.get_first(field)
        .and_then(|v| v.as_str().map(|s| s.to_string()))
}

fn first_i64(doc: &TantivyDocument, field: Field) -> Option<i64> {
    use tantivy::schema::Value;
    doc.get_first(field).and_then(|v| v.as_i64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rec(did: &str, text: &str, kind: MemoryKind, ts: i64) -> MemoryRecord {
        let mut r = MemoryRecord::new(
            did,
            kind,
            MemorySource::Controller,
            text,
            None,
            serde_json::json!({}),
        );
        r.created_at_ms = ts;
        r
    }

    #[test]
    fn insert_and_bm25_recall() {
        let dir = tempdir().unwrap();
        let backend = TantivyTextBackend::new(dir.path()).unwrap();
        backend
            .insert(&rec(
                "did:tenzro:machine:a",
                "the quick brown fox jumps over the lazy dog",
                MemoryKind::Granted,
                1,
            ))
            .unwrap();
        backend
            .insert(&rec(
                "did:tenzro:machine:a",
                "totally unrelated content about gardening",
                MemoryKind::Granted,
                2,
            ))
            .unwrap();
        let f = MemoryFilter::for_agent("did:tenzro:machine:a");
        let res = backend.search_by_text("brown fox", 5, &f).unwrap();
        assert!(!res.is_empty());
        assert!(res[0].text.contains("brown fox"));
    }

    #[test]
    fn time_filter_bounds_results() {
        let dir = tempdir().unwrap();
        let backend = TantivyTextBackend::new(dir.path()).unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "alpha", MemoryKind::Granted, 100))
            .unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "alpha", MemoryKind::Granted, 200))
            .unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "alpha", MemoryKind::Granted, 300))
            .unwrap();
        let mut f = MemoryFilter::for_agent("did:tenzro:machine:a");
        f.min_created_at_ms = Some(150);
        f.max_created_at_ms = Some(250);
        let res = backend.search_by_text("alpha", 10, &f).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].created_at_ms, 200);
    }

    #[test]
    fn list_returns_newest_first() {
        let dir = tempdir().unwrap();
        let backend = TantivyTextBackend::new(dir.path()).unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "old", MemoryKind::Granted, 1))
            .unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "new", MemoryKind::Granted, 1000))
            .unwrap();
        let f = MemoryFilter::for_agent("did:tenzro:machine:a");
        let res = backend.list(&f, 10).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].text, "new");
        assert_eq!(res[1].text, "old");
    }

    #[test]
    fn agent_did_isolates_recall() {
        let dir = tempdir().unwrap();
        let backend = TantivyTextBackend::new(dir.path()).unwrap();
        backend
            .insert(&rec("did:tenzro:machine:a", "shared text", MemoryKind::Granted, 1))
            .unwrap();
        backend
            .insert(&rec("did:tenzro:machine:b", "shared text", MemoryKind::Granted, 2))
            .unwrap();
        let f = MemoryFilter::for_agent("did:tenzro:machine:a");
        let res = backend.search_by_text("shared", 10, &f).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].agent_did, "did:tenzro:machine:a");
    }
}
