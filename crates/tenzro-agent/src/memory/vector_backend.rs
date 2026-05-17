//! Lance-backed vector store for the agent memory tier.
//!
//! Persists [`MemoryRecord`]s as Apache Arrow `RecordBatch`es in a single
//! Lance table at `{db_path}/agent_memory_vector.lance`. The table schema is:
//!
//! | column           | type                              | nullable |
//! |------------------|-----------------------------------|----------|
//! | id               | Utf8                              | no       |
//! | agent_did        | Utf8                              | no       |
//! | created_at_ms    | Int64                             | no       |
//! | kind             | Utf8                              | no       |
//! | source           | Utf8                              | no       |
//! | text             | Utf8                              | no       |
//! | metadata_json    | Utf8                              | no       |
//! | da_pointer_json  | Utf8                              | yes      |
//! | embedding        | FixedSizeList<Float32>(`emb_dim`) | no       |
//!
//! Recall is via cosine kNN over `embedding`, optionally filtered by an
//! agent DID, kind, and time bounds.

use std::path::PathBuf;
use std::sync::Arc;

use arrow_array::{
    Array, FixedSizeListArray, Float32Array, Int64Array, RecordBatch, StringArray,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use futures_util::TryStreamExt;
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::{Connection, Table};

use super::{MemoryError, MemoryFilter, MemoryKind, MemoryRecord, MemorySource, Result};

/// Default Lance subdirectory under the manager's data root.
pub const VECTOR_TABLE_FILE: &str = "agent_memory_vector.lance";

/// Lance table name. Scoped under `{db_path}/agent_memory_vector.lance` so a
/// single LanceDB connection points at exactly one table.
const TABLE_NAME: &str = "agent_memory";

/// Lance-backed vector store.
pub struct LanceVectorBackend {
    conn: Connection,
    /// Lazily-opened table handle. Lance creates the table on first insert
    /// because `create_empty_table` requires us to land schemas separately,
    /// and the manager needs the dim before either is possible.
    embedding_dim: usize,
    /// Fully resolved schema (includes the FixedSizeList width).
    schema: SchemaRef,
}

impl LanceVectorBackend {
    /// Open (or create) the Lance table at `{db_path}/agent_memory_vector.lance`.
    /// `embedding_dim` is the number of f32 components per vector — must be
    /// stable for the lifetime of the table (Lance enforces FixedSizeList
    /// width at insert time).
    pub async fn new(db_path: impl Into<PathBuf>, embedding_dim: usize) -> Result<Self> {
        if embedding_dim == 0 {
            return Err(MemoryError::InvalidArgument(
                "embedding_dim must be > 0".into(),
            ));
        }
        let db_path: PathBuf = db_path.into();
        // Lance writes its dataset under {db_path}/agent_memory_vector.lance.
        // Treat the parent (`db_path`) as the LanceDB connection root and
        // ensure it exists.
        std::fs::create_dir_all(&db_path)
            .map_err(|e| MemoryError::Vector(format!("create_dir_all {:?}: {}", db_path, e)))?;
        let lance_uri = db_path
            .to_str()
            .ok_or_else(|| MemoryError::Vector(format!("non-utf8 lance path: {:?}", db_path)))?
            .to_string();
        let conn = lancedb::connect(&lance_uri)
            .execute()
            .await
            .map_err(|e| MemoryError::Vector(format!("connect({}): {}", lance_uri, e)))?;
        let schema = Arc::new(Self::build_schema(embedding_dim));
        Ok(Self {
            conn,
            embedding_dim,
            schema,
        })
    }

    fn build_schema(dim: usize) -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Utf8, false),
            Field::new("agent_did", DataType::Utf8, false),
            Field::new("created_at_ms", DataType::Int64, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("source", DataType::Utf8, false),
            Field::new("text", DataType::Utf8, false),
            Field::new("metadata_json", DataType::Utf8, false),
            Field::new("da_pointer_json", DataType::Utf8, true),
            Field::new(
                "embedding",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    dim as i32,
                ),
                false,
            ),
        ])
    }

    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    async fn open_or_create_table(&self, first_batch: RecordBatch) -> Result<Table> {
        let names = self.conn.table_names().execute().await.map_err(|e| {
            MemoryError::Vector(format!("table_names: {}", e))
        })?;
        if names.iter().any(|n| n == TABLE_NAME) {
            let tbl = self
                .conn
                .open_table(TABLE_NAME)
                .execute()
                .await
                .map_err(|e| MemoryError::Vector(format!("open_table: {}", e)))?;
            tbl.add(vec![first_batch])
                .execute()
                .await
                .map_err(|e| MemoryError::Vector(format!("add (existing): {}", e)))?;
            Ok(tbl)
        } else {
            let tbl = self
                .conn
                .create_table(TABLE_NAME, vec![first_batch])
                .execute()
                .await
                .map_err(|e| MemoryError::Vector(format!("create_table: {}", e)))?;
            Ok(tbl)
        }
    }

    async fn open_table(&self) -> Result<Option<Table>> {
        let names = self.conn.table_names().execute().await.map_err(|e| {
            MemoryError::Vector(format!("table_names: {}", e))
        })?;
        if !names.iter().any(|n| n == TABLE_NAME) {
            return Ok(None);
        }
        let tbl = self
            .conn
            .open_table(TABLE_NAME)
            .execute()
            .await
            .map_err(|e| MemoryError::Vector(format!("open_table: {}", e)))?;
        Ok(Some(tbl))
    }

    /// Insert a single record. `record.embedding` must be `Some` and length
    /// must equal [`Self::embedding_dim`].
    pub async fn insert(&self, record: &MemoryRecord) -> Result<()> {
        let embedding = record
            .embedding
            .as_ref()
            .ok_or_else(|| MemoryError::InvalidArgument("record.embedding is None".into()))?;
        if embedding.len() != self.embedding_dim {
            return Err(MemoryError::DimMismatch {
                expected: self.embedding_dim,
                actual: embedding.len(),
            });
        }
        let batch = self.records_to_batch(std::slice::from_ref(record))?;
        // open_or_create_table inserts the batch atomically with creation.
        self.open_or_create_table(batch).await?;
        Ok(())
    }

    fn records_to_batch(&self, records: &[MemoryRecord]) -> Result<RecordBatch> {
        let n = records.len();
        if n == 0 {
            return Err(MemoryError::InvalidArgument("empty record batch".into()));
        }
        let mut ids = Vec::with_capacity(n);
        let mut dids = Vec::with_capacity(n);
        let mut tss = Vec::with_capacity(n);
        let mut kinds = Vec::with_capacity(n);
        let mut sources = Vec::with_capacity(n);
        let mut texts = Vec::with_capacity(n);
        let mut metas = Vec::with_capacity(n);
        let mut ptrs: Vec<Option<String>> = Vec::with_capacity(n);
        let mut emb_flat: Vec<f32> = Vec::with_capacity(n * self.embedding_dim);
        for r in records {
            let emb = r.embedding.as_ref().ok_or_else(|| {
                MemoryError::InvalidArgument(format!("record {} missing embedding", r.id))
            })?;
            if emb.len() != self.embedding_dim {
                return Err(MemoryError::DimMismatch {
                    expected: self.embedding_dim,
                    actual: emb.len(),
                });
            }
            ids.push(r.id.clone());
            dids.push(r.agent_did.clone());
            tss.push(r.created_at_ms);
            kinds.push(r.kind.as_str().to_string());
            sources.push(r.source.as_str().to_string());
            texts.push(r.text.clone());
            metas.push(serde_json::to_string(&r.metadata)?);
            ptrs.push(match &r.da_pointer {
                Some(p) => Some(serde_json::to_string(p)?),
                None => None,
            });
            emb_flat.extend_from_slice(emb);
        }
        let id_arr = Arc::new(StringArray::from(ids));
        let did_arr = Arc::new(StringArray::from(dids));
        let ts_arr = Arc::new(Int64Array::from(tss));
        let kind_arr = Arc::new(StringArray::from(kinds));
        let src_arr = Arc::new(StringArray::from(sources));
        let text_arr = Arc::new(StringArray::from(texts));
        let meta_arr = Arc::new(StringArray::from(metas));
        let ptr_arr = Arc::new(StringArray::from(ptrs));
        let item_field = Arc::new(Field::new("item", DataType::Float32, true));
        let emb_inner = Arc::new(Float32Array::from(emb_flat));
        let emb_arr = Arc::new(
            FixedSizeListArray::try_new(item_field, self.embedding_dim as i32, emb_inner, None)
                .map_err(|e| MemoryError::Vector(format!("FixedSizeListArray::try_new: {}", e)))?,
        );
        RecordBatch::try_new(
            self.schema.clone(),
            vec![
                id_arr, did_arr, ts_arr, kind_arr, src_arr, text_arr, meta_arr, ptr_arr, emb_arr,
            ],
        )
        .map_err(|e| MemoryError::Vector(format!("RecordBatch::try_new: {}", e)))
    }

    /// kNN search by query vector. Returns up to `k` records, sorted by
    /// ascending distance.
    pub async fn search_by_vector(
        &self,
        query: &[f32],
        k: usize,
        filter: &MemoryFilter,
    ) -> Result<Vec<MemoryRecord>> {
        if query.len() != self.embedding_dim {
            return Err(MemoryError::DimMismatch {
                expected: self.embedding_dim,
                actual: query.len(),
            });
        }
        let Some(tbl) = self.open_table().await? else {
            return Ok(Vec::new());
        };
        let where_sql = build_where_sql(filter);
        let q = tbl
            .query()
            .nearest_to(query.to_vec())
            .map_err(|e| MemoryError::Vector(format!("nearest_to: {}", e)))?
            .limit(k.max(1))
            .only_if(where_sql);
        let stream = q
            .execute()
            .await
            .map_err(|e| MemoryError::Vector(format!("execute query: {}", e)))?;
        let batches: Vec<RecordBatch> = stream
            .try_collect()
            .await
            .map_err(|e| MemoryError::Vector(format!("collect stream: {}", e)))?;
        let mut out = Vec::new();
        for b in &batches {
            out.extend(self.batch_to_records(b)?);
        }
        // Lance returns ANN results already ordered; truncate defensively.
        out.truncate(k.max(1));
        Ok(out)
    }

    /// Update the `da_pointer_json` cell for a single id. Implemented as
    /// delete-then-insert because Lance updates require an SQL update path
    /// with column expressions; we keep the row-replacement simple.
    pub async fn set_da_pointer(
        &self,
        record_id: &str,
        record_after_archive: &MemoryRecord,
    ) -> Result<()> {
        let Some(tbl) = self.open_table().await? else {
            return Err(MemoryError::NotFound(format!(
                "vector backend has no table; record {} not stored",
                record_id
            )));
        };
        let predicate = format!("id = '{}'", escape_sql_literal(record_id));
        tbl.delete(&predicate)
            .await
            .map_err(|e| MemoryError::Vector(format!("delete: {}", e)))?;
        let batch = self.records_to_batch(std::slice::from_ref(&record_after_archive))?;
        tbl.add(vec![batch])
            .execute()
            .await
            .map_err(|e| MemoryError::Vector(format!("add (after archive): {}", e)))?;
        Ok(())
    }

    /// Walk the table and return up to `limit` records matching the filter,
    /// most-recent-first. Used by `tenzro_listMemoryRecords`.
    pub async fn list(&self, filter: &MemoryFilter, limit: usize) -> Result<Vec<MemoryRecord>> {
        let Some(tbl) = self.open_table().await? else {
            return Ok(Vec::new());
        };
        let where_sql = build_where_sql(filter);
        let q = tbl
            .query()
            .only_if(where_sql)
            .limit(limit.max(1));
        let stream = q
            .execute()
            .await
            .map_err(|e| MemoryError::Vector(format!("list execute: {}", e)))?;
        let batches: Vec<RecordBatch> = stream
            .try_collect()
            .await
            .map_err(|e| MemoryError::Vector(format!("list collect: {}", e)))?;
        let mut out = Vec::new();
        for b in &batches {
            out.extend(self.batch_to_records(b)?);
        }
        // Sort newest first (Lance scan order is unspecified).
        out.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        out.truncate(limit.max(1));
        Ok(out)
    }

    fn batch_to_records(&self, batch: &RecordBatch) -> Result<Vec<MemoryRecord>> {
        let n = batch.num_rows();
        let id_col = downcast_string(batch, "id")?;
        let did_col = downcast_string(batch, "agent_did")?;
        let ts_col = downcast_i64(batch, "created_at_ms")?;
        let kind_col = downcast_string(batch, "kind")?;
        let src_col = downcast_string(batch, "source")?;
        let text_col = downcast_string(batch, "text")?;
        let meta_col = downcast_string(batch, "metadata_json")?;
        let ptr_col = downcast_string(batch, "da_pointer_json")?;
        let emb_col_idx = batch
            .schema()
            .index_of("embedding")
            .map_err(|e| MemoryError::Vector(format!("missing embedding column: {}", e)))?;
        let emb_col = batch
            .column(emb_col_idx)
            .as_any()
            .downcast_ref::<FixedSizeListArray>()
            .ok_or_else(|| MemoryError::Vector("embedding not FixedSizeListArray".into()))?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let kind = MemoryKind::parse(kind_col.value(i))
                .ok_or_else(|| MemoryError::Vector(format!("bad kind: {}", kind_col.value(i))))?;
            let source = MemorySource::parse(src_col.value(i)).ok_or_else(|| {
                MemoryError::Vector(format!("bad source: {}", src_col.value(i)))
            })?;
            let metadata: serde_json::Value = serde_json::from_str(meta_col.value(i))?;
            let da_pointer = if ptr_col.is_null(i) {
                None
            } else {
                Some(serde_json::from_str(ptr_col.value(i))?)
            };
            let emb_value = emb_col.value(i);
            let emb_arr = emb_value
                .as_any()
                .downcast_ref::<Float32Array>()
                .ok_or_else(|| MemoryError::Vector("embedding cell not Float32".into()))?;
            let embedding: Vec<f32> = emb_arr.values().to_vec();
            out.push(MemoryRecord {
                id: id_col.value(i).to_string(),
                agent_did: did_col.value(i).to_string(),
                created_at_ms: ts_col.value(i),
                kind,
                source,
                text: text_col.value(i).to_string(),
                embedding: Some(embedding),
                metadata,
                da_pointer,
            });
        }
        Ok(out)
    }
}

fn downcast_string<'a>(batch: &'a RecordBatch, name: &str) -> Result<&'a StringArray> {
    let idx = batch
        .schema()
        .index_of(name)
        .map_err(|e| MemoryError::Vector(format!("missing column {}: {}", name, e)))?;
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| MemoryError::Vector(format!("column {} not Utf8", name)))
}

fn downcast_i64<'a>(batch: &'a RecordBatch, name: &str) -> Result<&'a Int64Array> {
    let idx = batch
        .schema()
        .index_of(name)
        .map_err(|e| MemoryError::Vector(format!("missing column {}: {}", name, e)))?;
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| MemoryError::Vector(format!("column {} not Int64", name)))
}

fn escape_sql_literal(s: &str) -> String {
    // Simple SQL-literal escape for single quotes — sufficient for UUIDs and
    // DIDs that we generate ourselves. The `agent_did` is restricted to the
    // `did:tenzro:...` shape upstream so it never contains a stray quote in
    // practice; this keeps the row-update path safe even if it ever does.
    s.replace('\'', "''")
}

fn build_where_sql(filter: &MemoryFilter) -> String {
    let mut clauses: Vec<String> = Vec::new();
    clauses.push(format!(
        "agent_did = '{}'",
        escape_sql_literal(&filter.agent_did)
    ));
    if let Some(k) = filter.kind {
        clauses.push(format!("kind = '{}'", escape_sql_literal(k.as_str())));
    }
    if let Some(min) = filter.min_created_at_ms {
        clauses.push(format!("created_at_ms >= {}", min));
    }
    if let Some(max) = filter.max_created_at_ms {
        clauses.push(format!("created_at_ms <= {}", max));
    }
    clauses.join(" AND ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rec(did: &str, text: &str, emb: Vec<f32>, kind: MemoryKind) -> MemoryRecord {
        MemoryRecord::new(
            did,
            kind,
            MemorySource::Controller,
            text,
            Some(emb),
            serde_json::json!({}),
        )
    }

    #[tokio::test]
    async fn insert_and_knn_returns_nearest_first() {
        let dir = tempdir().unwrap();
        let backend = LanceVectorBackend::new(dir.path(), 4).await.unwrap();
        let near = rec("did:tenzro:machine:a", "near", vec![1.0, 0.0, 0.0, 0.0], MemoryKind::Granted);
        let far = rec("did:tenzro:machine:a", "far", vec![0.0, 1.0, 0.0, 0.0], MemoryKind::Granted);
        backend.insert(&near).await.unwrap();
        backend.insert(&far).await.unwrap();

        let f = MemoryFilter::for_agent("did:tenzro:machine:a");
        let res = backend
            .search_by_vector(&[1.0, 0.0, 0.0, 0.0], 2, &f)
            .await
            .unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].text, "near");
        assert_eq!(res[1].text, "far");
    }

    #[tokio::test]
    async fn knn_filters_by_agent_did() {
        let dir = tempdir().unwrap();
        let backend = LanceVectorBackend::new(dir.path(), 3).await.unwrap();
        let a = rec("did:tenzro:machine:alpha", "alpha", vec![0.5, 0.5, 0.5], MemoryKind::Granted);
        let b = rec("did:tenzro:machine:beta", "beta", vec![0.5, 0.5, 0.5], MemoryKind::Granted);
        backend.insert(&a).await.unwrap();
        backend.insert(&b).await.unwrap();

        let f = MemoryFilter::for_agent("did:tenzro:machine:alpha");
        let res = backend
            .search_by_vector(&[0.5, 0.5, 0.5], 5, &f)
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].text, "alpha");
    }

    #[tokio::test]
    async fn knn_filters_by_kind() {
        let dir = tempdir().unwrap();
        let backend = LanceVectorBackend::new(dir.path(), 2).await.unwrap();
        let g = rec("did:tenzro:machine:x", "g", vec![1.0, 0.0], MemoryKind::Granted);
        let s = rec("did:tenzro:machine:x", "s", vec![1.0, 0.0], MemoryKind::SelfNoted);
        backend.insert(&g).await.unwrap();
        backend.insert(&s).await.unwrap();
        let mut f = MemoryFilter::for_agent("did:tenzro:machine:x");
        f.kind = Some(MemoryKind::SelfNoted);
        let res = backend.search_by_vector(&[1.0, 0.0], 5, &f).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].text, "s");
    }

    #[tokio::test]
    async fn dim_mismatch_rejected() {
        let dir = tempdir().unwrap();
        let backend = LanceVectorBackend::new(dir.path(), 4).await.unwrap();
        let bad = rec("did:tenzro:machine:a", "bad", vec![1.0, 0.0], MemoryKind::Granted);
        let err = backend.insert(&bad).await.unwrap_err();
        assert!(matches!(err, MemoryError::DimMismatch { expected: 4, actual: 2 }));
    }
}
