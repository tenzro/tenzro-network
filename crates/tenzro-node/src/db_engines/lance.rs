//! Lance driver — embedded vector store, in-process.
//!
//! Unlike the external engines, Lance runs inside the node. Each partition is a
//! Lance dataset directory under `{root}/{database_id}_{partition_index}/`, one
//! LanceDB connection per partition. `start_partition` opens (creating the dir)
//! the connection; `stop_partition` drops the in-memory connection (the data on
//! disk is left intact — dropping a partition's data is an explicit `drop` op).
//!
//! The table schema is fixed: `id: Utf8`, `payload: Utf8` (opaque JSON the
//! caller stores alongside the vector), `embedding: FixedSizeList<Float32>(dim)`.
//! The query `body` is `{ "op": "add" | "search" | "count", ... }`:
//! - `add`:    `{ "op": "add", "rows": [ {id, payload?, vector}, ... ] }`
//! - `search`: `{ "op": "search", "vector": [...], "limit": N }`
//! - `count`:  `{ "op": "count" }`

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use arrow_array::{Array, FixedSizeListArray, Float32Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use async_trait::async_trait;
use futures_util::TryStreamExt;
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::{Connection, Table};
use serde::Deserialize;
use tenzro_database::{
    catalog::engine_ids, DatabaseEngine, DatabaseError, PartitionHandle, PartitionHealth,
    QueryRequest, QueryResponse, Result,
};
use tokio::sync::Mutex;

const TABLE_NAME: &str = "records";

/// An embedded Lance vector store rooted at `root`.
pub struct LanceEngine {
    root: PathBuf,
    /// Per-partition open connections, keyed by dataset dir name.
    connections: Mutex<HashMap<String, Arc<Connection>>>,
}

impl LanceEngine {
    /// Roots the store at `root` (`{data_dir}/databases/lance`). Partitions land
    /// in subdirectories under it.
    pub fn new(root: PathBuf) -> Self {
        Self { root, connections: Mutex::new(HashMap::new()) }
    }

    fn partition_key(database_id: &str, partition_index: usize) -> String {
        format!("{database_id}_{partition_index}")
    }

    fn dimension(handle: &PartitionHandle) -> Result<usize> {
        let cfg: LanceCfg = serde_json::from_value(handle.engine_config.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("lance config: {e}")))?;
        cfg.dimension
            .ok_or_else(|| DatabaseError::InvalidRequest("lance config missing dimension".into()))
    }

    async fn open_connection(&self, key: &str) -> Result<Arc<Connection>> {
        {
            let map = self.connections.lock().await;
            if let Some(c) = map.get(key) {
                return Ok(c.clone());
            }
        }
        let dir = self.root.join(key);
        std::fs::create_dir_all(&dir)
            .map_err(|e| DatabaseError::Backend(format!("lance mkdir {dir:?}: {e}")))?;
        let uri = dir
            .to_str()
            .ok_or_else(|| DatabaseError::Backend(format!("non-utf8 lance path: {dir:?}")))?;
        let conn = lancedb::connect(uri)
            .execute()
            .await
            .map_err(|e| DatabaseError::Backend(format!("lance connect: {e}")))?;
        let conn = Arc::new(conn);
        self.connections.lock().await.insert(key.to_string(), conn.clone());
        Ok(conn)
    }

    fn schema(dim: usize) -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Utf8, false),
            Field::new("payload", DataType::Utf8, true),
            Field::new(
                "embedding",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), dim as i32),
                false,
            ),
        ]))
    }

    async fn open_table(&self, conn: &Connection) -> Result<Option<Table>> {
        let names = conn
            .table_names()
            .execute()
            .await
            .map_err(|e| DatabaseError::Backend(format!("lance table_names: {e}")))?;
        if !names.iter().any(|n| n == TABLE_NAME) {
            return Ok(None);
        }
        let tbl = conn
            .open_table(TABLE_NAME)
            .execute()
            .await
            .map_err(|e| DatabaseError::Backend(format!("lance open_table: {e}")))?;
        Ok(Some(tbl))
    }

    fn rows_to_batch(rows: &[LanceRow], dim: usize) -> Result<RecordBatch> {
        let mut ids = Vec::with_capacity(rows.len());
        let mut payloads: Vec<Option<String>> = Vec::with_capacity(rows.len());
        let mut flat: Vec<f32> = Vec::with_capacity(rows.len() * dim);
        for r in rows {
            if r.vector.len() != dim {
                return Err(DatabaseError::InvalidRequest(format!(
                    "lance vector dim {} != table dim {}",
                    r.vector.len(),
                    dim
                )));
            }
            ids.push(r.id.clone());
            payloads.push(r.payload.as_ref().map(|p| p.to_string()));
            flat.extend_from_slice(&r.vector);
        }
        let id_arr = Arc::new(StringArray::from(ids));
        let payload_arr = Arc::new(StringArray::from(payloads));
        let item_field = Arc::new(Field::new("item", DataType::Float32, true));
        let inner = Arc::new(Float32Array::from(flat));
        let emb_arr = Arc::new(
            FixedSizeListArray::try_new(item_field, dim as i32, inner, None)
                .map_err(|e| DatabaseError::Backend(format!("lance list array: {e}")))?,
        );
        RecordBatch::try_new(Self::schema(dim), vec![id_arr, payload_arr, emb_arr])
            .map_err(|e| DatabaseError::Backend(format!("lance batch: {e}")))
    }

    fn batch_to_json(batch: &RecordBatch) -> Vec<serde_json::Value> {
        let n = batch.num_rows();
        let id_col = batch.column_by_name("id").and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let payload_col =
            batch.column_by_name("payload").and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let id = id_col.map(|c| c.value(i).to_string()).unwrap_or_default();
            let payload = payload_col.and_then(|c| {
                if c.is_null(i) {
                    None
                } else {
                    serde_json::from_str::<serde_json::Value>(c.value(i)).ok()
                }
            });
            out.push(serde_json::json!({ "id": id, "payload": payload }));
        }
        out
    }
}

#[async_trait]
impl DatabaseEngine for LanceEngine {
    fn engine_id(&self) -> &str {
        engine_ids::LANCE
    }

    async fn start_partition(&self, handle: &PartitionHandle) -> Result<()> {
        // Validate the config carries a dimension and open (create) the
        // connection dir. The table itself is created on first `add`.
        Self::dimension(handle)?;
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        self.open_connection(&key).await?;
        Ok(())
    }

    async fn stop_partition(&self, handle: &PartitionHandle) -> Result<()> {
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        self.connections.lock().await.remove(&key);
        Ok(())
    }

    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let op: LanceOp = serde_json::from_value(request.body.clone())
            .map_err(|e| DatabaseError::InvalidRequest(format!("lance op: {e}")))?;
        let key = Self::partition_key(&request.database_id, request.partition_index);
        let conn = self.open_connection(&key).await?;

        match op {
            LanceOp::Add { rows } => {
                if rows.is_empty() {
                    return Err(DatabaseError::InvalidRequest("lance add: no rows".into()));
                }
                let dim = rows[0].vector.len();
                if dim == 0 {
                    return Err(DatabaseError::InvalidRequest("lance add: empty vector".into()));
                }
                let batch = Self::rows_to_batch(&rows, dim)?;
                match self.open_table(&conn).await? {
                    Some(tbl) => {
                        tbl.add(vec![batch])
                            .execute()
                            .await
                            .map_err(|e| DatabaseError::Query(format!("lance add: {e}")))?;
                    }
                    None => {
                        conn.create_table(TABLE_NAME, vec![batch])
                            .execute()
                            .await
                            .map_err(|e| DatabaseError::Query(format!("lance create_table: {e}")))?;
                    }
                }
                Ok(QueryResponse { body: serde_json::json!({ "added": rows.len() }) })
            }
            LanceOp::Search { vector, limit } => {
                let Some(tbl) = self.open_table(&conn).await? else {
                    return Ok(QueryResponse { body: serde_json::json!({ "rows": [] }) });
                };
                let stream = tbl
                    .query()
                    .nearest_to(vector)
                    .map_err(|e| DatabaseError::Query(format!("lance nearest_to: {e}")))?
                    .limit(limit.max(1))
                    .execute()
                    .await
                    .map_err(|e| DatabaseError::Query(format!("lance search: {e}")))?;
                let batches: Vec<RecordBatch> = stream
                    .try_collect()
                    .await
                    .map_err(|e| DatabaseError::Query(format!("lance collect: {e}")))?;
                let mut rows = Vec::new();
                for b in &batches {
                    rows.extend(Self::batch_to_json(b));
                }
                Ok(QueryResponse { body: serde_json::json!({ "rows": rows }) })
            }
            LanceOp::Count => {
                let Some(tbl) = self.open_table(&conn).await? else {
                    return Ok(QueryResponse { body: serde_json::json!({ "count": 0 }) });
                };
                let count = tbl
                    .count_rows(None)
                    .await
                    .map_err(|e| DatabaseError::Query(format!("lance count: {e}")))?;
                Ok(QueryResponse { body: serde_json::json!({ "count": count }) })
            }
        }
    }

    async fn partition_health(&self, handle: &PartitionHandle) -> Result<PartitionHealth> {
        let key = Self::partition_key(&handle.database_id, handle.partition_index);
        match self.open_connection(&key).await {
            Ok(_) => Ok(PartitionHealth::Serving),
            Err(_) => Ok(PartitionHealth::Down),
        }
    }
}

/// The subset of the engine config the Lance driver reads.
#[derive(Debug, Deserialize)]
struct LanceCfg {
    #[serde(default)]
    dimension: Option<usize>,
}

/// A single row to add: id, opaque JSON payload, and the embedding vector.
#[derive(Debug, Deserialize)]
struct LanceRow {
    id: String,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    vector: Vec<f32>,
}

/// A Lance query op.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum LanceOp {
    /// Add rows to the partition's table.
    Add { rows: Vec<LanceRow> },
    /// kNN search by query vector.
    Search {
        vector: Vec<f32>,
        #[serde(default = "default_limit")]
        limit: usize,
    },
    /// Row count.
    Count,
}

fn default_limit() -> usize {
    10
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tenzro_database::WriteConsistency;

    #[tokio::test]
    async fn add_search_count_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = LanceEngine::new(dir.path().to_path_buf());
        let handle = PartitionHandle {
            database_id: "kb".into(),
            engine_id: engine_ids::LANCE.into(),
            partition_index: 0,
            engine_config: serde_json::json!({ "dimension": 3 }),
        };
        engine.start_partition(&handle).await.unwrap();

        let add = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            consistency: WriteConsistency::default(),
            body: serde_json::json!({
                "op": "add",
                "rows": [
                    { "id": "a", "payload": {"t": "near"}, "vector": [1.0, 0.0, 0.0] },
                    { "id": "b", "payload": {"t": "far"},  "vector": [0.0, 1.0, 0.0] }
                ]
            }),
        };
        let r = engine.query(&add).await.unwrap();
        assert_eq!(r.body["added"], 2);

        let search = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            consistency: WriteConsistency::default(),
            body: serde_json::json!({ "op": "search", "vector": [1.0, 0.0, 0.0], "limit": 1 }),
        };
        let r = engine.query(&search).await.unwrap();
        let rows = r.body["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "a");

        let count = QueryRequest {
            database_id: "kb".into(),
            partition_index: 0,
            consistency: WriteConsistency::default(),
            body: serde_json::json!({ "op": "count" }),
        };
        let r = engine.query(&count).await.unwrap();
        assert_eq!(r.body["count"], 2);
    }

    #[tokio::test]
    async fn search_before_add_returns_empty() {
        let dir = tempdir().unwrap();
        let engine = LanceEngine::new(dir.path().to_path_buf());
        let handle = PartitionHandle {
            database_id: "empty".into(),
            engine_id: engine_ids::LANCE.into(),
            partition_index: 0,
            engine_config: serde_json::json!({ "dimension": 2 }),
        };
        engine.start_partition(&handle).await.unwrap();
        let search = QueryRequest {
            database_id: "empty".into(),
            partition_index: 0,
            consistency: WriteConsistency::default(),
            body: serde_json::json!({ "op": "search", "vector": [1.0, 0.0] }),
        };
        let r = engine.query(&search).await.unwrap();
        assert!(r.body["rows"].as_array().unwrap().is_empty());
    }
}
