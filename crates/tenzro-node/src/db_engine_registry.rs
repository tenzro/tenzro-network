//! Node-side registry of live database-engine backends.
//!
//! [`tenzro_database::DatabaseRegistry`] tracks *what* databases exist and
//! *where* their partitions land; it never links an engine driver. This
//! registry is the node-layer counterpart: it holds the concrete
//! [`DatabaseEngine`] backends a node actually serves, keyed by catalog engine
//! id. A backend links its driver (Postgres/Qdrant/Valkey client, or an
//! embedded Lance/Tantivy handle) and answers queries against the partitions it
//! brought up.
//!
//! The RPC query path resolves a database's partition placement from the
//! [`tenzro_database::DatabaseRegistry`], confirms this node is a holder, then
//! dispatches the [`QueryRequest`] to the backend registered here for the
//! database's engine id. A node that serves no engine of that kind has no entry
//! and the query is answered with a routing error, not a panic — the seam is
//! wired even before any driver crate is linked.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_database::{
    DatabaseEngine, PartitionHandle, QueryRequest, QueryResponse, Result,
};

/// Live database-engine backends this node serves, keyed by catalog engine id.
#[derive(Default)]
pub struct EngineRegistry {
    backends: DashMap<String, Arc<dyn DatabaseEngine>>,
}

impl EngineRegistry {
    /// An empty registry — no engine backends linked yet.
    pub fn new() -> Self {
        Self { backends: DashMap::new() }
    }

    /// Registers `backend` under the engine id it reports. Replaces any prior
    /// backend for that engine id.
    pub fn register(&self, backend: Arc<dyn DatabaseEngine>) {
        self.backends.insert(backend.engine_id().to_string(), backend);
    }

    /// The backend serving `engine_id`, if this node runs one.
    pub fn get(&self, engine_id: &str) -> Option<Arc<dyn DatabaseEngine>> {
        self.backends.get(engine_id).map(|b| b.value().clone())
    }

    /// The catalog engine ids this node currently serves.
    pub fn serving_engine_ids(&self) -> Vec<String> {
        self.backends.iter().map(|e| e.key().clone()).collect()
    }

    /// Whether this node serves `engine_id`.
    pub fn serves(&self, engine_id: &str) -> bool {
        self.backends.contains_key(engine_id)
    }

    /// Brings up `handle`'s partition on the backend for `engine_id` (idempotent
    /// — create schema/collection/namespace for external engines, open the
    /// dataset/index dir for embedded ones). Errors if this node serves no such
    /// engine.
    pub async fn start_partition(&self, engine_id: &str, handle: &PartitionHandle) -> Result<()> {
        let backend = self.get(engine_id).ok_or_else(|| {
            tenzro_database::DatabaseError::Backend(format!(
                "this node serves no {engine_id} engine backend"
            ))
        })?;
        backend.start_partition(handle).await
    }

    /// Tears down `handle`'s partition on the backend for `engine_id`
    /// (idempotent). Errors if this node serves no such engine.
    pub async fn stop_partition(&self, engine_id: &str, handle: &PartitionHandle) -> Result<()> {
        let backend = self.get(engine_id).ok_or_else(|| {
            tenzro_database::DatabaseError::Backend(format!(
                "this node serves no {engine_id} engine backend"
            ))
        })?;
        backend.stop_partition(handle).await
    }

    /// Dispatches `request` to the backend for `engine_id`. Returns the engine's
    /// opaque response, or a query error if this node serves no such engine.
    pub async fn query(&self, engine_id: &str, request: &QueryRequest) -> Result<QueryResponse> {
        let backend = self.get(engine_id).ok_or_else(|| {
            tenzro_database::DatabaseError::Backend(format!(
                "this node serves no {engine_id} engine backend"
            ))
        })?;
        backend.query(request).await
    }
}
