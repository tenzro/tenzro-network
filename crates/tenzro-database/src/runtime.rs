//! The engine-agnostic runtime seam.
//!
//! [`DatabaseRegistry`] tracks *what* databases exist and *where* their
//! partitions land; it never spins an engine up or runs a query. That is a
//! [`DatabaseEngine`] backend concern, implemented at the node layer where the
//! external-process orchestration (Postgres/Qdrant/Valkey) and the embedded
//! engines (Lance/Tantivy) actually live. This mirrors the tenzro-training
//! split: the protocol crate owns the registry and placement rules, the node
//! layer owns the tensor library / the external process.
//!
//! Keeping the trait here — deps `async_trait` + `serde_json` only — lets the
//! registry hand a partition to a runtime without either crate depending on the
//! other's engine internals. A node constructs the concrete backend (which links
//! the engine driver), registers it against an engine id, and dispatches
//! [`PartitionHandle`]s to it.
//!
//! [`DatabaseRegistry`]: crate::database::DatabaseRegistry

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::database::DatabaseDescriptor;
use crate::error::Result;

/// The subset of a database a single runtime backend serves: one partition of
/// one database, with the engine-specific config the descriptor carried.
///
/// The registry produces these from a [`DatabaseDescriptor`] plus a partition
/// index; the runtime backend interprets `engine_config` (schema name, vector
/// dimension, collection name, …) to spin the partition up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionHandle {
    /// Database this partition belongs to.
    pub database_id: String,
    /// Catalog id of the engine that serves it.
    pub engine_id: String,
    /// Zero-based partition index. Always 0 for a local or embedded database.
    pub partition_index: usize,
    /// Engine-specific config, opaque to the registry, interpreted by the
    /// runtime backend.
    pub engine_config: serde_json::Value,
}

impl PartitionHandle {
    /// Builds the handle for `partition_index` of `desc`.
    pub fn from_descriptor(desc: &DatabaseDescriptor, partition_index: usize) -> Self {
        Self {
            database_id: desc.database_id.clone(),
            engine_id: desc.engine_id.clone(),
            partition_index,
            engine_config: desc.engine_config.clone(),
        }
    }
}

/// One executable request against a partition. Opaque at the protocol layer —
/// the runtime backend parses `body` in whatever dialect the engine speaks
/// (SQL, a vector-search request, a key-value op). The registry never inspects
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRequest {
    /// Database to run against.
    pub database_id: String,
    /// Partition to target. A caller that does not know the partition passes 0
    /// and lets the backend fan out for a network-sharded database.
    pub partition_index: usize,
    /// Engine-dialect request payload, opaque to the registry.
    pub body: serde_json::Value,
}

/// The result of a [`QueryRequest`]. Opaque rows the runtime backend shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Engine-dialect result payload, opaque to the registry.
    pub body: serde_json::Value,
}

/// Health of a single partition as reported by its runtime backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionHealth {
    /// The partition is up and serving.
    Serving,
    /// The partition is spinning up and not yet ready.
    Starting,
    /// The partition is not serving.
    Down,
}

/// A node-layer backend that spins up, serves, and tears down one engine's
/// partitions.
///
/// The registry hands a [`PartitionHandle`] to `start_partition`; the backend
/// links the engine driver, brings the partition up, and answers `query`
/// against it. External-process engines (Postgres/Qdrant/Valkey) orchestrate a
/// separate server; embedded engines (Lance/Tantivy) serve in-process. Either
/// way the trait is the same — the registry does not care which.
#[async_trait]
pub trait DatabaseEngine: Send + Sync {
    /// The catalog engine id this backend serves (see [`crate::catalog`]).
    fn engine_id(&self) -> &str;

    /// Brings `handle`'s partition up and makes it queryable. Idempotent: a
    /// backend that already serves the partition returns `Ok` without
    /// restarting it.
    async fn start_partition(&self, handle: &PartitionHandle) -> Result<()>;

    /// Tears the partition down and releases its resources. Idempotent: tearing
    /// down a partition that is not up returns `Ok`.
    async fn stop_partition(&self, handle: &PartitionHandle) -> Result<()>;

    /// Runs `request` against a partition this backend serves.
    async fn query(&self, request: &QueryRequest) -> Result<QueryResponse>;

    /// Reports the health of `handle`'s partition.
    async fn partition_health(&self, handle: &PartitionHandle) -> Result<PartitionHealth>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::PlacementMode;

    fn descriptor() -> DatabaseDescriptor {
        DatabaseDescriptor {
            database_id: "db-1".to_string(),
            engine_id: crate::catalog::engine_ids::POSTGRES.to_string(),
            placement: PlacementMode::Network,
            partitions: 4,
            replicas: 2,
            engine_config: serde_json::json!({ "schema": "public" }),
            access_policy: crate::access_control::AccessPolicy::owner_only(
                "did:tenzro:human:test-owner",
            ),
            confidential: None,
        }
    }

    #[test]
    fn handle_carries_config_from_descriptor() {
        let desc = descriptor();
        let handle = PartitionHandle::from_descriptor(&desc, 3);
        assert_eq!(handle.database_id, "db-1");
        assert_eq!(handle.engine_id, crate::catalog::engine_ids::POSTGRES);
        assert_eq!(handle.partition_index, 3);
        assert_eq!(handle.engine_config, serde_json::json!({ "schema": "public" }));
    }
}
