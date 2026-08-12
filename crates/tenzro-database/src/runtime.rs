//! The engine-agnostic runtime seam and the replicated query router.
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
//! [`QueryRouter`] sits between the registry and per-holder dispatch: reads go
//! to one holder with deterministic failover, writes fan out to every holder
//! under a [`WriteConsistency`] level.
//!
//! [`DatabaseRegistry`]: crate::database::DatabaseRegistry

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::database::{DatabaseDescriptor, DatabaseRegistry};
use crate::error::{DatabaseError, Result};

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
    ///
    /// Same `json_value_serde` treatment as
    /// [`crate::database::DatabaseDescriptor::engine_config`] — see there.
    #[serde(with = "tenzro_types::primitives::json_value_serde")]
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

/// How many holder acks a fanned-out write needs before it counts as applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteConsistency {
    /// Every holder must ack.
    All,
    /// A majority — `floor(n/2) + 1` of `n` holders — must ack.
    #[default]
    Quorum,
}

impl WriteConsistency {
    /// The ack count this level requires over `holders` targets.
    pub fn required_acks(&self, holders: usize) -> usize {
        match self {
            WriteConsistency::All => holders,
            WriteConsistency::Quorum => holders / 2 + 1,
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
    /// Ack level for [`QueryRouter::route_write`]. Ignored on the read path.
    pub consistency: WriteConsistency,
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

/// Sends one request to one holder of a partition. The node layer implements
/// this over its transport (local engine call for self, network RPC for a
/// remote holder); the router never knows which.
#[async_trait]
pub trait HolderDispatch: Send + Sync {
    /// Runs `request` on the holder identified by `endpoint_id`.
    async fn dispatch(&self, endpoint_id: &str, request: &QueryRequest) -> Result<QueryResponse>;
}

/// The outcome of a fanned-out write that met its consistency level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReceipt {
    /// The first successful holder response.
    pub response: QueryResponse,
    /// Holders that acked the write.
    pub acked_holders: Vec<String>,
    /// Holders whose dispatch failed. Non-empty is legal under `Quorum`.
    pub failed_holders: Vec<String>,
}

/// Routes queries over a partition's replicated holder set.
///
/// Reads try holders in placement order — local tier HRW rank first, then
/// network tier — and return the first success. There is no cross-holder
/// health registry yet, so a dispatch failure *is* the health signal; ordering
/// stays deterministic so co-located callers hit the same primary. Writes fan
/// out to every holder and enforce the request's [`WriteConsistency`].
pub struct QueryRouter {
    registry: Arc<DatabaseRegistry>,
    dispatch: Arc<dyn HolderDispatch>,
}

impl QueryRouter {
    /// A router over `registry`'s placements dispatching through `dispatch`.
    pub fn new(registry: Arc<DatabaseRegistry>, dispatch: Arc<dyn HolderDispatch>) -> Self {
        Self { registry, dispatch }
    }

    fn holders_for(&self, request: &QueryRequest) -> Result<Vec<String>> {
        let placement = self
            .registry
            .get_partition(&request.database_id, request.partition_index)?;
        let holders = placement.all_holders();
        if holders.is_empty() {
            // Possible after mark_holder_lost drains the set entirely.
            return Err(DatabaseError::InsufficientProviders {
                database_id: request.database_id.clone(),
                partition_index: request.partition_index,
                required: 1,
                available: 0,
            });
        }
        Ok(holders)
    }

    /// Runs a read against one holder, failing over in placement order.
    pub async fn route_read(&self, request: &QueryRequest) -> Result<QueryResponse> {
        let holders = self.holders_for(request)?;
        let mut last_err = None;
        for holder in &holders {
            match self.dispatch.dispatch(holder, request).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::warn!(
                        database_id = %request.database_id,
                        partition_index = request.partition_index,
                        holder = %holder,
                        error = %e,
                        "read dispatch failed; trying next holder"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("holders_for guarantees at least one holder"))
    }

    /// Fans a write out to every holder of the partition, requiring the
    /// request's [`WriteConsistency`] ack count. Failures beyond what the
    /// level tolerates return [`DatabaseError::WriteConsistencyNotMet`] naming
    /// the failed holders.
    pub async fn route_write(&self, request: &QueryRequest) -> Result<WriteReceipt> {
        let holders = self.holders_for(request)?;
        let required = request.consistency.required_acks(holders.len());

        let mut acked_holders = Vec::new();
        let mut failed_holders = Vec::new();
        let mut response = None;
        for holder in &holders {
            match self.dispatch.dispatch(holder, request).await {
                Ok(resp) => {
                    if response.is_none() {
                        response = Some(resp);
                    }
                    acked_holders.push(holder.clone());
                }
                Err(e) => {
                    tracing::warn!(
                        database_id = %request.database_id,
                        partition_index = request.partition_index,
                        holder = %holder,
                        error = %e,
                        "write dispatch failed"
                    );
                    failed_holders.push(holder.clone());
                }
            }
        }

        if acked_holders.len() < required {
            return Err(DatabaseError::WriteConsistencyNotMet {
                database_id: request.database_id.clone(),
                partition_index: request.partition_index,
                required,
                acked: acked_holders.len(),
                failed_holders,
            });
        }
        Ok(WriteReceipt {
            response: response.expect("required >= 1 acks implies a response"),
            acked_holders,
            failed_holders,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::database::{PlacementMode, ReplicationPolicy};
    use crate::placement::TieredCandidate;

    fn descriptor() -> DatabaseDescriptor {
        DatabaseDescriptor {
            database_id: "db-1".to_string(),
            engine_id: crate::catalog::engine_ids::POSTGRES.to_string(),
            placement: PlacementMode::Network,
            partitions: 4,
            replication: ReplicationPolicy::default(),
            engine_config: serde_json::json!({ "schema": "public" }),
            access_policy: crate::access_control::AccessPolicy::owner_only(
                "did:tenzro:human:test-owner",
            ),
            pricing: crate::pricing::DatabasePricing::free(),
            access: tenzro_types::resource_access::ResourceAccess::Private,
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
        assert_eq!(
            handle.engine_config,
            serde_json::json!({ "schema": "public" })
        );
    }

    #[test]
    fn quorum_math() {
        assert_eq!(WriteConsistency::Quorum.required_acks(1), 1);
        assert_eq!(WriteConsistency::Quorum.required_acks(2), 2);
        assert_eq!(WriteConsistency::Quorum.required_acks(3), 2);
        assert_eq!(WriteConsistency::Quorum.required_acks(4), 3);
        assert_eq!(WriteConsistency::All.required_acks(1), 1);
        assert_eq!(WriteConsistency::All.required_acks(2), 2);
        assert_eq!(WriteConsistency::All.required_acks(3), 3);
        assert_eq!(WriteConsistency::All.required_acks(4), 4);
    }

    struct ScriptedDispatch {
        fail: HashSet<String>,
    }

    #[async_trait]
    impl HolderDispatch for ScriptedDispatch {
        async fn dispatch(
            &self,
            endpoint_id: &str,
            _request: &QueryRequest,
        ) -> Result<QueryResponse> {
            if self.fail.contains(endpoint_id) {
                return Err(DatabaseError::Backend(format!("{endpoint_id} down")));
            }
            Ok(QueryResponse {
                body: serde_json::json!({ "served_by": endpoint_id }),
            })
        }
    }

    fn router_with_three_holders(fail: &[&str]) -> (QueryRouter, Vec<String>) {
        let registry = Arc::new(DatabaseRegistry::new());
        let cands: Vec<TieredCandidate> = (0..5)
            .map(|i| TieredCandidate::direct(format!("net-{i}")))
            .collect();
        let mut desc = descriptor();
        desc.partitions = 1;
        desc.replication = ReplicationPolicy {
            min_replication: 3,
            max_replication: 4,
        };
        registry.create_database(desc, &cands).unwrap();
        let holders = registry.get_partition("db-1", 0).unwrap().all_holders();
        let fail: HashSet<String> = fail.iter().map(|s| s.to_string()).collect();
        let router = QueryRouter::new(registry, Arc::new(ScriptedDispatch { fail }));
        (router, holders)
    }

    fn request(consistency: WriteConsistency) -> QueryRequest {
        QueryRequest {
            database_id: "db-1".to_string(),
            partition_index: 0,
            consistency,
            body: serde_json::json!({ "sql": "select 1" }),
        }
    }

    #[tokio::test]
    async fn read_fails_over_past_dead_primary() {
        // HRW is deterministic over a fixed candidate set, so two builds see
        // the same holder order.
        let (router, holders) = router_with_three_holders(&[]);
        let resp = router
            .route_read(&request(WriteConsistency::Quorum))
            .await
            .unwrap();
        assert_eq!(resp.body["served_by"], holders[0].as_str());

        let (router_dead, _) = router_with_three_holders(&[holders[0].as_str()]);
        let resp = router_dead
            .route_read(&request(WriteConsistency::Quorum))
            .await
            .unwrap();
        assert_eq!(resp.body["served_by"], holders[1].as_str());
    }

    #[tokio::test]
    async fn read_returns_error_when_all_holders_fail() {
        let (_, holders) = router_with_three_holders(&[]);
        let fails: Vec<&str> = holders.iter().map(|s| s.as_str()).collect();
        let (router, _) = router_with_three_holders(&fails);
        let err = router
            .route_read(&request(WriteConsistency::Quorum))
            .await
            .unwrap_err();
        assert!(matches!(err, DatabaseError::Backend(_)));
    }

    #[tokio::test]
    async fn quorum_write_tolerates_one_of_three_failing() {
        let (_, holders) = router_with_three_holders(&[]);
        let (router, _) = router_with_three_holders(&[holders[2].as_str()]);
        let receipt = router
            .route_write(&request(WriteConsistency::Quorum))
            .await
            .unwrap();
        assert_eq!(receipt.acked_holders.len(), 2);
        assert_eq!(receipt.failed_holders, vec![holders[2].clone()]);
        assert_eq!(receipt.response.body["served_by"], holders[0].as_str());
    }

    #[tokio::test]
    async fn all_write_fails_on_any_holder_failure() {
        let (_, holders) = router_with_three_holders(&[]);
        let (router, _) = router_with_three_holders(&[holders[1].as_str()]);
        let err = router
            .route_write(&request(WriteConsistency::All))
            .await
            .unwrap_err();
        match err {
            DatabaseError::WriteConsistencyNotMet {
                required,
                acked,
                failed_holders,
                ..
            } => {
                assert_eq!(required, 3);
                assert_eq!(acked, 2);
                assert_eq!(failed_holders, vec![holders[1].clone()]);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn quorum_write_fails_when_majority_down() {
        let (_, holders) = router_with_three_holders(&[]);
        let fails = [holders[0].as_str(), holders[2].as_str()];
        let (router, _) = router_with_three_holders(&fails);
        let err = router
            .route_write(&request(WriteConsistency::Quorum))
            .await
            .unwrap_err();
        match err {
            DatabaseError::WriteConsistencyNotMet {
                required,
                acked,
                failed_holders,
                ..
            } => {
                assert_eq!(required, 2);
                assert_eq!(acked, 1);
                assert_eq!(failed_holders, vec![holders[0].clone(), holders[2].clone()]);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }
}
