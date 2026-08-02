//! Node-layer database replication transport.
//!
//! [`tenzro_database::QueryRouter`] fans a write out to every holder of a
//! partition and enforces the request's [`tenzro_database::WriteConsistency`].
//! It reaches each holder through the [`tenzro_database::HolderDispatch`] trait
//! but never knows how a holder is reached. This module is that transport:
//!
//! * **local holder** — the endpoint's `PeerId` is this node's own, so the
//!   write applies in-process against the [`crate::db_engine_registry`] backend
//!   for the database's engine id.
//! * **remote holder** — the `PeerId` belongs to a peer, so the write is
//!   carried over the `/tenzro/db/replicate` request_response protocol
//!   ([`tenzro_network::DbReplicateRequest::ApplyWrite`]) and the peer applies
//!   it against its own copy of the partition.
//!
//! The [`HolderDispatchTransport`] is the writer side. [`DbReplicateServer`] is
//! the serving side: it consumes inbound `ApplyWrite` requests, confirms this
//! node actually holds the addressed partition **and** that the request came
//! from a recognized holder of it, applies the write locally, and replies with
//! the engine's own response body. Internal replication is never re-billed —
//! the origin holder already metered the client-facing query.
//!
//! ## Endpoint id shape
//!
//! Holder endpoint ids are the `"{host}#{peer_id}"` strings that
//! `discover_cluster_members` produces; the local node's own endpoint is
//! `"self#{peer_id}"`. Everything after the `#` is the libp2p dial target; the
//! host prefix is cosmetic. Parsing keys off the last `#` so a host containing
//! a `#` cannot spoof the peer id.

use std::str::FromStr;
use std::sync::Arc;

use tenzro_database::{
    DatabaseError, DatabaseRegistry, HolderDispatch, QueryRequest, QueryResponse,
    Result as DbResult,
};
use tenzro_network::{
    DbReplicateError, DbReplicateRequest, DbReplicateResponse, NetworkService, PeerId,
};

use crate::db_engine_registry::EngineRegistry;

/// Splits a holder endpoint id into its `(host, peer_id)` halves at the last
/// `#`. Returns `None` when the endpoint carries no `#` at all.
fn split_endpoint(endpoint_id: &str) -> Option<(&str, &str)> {
    endpoint_id.rsplit_once('#')
}

/// The `PeerId` half of a holder endpoint id, parsed. The registry stores
/// endpoints as `"{host}#{peer_id}"`; the peer id after the last `#` is the
/// dial target.
fn peer_id_of(endpoint_id: &str) -> DbResult<PeerId> {
    let (_, peer) = split_endpoint(endpoint_id).ok_or_else(|| {
        DatabaseError::Backend(format!(
            "holder endpoint '{endpoint_id}' carries no peer id"
        ))
    })?;
    PeerId::from_str(peer).map_err(|e| {
        DatabaseError::Backend(format!(
            "holder endpoint '{endpoint_id}' has an unparseable peer id: {e}"
        ))
    })
}

/// Writer-side transport for [`tenzro_database::QueryRouter`]. Dispatches a
/// per-holder [`QueryRequest`] either in-process (this node) or over the
/// replication protocol (a peer).
pub struct HolderDispatchTransport {
    network: Arc<dyn NetworkService>,
    engines: Arc<EngineRegistry>,
    registry: Arc<DatabaseRegistry>,
    /// This node's own libp2p `PeerId`. An endpoint whose peer id equals this
    /// resolves to the local engine backend; every other endpoint is dialed.
    local_peer: PeerId,
}

impl HolderDispatchTransport {
    /// Construct the transport. `local_peer` is this node's libp2p peer id —
    /// the discriminator between a local apply and a wire dispatch.
    pub fn new(
        network: Arc<dyn NetworkService>,
        engines: Arc<EngineRegistry>,
        registry: Arc<DatabaseRegistry>,
        local_peer: PeerId,
    ) -> Self {
        Self {
            network,
            engines,
            registry,
            local_peer,
        }
    }

    /// The catalog engine id serving `database_id`, read from the shared
    /// [`DatabaseRegistry`]. Needed because [`EngineRegistry`] is keyed by
    /// engine id, not database id.
    fn engine_id_for(&self, database_id: &str) -> DbResult<String> {
        let desc = self.registry.get_database(database_id)?;
        Ok(desc.engine_id)
    }

    /// Apply `request` against the local engine backend for its database.
    async fn dispatch_local(&self, request: &QueryRequest) -> DbResult<QueryResponse> {
        let engine_id = self.engine_id_for(&request.database_id)?;
        self.engines.query(&engine_id, request).await
    }

    /// Carry `request` to a peer holder over `/tenzro/db/replicate` and decode
    /// its reply.
    async fn dispatch_remote(
        &self,
        peer: PeerId,
        request: &QueryRequest,
    ) -> DbResult<QueryResponse> {
        let body = serde_json::to_vec(&request.body)
            .map_err(|e| DatabaseError::Backend(format!("encode replicated-write body: {e}")))?;
        let wire = DbReplicateRequest::ApplyWrite {
            database_id: request.database_id.clone(),
            partition_index: request.partition_index as u32,
            body,
        };
        let response = self
            .network
            .db_replicate_request(peer, wire)
            .await
            .map_err(|e| DatabaseError::Backend(format!("replicated-write transport: {e}")))?;
        match response {
            DbReplicateResponse::Applied { body } => {
                let body: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
                    DatabaseError::Backend(format!("decode replicated-write response: {e}"))
                })?;
                Ok(QueryResponse { body })
            }
            DbReplicateResponse::Error(e) => Err(replicate_error_to_db(e)),
        }
    }
}

#[async_trait::async_trait]
impl HolderDispatch for HolderDispatchTransport {
    async fn dispatch(&self, endpoint_id: &str, request: &QueryRequest) -> DbResult<QueryResponse> {
        let peer = peer_id_of(endpoint_id)?;
        if peer == self.local_peer {
            self.dispatch_local(request).await
        } else {
            self.dispatch_remote(peer, request).await
        }
    }
}

/// Projects a wire [`DbReplicateError`] onto the local [`DatabaseError`] the
/// router speaks. The serving-side detail is preserved verbatim.
fn replicate_error_to_db(e: DbReplicateError) -> DatabaseError {
    match e {
        DbReplicateError::ServerBusy { limit } => DatabaseError::Backend(format!(
            "holder busy — over {limit} concurrent inbound streams"
        )),
        DbReplicateError::NoHandler => {
            DatabaseError::Backend("holder has no database-replication handler attached".into())
        }
        DbReplicateError::NotHolder {
            database_id,
            partition_index,
        } => DatabaseError::Backend(format!(
            "peer is not a holder for {database_id}/{partition_index}"
        )),
        DbReplicateError::Engine(msg) => DatabaseError::Backend(msg),
    }
}

/// Inbound serving half of the replication protocol. Consumes
/// `subscribe_db_replicate_requests()` and answers each `ApplyWrite` from the
/// local engine backend — after confirming this node holds the addressed
/// partition and the origin peer is a recognized holder of it. One task per
/// node.
pub struct DbReplicateServer {
    network: Arc<dyn NetworkService>,
    engines: Arc<EngineRegistry>,
    registry: Arc<DatabaseRegistry>,
    /// This node's own peer id — the endpoint suffix used to confirm local
    /// holdership against the partition placement.
    local_peer: PeerId,
}

impl DbReplicateServer {
    /// Construct the inbound server sharing the same engine + database
    /// registries the writer path uses, so a write received over the wire is
    /// visible to a later local read.
    pub fn new(
        network: Arc<dyn NetworkService>,
        engines: Arc<EngineRegistry>,
        registry: Arc<DatabaseRegistry>,
        local_peer: PeerId,
    ) -> Self {
        Self {
            network,
            engines,
            registry,
            local_peer,
        }
    }

    /// Subscribe to inbound requests and spawn the serving loop. Returns the
    /// task handle; the caller keeps it alive for the node's lifetime.
    pub async fn spawn(self) -> tenzro_network::Result<tokio::task::JoinHandle<()>> {
        let mut rx = self.network.subscribe_db_replicate_requests().await?;
        let handle = tokio::spawn(async move {
            while let Some(inbound) = rx.recv().await {
                let response = self.handle(inbound.peer, inbound.request).await;
                if let Err(e) = self
                    .network
                    .send_db_replicate_response(inbound.request_id, response)
                    .await
                {
                    tracing::debug!(
                        error = %e,
                        "db-replicate reply channel closed before response was sent"
                    );
                }
            }
            tracing::info!("db-replicate inbound handler stream ended");
        });
        Ok(handle)
    }

    /// Answer one inbound request. Never panics — every routing / engine
    /// failure is folded into a `DbReplicateResponse::Error`.
    async fn handle(&self, origin: PeerId, request: DbReplicateRequest) -> DbReplicateResponse {
        match request {
            DbReplicateRequest::ApplyWrite {
                database_id,
                partition_index,
                body,
            } => {
                self.apply_write(origin, database_id, partition_index, body)
                    .await
            }
        }
    }

    async fn apply_write(
        &self,
        origin: PeerId,
        database_id: String,
        partition_index: u32,
        body: Vec<u8>,
    ) -> DbReplicateResponse {
        let partition_index = partition_index as usize;

        // Resolve placement. A database we don't know about is not held here.
        let placement = match self.registry.get_partition(&database_id, partition_index) {
            Ok(p) => p,
            Err(_) => {
                return DbReplicateResponse::Error(DbReplicateError::NotHolder {
                    database_id,
                    partition_index: partition_index as u32,
                });
            }
        };
        let holders = placement.all_holders();

        // Fail closed unless BOTH sides are recognized holders: this node must
        // hold the partition, and the origin peer must be a holder too (an
        // outsider cannot inject writes into someone else's replica set).
        let local_holds = holders
            .iter()
            .any(|h| endpoint_has_peer(h, &self.local_peer));
        let origin_holds = holders.iter().any(|h| endpoint_has_peer(h, &origin));
        if !local_holds || !origin_holds {
            return DbReplicateResponse::Error(DbReplicateError::NotHolder {
                database_id,
                partition_index: partition_index as u32,
            });
        }

        let engine_id = match self.registry.get_database(&database_id) {
            Ok(desc) => desc.engine_id,
            Err(e) => return DbReplicateResponse::Error(DbReplicateError::Engine(e.to_string())),
        };

        let request_body: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return DbReplicateResponse::Error(DbReplicateError::Engine(format!(
                    "decode replicated-write body: {e}"
                )));
            }
        };
        // Consistency is a writer-side concern; the applying holder just runs
        // the write against its own copy. Default is fine here.
        let request = QueryRequest {
            database_id,
            partition_index,
            consistency: tenzro_database::WriteConsistency::default(),
            body: request_body,
        };

        match self.engines.query(&engine_id, &request).await {
            Ok(resp) => match serde_json::to_vec(&resp.body) {
                Ok(body) => DbReplicateResponse::Applied { body },
                Err(e) => DbReplicateResponse::Error(DbReplicateError::Engine(format!(
                    "encode replicated-write response: {e}"
                ))),
            },
            Err(e) => DbReplicateResponse::Error(DbReplicateError::Engine(e.to_string())),
        }
    }
}

/// Whether a holder endpoint id's peer half equals `peer`. Guards against a
/// host that embeds a `#` by matching on the last segment only.
fn endpoint_has_peer(endpoint_id: &str, peer: &PeerId) -> bool {
    split_endpoint(endpoint_id)
        .and_then(|(_, p)| PeerId::from_str(p).ok())
        .map(|p| &p == peer)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_last_hash() {
        assert_eq!(split_endpoint("self#abc"), Some(("self", "abc")));
        assert_eq!(split_endpoint("ho#st#abc"), Some(("ho#st", "abc")));
        assert_eq!(split_endpoint("no-hash"), None);
    }

    #[test]
    fn endpoint_peer_match_uses_last_segment() {
        let peer = PeerId::random();
        let endpoint = format!("some-host#{peer}");
        assert!(endpoint_has_peer(&endpoint, &peer));
        let other = PeerId::random();
        assert!(!endpoint_has_peer(&endpoint, &other));
        // A host prefix that happens to contain a valid-looking segment must
        // not spoof the match — only the last segment is the peer.
        let spoofed = format!("{peer}#{other}");
        assert!(endpoint_has_peer(&spoofed, &other));
        assert!(!endpoint_has_peer(&spoofed, &peer));
    }

    #[test]
    fn peer_id_of_rejects_missing_hash() {
        assert!(peer_id_of("no-hash").is_err());
    }
}
