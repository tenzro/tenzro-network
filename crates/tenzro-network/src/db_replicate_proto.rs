//! Database replicated-write wire protocol for Tenzro Network.
//!
//! A single `libp2p::request_response` behaviour carries one RPC method —
//! `ApplyWrite` (serving holder → peer holder: "apply this write to your copy
//! of the partition and acknowledge"). The response is the engine's own reply
//! body plus an ack, so the caller can enforce write consistency (Quorum / All)
//! by counting acknowledgments across the partition's holder set.
//!
//! ## Why this shape (vs. the MPC relay's Ack-only pattern)
//!
//! The MPC relay (`mpc_relay.rs`) is fire-and-forget: real replies flow back
//! over a separate subscriber channel. A replicated write is genuinely
//! request→**reply-carrying** — the requesting holder must know whether each
//! peer holder actually applied the write before it can declare quorum. So the
//! outbound side uses per-request `oneshot` correlation (keyed by
//! `OutboundRequestId`) — the caller awaits its own reply — exactly like the
//! committee-DA relay (`da_committee_relay.rs`).
//!
//! ## Why the payload is an opaque byte body
//!
//! `tenzro-network` does **not** depend on `tenzro-database`, so it cannot name
//! `QueryRequest` / `QueryResponse`. The node-layer adapter
//! (`tenzro_node::db_holder_dispatch` — the only crate that depends on both
//! database and network) serializes the request body into `body` here and
//! decodes it on the far side. The scalar fields the transport routes on
//! (`database_id`, `partition_index`) travel in the clear.
//!
//! ## Concurrency limits
//!   * Per-peer inbound concurrent stream cap: 8 (reject overflow, do not queue).
//!   * Max request / response size: 16 MiB each.
//!   * Outbound request timeout: 30 s.

use libp2p::{
    StreamProtocol,
    request_response::{self, ProtocolSupport},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Stream-protocol identifier for the database replicated-write RPC.
///
/// The version segment is required by libp2p's `StreamProtocol` rules.
/// Internal Tenzro identifiers omit version segments per project conventions;
/// this constant is the libp2p exception.
pub const DB_REPLICATE_PROTOCOL: &str = "/tenzro/db/replicate/1.0.0";

/// Per-peer inbound concurrent stream cap. Overflow MUST be rejected with
/// `ServerBusy`, not queued.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 8;

/// Outbound request timeout for a replicated write apply.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Max request size (16 MiB).
pub const MAX_REQUEST_SIZE: usize = 16 * 1024 * 1024;

/// Max response size (16 MiB).
pub const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// Database replicated-write request envelope. Size-bounded by the codec's
/// [`MAX_REQUEST_SIZE`] cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbReplicateRequest {
    /// Serving holder asks this peer holder to apply a write to its copy of the
    /// partition. On success the peer replies [`DbReplicateResponse::Applied`]
    /// carrying the engine's own response body.
    ApplyWrite {
        /// Logical database id the write targets.
        database_id: String,
        /// Partition index within the database.
        partition_index: u32,
        /// Serialized engine request body (opaque to the network layer).
        body: Vec<u8>,
    },
}

/// Database replicated-write response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbReplicateResponse {
    /// Response to `ApplyWrite`: the peer applied the write and returns the
    /// engine's serialized response body.
    Applied {
        /// Serialized engine response body (opaque to the network layer).
        body: Vec<u8>,
    },

    /// Server-side error. The requester counts this holder as failed for
    /// consistency purposes.
    Error(DbReplicateError),
}

/// Errors a serving holder reports back to the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum DbReplicateError {
    /// Server is at its inbound concurrency cap.
    #[error("server busy — exceeded {limit} concurrent inbound streams from this peer")]
    ServerBusy { limit: usize },

    /// No database-replication handler is attached on the serving side.
    #[error("no database-replication handler attached")]
    NoHandler,

    /// This node does not hold the addressed partition, or the requesting peer
    /// is not a recognized holder of it.
    #[error("not a holder for {database_id}/{partition_index}")]
    NotHolder {
        database_id: String,
        partition_index: u32,
    },

    /// The engine could not apply the write. The message preserves the
    /// serving-side detail.
    #[error("database-replication engine error: {0}")]
    Engine(String),
}

/// Type alias for the libp2p request-response behaviour parameterized with our
/// wire types. Uses CBOR (`cbor4ii`) framing — the production default.
pub type DbReplicateBehaviour =
    request_response::cbor::Behaviour<DbReplicateRequest, DbReplicateResponse>;

/// Constructs a fresh database-replication `Behaviour` with production-tuned
/// config.
pub fn new_behaviour() -> DbReplicateBehaviour {
    let protocol = StreamProtocol::new(DB_REPLICATE_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    request_response::cbor::Behaviour::new(std::iter::once((protocol, ProtocolSupport::Full)), cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = DbReplicateRequest::ApplyWrite {
            database_id: "vecmem".to_string(),
            partition_index: 2,
            body: vec![1, 2, 3, 4, 5],
        };
        let bytes = bincode::serialize(&req).expect("encode");
        let decoded: DbReplicateRequest = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_round_trip() {
        let cases = vec![
            DbReplicateResponse::Applied {
                body: vec![9u8; 128],
            },
            DbReplicateResponse::Error(DbReplicateError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
            DbReplicateResponse::Error(DbReplicateError::NoHandler),
            DbReplicateResponse::Error(DbReplicateError::NotHolder {
                database_id: "vecmem".to_string(),
                partition_index: 1,
            }),
            DbReplicateResponse::Error(DbReplicateError::Engine("rocksdb closed".to_string())),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: DbReplicateResponse = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(resp, decoded);
        }
    }

    #[test]
    fn behaviour_constructs() {
        let _ = new_behaviour();
    }
}
