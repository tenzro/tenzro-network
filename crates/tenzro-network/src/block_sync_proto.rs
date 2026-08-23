//! Block-sync wire protocol for Tenzro Network.
//!
//! A state-sync request/response protocol: a single `libp2p::request_response`
//! behaviour multiplexes all sync RPC methods as enum variants on
//! `BlockSyncRequest` / `BlockSyncResponse`.
//!
//! Why this shape over Eth CL's chunked-stream `BeaconBlocksByRange`:
//!   * Empty-block payloads are small (≪10 MiB) — chunked framing is overkill.
//!   * CBOR-over-libp2p with bounded response size is dramatically simpler.
//!   * Production HotStuff-family chains use this pattern.
//!
//! Trust model — each `Block` carries a serialized `QuorumCertificate` in
//! `header.consensus_proof.proof_data` (populated by
//! `tenzro_consensus::HotStuff2Engine::finalize_with_commit_qc`). A receiving
//! node verifies the QC against the validator set known at the certifying
//! epoch before importing the block. No additional out-of-band trust is
//! required beyond a recent validator-set commitment.
//!
//! ## Concurrency limits
//!   * Per-peer in-flight cap: 10 (Lighthouse convention)
//!   * Inbound concurrent streams per peer: 5 (reject overflow, do not queue —
//!     queueing causes timeout cascades on the requester)
//!   * Max blocks per `GetBlockRange`: 128 (matches Eth CL `MAX_REQUEST_BLOCKS_DENEB`)
//!   * Max request size: 1 MiB (CBOR codec default)
//!   * Max response size: 10 MiB (CBOR codec default). A `BlockRange` is
//!     additionally bounded by [`MAX_BLOCK_RANGE_BYTES`], because 128 blocks
//!     at the 2 MiB block limit would be 256 MiB — the count cap is not a
//!     size cap. Originally noted as "sufficient for 128
//!     empty blocks, header+body)

use libp2p::{
    StreamProtocol,
    request_response::{self, ProtocolSupport},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tenzro_types::block::Block;
use tenzro_types::primitives::{BlockHeight, Hash};

/// Stream-protocol identifier for the block-sync RPC.
///
/// The version segment is required by libp2p's `StreamProtocol` rules
/// (third-party / external surface). Internal Tenzro identifiers (gossipsub
/// topics, JSON-RPC methods) intentionally omit version segments per the
/// project's identifier conventions.
pub const BLOCK_SYNC_PROTOCOL: &str = "/tenzro/block-sync/1.0.0";

/// Maximum blocks a peer may request in a single `GetBlockRange` call.
/// Mirrors Eth CL `MAX_REQUEST_BLOCKS_DENEB` (128).
pub const MAX_BLOCKS_PER_RANGE: u32 = 128;

/// Largest `BlockRange` body a server will assemble, in bytes.
///
/// The count cap alone is not a size cap. The codec allows a 10 MiB response,
/// and the note above records the original assumption — that 10 MiB is
/// "sufficient for 128" blocks — which held only while blocks were small. A
/// block may be up to `ConsensusConfig::max_block_size` (2 MiB), so 128 of them
/// is up to 256 MiB. The response was silently truncated on the wire and the
/// requester failed decoding it:
///
///   Block-sync: starting catch-up our_height=1496 target_height=3652 count=128
///   error=IO error on outbound stream: Eof { name: "u8", expect: Small.. }
///
/// which left followers permanently stuck: every catch-up attempt asked for the
/// same oversized range and died the same way.
///
/// Set below the codec ceiling so framing overhead cannot push a legal response
/// over it. A server returning fewer blocks than asked for is normal — the
/// requester re-asks from its new height — so truncating by bytes costs a round
/// trip, not correctness.
pub const MAX_BLOCK_RANGE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum block hashes a peer may request in a single `GetBlockBodies` call.
pub const MAX_BLOCK_HASHES_PER_REQUEST: usize = 128;

/// Per-peer in-flight outbound request cap (Lighthouse `SyncManager` convention).
pub const MAX_INFLIGHT_REQUESTS_PER_PEER: usize = 10;

/// Per-peer inbound concurrent stream cap. Overflow MUST be rejected, not
/// queued — queueing causes the requester's response timeout to fire while
/// the request still sits in our backlog.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 5;

/// Outbound request timeout for header-only / metadata methods.
pub const REQUEST_TIMEOUT_HEADERS: Duration = Duration::from_secs(10);

/// Outbound request timeout for full-block methods.
pub const REQUEST_TIMEOUT_BODIES: Duration = Duration::from_secs(30);

/// Block-sync request envelope.
///
/// All variants are size-bounded by the CBOR codec's 1 MiB request cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSyncRequest {
    /// Probe a peer's chain tip and lowest-available block.
    ///
    /// A checkpoint-availability probe. Used by the sync state
    /// machine to choose target peers and detect partitions.
    GetTipInfo,

    /// Fetch a contiguous range of blocks (header + body) starting at `start`,
    /// up to `count` blocks. The peer SHOULD return as many blocks as it can
    /// up to `count`; partial responses are valid (e.g., peer's tip is
    /// `start + count - 5`).
    ///
    /// Constraints:
    ///   * `count` MUST be in `1..=MAX_BLOCKS_PER_RANGE`. Larger values are
    ///     rejected with `BlockSyncError::RangeTooLarge`.
    GetBlockRange { start: BlockHeight, count: u32 },

    /// Fetch a specific block by its hash. Used for fork resolution
    /// (`parent_lookup` flow): when a peer advertises an unknown head, the
    /// syncer first asks for the block by hash, then walks backward via
    /// `prev_hash` until it finds a known ancestor.
    GetBlockByHash { hash: Hash },
}

/// Block-sync response envelope.
// Boxing the large `BlockByHash` payload would alter every cross-crate
// construction/match site of this wire type; the size disparity is inherent to
// the request/response shape.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSyncResponse {
    /// Response to `GetTipInfo`.
    TipInfo {
        /// Highest finalized block height the peer can serve.
        tip_height: BlockHeight,
        /// Hash of the block at `tip_height`.
        tip_hash: Hash,
        /// Lowest block height the peer has on disk. Pruning nodes report a
        /// value > 0; archive nodes report 0 (genesis).
        lowest_available: BlockHeight,
    },

    /// Response to `GetBlockRange`. Blocks are returned in ascending height
    /// order. May be shorter than the requested `count` if the peer's tip is
    /// reached or if the response would exceed the 10 MiB CBOR cap.
    BlockRange { blocks: Vec<Block> },

    /// Response to `GetBlockByHash`. `None` if the peer does not have the
    /// block (e.g., pruned, fork it doesn't follow).
    BlockByHash { block: Option<Block> },

    /// Server-side error for any request variant. The requesting node uses
    /// this to score the peer down and choose another.
    Error(BlockSyncError),
}

/// Errors a serving peer reports back to the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum BlockSyncError {
    /// `count` exceeded `MAX_BLOCKS_PER_RANGE`.
    #[error("requested range too large (max {max}, got {got})")]
    RangeTooLarge { got: u32, max: u32 },

    /// Server is at its inbound concurrency cap. Caller should retry against
    /// a different peer or back off.
    #[error("server busy — exceeded {limit} concurrent inbound streams from this peer")]
    ServerBusy { limit: usize },

    /// `start` is below the peer's `lowest_available` (peer pruned the range).
    #[error(
        "requested block below pruned tail (start={start}, lowest_available={lowest_available})"
    )]
    BelowPrunedTail {
        start: BlockHeight,
        lowest_available: BlockHeight,
    },

    /// Internal storage error on the serving side.
    #[error("server-side storage error: {0}")]
    Storage(String),
}

/// Type alias for the libp2p request-response behaviour parameterized with
/// our wire types. Uses CBOR (`cbor4ii`) framing — the production default.
pub type BlockSyncBehaviour =
    request_response::cbor::Behaviour<BlockSyncRequest, BlockSyncResponse>;

/// Constructs a fresh block-sync `Behaviour` with production-tuned config.
///
/// The CBOR codec defaults already set the size limits we want
/// (1 MiB request, 10 MiB response). The per-request timeout is set to
/// `REQUEST_TIMEOUT_BODIES` (30s) to accommodate the slowest variant; the
/// state machine layer enforces shorter per-method timeouts where
/// appropriate.
pub fn new_behaviour() -> BlockSyncBehaviour {
    let protocol = StreamProtocol::new(BLOCK_SYNC_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT_BODIES);
    request_response::cbor::Behaviour::new(std::iter::once((protocol, ProtocolSupport::Full)), cfg)
}

#[cfg(test)]
mod tests {
    /// The count cap must not be mistaken for a size cap.
    ///
    /// The codec allows a 10 MiB response and the protocol notes assumed that
    /// was "sufficient for 128" blocks — true only while blocks were small. At
    /// the 2 MiB block limit, 128 blocks is 256 MiB, so the response was
    /// truncated on the wire and every catch-up attempt died decoding it:
    ///
    ///   Block-sync: starting catch-up our_height=1496 target_height=3652 count=128
    ///   error=IO error on outbound stream: Eof { name: "u8", expect: Small.. }
    ///
    /// leaving followers permanently stuck. The byte budget must therefore be
    /// smaller than what the count cap can describe, and must sit below the
    /// codec ceiling with room for framing.
    // The assertions here are deliberately on constants: the point is to pin a
    // relationship *between* the limits, so that changing one without the other
    // fails the build rather than the network.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_block_count_cap_is_not_a_size_cap() {
        const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024; // ConsensusConfig::max_block_size
        const CODEC_RESPONSE_CEILING: usize = 10 * 1024 * 1024;

        let worst_case = MAX_BLOCKS_PER_RANGE as usize * MAX_BLOCK_BYTES;
        assert!(
            worst_case > CODEC_RESPONSE_CEILING,
            "if this no longer holds the byte budget may be unnecessary, but while it \
             does, count alone cannot bound a response"
        );
        assert!(
            MAX_BLOCK_RANGE_BYTES < CODEC_RESPONSE_CEILING,
            "the byte budget must leave headroom for codec framing"
        );
        assert!(
            MAX_BLOCK_RANGE_BYTES >= MAX_BLOCK_BYTES,
            "the budget must fit at least one maximum-size block, or sync stalls"
        );
    }

    use super::*;

    /// Serde round-trip: every request variant must encode and decode cleanly.
    /// We use `bincode` here as a stand-in for the runtime CBOR codec —
    /// what matters is that the types implement `Serialize + DeserializeOwned`
    /// correctly. The actual CBOR framing is exercised by libp2p's codec at
    /// runtime; the upstream cbor4ii crate's own tests cover that path.
    #[test]
    fn request_round_trip() {
        let cases = vec![
            BlockSyncRequest::GetTipInfo,
            BlockSyncRequest::GetBlockRange {
                start: BlockHeight::from(42u64),
                count: 16,
            },
            BlockSyncRequest::GetBlockByHash {
                hash: Hash::from_bytes(&[7u8; 32]).unwrap(),
            },
        ];
        for req in cases {
            let bytes = bincode::serialize(&req).expect("encode");
            let decoded: BlockSyncRequest = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(req, decoded);
        }
    }

    /// Serde round-trip for response variants. We don't construct a full
    /// `Block` here (it requires consensus context); a `BlockRange { blocks: [] }`
    /// + the other simple variants exercise the enum discriminant path.
    #[test]
    fn response_round_trip() {
        let cases = vec![
            BlockSyncResponse::TipInfo {
                tip_height: BlockHeight::from(1000u64),
                tip_hash: Hash::from_bytes(&[1u8; 32]).unwrap(),
                lowest_available: BlockHeight::from(0u64),
            },
            BlockSyncResponse::BlockRange { blocks: vec![] },
            BlockSyncResponse::BlockByHash { block: None },
            BlockSyncResponse::Error(BlockSyncError::RangeTooLarge {
                got: 999,
                max: MAX_BLOCKS_PER_RANGE,
            }),
            BlockSyncResponse::Error(BlockSyncError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: BlockSyncResponse = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(resp, decoded);
        }
    }

    #[test]
    fn behaviour_constructs() {
        // Smoke-test that constructing the behaviour doesn't panic on the
        // protocol name or config.
        let _ = new_behaviour();
    }
}
