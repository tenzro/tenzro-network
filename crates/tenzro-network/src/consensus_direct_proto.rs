//! Validator-only direct-connect overlay for HotStuff-2 consensus messages.
//!
//! Replaces the gossipsub `tenzro/consensus` publish path for the four
//! HotStuff-2 message kinds — `Vote`, `Proposal`, `Timeout`,
//! `NoEndorsement`. The gossipsub topic remains *subscribable* for observers
//! (RPC nodes, indexers, light clients that want to follow the consensus
//! state machine without participating); on a steady fleet of validators it
//! carries zero traffic because every publisher has been migrated here.
//!
//! ## Design
//!
//! A quorum-driver / consensus-network direct-dispatch pattern:
//! a single `libp2p::request_response::cbor::Behaviour` carries one
//! request-per-message with an `Ack`/`Error` response. The request body is a
//! `ConsensusMessage` lifted directly from the gossipsub wire type so the
//! migration is byte-for-byte identical on the receive side — only the
//! transport changes. Direct-connect dispatch is fanned out by the
//! `service.rs` event loop to every `PeerId` in the local
//! `ValidatorRegistry::validator_peer_ids()` snapshot taken at send time.
//!
//! ## Why request-response, not gossipsub direct_peers
//!
//! `gossipsub::Config::direct_peers` was the first design we tried.
//! Two problems made it unworkable:
//!
//!   1. **Mutual GRAFT rejection.** rust-libp2p's gossipsub treats explicit
//!      peers as *bypass-the-mesh* — any incoming GRAFT from such a peer is
//!      rejected (`behaviour.rs ~1426`: "GRAFT: ignoring request from direct
//!      peer"). When two validators classify each other as direct, neither
//!      can join the other's mesh. Block / transaction gossip — which we
//!      *want* on the mesh — degrades.
//!   2. **No back-pressure or per-message confirmation.** Gossipsub is
//!      fire-and-forget; we have no signal that a vote was actually
//!      delivered. Request-response surfaces typed `OutboundFailure` errors
//!      (`Timeout`, `ConnectionClosed`, `UnsupportedProtocols`, `Io`,
//!      `DialFailure`) which the consensus retry policy can react to.
//!
//! Request-response over a per-validator stream gives both: the gossipsub
//! mesh is preserved for blocks / transactions, and consensus traffic gets
//! per-message delivery semantics.
//!
//! ## Concurrency limits
//!
//!   * Per-peer in-flight cap: 64 (HotStuff-2 may emit a burst of
//!     vote+timeout+nec at the same view edge — be generous)
//!   * Inbound concurrent streams per peer: 16 (small validator sets;
//!     reject overflow rather than queue, same reasoning as block-sync)
//!   * Max request size: 1 MiB (CBOR codec default; a `Proposal` carries
//!     a full `Block` plus optional TC/NEC envelopes)
//!   * Max response size: 1 KiB (the `Ack` variant is empty; `Error`
//!     carries a string)
//!   * Request timeout: 5s — votes / timeouts must reach quorum within
//!     the pacemaker round timer (typically 1-3s); 5s gives a generous
//!     2x headroom before the consensus retry policy fires.

use libp2p::{
    StreamProtocol,
    request_response::{self, ProtocolSupport},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::message::ConsensusMessage;

/// Stream-protocol identifier for the consensus-direct RPC.
///
/// The version segment is required by libp2p's `StreamProtocol` rules
/// (third-party / external surface — same exception as block-sync). Internal
/// Tenzro identifiers (gossipsub topics, JSON-RPC methods, SHA-256 domain
/// tags) intentionally omit version segments per the project's identifier
/// conventions.
pub const CONSENSUS_DIRECT_PROTOCOL: &str = "/tenzro/consensus-direct/1.0.0";

/// Per-peer in-flight outbound request cap. HotStuff-2 may emit a burst at
/// the view edge — vote + timeout + NEC for the same view — and the leader
/// fans a fresh proposal out simultaneously, so the cap needs headroom.
pub const MAX_INFLIGHT_REQUESTS_PER_PEER: usize = 64;

/// Per-peer inbound concurrent stream cap. Overflow MUST be rejected, not
/// queued — queueing causes the requester's response timeout to fire while
/// the request still sits in our backlog.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 16;

/// Outbound request timeout. Tuned to ~2x the pacemaker round timer; longer
/// would let stale votes pile up beyond the round they belong to.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Consensus-direct request envelope.
///
/// One variant per kind so that the codec discriminator stays explicit and
/// the wire layout is forward-compatible if a future message type (e.g. a
/// fast-path optimistic-commit vote) needs its own framing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusDirectRequest {
    /// One HotStuff-2 message — vote, proposal, timeout, or NEC.
    Message(ConsensusMessage),
}

/// Consensus-direct response envelope.
///
/// `Ack` is the happy path; the receiver enqueued the message into its
/// consensus engine for processing (or deduped it as an echo). `Error`
/// carries a server-side rejection — the sender uses these to skip
/// retries on the offending peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusDirectResponse {
    /// Receiver accepted the message into its consensus pipeline.
    Ack,
    /// Receiver rejected the message at the transport layer.
    Error(ConsensusDirectError),
}

/// Errors a serving peer reports back to the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ConsensusDirectError {
    /// Receiver is at its inbound concurrency cap. Sender should back off
    /// briefly before retrying — typically the peer is processing a burst
    /// of votes from the prior view edge.
    #[error("server busy — exceeded {limit} concurrent inbound streams from this peer")]
    ServerBusy { limit: usize },

    /// Receiver has no consensus subscriber attached (light client / RPC
    /// node). Sender should NOT retry against this peer; remove from the
    /// validator set if observed repeatedly.
    #[error("no consensus subscriber attached")]
    NoSubscriber,

    /// Generic server-side error; payload was decoded but the receiver's
    /// downstream pipeline rejected it. Surfaces to the sender as a
    /// non-retryable failure.
    #[error("server error: {0}")]
    Internal(String),
}

/// Type alias for the libp2p request-response behaviour parameterised with
/// our wire types. CBOR (`cbor4ii`) framing — same codec choice as
/// block-sync, for consistency.
pub type ConsensusDirectBehaviour =
    request_response::cbor::Behaviour<ConsensusDirectRequest, ConsensusDirectResponse>;

/// Constructs a fresh consensus-direct `Behaviour` with production-tuned
/// config.
///
/// CBOR codec defaults set the size limits we want (1 MiB request, 10 MiB
/// response — even though our responses are tiny, the default is fine). The
/// per-request timeout is set to `REQUEST_TIMEOUT`; the consensus retry
/// policy enforces tighter per-message deadlines where appropriate.
pub fn new_behaviour() -> ConsensusDirectBehaviour {
    let protocol = StreamProtocol::new(CONSENSUS_DIRECT_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    request_response::cbor::Behaviour::new(std::iter::once((protocol, ProtocolSupport::Full)), cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::{Address, Hash};

    /// Serde round-trip for the response variants. Bincode stands in for
    /// the runtime CBOR codec — what matters is that the types implement
    /// `Serialize + DeserializeOwned` correctly. Actual CBOR framing is
    /// exercised by libp2p's codec at runtime.
    #[test]
    fn response_round_trip() {
        let cases = vec![
            ConsensusDirectResponse::Ack,
            ConsensusDirectResponse::Error(ConsensusDirectError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
            ConsensusDirectResponse::Error(ConsensusDirectError::NoSubscriber),
            ConsensusDirectResponse::Error(ConsensusDirectError::Internal(
                "downstream queue full".to_string(),
            )),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: ConsensusDirectResponse = bincode::deserialize(&bytes).expect("decode");
            // PartialEq on the response is satisfied via enum discriminant
            // round-trip; we don't derive PartialEq on the outer to avoid
            // pulling it through ConsensusMessage. Compare via Debug fmt
            // — sufficient for the smoke check.
            assert_eq!(format!("{:?}", resp), format!("{:?}", decoded));
        }
    }

    /// Serde round-trip for a representative request — a Timeout message,
    /// chosen because its `Address` voter field exercises the
    /// tenzro_types primitives serde path.
    #[test]
    fn request_round_trip_timeout() {
        let req = ConsensusDirectRequest::Message(ConsensusMessage::Timeout {
            format_version: 1,
            view: 42,
            high_qc_view: 41,
            finalized_height: 40,
            voter: Address::from_bytes(&[0u8; 32]).unwrap(),
            signature: vec![0xab; 64],
            public_key: vec![0xcd; 32],
        });
        let bytes = bincode::serialize(&req).expect("encode");
        let decoded: ConsensusDirectRequest = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(format!("{:?}", req), format!("{:?}", decoded));
    }

    /// Serde round-trip for a Vote request — exercises the larger payload
    /// path (CompositeSignature + CompositePublicKey blobs).
    #[test]
    fn request_round_trip_vote() {
        let req = ConsensusDirectRequest::Message(ConsensusMessage::Vote {
            block_hash: Hash::from_bytes(&[7u8; 32]).unwrap(),
            voter: "0123456789abcdef".to_string(),
            vote_type: crate::message::VoteType::Prevote,
            round: 5,
            height: 100,
            high_qc_view: 4,
            signature: vec![0u8; 96],
            public_key: vec![1u8; 1952],
            bls_signature: vec![0u8; 96],
        });
        let bytes = bincode::serialize(&req).expect("encode");
        let decoded: ConsensusDirectRequest = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(format!("{:?}", req), format!("{:?}", decoded));
    }

    #[test]
    fn behaviour_constructs() {
        let _ = new_behaviour();
    }
}
