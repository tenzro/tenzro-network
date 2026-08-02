//! libp2p binding for the MPC `Transport` surface used by `tenzro-bridge`.
//!
//! ## Two transports, one behaviour family
//!
//! Per the bridge-side documentation in
//! `tenzro_bridge::mpc::libp2p_relay`, MPC sessions use two libp2p surfaces:
//!
//! - **request-response (`/tenzro/mpc/req-resp/1.0.0`)** — point-to-point
//!   delivery of `MpcRoundMessage` envelopes between named DIDs. Every
//!   per-recipient round message goes through this codec; reliable, ordered,
//!   back-pressure-aware. The DKLS23 broadcast-round messages are unrolled
//!   into per-peer messages by the session driver (see
//!   `tenzro_bridge::mpc::sign::SignSession::run`); the wire only ever sees
//!   point-to-point.
//! - **gossipsub topic prefix `/tenzro/mpc/session/<instance_id>`** — broadcast
//!   channel for session-control envelopes only (quorum-open / quorum-close /
//!   abort evidence). NOT used for DKLS23 rounds;
//!   broadcasting them would leak the session graph and waste mesh
//!   bandwidth.
//!
//! ## DID ↔ PeerId routing
//!
//! The bridge layer addresses messages by TDIP DID strings; libp2p moves
//! bytes by `PeerId`. The network crate does not own identity state, so it
//! takes an `Arc<dyn MpcDidResolver>` from the node and uses it for every
//! outbound dispatch and every inbound `from_did` audit. The resolver is
//! authoritative: a missing mapping for an outbound `to_did` is a hard
//! `TransportError`; a missing mapping for an inbound `from_did` causes the
//! message to be rejected with `MpcRelayError::UnknownSender` so a peer
//! can't pretend to be a DID they don't control.
//!
//! ## Why we don't reuse `ConsensusDirect`
//!
//! Consensus addresses by `PeerId` and broadcasts to the full validator set.
//! MPC addresses by DID and routes to one specific counterparty in the
//! signing quorum. Sharing a single codec would force both call sites to
//! agree on a single envelope shape, blocking either side from evolving its
//! wire format independently. The codecs are small (~150 LOC each); the
//! separation is cheap and structurally honest.
//!
//! ## Concurrency limits
//!
//! Borrowed from `consensus_direct_proto` with tighter inbound caps because
//! DKLS23 rounds are smaller and we expect at most one in-flight session per
//! group at any given time:
//!
//!   * Per-peer in-flight outbound: 32 (a 5-of-N signing session emits at
//!     most ~10 messages per round across 4 phases — 32 leaves headroom for
//!     two concurrent sessions sharing the same counterparty).
//!   * Per-peer inbound concurrent streams: 8 (overflow rejected, not
//!     queued — see the `consensus_direct_proto` design note for why).
//!   * Max request size: 1 MiB (DKLS23 phase-3 broadcasts are ~50 KB at
//!     n=10; 1 MiB is 20x headroom for future curves with larger payloads).
//!   * Max response size: 1 KiB (`Ack`/`Error` only).
//!   * Request timeout: 10 s — DKLS23 rounds are interactive, so a
//!     per-message timeout that's significantly longer than typical RTT
//!     (≤300 ms even cross-region) gives plenty of slack for a slow peer
//!     without letting the session hang indefinitely on a stuck stream.

use libp2p::{
    PeerId, StreamProtocol,
    request_response::{self, ProtocolSupport},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Stream-protocol identifier for the MPC round-message RPC.
///
/// The trailing `/1.0.0` version segment is required by libp2p's
/// `StreamProtocol` (a third-party convention — same exception as block-sync
/// and consensus-direct). Internal Tenzro identifiers (gossipsub topics,
/// JSON-RPC methods, SHA-256 domain tags) intentionally omit version segments
/// per the project's identifier conventions.
pub const MPC_RELAY_PROTOCOL: &str = "/tenzro/mpc/req-resp/1.0.0";

/// gossipsub topic prefix for per-session MPC session-control broadcasts
/// (quorum-open / quorum-close / abort-evidence). Per-session
/// topic is `MPC_RELAY_GOSSIP_TOPIC_PREFIX + hex(instance_id)`. DKLS23 round
/// messages themselves go via request-response, never gossipsub.
pub const MPC_RELAY_GOSSIP_TOPIC_PREFIX: &str = "/tenzro/mpc/session/";

/// Per-peer in-flight outbound request cap.
pub const MAX_INFLIGHT_REQUESTS_PER_PEER: usize = 32;

/// Per-peer inbound concurrent stream cap. Overflow MUST be rejected, not
/// queued — queueing causes the requester's response timeout to fire while
/// the request still sits in our backlog.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 8;

/// Outbound request timeout. Tuned to ≥30x typical cross-region RTT.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Compute the per-session gossipsub topic for an `instance_id` hex.
pub fn session_topic(instance_id_hex: &str) -> String {
    format!("{}{}", MPC_RELAY_GOSSIP_TOPIC_PREFIX, instance_id_hex)
}

/// Wire envelope for one MPC round message.
///
/// Mirrors `tenzro_bridge::mpc::transport::MpcRoundMessage` field-for-field
/// rather than re-exporting it directly — `tenzro-network` must not depend
/// on `tenzro-bridge` (the bridge depends on the network indirectly via the
/// node-layer adapter). The bridge-side type re-encodes through this wire
/// envelope at the node-layer adapter boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcRelayRequest {
    /// Session-derived `InstanceId` as 32-byte hash bytes. Opaque to the
    /// network layer; the bridge uses it to demultiplex by session.
    pub instance_id: [u8; 32],
    /// Phase discriminant (DKG=0, Sign=1, Refresh=2, ReKey=3). Opaque to
    /// the network; the bridge decodes it.
    pub phase: u8,
    /// Monotonic round index within `phase`. Receiver-side ordering invariant
    /// is enforced by the bridge, not the wire.
    pub round_index: u32,
    /// Sender TDIP DID.
    pub from_did: String,
    /// Receiver TDIP DID.
    pub to_did: String,
    /// Opaque dkls23-core round payload (bincode-serialized by the bridge).
    pub payload: Vec<u8>,
}

/// Wire response for one MPC round message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcRelayResponse {
    /// Receiver enqueued the message into its MPC session pipeline.
    Ack,
    /// Receiver rejected the message at the transport layer.
    Error(MpcRelayError),
}

/// Errors returned to the sender across the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum MpcRelayError {
    /// Receiver is at its inbound concurrency cap. Sender should back off
    /// briefly before retrying — typically the peer is processing a burst
    /// of round messages from a concurrent session.
    #[error("server busy — exceeded {limit} concurrent inbound streams from this peer")]
    ServerBusy { limit: usize },

    /// Receiver has no MPC subscriber attached. Sender should NOT retry
    /// against this peer; the peer may not be participating in this session.
    #[error("no MPC subscriber attached")]
    NoSubscriber,

    /// Sender claimed a `from_did` whose DID-to-PeerId mapping does not
    /// resolve back to the sending `PeerId`. The connection is dropped and
    /// the sender is penalised at the peer-score layer.
    #[error("sender DID does not match connection peer ID")]
    UnknownSender,

    /// Generic server-side error; payload was decoded but the receiver's
    /// downstream pipeline rejected it.
    #[error("server error: {0}")]
    Internal(String),
}

/// CBOR-framed request-response behaviour for the MPC relay.
pub type MpcRelayBehaviour = request_response::cbor::Behaviour<MpcRelayRequest, MpcRelayResponse>;

/// Constructs a fresh MPC relay `Behaviour` with production-tuned config.
pub fn new_behaviour() -> MpcRelayBehaviour {
    let protocol = StreamProtocol::new(MPC_RELAY_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    request_response::cbor::Behaviour::new(std::iter::once((protocol, ProtocolSupport::Full)), cfg)
}

/// DID-to-PeerId resolver injected by the node layer.
///
/// Implementations consult `IdentityRegistry` (or equivalent) to map TDIP
/// DIDs ↔ libp2p PeerIds. The network layer holds an `Arc<dyn MpcDidResolver>`
/// for the lifetime of the node so the MPC relay can route by DID without
/// pulling in the identity-crate dependency tree.
pub trait MpcDidResolver: Send + Sync {
    /// Resolve a TDIP DID to the libp2p PeerId of the node that controls it.
    /// Returns `None` if no mapping is registered (the DID is unknown to
    /// this node, or has been revoked).
    fn peer_id_for_did(&self, did: &str) -> Option<PeerId>;

    /// Reverse lookup: which DID is bound to this PeerId? Returns `None`
    /// for peers that have not announced an identity (RPC nodes, light
    /// clients) or for DIDs that have been revoked. Used to audit inbound
    /// `from_did` claims.
    fn did_for_peer_id(&self, peer_id: &PeerId) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_id_is_namespaced() {
        assert!(MPC_RELAY_PROTOCOL.starts_with("/tenzro/mpc/"));
        assert!(MPC_RELAY_GOSSIP_TOPIC_PREFIX.starts_with("/tenzro/mpc/"));
    }

    #[test]
    fn session_topic_formats() {
        let t = session_topic("deadbeef");
        assert_eq!(t, "/tenzro/mpc/session/deadbeef");
    }

    #[test]
    fn request_round_trip() {
        let req = MpcRelayRequest {
            instance_id: [7u8; 32],
            phase: 1,
            round_index: 3,
            from_did: "did:tenzro:machine:p1".to_string(),
            to_did: "did:tenzro:machine:p2".to_string(),
            payload: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes = bincode::serialize(&req).expect("encode");
        let decoded: MpcRelayRequest = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(req.instance_id, decoded.instance_id);
        assert_eq!(req.phase, decoded.phase);
        assert_eq!(req.round_index, decoded.round_index);
        assert_eq!(req.from_did, decoded.from_did);
        assert_eq!(req.to_did, decoded.to_did);
        assert_eq!(req.payload, decoded.payload);
    }

    #[test]
    fn response_round_trip() {
        let cases = vec![
            MpcRelayResponse::Ack,
            MpcRelayResponse::Error(MpcRelayError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
            MpcRelayResponse::Error(MpcRelayError::NoSubscriber),
            MpcRelayResponse::Error(MpcRelayError::UnknownSender),
            MpcRelayResponse::Error(MpcRelayError::Internal("downstream queue full".to_string())),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: MpcRelayResponse = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(format!("{:?}", resp), format!("{:?}", decoded));
        }
    }

    #[test]
    fn behaviour_constructs() {
        let _ = new_behaviour();
    }
}
