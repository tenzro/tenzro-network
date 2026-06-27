//! Authenticated tunnel for LAN-cluster pipeline traffic.
//!
//! A cluster member runs llama.cpp's `rpc-server` bound to loopback. That
//! server is insecure on an open network by design (the upstream README is
//! explicit: "Never run the RPC server on an open network"), so its TCP
//! byte stream is never exposed directly. Instead the head and the member
//! relay those bytes to each other over this protocol, which rides the same
//! peer-ID-authenticated, Noise/TLS-encrypted transport as the rest of the
//! swarm. The head dials a member's tunnel, the member splices the tunnel to
//! its local `rpc-server` socket, and the ggml RPC backend on the head sees
//! an ordinary connection.
//!
//! ## Design
//!
//! Modeled on [`crate::consensus_direct_proto`] and block-sync: a single
//! `request_response::cbor::Behaviour` carries framed chunks. Each request is
//! one [`TunnelFrame`] tagged with a session id and a monotonic sequence
//! number; the response acknowledges receipt and may carry return-path bytes
//! piggybacked, so a single request-response pair moves data in both
//! directions. This keeps the protocol inside the existing message-oriented
//! overlay rather than pulling in the alpha `libp2p-stream` crate, whose
//! libp2p-core version is not pinned to the umbrella 0.56 we depend on.
//!
//! Ordering within a session is the responsibility of the splice loops on
//! each side: they emit frames in sequence order and reassemble by sequence
//! number, dropping a session on any gap (the RPC backend treats a dropped
//! connection as a stage failure, which the serving runtime's failover
//! handles).
//!
//! ## Why not raw gossip or a new transport
//!
//! Pipeline activation traffic is point-to-point, ordered, and back-pressured
//! — none of which gossipsub provides. Request-response gives typed
//! `OutboundFailure` signals (`Timeout`, `ConnectionClosed`, `Io`) that the
//! serving runtime's latency-ordered failover reacts to.
//!
//! ## Limits
//!
//!   * Max frame payload: 1 MiB — a boundary activation for even a wide model
//!     is tens of KiB per token, but prompt-processing batches many tokens, so
//!     give generous headroom.
//!   * Per-peer in-flight cap: 256 — the splice loop pipelines many frames.
//!   * Request timeout: 30s — a stage may be mid-decode on a large batch.

use libp2p::{
    request_response::{self, ProtocolSupport},
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Stream-protocol identifier for the cluster pipeline tunnel.
///
/// Carries a version segment per libp2p's `StreamProtocol` rules (external
/// surface — same exception as block-sync / consensus-direct).
pub const CLUSTER_TUNNEL_PROTOCOL: &str = "/tenzro/cluster-tunnel/1.0.0";

/// Per-peer in-flight outbound frame cap. The splice loop pipelines frames to
/// keep the rpc-server socket saturated, so this needs real headroom.
pub const MAX_INFLIGHT_FRAMES_PER_PEER: usize = 256;

/// Per-peer inbound concurrent stream cap. Overflow is rejected, not queued.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 64;

/// Outbound frame timeout. A stage may be mid-decode on a large batch before
/// it can ack, so this is generous relative to consensus traffic.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum payload bytes carried in a single tunnel frame.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// One framed chunk of tunneled `rpc-server` bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelFrame {
    /// Opaque session id — one per head↔member rpc-server connection. Lets a
    /// member multiplex several head connections over one peer link.
    pub session: u64,
    /// Monotonic per-session sequence number. The receiving splice loop
    /// reassembles in this order and drops the session on a gap.
    pub seq: u64,
    /// The kind of frame — open, data, or close.
    pub kind: TunnelFrameKind,
    /// Payload bytes (empty for `Open` / `Close`). Forwarded verbatim into the
    /// peer's rpc-server socket.
    pub payload: Vec<u8>,
}

/// Lifecycle marker for a tunnel frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelFrameKind {
    /// First frame of a session — the member should dial its local
    /// rpc-server and begin splicing.
    Open,
    /// Carries `rpc-server` byte payload.
    Data,
    /// Last frame — the member tears down the local socket.
    Close,
}

/// Tunnel request envelope: one frame, optionally requesting return data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTunnelRequest {
    /// The frame being delivered to the peer.
    pub frame: TunnelFrame,
}

/// Tunnel response envelope. Acknowledges the delivered frame and piggybacks
/// any bytes the peer's rpc-server produced on the return path, so a single
/// request-response pair is full-duplex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterTunnelResponse {
    /// Frame accepted; `return_frames` carries any bytes read back from the
    /// peer's rpc-server socket since the last ack (may be empty).
    Ack {
        /// Return-path frames, in sequence order.
        return_frames: Vec<TunnelFrame>,
    },
    /// Peer rejected the frame.
    Error(ClusterTunnelError),
}

/// Errors a serving peer reports back on the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ClusterTunnelError {
    /// Peer is at its inbound concurrency cap. Back off and retry.
    #[error("server busy — exceeded {limit} concurrent inbound tunnels from this peer")]
    ServerBusy {
        /// The cap that was hit.
        limit: usize,
    },

    /// Peer is not running a cluster member runtime (no rpc-server to splice
    /// to). Sender must not retry against this peer.
    #[error("no cluster member runtime attached")]
    NoMember,

    /// The local rpc-server socket could not be reached or dropped mid-session.
    /// The head treats this as a stage failure and fails over.
    #[error("rpc-server socket error: {0}")]
    SocketError(String),

    /// Sequence gap detected — the session is being torn down.
    #[error("sequence gap on session {session}: expected {expected}, got {got}")]
    SequenceGap {
        /// The session id.
        session: u64,
        /// The sequence number the receiver expected next.
        expected: u64,
        /// The sequence number actually received.
        got: u64,
    },
}

/// Request-response behaviour parameterised with the tunnel wire types. CBOR
/// framing — same codec as block-sync / consensus-direct.
pub type ClusterTunnelBehaviour =
    request_response::cbor::Behaviour<ClusterTunnelRequest, ClusterTunnelResponse>;

/// Construct a fresh cluster-tunnel `Behaviour` with production-tuned config.
pub fn new_behaviour() -> ClusterTunnelBehaviour {
    let protocol = StreamProtocol::new(CLUSTER_TUNNEL_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    request_response::cbor::Behaviour::new(std::iter::once((protocol, ProtocolSupport::Full)), cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = TunnelFrame {
            session: 7,
            seq: 42,
            kind: TunnelFrameKind::Data,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let req = ClusterTunnelRequest { frame };
        let bytes = bincode::serialize(&req).expect("encode");
        let decoded: ClusterTunnelRequest = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(decoded.frame.session, 7);
        assert_eq!(decoded.frame.seq, 42);
        assert_eq!(decoded.frame.kind, TunnelFrameKind::Data);
        assert_eq!(decoded.frame.payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn response_round_trip() {
        let cases = vec![
            ClusterTunnelResponse::Ack {
                return_frames: vec![TunnelFrame {
                    session: 1,
                    seq: 0,
                    kind: TunnelFrameKind::Open,
                    payload: vec![],
                }],
            },
            ClusterTunnelResponse::Error(ClusterTunnelError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
            ClusterTunnelResponse::Error(ClusterTunnelError::NoMember),
            ClusterTunnelResponse::Error(ClusterTunnelError::SequenceGap {
                session: 3,
                expected: 10,
                got: 12,
            }),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: ClusterTunnelResponse = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(format!("{:?}", resp), format!("{:?}", decoded));
        }
    }

    #[test]
    fn behaviour_constructs() {
        let _ = new_behaviour();
    }
}
