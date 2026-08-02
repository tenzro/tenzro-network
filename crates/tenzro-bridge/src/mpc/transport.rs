//! Round-message transport abstraction (`MpcRoundMessage` + `Transport`).
//!
//! DKLS23 protocols (DKG, signing, refresh, re-key) are reactive state
//! machines: each party consumes inbound messages addressed to it, produces
//! outbound messages addressed to specific counterparties, and yields a
//! final output when all rounds complete. The session driver is wire-agnostic
//! — it only knows how to push a `(from, to)` envelope into a `Transport`
//! and pull envelopes back out.
//!
//! Two transport implementations are anticipated:
//!
//! - **`libp2p_relay`** (default, production) — binds [`Transport`] to the
//!   `tenzro/mpc/v1` request-response + gossipsub protocols (task #19).
//! - **In-memory `tokio::mpsc`** (tests) — round-trips messages between
//!   parties on a single process. Lands alongside the session drivers in
//!   tasks #17, #18, #20.
//!
//! Encoding rules:
//!
//! - `MpcRoundMessage::payload` is the **opaque** dkls23-core round bytes —
//!   the session driver chooses serialization (bincode or postcard per
//!   `dkls23_core::protocols::messages` feature gates) and this module does
//!   not interpret it.
//! - `MpcRoundMessage::from_did` / `to_did` are TDIP DIDs; the transport
//!   resolves DIDs to `PeerId`s via the network layer.

use serde::{Deserialize, Serialize};

use crate::mpc::setup::InstanceId;

/// Logical phase tag carried on every round message. Lets a receiver reject
/// messages that arrive out-of-band for a phase it is not currently in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MpcPhase {
    /// Distributed key generation (initial group key).
    Dkg,
    /// Distributed signing (per-message session).
    Sign,
    /// Proactive share refresh (same group key, fresh shares).
    Refresh,
    /// Re-keying (rotate group key with same participant set, used during
    /// audited rotation rather than per-epoch refresh).
    ReKey,
}

/// A single round-trip envelope between two MPC parties.
///
/// Wire format is bincode-serializable for binary transports and JSON-
/// serializable for debug/CLI inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcRoundMessage {
    /// Session this message belongs to.
    pub instance_id: InstanceId,
    /// Phase discriminant.
    pub phase: MpcPhase,
    /// Monotonic round index within `phase` (0 = first round). The receiver
    /// expects strict-ascending rounds per `(from, to)` pair.
    pub round_index: u32,
    /// Sender DID.
    pub from_did: String,
    /// Receiver DID. Broadcast envelopes are unrolled into one
    /// `MpcRoundMessage` per recipient by the session driver — the
    /// transport sees only point-to-point messages.
    pub to_did: String,
    /// Opaque dkls23-core message payload.
    pub payload: Vec<u8>,
}

/// Errors returned by [`Transport`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Send was rejected by the underlying network (peer unreachable,
    /// channel closed, quota exceeded).
    #[error("transport send error: {0}")]
    Send(String),
    /// Receive returned no message before the channel was closed.
    #[error("transport receive closed")]
    Closed,
    /// Underlying network layer failure.
    #[error("transport backend error: {0}")]
    Backend(String),
}

/// Bidirectional point-to-point transport for `MpcRoundMessage` envelopes.
///
/// Session drivers (`keygen`, `sign`, `refresh`) own a `Transport` for the
/// lifetime of one session. Implementations are responsible for:
///
/// 1. Demultiplexing inbound messages by `(instance_id, to_did)`.
/// 2. Routing outbound messages to the peer that owns `to_did`.
/// 3. Enforcing back-pressure when peers fall behind.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Push an outbound envelope. Returns when the network layer has
    /// accepted the message for delivery — not when the peer has
    /// processed it.
    async fn send(&self, message: MpcRoundMessage) -> Result<(), TransportError>;

    /// Pop the next inbound envelope for this party's session, blocking
    /// until one is available or the channel closes.
    async fn recv(&self) -> Result<MpcRoundMessage, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::setup::SESSION_NONCE_LEN;
    use tenzro_types::Hash;

    fn sample_message() -> MpcRoundMessage {
        let block = Hash::from_bytes(&[1u8; 32]).unwrap();
        MpcRoundMessage {
            instance_id: InstanceId::derive(&block, &[2u8; 32], &[3u8; SESSION_NONCE_LEN]),
            phase: MpcPhase::Sign,
            round_index: 0,
            from_did: "did:tenzro:machine:p1".to_string(),
            to_did: "did:tenzro:machine:p2".to_string(),
            payload: vec![0xAA, 0xBB, 0xCC],
        }
    }

    #[test]
    fn message_serdes_roundtrip() {
        let m = sample_message();
        let encoded = serde_json::to_vec(&m).unwrap();
        let decoded: MpcRoundMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn phase_discriminants_distinct() {
        let phases = [
            MpcPhase::Dkg,
            MpcPhase::Sign,
            MpcPhase::Refresh,
            MpcPhase::ReKey,
        ];
        let mut seen = std::collections::HashSet::new();
        for p in phases {
            let encoded = serde_json::to_string(&p).unwrap();
            assert!(seen.insert(encoded));
        }
    }
}
