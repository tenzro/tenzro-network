//! Bridge-side handle for the libp2p MPC relay surface.
//!
//! The actual libp2p [`request_response::Behaviour`] and protocol-identifier
//! constants live in `tenzro_network::mpc_relay` (see that module for the
//! canonical `MPC_RELAY_PROTOCOL`, `MPC_RELAY_GOSSIP_TOPIC_PREFIX`, wire
//! envelope, and concurrency-cap rationale). This module declares only the
//! *call surface* the bridge needs: a trait the node-layer adapter
//! implements (`MpcLibp2pSurface`) and a [`Transport`] wrapper that maps
//! the bridge's `MpcRoundMessage` onto that surface.
//!
//! Why the split: `tenzro-network` and `tenzro-bridge` are siblings.
//! Neither may depend on the other. The node-layer adapter (which depends
//! on both) implements `MpcLibp2pSurface` by translating
//! `MpcRoundMessage` ↔ `tenzro_network::mpc_relay::MpcRelayRequest`.
//!
//! Wire mapping (handled in the node-layer adapter, not here):
//! - `instance_id: InstanceId([u8; 32])` ↔ `MpcRelayRequest.instance_id: [u8; 32]`
//! - `phase: MpcPhase` ↔ `phase: u8` (Dkg=0, Sign=1, Refresh=2, ReKey=3)
//! - `round_index`, `from_did`, `to_did`, `payload` are field-identical.

use std::sync::Arc;

use crate::mpc::transport::{MpcRoundMessage, Transport, TransportError};

/// Trait implemented by the network-layer surface that owns the libp2p
/// `Swarm`. The MPC session driver calls into this trait to send/recv
/// without pulling in the libp2p type tree (or the network crate's
/// dependency graph).
///
/// The concrete implementation lives in `tenzro-node` and bridges this
/// trait to `tenzro_network::NetworkService::send_mpc_relay_message` +
/// `subscribe_mpc_relay`.
#[async_trait::async_trait]
pub trait MpcLibp2pSurface: Send + Sync {
    /// Send a round message to the peer that owns `message.to_did`. The
    /// network layer resolves the DID through the installed
    /// `MpcDidResolver`; an unresolved DID surfaces as
    /// `TransportError::Send`.
    async fn send_point_to_point(&self, message: &MpcRoundMessage) -> Result<(), TransportError>;

    /// Receive the next inbound round message for the local party's
    /// active session. The surface is responsible for demultiplexing
    /// inbound traffic by `(instance_id, to_did)` if a single node
    /// participates in multiple concurrent sessions.
    async fn recv_point_to_point(&self) -> Result<MpcRoundMessage, TransportError>;
}

/// [`Transport`] adapter that delegates to an [`MpcLibp2pSurface`]. The
/// session driver constructs one of these per active session.
pub struct MpcLibp2pRelay {
    surface: Arc<dyn MpcLibp2pSurface>,
}

impl MpcLibp2pRelay {
    /// Wrap a network-layer surface into a `Transport`.
    pub fn new(surface: Arc<dyn MpcLibp2pSurface>) -> Self {
        Self { surface }
    }
}

#[async_trait::async_trait]
impl Transport for MpcLibp2pRelay {
    async fn send(&self, message: MpcRoundMessage) -> Result<(), TransportError> {
        self.surface.send_point_to_point(&message).await
    }

    async fn recv(&self) -> Result<MpcRoundMessage, TransportError> {
        self.surface.recv_point_to_point().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::setup::{InstanceId, SESSION_NONCE_LEN};
    use crate::mpc::transport::MpcPhase;
    use std::sync::Mutex;
    use tenzro_types::Hash;

    /// In-memory `MpcLibp2pSurface` used to exercise the `Transport` adapter
    /// without standing up libp2p.
    struct LoopbackSurface {
        outbox: Mutex<Vec<MpcRoundMessage>>,
        inbox: Mutex<Vec<MpcRoundMessage>>,
    }

    impl LoopbackSurface {
        fn new(inbound: Vec<MpcRoundMessage>) -> Self {
            Self {
                outbox: Mutex::new(Vec::new()),
                inbox: Mutex::new(inbound),
            }
        }
    }

    #[async_trait::async_trait]
    impl MpcLibp2pSurface for LoopbackSurface {
        async fn send_point_to_point(
            &self,
            message: &MpcRoundMessage,
        ) -> Result<(), TransportError> {
            self.outbox.lock().unwrap().push(message.clone());
            Ok(())
        }

        async fn recv_point_to_point(&self) -> Result<MpcRoundMessage, TransportError> {
            self.inbox
                .lock()
                .unwrap()
                .pop()
                .ok_or(TransportError::Closed)
        }
    }

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

    #[tokio::test]
    async fn adapter_send_round_trips_to_surface() {
        let surface = Arc::new(LoopbackSurface::new(vec![]));
        let relay = MpcLibp2pRelay::new(surface.clone());
        let m = sample_message();
        relay.send(m.clone()).await.unwrap();
        let captured = surface.outbox.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], m);
    }

    #[tokio::test]
    async fn adapter_recv_drains_surface_inbox() {
        let m = sample_message();
        let surface = Arc::new(LoopbackSurface::new(vec![m.clone()]));
        let relay = MpcLibp2pRelay::new(surface);
        let got = relay.recv().await.unwrap();
        assert_eq!(got, m);
    }

    #[tokio::test]
    async fn adapter_recv_returns_closed_when_inbox_empty() {
        let surface = Arc::new(LoopbackSurface::new(vec![]));
        let relay = MpcLibp2pRelay::new(surface);
        let err = relay.recv().await.expect_err("empty inbox should close");
        assert!(matches!(err, TransportError::Closed));
    }
}
