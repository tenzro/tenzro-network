//! Node-layer adapter binding the bridge-side `MpcLibp2pSurface` to the
//! network-side `NetworkService::send_mpc_relay_message` /
//! `subscribe_mpc_relay`.
//!
//! ## Why this file exists
//!
//! `tenzro-bridge` and `tenzro-network` are workspace siblings — neither may
//! depend on the other (see the bridge-side doc in
//! `tenzro_bridge::mpc::libp2p_relay`). The node crate is the only place that
//! depends on both, so it is the natural seam where:
//!
//! 1. The bridge's `MpcRoundMessage { instance_id: InstanceId, phase: MpcPhase,
//!    .. }` envelope is mapped to the network's wire shape
//!    `MpcRelayRequest { instance_id: [u8; 32], phase: u8, .. }` and back.
//! 2. The bridge's `Arc<dyn MpcDidResolver>` (network-crate trait) is bound to
//!    an in-process DID-to-PeerId registry.
//!
//! ## Why the DID↔PeerId registry is its own thing
//!
//! The TDIP identity record carries an Ed25519 public key, but that is the
//! identity-signing key — NOT the libp2p p2p key. The libp2p `Keypair` is
//! generated independently by `tenzro_network::service::node_identity_keypair`
//! and persisted under the node's data directory; nothing in the workspace
//! today binds the two by construction (a deliberate choice — rotating one
//! must not rotate the other). So the `MpcDidResolver` cannot derive a
//! `PeerId` from a TDIP record on its own; it needs an explicit mapping that
//! is populated either:
//!
//! - by the local node for the local node (`insert_self`), as part of node
//!   startup, OR
//! - by an out-of-band DID-announcement protocol (an `Identify`-payload
//!   extension or a dedicated gossipsub topic) that registers each peer's
//!   `(did, peer_id)` claim. The announcement protocol itself is a separate
//!   follow-up task; the registry surface here is what it will write into.
//!
//! ## Phase mapping
//!
//! `MpcPhase` → `u8` per the canonical mapping documented in
//! `tenzro_bridge::mpc::libp2p_relay`:
//!
//! | Variant            | Wire byte |
//! |--------------------|-----------|
//! | `MpcPhase::Dkg`    | `0`       |
//! | `MpcPhase::Sign`   | `1`       |
//! | `MpcPhase::Refresh`| `2`       |
//! | `MpcPhase::ReKey`  | `3`       |
//!
//! Inbound bytes outside `[0, 3]` are rejected with `TransportError::Backend`
//! so a malformed `phase` on the wire can never silently become `Dkg`.

use std::sync::Arc;

use dashmap::DashMap;
use libp2p::PeerId;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedReceiver;

use tenzro_bridge::mpc::libp2p_relay::MpcLibp2pSurface;
use tenzro_bridge::mpc::setup::{INSTANCE_ID_LEN, InstanceId};
use tenzro_bridge::mpc::transport::{MpcPhase, MpcRoundMessage, TransportError};
use tenzro_network::NetworkService;
use tenzro_network::mpc_relay::{MpcDidResolver, MpcRelayRequest};

/// In-process two-way registry binding TDIP DIDs to libp2p `PeerId`s.
///
/// This is the concrete `MpcDidResolver` implementation that the node hands
/// to `NetworkService::set_mpc_did_resolver`. It is intentionally write-only
/// from the outside (no eviction surface): an MPC committee that drops a DID
/// from its participant set must spin up a fresh resolver, not mutate a
/// shared one — entries are session-bound, not lifetime-bound.
///
/// Both directions are stored explicitly because the network layer uses the
/// reverse direction (`did_for_peer_id`) on every inbound message to audit
/// the sender's `from_did` claim against the connection-attested `PeerId`.
#[derive(Default)]
pub struct MpcDidPeerRegistry {
    did_to_peer: DashMap<String, PeerId>,
    peer_to_did: DashMap<PeerId, String>,
}

impl MpcDidPeerRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `(did, peer_id)` mapping. If a different mapping for the
    /// same DID or `PeerId` is already present, it is overwritten — the
    /// caller is responsible for ensuring monotonic updates (this registry is
    /// not the policy layer).
    pub fn insert(&self, did: impl Into<String>, peer_id: PeerId) {
        let did = did.into();
        self.did_to_peer.insert(did.clone(), peer_id);
        self.peer_to_did.insert(peer_id, did);
    }

    /// Convenience: register the local node's own DID under its own
    /// `PeerId`. Required so a session driver running locally can see
    /// inbound messages addressed to itself routed back through the network
    /// layer's sender-DID audit.
    pub fn insert_self(&self, local_did: impl Into<String>, local_peer_id: PeerId) {
        self.insert(local_did, local_peer_id);
    }

    /// Current number of `(did, peer_id)` bindings. Used by tests / logs.
    pub fn len(&self) -> usize {
        self.did_to_peer.len()
    }

    /// Whether the registry currently has no bindings.
    pub fn is_empty(&self) -> bool {
        self.did_to_peer.is_empty()
    }
}

impl MpcDidResolver for MpcDidPeerRegistry {
    fn peer_id_for_did(&self, did: &str) -> Option<PeerId> {
        self.did_to_peer.get(did).map(|v| *v.value())
    }

    fn did_for_peer_id(&self, peer_id: &PeerId) -> Option<String> {
        self.peer_to_did.get(peer_id).map(|v| v.value().clone())
    }
}

/// `MpcLibp2pSurface` impl that delegates to a `NetworkService` for sends and
/// owns the single inbound `MpcRelayRequest` stream produced by
/// `NetworkService::subscribe_mpc_relay`.
///
/// One instance per running node; the bridge's session drivers all share it
/// through `MpcLibp2pRelay::new(Arc::clone(&surface))`. Inbound demultiplexing
/// by `(instance_id, to_did)` is the responsibility of the consumer wrapping
/// this surface — at this layer, every `recv_point_to_point` call yields the
/// next envelope the network layer hands us regardless of session.
pub struct NetworkMpcSurface {
    network: Arc<dyn NetworkService>,
    inbox: Mutex<UnboundedReceiver<MpcRelayRequest>>,
}

impl NetworkMpcSurface {
    /// Subscribe once to the network layer's MPC relay stream and wrap it
    /// into the bridge-side surface trait.
    ///
    /// Errors propagate the network-layer subscription error verbatim — this
    /// is a one-shot setup call invoked during node init, so a failure here
    /// should fail node startup, not silently degrade.
    pub async fn new(network: Arc<dyn NetworkService>) -> tenzro_network::Result<Self> {
        let rx = network.subscribe_mpc_relay().await?;
        Ok(Self {
            network,
            inbox: Mutex::new(rx),
        })
    }
}

#[async_trait::async_trait]
impl MpcLibp2pSurface for NetworkMpcSurface {
    async fn send_point_to_point(&self, message: &MpcRoundMessage) -> Result<(), TransportError> {
        let request = round_message_to_request(message);
        self.network
            .send_mpc_relay_message(request)
            .await
            .map_err(|e| TransportError::Send(e.to_string()))
    }

    async fn recv_point_to_point(&self) -> Result<MpcRoundMessage, TransportError> {
        let mut rx = self.inbox.lock().await;
        match rx.recv().await {
            Some(request) => request_to_round_message(request),
            None => Err(TransportError::Closed),
        }
    }
}

/// Convert a bridge-side `MpcRoundMessage` to a network-side
/// `MpcRelayRequest`. Field-for-field copy; only `InstanceId` and `MpcPhase`
/// need unwrapping.
fn round_message_to_request(m: &MpcRoundMessage) -> MpcRelayRequest {
    MpcRelayRequest {
        instance_id: *m.instance_id.as_bytes(),
        phase: phase_to_u8(m.phase),
        round_index: m.round_index,
        from_did: m.from_did.clone(),
        to_did: m.to_did.clone(),
        payload: m.payload.clone(),
    }
}

/// Convert an inbound `MpcRelayRequest` back into the bridge-side
/// `MpcRoundMessage`. Rejects malformed `phase` bytes with `Backend` so the
/// session driver can fail loudly rather than enqueueing a default variant.
fn request_to_round_message(r: MpcRelayRequest) -> Result<MpcRoundMessage, TransportError> {
    let phase = phase_from_u8(r.phase)
        .ok_or_else(|| TransportError::Backend(format!("unknown MPC phase byte: {}", r.phase)))?;
    if r.instance_id.len() != INSTANCE_ID_LEN {
        // `instance_id` is a `[u8; 32]` so this is impossible by construction,
        // but the explicit check documents the wire-layer invariant.
        return Err(TransportError::Backend(format!(
            "wrong instance_id length: {}",
            r.instance_id.len()
        )));
    }
    Ok(MpcRoundMessage {
        instance_id: InstanceId(r.instance_id),
        phase,
        round_index: r.round_index,
        from_did: r.from_did,
        to_did: r.to_did,
        payload: r.payload,
    })
}

fn phase_to_u8(p: MpcPhase) -> u8 {
    match p {
        MpcPhase::Dkg => 0,
        MpcPhase::Sign => 1,
        MpcPhase::Refresh => 2,
        MpcPhase::ReKey => 3,
    }
}

fn phase_from_u8(b: u8) -> Option<MpcPhase> {
    match b {
        0 => Some(MpcPhase::Dkg),
        1 => Some(MpcPhase::Sign),
        2 => Some(MpcPhase::Refresh),
        3 => Some(MpcPhase::ReKey),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_bridge::mpc::setup::SESSION_NONCE_LEN;
    use tenzro_types::Hash;

    fn sample_message() -> MpcRoundMessage {
        let block = Hash::from_bytes(&[1u8; 32]).unwrap();
        MpcRoundMessage {
            instance_id: InstanceId::derive(&block, &[2u8; 32], &[3u8; SESSION_NONCE_LEN]),
            phase: MpcPhase::Refresh,
            round_index: 7,
            from_did: "did:tenzro:machine:p1".to_string(),
            to_did: "did:tenzro:machine:p2".to_string(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    #[test]
    fn phase_round_trip_all_variants() {
        for phase in [
            MpcPhase::Dkg,
            MpcPhase::Sign,
            MpcPhase::Refresh,
            MpcPhase::ReKey,
        ] {
            let byte = phase_to_u8(phase);
            assert_eq!(phase_from_u8(byte), Some(phase));
        }
    }

    #[test]
    fn phase_byte_values_are_canonical() {
        assert_eq!(phase_to_u8(MpcPhase::Dkg), 0);
        assert_eq!(phase_to_u8(MpcPhase::Sign), 1);
        assert_eq!(phase_to_u8(MpcPhase::Refresh), 2);
        assert_eq!(phase_to_u8(MpcPhase::ReKey), 3);
    }

    #[test]
    fn unknown_phase_byte_rejected() {
        assert!(phase_from_u8(4).is_none());
        assert!(phase_from_u8(255).is_none());
    }

    #[test]
    fn round_message_round_trips_through_wire_shape() {
        let msg = sample_message();
        let req = round_message_to_request(&msg);
        assert_eq!(req.instance_id, *msg.instance_id.as_bytes());
        assert_eq!(req.phase, 2); // Refresh
        assert_eq!(req.round_index, msg.round_index);
        assert_eq!(req.from_did, msg.from_did);
        assert_eq!(req.to_did, msg.to_did);
        assert_eq!(req.payload, msg.payload);

        let back = request_to_round_message(req).expect("round-trip");
        assert_eq!(back, msg);
    }

    #[test]
    fn request_with_bad_phase_is_rejected() {
        let bad = MpcRelayRequest {
            instance_id: [9u8; 32],
            phase: 99,
            round_index: 0,
            from_did: "did:x".to_string(),
            to_did: "did:y".to_string(),
            payload: vec![],
        };
        let err = request_to_round_message(bad).expect_err("bad phase");
        assert!(matches!(err, TransportError::Backend(_)));
    }

    #[test]
    fn registry_insert_and_resolve_both_directions() {
        let reg = MpcDidPeerRegistry::new();
        assert!(reg.is_empty());

        let did = "did:tenzro:machine:p1".to_string();
        let peer = PeerId::random();
        reg.insert(did.clone(), peer);
        assert_eq!(reg.len(), 1);

        assert_eq!(reg.peer_id_for_did(&did), Some(peer));
        assert_eq!(reg.did_for_peer_id(&peer), Some(did));

        // Unknown lookups return None, never default.
        assert_eq!(reg.peer_id_for_did("did:tenzro:machine:unknown"), None);
        assert_eq!(reg.did_for_peer_id(&PeerId::random()), None);
    }

    #[test]
    fn registry_insert_overwrites_existing_did_binding() {
        let reg = MpcDidPeerRegistry::new();
        let did = "did:tenzro:machine:p1".to_string();
        let peer_old = PeerId::random();
        let peer_new = PeerId::random();
        assert_ne!(peer_old, peer_new);

        reg.insert(did.clone(), peer_old);
        reg.insert(did.clone(), peer_new);

        assert_eq!(reg.peer_id_for_did(&did), Some(peer_new));
        // The old reverse mapping is left in place — the registry is a
        // best-effort cache, not a transactional store; callers that care
        // about evictions must rebuild the registry. The new reverse
        // mapping is what gets consulted on the live session.
        assert_eq!(reg.did_for_peer_id(&peer_new), Some(did));
    }

    #[test]
    fn registry_insert_self_is_two_way() {
        let reg = MpcDidPeerRegistry::new();
        let local_did = "did:tenzro:machine:local".to_string();
        let local_peer = PeerId::random();
        reg.insert_self(local_did.clone(), local_peer);

        assert_eq!(reg.peer_id_for_did(&local_did), Some(local_peer));
        assert_eq!(reg.did_for_peer_id(&local_peer), Some(local_did));
    }
}
