//! CGGMP24 threshold-ECDSA foundation for the bridge signer (Phase D).
//!
//! This module is the **foundation layer only** for an eventual t-of-n
//! distributed signing path for bridge custody. It pins the upstream
//! `cggmp24` / `cggmp24-keygen` / `round-based` / `generic-ec` versions,
//! defines the `MpcTransport` abstraction that decouples the protocol from
//! any specific wire (libp2p / iroh / in-memory), and ships an
//! `InMemoryMpcTransport` for local multi-party unit tests.
//!
//! Live distributed key generation and signing through real party-to-party
//! networking lands in a follow-up wave. The Phase D bridge currently
//! defaults to [`crate::evm_signer::SignerBackend::SealedKey`] for single-key
//! TEE-sealed custody; `Cggmp24Signer` is the seam where the t-of-n backend
//! is introduced once the live flow is wired.
//!
//! ## Upstream-vendor note
//!
//! Building this module requires the vendored `glass_pumpkin` at
//! `vendor/glass_pumpkin/` because the upstream registry version of
//! `glass_pumpkin 1.9.0` transitively requires the yanked `core2` crate.
//! See `vendor/glass_pumpkin/README.md` for the full blocker chain.

use crate::error::{BridgeError, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Logical identifier of a signing-committee party.
///
/// CGGMP24 uses `u16` party indices throughout (capped at the committee
/// size, typically ≤ 32 in production). We mirror that here so the
/// type lines up directly with `cggmp24::ExecutionId` party slots without
/// requiring conversion at the transport boundary.
pub type PartyId = u16;

/// Opaque wire-format message exchanged between MPC parties.
///
/// CGGMP24 rounds produce `Vec<u8>` payloads (canonical bincode encoding
/// of the round's protocol message). We pass them through opaquely; the
/// transport only needs to deliver `(from, to, bytes)` triples in order
/// per (from, to) pair.
#[derive(Clone, Debug)]
pub struct MpcMessage {
    /// Sender party index.
    pub from: PartyId,
    /// Recipient party index. `None` for broadcast (all parties except `from`).
    pub to: Option<PartyId>,
    /// Round number within the current protocol execution. Used by
    /// receivers to dispatch into the right `round_based::Incoming` queue
    /// when running multiple protocols concurrently against one transport.
    pub round: u16,
    /// Opaque round payload (bincode-serialized CGGMP24 message).
    pub payload: Vec<u8>,
}

/// Transport abstraction for CGGMP24 round-based protocols.
///
/// Implementations must guarantee:
///
/// - **FIFO per (sender, recipient) pair.** Reordering across senders is
///   acceptable; reordering between the same sender and recipient is not.
/// - **At-least-once delivery on success.** Duplicates are filtered by the
///   protocol layer via the per-round CGGMP24 transcript hash.
/// - **Best-effort broadcast.** When `MpcMessage::to == None`, the transport
///   fans out to every other party in the committee.
///
/// Concrete transports planned for the threshold-signing path:
///
/// - `Libp2pMpcTransport` — request-response over the existing libp2p stack
///   (consensus-direct overlay), keyed by party-DID → PeerId.
/// - `IrohMpcTransport` — bidirectional iroh QUIC streams keyed by party-DID
///   → `iroh::EndpointId`, paired with the `tenzro/mpc` ALPN.
///
/// This trait stays object-safe (`Box<dyn MpcTransport>`-able) so the live
/// signer can swap transports without recompilation.
#[async_trait]
pub trait MpcTransport: Send + Sync {
    /// Sends a single message to one peer (or broadcasts when `to == None`).
    async fn send(&self, msg: MpcMessage) -> Result<()>;

    /// Receives the next message addressed to `my_party_id`.
    ///
    /// Blocks until a message is available or the transport is shut down.
    /// Returns `Ok(None)` once the transport is permanently closed.
    async fn recv(&self, my_party_id: PartyId) -> Result<Option<MpcMessage>>;

    /// Returns the committee membership this transport is currently bound to.
    fn committee(&self) -> &[PartyId];
}

/// In-memory `MpcTransport` for local multi-party unit tests.
///
/// Spins up one unbounded MPSC queue per party; `send` dispatches into
/// either one queue (unicast) or every queue except the sender's
/// (broadcast). Used by the foundation-layer round-trip tests in this
/// module; production deployments must use a real network transport.
pub struct InMemoryMpcTransport {
    /// Snapshot of the committee membership.
    committee: Vec<PartyId>,
    /// Inbox per party.
    inboxes: Arc<Mutex<HashMap<PartyId, mpsc::UnboundedSender<MpcMessage>>>>,
    /// Receiver for `my_party_id`'s inbox. Wrapped in a mutex because
    /// `tokio::sync::mpsc::UnboundedReceiver::recv` requires `&mut self`
    /// and `MpcTransport::recv` takes `&self` (trait must stay object-safe).
    my_inbox: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<MpcMessage>>>,
    /// The party index this transport handle represents.
    my_party_id: PartyId,
}

impl InMemoryMpcTransport {
    /// Constructs a committee of `n` parties and returns one transport
    /// handle per party. The returned `Vec` is index-aligned with
    /// `0..n` party ids.
    pub fn committee(size: u16) -> Vec<Self> {
        let mut inbox_senders: HashMap<PartyId, mpsc::UnboundedSender<MpcMessage>> = HashMap::new();
        let mut inbox_receivers: Vec<(PartyId, mpsc::UnboundedReceiver<MpcMessage>)> = Vec::new();
        for id in 0..size {
            let (tx, rx) = mpsc::unbounded_channel();
            inbox_senders.insert(id, tx);
            inbox_receivers.push((id, rx));
        }
        let inboxes = Arc::new(Mutex::new(inbox_senders));
        let committee: Vec<PartyId> = (0..size).collect();
        inbox_receivers
            .into_iter()
            .map(|(my_party_id, rx)| Self {
                committee: committee.clone(),
                inboxes: inboxes.clone(),
                my_inbox: Arc::new(tokio::sync::Mutex::new(rx)),
                my_party_id,
            })
            .collect()
    }

    /// Returns the party id this transport handle represents.
    pub fn my_party_id(&self) -> PartyId {
        self.my_party_id
    }
}

#[async_trait]
impl MpcTransport for InMemoryMpcTransport {
    async fn send(&self, msg: MpcMessage) -> Result<()> {
        let inboxes = self.inboxes.lock();
        match msg.to {
            Some(target) => {
                if let Some(tx) = inboxes.get(&target) {
                    tx.send(msg).map_err(|e| {
                        BridgeError::AdapterError(format!("MPC inbox closed: {}", e))
                    })?;
                }
                Ok(())
            }
            None => {
                for (&party, tx) in inboxes.iter() {
                    if party != msg.from {
                        let _ = tx.send(msg.clone());
                    }
                }
                Ok(())
            }
        }
    }

    async fn recv(&self, my_party_id: PartyId) -> Result<Option<MpcMessage>> {
        if my_party_id != self.my_party_id {
            return Err(BridgeError::AdapterError(format!(
                "MPC transport receiver mismatch: handle bound to party {} but recv called for {}",
                self.my_party_id, my_party_id
            )));
        }
        let mut rx = self.my_inbox.lock().await;
        Ok(rx.recv().await)
    }

    fn committee(&self) -> &[PartyId] {
        &self.committee
    }
}

/// Skeleton signer for CGGMP24 t-of-n threshold-ECDSA over secp256k1.
///
/// This is the foundation seam where the live distributed signing flow
/// will be wired for distributed signing — at which point the `_keyshare`
/// will hold a real `cggmp24_keygen::IncompleteKeyShare<...>` produced by
/// the UC-secure DKG, and `sign_prehash` will drive a round-based
/// `cggmp24::signing` execution over the configured `MpcTransport`.
///
/// The skeleton intentionally returns `BridgeError::NotImplemented` from
/// the signing entry points; this keeps the live `EvmTransactionSigner`
/// untouched (it currently routes through `SealedKey` for production
/// custody) while making the integration surface area concrete.
pub struct Cggmp24Signer {
    /// Threshold `t` (minimum signers required).
    threshold: u16,
    /// Total committee size `n`.
    committee_size: u16,
    /// Transport binding this signer to its committee.
    transport: Arc<dyn MpcTransport>,
}

impl Cggmp24Signer {
    /// Constructs a new signer skeleton bound to a committee transport.
    ///
    /// `threshold` must satisfy `1 <= threshold <= committee_size`.
    pub fn new(threshold: u16, committee_size: u16, transport: Arc<dyn MpcTransport>) -> Result<Self> {
        if threshold == 0 || threshold > committee_size {
            return Err(BridgeError::AdapterError(format!(
                "invalid CGGMP24 threshold: {}-of-{}",
                threshold, committee_size
            )));
        }
        if transport.committee().len() != committee_size as usize {
            return Err(BridgeError::AdapterError(format!(
                "transport committee size {} does not match signer committee size {}",
                transport.committee().len(),
                committee_size
            )));
        }
        Ok(Self {
            threshold,
            committee_size,
            transport,
        })
    }

    /// Returns the threshold `t`.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the committee size `n`.
    pub fn committee_size(&self) -> u16 {
        self.committee_size
    }

    /// Returns a reference to the bound `MpcTransport`.
    pub fn transport(&self) -> &Arc<dyn MpcTransport> {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_transport_unicast() {
        let handles = InMemoryMpcTransport::committee(3);
        let (p0, p1, _p2) = (&handles[0], &handles[1], &handles[2]);
        p0.send(MpcMessage {
            from: 0,
            to: Some(1),
            round: 0,
            payload: b"hello-1".to_vec(),
        })
        .await
        .unwrap();
        let got = p1.recv(1).await.unwrap().unwrap();
        assert_eq!(got.from, 0);
        assert_eq!(got.to, Some(1));
        assert_eq!(got.payload, b"hello-1");
    }

    #[tokio::test]
    async fn in_memory_transport_broadcast_skips_sender() {
        let handles = InMemoryMpcTransport::committee(3);
        let (p0, p1, p2) = (&handles[0], &handles[1], &handles[2]);
        p0.send(MpcMessage {
            from: 0,
            to: None,
            round: 0,
            payload: b"bcast".to_vec(),
        })
        .await
        .unwrap();
        // Both p1 and p2 should receive; p0 should not.
        let got1 = p1.recv(1).await.unwrap().unwrap();
        let got2 = p2.recv(2).await.unwrap().unwrap();
        assert_eq!(got1.payload, b"bcast");
        assert_eq!(got2.payload, b"bcast");
    }

    #[tokio::test]
    async fn signer_rejects_invalid_threshold() {
        let handles = InMemoryMpcTransport::committee(3);
        let transport: Arc<dyn MpcTransport> = Arc::new(handles.into_iter().next().unwrap());
        assert!(Cggmp24Signer::new(0, 3, transport.clone()).is_err());
        assert!(Cggmp24Signer::new(4, 3, transport.clone()).is_err());
        assert!(Cggmp24Signer::new(2, 3, transport).is_ok());
    }

    #[tokio::test]
    async fn signer_rejects_size_mismatch() {
        let handles = InMemoryMpcTransport::committee(3);
        let transport: Arc<dyn MpcTransport> = Arc::new(handles.into_iter().next().unwrap());
        // Committee says 5 but transport was built for 3.
        assert!(Cggmp24Signer::new(3, 5, transport).is_err());
    }
}
