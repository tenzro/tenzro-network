//! Content-addressed outer-gradient payload store.
//!
//! [`OuterGradient`](tenzro_types::training::OuterGradient) carries only the
//! BLAKE3-equivalent SHA-256 `safetensors_hash` and `payload_bytes` size; the
//! actual safetensors bytes live off the gossip path. This module defines the
//! abstraction the syncer uses to publish gradients it produced locally and
//! to fetch gradients announced by remote trainers before running aggregation.
//!
//! Per the model statement (locked 2026-05-17): **"Tenzro uses Iroh as a
//! performance-oriented P2P data plane while retaining libp2p-style
//! interoperability for decentralized coordination."** Outer-gradient bulk
//! transfer is data-plane work — the protocol layer asks for "publish/fetch
//! by content hash" and a concrete adapter (e.g. `tenzro-iroh`'s
//! `IrohGradientStore`, landing as Phase B1 #216) provides the bytes via
//! iroh-blobs.
//!
//! # Why a dedicated trait (and not just reuse `DaBackend`)
//!
//! `DaBackend` returns a `DaPointer` whose locator the caller stores in a
//! receipt envelope. Outer-gradient distribution has no envelope — the
//! `safetensors_hash` already on the gossiped `OuterGradient` IS the locator,
//! and aggregation pulls the bytes by that hash. A `DaBackend` round-trip
//! would force a second locator that's redundant (different shape, same
//! content). This trait is the minimal surface that matches the consumer.
//!
//! # Integrity contract
//!
//! On fetch, implementations MUST verify the returned bytes hash to
//! `expected.safetensors_hash` (typically by virtue of BLAKE3 self-verification
//! at the transport layer, plus a SHA-256 re-check at the protocol boundary)
//! and that `bytes.len() == expected.payload_bytes`. The default
//! [`InMemoryGradientStore`] enforces both directly. Adapters that delegate
//! integrity to a content-addressed transport (iroh-blobs verifies BLAKE3
//! end-to-end on transfer) MUST still run the protocol-side check to defend
//! against an adapter wiring bug; cheap belt-and-braces.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use tenzro_types::primitives::Hash;
use tenzro_types::training::OuterGradient;

use crate::error::{Result, TrainingError};

/// Content-addressed publish/fetch surface for outer-gradient safetensors
/// payloads.
///
/// Implementations are constructed by the node (Phase C1 wires the iroh-blobs
/// adapter alongside the in-memory default) and shared with the
/// [`TrainingRuntime`](crate::TrainingRuntime) via
/// [`TrainingRuntime::with_payload_store`](crate::TrainingRuntime::with_payload_store).
#[async_trait]
pub trait GradientPayloadStore: Send + Sync {
    /// Backend identifier — for logs, metrics, and the
    /// `tenzro_training_status` RPC. Stable across restarts.
    fn id(&self) -> &'static str;

    /// Publish a payload. Returns the SHA-256 hash of `payload` (which MUST
    /// equal the `safetensors_hash` on the corresponding
    /// [`OuterGradient`]). Idempotent — re-publishing the same bytes yields
    /// the same hash and does not error.
    async fn publish(&self, payload: Bytes) -> Result<Hash>;

    /// Fetch a payload by an announced [`OuterGradient`]. Implementations
    /// MUST verify the returned bytes match `expected.safetensors_hash` and
    /// `expected.payload_bytes` before returning, raising
    /// [`TrainingError::PayloadHashMismatch`] or
    /// [`TrainingError::PayloadSizeMismatch`] otherwise.
    async fn fetch(&self, expected: &OuterGradient) -> Result<Bytes>;
}

/// Compute the SHA-256 hash of a payload, in the protocol's canonical
/// [`Hash`] shape. Used by adapters to satisfy the integrity contract on
/// fetch.
pub fn compute_payload_hash(payload: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Hash::new(bytes)
}

/// Verify a fetched payload against an announced gradient. Returns
/// `Ok(())` on match. Used by every adapter — including the in-memory default
/// — so a wiring bug surfaces immediately rather than corrupting aggregation.
pub fn verify_payload(expected: &OuterGradient, payload: &[u8]) -> Result<()> {
    if payload.len() as u64 != expected.payload_bytes {
        return Err(TrainingError::PayloadSizeMismatch {
            header: expected.payload_bytes,
            actual: payload.len() as u64,
        });
    }
    if compute_payload_hash(payload) != expected.safetensors_hash {
        return Err(TrainingError::PayloadHashMismatch);
    }
    Ok(())
}

/// In-process, in-memory [`GradientPayloadStore`] backed by a
/// [`DashMap`] keyed by [`Hash`]. The fallback when no networked adapter is
/// wired — useful for unit tests and single-node training reproductions.
///
/// Does NOT persist across restarts and does NOT distribute payloads across
/// nodes. Production deployments swap this for an iroh-blobs adapter.
#[derive(Debug, Default)]
pub struct InMemoryGradientStore {
    by_hash: DashMap<Hash, Bytes>,
}

impl InMemoryGradientStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arc() -> Arc<dyn GradientPayloadStore> {
        Arc::new(Self::new())
    }

    /// How many distinct payloads are currently held. Useful for tests
    /// asserting publish idempotency.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

#[async_trait]
impl GradientPayloadStore for InMemoryGradientStore {
    fn id(&self) -> &'static str {
        "in_memory"
    }

    async fn publish(&self, payload: Bytes) -> Result<Hash> {
        let hash = compute_payload_hash(&payload);
        // Insert is content-addressed-idempotent: the same payload always
        // computes to the same hash; we just overwrite the equivalent entry.
        self.by_hash.insert(hash, payload);
        Ok(hash)
    }

    async fn fetch(&self, expected: &OuterGradient) -> Result<Bytes> {
        let bytes = self
            .by_hash
            .get(&expected.safetensors_hash)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                TrainingError::Internal(format!(
                    "InMemoryGradientStore has no payload for hash {}",
                    expected.safetensors_hash
                ))
            })?;
        verify_payload(expected, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::{Address, Signature, Timestamp};

    fn make_gradient(hash: Hash, len: u64) -> OuterGradient {
        OuterGradient {
            task_id: "task-1".into(),
            round: 0,
            fragment: 0,
            trainer_did: "did:tenzro:machine:trainer-1".into(),
            trainer_address: Address::new([1u8; 32]),
            safetensors_hash: hash,
            payload_bytes: len,
            inner_step_count: 100,
            submitted_at: Timestamp::new(1_700_000_000_000),
            signature: Signature::new(vec![0u8; 64], vec![0u8; 32]),
            attestation: None,
        }
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips() {
        let store = InMemoryGradientStore::new();
        let payload = Bytes::from_static(b"safetensors-encoded outer gradient");
        let hash = store.publish(payload.clone()).await.unwrap();

        let grad = make_gradient(hash, payload.len() as u64);
        let fetched = store.fetch(&grad).await.unwrap();
        assert_eq!(fetched, payload);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_publish_is_idempotent() {
        let store = InMemoryGradientStore::new();
        let payload = Bytes::from_static(b"same bytes twice");
        let h1 = store.publish(payload.clone()).await.unwrap();
        let h2 = store.publish(payload.clone()).await.unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn distinct_payloads_distinct_hashes() {
        let store = InMemoryGradientStore::new();
        let h1 = store.publish(Bytes::from_static(b"a")).await.unwrap();
        let h2 = store.publish(Bytes::from_static(b"b")).await.unwrap();
        assert_ne!(h1, h2);
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn fetch_with_size_mismatch_rejects() {
        let store = InMemoryGradientStore::new();
        let payload = Bytes::from_static(b"some payload");
        let hash = store.publish(payload.clone()).await.unwrap();
        // Announced size is wrong — must be caught.
        let lying = make_gradient(hash, payload.len() as u64 + 1);
        let err = store.fetch(&lying).await.unwrap_err();
        assert!(matches!(err, TrainingError::PayloadSizeMismatch { .. }), "{:?}", err);
    }

    #[tokio::test]
    async fn fetch_unknown_hash_errors() {
        let store = InMemoryGradientStore::new();
        let bogus = make_gradient(Hash::new([0u8; 32]), 0);
        let err = store.fetch(&bogus).await.unwrap_err();
        assert!(matches!(err, TrainingError::Internal(_)));
    }

    #[test]
    fn verify_payload_size_mismatch() {
        let payload = b"abc";
        let hash = compute_payload_hash(payload);
        let grad = make_gradient(hash, 10); // lying about size
        let err = verify_payload(&grad, payload).unwrap_err();
        assert!(matches!(err, TrainingError::PayloadSizeMismatch { header: 10, actual: 3 }));
    }

    #[test]
    fn verify_payload_hash_mismatch() {
        let payload = b"abc";
        let grad = make_gradient(Hash::new([7u8; 32]), payload.len() as u64);
        let err = verify_payload(&grad, payload).unwrap_err();
        assert!(matches!(err, TrainingError::PayloadHashMismatch));
    }

    #[test]
    fn verify_payload_matches() {
        let payload = b"abc";
        let hash = compute_payload_hash(payload);
        let grad = make_gradient(hash, payload.len() as u64);
        verify_payload(&grad, payload).unwrap();
    }
}
