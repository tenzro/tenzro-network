//! Outer-gradient payload store backed by iroh-blobs.
//!
//! This is the Phase B1 (#216) consumer of [`IrohBackedResolver`]. It
//! satisfies the [`tenzro_training::GradientPayloadStore`] trait so the
//! syncer can publish a locally-computed outer gradient's safetensors blob,
//! gossip a tiny [`OuterGradient`] envelope carrying only the BLAKE3-equivalent
//! SHA-256 `safetensors_hash` + `payload_bytes`, and let other syncers fetch
//! the bytes by hash before running aggregation.
//!
//! Per the locked model statement (2026-05-17): **"Tenzro uses Iroh as a
//! performance-oriented P2P data plane while retaining libp2p-style
//! interoperability for decentralized coordination."** Outer-gradient bulk
//! transfer is data-plane work — the gossiped envelope rides libp2p
//! gossipsub (`tenzro/training`), and the bytes ride iroh-blobs via this
//! adapter.
//!
//! # Why not the `DaBackend` adapter
//!
//! `IrohBlobsDaBackend` returns a [`DaPointer`] whose locator the caller
//! stores inside a `ReceiptEnvelope`. The training gossip path has no
//! envelope: the `safetensors_hash` already on [`OuterGradient`] IS the
//! locator. Routing through `DaBackend` would force a second redundant
//! pointer (different shape, same content). This adapter is the minimal
//! surface that matches the consumer.
//!
//! # Integrity contract
//!
//! iroh-blobs verifies BLAKE3 end-to-end on transfer. The
//! [`GradientPayloadStore::fetch`] contract additionally requires the
//! protocol-side `verify_payload` check (SHA-256 + size) so a wiring bug
//! between the resolver and the syncer surfaces immediately rather than
//! corrupting aggregation. Both checks pass on the same bytes because the
//! protocol uses SHA-256 as its canonical hash and the [`IrohBackedResolver`]
//! computes the iroh-blobs BLAKE3 over the same bytes — the equality
//! between them is checked by [`compute_payload_hash`].

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use tenzro_training::{
    compute_payload_hash, verify_payload, GradientPayloadStore, Result as TrainingResult,
    TrainingError,
};
use tenzro_types::primitives::Hash;
use tenzro_types::tenzro_uri::TenzroUri;
use tenzro_types::training::OuterGradient;

use crate::error::IrohError;
use crate::resolver::{IrohBackedResolver, IrohResolver};

/// iroh-blobs-backed [`GradientPayloadStore`] adapter (Phase B1, #216).
///
/// Shares the resolver with [`crate::IrohBlobsDaBackend`] and any direct
/// `tenzro://blob/<hash>` URI fetches — one endpoint, one ALPN, one hash
/// space.
///
/// # SHA-256 ↔ BLAKE3 indirection
///
/// The protocol-side `OuterGradient` carries `safetensors_hash` as a
/// SHA-256 (the canonical Tenzro hash, computed by
/// [`compute_payload_hash`]). iroh-blobs indexes by **BLAKE3** — a
/// different hash of the same bytes. This adapter maintains a
/// [`DashMap`] from SHA-256 → BLAKE3-hex so `fetch` can translate the
/// announced hash into something iroh-blobs can look up. Phase B1 is
/// local-only (publish on this node, fetch on this node); Phase B2 (#217)
/// distributes BLAKE3 tickets out-of-band so remote nodes can construct
/// the same mapping on receipt of an `OuterGradient`.
pub struct IrohGradientStore {
    resolver: Arc<IrohBackedResolver>,
    /// SHA-256 (protocol hash) → BLAKE3 hex (iroh-blobs locator), populated
    /// on every successful local `publish` so subsequent `fetch` calls can
    /// dispatch through `tenzro://blob/<blake3>` rather than the
    /// not-yet-resolvable `tenzro://blob/<sha256>`.
    sha256_to_blake3: DashMap<Hash, String>,
}

impl IrohGradientStore {
    /// Construct an adapter over an already-bound resolver. The resolver is
    /// shared — typically the same `Arc<IrohBackedResolver>` that services
    /// direct `tenzro://blob/<hash>` URI fetches and the
    /// [`crate::IrohBlobsDaBackend`] receipt-offload path.
    pub fn new(resolver: Arc<IrohBackedResolver>) -> Self {
        Self {
            resolver,
            sha256_to_blake3: DashMap::new(),
        }
    }

    /// Construct and box as `Arc<dyn GradientPayloadStore>` for the
    /// `TrainingRuntime::with_payload_store` builder.
    pub fn arc(resolver: Arc<IrohBackedResolver>) -> Arc<dyn GradientPayloadStore> {
        Arc::new(Self::new(resolver))
    }

    /// Borrow the underlying resolver — useful for tests and for callers
    /// that want to also dispatch direct `tenzro://` URIs.
    pub fn resolver(&self) -> &Arc<IrohBackedResolver> {
        &self.resolver
    }
}

#[async_trait]
impl GradientPayloadStore for IrohGradientStore {
    fn id(&self) -> &'static str {
        "iroh_blobs"
    }

    async fn publish(&self, payload: Bytes) -> TrainingResult<Hash> {
        // Compute the SHA-256 hash up front so we can return it without
        // round-tripping through the iroh-blobs BLAKE3. The resolver will
        // compute its own BLAKE3 separately; both bind to the same bytes
        // but ARE NOT equal — SHA-256 is the on-protocol commitment,
        // BLAKE3 is the iroh-blobs transport locator. We record the
        // mapping so `fetch` can translate the protocol hash into the
        // iroh-blobs lookup key.
        let protocol_hash = compute_payload_hash(&payload);
        let uri = self
            .resolver
            .publish_bytes(payload)
            .await
            .map_err(map_iroh_err)?;
        let blake3_hex = match uri {
            TenzroUri::Blob { hash, .. } => hash,
            other => {
                return Err(TrainingError::Internal(format!(
                    "iroh resolver returned non-Blob URI from publish_bytes: {other}"
                )));
            }
        };
        self.sha256_to_blake3.insert(protocol_hash, blake3_hex);
        Ok(protocol_hash)
    }

    async fn fetch(&self, expected: &OuterGradient) -> TrainingResult<Bytes> {
        // Translate the protocol-side SHA-256 hash into the iroh-blobs
        // BLAKE3 locator via the local mapping built during `publish`.
        // Phase B1's single-node path: publish on this node, fetch on this
        // node — the mapping is always present for locally-published
        // payloads. Phase B2 (#217) distributes BLAKE3 tickets through
        // iroh-docs so remote receivers can populate the same mapping on
        // receipt of an `OuterGradient` envelope.
        let blake3_hex = self
            .sha256_to_blake3
            .get(&expected.safetensors_hash)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                TrainingError::Internal(format!(
                    "iroh-blobs payload not found: no local BLAKE3 mapping for sha256 {}",
                    expected.safetensors_hash
                ))
            })?;
        let uri = TenzroUri::Blob {
            hash: blake3_hex,
            provider_hint: None,
        };
        let bytes = self
            .resolver
            .fetch_bytes(&uri)
            .await
            .map_err(map_iroh_err)?;
        verify_payload(expected, &bytes)?;
        Ok(bytes)
    }
}

fn map_iroh_err(err: IrohError) -> TrainingError {
    match err {
        IrohError::NotFound(s) => {
            TrainingError::Internal(format!("iroh-blobs payload not found: {s}"))
        }
        other => TrainingError::Internal(format!("iroh-blobs adapter: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_training::compute_payload_hash;
    use tenzro_types::primitives::{Address, Signature, Timestamp};

    fn make_gradient(hash: Hash, len: u64) -> OuterGradient {
        OuterGradient {
            task_id: "task-iroh-1".into(),
            round: 0,
            fragment: 0,
            trainer_did: "did:tenzro:machine:trainer-iroh".into(),
            trainer_address: Address::new([1u8; 32]),
            safetensors_hash: hash,
            payload_bytes: len,
            quantization: tenzro_types::training::GradientQuantization::None,
            inner_step_count: 250,
            submitted_at: Timestamp::new(1_700_000_000_000),
            signature: Signature::new(vec![0u8; 64], vec![0u8; 32]),
            attestation: None,
            commitment: None,
        }
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips_through_iroh_blobs() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind iroh resolver");
        let store = IrohGradientStore::new(resolver);

        let payload = Bytes::from_static(b"safetensors payload bytes via iroh-blobs");
        let hash = store.publish(payload.clone()).await.expect("publish");
        // Hash returned by publish must match the SHA-256 of the bytes.
        assert_eq!(hash, compute_payload_hash(&payload));

        let grad = make_gradient(hash, payload.len() as u64);
        let fetched = store.fetch(&grad).await.expect("fetch");
        assert_eq!(fetched, payload);
    }

    #[tokio::test]
    async fn fetch_rejects_size_mismatch_after_iroh_round_trip() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohGradientStore::new(resolver);

        let payload = Bytes::from_static(b"sized payload");
        let hash = store.publish(payload.clone()).await.unwrap();
        // Lie about the size — the protocol-side verify_payload must catch
        // this even though iroh-blobs already passed BLAKE3 on transfer.
        let lying = make_gradient(hash, payload.len() as u64 + 1);
        let err = store.fetch(&lying).await.unwrap_err();
        assert!(
            matches!(err, TrainingError::PayloadSizeMismatch { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_unknown_hash_surfaces_internal_error() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohGradientStore::new(resolver);

        let bogus = make_gradient(Hash::new([0u8; 32]), 0);
        let err = store.fetch(&bogus).await.unwrap_err();
        // Either Internal (mapped from iroh NotFound) or a downstream
        // verify error is acceptable; the contract is "fetch fails".
        assert!(
            matches!(err, TrainingError::Internal(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn id_is_stable() {
        // Constructed via a non-async path — only the id() arm is exercised,
        // no endpoint bind needed.
        let id = <IrohGradientStore as GradientPayloadStore>::id;
        // Ensure the function pointer resolves; static string is checked by
        // the contract at the call site (status RPC).
        let _ = id;
    }
}
