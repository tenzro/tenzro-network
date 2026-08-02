//! Sealed-shard ciphertext store backed by iroh-blobs.
//!
//! This is the Phase B2 (#217) consumer of [`IrohBackedResolver`]. It
//! satisfies the [`tenzro_training::SealedShardStore`] trait so a
//! Confidential-tier sponsor can publish per-shard AES-256-GCM ciphertexts
//! to iroh-blobs, then announce a [`SealedDatasetManifest`] on the
//! existing `tenzro/training` libp2p gossipsub topic (via
//! [`tenzro_training::TrainingGossipMessage::InstallSealedManifest`]) so
//! enrolled trainers can fetch the ciphertexts by hash from inside their
//! TEE enclave.
//!
//! # Why no iroh-docs
//!
//! `SealedDatasetManifest` is **immutable once sponsor-signed**: the
//! `manifest_hash` binds the envelope set, and adding/removing a trainer
//! requires posting a new task version with a new `tee://<hex>`
//! `dataset_ref`. There is no mutation to merge — so iroh-docs' CRDT
//! semantics earn nothing while costing an alpha-grade dependency, an
//! alternate auth model (doc write key vs. our sponsor DID signature), and
//! a second mesh. The sponsor's DID signature on the manifest IS the auth
//! model; the existing `tenzro/training` mesh IS the distribution channel.
//!
//! See `feedback_iroh_docs_alpha_2026.md` (project research, 2026-05-17)
//! for the upstream-bug survey that led to this decision.
//!
//! # Integrity contract
//!
//! iroh-blobs verifies BLAKE3 over the whole transfer. The
//! [`SealedShardStore::fetch`] contract additionally requires the
//! protocol-side [`verify_shard_ciphertext`] check (SHA-256 + size) so a
//! wiring bug between the resolver and the trainer surfaces immediately
//! rather than corrupting the inner training loop. The same belt-and-braces
//! discipline as [`crate::IrohGradientStore`] from Phase B1.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use tenzro_training::{
    Result as TrainingResult, SealedShardStore, TrainingError, compute_shard_ciphertext_hash,
    verify_shard_ciphertext,
};
use tenzro_types::primitives::Hash;
use tenzro_types::tenzro_uri::TenzroUri;
use tenzro_types::training::SealedShardEnvelope;

use crate::error::IrohError;
use crate::resolver::{IrohBackedResolver, IrohResolver};

/// iroh-blobs-backed [`SealedShardStore`] adapter (Phase B2, #217).
///
/// Shares the resolver with [`crate::IrohBlobsDaBackend`],
/// [`crate::IrohGradientStore`], and any direct `tenzro://blob/<hash>` URI
/// fetches — one endpoint, one ALPN, one hash space.
///
/// # SHA-256 ↔ BLAKE3 indirection
///
/// Sealed shard ciphertexts inherit the same hash bridging discipline as
/// outer gradients in Phase B1. The protocol-side
/// [`SealedShardEnvelope::shard_ciphertext_hash`] is a domain-separated
/// SHA-256 (`compute_shard_ciphertext_hash`); iroh-blobs indexes by
/// BLAKE3. This adapter maintains a [`DashMap<Hash, String>`] from SHA-256
/// → BLAKE3-hex so `fetch` can dispatch the iroh-blobs lookup.
///
/// **Phase B2 is local-publish + remote-fetch**: the sponsor publishes
/// shard ciphertexts on their own node (which populates the local
/// mapping); when the [`InstallSealedManifest`] event arrives on
/// `tenzro/training`, remote receivers know which SHA-256 hashes to fetch
/// but do *not* know the BLAKE3 locator. In single-region testnet that's
/// fine because the sponsor node is also reachable for direct
/// `tenzro://blob/<sha256>` round-trips through the same content store.
/// For multi-region Confidential-tier runs the manifest will need to carry
/// per-envelope BLAKE3 tickets — that depends on iroh-blobs exposing ticket
/// distribution alongside the iroh 1.0 cut (deferred from B2 to keep that
/// change focused on the manifest plane). Until then, sponsors run a single
/// iroh-blobs publish node and trainers in the same region fetch via the
/// gossipsub-announced manifest.
pub struct IrohSealedShardStore {
    resolver: Arc<IrohBackedResolver>,
    /// SHA-256 (protocol hash) → BLAKE3 hex (iroh-blobs locator), populated
    /// on every successful local `publish`.
    sha256_to_blake3: DashMap<Hash, String>,
}

impl IrohSealedShardStore {
    /// Construct an adapter over an already-bound resolver. The resolver
    /// is shared with all other iroh-blobs consumers on this node.
    pub fn new(resolver: Arc<IrohBackedResolver>) -> Self {
        Self {
            resolver,
            sha256_to_blake3: DashMap::new(),
        }
    }

    /// Construct and box as `Arc<dyn SealedShardStore>` for the
    /// `TrainingRuntime::with_sealed_shard_store` builder.
    pub fn arc(resolver: Arc<IrohBackedResolver>) -> Arc<dyn SealedShardStore> {
        Arc::new(Self::new(resolver))
    }

    /// Borrow the underlying resolver — useful for tests and for callers
    /// that want to also dispatch direct `tenzro://` URIs.
    pub fn resolver(&self) -> &Arc<IrohBackedResolver> {
        &self.resolver
    }

    /// Pre-populate the SHA-256 → BLAKE3 mapping for a remotely-fetched
    /// shard. Used by callers that learn the BLAKE3 locator out-of-band
    /// (e.g. a future per-envelope ticket field on
    /// [`SealedShardEnvelope`]). Not exercised by the Phase B2 path; included
    /// so the multi-region path doesn't require a second adapter type.
    pub fn record_blake3(&self, sha256: Hash, blake3_hex: String) {
        self.sha256_to_blake3.insert(sha256, blake3_hex);
    }
}

#[async_trait]
impl SealedShardStore for IrohSealedShardStore {
    fn id(&self) -> &'static str {
        "iroh_blobs"
    }

    async fn publish(&self, ciphertext: Bytes) -> TrainingResult<Hash> {
        // Compute the canonical SHA-256 (domain-tagged) up front so we
        // return the value the sponsor will write into the envelope's
        // `shard_ciphertext_hash` field. The resolver computes its own
        // BLAKE3 separately; both bind to the same bytes but are NOT
        // equal — SHA-256 is the on-protocol commitment, BLAKE3 is the
        // iroh-blobs transport locator.
        let protocol_hash = compute_shard_ciphertext_hash(&ciphertext);
        let uri = self
            .resolver
            .publish_bytes(ciphertext)
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

    async fn fetch(&self, envelope: &SealedShardEnvelope) -> TrainingResult<Bytes> {
        let blake3_hex = self
            .sha256_to_blake3
            .get(&envelope.shard_ciphertext_hash)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                TrainingError::Internal(format!(
                    "iroh-blobs sealed shard not found: no local BLAKE3 mapping for sha256 {} (shard_index={})",
                    envelope.shard_ciphertext_hash, envelope.shard_index,
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
        verify_shard_ciphertext(envelope, &bytes)?;
        Ok(bytes)
    }
}

fn map_iroh_err(err: IrohError) -> TrainingError {
    match err {
        IrohError::NotFound(s) => {
            TrainingError::Internal(format!("iroh-blobs sealed shard not found: {s}"))
        }
        other => TrainingError::Internal(format!("iroh-blobs sealed-shard adapter: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Timestamp;

    fn make_envelope(hash: Hash, len: u64, shard_index: u32) -> SealedShardEnvelope {
        SealedShardEnvelope {
            trainer_did: "did:tenzro:machine:trainer-iroh".to_string(),
            shard_index,
            shard_ciphertext_hash: hash,
            shard_ciphertext_bytes: len,
            wrapped_data_key: vec![0xbb; 96],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![0xcc; 32],
            enclave_measurement_hex: "deadbeef".to_string(),
            created_at: Timestamp::now(),
        }
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips_through_iroh_blobs() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind iroh resolver");
        let store = IrohSealedShardStore::new(resolver);

        let ciphertext = Bytes::from_static(b"AES-256-GCM ciphertext bytes for shard 0");
        let hash = store.publish(ciphertext.clone()).await.expect("publish");
        assert_eq!(hash, compute_shard_ciphertext_hash(&ciphertext));

        let env = make_envelope(hash, ciphertext.len() as u64, 0);
        let fetched = store.fetch(&env).await.expect("fetch");
        assert_eq!(fetched, ciphertext);
    }

    #[tokio::test]
    async fn fetch_rejects_size_mismatch_after_iroh_round_trip() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohSealedShardStore::new(resolver);

        let ciphertext = Bytes::from_static(b"sized shard ciphertext");
        let hash = store.publish(ciphertext.clone()).await.unwrap();
        let lying = make_envelope(hash, ciphertext.len() as u64 + 1, 0);
        let err = store.fetch(&lying).await.unwrap_err();
        assert!(
            matches!(err, TrainingError::SealedShardSizeMismatch { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_unknown_hash_surfaces_internal_error() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohSealedShardStore::new(resolver);

        let bogus = make_envelope(Hash::new([0u8; 32]), 0, 0);
        let err = store.fetch(&bogus).await.unwrap_err();
        assert!(
            matches!(err, TrainingError::Internal(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn id_is_stable() {
        let id = <IrohSealedShardStore as SealedShardStore>::id;
        let _ = id;
    }
}
