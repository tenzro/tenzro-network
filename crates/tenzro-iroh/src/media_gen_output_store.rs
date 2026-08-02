//! Generated-media store backed by iroh-blobs.
//!
//! A rendered image or video is bulk data: tens of kilobytes for a single
//! frame, tens of megabytes for a clip. It rides the iroh data plane, while
//! the tiny [`MediaGenReceipt`] envelope that commits to it rides the
//! `tenzro/media-gen` libp2p gossipsub topic. Same split as
//! [`IrohGradientStore`](crate::IrohGradientStore) uses for outer gradients.
//!
//! # Why not the `DaBackend` adapter
//!
//! [`IrohBlobsDaBackend`](crate::IrohBlobsDaBackend) hands back a `DaPointer`
//! that the caller stores inside a `ReceiptEnvelope`. A media-gen receipt has
//! no envelope: the `output_hash` already on [`MediaGenReceipt`] *is* the
//! locator. Routing through `DaBackend` would mint a second pointer to the
//! same content in a different shape.
//!
//! # Integrity contract
//!
//! iroh-blobs verifies BLAKE3 over the whole transfer, which proves "these are
//! the bytes I asked for" — not "these are the bytes the receipt committed
//! to". [`verify_output`] closes that gap on every fetch, so a wiring bug
//! between the resolver and the runtime surfaces immediately instead of
//! handing a requester somebody else's render. [`verify_latent`] does the
//! same for the intermediate latent a split job hands between its two
//! experts, which travels the same way for the same reason.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use tenzro_media_gen::{
    MediaGenError, MediaGenHandoff, MediaGenOutputStore, MediaGenReceipt, Result as MediaGenResult,
    compute_output_hash, verify_input, verify_latent, verify_output,
};
use tenzro_types::primitives::Hash;
use tenzro_types::tenzro_uri::TenzroUri;

use crate::error::IrohError;
use crate::resolver::{IrohBackedResolver, IrohResolver};

/// iroh-blobs-backed [`MediaGenOutputStore`] adapter.
///
/// Shares the resolver with every other iroh consumer on the node — one
/// endpoint, one ALPN, one hash space.
///
/// # SHA-256 ↔ BLAKE3 indirection
///
/// [`MediaGenReceipt::output_hash`] is SHA-256 (the canonical Tenzro content
/// hash, computed by [`compute_output_hash`]). iroh-blobs indexes by BLAKE3 —
/// a different digest of the same bytes. This adapter keeps a
/// [`DashMap`] from SHA-256 → BLAKE3-hex so `fetch` can translate the hash a
/// receipt announced into a locator iroh-blobs can resolve. The mapping is
/// populated on `publish` (the worker's own node) and by
/// [`record_blake3`](Self::record_blake3) when a remote node learns the pair
/// from a gossiped receipt.
pub struct IrohMediaGenOutputStore {
    resolver: Arc<IrohBackedResolver>,
    sha256_to_blake3: DashMap<Hash, String>,
}

impl IrohMediaGenOutputStore {
    /// Construct an adapter over an already-bound resolver.
    pub fn new(resolver: Arc<IrohBackedResolver>) -> Self {
        Self {
            resolver,
            sha256_to_blake3: DashMap::new(),
        }
    }

    /// Borrow the underlying resolver.
    pub fn resolver(&self) -> &Arc<IrohBackedResolver> {
        &self.resolver
    }

    /// Record a SHA-256 → BLAKE3 pair learned out of band, so a node that did
    /// not render the output can still fetch it. The gossip consumer calls
    /// this when a receipt arrives carrying the producing worker's BLAKE3
    /// locator.
    pub fn record_blake3(&self, output_hash: Hash, blake3_hex: String) {
        self.sha256_to_blake3.insert(output_hash, blake3_hex);
    }

    /// Look up the iroh-blobs locator for a canonical output hash.
    pub fn blake3_for(&self, output_hash: &Hash) -> Option<String> {
        self.sha256_to_blake3
            .get(output_hash)
            .map(|entry| entry.value().clone())
    }

    /// Resolve a canonical SHA-256 to its iroh-blobs locator and pull the
    /// bytes. The caller checks them against whichever commitment named the
    /// hash — this is the transport half only.
    async fn fetch_by_sha256(&self, sha256: &Hash) -> MediaGenResult<Bytes> {
        let blake3_hex = self.blake3_for(sha256).ok_or_else(|| {
            MediaGenError::OutputNotFound(format!(
                "no iroh-blobs locator known for sha256 {sha256}"
            ))
        })?;
        let uri = TenzroUri::Blob {
            hash: blake3_hex,
            provider_hint: None,
        };
        self.resolver.fetch_bytes(&uri).await.map_err(map_iroh_err)
    }
}

#[async_trait]
impl MediaGenOutputStore for IrohMediaGenOutputStore {
    fn id(&self) -> &'static str {
        "iroh_blobs"
    }

    async fn publish(&self, bytes: Bytes) -> MediaGenResult<Hash> {
        // Compute the protocol hash before handing the bytes to iroh so the
        // return value is the SHA-256 the receipt will commit to, never the
        // transport's BLAKE3.
        let output_hash = compute_output_hash(&bytes);
        let uri = self
            .resolver
            .publish_bytes(bytes)
            .await
            .map_err(map_iroh_err)?;
        let blake3_hex = match uri {
            TenzroUri::Blob { hash, .. } => hash,
            other => {
                return Err(MediaGenError::Storage(format!(
                    "iroh resolver returned non-Blob URI from publish_bytes: {other}"
                )));
            }
        };
        self.sha256_to_blake3.insert(output_hash, blake3_hex);
        Ok(output_hash)
    }

    async fn fetch(&self, expected: &MediaGenReceipt) -> MediaGenResult<Bytes> {
        let bytes = self.fetch_by_sha256(&expected.output_hash).await?;
        verify_output(expected, &bytes)?;
        Ok(bytes)
    }

    async fn fetch_latent(&self, expected: &MediaGenHandoff) -> MediaGenResult<Bytes> {
        let bytes = self.fetch_by_sha256(&expected.latent_hash).await?;
        verify_latent(expected, &bytes)?;
        Ok(bytes)
    }

    async fn fetch_input(&self, hash: &Hash) -> MediaGenResult<Bytes> {
        let bytes = self.fetch_by_sha256(hash).await?;
        verify_input(hash, &bytes)?;
        Ok(bytes)
    }
}

fn map_iroh_err(err: IrohError) -> MediaGenError {
    match err {
        IrohError::NotFound(s) => MediaGenError::OutputNotFound(s),
        other => MediaGenError::Storage(format!("iroh-blobs media store: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_media_gen::{MediaGenKind, MediaGenParams, MediaGenTaskSpec};
    use tenzro_types::primitives::{Address, Signature, Timestamp};

    fn receipt_for(bytes: &[u8]) -> MediaGenReceipt {
        let params = MediaGenParams {
            prompt: "a plaster model of a lighthouse".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            seed: Some(11),
            input_image_hash: None,
            metadata: Default::default(),
        };
        let spec = MediaGenTaskSpec {
            job_id: "job-iroh-1".to_string(),
            requester_did: "did:tenzro:human:requester".to_string(),
            requester_address: Address::zero(),
            model_id: "qwen-image".to_string(),
            kind: MediaGenKind::Text2Image,
            params,
            max_price: 10_000,
            created_at: Timestamp::new(0),
            metadata: Default::default(),
        };
        MediaGenReceipt {
            job_id: "job-iroh-1".to_string(),
            task_spec: spec,
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::new([3u8; 32]),
            output_hash: compute_output_hash(bytes),
            output_mime: "image/png".to_string(),
            output_bytes: bytes.len() as u64,
            seed_used: 11,
            generation_time_ms: 3_100,
            price_paid: 9_000,
            completed_at: Timestamp::new(9),
            worker_signature: Signature::default(),
        }
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips_through_iroh_blobs() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind iroh resolver");
        let store = IrohMediaGenOutputStore::new(resolver);

        let payload = Bytes::from_static(b"\x89PNG\r\n\x1a\n rendered image bytes");
        let hash = store.publish(payload.clone()).await.expect("publish");
        assert_eq!(hash, compute_output_hash(&payload));
        assert!(store.blake3_for(&hash).is_some());

        let receipt = receipt_for(&payload);
        let fetched = store.fetch(&receipt).await.expect("fetch");
        assert_eq!(fetched, payload);
    }

    #[tokio::test]
    async fn fetch_rejects_a_size_mismatch_after_the_iroh_round_trip() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohMediaGenOutputStore::new(resolver);

        let payload = Bytes::from_static(b"sized render");
        store.publish(payload.clone()).await.unwrap();

        let mut lying = receipt_for(&payload);
        lying.output_bytes += 1;
        let err = store.fetch(&lying).await.unwrap_err();
        assert!(
            matches!(err, MediaGenError::OutputSizeMismatch { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_without_a_known_locator_reports_not_found() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let store = IrohMediaGenOutputStore::new(resolver);

        let receipt = receipt_for(b"never-published");
        let err = store.fetch(&receipt).await.unwrap_err();
        assert!(matches!(err, MediaGenError::OutputNotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_low_noise_worker_pulls_the_latent_the_handoff_committed_to() {
        // The split-expert path across two machines: the high-noise holder
        // publishes the intermediate latent, the low-noise holder learns the
        // locator from the gossiped handoff and pulls the bytes.
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        let high_noise = IrohMediaGenOutputStore::new(resolver.clone());
        let latent = Bytes::from_static(b"partly-denoised latent tensor");
        let hash = high_noise.publish(latent.clone()).await.unwrap();
        let locator = high_noise
            .blake3_for(&hash)
            .expect("publisher knows locator");

        let handoff = MediaGenHandoff {
            job_id: "job-iroh-1".to_string(),
            from_worker_did: "did:tenzro:machine:high".to_string(),
            from_worker_address: Address::new([4u8; 32]),
            latent_hash: hash,
            latent_bytes: latent.len() as u64,
            steps_completed: 26,
            handed_off_at: Timestamp::new(5),
            worker_signature: Signature::default(),
        };

        let low_noise = IrohMediaGenOutputStore::new(resolver);
        assert!(matches!(
            low_noise.fetch_latent(&handoff).await.unwrap_err(),
            MediaGenError::OutputNotFound(_)
        ));

        low_noise.record_blake3(hash, locator);
        let fetched = low_noise
            .fetch_latent(&handoff)
            .await
            .expect("fetch latent");
        assert_eq!(fetched, latent);
    }

    #[tokio::test]
    async fn a_recorded_locator_makes_a_remote_output_fetchable() {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        // The producing side publishes; a second adapter over the same
        // endpoint stands in for a node that only saw the gossiped receipt.
        let producer = IrohMediaGenOutputStore::new(resolver.clone());
        let payload = Bytes::from_static(b"gossiped render");
        let hash = producer.publish(payload.clone()).await.unwrap();
        let locator = producer.blake3_for(&hash).expect("producer knows locator");

        let consumer = IrohMediaGenOutputStore::new(resolver);
        let receipt = receipt_for(&payload);
        assert!(matches!(
            consumer.fetch(&receipt).await.unwrap_err(),
            MediaGenError::OutputNotFound(_)
        ));

        consumer.record_blake3(hash, locator);
        let fetched = consumer.fetch(&receipt).await.expect("fetch after record");
        assert_eq!(fetched, payload);
    }
}
