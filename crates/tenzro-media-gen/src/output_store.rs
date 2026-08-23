//! Content-addressed store for generated media bytes.
//!
//! The protocol layer never holds the rendered image or video in a job record —
//! a [`MediaGenReceipt`] carries only the SHA-256 `output_hash`, the declared
//! byte length, and the MIME type. Fetching the bytes goes through this trait so
//! the transport (iroh-blobs, a DA backend, plain local storage) stays out of
//! the protocol crate.
//!
//! # Three kinds of payload, one hash space
//!
//! A job served whole produces one payload: the rendered output. A job split
//! across two experts produces two, because the high-noise half ends with a
//! partly-denoised latent that the low-noise half has to start from. An
//! editing or image-conditioned job adds a third, supplied by the requester
//! ahead of the job and named by `MediaGenParams::input_image_hash`. All three
//! are opaque bytes addressed by SHA-256, so all three ride the same store —
//! [`MediaGenOutputStore::publish`] takes any of them, and the fetch methods
//! differ only in which commitment they check against.
//!
//! The latent is what makes a split job runnable on two machines at all. On one
//! machine the second worker could read the first worker's memory; across a
//! network it has to fetch the bytes and prove they are the ones the handoff
//! committed to. The input image is the same problem in the other direction: a
//! worker elsewhere cannot read the requester's disk.
//!
//! # Integrity contract
//!
//! An implementation MUST re-verify size and SHA-256 at the protocol boundary
//! even when the underlying transport already self-verifies its own hash. A
//! transport that indexes by BLAKE3 proves "these are the bytes I was asked
//! for", not "these are the bytes the receipt committed to". [`verify_output`]
//! closes that gap.

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};

use tenzro_types::media_gen::{MediaGenHandoff, MediaGenReceipt};
use tenzro_types::primitives::Hash;

use crate::error::{MediaGenError, Result};

/// Publish and fetch generated media by content hash.
#[async_trait]
pub trait MediaGenOutputStore: Send + Sync {
    /// Stable identifier for the backing transport, used in logs.
    fn id(&self) -> &'static str;

    /// Store `bytes` and return their canonical SHA-256 hash. Used for both
    /// rendered outputs and intermediate latents — the store does not care
    /// which, only the commitment checked on the way back out differs.
    async fn publish(&self, bytes: Bytes) -> Result<Hash>;

    /// Fetch the bytes committed to by `expected`, verifying size and hash.
    async fn fetch(&self, expected: &MediaGenReceipt) -> Result<Bytes>;

    /// Fetch the intermediate latent committed to by `expected`, verifying
    /// size and hash. This is the low-noise expert's entry point into a job
    /// the high-noise expert started on another machine.
    async fn fetch_latent(&self, expected: &MediaGenHandoff) -> Result<Bytes>;

    /// Fetch a requester-supplied input image by hash, verifying the hash.
    ///
    /// No length accompanies `input_image_hash` on a spec, so the hash is the
    /// whole commitment — and it is already bound, because the job id is
    /// derived over it. A worker serving an `Image2Image` or `Image2Video` job
    /// calls this to obtain the conditioning frame.
    async fn fetch_input(&self, hash: &Hash) -> Result<Bytes>;
}

/// Canonical Tenzro content hash of a media payload.
pub fn compute_output_hash(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    Hash::from_bytes(&digest).expect("sha256 digest is 32 bytes")
}

/// Check fetched bytes against the size and hash a receipt committed to.
pub fn verify_output(expected: &MediaGenReceipt, bytes: &[u8]) -> Result<()> {
    let actual = bytes.len() as u64;
    if actual != expected.output_bytes {
        return Err(MediaGenError::OutputSizeMismatch {
            declared: expected.output_bytes,
            actual,
        });
    }
    if compute_output_hash(bytes) != expected.output_hash {
        return Err(MediaGenError::OutputHashMismatch);
    }
    Ok(())
}

/// Check fetched bytes against the hash a spec's `input_image_hash` names.
pub fn verify_input(expected: &Hash, bytes: &[u8]) -> Result<()> {
    if compute_output_hash(bytes) != *expected {
        return Err(MediaGenError::OutputHashMismatch);
    }
    Ok(())
}

/// Check fetched bytes against the size and hash a handoff committed to.
pub fn verify_latent(expected: &MediaGenHandoff, bytes: &[u8]) -> Result<()> {
    let actual = bytes.len() as u64;
    if actual != expected.latent_bytes {
        return Err(MediaGenError::OutputSizeMismatch {
            declared: expected.latent_bytes,
            actual,
        });
    }
    if compute_output_hash(bytes) != expected.latent_hash {
        return Err(MediaGenError::OutputHashMismatch);
    }
    Ok(())
}

/// In-process store, used by tests and by single-node deployments that keep
/// generated media only for the lifetime of the process.
#[derive(Debug, Default)]
pub struct InMemoryOutputStore {
    by_hash: DashMap<Hash, Bytes>,
}

impl InMemoryOutputStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct payloads held.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

#[async_trait]
impl MediaGenOutputStore for InMemoryOutputStore {
    fn id(&self) -> &'static str {
        "in-memory"
    }

    async fn publish(&self, bytes: Bytes) -> Result<Hash> {
        let hash = compute_output_hash(&bytes);
        self.by_hash.insert(hash, bytes);
        Ok(hash)
    }

    async fn fetch(&self, expected: &MediaGenReceipt) -> Result<Bytes> {
        let bytes = self
            .by_hash
            .get(&expected.output_hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MediaGenError::OutputNotFound(expected.output_hash.to_string()))?;
        verify_output(expected, &bytes)?;
        Ok(bytes)
    }

    async fn fetch_latent(&self, expected: &MediaGenHandoff) -> Result<Bytes> {
        let bytes = self
            .by_hash
            .get(&expected.latent_hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MediaGenError::OutputNotFound(expected.latent_hash.to_string()))?;
        verify_latent(expected, &bytes)?;
        Ok(bytes)
    }

    async fn fetch_input(&self, hash: &Hash) -> Result<Bytes> {
        let bytes = self
            .by_hash
            .get(hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MediaGenError::OutputNotFound(hash.to_string()))?;
        verify_input(hash, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::media_gen::{MediaGenKind, MediaGenParams, MediaGenTaskSpec};
    use tenzro_types::primitives::{Address, Signature, Timestamp};

    fn receipt_for(bytes: &[u8]) -> MediaGenReceipt {
        let params = MediaGenParams {
            prompt: "a plaster studio room".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            voxel_resolution: None,
            audio_duration_secs: None,
            seed: Some(7),
            input_image_hash: None,
            metadata: Default::default(),
        };
        let spec = MediaGenTaskSpec {
            job_id: "job".to_string(),
            requester_did: "did:tenzro:human:r".to_string(),
            requester_address: Address::zero(),
            model_id: "qwen-image".to_string(),
            kind: MediaGenKind::Text2Image,
            params,
            max_price: 1_000,
            created_at: Timestamp::new(0),
            metadata: Default::default(),
        };
        MediaGenReceipt {
            job_id: "job".to_string(),
            task_spec: spec,
            worker_did: "did:tenzro:machine:w".to_string(),
            worker_address: Address::new([2u8; 32]),
            output_hash: compute_output_hash(bytes),
            output_mime: "image/png".to_string(),
            output_bytes: bytes.len() as u64,
            seed_used: 7,
            generation_time_ms: 4_200,
            price_paid: 900,
            completed_at: Timestamp::new(1),
            worker_signature: Signature::default(),
        }
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips() {
        let store = InMemoryOutputStore::new();
        let bytes = Bytes::from_static(b"png-bytes");
        let hash = store.publish(bytes.clone()).await.unwrap();
        assert_eq!(hash, compute_output_hash(&bytes));

        let receipt = receipt_for(&bytes);
        let fetched = store.fetch(&receipt).await.unwrap();
        assert_eq!(fetched, bytes);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn fetch_reports_missing_payloads() {
        let store = InMemoryOutputStore::new();
        let receipt = receipt_for(b"never-published");
        let err = store.fetch(&receipt).await.unwrap_err();
        assert!(matches!(err, MediaGenError::OutputNotFound(_)));
    }

    fn handoff_for(bytes: &[u8]) -> MediaGenHandoff {
        MediaGenHandoff {
            job_id: "job".to_string(),
            from_worker_did: "did:tenzro:machine:high".to_string(),
            from_worker_address: Address::new([3u8; 32]),
            latent_hash: compute_output_hash(bytes),
            latent_bytes: bytes.len() as u64,
            steps_completed: 26,
            handed_off_at: Timestamp::new(2),
            worker_signature: Signature::default(),
        }
    }

    #[tokio::test]
    async fn a_latent_round_trips_through_the_same_store_as_an_output() {
        let store = InMemoryOutputStore::new();
        let latent = Bytes::from_static(b"serialized-latent-tensor");
        store.publish(latent.clone()).await.unwrap();

        let fetched = store.fetch_latent(&handoff_for(&latent)).await.unwrap();
        assert_eq!(fetched, latent);
    }

    #[tokio::test]
    async fn fetch_latent_rejects_bytes_the_handoff_did_not_commit_to() {
        let store = InMemoryOutputStore::new();
        let latent = Bytes::from_static(b"serialized-latent-tensor");
        store.publish(latent.clone()).await.unwrap();

        // A handoff naming the right hash but the wrong length is the shape a
        // truncated or padded transfer takes.
        let mut lying = handoff_for(&latent);
        lying.latent_bytes += 1;
        let err = store.fetch_latent(&lying).await.unwrap_err();
        assert!(matches!(err, MediaGenError::OutputSizeMismatch { .. }));
    }

    #[test]
    fn verify_output_rejects_a_size_mismatch() {
        let bytes = b"png-bytes";
        let mut receipt = receipt_for(bytes);
        receipt.output_bytes += 1;
        let err = verify_output(&receipt, bytes).unwrap_err();
        assert!(matches!(err, MediaGenError::OutputSizeMismatch { .. }));
    }

    #[test]
    fn verify_output_rejects_a_hash_mismatch() {
        let bytes = b"png-bytes";
        let mut receipt = receipt_for(bytes);
        receipt.output_hash = compute_output_hash(b"other-bytes");
        let err = verify_output(&receipt, bytes).unwrap_err();
        assert!(matches!(err, MediaGenError::OutputHashMismatch));
    }
}
