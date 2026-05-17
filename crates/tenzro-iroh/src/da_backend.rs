//! `DaBackend` adapter that offloads receipt payloads to iroh-blobs.
//!
//! This is the Phase A2 (#214) consumer of [`IrohBackedResolver`]. It satisfies
//! the `tenzro_storage::da::DaBackend` trait so the rest of the protocol
//! (channel storage, inference receipts, agent-message receipts) can flip from
//! the `InlineFallbackBackend` to BLAKE3-verified content-addressed storage
//! without changing call sites.
//!
//! # Pointer encoding
//!
//! [`DaPointer`] is the on-chain shape — it must round-trip through
//! `serde_json` / `bincode` without loss and reference iroh-blobs content
//! deterministically. The encoding is:
//!
//! - `backend`: [`DaBackendId::IrohBlobs`]
//! - `namespace`: caller-provided opaque bytes (e.g. `b"tenzro/inference"`).
//!   Not interpreted by the adapter — it's metadata for indexers and
//!   namespace-aware backends. iroh-blobs is global by hash, so the namespace
//!   does not change resolution.
//! - `locator`: raw 32-byte BLAKE3 hash. We store the **raw bytes**, not the
//!   hex string, so the on-chain footprint is 32 bytes per pointer regardless
//!   of envelope encoding.
//! - `commitment_kzg`: `None`. iroh-blobs verifies BLAKE3 end-to-end on
//!   transfer, and the chain-of-custody commitment in
//!   `ReceiptEnvelope::commitment` (SHA-256 over the canonical payload) is the
//!   authoritative integrity check. We do not double-attest with KZG.
//! - `attestation_root`: `None`. Unlike EigenDA's restaking attestation,
//!   iroh-blobs has no signed availability committee.
//!
//! # Availability model
//!
//! `submit` writes the payload to the local in-memory store and returns the
//! BLAKE3 hash. Other nodes can fetch it via the same `IrohBackedResolver`
//! they already use for `tenzro://blob/<hash>` URIs — the iroh-blobs ALPN is
//! registered on the same endpoint. Phase B1 (#216) and B3 (#218) consumers
//! reuse this exact path.
//!
//! `fetch` is a local-store lookup. Cross-node retrieval (downloader →
//! provider list → BLAKE3-verified pull) is the path the existing
//! `IrohBackedResolver::fetch_bytes` takes; this adapter is intentionally a
//! thin wrapper so both code paths exercise the same machinery.
//!
//! `verify_availability` is currently identical to `fetch` minus the byte
//! transfer — it checks that the hash is known to the local store. Once the
//! downloader is wired (Phase B1), it becomes a probe against the peer pool.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use tenzro_storage::da::{DaBackend, DaBackendId, DaBackendStatus, DaPointer};
use tenzro_storage::error::{Result as StorageResult, StorageError};
use tenzro_types::primitives::Timestamp;
use tenzro_types::tenzro_uri::TenzroUri;

use crate::error::IrohError;
use crate::resolver::{IrohBackedResolver, IrohResolver};

/// iroh-blobs-backed [`DaBackend`] adapter (Phase A2, #214).
///
/// Wraps an [`IrohBackedResolver`] and projects its publish / fetch surface
/// into the `tenzro_storage::da` trait the rest of the workspace consumes.
/// Constructed by `tenzro-node` startup and registered alongside the inline
/// fallback under [`DaBackendId::IrohBlobs`].
pub struct IrohBlobsDaBackend {
    resolver: Arc<IrohBackedResolver>,
    last_submission_ms: Mutex<Option<i64>>,
    last_fetch_ms: Mutex<Option<i64>>,
}

impl IrohBlobsDaBackend {
    /// Construct an adapter over an already-bound resolver. The resolver is
    /// shared — the same `Arc<IrohBackedResolver>` typically also services
    /// direct `tenzro://blob/<hash>` URI fetches from RPC / CLI / MCP.
    pub fn new(resolver: Arc<IrohBackedResolver>) -> Self {
        Self {
            resolver,
            last_submission_ms: Mutex::new(None),
            last_fetch_ms: Mutex::new(None),
        }
    }

    /// Construct as an `Arc<dyn DaBackend>` for direct registration in the
    /// node's backend table.
    pub fn arc(resolver: Arc<IrohBackedResolver>) -> Arc<dyn DaBackend> {
        Arc::new(Self::new(resolver))
    }

    /// Expose the underlying resolver — needed by consumers that want to
    /// dispatch `tenzro://` URIs directly without going through the DA
    /// pointer envelope (e.g. Phase B3 model-weight downloads).
    pub fn resolver(&self) -> &Arc<IrohBackedResolver> {
        &self.resolver
    }

    /// Reconstruct the iroh-blobs hash from a [`DaPointer`]. Locators are the
    /// raw 32-byte BLAKE3 hash — anything else is a bug or a foreign pointer.
    fn locator_to_hash(pointer: &DaPointer) -> StorageResult<[u8; 32]> {
        if pointer.backend != DaBackendId::IrohBlobs {
            return Err(StorageError::Generic(format!(
                "IrohBlobsDaBackend cannot resolve pointer with backend {:?}",
                pointer.backend
            )));
        }
        if pointer.locator.len() != 32 {
            return Err(StorageError::InvalidValue(format!(
                "IrohBlobs pointer locator must be 32 bytes (BLAKE3), got {}",
                pointer.locator.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&pointer.locator);
        Ok(hash)
    }

    /// Reconstruct the canonical `tenzro://blob/<hex>` URI for the pointer so
    /// fetch flows through the same resolver path as direct URI fetches.
    fn pointer_to_blob_uri(pointer: &DaPointer) -> StorageResult<TenzroUri> {
        let raw = Self::locator_to_hash(pointer)?;
        Ok(TenzroUri::Blob {
            hash: hex::encode(raw),
            provider_hint: None,
        })
    }

    fn now_ms() -> i64 {
        Timestamp::now().0
    }

    /// Project an [`IrohError`] into the storage-side error type. Preserve
    /// the `NotFound` discriminant so callers can distinguish "missing" from
    /// "backend broken".
    fn map_err(err: IrohError) -> StorageError {
        match err {
            IrohError::NotFound(msg) => StorageError::KeyNotFound(msg),
            other => StorageError::Generic(format!("iroh-blobs DA: {}", other)),
        }
    }
}

#[async_trait]
impl DaBackend for IrohBlobsDaBackend {
    fn id(&self) -> DaBackendId {
        DaBackendId::IrohBlobs
    }

    fn status(&self) -> DaBackendStatus {
        DaBackendStatus {
            backend: DaBackendId::IrohBlobs,
            // Endpoint health is implicit — if the resolver is alive, the
            // ALPN is registered. Phase B1 wires a real readiness probe
            // against the downloader once cross-node fetch is exercised.
            healthy: true,
            last_submission_ms: *self.last_submission_ms.lock(),
            last_fetch_ms: *self.last_fetch_ms.lock(),
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> StorageResult<DaPointer> {
        let bytes = bytes::Bytes::copy_from_slice(payload);
        let uri = self
            .resolver
            .publish_bytes(bytes)
            .await
            .map_err(Self::map_err)?;
        let hex_hash = match &uri {
            TenzroUri::Blob { hash, .. } => hash.clone(),
            other => {
                return Err(StorageError::Generic(format!(
                    "IrohBackedResolver::publish_bytes returned non-Blob URI: {:?}",
                    other
                )))
            }
        };
        let raw = hex::decode(&hex_hash).map_err(|e| {
            StorageError::Generic(format!("publish returned non-hex BLAKE3 hash: {}", e))
        })?;
        if raw.len() != 32 {
            return Err(StorageError::Generic(format!(
                "publish returned BLAKE3 of wrong length: {}",
                raw.len()
            )));
        }
        *self.last_submission_ms.lock() = Some(Self::now_ms());
        Ok(DaPointer {
            backend: DaBackendId::IrohBlobs,
            namespace: namespace.to_vec(),
            locator: raw,
            commitment_kzg: None,
            attestation_root: None,
        })
    }

    async fn fetch(&self, pointer: &DaPointer) -> StorageResult<Vec<u8>> {
        let uri = Self::pointer_to_blob_uri(pointer)?;
        let bytes = self
            .resolver
            .fetch_bytes(&uri)
            .await
            .map_err(Self::map_err)?;
        *self.last_fetch_ms.lock() = Some(Self::now_ms());
        Ok(bytes.to_vec())
    }

    async fn verify_availability(&self, pointer: &DaPointer) -> StorageResult<()> {
        // Local-store probe: try the fetch path but discard the bytes. Once
        // Phase B1's downloader lands, this becomes a cheaper provider-list
        // probe that does not transfer the payload.
        let uri = Self::pointer_to_blob_uri(pointer)?;
        self.resolver
            .fetch_bytes(&uri)
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }
}

impl std::fmt::Debug for IrohBlobsDaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohBlobsDaBackend")
            .field("backend", &DaBackendId::IrohBlobs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::da::{compute_commitment, ReceiptEnvelope, ReceiptKind, ReceiptSummary};
    use tenzro_types::primitives::{Hash, Timestamp};

    fn sample_summary() -> ReceiptSummary {
        ReceiptSummary {
            receipt_id: Hash::new([9u8; 32]),
            payer: Some("did:tenzro:human:alice".into()),
            payee: Some("did:tenzro:machine:bob".into()),
            amount_wei: Some(42),
            timestamp: Timestamp::new(1_700_000_000_000),
            principal_chain_summary: None,
        }
    }

    #[tokio::test]
    async fn submit_then_fetch_round_trips_via_da_pointer() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let payload = b"phase-A2 DA payload over iroh-blobs".to_vec();
        let pointer = backend
            .submit(b"tenzro/inference", &payload)
            .await
            .expect("submit payload");

        assert_eq!(pointer.backend, DaBackendId::IrohBlobs);
        assert_eq!(pointer.namespace, b"tenzro/inference".to_vec());
        assert_eq!(pointer.locator.len(), 32, "locator must be raw BLAKE3");
        assert!(pointer.commitment_kzg.is_none());
        assert!(pointer.attestation_root.is_none());

        // verify_availability succeeds for a known hash.
        backend
            .verify_availability(&pointer)
            .await
            .expect("known hash must verify");

        // Fetch round-trips the payload.
        let fetched = backend.fetch(&pointer).await.expect("fetch payload");
        assert_eq!(fetched, payload);

        // Status reflects activity.
        let status = backend.status();
        assert_eq!(status.backend, DaBackendId::IrohBlobs);
        assert!(status.healthy);
        assert!(status.last_submission_ms.is_some());
        assert!(status.last_fetch_ms.is_some());

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn duplicate_submit_is_content_addressed_idempotent() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let payload = b"idempotent payload".to_vec();
        let p1 = backend.submit(b"ns/a", &payload).await.unwrap();
        let p2 = backend.submit(b"ns/b", &payload).await.unwrap();

        // BLAKE3 is content-addressed — same payload, same locator.
        assert_eq!(p1.locator, p2.locator);
        // Namespace is metadata, not part of the address — caller-controlled.
        assert_ne!(p1.namespace, p2.namespace);

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn fetch_unknown_pointer_is_key_not_found() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let bogus = DaPointer {
            backend: DaBackendId::IrohBlobs,
            namespace: b"ns".to_vec(),
            locator: vec![0u8; 32],
            commitment_kzg: None,
            attestation_root: None,
        };

        let err = backend.fetch(&bogus).await.expect_err("zero-hash must miss");
        assert!(matches!(err, StorageError::KeyNotFound(_)), "got {:?}", err);

        let verify_err = backend
            .verify_availability(&bogus)
            .await
            .expect_err("zero-hash must miss verify");
        assert!(matches!(verify_err, StorageError::KeyNotFound(_)));

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn rejects_foreign_backend_pointer() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let foreign = DaPointer {
            backend: DaBackendId::EigenDA,
            namespace: vec![],
            locator: vec![1u8; 32],
            commitment_kzg: None,
            attestation_root: None,
        };
        assert!(matches!(
            backend.fetch(&foreign).await,
            Err(StorageError::Generic(_))
        ));
        assert!(matches!(
            backend.verify_availability(&foreign).await,
            Err(StorageError::Generic(_))
        ));

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn rejects_locator_of_wrong_length() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let bad_len = DaPointer {
            backend: DaBackendId::IrohBlobs,
            namespace: vec![],
            locator: vec![0u8; 16], // half a hash
            commitment_kzg: None,
            attestation_root: None,
        };
        assert!(matches!(
            backend.fetch(&bad_len).await,
            Err(StorageError::InvalidValue(_))
        ));

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn receipt_envelope_round_trips_via_da_pointer() {
        // End-to-end: build an OffloadedDA ReceiptEnvelope referencing a
        // payload submitted through the iroh-blobs backend. Fetch the
        // payload back via the pointer and validate it matches the
        // envelope's SHA-256 commitment.
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let backend = IrohBlobsDaBackend::new(resolver.clone());

        let payload = b"inference receipt payload (offloaded)".to_vec();
        let pointer = backend
            .submit(b"tenzro/inference", &payload)
            .await
            .expect("submit");
        let commitment = compute_commitment(&payload);

        let envelope =
            ReceiptEnvelope::offloaded(ReceiptKind::Inference, sample_summary(), pointer, commitment);
        envelope.validate().expect("offloaded envelope valid");

        let pointer = envelope.da_pointer.as_ref().expect("has pointer");
        let fetched = backend.fetch(pointer).await.expect("fetch via envelope");
        assert_eq!(compute_commitment(&fetched), envelope.commitment);

        resolver.shutdown().await.ok();
    }
}
