//! Celestia data-availability backend.
//!
//! Implements [`DaBackend`] against a celestia-node JSON-RPC endpoint via the
//! `celestia-rpc` crate (pinned to `1.0.0`). This is an external DA
//! layer wired into Tenzro — EigenDA and Avail follow.
//!
//! # Wire model
//!
//! - `submit(namespace, payload)` — wraps `payload` in a `celestia_types::Blob`
//!   under the chosen namespace, posts it via `BlobClient::blob_submit`, and
//!   captures the inclusion height + Celestia commitment. Returns a
//!   [`DaPointer`] whose `locator` is the UTF-8 bytes of `"{height}:{hex}"`,
//!   `commitment_kzg` carries the Celestia (NMT) commitment, and
//!   `attestation_root` is `None` (Celestia does not produce a Tenzro-side
//!   attestation root — fraud-proof safety comes from the Celestia DA layer
//!   itself).
//!
//! - `fetch(pointer)` — parses the `height:commitment` locator and calls
//!   `BlobClient::blob_get` to recover the original payload bytes.
//!
//! - `verify_availability(pointer)` — fetches the inclusion proof via
//!   `BlobClient::blob_get_proof` and asks the celestia node to validate it
//!   against the block at `height` via `BlobClient::blob_included`. Returning
//!   `Ok(())` means the celestia node attested that the commitment is included
//!   in the canonical block at that height under the requested namespace.
//!   Header-side validation against a fraud-proof-resistant Tendermint header
//!   is layered on top by callers that hold a verified header (e.g. light
//!   clients) and is intentionally out of scope for this backend, which speaks
//!   only to a trusted local celestia-node.
//!
//! # Important: dual commitment model
//!
//! The chain-of-custody commitment in [`ReceiptEnvelope::commitment`] is always
//! `SHA-256(canonical_payload)` — see [`compute_commitment`]. Celestia returns
//! its own NMT-Merkle commitment, which we surface in
//! [`DaPointer::commitment_kzg`] (the field is named for KZG by convention but
//! holds whatever backend-attested commitment the underlying DA layer produces).
//! Verifiers MUST hash the fetched payload and compare against the SHA-256
//! receipt commitment before trusting the bytes — the Celestia commitment
//! alone is not sufficient because it is computed in a different domain.

use async_trait::async_trait;
use celestia_rpc::{BlobClient, Client, TxConfig};
use celestia_types::blob::{Blob, Commitment};
use celestia_types::nmt::Namespace;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::da::{DaBackend, DaBackendId, DaBackendStatus, DaPointer};
use crate::error::{Result, StorageError};

/// Celestia DA backend. Holds a long-lived JSON-RPC client and the namespace
/// under which all blobs are submitted.
///
/// Construct via [`CelestiaBackend::connect`] or wrap an existing client with
/// [`CelestiaBackend::new`].
pub struct CelestiaBackend {
    client: Arc<Client>,
    namespace: Namespace,
    /// Most recent successful submission timestamp (ms since epoch).
    last_submission_ms: RwLock<Option<i64>>,
    /// Most recent successful fetch timestamp (ms since epoch).
    last_fetch_ms: RwLock<Option<i64>>,
}

impl CelestiaBackend {
    /// Wrap an existing `celestia_rpc::Client` and namespace. Use this when the
    /// caller already manages connection lifecycle (e.g. shared across multiple
    /// backends or behind a connection pool).
    pub fn new(client: Arc<Client>, namespace: Namespace) -> Self {
        Self {
            client,
            namespace,
            last_submission_ms: RwLock::new(None),
            last_fetch_ms: RwLock::new(None),
        }
    }

    /// Connect to a celestia-node JSON-RPC endpoint (`http://...` or `ws://...`)
    /// and bind the backend to a v0 namespace derived from `namespace_id` (which
    /// must be a 1–10 byte suffix per Celestia's namespace v0 rules).
    pub async fn connect(
        url: &str,
        auth_token: &str,
        namespace_id: &[u8],
    ) -> Result<Self> {
        let namespace = Namespace::new_v0(namespace_id).map_err(|e| {
            StorageError::Generic(format!("invalid Celestia namespace id: {e}"))
        })?;
        let client = Client::new(
            url,
            Some(auth_token),
            Some(Duration::from_secs(10)),
            Some(Duration::from_secs(60)),
        )
        .await
        .map_err(|e| StorageError::Generic(format!("Celestia client connect failed: {e}")))?;
        Ok(Self::new(Arc::new(client), namespace))
    }

    /// Resolve the configured namespace.
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Resolve the namespace for a submit/fetch call. If the caller passes a
    /// non-empty `override_ns`, it is interpreted as a v0 namespace suffix and
    /// used instead of the configured default — this lets a single backend
    /// serve multiple receipt kinds without re-connecting.
    fn resolve_namespace(&self, override_ns: &[u8]) -> Result<Namespace> {
        if override_ns.is_empty() {
            Ok(self.namespace)
        } else {
            Namespace::new_v0(override_ns).map_err(|e| {
                StorageError::Generic(format!("invalid Celestia namespace override: {e}"))
            })
        }
    }
}

/// Encode a `(height, commitment)` pair into the `DaPointer::locator` field.
/// Format: `"{height}:{commitment_hex}"` UTF-8 bytes.
fn encode_locator(height: u64, commitment: &Commitment) -> Vec<u8> {
    let hex = hex::encode(commitment.hash());
    format!("{height}:{hex}").into_bytes()
}

/// Inverse of [`encode_locator`]. Returns `(height, commitment_bytes)`.
fn decode_locator(locator: &[u8]) -> Result<(u64, Vec<u8>)> {
    let s = std::str::from_utf8(locator).map_err(|e| {
        StorageError::InvalidValue(format!("Celestia locator not valid UTF-8: {e}"))
    })?;
    let (height_str, hex_str) = s.split_once(':').ok_or_else(|| {
        StorageError::InvalidValue(format!(
            "Celestia locator missing ':' separator: {s}"
        ))
    })?;
    let height = height_str.parse::<u64>().map_err(|e| {
        StorageError::InvalidValue(format!("Celestia locator height invalid: {e}"))
    })?;
    let bytes = hex::decode(hex_str).map_err(|e| {
        StorageError::InvalidValue(format!("Celestia locator commitment hex invalid: {e}"))
    })?;
    Ok((height, bytes))
}

fn commitment_from_bytes(bytes: &[u8]) -> Result<Commitment> {
    if bytes.len() != 32 {
        return Err(StorageError::InvalidValue(format!(
            "Celestia commitment must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(Commitment::new(arr))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl DaBackend for CelestiaBackend {
    fn id(&self) -> DaBackendId {
        DaBackendId::Celestia
    }

    fn status(&self) -> DaBackendStatus {
        // Snapshot timestamps without blocking — try_read avoids stalling the
        // status RPC if a long submission is in flight.
        let last_submission_ms = self.last_submission_ms.try_read().ok().and_then(|g| *g);
        let last_fetch_ms = self.last_fetch_ms.try_read().ok().and_then(|g| *g);
        DaBackendStatus {
            backend: DaBackendId::Celestia,
            healthy: true,
            last_submission_ms,
            last_fetch_ms,
            // Error-rate accounting will land alongside the metrics wave; the
            // backend itself currently exposes only the per-call Result.
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer> {
        let ns = self.resolve_namespace(namespace)?;
        let blob = Blob::new(ns, payload.to_vec(), None).map_err(|e| {
            StorageError::Generic(format!("failed to construct Celestia blob: {e}"))
        })?;
        let commitment = blob.commitment;
        let height = self
            .client
            .blob_submit(&[blob], TxConfig::default())
            .await
            .map_err(|e| {
                StorageError::Generic(format!("Celestia blob_submit failed: {e}"))
            })?;

        *self.last_submission_ms.write().await = Some(now_ms());

        Ok(DaPointer {
            backend: DaBackendId::Celestia,
            namespace: namespace.to_vec(),
            locator: encode_locator(height, &commitment),
            commitment_kzg: Some(commitment.hash().to_vec()),
            attestation_root: None,
        })
    }

    async fn fetch(&self, pointer: &DaPointer) -> Result<Vec<u8>> {
        if pointer.backend != DaBackendId::Celestia {
            return Err(StorageError::InvalidValue(format!(
                "CelestiaBackend cannot fetch pointer for backend {:?}",
                pointer.backend
            )));
        }
        let ns = self.resolve_namespace(&pointer.namespace)?;
        let (height, commitment_bytes) = decode_locator(&pointer.locator)?;
        let commitment = commitment_from_bytes(&commitment_bytes)?;
        let blob = self
            .client
            .blob_get(height, ns, commitment)
            .await
            .map_err(|e| {
                StorageError::Generic(format!("Celestia blob_get failed: {e}"))
            })?;

        *self.last_fetch_ms.write().await = Some(now_ms());
        Ok(blob.data)
    }

    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()> {
        if pointer.backend != DaBackendId::Celestia {
            return Err(StorageError::InvalidValue(format!(
                "CelestiaBackend cannot verify pointer for backend {:?}",
                pointer.backend
            )));
        }
        let ns = self.resolve_namespace(&pointer.namespace)?;
        let (height, commitment_bytes) = decode_locator(&pointer.locator)?;
        let commitment = commitment_from_bytes(&commitment_bytes)?;
        let proofs = self
            .client
            .blob_get_proof(height, ns, commitment)
            .await
            .map_err(|e| {
                StorageError::Generic(format!("Celestia blob_get_proof failed: {e}"))
            })?;
        if proofs.is_empty() {
            return Err(StorageError::Generic(
                "Celestia returned empty proof set for blob".into(),
            ));
        }
        // Server-side inclusion check: ask the celestia-node to verify the proof
        // against the block at `height`. Returns true iff the commitment is
        // included under the namespace at that height.
        //
        // This trusts the local celestia-node; full light-client verification
        // (re-fetch header via `header_get_by_height` and verify the NMT
        // root locally) is layered on top by callers that already maintain a
        // verified header chain. For the in-process backend that's overkill —
        // the operator's own celestia-node is the trust anchor.
        let included = self
            .client
            .blob_included(height, ns, &proofs[0], commitment)
            .await
            .map_err(|e| {
                StorageError::Generic(format!("Celestia blob_included failed: {e}"))
            })?;
        if included {
            Ok(())
        } else {
            Err(StorageError::Generic(format!(
                "Celestia reports commitment not included at height {height}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::compute_commitment;

    #[test]
    fn locator_round_trip() {
        let commitment = Commitment::new([0xab; 32]);
        let encoded = encode_locator(123_456, &commitment);
        let s = std::str::from_utf8(&encoded).unwrap();
        assert!(s.starts_with("123456:"));
        let (height, bytes) = decode_locator(&encoded).unwrap();
        assert_eq!(height, 123_456);
        assert_eq!(bytes, commitment.hash());
    }

    #[test]
    fn locator_decode_rejects_garbage() {
        assert!(decode_locator(b"no-colon-here").is_err());
        assert!(decode_locator(b"notanumber:dead").is_err());
        assert!(decode_locator(b"100:not-hex-zz").is_err());
    }

    #[test]
    fn commitment_from_bytes_enforces_length() {
        assert!(commitment_from_bytes(&[0u8; 32]).is_ok());
        assert!(commitment_from_bytes(&[0u8; 31]).is_err());
        assert!(commitment_from_bytes(&[0u8; 33]).is_err());
    }

    /// Live integration smoke-test. Skipped unless the operator has a
    /// celestia-node reachable at `CELESTIA_RPC_URL` with `CELESTIA_AUTH_TOKEN`
    /// (a write-permission token, since we exercise `blob_submit`).
    #[tokio::test]
    #[ignore = "requires CELESTIA_RPC_URL + CELESTIA_AUTH_TOKEN env vars and a reachable celestia-node"]
    async fn live_submit_fetch_verify_round_trip() {
        let url = match std::env::var("CELESTIA_RPC_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skipping: CELESTIA_RPC_URL not set");
                return;
            }
        };
        let auth = match std::env::var("CELESTIA_AUTH_TOKEN") {
            Ok(t) => t,
            Err(_) => {
                eprintln!("skipping: CELESTIA_AUTH_TOKEN not set");
                return;
            }
        };
        let backend = CelestiaBackend::connect(&url, &auth, b"tenzro-test")
            .await
            .expect("connect");
        let payload = b"tenzro celestia DA round-trip smoke test".to_vec();
        let sha = compute_commitment(&payload);
        let pointer = backend.submit(b"", &payload).await.expect("submit");
        assert_eq!(pointer.backend, DaBackendId::Celestia);
        assert!(pointer.commitment_kzg.is_some());
        // Celestia commitment differs from our SHA-256 commitment by design.
        assert_ne!(
            pointer.commitment_kzg.as_ref().unwrap().as_slice(),
            sha.as_bytes()
        );
        let fetched = backend.fetch(&pointer).await.expect("fetch");
        assert_eq!(fetched, payload);
        assert_eq!(compute_commitment(&fetched), sha);
        backend
            .verify_availability(&pointer)
            .await
            .expect("verify_availability");
    }
}
