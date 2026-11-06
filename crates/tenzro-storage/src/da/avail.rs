//! Avail data-availability backend.
//!
//! Implements [`DaBackend`] against an Avail Light Client HTTP gateway
//! (<https://docs.availproject.org/docs/operate-a-node/run-a-light-client>),
//! the production interface Avail recommends for L2s and rollups since
//! `avail-light` v1.12. The light client exposes a stable REST surface that
//! abstracts over the underlying substrate JSON-RPC:
//!
//! - `POST /v2/submit`                     — submit a data payload, returns
//!     `{ "block_number": N, "block_hash": "0x...", "hash": "0x...",
//!        "index": K }`
//! - `GET  /v2/blocks/{block_number}/data?fields=data` — fetch the submitted
//!     payloads from a block (filterable by extrinsic index)
//! - `GET  /v2/status`                     — liveness + sync status
//!
//! The light client also performs KZG-based data-availability sampling
//! locally, so a successful `POST /v2/submit` is a stronger guarantee than the
//! equivalent EigenDA `/put/`: Avail's data root is included in the block
//! header, and the light client verifies a randomised cell sample before
//! reporting success.
//!
//! # Wire model
//!
//! - `submit(namespace, payload)` — POSTs the payload as JSON
//!     `{"data": "<base64>"}` to `/v2/submit`. Avail responds with the
//!     `block_number`, `block_hash`, `hash` (data hash), and `index`
//!     (extrinsic position). The locator is `"{block_number}:{index}"` UTF-8
//!     bytes — sufficient to recover the payload via the block-data endpoint.
//!     `commitment_kzg` carries the 32-byte `hash` (data hash) Avail returns,
//!     and `attestation_root` carries the `block_hash` so a verifier can
//!     cross-check the data root against the canonical block header.
//!
//! - `fetch(pointer)` — parses the `{block_number}:{index}` locator and GETs
//!     `/v2/blocks/{block_number}/data?fields=data&decode=true`, then walks
//!     the `data_transactions` array to pluck the entry at the matching index.
//!     Avail returns the payload base64-encoded; we decode before returning.
//!
//! - `verify_availability(pointer)` — re-fetches the block data via the
//!     same endpoint and confirms the index resolves. The light client's
//!     local DA-sampling guarantees attest availability at submission time;
//!     this method is the cheap "still there" probe.
//!
//! # Dual commitment model
//!
//! The chain-of-custody commitment in [`ReceiptEnvelope::commitment`] is always
//! `SHA-256(canonical_payload)` (see [`compute_commitment`]). Avail returns
//! its own BLAKE2b-256 `hash` over the encoded extrinsic, which we surface in
//! [`DaPointer::commitment_kzg`]. Verifiers MUST hash the fetched payload and
//! compare against the SHA-256 receipt commitment before trusting the bytes.
//!
//! `attestation_root` carries Avail's `block_hash`, which a future hardening
//! step (when we wire in an Avail light-client sync) will use to verify the
//! data root locally against the substrate header — for the in-process
//! backend the operator's own avail-light is the trust anchor, mirroring the
//! Celestia and EigenDA backends.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::RwLock;

use crate::da::{DaBackend, DaBackendId, DaBackendStatus, DaPointer};
use crate::error::{Result, StorageError};
use tenzro_types::primitives::Hash;

#[derive(Debug, Serialize)]
struct SubmitBody {
    /// Base64-encoded payload. Avail's `/v2/submit` accepts either `"data"`
    /// (binary, base64-encoded by the gateway) or `"extrinsic"` (raw extrinsic
    /// hex) — `"data"` is the path rollups use.
    data: String,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    block_number: u64,
    block_hash: String,
    /// Avail's BLAKE2b-256 data hash over the submitted extrinsic.
    hash: String,
    /// Extrinsic index within the block.
    index: u32,
}

#[derive(Debug, Deserialize)]
struct BlockDataResponse {
    #[serde(default)]
    data_transactions: Vec<BlockDataTx>,
}

#[derive(Debug, Deserialize)]
struct BlockDataTx {
    /// Base64-encoded payload as returned by the light client.
    data: String,
    /// Extrinsic index within the block, used to disambiguate when a block
    /// holds multiple submissions.
    extrinsic_index: u32,
}

/// Avail backend driven by a local `avail-light` HTTP gateway.
pub struct AvailBackend {
    client: reqwest::Client,
    /// Light-client base URL, e.g. `http://127.0.0.1:7000`. Trailing slash
    /// stripped.
    base_url: String,
    /// Most recent successful submission timestamp (ms since epoch).
    last_submission_ms: RwLock<Option<i64>>,
    /// Most recent successful fetch timestamp (ms since epoch).
    last_fetch_ms: RwLock<Option<i64>>,
}

impl AvailBackend {
    /// Connect to an `avail-light` HTTP gateway. Lazy — the constructor does
    /// not hit the network.
    pub fn connect(base_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                StorageError::Generic(format!("Avail reqwest client build failed: {e}"))
            })?;
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        if base.is_empty() {
            return Err(StorageError::InvalidValue(
                "Avail base URL must not be empty".into(),
            ));
        }
        Ok(Self {
            client,
            base_url: base,
            last_submission_ms: RwLock::new(None),
            last_fetch_ms: RwLock::new(None),
        })
    }

    fn submit_url(&self) -> String {
        format!("{}/v2/submit", self.base_url)
    }

    fn block_data_url(&self, block_number: u64) -> String {
        format!(
            "{}/v2/blocks/{}/data?fields=data&decode=true",
            self.base_url, block_number
        )
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Encode a `(block_number, extrinsic_index)` pair into the
/// `DaPointer::locator` field. Format: `"{block_number}:{index}"` UTF-8 bytes.
fn encode_locator(block_number: u64, index: u32) -> Vec<u8> {
    format!("{block_number}:{index}").into_bytes()
}

/// Inverse of [`encode_locator`].
fn decode_locator(locator: &[u8]) -> Result<(u64, u32)> {
    let s = std::str::from_utf8(locator)
        .map_err(|e| StorageError::InvalidValue(format!("Avail locator not valid UTF-8: {e}")))?;
    let (n_str, i_str) = s.split_once(':').ok_or_else(|| {
        StorageError::InvalidValue(format!("Avail locator missing ':' separator: {s}"))
    })?;
    let block_number = n_str.parse::<u64>().map_err(|e| {
        StorageError::InvalidValue(format!("Avail locator block_number invalid: {e}"))
    })?;
    let index = i_str
        .parse::<u32>()
        .map_err(|e| StorageError::InvalidValue(format!("Avail locator index invalid: {e}")))?;
    Ok((block_number, index))
}

/// Decode a `0x`-prefixed (or bare) hex string into raw bytes. Used for
/// translating Avail's `hash` and `block_hash` strings.
fn decode_hex_opt(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map_err(|e| StorageError::InvalidValue(format!("Avail hex value invalid: {e}")))
}

/// Coerce a hex string into a 32-byte `Hash`. Returns `None` if the string
/// does not decode to exactly 32 bytes — Avail block hashes are always
/// 32 bytes, but a defensive coercion avoids panicking on a malformed
/// response.
fn try_hash_from_hex(s: &str) -> Option<Hash> {
    let bytes = decode_hex_opt(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash::new(arr))
}

#[async_trait]
impl DaBackend for AvailBackend {
    fn id(&self) -> DaBackendId {
        DaBackendId::Avail
    }

    fn status(&self) -> DaBackendStatus {
        let last_submission_ms = self.last_submission_ms.try_read().ok().and_then(|g| *g);
        let last_fetch_ms = self.last_fetch_ms.try_read().ok().and_then(|g| *g);
        DaBackendStatus {
            backend: DaBackendId::Avail,
            healthy: true,
            last_submission_ms,
            last_fetch_ms,
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer> {
        let body = SubmitBody {
            data: BASE64.encode(payload),
        };
        let resp = self
            .client
            .post(self.submit_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| StorageError::Generic(format!("Avail POST /v2/submit failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(StorageError::Generic(format!(
                "Avail /v2/submit returned HTTP {status}: {body}"
            )));
        }
        let parsed: SubmitResponse = resp.json().await.map_err(|e| {
            StorageError::Generic(format!("Avail /v2/submit body decode failed: {e}"))
        })?;

        let commitment_bytes = decode_hex_opt(&parsed.hash)?;
        let attestation_root = try_hash_from_hex(&parsed.block_hash);

        *self.last_submission_ms.write().await = Some(now_ms());
        Ok(DaPointer {
            backend: DaBackendId::Avail,
            namespace: namespace.to_vec(),
            locator: encode_locator(parsed.block_number, parsed.index),
            commitment_kzg: Some(commitment_bytes),
            attestation_root,
        })
    }

    async fn fetch(&self, pointer: &DaPointer) -> Result<Vec<u8>> {
        if pointer.backend != DaBackendId::Avail {
            return Err(StorageError::InvalidValue(format!(
                "AvailBackend cannot fetch pointer for backend {:?}",
                pointer.backend
            )));
        }
        let (block_number, index) = decode_locator(&pointer.locator)?;
        let resp = self
            .client
            .get(self.block_data_url(block_number))
            .send()
            .await
            .map_err(|e| {
                StorageError::Generic(format!(
                    "Avail GET /v2/blocks/{block_number}/data failed: {e}"
                ))
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(StorageError::Generic(format!(
                "Avail /v2/blocks/{block_number}/data returned HTTP {status}"
            )));
        }
        let parsed: BlockDataResponse = resp.json().await.map_err(|e| {
            StorageError::Generic(format!(
                "Avail /v2/blocks/{block_number}/data body decode failed: {e}"
            ))
        })?;
        let entry = parsed
            .data_transactions
            .into_iter()
            .find(|tx| tx.extrinsic_index == index)
            .ok_or_else(|| {
                StorageError::KeyNotFound(format!(
                    "Avail block {block_number} has no extrinsic at index {index}"
                ))
            })?;
        let bytes = BASE64.decode(entry.data.as_bytes()).map_err(|e| {
            StorageError::InvalidValue(format!("Avail payload base64 decode failed: {e}"))
        })?;

        *self.last_fetch_ms.write().await = Some(now_ms());
        Ok(bytes)
    }

    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()> {
        if pointer.backend != DaBackendId::Avail {
            return Err(StorageError::InvalidValue(format!(
                "AvailBackend cannot verify pointer for backend {:?}",
                pointer.backend
            )));
        }
        // Cheapest "still there" probe = re-fetch the block-data list and
        // confirm the index resolves. Avoids transferring the full payload
        // if the block holds many extrinsics by checking only the index.
        let (block_number, index) = decode_locator(&pointer.locator)?;
        let resp = self
            .client
            .get(self.block_data_url(block_number))
            .send()
            .await
            .map_err(|e| {
                StorageError::Generic(format!(
                    "Avail GET /v2/blocks/{block_number}/data failed: {e}"
                ))
            })?;
        if !resp.status().is_success() {
            return Err(StorageError::Generic(format!(
                "Avail block {block_number} unavailable: HTTP {}",
                resp.status()
            )));
        }
        let parsed: BlockDataResponse = resp.json().await.map_err(|e| {
            StorageError::Generic(format!(
                "Avail /v2/blocks/{block_number}/data body decode failed: {e}"
            ))
        })?;
        if parsed
            .data_transactions
            .iter()
            .any(|tx| tx.extrinsic_index == index)
        {
            Ok(())
        } else {
            Err(StorageError::KeyNotFound(format!(
                "Avail block {block_number} no longer holds extrinsic {index}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::compute_commitment;

    #[test]
    fn connect_rejects_empty_base_url() {
        assert!(AvailBackend::connect("").is_err());
        assert!(AvailBackend::connect("///").is_err());
    }

    #[test]
    fn connect_strips_trailing_slash() {
        let b = AvailBackend::connect("http://localhost:7000/").unwrap();
        assert_eq!(b.base_url, "http://localhost:7000");
        assert_eq!(b.submit_url(), "http://localhost:7000/v2/submit");
        assert_eq!(
            b.block_data_url(42),
            "http://localhost:7000/v2/blocks/42/data?fields=data&decode=true"
        );
    }

    #[test]
    fn locator_round_trip() {
        let l = encode_locator(1234, 7);
        assert_eq!(l, b"1234:7".to_vec());
        let (n, i) = decode_locator(&l).unwrap();
        assert_eq!(n, 1234);
        assert_eq!(i, 7);
    }

    #[test]
    fn locator_decode_rejects_garbage() {
        assert!(decode_locator(b"no-colon-here").is_err());
        assert!(decode_locator(b"notanumber:5").is_err());
        assert!(decode_locator(b"100:not-a-number").is_err());
    }

    #[test]
    fn decode_hex_opt_accepts_prefix() {
        let a = decode_hex_opt("0xdeadbeef").unwrap();
        let b = decode_hex_opt("deadbeef").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn try_hash_from_hex_enforces_length() {
        let ok = format!("0x{}", hex::encode([0xab; 32]));
        assert!(try_hash_from_hex(&ok).is_some());
        let short = format!("0x{}", hex::encode([0xab; 31]));
        assert!(try_hash_from_hex(&short).is_none());
        assert!(try_hash_from_hex("not-hex").is_none());
    }

    /// Live smoke-test. Skipped unless the operator has an `avail-light`
    /// reachable at `AVAIL_LIGHT_URL` configured to submit against a
    /// funded application key.
    #[tokio::test]
    #[ignore = "requires AVAIL_LIGHT_URL env var and a reachable avail-light"]
    async fn live_submit_fetch_verify_round_trip() {
        let url = match std::env::var("AVAIL_LIGHT_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skipping: AVAIL_LIGHT_URL not set");
                return;
            }
        };
        let backend = AvailBackend::connect(url).expect("connect");
        let payload = b"tenzro avail DA round-trip smoke test".to_vec();
        let sha = compute_commitment(&payload);
        let pointer = backend
            .submit(b"tenzro/inference", &payload)
            .await
            .expect("submit");
        assert_eq!(pointer.backend, DaBackendId::Avail);
        assert!(pointer.commitment_kzg.is_some());
        // Avail's BLAKE2b-256 commitment ≠ our SHA-256 by design.
        assert_ne!(
            pointer.commitment_kzg.as_ref().unwrap().as_slice(),
            sha.as_bytes()
        );
        let fetched = backend.fetch(&pointer).await.expect("fetch");
        assert_eq!(fetched, payload);
        assert_eq!(compute_commitment(&fetched), sha);
        backend.verify_availability(&pointer).await.expect("verify");
    }
}
