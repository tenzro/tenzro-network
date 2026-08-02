//! EigenDA data-availability backend.
//!
//! Implements [`DaBackend`] against the EigenDA proxy gateway
//! (<https://github.com/Layr-Labs/eigenda-proxy>) — the Go service Eigen Labs
//! publishes for rollups that don't want to depend directly on the disperser
//! gRPC ABI. The proxy exposes a stable REST surface:
//!
//! - `POST /put/`           — submit a blob, returns a hex-encoded commitment
//! - `GET  /get/{commitment}` — fetch the original payload bytes by commitment
//! - `GET  /health`         — liveness probe (200 = up)
//!
//! Used in production by Eigen Layer's own client integrations (Mantle, Layr,
//! ZKsync, etc.). Re-using it here means a Tenzro operator runs a sidecar
//! `eigenda-proxy` binary against the public EigenDA disperser, and we speak
//! plain HTTP to it — no custom RLP, no proto pinning, no signer key handling.
//!
//! # Wire model
//!
//! - `submit(namespace, payload)` — POSTs the raw payload bytes to `/put/`
//!   with `Content-Type: application/octet-stream`. The response body is the
//!   EigenDA commitment (32-byte SHA-256-style hash of the encoded blob,
//!   not the same as our chain-of-custody `SHA-256(payload)`). The locator is
//!   the lowercase-hex encoding of that commitment.
//!
//! - `fetch(pointer)` — GETs `/get/0x{commitment_hex}` and returns the body.
//!
//! - `verify_availability(pointer)` — issues a `HEAD /get/0x{commitment_hex}`;
//!   a 2xx response means the proxy is willing to serve the commitment, which
//!   is the strongest cheap probe the proxy exposes. (Full attestation-quorum
//!   verification — querying the EigenDA attestation service for the BN254
//!   signature set — is a future hardening step; for the in-process backend
//!   the local proxy is the trust anchor, same model the Celestia backend
//!   uses with a local celestia-node.)
//!
//! # Dual commitment model
//!
//! The chain-of-custody commitment in [`ReceiptEnvelope::commitment`] is always
//! `SHA-256(canonical_payload)` (see [`compute_commitment`]). EigenDA returns
//! its own commitment computed over the encoded blob, which we surface in
//! [`DaPointer::commitment_kzg`]. Verifiers MUST hash the fetched payload and
//! compare against the SHA-256 receipt commitment before trusting the bytes —
//! the EigenDA commitment alone is computed in a different domain.
//!
//! `attestation_root` is left `None`; the EigenDA disperser does produce a
//! quorum attestation, but it is fetched via a separate `eigenda-proxy`
//! endpoint and verifying it requires the BN254 aggregation libraries, which
//! this module does not pull in. That verification belongs with the Tenzro
//! fraud-proof path.

use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::da::{DaBackend, DaBackendId, DaBackendStatus, DaPointer};
use crate::error::{Result, StorageError};

/// EigenDA backend driven by a local `eigenda-proxy` HTTP gateway.
pub struct EigenDaBackend {
    client: reqwest::Client,
    /// Proxy base URL, e.g. `http://127.0.0.1:3100`. Trailing slash stripped.
    base_url: String,
    /// Most recent successful submission timestamp (ms since epoch).
    last_submission_ms: RwLock<Option<i64>>,
    /// Most recent successful fetch timestamp (ms since epoch).
    last_fetch_ms: RwLock<Option<i64>>,
}

impl EigenDaBackend {
    /// Connect to an `eigenda-proxy` HTTP gateway. The base URL may include or
    /// omit a trailing slash; it is normalised.
    ///
    /// Connection itself is lazy (reqwest only opens TCP on first request),
    /// so this constructor never blocks on the network — startup ordering
    /// stays decoupled from proxy availability.
    pub fn connect(base_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                StorageError::Generic(format!("EigenDA reqwest client build failed: {e}"))
            })?;
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        if base.is_empty() {
            return Err(StorageError::InvalidValue(
                "EigenDA base URL must not be empty".into(),
            ));
        }
        Ok(Self {
            client,
            base_url: base,
            last_submission_ms: RwLock::new(None),
            last_fetch_ms: RwLock::new(None),
        })
    }

    fn get_url(&self, commitment_hex: &str) -> String {
        format!("{}/get/0x{}", self.base_url, commitment_hex)
    }

    fn put_url(&self) -> String {
        format!("{}/put/", self.base_url)
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Decode a hex-encoded commitment from the proxy response body, accepting an
/// optional `0x` prefix and ignoring trailing whitespace from `text()`.
fn decode_commitment_hex(body: &str) -> Result<Vec<u8>> {
    let trimmed = body.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(stripped).map_err(|e| {
        StorageError::InvalidValue(format!(
            "EigenDA proxy returned non-hex commitment {trimmed:?}: {e}"
        ))
    })
}

/// Decode the `DaPointer::locator` produced by [`EigenDaBackend::submit`] back
/// to a lowercase commitment-hex string suitable for the GET path.
fn locator_to_hex(locator: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(locator)
        .map_err(|e| StorageError::InvalidValue(format!("EigenDA locator not valid UTF-8: {e}")))?;
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    // Validate it's actual hex up front so we surface a clean error rather
    // than letting the proxy 404 on a malformed path.
    let bytes = hex::decode(stripped)
        .map_err(|e| StorageError::InvalidValue(format!("EigenDA locator hex invalid: {e}")))?;
    Ok(hex::encode(bytes))
}

#[async_trait]
impl DaBackend for EigenDaBackend {
    fn id(&self) -> DaBackendId {
        DaBackendId::EigenDA
    }

    fn status(&self) -> DaBackendStatus {
        let last_submission_ms = self.last_submission_ms.try_read().ok().and_then(|g| *g);
        let last_fetch_ms = self.last_fetch_ms.try_read().ok().and_then(|g| *g);
        DaBackendStatus {
            backend: DaBackendId::EigenDA,
            healthy: true,
            last_submission_ms,
            last_fetch_ms,
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer> {
        let resp = self
            .client
            .post(self.put_url())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|e| StorageError::Generic(format!("EigenDA POST /put/ failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| StorageError::Generic(format!("EigenDA /put/ body read failed: {e}")))?;
        if !status.is_success() {
            return Err(StorageError::Generic(format!(
                "EigenDA /put/ returned HTTP {status}: {body}"
            )));
        }
        let commitment_bytes = decode_commitment_hex(&body)?;

        *self.last_submission_ms.write().await = Some(now_ms());
        Ok(DaPointer {
            backend: DaBackendId::EigenDA,
            namespace: namespace.to_vec(),
            locator: hex::encode(&commitment_bytes).into_bytes(),
            commitment_kzg: Some(commitment_bytes),
            attestation_root: None,
        })
    }

    async fn fetch(&self, pointer: &DaPointer) -> Result<Vec<u8>> {
        if pointer.backend != DaBackendId::EigenDA {
            return Err(StorageError::InvalidValue(format!(
                "EigenDaBackend cannot fetch pointer for backend {:?}",
                pointer.backend
            )));
        }
        let hex_str = locator_to_hex(&pointer.locator)?;
        let resp = self
            .client
            .get(self.get_url(&hex_str))
            .send()
            .await
            .map_err(|e| StorageError::Generic(format!("EigenDA GET /get/ failed: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| StorageError::Generic(format!("EigenDA /get/ body read failed: {e}")))?;
        if !status.is_success() {
            return Err(StorageError::Generic(format!(
                "EigenDA /get/ returned HTTP {status} for commitment 0x{hex_str}"
            )));
        }
        *self.last_fetch_ms.write().await = Some(now_ms());
        Ok(bytes.to_vec())
    }

    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()> {
        if pointer.backend != DaBackendId::EigenDA {
            return Err(StorageError::InvalidValue(format!(
                "EigenDaBackend cannot verify pointer for backend {:?}",
                pointer.backend
            )));
        }
        let hex_str = locator_to_hex(&pointer.locator)?;
        let resp = self
            .client
            .head(self.get_url(&hex_str))
            .send()
            .await
            .map_err(|e| StorageError::Generic(format!("EigenDA HEAD /get/ failed: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(StorageError::Generic(format!(
                "EigenDA proxy reports commitment 0x{hex_str} unavailable: HTTP {}",
                resp.status()
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
        assert!(EigenDaBackend::connect("").is_err());
        assert!(EigenDaBackend::connect("///").is_err());
    }

    #[test]
    fn connect_strips_trailing_slash() {
        let b = EigenDaBackend::connect("http://localhost:3100/").unwrap();
        assert_eq!(b.base_url, "http://localhost:3100");
        assert_eq!(b.put_url(), "http://localhost:3100/put/");
        assert_eq!(
            b.get_url("deadbeef"),
            "http://localhost:3100/get/0xdeadbeef"
        );
    }

    #[test]
    fn decode_commitment_hex_accepts_prefix_and_whitespace() {
        let body = "  0xDEADBEEF\n";
        let bytes = decode_commitment_hex(body).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_commitment_hex_rejects_garbage() {
        assert!(decode_commitment_hex("xyz").is_err());
        assert!(decode_commitment_hex("0xnothex").is_err());
    }

    #[test]
    fn locator_to_hex_round_trip() {
        let commitment = vec![0xab, 0xcd, 0xef, 0x01];
        let locator = hex::encode(&commitment).into_bytes();
        let hex_str = locator_to_hex(&locator).unwrap();
        assert_eq!(hex_str, "abcdef01");
        // Accepts an optional 0x prefix on inbound locators too.
        let prefixed = format!("0x{}", hex_str).into_bytes();
        assert_eq!(locator_to_hex(&prefixed).unwrap(), hex_str);
    }

    #[test]
    fn locator_to_hex_rejects_non_utf8() {
        let bad = vec![0xff, 0xfe, 0xfd];
        assert!(locator_to_hex(&bad).is_err());
    }

    /// Live smoke-test. Skipped unless the operator has an `eigenda-proxy`
    /// reachable at `EIGENDA_PROXY_URL` with write permission against the
    /// configured disperser.
    #[tokio::test]
    #[ignore = "requires EIGENDA_PROXY_URL env var and a reachable eigenda-proxy"]
    async fn live_submit_fetch_verify_round_trip() {
        let url = match std::env::var("EIGENDA_PROXY_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skipping: EIGENDA_PROXY_URL not set");
                return;
            }
        };
        let backend = EigenDaBackend::connect(url).expect("connect");
        let payload = b"tenzro eigenda DA round-trip smoke test".to_vec();
        let sha = compute_commitment(&payload);
        let pointer = backend
            .submit(b"tenzro/inference", &payload)
            .await
            .expect("submit");
        assert_eq!(pointer.backend, DaBackendId::EigenDA);
        assert!(pointer.commitment_kzg.is_some());
        // EigenDA commitment ≠ our SHA-256 by design.
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
