//! Remote DID resolution fallback for the identity registry.
//!
//! `IdentityRegistry::resolve()` consults a `DidResolutionBackend` when a
//! DID is absent from the local registry. This module supplies the concrete
//! backend: a JSON-RPC client that calls `tenzro_resolveIdentity` with
//! `include_record: true` on an upstream node (typically a bootstrap
//! validator) and deserializes the full `TenzroIdentity` record from the
//! response. Successful resolutions are cached by the registry, so the
//! upstream is only consulted once per unknown DID.
//!
//! The trait is synchronous while the node runs inside tokio, so each call
//! runs the HTTP round-trip on a dedicated OS thread with its own
//! current-thread runtime. Fallback resolution is rare (cache-miss only),
//! so the per-call thread cost is acceptable and avoids both a `blocking`
//! reqwest feature on the workspace and panics from nested runtimes.

use std::time::Duration;

use tenzro_identity::{DidResolutionBackend, IdentityError, TenzroIdentity};
use tracing::debug;

/// JSON-RPC error code returned by `tenzro_resolveIdentity` when the DID
/// has no record on the upstream ledger. Mapped to `Ok(None)` so the
/// registry falls through to `NotFound` instead of logging a warning.
const NOT_FOUND_CODE: i64 = -32404;

/// Resolves unknown DIDs against an upstream node's JSON-RPC endpoint.
pub struct RemoteDidResolutionBackend {
    endpoint: String,
    timeout: Duration,
}

impl RemoteDidResolutionBackend {
    /// Create a backend targeting `endpoint` (e.g. `https://rpc.tenzro.xyz`)
    /// with a 10-second request timeout.
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_secs(10),
        }
    }

    async fn resolve_async(
        endpoint: String,
        timeout: Duration,
        did: String,
    ) -> Result<Option<TenzroIdentity>, IdentityError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tenzro_resolveIdentity",
            "params": { "did": did, "include_record": true },
        });

        let response = crate::http_client::shared()
            .post(&endpoint)
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| IdentityError::ResolutionError(format!("request to {}: {}", endpoint, e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(IdentityError::ResolutionError(format!(
                "upstream {} returned HTTP {}",
                endpoint, status
            )));
        }

        let envelope: serde_json::Value = response
            .json()
            .await
            .map_err(|e| IdentityError::ResolutionError(format!("response decode: {}", e)))?;

        if let Some(err) = envelope.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            if code == NOT_FOUND_CODE {
                return Ok(None);
            }
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown upstream error");
            return Err(IdentityError::ResolutionError(format!(
                "upstream error {}: {}",
                code, message
            )));
        }

        let record = envelope
            .get("result")
            .and_then(|r| r.get("record"))
            .cloned()
            .ok_or_else(|| {
                IdentityError::ResolutionError(
                    "upstream response missing 'record' — upstream may predate include_record support"
                        .to_string(),
                )
            })?;

        let identity: TenzroIdentity = serde_json::from_value(record)
            .map_err(|e| IdentityError::ResolutionError(format!("record deserialize: {}", e)))?;

        Ok(Some(identity))
    }
}

impl DidResolutionBackend for RemoteDidResolutionBackend {
    fn resolve_remote(&self, did: &str) -> tenzro_identity::Result<Option<TenzroIdentity>> {
        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;
        let did = did.to_string();
        debug!("Remote DID resolution for {} via {}", did, endpoint);

        // Dedicated OS thread + current-thread runtime: callable from both
        // sync and async contexts without a nested-runtime panic.
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| IdentityError::ResolutionError(format!("runtime build: {}", e)))?;
            rt.block_on(Self::resolve_async(endpoint, timeout, did))
        });

        handle
            .join()
            .map_err(|_| IdentityError::ResolutionError("resolution thread panicked".to_string()))?
    }
}
