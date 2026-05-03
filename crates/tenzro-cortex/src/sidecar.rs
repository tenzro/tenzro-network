//! HTTP sidecar backend for OpenMythos-style recurrent-depth models.
//!
//! This backend speaks a small JSON protocol to an external Python service
//! (typically FastAPI or Triton) that owns the actual PyTorch model. The
//! Rust worker handles metering, receipt signing, budget enforcement, and
//! payment routing; the sidecar handles the forward pass.
//!
//! # Sidecar contract
//!
//! `POST /v1/cortex/infer`
//!
//! Request body:
//! ```json
//! {
//!   "model_id": "mythos-3b",
//!   "input": "<hex-encoded bytes>",
//!   "n_loops_min": 8,
//!   "n_loops_max": 8,
//!   "params": {"temperature": "0.7"}
//! }
//! ```
//!
//! Response body:
//! ```json
//! {
//!   "output": "<hex-encoded bytes>",
//!   "loops_used": 8,
//!   "input_tokens": 10,
//!   "output_tokens": 24,
//!   "latency_ms": 412,
//!   "model_version": "mythos-3b-v0.1",
//!   "finish_reason": "stop",
//!   "experts_activated": 64,
//!   "weights_hash_hex": "0x...",
//!   "runtime_hash_hex": "0x..."
//! }
//! ```
//!
//! The sidecar is trusted to report `loops_used` honestly. For untrusted
//! backends, wrap them in a TEE (see `tenzro-tee`) and compare the reported
//! values against an attested quote before settlement.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tenzro_types::{
    cortex::{CortexMetadata, CortexModelFamily, CortexRequest, CortexResponse},
    primitives::{Address, Hash},
};
use tracing::debug;

use crate::{
    error::{CortexError, Result},
    receipt::{canonicalize_input, canonicalize_output, hash_commitment, sign_receipt},
    traits::RecurrentDepthModel,
};

/// Sidecar configuration.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Base URL of the sidecar (e.g. `http://127.0.0.1:8799`).
    pub base_url: String,
    /// Total request timeout.
    pub timeout: Duration,
    /// Optional bearer token for auth.
    pub bearer_token: Option<String>,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8799".to_string(),
            timeout: Duration::from_secs(120),
            bearer_token: None,
        }
    }
}

/// HTTP sidecar backend implementing [`RecurrentDepthModel`].
pub struct SidecarModel {
    model_id: String,
    family: CortexModelFamily,
    worker_did: String,
    worker_address: Address,
    signer: std::sync::Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
    cfg: SidecarConfig,
    http: reqwest::Client,
}

impl SidecarModel {
    /// Build a new sidecar-backed model.
    pub fn new(
        model_id: impl Into<String>,
        family: CortexModelFamily,
        worker_did: impl Into<String>,
        worker_address: Address,
        signer: std::sync::Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
        cfg: SidecarConfig,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .map_err(CortexError::Http)?;
        Ok(Self {
            model_id: model_id.into(),
            family,
            worker_did: worker_did.into(),
            worker_address,
            signer,
            cfg,
            http,
        })
    }

    /// Ping the sidecar's `GET /healthz` endpoint with a short timeout to
    /// verify reachability before accepting requests. Operators should call
    /// this at node startup (after `SidecarModel::new`) to fail fast if the
    /// Python inference process isn't up, rather than surfacing connection
    /// errors on the first paying request.
    ///
    /// Uses a 5-second timeout regardless of `SidecarConfig::timeout` because
    /// health checks should never block a startup sequence for minutes.
    pub async fn ping_health(&self) -> Result<()> {
        let url = format!("{}/healthz", self.cfg.base_url.trim_end_matches('/'));
        let mut req = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5));
        if let Some(token) = &self.cfg.bearer_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(CortexError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CortexError::SidecarStatus {
                status: status.as_u16(),
                body,
            });
        }
        debug!(url = %url, "cortex sidecar health check OK");
        Ok(())
    }
}

#[derive(Serialize)]
struct InferRequestWire<'a> {
    model_id: &'a str,
    input_hex: String,
    n_loops_min: u32,
    n_loops_max: u32,
    params: &'a std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct InferResponseWire {
    /// Hex-encoded output bytes.
    output_hex: String,
    loops_used: u32,
    input_tokens: u32,
    output_tokens: u32,
    latency_ms: u64,
    #[serde(default)]
    model_version: Option<String>,
    #[serde(default)]
    finish_reason: Option<String>,
    #[serde(default)]
    experts_activated: Option<u32>,
    /// Hex-encoded 32-byte weights hash.
    weights_hash_hex: String,
    /// Hex-encoded 32-byte runtime hash.
    runtime_hash_hex: String,
}

#[async_trait]
impl RecurrentDepthModel for SidecarModel {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn family(&self) -> &CortexModelFamily {
        &self.family
    }

    async fn infer(&self, request: &CortexRequest) -> Result<CortexResponse> {
        if request.model_id != self.model_id {
            return Err(CortexError::UnknownModel(request.model_id.clone()));
        }
        if request.budget.max_loops > self.family.max_loops {
            return Err(CortexError::InvalidBudget(format!(
                "request max_loops {} exceeds model max_loops {}",
                request.budget.max_loops, self.family.max_loops
            )));
        }

        let url = format!("{}/v1/cortex/infer", self.cfg.base_url.trim_end_matches('/'));
        let wire = InferRequestWire {
            model_id: &self.model_id,
            input_hex: hex::encode(&request.input),
            n_loops_min: request.budget.min_loops,
            n_loops_max: request.budget.max_loops,
            params: &request.params,
        };

        let mut req = self.http.post(&url).json(&wire);
        if let Some(token) = &self.cfg.bearer_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(CortexError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CortexError::SidecarStatus {
                status: status.as_u16(),
                body,
            });
        }

        let body: InferResponseWire = resp.json().await.map_err(CortexError::Http)?;
        debug!(
            model_id = %self.model_id,
            loops_used = body.loops_used,
            latency_ms = body.latency_ms,
            "cortex sidecar returned response"
        );

        if !request.budget.allows_loops(body.loops_used) {
            return Err(CortexError::LoopsOutOfRange {
                loops_used: body.loops_used,
                min: request.budget.min_loops,
                max: request.budget.max_loops,
            });
        }

        let output = hex::decode(&body.output_hex)
            .map_err(|e| CortexError::Other(format!("invalid output_hex: {e}")))?;

        let weights_hash = parse_hash_hex(&body.weights_hash_hex, "weights_hash_hex")?;
        let runtime_hash = parse_hash_hex(&body.runtime_hash_hex, "runtime_hash_hex")?;

        let metadata = CortexMetadata {
            input_tokens: body.input_tokens,
            output_tokens: body.output_tokens,
            loops_used: body.loops_used,
            latency_ms: body.latency_ms,
            model_version: body.model_version,
            finish_reason: body.finish_reason,
            experts_activated: body.experts_activated,
        };

        // Commitments bind the receipt to canonical request/response payloads.
        let input_commitment = hash_commitment(&canonicalize_input(request));
        let output_commitment = hash_commitment(&canonicalize_output(&output));

        // Price is not set here — the worker layer applies CortexPricing. We
        // insert a placeholder of 0 which the worker overwrites before
        // returning to the caller.
        let receipt = sign_receipt(
            &*self.signer,
            &self.model_id,
            weights_hash,
            runtime_hash,
            request.budget.max_loops,
            body.loops_used,
            input_commitment,
            output_commitment,
            &self.worker_did,
            self.worker_address,
            None,
            None,
            body.input_tokens,
            body.output_tokens,
            0, // price_tnzo — finalized by worker
        )?;

        let response_id = uuid::Uuid::new_v4().to_string();

        Ok(CortexResponse {
            request_id: request.request_id.clone(),
            response_id,
            model_id: self.model_id.clone(),
            worker: self.worker_address,
            output,
            metadata,
            price_tnzo: 0,
            receipt,
            timestamp: tenzro_types::primitives::Timestamp::now(),
        })
    }
}

fn parse_hash_hex(s: &str, field: &str) -> Result<Hash> {
    let trimmed = s.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| CortexError::Other(format!("invalid {field}: {e}")))?;
    Hash::from_bytes(&bytes).ok_or_else(|| CortexError::Other(format!("{field} not 32 bytes")))
}
