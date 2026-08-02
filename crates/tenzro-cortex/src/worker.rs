//! Cortex worker: pairs a [`RecurrentDepthModel`] backend with pricing,
//! budget enforcement, and receipt finalization.
//!
//! A [`CortexWorker`] is what a node exposes on the network. It:
//!
//! 1. Accepts a [`CortexRequest`] from the RPC / MCP layer.
//! 2. Enforces the caller's [`ReasoningBudget`] against the model's
//!    declared [`CortexModelFamily`].
//! 3. Delegates inference to a backend implementing
//!    [`crate::traits::RecurrentDepthModel`] (e.g. an HTTP sidecar).
//! 4. Computes the final price using [`CortexPricing::compute`].
//! 5. Rejects the response if cost exceeds the caller's budget.
//! 6. Re-signs the receipt with the final price and returns it.

use std::sync::Arc;
use std::time::Instant;

use tenzro_crypto::signatures::Signer;
use tenzro_types::{
    cortex::{
        AttestationRequirement, CortexPricing, CortexRequest, CortexResponse, ReasoningBudget,
    },
    primitives::Address,
};
use tracing::{debug, warn};

use crate::{
    attestation::AttestationSuite,
    error::{CortexError, Result},
    metrics::{CortexMetrics, RejectionReason},
    receipt::sign_receipt,
    traits::RecurrentDepthModel,
};

/// A network-exposed Cortex worker.
pub struct CortexWorker {
    model: Arc<dyn RecurrentDepthModel>,
    pricing: CortexPricing,
    signer: Arc<dyn Signer + Send + Sync>,
    worker_did: String,
    worker_address: Address,
    attestation: AttestationSuite,
    metrics: CortexMetrics,
}

impl CortexWorker {
    pub fn new(
        model: Arc<dyn RecurrentDepthModel>,
        pricing: CortexPricing,
        signer: Arc<dyn Signer + Send + Sync>,
        worker_did: impl Into<String>,
        worker_address: Address,
    ) -> Self {
        Self {
            model,
            pricing,
            signer,
            worker_did: worker_did.into(),
            worker_address,
            attestation: AttestationSuite::default(),
            metrics: CortexMetrics::new(),
        }
    }

    /// Attach a TEE/ZK attestation suite. Without this, any request that
    /// specifies `AttestationRequirement::Tee` or `TeeAndZk` will be
    /// rejected.
    pub fn with_attestation(mut self, suite: AttestationSuite) -> Self {
        self.attestation = suite;
        self
    }

    /// Attach a pre-existing metrics collector so multiple workers on
    /// the same node can share a Prometheus-exportable registry.
    pub fn with_metrics(mut self, metrics: CortexMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Clone of the metrics handle. Hand this to an HTTP exporter.
    pub fn metrics(&self) -> CortexMetrics {
        self.metrics.clone()
    }

    /// Model identifier this worker serves.
    pub fn model_id(&self) -> &str {
        self.model.model_id()
    }

    /// DID of the worker signing receipts.
    pub fn worker_did(&self) -> &str {
        &self.worker_did
    }

    /// Worker's on-chain settlement address.
    pub fn worker_address(&self) -> Address {
        self.worker_address
    }

    /// Underlying recurrent-depth backend.
    pub fn backend(&self) -> &Arc<dyn RecurrentDepthModel> {
        &self.model
    }

    /// Pricing schedule applied to this worker's receipts.
    pub fn pricing(&self) -> &CortexPricing {
        &self.pricing
    }

    /// Estimate the maximum possible cost for a request, in wei.
    pub fn estimate_max_cost(
        &self,
        budget: &ReasoningBudget,
        estimated_input_tokens: u32,
        estimated_output_tokens: u32,
    ) -> u128 {
        self.pricing.compute(
            estimated_input_tokens,
            estimated_output_tokens,
            budget.max_loops,
            budget.attestation,
        )
    }

    /// Execute a reasoning request: validate budget, run inference, price,
    /// attest, and re-sign the receipt.
    pub async fn execute(&self, request: &CortexRequest) -> Result<CortexResponse> {
        let started = Instant::now();
        let tier = request.budget.tier;
        self.metrics.record_request_accepted(tier);

        if let Err(e) = self.validate_budget(&request.budget) {
            self.metrics
                .record_rejection(RejectionReason::InvalidBudget);
            return Err(e);
        }

        debug!(
            model_id = %self.model.model_id(),
            tier = %request.budget.tier,
            min_loops = request.budget.min_loops,
            max_loops = request.budget.max_loops,
            "cortex worker executing request"
        );

        let mut response = match self.model.infer(request).await {
            Ok(r) => r,
            Err(e) => {
                self.metrics.record_rejection(RejectionReason::BackendError);
                return Err(e);
            }
        };

        // Recompute price from the backend's reported metadata.
        let cost = self.pricing.compute(
            response.metadata.input_tokens,
            response.metadata.output_tokens,
            response.metadata.loops_used,
            request.budget.attestation,
        );

        if cost > request.budget.max_cost_wei {
            warn!(
                cost,
                budget = request.budget.max_cost_wei,
                "cortex cost exceeded caller budget"
            );
            self.metrics.record_rejection(RejectionReason::CostExceeded);
            return Err(CortexError::CostExceeded {
                cost,
                budget: request.budget.max_cost_wei,
            });
        }
        response.price_wei = cost;

        // Generate TEE / ZK attestations as required by the caller's
        // budget. We build an intermediate preimage covering the receipt
        // fields that bind this specific execution (weights, commitments,
        // loops, tokens) so the quote/proof attests the same facts the
        // receipt signature does.
        let attestation_preimage = attestation_preimage(
            &response.receipt.model_id,
            &response.receipt.weights_hash,
            &response.receipt.runtime_hash,
            response.receipt.loops_used,
            &response.receipt.input_commitment,
            &response.receipt.output_commitment,
            response.receipt.tokens_in,
            response.receipt.tokens_out,
        );

        let (tee_quote, zk_proof) = match self
            .generate_attestations(request.budget.attestation, &attestation_preimage)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // WorkerRejected from generate_attestations means a provider
                // was not configured; anything else is backend-class.
                let reason = match &e {
                    CortexError::WorkerRejected(_) => RejectionReason::AttestationMissing,
                    _ => RejectionReason::BackendError,
                };
                self.metrics.record_rejection(reason);
                return Err(e);
            }
        };

        // Re-sign the receipt with the finalized price + fresh
        // attestations so auditors see the settlement-ready figures
        // rather than the placeholders emitted by the backend.
        let r = &response.receipt;
        let signed = match sign_receipt(
            &*self.signer,
            &r.model_id,
            r.weights_hash,
            r.runtime_hash,
            r.loops_requested,
            r.loops_used,
            r.input_commitment,
            r.output_commitment,
            &self.worker_did,
            self.worker_address,
            tee_quote,
            zk_proof,
            r.tokens_in,
            r.tokens_out,
            cost,
        ) {
            Ok(s) => s,
            Err(e) => {
                self.metrics.record_rejection(RejectionReason::BackendError);
                return Err(e);
            }
        };
        response.receipt = signed;

        let latency_ms = started.elapsed().as_secs_f64() * 1_000.0;
        self.metrics.record_success(
            tier,
            response.metadata.loops_used,
            cost,
            response.metadata.input_tokens,
            response.metadata.output_tokens,
            latency_ms,
            request.budget.attestation,
        );

        Ok(response)
    }

    /// Build the TEE quote and/or ZK proof required by the caller's
    /// attestation policy. Returns `(tee_quote, zk_proof)`.
    async fn generate_attestations(
        &self,
        req: AttestationRequirement,
        preimage: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        match req {
            AttestationRequirement::None => Ok((None, None)),
            AttestationRequirement::Tee => {
                let tee = self
                    .attestation
                    .tee
                    .as_ref()
                    .ok_or_else(|| {
                        CortexError::WorkerRejected(
                            "TEE attestation requested but no provider is configured".into(),
                        )
                    })?
                    .attest(preimage)
                    .await?;
                Ok((Some(tee), None))
            }
            AttestationRequirement::TeeAndZk => {
                let tee = self
                    .attestation
                    .tee
                    .as_ref()
                    .ok_or_else(|| {
                        CortexError::WorkerRejected(
                            "TEE attestation requested but no provider is configured".into(),
                        )
                    })?
                    .attest(preimage)
                    .await?;
                let zk = self
                    .attestation
                    .zk
                    .as_ref()
                    .ok_or_else(|| {
                        CortexError::WorkerRejected(
                            "ZK proof requested but no provider is configured".into(),
                        )
                    })?
                    .prove(preimage)
                    .await?;
                Ok((Some(tee), Some(zk)))
            }
        }
    }

    /// Exposes the worker's attestation suite (for tests).
    pub fn attestation_suite(&self) -> &AttestationSuite {
        &self.attestation
    }

    fn validate_budget(&self, budget: &ReasoningBudget) -> Result<()> {
        // RDT inference requires at least one recurrent pass. A budget of
        // max_loops == 0 would mean "do no work" — which is not a legitimate
        // inference request. Reject before we hit the backend.
        if budget.max_loops == 0 {
            return Err(CortexError::InvalidBudget(
                "max_loops must be > 0 for RDT inference".to_string(),
            ));
        }
        if budget.min_loops > budget.max_loops {
            return Err(CortexError::InvalidBudget(format!(
                "min_loops {} > max_loops {}",
                budget.min_loops, budget.max_loops
            )));
        }
        let family = self.model.family();
        if budget.max_loops > family.max_loops {
            return Err(CortexError::InvalidBudget(format!(
                "max_loops {} exceeds model max_loops {}",
                budget.max_loops, family.max_loops
            )));
        }
        if !family.supported_tiers.is_empty() && !family.supported_tiers.contains(&budget.tier) {
            return Err(CortexError::InvalidBudget(format!(
                "tier {:?} not supported by model",
                budget.tier
            )));
        }
        Ok(())
    }
}

/// Canonical bytes an attestation provider should sign/prove over.
///
/// Deliberately narrower than the receipt's signing preimage because
/// attestations are bound to the *execution* (what ran, on which weights,
/// producing what output) rather than to the *settlement* (price, worker
/// DID, timestamp). The worker then embeds the resulting quote/proof
/// into the final signed receipt.
fn attestation_preimage(
    model_id: &str,
    weights_hash: &tenzro_types::primitives::Hash,
    runtime_hash: &tenzro_types::primitives::Hash,
    loops_used: u32,
    input_commitment: &tenzro_types::primitives::Hash,
    output_commitment: &tenzro_types::primitives::Hash,
    tokens_in: u32,
    tokens_out: u32,
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct P<'a> {
        model_id: &'a str,
        weights_hash: &'a tenzro_types::primitives::Hash,
        runtime_hash: &'a tenzro_types::primitives::Hash,
        loops_used: u32,
        input_commitment: &'a tenzro_types::primitives::Hash,
        output_commitment: &'a tenzro_types::primitives::Hash,
        tokens_in: u32,
        tokens_out: u32,
    }
    serde_json::to_vec(&P {
        model_id,
        weights_hash,
        runtime_hash,
        loops_used,
        input_commitment,
        output_commitment,
        tokens_in,
        tokens_out,
    })
    .unwrap_or_default()
}
