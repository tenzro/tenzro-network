//! Deterministic mock backend for tests and demos.
//!
//! Not for production. This backend echoes the input, reports `loops_used`
//! equal to the request's `max_loops`, and derives fake weights/runtime
//! hashes from the model id.

use async_trait::async_trait;
use tenzro_types::{
    cortex::{CortexMetadata, CortexModelFamily, CortexRequest, CortexResponse},
    primitives::{Address, Hash},
};

use crate::{
    error::Result,
    receipt::{canonicalize_input, canonicalize_output, hash_commitment, sign_receipt},
    traits::RecurrentDepthModel,
};

/// Mock recurrent-depth model.
pub struct MockCortexModel {
    model_id: String,
    family: CortexModelFamily,
    worker_did: String,
    worker_address: Address,
    signer: std::sync::Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
}

impl MockCortexModel {
    pub fn new(
        model_id: impl Into<String>,
        family: CortexModelFamily,
        worker_did: impl Into<String>,
        worker_address: Address,
        signer: std::sync::Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            family,
            worker_did: worker_did.into(),
            worker_address,
            signer,
        }
    }
}

#[async_trait]
impl RecurrentDepthModel for MockCortexModel {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn family(&self) -> &CortexModelFamily {
        &self.family
    }

    async fn infer(&self, request: &CortexRequest) -> Result<CortexResponse> {
        let output = request.input.clone();
        let loops_used = request.budget.max_loops;
        let tokens_in = (request.input.len() / 4).max(1) as u32;
        let tokens_out = (output.len() / 4).max(1) as u32;

        let weights_hash = hash_commitment(format!("weights:{}", self.model_id).as_bytes());
        let runtime_hash = hash_commitment(b"tenzro-cortex-mock@0.1");

        let input_commitment = hash_commitment(&canonicalize_input(request));
        let output_commitment = hash_commitment(&canonicalize_output(&output));

        let receipt = sign_receipt(
            &*self.signer,
            &self.model_id,
            weights_hash,
            runtime_hash,
            request.budget.max_loops,
            loops_used,
            input_commitment,
            output_commitment,
            &self.worker_did,
            self.worker_address,
            None,
            None,
            tokens_in,
            tokens_out,
            0,
        )?;

        let metadata = CortexMetadata {
            input_tokens: tokens_in,
            output_tokens: tokens_out,
            loops_used,
            latency_ms: 1,
            model_version: Some("mock-0.1".to_string()),
            finish_reason: Some("stop".to_string()),
            experts_activated: Some(self.family.experts_per_token),
        };

        let _ = Hash::zero(); // keep Hash in scope
        Ok(CortexResponse {
            request_id: request.request_id.clone(),
            response_id: uuid::Uuid::new_v4().to_string(),
            model_id: self.model_id.clone(),
            worker: self.worker_address,
            output,
            metadata,
            price_wei: 0,
            receipt,
            timestamp: tenzro_types::primitives::Timestamp::now(),
        })
    }
}
