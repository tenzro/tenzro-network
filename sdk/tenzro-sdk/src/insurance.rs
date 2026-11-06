//! The network insurance pool.
//!
//! The pool is funded by a governed share of fee revenue and by slashed agent
//! bonds. It pays the party a piece of evidence names, once, capped by
//! governance: a proven metered-charge dispute the meter's bond did not
//! cover, a frozen SLA verdict that judged a provider unavailable in an epoch
//! the claimant's stream paid it for, or a settlement-lock mismatch on an
//! attested route.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::{Value, json};
use std::sync::Arc;

/// Client for the insurance pool.
#[derive(Clone)]
pub struct InsuranceClient {
    rpc: Arc<RpcClient>,
}

impl InsuranceClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The pool's balance, history and claim cap.
    pub async fn pool(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getInsurancePoolBalance", json!({}))
            .await
    }

    /// Every paid claim, oldest first.
    pub async fn list_claims(&self) -> SdkResult<Value> {
        self.rpc.call("tenzro_listInsuranceClaims", json!({})).await
    }

    /// One paid claim, or null.
    pub async fn get_claim(&self, claim_id: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getInsuranceClaim", json!({ "claim_id": claim_id }))
            .await
    }
}
