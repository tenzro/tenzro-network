//! Network duties and evidence checks.
//!
//! A duty is work the chain pays the first prover for: a route's
//! settlement-lock reconciliation each epoch, the install of a voided agent
//! grant on another chain. Its reward sits in a keyless vault and the
//! transaction proving the work pays it. An evidence check answers what an
//! evidence item proves against chain state, for applications that pay on
//! delivery.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::{Value, json};
use std::sync::Arc;

/// Client for network duties and evidence checks.
#[derive(Clone)]
pub struct DutyClient {
    rpc: Arc<RpcClient>,
}

impl DutyClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Every open duty, oldest first.
    pub async fn list(&self) -> SdkResult<Value> {
        self.rpc.call("tenzro_listDuties", json!({})).await
    }

    /// One duty by id (32-byte hex), or null.
    pub async fn get(&self, duty_id: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getDuty", json!({ "duty_id": duty_id }))
            .await
    }

    /// What each evidence item proves against chain state. `items` is the
    /// list of evidence items in the node's JSON form.
    pub async fn verify_evidence(&self, items: Value) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_verifyEvidence", json!({ "items": items }))
            .await
    }
}
