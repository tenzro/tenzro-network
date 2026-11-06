//! Proof-of-Reserve client: submit and read the reserve attestation backing
//! a tokenized asset. A reserve-backed token mints with its attestor's
//! attestation inside a signed `Token` transaction
//! ([`crate::typed_tx`]).

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::Value;
use std::sync::Arc;

/// Reserve client.
#[derive(Clone)]
pub struct ReserveClient {
    rpc: Arc<RpcClient>,
}

impl ReserveClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Submit a 1:1-backed reserve attestation for a tokenized asset.
    pub async fn submit_reserve_attestation(&self, attestation: Value) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_submitReserveAttestation",
                serde_json::json!({ "attestation": attestation }),
            )
            .await
    }

    /// Read the latest reserve attestation for a tokenized asset.
    pub async fn get_reserve(&self, asset_id: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getReserve",
                serde_json::json!({ "asset_id": asset_id }),
            )
            .await
    }
}

impl ReserveClient {
    /// Calls `tenzro_buildReserveAttestationFromPor`: build reserve attestation from por.
    pub async fn build_reserve_attestation_from_por(
        &self,
        asset_id: &str,
        attestor_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_buildReserveAttestationFromPor",
                serde_json::json!({ "asset_id": asset_id, "attestor_did": attestor_did }),
            )
            .await
    }
}
