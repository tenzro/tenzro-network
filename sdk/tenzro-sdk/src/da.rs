//! Da queries and operations served by a node.

use crate::rpc::RpcClient;
use std::sync::Arc;

/// Client for the node's da RPC methods.
#[derive(Clone)]
pub struct DaClient {
    rpc: Arc<RpcClient>,
}

impl DaClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }
}

impl DaClient {
    /// Calls `tenzro_daAvailability`: da availability.
    pub async fn availability(
        &self,
        address: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_daAvailability",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// Calls `tenzro_daChallenge`: da challenge.
    pub async fn challenge(
        &self,
        commitment: &str,
        target_index: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_daChallenge",
                serde_json::json!({ "commitment": commitment, "target_index": target_index }),
            )
            .await
    }

    /// Calls `tenzro_daCommittee`: da committee.
    pub async fn committee(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_daCommittee", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_daListBlobs`: da list blobs.
    pub async fn list_blobs(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_daListBlobs", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_daListChallenges`: da list challenges.
    pub async fn list_challenges(
        &self,
        limit: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_daListChallenges",
                serde_json::json!({ "limit": limit }),
            )
            .await
    }
}

impl DaClient {
    /// A data-availability object as chain state records it, with its expiry.
    pub async fn da_object(&self, commitment: &str) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getDaObject",
                serde_json::json!({ "commitment": commitment }),
            )
            .await
    }

    /// Data-availability retention per class, live and expired totals.
    pub async fn da_retention(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getDaRetention", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_getDaBackends`: get da backends.
    pub async fn get_da_backends(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getDaBackends", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_verifyDaPointer`: verify da pointer.
    pub async fn verify_da_pointer(
        &self,
        pointer: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyDaPointer",
                serde_json::json!({ "pointer": pointer }),
            )
            .await
    }
}
