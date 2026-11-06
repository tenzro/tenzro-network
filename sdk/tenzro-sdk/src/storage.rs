//! Decentralized storage client for Tenzro Network.
//!
//! A node started with the `storage` role spawns a storage-provider runtime:
//! it erasure-codes objects, publishes their shards over the content-addressed
//! transport. A renter pays for keeping an object through a storage compute
//! claim that commits the object's descriptor digest; each hour the claim pays
//! the provider only if validators found its bond available, which requires a
//! possession proof of the object.
//!
//! These calls target the provider node directly; they succeed only when that
//! node is serving the storage role.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Storage-provider client.
pub struct StorageClient {
    rpc: Arc<RpcClient>,
}

impl StorageClient {
    /// Creates a new storage client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Stores an object owned by `owner_did`: erasure-codes `data` under
    /// `data_shards`+`parity_shards` and publishes the shards over the
    /// transport. Only `owner_did` may retrieve it. `signer` holds the key
    /// `owner_did` resolves to and signs the request's envelope. Returns the
    /// stored size and shard layout.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # async fn run(signer: &dyn tenzro_sdk::wallet::HybridSigner) -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let storage = client.storage();
    /// let stored = storage
    ///     .store_object("photo-1", "0xowner", b"...bytes...", 4, 2, "did:tenzro:human:alice", signer)
    ///     .await?;
    /// println!("stored {} bytes", stored.size_bytes);
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn store_object(
        &self,
        object_id: &str,
        owner: &str,
        data: &[u8],
        data_shards: u32,
        parity_shards: u32,
        owner_did: &str,
        signer: &dyn crate::wallet::HybridSigner,
    ) -> SdkResult<StoredObject> {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let params = crate::did_envelope::with_request_envelope(
            signer,
            owner_did,
            "tenzro_storageStoreObject",
            json!({
                "object_id": object_id,
                "owner": owner,
                "data": data_b64,
                "data_shards": data_shards,
                "parity_shards": parity_shards,
                "owner_did": owner_did,
            }),
        )
        .await?;
        let result = self.rpc.call("tenzro_storageStoreObject", params).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse stored object: {}", e)))
    }

    /// Rebuilds an object from its shards for `reader_did` and returns its
    /// bytes. The object's access policy must admit `reader_did`; `signer`
    /// holds the key it resolves to and signs the request's envelope.
    pub async fn retrieve_object(
        &self,
        object_id: &str,
        reader_did: &str,
        signer: &dyn crate::wallet::HybridSigner,
    ) -> SdkResult<Vec<u8>> {
        let params = crate::did_envelope::with_request_envelope(
            signer,
            reader_did,
            "tenzro_storageRetrieveObject",
            json!({ "object_id": object_id }),
        )
        .await?;
        let result: serde_json::Value = self
            .rpc
            .call("tenzro_storageRetrieveObject", params)
            .await?;
        let data = result
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SdkError::RpcError("the node returned no data".to_string()))?;
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| SdkError::RpcError(format!("the node returned invalid base64: {e}")))
    }

    /// Sets the provider's fixed byte-epoch rate, in wei, what deals opened
    /// from now on pay.
    pub async fn set_fixed_rate(&self, rate: u128) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_storageSetPricing",
                json!([{ "mode": "fixed", "rate": rate.to_string() }]),
            )
            .await
    }

    /// Returns this node's storage-provider status (effective rate, object count).
    pub async fn status(&self) -> SdkResult<StorageStatus> {
        let result = self.rpc.call("tenzro_storageStatus", json!([])).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse storage status: {}", e)))
    }
}

/// Result of [`StorageClient::store_object`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    /// Logical object id.
    pub object_id: String,
    /// Stored payload size in bytes.
    pub size_bytes: usize,
    /// Number of data shards.
    pub data_shards: usize,
    /// Number of parity shards.
    pub parity_shards: usize,
    /// Hex SHA-256 of the object descriptor: what a storage compute claim
    /// commits to pay for keeping the object.
    pub descriptor_digest: Option<String>,
}

/// Storage-provider status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    /// Whether this node is serving the storage role.
    #[serde(default)]
    pub is_storage_provider: bool,
    /// Effective byte-epoch rate in wei (string-encoded).
    #[serde(default)]
    pub effective_rate_wei: String,
    /// Number of objects this provider holds.
    #[serde(default)]
    pub object_count: u64,
}
