//! Decentralized storage client for Tenzro Network.
//!
//! A node started with the `storage` role spawns a storage-provider runtime:
//! it erasure-codes objects and publishes their shards over the
//! content-addressed transport. The provider prices storage at a fixed rate
//! per byte-epoch that never follows demand ([`StorageClient::set_fixed_rate`]).
//!
//! Storage is held to proofs of retrievability: a renter pays for keeping an
//! object through a storage compute claim that commits the object's
//! descriptor digest ([`StoredObject::descriptor_digest`]), and each hour the
//! claim pays the provider only if validators found its bond available, which
//! requires a possession proof of the object. The claim is written and bought
//! with the `ComputeClaim` transaction and read through
//! [`crate::compute::ComputeClient::get_claim`], where `storage_descriptor`
//! names the object.
//!
//! These calls target the provider node directly; they succeed only when that
//! node is serving the storage role.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// One operator a buyer may read an object from, with the voucher that pays
/// that operator alone.
pub struct ReadOperator {
    /// A name the buyer recognises the operator by, such as its endpoint.
    pub name: String,
    pub client: StorageClient,
    /// A channel voucher to this operator's node, for an object stored under
    /// a priced class.
    pub voucher: Option<serde_json::Value>,
}

/// A read some operator served.
#[derive(Debug)]
pub struct ServedRead {
    /// The operator that served it, and so the only one whose voucher is
    /// spent.
    pub operator: String,
    pub data: Vec<u8>,
    /// The operators tried first, each with why it did not serve.
    pub down: Vec<(String, String)>,
}

/// Reads `object_id` from the first of `operators` that serves it, in the
/// order given. An operator that is down, or that cannot rebuild the object,
/// is passed over without its voucher being sent anywhere else, so the read
/// is metered and paid to the operator that served it. A refusal because
/// `reader_did` may not read the object ends the read: another operator
/// holds the same policy.
pub async fn retrieve_with_failover(
    operators: &[ReadOperator],
    object_id: &str,
    reader_did: &str,
    signer: &dyn crate::wallet::HybridSigner,
) -> SdkResult<ServedRead> {
    let mut down = Vec::new();
    for op in operators {
        match op
            .client
            .retrieve_object(object_id, reader_did, op.voucher.as_ref(), signer)
            .await
        {
            Ok(data) => {
                return Ok(ServedRead {
                    operator: op.name.clone(),
                    data,
                    down,
                });
            }
            Err(e) if e.node_error().is_some_and(|n| n.code == -32001) => return Err(e),
            Err(e) => down.push((op.name.clone(), e.to_string())),
        }
    }
    Err(SdkError::RpcError(format!(
        "no operator served {object_id}: {}",
        down.iter()
            .map(|(n, why)| format!("{n}: {why}"))
            .collect::<Vec<_>>()
            .join("; ")
    )))
}

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
    /// stored size and shard layout. `class` (`hot`, `warm` or `cold`) is the
    /// storage class the object is bought under, which prices its reads.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # async fn run(signer: &dyn tenzro_sdk::wallet::HybridSigner) -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let storage = client.storage();
    /// let stored = storage
    ///     .store_object("photo-1", "0xowner", b"...bytes...", 4, 2, None, "did:tenzro:human:alice", None, signer)
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
        class: Option<&str>,
        owner_did: &str,
        placement: Option<&Placement>,
        signer: &dyn crate::wallet::HybridSigner,
    ) -> SdkResult<StoredObject> {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let mut request = json!({
            "object_id": object_id,
            "owner": owner,
            "data": data_b64,
            "data_shards": data_shards,
            "parity_shards": parity_shards,
            "owner_did": owner_did,
        });
        if let Some(p) = placement {
            request["placement"] = json!(p);
        }
        if let Some(class) = class {
            request["class"] = json!(class);
        }
        let params = crate::did_envelope::with_request_envelope(
            signer,
            owner_did,
            "tenzro_storageStoreObject",
            request,
        )
        .await?;
        let result = self.rpc.call("tenzro_storageStoreObject", params).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse stored object: {}", e)))
    }

    /// Rebuilds an object from its shards for `reader_did` and returns its
    /// bytes. The object's access policy must admit `reader_did`; `signer`
    /// holds the key it resolves to and signs the request's envelope. An
    /// object stored under a priced class is paid with `voucher`, a channel
    /// voucher to the node covering the read.
    pub async fn retrieve_object(
        &self,
        object_id: &str,
        reader_did: &str,
        voucher: Option<&serde_json::Value>,
        signer: &dyn crate::wallet::HybridSigner,
    ) -> SdkResult<Vec<u8>> {
        let mut request = json!({ "object_id": object_id });
        if let Some(voucher) = voucher {
            request["voucher"] = voucher.clone();
        }
        let params = crate::did_envelope::with_request_envelope(
            signer,
            reader_did,
            "tenzro_storageRetrieveObject",
            request,
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

    /// This node's signed receipt for the shards of `object_id` it holds
    /// now under a placement constraint, or `null` when it holds none.
    pub async fn holding_receipt(&self, object_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getStorageHoldingReceipt",
                json!([{ "object_id": object_id }]),
            )
            .await
    }

    /// Sets the byte-epoch rate and what reading each class costs, wei per
    /// gibibyte read (`hot`, `warm`, `cold`), each under its governed ceiling.
    pub async fn set_read_rates(
        &self,
        rate: u128,
        hot: u128,
        warm: u128,
        cold: u128,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_storageSetPricing",
                json!([{
                    "mode": "fixed",
                    "rate": rate.to_string(),
                    "read_rates": { "hot": hot.to_string(), "warm": warm.to_string(), "cold": cold.to_string() },
                }]),
            )
            .await
    }

    /// The storage providers the node has heard announce, best record first,
    /// each with its standing read from consensus state and whether any SLA
    /// verdict judged it.
    pub async fn providers(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listStorageProviders", json!({}))
            .await
    }

    /// Returns this node's storage-provider status (effective rate, read rates, object count).
    pub async fn status(&self) -> SdkResult<StorageStatus> {
        let result = self.rpc.call("tenzro_storageStatus", json!([])).await?;
        serde_json::from_value(result)
            .map_err(|e| SdkError::RpcError(format!("Failed to parse storage status: {}", e)))
    }
}

/// Where an object's shards may be held: in one of `jurisdiction` (country
/// codes, by the region each holder declares), by one of `operators`
/// (provider accounts, hex), or both. The storing node must itself be
/// inside it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Placement {
    pub jurisdiction: Vec<String>,
    pub operators: Vec<String>,
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
