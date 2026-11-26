//! Node queries and operations served by a node.

use crate::rpc::RpcClient;
use std::sync::Arc;

/// Client for the node's node RPC methods.
#[derive(Clone)]
pub struct NodeClient {
    rpc: Arc<RpcClient>,
}

impl NodeClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }
}

impl NodeClient {
    /// Calls `tenzro_verifyJurisdictionReceipt`: whether a jurisdiction
    /// receipt's signature holds in either form (`record`, or `identity_key`
    /// checked against the machine's key history on chain) and the key is
    /// registered.
    pub async fn verify_jurisdiction_receipt(
        &self,
        receipt: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyJurisdictionReceipt",
                serde_json::json!({ "receipt": receipt }),
            )
            .await
    }

    /// Calls `tenzro_autotuneDecisions`: autotune decisions.
    pub async fn autotune_decisions(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_autotuneDecisions", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_previewServe`: whether `model_id` would fit on this node
    /// before it is served: the weights, KV cache and headroom at the given
    /// quantization, context length and concurrency, with the advice to make
    /// it fit when it does not. Unset values default to the catalog's
    /// quantization and context length and 4 concurrent requests.
    pub async fn preview_serve(
        &self,
        model_id: &str,
        quant: Option<&str>,
        context_length: Option<u32>,
        max_concurrent: Option<u32>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let mut params = serde_json::json!({ "model_id": model_id });
        if let Some(q) = quant {
            params["quant"] = serde_json::json!(q);
        }
        if let Some(c) = context_length {
            params["context_length"] = serde_json::json!(c);
        }
        if let Some(m) = max_concurrent {
            params["max_concurrent"] = serde_json::json!(m);
        }
        self.rpc.call("tenzro_previewServe", params).await
    }

    /// Calls `tenzro_memoryBudget`: memory budget.
    pub async fn memory_budget(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_memoryBudget", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_trafficStats`: traffic stats.
    pub async fn traffic_stats(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_trafficStats", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_standbyQuote`: live operators holding `model_id` on
    /// standby in `jurisdiction`, cheapest first, with the account a
    /// reservation escrow must pay and the fee each one advertises.
    pub async fn standby_quote(
        &self,
        model_id: &str,
        jurisdiction: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_standbyQuote",
                serde_json::json!({ "model_id": model_id, "jurisdiction": jurisdiction }),
            )
            .await
    }

    /// Calls `tenzro_getAppTransportInfo`: where devices reach the node's app
    /// transport, and the certificates to pin, signed by the node.
    pub async fn app_transport_info(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getAppTransportInfo", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_getAppTransportUsage`: what the node's app transport carried
    /// for the signed-in caller, or for every identity to an administrator.
    pub async fn app_transport_usage(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getAppTransportUsage", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_nodeDidDocument`: node did document.
    pub async fn node_did_document(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_nodeDidDocument", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_nodeVisibility`: node visibility.
    pub async fn visibility(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_nodeVisibility", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_setNodeVisibility`: set node visibility.
    pub async fn set_visibility(
        &self,
        visibility: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_setNodeVisibility",
                serde_json::json!({ "visibility": visibility }),
            )
            .await
    }

    /// Calls `tenzro_shutdown` (operator only): the node stops gracefully.
    /// [`NodeClient::graceful_exit`] first steps a validator out of the
    /// rounds it leads.
    pub async fn shutdown(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_shutdown", serde_json::json!({}))
            .await
    }

    /// Calls `tenzro_validatorPublicKeys`: validator public keys.
    pub async fn validator_public_keys(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_validatorPublicKeys", serde_json::json!({}))
            .await
    }
}

impl NodeClient {
    /// Calls `tenzro_currentHeader`: current header.
    pub async fn current_header(&self) -> crate::error::SdkResult<CurrentHeader> {
        self.rpc
            .call("tenzro_currentHeader", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_fabricProfile`: fabric profile.
    pub async fn fabric_profile(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_fabricProfile", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_gossipStats`: gossip stats.
    pub async fn gossip_stats(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_gossipStats", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_gracefulExit`: graceful exit.
    pub async fn graceful_exit(
        &self,
        max_wait_secs: Option<u64>,
        force: Option<bool>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_gracefulExit",
                serde_json::json!({ "max_wait_secs": max_wait_secs, "force": force }),
            )
            .await
    }

    /// Calls `tenzro_listConditions` (operator only): what on this node is
    /// open and needs its operator's attention, the most severe first.
    pub async fn list_conditions(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listConditions", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_acknowledgeCondition` (operator only): acknowledge an
    /// open condition. `since` is as the list gives it; `reason` is 1 to 500
    /// characters.
    pub async fn acknowledge_condition(
        &self,
        id: &str,
        since: serde_json::Value,
        reason: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_acknowledgeCondition",
                serde_json::json!({ "id": id, "since": since, "reason": reason }),
            )
            .await
    }

    /// Calls `tenzro_submitApproval` (operator only): answer an open condition
    /// that asks. An approval carries the operator passkey's `assertion`
    /// (`credential_id`, `authenticator_data`, `client_data_json`,
    /// `signature`, base64url) over the condition's challenge; a decline needs
    /// none.
    pub async fn submit_approval(
        &self,
        condition_id: &str,
        approve: bool,
        assertion: Option<serde_json::Value>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_submitApproval",
                serde_json::json!({
                    "condition_id": condition_id,
                    "approve": approve,
                    "assertion": assertion,
                }),
            )
            .await
    }

    /// Calls `tenzro_installUpdate` (operator only): start the installed
    /// updater for the newest verified release this node knows of.
    pub async fn install_update(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_installUpdate", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_restartNode` (operator only): restart this node through
    /// the service that runs it; refused when no service runs it.
    pub async fn restart_node(
        &self,
        max_wait_secs: Option<u64>,
        force: Option<bool>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_restartNode",
                serde_json::json!({ "max_wait_secs": max_wait_secs, "force": force }),
            )
            .await
    }

    /// Calls `tenzro_iroh_resolveTenzroUri`: iroh resolve tenzro uri.
    pub async fn iroh_resolve_tenzro_uri(
        &self,
        tenzro_uri: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_iroh_resolveTenzroUri",
                serde_json::json!({ "tenzro_uri": tenzro_uri }),
            )
            .await
    }

    /// Calls `tenzro_livenessStats`: liveness stats.
    pub async fn liveness_stats(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_livenessStats", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_setDraining`: set draining.
    pub async fn set_draining(
        &self,
        draining: Option<bool>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_setDraining",
                serde_json::json!({ "draining": draining }),
            )
            .await
    }

    /// Calls `tenzro_cleanupIdleLocalModelServices`: cleanup idle local model services.
    pub async fn cleanup_idle_local_model_services(
        &self,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_cleanupIdleLocalModelServices",
                serde_json::Value::Null,
            )
            .await
    }

    /// Calls `tenzro_layerPipelineStatus`: this machine's part in a model served
    /// across the operator's machines (operator only).
    pub async fn layer_pipeline_status(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_layerPipelineStatus", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_produceSnapshot`: produce snapshot.
    pub async fn produce_snapshot(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_produceSnapshot", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_getStateRoot`: get state root.
    pub async fn get_state_root(&self) -> crate::error::SdkResult<StateRoot> {
        self.rpc
            .call("tenzro_getStateRoot", serde_json::Value::Null)
            .await
    }

    /// Calls `tenzro_getStateProof`: the value of (`namespace`, `key`, hex)
    /// and its proof, at `height` or the latest committed height. Ask at a
    /// certified checkpoint's state height to check the proof against that
    /// checkpoint's state root.
    pub async fn get_state_proof(
        &self,
        namespace: &str,
        key: &str,
        height: Option<u64>,
    ) -> crate::error::SdkResult<StateProof> {
        let mut params = serde_json::json!({ "namespace": namespace, "key": key });
        if let Some(height) = height {
            params["height"] = height.into();
        }
        self.rpc.call("tenzro_getStateProof", params).await
    }

    /// Calls `tenzro_getAccountContention`: get account contention.
    pub async fn get_account_contention(
        &self,
        address: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAccountContention",
                serde_json::json!({ "address": address }),
            )
            .await
    }
}

/// The node's current head and how old it is (`tenzro_currentHeader`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrentHeader {
    /// Head height.
    pub height: u64,
    /// Head block hash, 0x-prefixed hex (empty when the store has no block there).
    pub hash: String,
    /// Head block time, seconds.
    pub timestamp_secs: u64,
    /// The node's clock, seconds.
    pub now_secs: u64,
    /// Age of the head, seconds.
    pub age_secs: u64,
    /// `live`, `stale_yellow`, `stale_red`, `invalid` (older than 14 days) or `unknown`.
    pub tier: String,
}

/// The committed state root (`tenzro_getStateRoot`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateRoot {
    /// Height of the committed state.
    pub height: u64,
    /// The state root.
    pub state_root: String,
    /// The checkpoint that certifies this height, when one does.
    #[serde(default)]
    pub certified_by_checkpoint: Option<u64>,
}

/// A value in committed state with its proof against the state root
/// (`tenzro_getStateProof`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateProof {
    /// Height of the committed state.
    pub height: u64,
    /// The state root the proof is against.
    pub state_root: String,
    /// The node hash of the state trie at that height (`sha256`,
    /// `sha3_256`), the scheme the proof is checked under.
    pub state_trie_hash: String,
    /// The checkpoint that certifies this height, when one does.
    #[serde(default)]
    pub certified_by_checkpoint: Option<u64>,
    /// The state namespace.
    pub namespace: String,
    /// The key, hex.
    pub key: String,
    /// The value, hex, or `None` when the proof shows absence.
    #[serde(default)]
    pub value: Option<String>,
    /// The proof.
    pub proof: serde_json::Value,
}
