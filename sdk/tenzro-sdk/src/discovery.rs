//! Discovery + helper RPCs for the Universal Resolver, SIWT, KERI,
//! PKR, and Institution-identity modules.
//!
//! State-bearing dispatch (party allocation, mint apply)
//! lives on the individual adapter clients; the surface here gives wallets
//! and SDK consumers read access to the new modules.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use std::sync::Arc;

#[derive(Clone)]
pub struct DiscoveryClient {
    rpc: Arc<RpcClient>,
}

impl DiscoveryClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Decentralized MoE shard map for `model_id`: distinct providers
    /// holding each `(layer, expert)` for the model, per-expert
    /// replication factor, under-replicated experts, hot experts, and
    /// role counts (ExpertHolder / Router / Prefill / Decode / Replica).
    pub async fn moe_shard_map(&self, model_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeShardMap",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Build a dispatch plan for `model_id` given per-token top-k routing
    /// decisions. `routings` is `[{token_index, experts: [{layer,
    /// expert}, ...]}, ...]`. When `allow_cold` is false (default) the
    /// planner only picks warm holders.
    pub async fn moe_plan_dispatch(
        &self,
        model_id: &str,
        routings: serde_json::Value,
        allow_cold: bool,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moePlanDispatch",
                serde_json::json!({
                    "model_id": model_id,
                    "routings": routings,
                    "allow_cold": allow_cold,
                }),
            )
            .await
    }

    /// Current governance-tuned replication policy.
    pub async fn moe_replication_policy(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_moeReplicationPolicy", serde_json::json!([]))
            .await
    }

    /// Catalog-side MoE topology (`num_experts`, `experts_per_token`,
    /// `shared_experts`, `params_per_expert_x10`) for `model_id`.
    pub async fn moe_catalog_shape(&self, model_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeCatalogShape",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Resident experts and gates on this node's expert runtime, each with
    /// its residency tier (`Warm` in memory / `Cold` on disk) and byte
    /// footprint, plus the memory budget and whether GPU compute is active.
    pub async fn moe_expert_status(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_moeExpertStatus", serde_json::json!([]))
            .await
    }

    /// Slice a catalog checkpoint into per-expert blobs, optionally
    /// block-quantizing each projection, and publish them for holders to
    /// load. `quant` is a preset (`q4_k_m` / `q8_0` / `q4_k` / `q6_k`) or a
    /// per-projection object like `{"gate":"q4_k","up":"q4_k","down":"q6_k"}`;
    /// pass `serde_json::Value::Null` to publish dense f32 blobs. `experts`
    /// empty prepares every expert in the layer.
    pub async fn moe_prepare_experts(
        &self,
        model_id: &str,
        layer: u32,
        experts: Vec<u32>,
        include_gate: bool,
        quant: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        let mut params = serde_json::json!({
            "model_id": model_id,
            "layer": layer,
            "include_gate": include_gate,
        });
        if !experts.is_empty() {
            params["experts"] = serde_json::json!(experts);
        }
        if !quant.is_null() {
            params["quant"] = quant;
        }
        self.rpc.call("tenzro_moePrepareExperts", params).await
    }

    /// Run one distributed MoE layer forward on the node's expert runtime:
    /// gate `hidden` locally, fan the selected experts out to holders over
    /// the `tenzro/moe` transport, and combine the gate-weighted outputs.
    /// `hidden` is the row-major `[num_tokens, d_model]` activation, sent as
    /// `hidden_states` (little-endian f32, base64); the combined `outputs`
    /// come back in the same encoding (see [`decode_f32_base64`]).
    pub async fn moe_forward(
        &self,
        model_id: &str,
        layer: u32,
        d_model: u32,
        hidden: &[f32],
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeForward",
                serde_json::json!({
                    "model_id": model_id,
                    "layer": layer,
                    "d_model": d_model,
                    "hidden_states": encode_f32_base64(hidden),
                }),
            )
            .await
    }

    /// This node's hardware self-profile from the ggml device API: build
    /// commit, CPU arch, OS, devices, and the derived serving VRAM / backend /
    /// capability key.
    pub async fn node_profile(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_nodeProfile", serde_json::json!([]))
            .await
    }

    /// Create a cluster or change its members: derives the cluster DID from
    /// the operator DID and name, and returns the custody challenge request
    /// the operator's passkey answers and the digest each member machine
    /// accepts. `seq` is 1 for a new cluster and higher for every change.
    pub async fn derive_cluster_membership(
        &self,
        operator_did: &str,
        name: &str,
        seq: u64,
        members: &[String],
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_deriveClusterMembership",
                serde_json::json!({
                    "operator_did": operator_did,
                    "name": name,
                    "seq": seq,
                    "members": members,
                }),
            )
            .await
    }

    /// Submit a membership list the operator approved (through the custody
    /// challenge `challenge_id`) and every member accepted.
    pub async fn set_cluster_membership(
        &self,
        membership: serde_json::Value,
        challenge_id: &str,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_setClusterMembership",
                serde_json::json!({ "membership": membership, "challenge_id": challenge_id }),
            )
            .await
    }

    /// The verified members of `cluster_did` (this node's own cluster when
    /// `None`) and the cluster's aggregated reputation record.
    pub async fn cluster_members(&self, cluster_did: Option<&str>) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_clusterMembers",
                serde_json::json!({ "entry": cluster_did }),
            )
            .await
    }
}

impl DiscoveryClient {
    /// Calls `tenzro_acceptClusterMembership`: accept cluster membership.
    pub async fn accept_cluster_membership(
        &self,
        cluster_did: &str,
        seq: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_acceptClusterMembership",
                serde_json::json!({ "cluster_did": cluster_did, "seq": seq }),
            )
            .await
    }
}

/// Little-endian f32 values as base64, the encoding `tenzro_moeForward` takes
/// its `hidden_states` in.
pub fn encode_f32_base64(values: &[f32]) -> String {
    use base64::Engine as _;
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for v in values {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The f32 values a base64 string of little-endian f32s carries, as
/// `tenzro_moeForward` returns its `outputs`.
pub fn decode_f32_base64(s: &str) -> crate::error::SdkResult<Vec<f32>> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| crate::error::SdkError::InvalidParameter(format!("invalid base64: {e}")))?;
    if bytes.len() % 4 != 0 {
        return Err(crate::error::SdkError::InvalidParameter(
            "f32 payload length is not a multiple of 4 bytes".into(),
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}
