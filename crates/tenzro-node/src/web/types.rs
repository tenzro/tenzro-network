use serde::{Deserialize, Serialize};
use tenzro_types::runtime::{
    ArtifactCompleteness, ArtifactMetadata, CapabilityResolution, ExecutionReceipt,
    NodeNetworkProfile, PlacementConstraints, RequiredExecution, RoutingPolicy, RuntimeSupport,
    TrustProfile, WorkerRole,
};

// === Common Response ===
#[derive(Serialize)]
pub struct VerificationResponse {
    pub valid: bool,
    pub details: serde_json::Value,
    pub verified_at: String,    // ISO 8601 timestamp
}

// === ZK Proof ===
#[derive(Deserialize)]
pub struct VerifyZkProofRequest {
    #[serde(alias = "proof")]
    pub proof_bytes: String,        // hex-encoded — bincode-encoded p3_uni_stark::Proof
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub public_inputs: Vec<String>, // hex-encoded field elements (4-byte LE KoalaBear chunks)
    /// Names the AIR to dispatch to (e.g. `"inference"`, `"settlement"`, `"identity"`).
    pub circuit_id: String,
}

/// Deserialize a field that can be either a single string or a Vec<String>
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Vec<String>, E> {
            Ok(vec![value])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error> {
            let mut vec = Vec::new();
            while let Some(val) = seq.next_element::<String>()? {
                vec.push(val);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

// === TEE Attestation ===
#[derive(Deserialize)]
pub struct VerifyTeeAttestationRequest {
    #[serde(alias = "provider")]
    pub vendor: String,             // "intel_tdx", "amd_sev_snp", "aws_nitro"
    #[serde(alias = "attestation")]
    pub report_data: String,        // hex-encoded raw report
    pub measurement: Option<String>, // expected measurement hash
    pub certificate_chain: Option<Vec<String>>, // PEM certs
}

// === Transaction ===
#[derive(Deserialize)]
pub struct VerifyTransactionRequest {
    pub tx_hash: String,           // hex-encoded
    pub signature: String,         // hex-encoded classical (Ed25519/Secp256k1) signature
    pub sender: String,            // hex-encoded classical public key
    pub data: Option<String>,      // hex-encoded tx data
    /// Hex-encoded ML-DSA-65 (FIPS 204) signature, 3309 bytes. Mandatory in
    /// the post-quantum hybrid window — every signed Tenzro transaction
    /// carries one (see `tenzro-types::transaction::SignedTransaction`).
    pub pq_signature: String,
    /// Hex-encoded ML-DSA-65 verifying key, 1952 bytes. Mandatory in the
    /// post-quantum hybrid window.
    pub pq_public_key: String,
}

// === Settlement ===
#[derive(Deserialize)]
pub struct VerifySettlementRequest {
    pub receipt_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,            // decimal string
    pub asset: String,
    pub proof_of_service: Option<String>, // hex-encoded proof
}

// === Inference ===
#[derive(Deserialize)]
pub struct VerifyInferenceRequest {
    pub model_id: String,
    pub input_hash: String,        // hex-encoded
    pub output_hash: String,       // hex-encoded
    pub provider: String,          // provider address
    pub tee_attestation: Option<String>, // hex-encoded attestation
    pub zk_proof: Option<String>,  // hex-encoded proof
}

// === Status ===
#[derive(Serialize)]
pub struct NodeStatusResponse {
    pub node_state: String,
    pub roles: Vec<String>,
    pub health: String,
    pub block_height: u64,
    pub peer_count: u64,
    pub uptime_secs: u64,
    pub ready: bool,
    pub status_message: String,
}

// === Health ===
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub verification_service: bool,
}

// === Readiness (for K8s readinessProbe / load-balancer gating) ===
//
// Distinct from `/health`: `/health` is liveness (is the process alive
// and not crash-looping), `/ready` is "is this pod safe to receive
// production traffic." A node that has just finished pod-init but is
// still bootstrapping consensus state passes liveness but must fail
// readiness — otherwise the K8s service routes traffic to it and
// clients see stale state.
//
// Ready iff:
//   * `block_height >= network_median - block_lag_tolerance` (default 5)
//   * `high_qc_view  >= network_high_qc - view_lag_tolerance`  (default 2)
//   * peer_count >= 1 (at least one other peer to gossip with)
//
// When `network_median` is unknown (no fresh peer status), the node
// reports Ready iff peer_count >= 1 — the alternative would be
// "always not-ready on a fresh cluster," which prevents bootstrap.
#[derive(Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub block_height: u64,
    pub network_tip: Option<u64>,
    pub block_lag: Option<u64>,
    pub high_qc_view: u64,
    pub peer_count: u64,
    pub reason: String,
}

// === Faucet ===
#[derive(Deserialize)]
pub struct FaucetRequest {
    pub address: String,   // hex-encoded recipient address (with or without 0x prefix)
}

#[derive(Serialize)]
pub struct FaucetResponse {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub amount: String,       // TNZO amount dispensed
    pub message: String,
}

// === Chat ===
#[derive(Deserialize)]
pub struct ChatRequest {
    pub model: String,           // model ID or name
    pub messages: Vec<ChatMessage>,
    pub stream: Option<bool>,    // default true
    pub max_tokens: Option<u64>,
    pub temperature: Option<f64>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ChatMessage {
    pub role: String,      // "system", "user", "assistant"
    pub content: String,
}

#[derive(Serialize)]
pub struct ChatCompletionChunk {
    pub id: String,
    pub object: String,           // "chat.completion.chunk"
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
}

#[derive(Serialize)]
pub struct ChatChoice {
    pub index: u32,
    pub delta: ChatDelta,
    pub finish_reason: Option<String>,
}

#[derive(Serialize)]
pub struct ChatDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,           // "chat.completion"
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
    pub usage: ChatUsage,
}

#[derive(Serialize)]
pub struct ChatCompletionChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Serialize)]
pub struct ChatUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

// === RFC-0007: Adaptive Execution — HTTP types ===

// POST /execution/resolve
#[derive(Deserialize)]
pub struct ResolveExecutionRequest {
    pub model_id: String,
    #[serde(default)]
    pub required_execution: Option<RequiredExecution>,
    #[serde(default)]
    pub routing_policy: Option<RoutingPolicy>,
    #[serde(default)]
    pub placement_constraints: Option<PlacementConstraints>,
}

#[derive(Serialize)]
pub struct ResolveExecutionResponse {
    pub resolution: CapabilityResolution,
    pub resolved_at: String,
}

// GET /models/:model_id/artifacts
#[derive(Serialize)]
pub struct ModelArtifactsResponse {
    pub model_id: String,
    pub artifacts: Vec<ArtifactMetadata>,
    pub artifact_completeness: ArtifactCompleteness,
}

// GET /providers
#[derive(Serialize)]
pub struct ProviderRuntimeInfo {
    pub peer_id: String,
    pub provider_address: String,
    pub provider_type: String,
    pub served_models: Vec<String>,
    pub capabilities: Vec<String>,
    pub rpc_endpoint: String,
    pub status: String,
    pub runtime_support: RuntimeSupport,
    pub network_profile: NodeNetworkProfile,
    pub trust_profile: TrustProfile,
    pub worker_roles: Vec<WorkerRole>,
    pub is_local: bool,
}

// GET /execution/receipts/:receipt_id
#[derive(Serialize)]
pub struct ExecutionReceiptResponse {
    pub receipt: Option<ExecutionReceipt>,
    pub found: bool,
}
