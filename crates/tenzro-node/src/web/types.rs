use serde::{Deserialize, Serialize};
use tenzro_types::runtime::{
    ArtifactCompleteness, ArtifactMetadata, CapabilityResolution, NodeNetworkProfile,
    PlacementConstraints, RequiredExecution, RoutingPolicy, RuntimeSupport, TrustProfile,
    WorkerRole,
};

// === Common Response ===
#[derive(Serialize)]
pub struct VerificationResponse {
    pub valid: bool,
    pub details: serde_json::Value,
    pub verified_at: String, // ISO 8601 timestamp
}

// === ZK Proof ===
#[derive(Deserialize)]
pub struct VerifyZkProofRequest {
    pub proof_bytes: String, // hex-encoded — bincode-encoded p3_uni_stark::Proof
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub public_inputs: Vec<String>, // hex-encoded [digest, binding], 32 bytes each
    /// The circuit (`"identity"` or `"settlement"`).
    pub circuit_id: String,
    /// The proof system the proof bytes belong to
    /// (`"koala-bear-sha256-fri"`, `"goldilocks-blake3-fri"` or
    /// `"halo2-ipa-pasta"`).
    pub system: String,
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

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
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
    pub vendor: String,              // "intel_tdx", "amd_sev_snp", "aws_nitro"
    pub report_data: String,         // hex-encoded raw report
    pub measurement: Option<String>, // expected measurement hash
    pub certificate_chain: Option<Vec<String>>, // PEM certs
    /// Hex of the user data the report must carry: the verifier's challenge,
    /// packed for the vendor.
    pub expected_user_data: String,
    /// Vendor collateral carried with the evidence (for TDX, the DCAP
    /// collateral under `tdx_collateral`).
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

// === Transaction ===
#[derive(Deserialize)]
pub struct VerifyTransactionRequest {
    /// Hex-encoded transaction hash (the signed message).
    pub tx_hash: String,
    /// The sender's hardware P-256 key, x || y (64 bytes hex).
    pub sender: String,
    /// The composite signature: `{classical: {form, ...}, pq?}`.
    pub signature: tenzro_crypto::composite::CompositeSignature,
    /// The ML-DSA-65 key the sender's account enrolled (1952 bytes hex), when
    /// it enrolled one; the ML-DSA-65 leg is then required.
    pub ml_dsa_public_key: Option<String>,
    /// Hex-encoded transaction data.
    pub data: Option<String>,
}

// === Settlement ===
#[derive(Deserialize)]
pub struct VerifySettlementRequest {
    pub receipt_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: String, // decimal string
    pub asset: String,
    pub proof_of_service: Option<String>, // hex-encoded proof
}

// === Inference ===
#[derive(Deserialize)]
pub struct VerifyInferenceRequest {
    pub model_id: String,
    pub input_hash: String,              // hex-encoded
    pub output_hash: String,             // hex-encoded
    pub provider: String,                // provider address
    pub tee_attestation: Option<String>, // hex-encoded attestation
    pub zk_proof: Option<String>,        // hex-encoded proof
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
    /// Why the status is not healthy: one `subsystem: reason` per degraded
    /// or unhealthy subsystem. Absent when healthy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
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
//   * on a validator, `certified_height >= block_height - certification_lag_tolerance`
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
    pub certified_height: u64,
    pub peer_count: u64,
    pub reason: String,
}

// === Adaptive execution: HTTP types ===

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
    pub iroh_endpoint_id: String,
    pub provider_address: String,
    pub provider_type: String,
    pub served_models: Vec<String>,
    pub capabilities: Vec<String>,
    pub status: String,
    pub runtime_support: RuntimeSupport,
    pub network_profile: NodeNetworkProfile,
    pub trust_profile: TrustProfile,
    pub worker_roles: Vec<WorkerRole>,
    pub is_local: bool,
}
