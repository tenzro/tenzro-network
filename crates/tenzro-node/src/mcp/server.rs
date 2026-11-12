use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
    Json, ServerHandler, handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::error::Result as NodeResult;
use crate::node::TenzroNode;
use crate::web::handlers::WebState;
use tenzro_types::primitives::Address;

use super::tool_types_access::*;
use super::tool_types_chain::*;
use super::tool_types_models::*;
use super::tool_types_payments::*;

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IdentityDidParams {
    /// The identity whose devices to inspect, e.g. `did:tenzro:human:…`.
    pub identity_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MirrorSettlementParams {
    /// The interaction record of the settlement to mirror.
    pub interaction: PayInteractionProvenance,
    /// Chains to mirror onto — CAIP-2 ids (`eip155:8453`) or adapter chain
    /// names (`base`). Both are accepted.
    pub chains: Vec<String>,
    /// Write only the digest rather than the full settlement bytes. Cheaper,
    /// but the record then does not survive the Tenzro Ledger losing state.
    #[serde(default)]
    pub digest_only: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBalanceParams {
    #[schemars(description = "Hex-encoded account address (with or without 0x prefix)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBlockParams {
    #[schemars(description = "Block height to retrieve")]
    pub height: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBlockRangeParams {
    #[schemars(description = "First block height to fetch (inclusive)")]
    pub start_height: u64,
    #[schemars(description = "Last block height to fetch (inclusive)")]
    pub end_height: u64,
    #[schemars(description = "Maximum number of blocks to return (default 64, capped at 256)")]
    pub max_results: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetFeeMarketParams {
    #[schemars(
        description = "Number of recent blocks to summarize in fee history (1..=1024, default 10)"
    )]
    pub blocks: Option<u64>,
    #[schemars(
        description = "Tip percentiles to request, e.g. [25.0, 50.0, 75.0]; pass [] or omit to skip percentile sampling"
    )]
    pub reward_percentiles: Option<Vec<f64>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterIdentityParams {
    #[schemars(description = "Identity type: 'human' or 'machine'")]
    pub identity_type: String,
    #[schemars(description = "Display name for the identity")]
    pub display_name: String,
    #[schemars(
        description = "Controller DID (required for machine identities, e.g. did:tenzro:human:uuid)"
    )]
    pub controller_did: Option<String>,
    #[schemars(
        description = "Hex public key of the key that owns this identity — the passkey \
                       (human) or the TPM / Secure Enclave key (machine). Required: this \
                       node does not generate keys on your behalf."
    )]
    pub public_key: String,
    #[schemars(
        description = "Hex passkey credential id (human identities only). An autonomous \
                       machine has no passkey and omits this."
    )]
    pub credential_id: Option<String>,
    #[schemars(
        description = "Hex DID envelope from the controller DID, bound to method \
                       tenzro_registerIdentity and these parameters. Required for machine \
                       identities: the machine draws on its controller's admission quota \
                       and delegation scope, so the controller has to sign for it."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_envelope: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveDidParams {
    #[schemars(
        description = "DID to resolve (e.g. did:tenzro:human:uuid or did:tenzro:machine:controller:uuid)"
    )]
    pub did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTransactionParams {
    #[schemars(description = "Hex-encoded transaction hash (with or without 0x prefix)")]
    pub tx_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyZkProofParams {
    #[schemars(
        description = "Proof legs: [{\"system\": \"koala-bear-sha256-fri\" | \"goldilocks-blake3-fri\" | \"halo2-ipa-pasta\", \"proof\": \"0x...\"}]"
    )]
    pub proofs: Vec<ZkProofLegInput>,
    #[schemars(description = "Public inputs [digest, binding], each 32-byte hex")]
    pub public_inputs: Vec<String>,
    #[schemars(description = "Circuit identifier — 'identity' or 'settlement'")]
    pub circuit_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetZkAttestationParams {
    #[schemars(description = "Hex-encoded 32-byte ZK commitment hash (with or without 0x prefix)")]
    pub commitment: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyVrfProofParams {
    #[schemars(description = "Hex-encoded 32-byte VRF public key (Edwards25519 compressed point)")]
    pub pubkey: String,
    #[schemars(
        description = "Hex-encoded 80-byte VRF proof: Gamma(32) || c(16) || s(32) per RFC 9381"
    )]
    pub proof: String,
    #[schemars(
        description = "Hex-encoded input message (alpha). Public inputs like block hash, request ID, or NFT mint nonce"
    )]
    pub alpha: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListModelsParams {
    #[schemars(description = "Optional modality filter (text, image, audio, video, ...)")]
    pub modality: Option<String>,
    #[schemars(
        description = "true lists every model this node holds, of every type (chat, vision, embedding, forecast, segmentation, detection, audio, video, media, speech), with its engine, visibility, access and loaded/serving state"
    )]
    pub loaded: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSealedModelParams {
    #[schemars(description = "Model ID of the sealed-model manifest to fetch")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetModelProvenanceParams {
    #[schemars(
        description = "Model name (a Hub repository such as `owner/name`, or a model id outside the catalog) whose manifests to fetch"
    )]
    #[serde(default)]
    pub name: Option<String>,
    #[schemars(
        description = "Manifest root (hex) to fetch instead of every manifest under a name"
    )]
    #[serde(default)]
    pub root: Option<String>,
    #[schemars(
        description = "A file path in the model; each manifest then carries that file's entry and Merkle inclusion proof"
    )]
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListCatalogParams {
    #[schemars(
        description = "Only entries of this engine family: gguf, rerank, embed, onnx-vision, onnx-forecast, onnx-text-embedding, onnx-segmentation, onnx-text-segmentation, onnx-detection, onnx-audio, tts, onnx-video or media-gen"
    )]
    #[serde(default)]
    pub engine: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCatalogEntryParams {
    #[schemars(description = "Model id")]
    pub model: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RouteByIntentParams {
    #[schemars(
        description = "Use case: 'chat', 'code', 'reasoning', 'research', 'summarize', 'extract', or 'embed'. Maps to a modality and biases quality tiering"
    )]
    pub use_case: String,
    #[schemars(
        description = "Per-request cost cap in smallest TNZO unit. Accepts number or decimal string. Absent = no per-request cap. Optional",
        with = "Option<String>"
    )]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub budget: Option<u128>,
    #[schemars(
        description = "Cost-quality knob in [0.0, 1.0]: 0.0 = cheapest acceptable, 1.0 = strongest. Optional"
    )]
    pub optimize: Option<f64>,
    #[schemars(description = "Reject any model below this tier: 'cheap' or 'strong'. Optional")]
    pub quality_floor: Option<String>,
    #[schemars(description = "Estimated input tokens for cost estimation. Optional")]
    pub est_input_tokens: Option<u64>,
    #[schemars(description = "Estimated output tokens for cost estimation. Optional")]
    pub est_output_tokens: Option<u64>,
    #[schemars(
        description = "Payer DID. When set, the per-DID rolling-window budget gate is enforced. Optional"
    )]
    pub payer_did: Option<String>,
    #[schemars(
        description = "Payer wallet address (hex). When set, the payer's on-chain TNZO balance is a hard ceiling: unaffordable models are dropped. Optional"
    )]
    pub payer_address: Option<String>,
    #[schemars(
        description = "The text the model would answer. Used only to place the request in a difficulty cluster so selection accounts for how hard the prompt is; it is not sent to any provider. Without it the decision rests on declared metadata alone. Optional"
    )]
    pub prompt: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChatByIntentParams {
    #[schemars(
        description = "Use case: 'chat', 'code', 'reasoning', 'research', 'summarize', 'extract', or 'embed'. Maps to a modality and biases quality tiering"
    )]
    pub use_case: String,
    #[schemars(
        description = "The user message (simple single-turn shape). Provide this or 'messages'"
    )]
    pub message: Option<String>,
    #[schemars(
        description = "Chat turns as [{role, content}] (rich multi-turn shape). The last user turn is what difficulty scoring reads. Provide this or 'message'"
    )]
    pub messages: Option<Vec<ChatMessageParam>>,
    #[schemars(
        description = "Per-request cost cap in smallest TNZO unit. Accepts number or decimal string. Absent = no per-request cap. Optional",
        with = "Option<String>"
    )]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub budget: Option<u128>,
    #[schemars(
        description = "Cost-quality knob in [0.0, 1.0]: 0.0 = cheapest acceptable, 1.0 = strongest. Optional"
    )]
    pub optimize: Option<f64>,
    #[schemars(description = "Reject any model below this tier: 'cheap' or 'strong'. Optional")]
    pub quality_floor: Option<String>,
    #[schemars(description = "Estimated input tokens for cost estimation. Optional")]
    pub est_input_tokens: Option<u64>,
    #[schemars(description = "Estimated output tokens for cost estimation. Optional")]
    pub est_output_tokens: Option<u64>,
    #[schemars(
        description = "Payer DID. When set, the per-DID rolling-window budget gate is enforced. Optional"
    )]
    pub payer_did: Option<String>,
    #[schemars(
        description = "Payer wallet address (hex). When set, the payer's on-chain TNZO balance is a hard ceiling and the call bills to it. Optional"
    )]
    pub payer_address: Option<String>,
    #[schemars(description = "Temperature (0.0-2.0). Optional")]
    pub temperature: Option<f64>,
    #[schemars(description = "Maximum tokens to generate. Optional")]
    pub max_tokens: Option<u32>,
    #[schemars(
        description = "Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes and/or bloc tokens (e.g. 'DE,EU'), case-insensitive. The serving node must declare a matching attestation-bound locality claim or the request is refused. Optional"
    )]
    pub jurisdiction: Option<String>,
    #[schemars(
        description = "Set to 'required' to fail the request unless the response carries a verifiable signed jurisdiction receipt. Optional"
    )]
    pub jurisdiction_receipt: Option<String>,
    #[schemars(
        description = "p95 latency target in milliseconds; providers observed slower are skipped. Optional"
    )]
    pub max_p95_ms: Option<u64>,
    #[schemars(
        description = "Continuity level: 'none', 'standby' or 'hot_successor'. Above 'none' the network assigns a successor in the same jurisdiction that holds the session's KV cache and takes over if the provider fails; needs 'jurisdiction' and 'session_id'. Optional"
    )]
    pub continuity: Option<String>,
    #[schemars(
        description = "The session the turns belong to, when continuity is above 'none'. Optional"
    )]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecordRouteOutcomeParams {
    #[schemars(
        description = "The model that served the call. Take it from the routing decision's model_id"
    )]
    pub model_id: String,
    #[schemars(
        description = "The difficulty cluster the request landed in. Take it from the routing decision's 'cluster'"
    )]
    pub cluster: u32,
    #[schemars(
        description = "How the call turned out: 'resolved' (answered acceptably), 'escalated' (you took the answer to a stronger model), or 'failed' (no usable answer)"
    )]
    pub outcome: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RouteDifficultyStatsParams {
    #[schemars(
        description = "Model to report per-cluster outcome counters and error rate for. Omit for the cluster map alone. Optional"
    )]
    pub model_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreatePaymentChallengeParams {
    #[schemars(
        description = "Payment protocol: 'mpp' (Machine Payments Protocol — session-based streaming), 'x402' (Coinbase HTTP 402 — stateless one-shot), or 'native' (direct TNZO transfer)"
    )]
    pub protocol: String,
    #[schemars(
        description = "Resource URL or identifier being paid for (e.g. /api/inference, /api/data/query)"
    )]
    pub resource: String,
    #[schemars(
        description = "Payment amount in smallest unit (e.g. 100 = 0.000100 USDC for x402, or TNZO base units for native)"
    )]
    pub amount: u128,
    #[schemars(description = "Payment asset: 'USDC', 'USDT', or 'TNZO'")]
    pub asset: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub recipient: String,
    #[schemars(
        description = "Registered app_id for developer-margin attribution. The amount is marked up by the app's margin and the margin is carved out to the app wallet at settlement."
    )]
    pub app_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyPaymentParams {
    #[schemars(description = "Challenge ID from the payment challenge")]
    pub challenge_id: String,
    #[schemars(description = "Payment protocol used: 'mpp', 'x402', or 'native'")]
    pub protocol: String,
    #[schemars(
        description = "Payer DID (e.g. did:tenzro:human:uuid or did:tenzro:machine:controller:uuid)"
    )]
    pub payer_did: String,
    #[schemars(description = "Payer wallet address (hex-encoded)")]
    pub payer_address: String,
    #[schemars(description = "Payment amount in smallest unit")]
    pub amount: u128,
    #[schemars(description = "Payment asset: 'USDC', 'USDT', or 'TNZO'")]
    pub asset: String,
    #[schemars(
        description = "Hex-encoded P-256 public key (x || y, 64 bytes) of the hardware key that signed the payment. The payer is the account this key controls; payer_address must be that account or empty."
    )]
    pub public_key: String,
    #[schemars(
        description = "Composite signature over the canonical payment authorization (chain id, challenge id, payer, payee, amount, asset): {\"classical\": {\"form\": \"raw\", \"signature\": hex} or {\"form\": \"webauthn\", \"authenticator_data\", \"client_data_json\", \"signature\"}, \"pq\": hex ML-DSA-65 signature, required when the payer's account enrolled an ML-DSA-65 key}"
    )]
    pub signature: PayCompositeSignature,
}

// ─── OAuth 2.1 + AAP delegation params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExchangeTokenParams {
    #[schemars(
        description = "Parent JWT (the `subject_token` per RFC 8693). The AS validates its signature, exp, and revocation state before issuing the child token."
    )]
    pub subject_token: String,
    #[schemars(
        description = "DID that will be the `sub` of the new child JWT — typically a delegated agent or sub-agent in the act-chain"
    )]
    pub child_bearer_did: String,
    #[schemars(
        description = "RFC 7638 JWK thumbprint of the child holder's Ed25519 public key. The child token is DPoP-bound to this key."
    )]
    pub child_dpop_jkt: String,
    #[schemars(
        description = "RFC 9396 typed scope envelope the child should carry. Must be a strict subset of the parent's authorization_details. An object `{details: [...]}`."
    )]
    pub requested_rar: RarAuthorizationDetails,
    #[schemars(
        description = "AAP `aap_capabilities` claim list — per-action constraints layered over RAR. Must be a subset of the parent's capabilities."
    )]
    pub requested_aap_capabilities: Vec<AapCapabilityWire>,
    #[schemars(
        description = "Optional TTL override for the child token in seconds. Clamped to the engine's max_ttl_secs and the parent's remaining lifetime."
    )]
    pub requested_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IntrospectTokenParams {
    #[schemars(
        description = "JWT to introspect. The AS returns `{active: true, ...claims}` on success or `{active: false}` per RFC 7662 §2.2 if the token is unknown, expired, or revoked."
    )]
    pub token: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRoleStakesParams {
    #[schemars(
        description = "Hex account address (with or without 0x). If omitted, this node's operator payee"
    )]
    pub address: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListRoleEndpointsParams {
    #[schemars(
        description = "Role whose staked operators to list (rpc, ai, storage, ...). Default rpc"
    )]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProviderStatsParams {
    #[schemars(
        description = "Hex-encoded provider address (with or without 0x prefix). If omitted, returns stats for the local node"
    )]
    pub address: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetComputeBondParams {
    #[schemars(
        description = "Provider DID the bond is posted against (e.g. did:tenzro:machine:...). If omitted, lists every compute bond on the node"
    )]
    pub provider_did: Option<String>,
}

// ─── Duty and Evidence Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDutyParams {
    #[schemars(description = "Duty id (32-byte hex)")]
    pub duty_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyEvidenceParams {
    #[schemars(
        description = "Evidence items, 1 to 16, each one of: {\"audit\": <audit proof>}, {\"terms\": {\"agent_did\"}}, {\"settlement\": {\"payment_id\"}}, {\"sensor_data\": {\"device_did\", \"payload_digest\", \"measured_at_ms\", \"signature\"}}, {\"finality_proof\": {\"journal\", \"stark\"}} (the quantum-safe STARK; a Groth16 \"seal\" in place of \"stark\" is the classical compact form), {\"document\": {\"kind\", \"digest\"}}"
    )]
    pub items: Vec<EvidenceItemParam>,
}

// ─── MicroNode Join parameter struct ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JoinAsMicroNodeParams {
    #[schemars(description = "Display name for this participant (human-readable, optional)")]
    pub display_name: Option<String>,
    #[schemars(
        description = "Hex public key of the key that owns this participant — the passkey \
                       (human) or the TPM / Secure Enclave key (agent/bot). Required: the \
                       node does not generate keys on your behalf."
    )]
    pub public_key: String,
    #[schemars(
        description = "Hex passkey credential id. Required when participant_type is \
                       'human'; omitted for an autonomous 'agent' / 'bot'."
    )]
    pub credential_id: Option<String>,
    #[schemars(
        description = "Entry point: 'mcp' | 'claude' | 'clawbot' | 'a2a' | 'sdk' | 'api' | 'cli' | 'app'"
    )]
    pub origin: Option<String>,
    #[schemars(description = "Participant type: 'human' | 'agent' | 'bot'")]
    pub participant_type: Option<String>,
}

// ─── Governance Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListProposalsParams {
    #[schemars(description = "How many to return, newest first (1-100, default 20).")]
    pub limit: Option<u64>,
    #[schemars(description = "Continue from a previous page's 'next'.")]
    pub before: Option<u64>,
    #[schemars(
        description = "Keep only one action kind, e.g. 'policy_update', 'parameter_change', 'treasury_grant'."
    )]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetGuardianStateParams {
    #[schemars(description = "Optional hex address whose guardian seat to return")]
    pub address: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetVotingPowerParams {
    #[schemars(description = "Hex-encoded address to query voting power for")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTreasuryPayoutsParams {
    #[schemars(
        description = "Hex-encoded address to read the approval status and total received of"
    )]
    pub address: Option<String>,
    #[schemars(description = "Disbursements to skip, oldest first (default 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Most disbursements to return (default 100, at most 100)")]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSponsoredBondParams {
    #[schemars(
        description = "Hex-encoded validator address to read the governance-sponsored bond of"
    )]
    pub address: String,
}

// ─── Token Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TokenBalanceParams {
    #[schemars(description = "Hex-encoded address to query TNZO balance for")]
    pub address: String,
}

// ─── Settlement Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettlePaymentParams {
    #[schemars(description = "Payee address (hex)")]
    pub payee: String,
    #[schemars(description = "Amount in wei, decimal string")]
    pub amount_wei: String,
    #[schemars(
        description = "The payer's signed authorization: {payer, payment_id, authorization}, where authorization is the payer's PaymentAuthorization naming this payee and a ceiling of at least the amount"
    )]
    pub payment: PayPayerPayment,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateEscrowParams {
    #[schemars(description = "Hex-encoded 32-byte payee address (receives funds on release)")]
    pub payee: String,
    #[schemars(
        description = "Amount in wei to hold in escrow as a decimal string (1 TNZO = 10^18 wei)."
    )]
    pub amount_wei: String,
    #[schemars(
        description = "Release condition: 'provider_signature' | 'consumer_signature' | 'both_signatures' | 'timeout' | 'custom'"
    )]
    pub release_condition: String,
    #[schemars(
        description = "Seconds until the agent's wallet may refund what remains (default 3600)"
    )]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReleaseEscrowParams {
    #[schemars(description = "32-byte escrow ID (hex, with or without 0x prefix)")]
    pub escrow_id: String,
    #[schemars(description = "Optional hex-encoded proof bytes")]
    pub proof_data_hex: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListRegistryParams {
    #[schemars(description = "Entry kind (service type), e.g. unit, card, service, app, dataset")]
    pub kind: String,
    #[schemars(description = "List ids after this one (the previous page's next)")]
    pub after: Option<String>,
    #[schemars(description = "Most entries to return (default 100, at most 500)")]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRegistryEntryParams {
    #[schemars(description = "Entry id")]
    pub id: String,
    #[schemars(description = "A past version of the entry (default: the latest)")]
    pub version: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPriceCardParams {
    #[schemars(description = "The provider's account (hex)")]
    pub provider: String,
    #[schemars(description = "Model or service id the card is for")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QuoteInferenceParams {
    #[schemars(description = "Model id")]
    pub model: String,
    #[schemars(
        description = "Billable units of the request, e.g. {\"input_tokens\": 800, \"output_tokens\": 200}; omitted units are zero"
    )]
    pub units: Option<ModelsUnits>,
    #[schemars(description = "Verification level: none (default), receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(description = "Only this provider's address")]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RefundEscrowParams {
    #[schemars(description = "32-byte escrow ID (hex, with or without 0x prefix)")]
    pub escrow_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenPaymentChannelParams {
    #[schemars(
        description = "Escrow id (hex) of a CreateEscrow the payer already submitted and signed, naming this node's payee. The escrow is the channel's deposit."
    )]
    pub channel_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClosePaymentChannelParams {
    #[schemars(description = "Channel (escrow) id to close")]
    pub channel_id: String,
    #[schemars(description = "Payer's hardware P-256 key, x || y (64 bytes hex)")]
    pub public_key: String,
    #[schemars(
        description = "Payer's composite signature over the close request: {classical: {form, ...}, pq?}"
    )]
    pub signature: PayCompositeSignature,
    #[schemars(description = "Unix-millisecond timestamp the signature covers")]
    pub timestamp_ms: i64,
}

// ─── Model Lifecycle Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServeModelMcpParams {
    #[schemars(description = "Model ID to start serving (must be downloaded first)")]
    pub model_id: String,
    #[schemars(description = "Optional maximum number of concurrent inference requests")]
    pub max_concurrent: Option<u32>,
}

// ─── Universal RPC gateway parameter structs ───

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TransactionSigningPayloadParams {
    #[schemars(
        description = "The unsigned transaction, as tenzro_sendRawTransaction takes it without signatures"
    )]
    pub transaction: PayAnyUnsignedTx,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessChallengeParams {
    #[schemars(description = "The DID signing in")]
    pub did: String,
    #[schemars(
        description = "RFC 7638 SHA-256 thumbprint of the DPoP key the token will be bound to"
    )]
    pub dpop_jkt: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IssueAccessTokenParams {
    #[schemars(description = "The challenge id from access_challenge")]
    pub challenge_id: String,
    #[schemars(description = "The passkey or hardware-key answer to the challenge")]
    pub proof: AccessSignInProof,
    #[schemars(description = "KYA credentials about the DID, for policies that require one")]
    pub credentials: Option<Vec<KyaCredential>>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SetAccessPolicyParams {
    #[schemars(description = "The full access.toml text")]
    pub toml: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PreviewAccessParams {
    #[schemars(description = "rpc, mcp, a2a, openai, files, web or iroh")]
    pub surface: String,
    #[schemars(description = "A JSON-RPC method name; give this or class")]
    pub method: Option<String>,
    #[schemars(
        description = "A method class (read, owner_write, admin, inference, media, storage, files, index, payments, identity); give this or method"
    )]
    pub class: Option<String>,
    #[schemars(description = "The caller's DID; omit for an anonymous caller")]
    pub did: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevokeAccessTokenParams {
    #[schemars(description = "The token id to withdraw")]
    pub jti: Option<String>,
    #[schemars(description = "Withdraw every live token of this DID")]
    pub did: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CustodyChallengeParams {
    #[schemars(description = "Smart account being changed (0x-prefixed 20-byte address)")]
    pub account_address: String,
    #[schemars(
        description = "One of: enroll_passkey, grant_session_key, revoke_session_key, set_spending_limit, add_hardware_signer"
    )]
    pub operation: String,
    #[schemars(
        description = "The operation's subject, hex — the credential being revoked, the session key being withdrawn"
    )]
    pub target_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListRpcMethodsParams {
    #[schemars(
        description = "Restrict to one namespace, e.g. `eth`, `iroh`, `list`. Omit to search across all"
    )]
    pub namespace: Option<String>,
    #[schemars(
        description = "Case-insensitive substring of the method name, e.g. `database`, `stake`, `Forecast`"
    )]
    pub contains: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallRpcParams {
    #[schemars(
        description = "Exact JSON-RPC method name as returned by list_rpc_methods, e.g. `tenzro_previewServe`"
    )]
    pub method: String,
    #[schemars(
        description = "The method's parameters as a JSON object. Omit for methods that take none"
    )]
    pub params: Option<JsonValue>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StopModelParams {
    #[schemars(description = "Model ID to stop serving")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteModelParams {
    #[schemars(description = "Model ID to delete from local storage")]
    pub model_id: String,
}

// ─── Provider Config Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetProviderPricingParams {
    #[schemars(
        description = "Catalog id of the model the card is for. Omit to set the card every model without its own is priced on."
    )]
    pub model_id: Option<String>,
    #[schemars(
        description = "The price card: {denom: 'nano_usd' | 'wei', lines: {<unit or unit@tier>: {price, per_exp}}, min_charge}. A price is per 10^per_exp units, in billionths of a dollar (settled in TNZO at the chain's rate) or in TNZO base units. Units are registered ids such as input_tokens, output_tokens, reasoning_tokens, cached_read_tokens, pixel_steps, characters, audio_out_ms, rerank_pairs, action_chunks."
    )]
    pub card: ModelsRateCard,
}

// ─── AgentBond Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentBondParams {
    #[schemars(description = "Agent DID to look up")]
    pub agent_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IrohPublishBlobParams {
    #[schemars(description = "Base64-encoded payload to publish to the shared iroh-blobs store.")]
    pub bytes_b64: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IrohFetchBlobParams {
    #[schemars(description = "Content-addressed tenzro:// URI to fetch (blob / model / receipt).")]
    pub tenzro_uri: String,
}

// ---- adaptive burn-rate governance dial ------------------------

// ---- Settlement plans ------------------------------------------------------

/// Completes `transaction` with the `SettlementPlan` body for `op`, checked
/// as the chain checks its shape, and the gas the VM charges for it.
fn plan_request(
    transaction: serde_json::Value,
    op: serde_json::Value,
) -> std::result::Result<serde_json::Value, ErrorData> {
    let op: tenzro_types::settlement::PlanOp = serde_json::from_value(op)
        .map_err(|e| ErrorData::invalid_params(format!("plan operation: {e}"), None))?;
    op.validate()
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let gas_limit = tenzro_vm::native::settlement_plan_gas(&op);
    typed_request(
        transaction,
        tenzro_types::transaction::TransactionType::SettlementPlan { op },
        gas_limit,
    )
}

/// Complete an unsigned request with `tx_type` and `gas_limit`.
fn typed_request(
    mut transaction: serde_json::Value,
    tx_type: tenzro_types::transaction::TransactionType,
    gas_limit: u64,
) -> std::result::Result<serde_json::Value, ErrorData> {
    let tx_type =
        serde_json::to_value(tx_type).map_err(|e| err_internal(format!("serialize: {e}")))?;
    let fields = transaction
        .as_object_mut()
        .ok_or_else(|| ErrorData::invalid_params("transaction must be an object", None))?;
    fields.insert("tx_type".into(), tx_type);
    fields.insert("gas_limit".into(), gas_limit.into());
    Ok(transaction)
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeOutboundParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two. `from` is the holder."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(
        description = "External chain the value goes to (a route's chain, e.g. base, ethereum, solana)."
    )]
    pub target_chain: String,
    #[schemars(description = "Recipient account on the external chain (hex).")]
    pub recipient: String,
    #[schemars(
        description = "Amount in base units (decimal string): TNZO, the deposit asset over a deposit route, or the carried asset named by `asset`."
    )]
    pub amount: String,
    #[schemars(
        description = "A carried asset's symbol (USDC): its representation is burned here and the route's vault releases the token there. Omit to move TNZO."
    )]
    pub asset: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PaymentRefundParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two. `from` is the payee."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(description = "The payment record's pay_ref (32-byte hex).")]
    pub pay_ref: String,
    #[schemars(
        description = "Amount returned to the payer, in the paid asset's smallest unit (decimal string)."
    )]
    pub amount: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PaymentSetSplitParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two. `from` is the payee."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(
        description = "The split rule in the split engine's form ({version, lines}, as tenzro_getPayeeSplit returns it); null clears the payee's rule."
    )]
    pub rule: Option<PaySplitRule>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleNettingBatchParams {
    #[schemars(description = "Token id of the asset (32-byte hex; TNZO's id for TNZO).")]
    pub asset: String,
    #[schemars(description = "Batch number; the asset's latest batch when omitted.")]
    pub seq: Option<u64>,
    #[schemars(
        description = "A participant (32-byte hex address): adds its collateral, defaults, and, once settled, its gross-to-net statement with Merkle paths."
    )]
    pub participant: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleRouteParams {
    #[schemars(description = "The route's bridge protocol: ccip, ibc, deposit or contract.")]
    pub adapter: String,
    #[schemars(description = "The route's external chain, e.g. ethereum.")]
    pub chain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleReconcileParams {
    #[schemars(description = "The route's bridge protocol: ccip, ibc, deposit or contract.")]
    pub adapter: String,
    #[schemars(description = "The route's external chain, e.g. ethereum.")]
    pub chain: String,
    #[schemars(
        description = "The entries the lock recorded since the last reconciliation, in order: [{plan_id, leg_id, kind: locked|released|refunded, amount}]."
    )]
    pub entries: Vec<PayReconEntry>,
    #[schemars(description = "The route's proof of the lock's checkpoint, hex.")]
    pub checkpoint: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettlePlanIdParams {
    #[schemars(description = "32-byte plan id (hex).")]
    pub plan_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleLegReceiptParams {
    #[schemars(description = "32-byte plan id (hex).")]
    pub plan_id: String,
    #[schemars(description = "The leg's index in the plan, 0 to 15.")]
    pub index: u8,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleOpenPlanParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(
        description = "The open operation: {nonce, quote_digest, split_hash, split, legs, decide_deadline_ms, agent}, as `tenzro settle open` reads it from a plan file. legs are {kind, class_required, usd_e6, max_network_fee}."
    )]
    pub open: PaySettleOpen,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleProveLegParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(description = "32-byte plan id (hex).")]
    pub plan_id: String,
    #[schemars(description = "The leg's index in the plan, 0 to 15.")]
    pub index: u8,
    #[schemars(
        description = "What proves the leg (hex): a lock leg's proof of its Locked event, a hash-locked leg's funding proof or preimage; empty for legs Tenzro reads from its own state."
    )]
    pub evidence: Option<String>,
    #[schemars(
        description = "The fee paid on the leg's network to carry this proof, wei of TNZO, decimal string (default 0); a commit repays it up to the leg's max_network_fee."
    )]
    pub network_fee: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleDisputeRailParams {
    #[schemars(
        description = "The unsigned transaction request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_price, timestamp, valid_until), without tx_type, gas_limit, public_key or signature; the tool fills those two."
    )]
    pub transaction: PayUnsignedTxRequest,
    #[schemars(description = "32-byte plan id (hex).")]
    pub plan_id: String,
    #[schemars(description = "The rail leg's index in the plan.")]
    pub index: u8,
    #[schemars(
        description = "The payee's evidence that the payment did not arrive (hex): its account statement or return notice."
    )]
    pub evidence: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettleListPlansParams {
    #[schemars(description = "Only plans this payer opened (32-byte hex).")]
    pub payer: Option<String>,
    #[schemars(description = "Only plans in this status: open, committed or aborted.")]
    pub status: Option<String>,
    #[schemars(description = "Most plans to return (default 50, at most 200).")]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettlePreviewParams {
    #[schemars(description = "Gross amount, wei, as a decimal string.")]
    pub gross: String,
    #[schemars(
        description = "The split rule: {version: 1, lines: [{role, recipient, basis, cap}]}, exactly one line with basis \"remainder\"."
    )]
    pub split: PaySplitRule,
    #[schemars(description = "Network fees the payee side bears, wei (default 0).")]
    pub network_fees: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiscoverModelsParams {
    #[schemars(description = "Free-text query")]
    pub query: Option<String>,
    #[schemars(description = "Modality filter")]
    pub modality: Option<String>,
    #[schemars(description = "Only models currently served")]
    pub serving_only: Option<bool>,
}

// ─── Token & Contract Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenInfoParams {
    #[schemars(description = "Token symbol (e.g. 'TNZO')")]
    pub symbol: Option<String>,
    #[schemars(description = "EVM contract address (hex)")]
    pub evm_address: Option<String>,
    #[schemars(description = "Token ID (hex, 32 bytes)")]
    pub token_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListTokensParams {
    #[schemars(description = "Filter by VM type: 'evm', 'svm', 'native'")]
    pub vm_type: Option<String>,
    #[schemars(description = "Maximum number of tokens to return (default: 50, max: 100)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VmCallParam {
    #[schemars(description = "VM the call runs in: 'evm' or 'svm'")]
    pub vm: String,
    #[schemars(
        description = "Code called (hex): an EVM contract (20 bytes) or an SVM program (32 bytes)"
    )]
    pub to: String,
    #[schemars(description = "Calldata (hex) in the VM's own format")]
    pub data: String,
    #[schemars(description = "TNZO the call carries, wei as a decimal string (EVM only)")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenBalanceParams {
    #[schemars(description = "Address to query (hex)")]
    pub address: String,
}

// ─── Token Rule Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CanTransferParams {
    #[schemars(description = "Token id (64 hex)")]
    pub token_id: String,
    #[schemars(description = "Sender account (hex)")]
    pub from: String,
    #[schemars(description = "Recipient account (hex)")]
    pub to: String,
    #[schemars(description = "Amount in the token's smallest unit (decimal string)")]
    pub amount: String,
}

// ─── Events Params ───

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct QueryEventsParams {
    #[schemars(
        description = "Event filter: {event_types: ['log' | 'transaction_included'], addresses: [20-byte hex], topics: [null | hex | [hex]], from_block, to_block}"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<EventFilterInput>,
    #[schemars(description = "Resume after this cursor (height:tx_index:event_index)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_cursor: Option<String>,
    #[schemars(description = "Start at this height (instead of from_cursor)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_height: Option<u64>,
    #[schemars(description = "Stop at this cursor, inclusive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_cursor: Option<String>,
    #[schemars(description = "Most events to return (default 100, max 1000)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[schemars(
        description = "Also prove the page left out nothing the filter selects: the block-index entries of every block it covered (at most 256 heights a page)"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness: Option<bool>,
    #[schemars(
        description = "Checkpoint index every proof ends at (default: the latest certified)"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_index: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SubscribeEventsParams {
    #[schemars(description = "Event filter, as for query_events")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<EventFilterInput>,
    #[schemars(
        description = "Resume after this cursor; omit both this and from_height to start at the tip"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_cursor: Option<String>,
    #[schemars(description = "Start at this height (instead of from_cursor)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_height: Option<u64>,
    #[schemars(description = "Most events to return (default 100, max 1000)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[schemars(description = "Wait up to this many milliseconds for new events (max 30000)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    #[schemars(description = "Attach each event's proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<bool>,
    #[schemars(description = "Attach each event's proof and the page's completeness proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetBeaconParams {
    #[schemars(description = "The value the beacon took at this round")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u64>,
    #[schemars(description = "The first value the beacon took at or after this block time, ms")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_ms: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetDaObjectParams {
    #[schemars(description = "The object's 32-byte commitment, hex")]
    pub commitment: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyEventProofParams {
    #[schemars(description = "The proof object, as query_events returns it")]
    pub proof: EventProofBody,
}

// ─── SLA Fault Detector Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SlaIssueProbeParams {
    #[schemars(description = "DID of the ModelProvider / TeeProvider being probed")]
    pub provider_did: String,
    #[schemars(description = "Validator epoch the probe is issued in")]
    pub epoch: u64,
    #[schemars(description = "Probe round within the epoch")]
    pub round: u64,
    #[schemars(
        description = "Unix-millisecond deadline by which the provider must respond before the probe is considered missed"
    )]
    pub deadline_ms: i64,
}

// ─── Snapshot (State Sync) Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SnapshotManifestParams {
    #[schemars(description = "Block height of the snapshot to fetch the manifest for")]
    pub height: u64,
}

// ─── Permit2 Params ───

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Permit2VerifyAndConsumeParams {
    pub chain_id: u64,
    pub owner: String,
    pub token: String,
    pub amount: String,
    pub spender: String,
    pub nonce: String,
    pub deadline: u64,
    #[schemars(description = "65-byte ECDSA signature (0x-prefixed hex)")]
    pub signature: String,
    pub witness: Option<String>,
    pub witness_type_string: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Permit2NonceUsedParams {
    pub owner: String,
    pub nonce: String,
}

// ─── Escrow + Dispute inspection Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetEscrowParams {
    #[schemars(
        description = "Escrow id — 32-byte SHA-256 digest derived by the VM during CreateEscrow. Accepts both 0x-prefixed and bare hex."
    )]
    pub escrow_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPaymentProofParams {
    #[schemars(description = "The payment record's reference, 32 bytes hex")]
    pub pay_ref: Option<String>,
    #[schemars(description = "The payment id a native payment settled under")]
    pub payment_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListPaymentsParams {
    #[schemars(description = "Only payments to this payee, 32-byte hex address")]
    pub payee: Option<String>,
    #[schemars(description = "Only payments from this payer")]
    pub payer: Option<String>,
    #[schemars(description = "Only payments made by this delegated agent DID")]
    pub agent_did: Option<String>,
    #[schemars(description = "Only this record class: native, proven or attested")]
    pub class: Option<String>,
    #[schemars(description = "Only this asset")]
    pub asset: Option<String>,
    #[schemars(
        description = "Continue after this event cursor (the cursor a previous call returned)"
    )]
    pub from_cursor: Option<String>,
    #[schemars(description = "Start at this block height")]
    pub from_height: Option<u64>,
    #[schemars(description = "Most records")]
    pub limit: Option<u64>,
    #[schemars(description = "Include each record's event proof")]
    pub proofs: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPayeeSplitParams {
    #[schemars(description = "The payee's address, 32-byte hex")]
    pub payee: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AgentVoucherParams {
    #[schemars(description = "Channel (escrow) id, 0x-prefixed 32-byte hex")]
    pub channel_id: String,
    #[schemars(description = "New cumulative amount owed on the channel, decimal u128 string")]
    pub cumulative_amount: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QuoteResourceParams {
    #[schemars(description = "The price in USD micro-units (1 USD = 1000000)")]
    pub usd_e6: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoteChannelVoucherParams {
    #[schemars(description = "The chain the agent's account holds the channel on, CAIP-2")]
    pub chain: String,
    #[schemars(description = "The channel's id on the account")]
    pub channel_id: u64,
    #[schemars(description = "New cumulative amount owed on the channel, decimal u128 string")]
    pub cumulative_amount: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListEscrowsByPayerParams {
    #[schemars(
        description = "Payer address (the wallet that created the escrow). Returns {payer, count, escrows: [...]} from the `escrow_payer:` secondary index in CF_SETTLEMENTS."
    )]
    pub payer: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListEscrowsByPayeeParams {
    #[schemars(
        description = "Payee address (the recipient on successful release). Returns {payee, count, escrows: [...]} from the `escrow_payee:` secondary index in CF_SETTLEMENTS."
    )]
    pub payee: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentTermsParams {
    #[schemars(description = "Agent DID (`did:tenzro:machine:{root}:{id}`).")]
    pub agent_did: String,
}

// ─── Verifiable Inference Params (TOPLOC commitments + challenges) ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetInferenceCommitmentParams {
    #[schemars(
        description = "Commitment hash (hex, with or without 0x prefix) returned alongside a verifiable chat response. Returns the stored envelope {commitment_hash, model_id, provider, created_at, commitment: {k, prompt_tokens, steps}} or null when unknown."
    )]
    pub commitment_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyInferenceCommitmentParams {
    #[schemars(
        description = "Commitment hash (hex, with or without 0x prefix) of the stored commitment to verify."
    )]
    pub commitment_hash: String,
    #[schemars(
        description = "The exact prompt the committed response was generated from. Prompts are never stored with commitments — the verifier supplies it at verification time. The node re-executes prompt+output as a single prefill and compares per-step top-k logits."
    )]
    pub prompt: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileInferenceChallengeParams {
    #[schemars(
        description = "Commitment hash (hex, with or without 0x prefix) being disputed. Unknown hashes are rejected."
    )]
    pub commitment_hash: String,
    #[schemars(
        description = "Challenger identity (DID or address). Recorded verbatim on the challenge."
    )]
    pub challenger: String,
    #[serde(default)]
    #[schemars(description = "Optional free-text reason for the dispute.")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetInferenceChallengeParams {
    #[schemars(
        description = "Challenge id (UUID) returned by file_inference_challenge. Returns the full challenge record or null when unknown."
    )]
    pub challenge_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListInferenceChallengesParams {
    #[serde(default)]
    #[schemars(
        description = "Optional status filter: voting_commit, voting_reveal, upheld, or dismissed."
    )]
    pub status: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional provider filter (announce-signer pubkey hex).")]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CommitChallengeVoteParams {
    #[schemars(description = "Challenge id (UUID) being voted on.")]
    pub challenge_id: String,
    #[schemars(
        description = "Committee-member identity (validator address, hex). Must be a drawn committee seat."
    )]
    pub voter: String,
    #[schemars(
        description = "Vote commitment hash (hex) = compute_vote_commit(verdict, salt, challenge_id, voter)."
    )]
    pub commit_hash: String,
    #[schemars(
        description = "Hex Ed25519 signature by the seat's consensus key over the commit, from tenzro_signChallengeVote on the voter's own node."
    )]
    pub signature: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RevealChallengeVoteParams {
    #[schemars(description = "Challenge id (UUID) being revealed.")]
    pub challenge_id: String,
    #[schemars(
        description = "Committee-member identity (validator address, hex). Must match the earlier commit."
    )]
    pub voter: String,
    #[schemars(
        description = "Revealed verdict: true = commitment did not verify (upholds), false = dismisses."
    )]
    pub verdict: bool,
    #[schemars(description = "Reveal salt (hex) — must reproduce the earlier commit hash.")]
    pub salt: String,
    #[schemars(
        description = "Hex Ed25519 signature by the seat's consensus key over the reveal, from tenzro_signChallengeVote on the voter's own node."
    )]
    pub signature: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FinalizeChallengeParams {
    #[schemars(
        description = "Challenge id (UUID) to finalize by tallying revealed committee votes."
    )]
    pub challenge_id: String,
}

// ─── Crypto Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifySignatureParams {
    #[schemars(description = "Hex-encoded public key")]
    pub public_key: String,
    #[schemars(description = "Hex-encoded message bytes that were signed")]
    pub message_hex: String,
    #[schemars(description = "Hex-encoded signature")]
    pub signature_hex: String,
}

// ─── TEE Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DetectTeeParams {
    // No parameters — detects available TEE hardware
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTeeAttestationParams {
    #[schemars(
        description = "Hex data the report commits to (packed into the vendor's report data); 64 zero bytes when omitted"
    )]
    pub user_data: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyTeeAttestationParams {
    #[schemars(description = "Hex of the JSON attestation report (with its vendor collateral)")]
    pub attestation: String,
    #[schemars(
        description = "Hex nonce from tenzro_teeAttestationChallenge that the report answers"
    )]
    pub nonce: String,
    #[schemars(description = "Optional hex data the report binds alongside the nonce")]
    pub bound_data: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListTeeProvidersParams {
    // No parameters — lists all registered TEE providers
}

// ─── ZK Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateZkProofParams {
    #[schemars(
        description = "Circuit identifier — 'settlement' (identity proofs are made by the key holder, never by a node)"
    )]
    pub circuit_id: String,
    #[schemars(
        description = "JSON object {\"witness\": 32-byte hex service result, \"binding\": 32-byte hex request binding}"
    )]
    pub witness: ZkSettlementWitness,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListZkCircuitsParams {
    // No parameters — lists all available ZK circuits
}

// ─── Network funding params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GovernanceGetParams {
    #[schemars(
        description = "What to read: 'proposal', 'policy', 'grant', 'readiness' or 'receipt'."
    )]
    pub kind: String,
    #[schemars(
        description = "Proposal or grant id (64 hex); a binary's SHA-256 (64 hex) for readiness; the policy kind for a policy (economic_policy, adaptive_burn_config, supply_targets, protocol_upgrade)."
    )]
    pub id: String,
}

// ─── ERC-8004 (Trustless Agents Registry) params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004MetadataEntryParam {
    #[schemars(description = "Metadata key string (free-form ASCII identifier)")]
    pub key: String,
    #[schemars(description = "Metadata value as 0x-prefixed hex bytes")]
    pub value: String,
}

// ─── Bridge route params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeRouteKeyParams {
    #[schemars(description = "Route transport: ccip, ibc, deposit or contract")]
    pub adapter: String,
    #[schemars(
        description = "External chain name, e.g. ethereum, base, solana, cosmoshub, bitcoin or sui"
    )]
    pub source_chain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeOutboundRecordParams {
    #[schemars(description = "Route transport: ccip, ibc, deposit or contract")]
    pub adapter: String,
    #[schemars(description = "External chain name, e.g. ethereum, solana or bitcoin")]
    pub source_chain: String,
    #[schemars(description = "The outbound record's sequence on the route")]
    pub sequence: u64,
}

// ─── Multi-modal (forecast / vision / text-embed / segment / detect / transcribe / video) Params ───

#[derive(Debug, Deserialize, Default, schemars::JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ModelIdParams {
    #[schemars(description = "Registered model id (the same id used at load time)")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TrainingRoundParams {
    #[schemars(description = "Catalog model id loaded for training on this node")]
    pub model_id: String,
    #[schemars(
        description = "LoRA recipe: { rank, alpha, targets: ['attn_q.weight', ...], lr, beta1, beta2, eps, weight_decay, seq_len, batch, grad_clip }"
    )]
    pub recipe: LoraRecipeParam,
    #[schemars(
        description = "Records: [{ prompt, completion }]; the loss counts the completion's tokens"
    )]
    pub records: Vec<TrainingRecordParam>,
    #[schemars(description = "Seed of batch selection")]
    pub sample_seed: u64,
    #[schemars(description = "Seed of the adapter's initial weights")]
    pub adapter_seed: u64,
    #[schemars(description = "Steps the round takes")]
    pub steps: u64,
    #[schemars(
        description = "Where the round starts: { state_uri, start_root, steps_taken } from the previous round; omit for fresh weights"
    )]
    pub start: Option<TrainingStartParam>,
    #[schemars(description = "Receipt verification level; omit for the node's default")]
    pub verification: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ForecastParams {
    #[schemars(description = "Registered forecast model id (e.g. 'timesfm-2.5-200m')")]
    pub model_id: String,
    #[schemars(description = "Univariate context series (most-recent-last). Non-empty.")]
    pub history: Vec<f32>,
    #[schemars(description = "Forecast horizon (steps ahead). Must be > 0.")]
    pub horizon: u32,
    #[schemars(
        description = "Optional output quantile levels in (0,1) (e.g. [0.1, 0.5, 0.9]). Defaults to model-native quantiles."
    )]
    pub quantiles: Option<Vec<f32>>,
    #[schemars(
        description = "Optional sampling frequency in seconds (used by frequency-aware models)"
    )]
    pub frequency_seconds: Option<u64>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VisionEmbedParams {
    #[schemars(description = "Registered vision encoder id (DINOv3, SigLIP2, CLIP, etc.)")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes (PNG/JPEG/WebP)")]
    pub image_base64: String,
    #[schemars(description = "L2-normalize the embedding before returning it (default false)")]
    pub normalize: Option<bool>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VisionSimilarityParams {
    #[schemars(description = "Image embedding (typically from vision_embed)")]
    pub image_embedding: Vec<f32>,
    #[schemars(
        description = "Text embedding (typically from text_embed against a CLIP/SigLIP text tower of matching dimension)"
    )]
    pub text_embedding: Vec<f32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TextEmbedParams {
    #[schemars(
        description = "Registered text-embedding model id (e.g. 'qwen3-embedding-0.6b', 'embeddinggemma-300m', 'bge-m3')"
    )]
    pub model_id: String,
    #[schemars(
        description = "Inputs to embed, one row each. Non-empty. An input is a string, or an object with `text`, `image` (base64 PNG/JPEG/WebP) and/or `video` (base64 frames in order) embedded as one item; pictures and video need a vision-language embedder (e.g. 'qwen3-vl-embedding-2b')."
    )]
    pub inputs: Vec<EmbedInputParam>,
    #[schemars(
        description = "Matryoshka truncation target dimension (e.g. 128/256/512). If omitted, returns the model-native dim."
    )]
    pub requested_dim: Option<u32>,
    #[schemars(description = "L2-normalize each row before returning (default false)")]
    pub normalize: Option<bool>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

/// One input of `text_embed`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum EmbedInputParam {
    /// Text to embed.
    Text(String),
    /// Text, a picture and/or a video, embedded as one item.
    Media {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// Base64 picture bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        /// Base64 frames, in order.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video: Option<Vec<String>>,
    },
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SegmentParams {
    #[schemars(
        description = "Registered segmenter id (e.g. 'sam2-base', 'sam2-large', 'edgesam', 'mobilesam')"
    )]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes")]
    pub image_base64: String,
    #[schemars(
        description = "Prompts: array of `{type:'point', x, y, is_foreground}` (is_foreground true marks a point inside the object, false marks background) or `{type:'box', x0, y0, x1, y1}` objects. Coordinates are original-image pixels."
    )]
    pub prompts: Vec<SegmentPromptParam>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SpeakParams {
    #[schemars(description = "Loaded speech model id")]
    pub model_id: String,
    #[schemars(description = "Text to speak (up to 4096 characters)")]
    pub input: String,
    #[schemars(description = "Language code the model takes (en, zh, ...)")]
    pub language: Option<String>,
    #[schemars(description = "Seed; the same seed, text and voice give the same audio")]
    pub seed: Option<u32>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

/// One typed question for a decision model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecisionQuestionParam {
    #[schemars(description = "The id the answer is returned under; distinct within the request")]
    pub id: String,
    #[schemars(description = "choice, score or noul (yes or no)")]
    #[serde(rename = "type")]
    pub kind: String,
    #[schemars(description = "What is asked: text, or any JSON value")]
    pub instructions: JsonValue,
    #[schemars(
        description = "choice: the options (at most 255), an array of { key, description? } in the order the prompt lists them, or an object of key to description. score: 2 to 10 level descriptions, level 0 first. noul: optionally { false, true } describing the two answers."
    )]
    pub criteria: Option<JsonValue>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DecideParams {
    #[schemars(description = "Loaded decision model id (e.g. 'laya')")]
    pub model_id: String,
    #[schemars(
        description = "What to decide about: text, or any JSON value (an email, a ticket, a record)"
    )]
    pub state: JsonValue,
    #[schemars(description = "1 to 64 questions, answered in this order")]
    pub questions: Vec<DecisionQuestionParam>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RerankParams {
    #[schemars(description = "Loaded reranker id")]
    pub model_id: String,
    #[schemars(
        description = "The query: a string, or an object with `text`, `image` (base64 PNG/JPEG/WebP) and/or `video` (base64 frames in order); pictures and video need a vision-language reranker (e.g. 'qwen3-vl-reranker-2b')."
    )]
    pub query: EmbedInputParam,
    #[schemars(
        description = "Documents to score (1 to 1000), each in the same shape as the query"
    )]
    pub documents: Vec<EmbedInputParam>,
    #[schemars(description = "Return only the best N")]
    pub top_n: Option<u64>,
    #[schemars(description = "Include each document as given in the answer")]
    pub return_documents: Option<bool>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DetectParams {
    #[schemars(
        description = "Registered detector id (e.g. 'rf-detr-base', 'rf-detr-nano', 'd-fine-l')"
    )]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes")]
    pub image_base64: String,
    #[schemars(
        description = "Score threshold (0.0–1.0). Detections below this are dropped. Default 0.25."
    )]
    pub score_threshold: Option<f32>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TranscribeStreamParams {
    #[schemars(description = "ASR model id served by this node (e.g. 'whisper-large-v3-turbo')")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded 16-bit PCM WAV (the first channel is transcribed)")]
    pub audio_base64: String,
    #[schemars(description = "Optional ISO language hint (e.g. 'en')")]
    pub language: Option<String>,
    #[schemars(description = "Milliseconds of audio per chunk (default 200)")]
    pub chunk_ms: Option<u32>,
    #[schemars(
        description = "Verification level for each final segment: none, receipt, optimistic or tee"
    )]
    pub verification: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TranscribeParams {
    #[schemars(
        description = "Registered ASR model id (e.g. 'whisper-large-v3-turbo', 'distil-whisper-small.en', 'moonshine-base-v2', 'parakeet-tdt-0.6b-v3', 'canary-1b-flash')"
    )]
    pub model_id: String,
    #[schemars(description = "Base64-encoded audio bytes (WAV/MP3/FLAC)")]
    pub audio_base64: String,
    #[schemars(
        description = "Optional ISO language hint (e.g. 'en', 'es', 'fr'). Many models auto-detect."
    )]
    pub language: Option<String>,
    #[schemars(
        description = "Emit per-segment / per-word timestamps in the result (default false)"
    )]
    pub timestamps: Option<bool>,
    #[schemars(description = "Decoding temperature (default 0.0)")]
    pub temperature: Option<f32>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VideoEmbedParams {
    #[schemars(
        description = "Registered video encoder id — the id passed to load_video_model, not a catalog id."
    )]
    pub model_id: String,
    #[schemars(description = "Base64-encoded video bytes")]
    pub video_base64: String,
    #[schemars(description = "L2-normalize the pooled embedding (default false)")]
    pub normalize: Option<bool>,
    #[schemars(
        description = "Keep every Nth decoded frame instead of spreading the samples evenly across the clip. Still capped at the frame budget the clip encoder was registered with."
    )]
    pub frame_stride: Option<u32>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

// ─── Multi-modal load params ───

/// What every catalog model load takes: the files, repository and shapes all
/// come from the signed catalog entry.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LoadCatalogModelParams {
    #[schemars(
        description = "Catalog model id (e.g. 'clip-vit-b32', 'timesfm-2.5-200m', 'rf-detr-base')"
    )]
    pub model_id: String,
    #[schemars(
        description = "Visibility override: 'public', 'gated' or 'private'. Omit to follow the node's visibility."
    )]
    pub visibility: Option<String>,
}

impl LoadCatalogModelParams {
    fn payload(&self) -> serde_json::Value {
        let mut payload = serde_json::json!({ "model_id": self.model_id });
        if let Some(v) = &self.visibility {
            payload["visibility"] = serde_json::json!(v);
        }
        payload
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TextSegmentParams {
    #[schemars(description = "Registered SAM-3 family segmenter id (e.g. 'sam3-vit-h')")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes")]
    pub image_base64: String,
    #[schemars(description = "Free-text label to segment (e.g. 'person', 'sofa', 'dog')")]
    pub text_prompt: String,
    #[schemars(description = "Optional normalized cxcywh box prompt {cx, cy, w, h} in [0,1]")]
    pub box_prompt: Option<TextSegmentBoxParam>,
    #[schemars(
        description = "Score threshold in [0, 1]; detections below are dropped (default 0.5)"
    )]
    pub score_threshold: Option<f32>,
    #[schemars(description = "Verification level: none, receipt, optimistic or tee")]
    pub verification: Option<String>,
    #[schemars(
        description = "Serve on this provider's offer (payee address, hex). Without it, a model this node does not serve goes to a provider offering it"
    )]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LoadVideoModelParams {
    #[schemars(description = "Model id to register the clip-level encoder under")]
    pub model_id: String,
    #[schemars(
        description = "Id of an image encoder already loaded via load_vision_model. Video embedding is frame-based: the node extracts frames, embeds each through this encoder, and mean-pools. An unloaded id is refused with -32004."
    )]
    pub vision_model_id: String,
    #[schemars(
        description = "Frames to extract per clip, evenly spaced (default 8, clamped to 1..128)"
    )]
    pub num_frames: Option<u32>,
    #[schemars(
        description = "Visibility override: 'public', 'gated' or 'private'. Omit to follow the node's visibility."
    )]
    pub visibility: Option<String>,
}

// ─── Committee-DA possession challenge params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DaChallengeParams {
    #[schemars(
        description = "0x-prefixed 32-byte blob commitment whose sliver custody should be challenged"
    )]
    pub commitment: String,
    #[schemars(description = "Committee index of the member to challenge")]
    pub target_index: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DaListChallengesParams {
    #[schemars(description = "Max challenge records to return, newest-first (default 100)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DaAvailabilityParams {
    #[schemars(
        description = "Optional 0x-prefixed member address. Omit to list every scored member, lowest score first"
    )]
    pub address: Option<String>,
}

// ─── Operability inspection params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetValidatorStateParams {
    #[schemars(description = "Hex-encoded 32-byte validator address (with or without 0x prefix)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListValidatorsParams {
    #[schemars(
        description = "Optional status filter: 'Active' | 'Candidate' | 'PendingActive' | 'PendingExit' | 'Exited' | 'Jailed'"
    )]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MediaGenRenderParams {
    #[schemars(
        description = "Catalog model id of a media model served whole (not split across two experts)"
    )]
    pub model_id: String,
    #[schemars(
        description = "Media kind: 'text2image' | 'image2image' | 'text2video' | 'image2video' | 'text2audio' | 'image23d' | 'action_policy' | 'world_model'"
    )]
    pub kind: String,
    #[schemars(
        description = "MediaGenParams object: prompt, width, height, steps, guidance_scale; for video num_frames and fps; for action_policy action_chunks; for world_model num_frames, fps and session_hold_secs; for image23d an empty prompt, the reference image's width and height and optionally voxel_resolution (the output is a GLB); a seed (a render is seeded, so another provider can re-render it); inputs = ordered [{role, hash}] naming each input by SHA-256, role one of first_frame | last_frame | reference | edit_source | mask | observation"
    )]
    pub params: MediaGenParamsInput,
    #[schemars(description = "Base64 bytes of each input params.inputs names, in the same order")]
    #[serde(default)]
    pub inputs_base64: Option<Vec<String>>,
    #[schemars(
        description = "Verification the answer must carry: 'none' | 'receipt' | 'optimistic' | 'tee'"
    )]
    #[serde(default)]
    pub verification: Option<String>,
    #[schemars(description = "Hex address of a provider to render on, from its announced offer")]
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProvenanceParams {
    #[schemars(description = "32-byte hex content hash (with or without 0x prefix)")]
    pub content_hash: String,
}

// ─── Storage market param structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StorageRetrieveObjectParams {
    #[schemars(description = "Object identifier it was stored under")]
    pub object_id: String,
    #[schemars(
        description = "The reading DID's envelope (hex) for tenzro_storageRetrieveObject over {object_id}; the object's access policy must admit that DID"
    )]
    pub did_envelope: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StorageStoreObjectParams {
    #[schemars(description = "Object identifier")]
    pub object_id: String,
    #[schemars(description = "Owner address (hex), optional")]
    pub owner: Option<String>,
    #[schemars(description = "Object bytes, base64-encoded")]
    pub data: String,
    #[schemars(description = "Erasure-code data shard count (default 4)")]
    pub data_shards: Option<u32>,
    #[schemars(description = "Erasure-code parity shard count (default 2)")]
    pub parity_shards: Option<u32>,
    #[schemars(description = "DID that owns the object and may retrieve it (owner-only)")]
    pub owner_did: String,
    #[schemars(
        description = "The owner DID's envelope (hex) for tenzro_storageStoreObject over every other field given here"
    )]
    pub did_envelope: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StorageSetPricingParams {
    #[schemars(description = "Fixed rate in wei per byte-epoch (decimal string — u128)")]
    pub rate: String,
}

// ─── Compute price feed param structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ComputePriceFeedParams {
    #[schemars(description = "Only this model id")]
    pub model_id: Option<String>,
    #[schemars(
        description = "Only this hardware class: cpu, consumer_gpu, datacenter_gpu or multi_accelerator"
    )]
    pub hardware_class: Option<String>,
    #[schemars(
        description = "Only this region (ISO 3166-1 alpha-2 country code, case-insensitive)"
    )]
    pub region: Option<String>,
    #[schemars(
        description = "Only providers observed by enough distinct validators to be attested"
    )]
    pub attested_only: Option<bool>,
    #[schemars(description = "Maximum rows (default 100, max 1000)")]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ComputeListClaimsParams {
    #[schemars(description = "Claims this address has written or held (hex)")]
    pub party: String,
    #[schemars(description = "Maximum rows (default 100, max 1000)")]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCheckpointCertificateParams {
    #[schemars(description = "Checkpoint index; omit for the latest certificate")]
    pub index: Option<u64>,
    #[schemars(description = "Also return the signer set decoded against the epoch's committee")]
    pub decode: Option<bool>,
}

// ─── MoE serving param structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeModelIdParams {
    #[schemars(description = "Catalog model id")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeExpertRef {
    #[schemars(description = "Layer index")]
    pub layer: u32,
    #[schemars(description = "Expert index within the layer")]
    pub expert: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeTokenRouting {
    #[schemars(description = "Token position index")]
    pub token_index: u32,
    #[schemars(description = "Top-k experts selected for this token")]
    pub experts: Vec<MoeExpertRef>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoePlanDispatchParams {
    #[schemars(description = "Catalog model id")]
    pub model_id: String,
    #[schemars(description = "Per-token top-k routing decisions")]
    pub routings: Vec<MoeTokenRouting>,
    #[schemars(
        description = "Allow routing to experts that are not warm-resident (default false)"
    )]
    pub allow_cold: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeExpertLoadParams {
    #[schemars(description = "Catalog model id")]
    pub model_id: String,
    #[schemars(description = "Layer index")]
    pub layer: u32,
    #[schemars(description = "Expert index within the layer")]
    pub expert: u32,
    #[schemars(
        description = "Base64 safetensors blob with gate_proj/up_proj/down_proj weights (alternative to uri)"
    )]
    pub blob_base64: Option<String>,
    #[schemars(
        description = "Content-addressed tenzro://blob/<hash> URI to fetch the blob from (alternative to blob_base64)"
    )]
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeGateLoadParams {
    #[schemars(description = "Catalog model id")]
    pub model_id: String,
    #[schemars(description = "Layer index")]
    pub layer: u32,
    #[schemars(description = "Base64 safetensors blob with router.weight (alternative to uri)")]
    pub blob_base64: Option<String>,
    #[schemars(
        description = "Content-addressed tenzro://blob/<hash> URI to fetch the blob from (alternative to blob_base64)"
    )]
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoePrepareExpertsParams {
    #[schemars(description = "Catalog model id (must be a MoE entry)")]
    pub model_id: String,
    #[schemars(description = "Layer index to prepare experts for")]
    pub layer: u32,
    #[schemars(
        description = "Expert indices to prepare; omit or empty to prepare every expert in the layer"
    )]
    pub experts: Option<Vec<u32>>,
    #[schemars(
        description = "Publish the layer's gating-network blob alongside the experts (default true)"
    )]
    pub include_gate: Option<bool>,
    #[schemars(
        description = "Block-quantization: a preset string (q4_k_m / q8_0 / q4_k / q6_k) or a per-projection object like {\"gate\":\"q4_k\",\"up\":\"q4_k\",\"down\":\"q6_k\"}. Omit for dense f32 blobs."
    )]
    pub quant: Option<MoeQuantParam>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoePrepareStatusParams {
    #[schemars(description = "Job id returned by moe_prepare_experts")]
    pub job_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoeForwardParams {
    #[schemars(description = "Catalog model id")]
    pub model_id: String,
    #[schemars(description = "Layer index")]
    pub layer: u32,
    #[schemars(description = "Hidden dimension per token")]
    pub d_model: u32,
    #[schemars(description = "Base64 of little-endian f32 hidden states, n_tokens x d_model")]
    pub hidden_states: String,
    #[schemars(
        description = "Experts per token; defaults to the catalog experts_per_token for the model"
    )]
    pub top_k: Option<u32>,
    #[schemars(
        description = "Allow dispatch to experts that are not warm-resident (default false)"
    )]
    pub allow_cold: Option<bool>,
}

// ─── Local discovery / cluster param structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClusterPlanModel {
    #[schemars(description = "Transformer layer count")]
    pub layers: u32,
    #[schemars(description = "Hidden dimension")]
    pub hidden_dim: u32,
    #[schemars(description = "Total model VRAM footprint in GB")]
    pub total_vram_gb: f32,
}

// ─── Tool output structs (structuredContent + outputSchema) ───
//
// Each `#[tool]` handler that returns `Result<Json<T>, ErrorData>` makes
// `T: JsonSchema` available to the rmcp macro, which then emits the schema
// into the tool's `outputSchema` field in `tools/list`. The runtime wraps
// the value in `CallToolResult::structured(value)` — that constructor sets
// both `structuredContent` (typed) and `content[0]: text` (stringified
// summary), exactly as the served MCP revision requires.

/// Output of `send_transaction` — passthrough envelope from
/// `tenzro_sendRawTransaction`. The exact
/// shape is determined by the underlying RPC; common fields include
/// `tx_hash`, `block_hash`, `block_height`, `status`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendTransactionOutput {
    /// Underlying RPC result envelope verbatim.
    pub result: serde_json::Value,
}

/// Generic passthrough envelope for MCP tools that surface arbitrary
/// JSON returned by the underlying JSON-RPC layer or upstream HTTP API.
///
/// Per the served MCP revision, every `#[tool]` handler must return a
/// schema-bearing typed value so the rmcp router can populate
/// `outputSchema` on `tools/list` and emit `structuredContent` on
/// `tools/call`. For tools whose underlying response shape is determined
/// by an external surface (the Tenzro JSON-RPC dispatcher, an L1
/// blockchain RPC, or a SaaS API), `RpcPassthroughOutput` carries the
/// raw `serde_json::Value` verbatim under a single `result` field.
///
/// Tools with a stable, fully-typed response shape (e.g. `get_balance`)
/// define their own dedicated `*Output` struct instead.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RpcPassthroughOutput {
    /// Underlying response payload verbatim.
    pub result: serde_json::Value,
}

/// Any JSON value, for a field whose content the caller chooses: the arguments
/// of a tool the caller defined, or the result of a JSON-RPC method the caller
/// names. Its schema is the recursive JSON value type, not a free-form one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonValue(pub serde_json::Value);

impl schemars::JsonSchema for JsonValue {
    fn schema_name() -> Cow<'static, str> {
        "JsonValue".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let item = generator.subschema_for::<JsonValue>();
        schemars::json_schema!({
            "description": "Any JSON value.",
            "anyOf": [
                { "type": "null" },
                { "type": "boolean" },
                { "type": "number" },
                { "type": "string" },
                { "type": "array", "items": item },
                { "type": "object", "additionalProperties": item }
            ]
        })
    }
}

/// A tool result with a typed schema, under the same `result` envelope as
/// [`RpcPassthroughOutput`]: a tool gains a typed output without changing what
/// its callers read.
#[cfg(feature = "mcp-output-schemas")]
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Typed<T> {
    pub result: T,
}

/// [`Typed`] in a build without `mcp-output-schemas` (the edge build): the
/// same `result` envelope carrying the method's result as it came, described
/// as [`RpcPassthroughOutput`]. Callers read what the full build returns; the
/// per-tool output schemas and the check of each result against its type,
/// which cost the edge binary about 8 MB, are left out.
#[cfg(not(feature = "mcp-output-schemas"))]
#[derive(Debug, Serialize)]
pub struct Typed<T> {
    pub result: serde_json::Value,
    #[serde(skip)]
    shape: std::marker::PhantomData<fn() -> T>,
}

#[cfg(not(feature = "mcp-output-schemas"))]
impl<T> schemars::JsonSchema for Typed<T> {
    fn schema_name() -> Cow<'static, str> {
        RpcPassthroughOutput::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RpcPassthroughOutput::json_schema(generator)
    }
}

/// A model taken out of one of this node's runtimes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelUnloaded {
    /// The model named.
    pub model_id: String,
    /// Whether it was loaded and is now removed.
    pub removed: bool,
}

/// Whether a model's files matched a verified provenance manifest when loaded.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoadProvenanceOutput {
    /// `verified` or `unverified`.
    pub status: String,
    /// The verified manifests the files matched, as `tenzro:model:<root>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifests: Option<Vec<String>>,
}

/// A model loaded into one of this node's runtimes. Which shape fields are
/// present depends on the runtime.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelLoadedOutput {
    pub model_id: String,
    pub loaded: bool,
    /// Where its files are on this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LoadProvenanceOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Input image side, pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_classes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_audio_seconds: Option<u64>,
    /// Output sample rate, Hz.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_horizon: Option<u64>,
    /// The image encoder a video model pools frames from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_frames: Option<u64>,
}

/// A list of catalog rows of one model type.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogOutput<R> {
    pub models: Vec<R>,
}

/// A catalog row: the entry's own fields, then the licence the signed catalog
/// states for it, when it states one.
macro_rules! catalog_row {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
        pub struct $name {
            $($(#[$fm])* pub $f: $t,)*
            /// The licence's name.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub license: Option<String>,
            /// The licence's SPDX or catalog id.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub license_id: Option<String>,
            /// permissive, attribution, commercial_custom or non_commercial.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub license_tier: Option<String>,
            /// Conditions the licence attaches to use.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub license_conditions: Option<String>,
            /// Whether the licence permits paid serving.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub paid_serving: Option<bool>,
            /// Whether the weights are gated at their source.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub gated: Option<bool>,
        }
    };
}

catalog_row! {
    /// An image encoder in the catalog.
    VisionCatalogRow { id: String, name: String, family: String, hf_repo: String, hf_filename: String, input_size: u32, embedding_dim: u64, normalization: String, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// A time-series forecaster in the catalog.
    ForecastCatalogRow { id: String, name: String, family: String, hf_repo: String, hf_filename: String, context_length: u64, max_horizon: u64, n_quantiles: u64, #[serde(default, skip_serializing_if = "Option::is_none")] output_name: Option<String>, batch_size: u64, parameters: String, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// A point- or box-promptable segmentation model in the catalog.
    SegmentationCatalogRow { id: String, name: String, family: String, hf_repo: String, encoder_filename: String, decoder_filename: String, input_size: u32, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// A text-promptable segmentation model in the catalog.
    TextSegmentationCatalogRow { id: String, name: String, family: String, hf_repo: String, image_encoder_filename: String, language_encoder_filename: String, decoder_filename: String, tokenizer_filename: String, input_size: u32, context_length: u32, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// An object detector in the catalog.
    DetectionCatalogRow { id: String, name: String, family: String, hf_repo: String, hf_filename: String, input_size: u32, num_classes: u32, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// A speech recognizer in the catalog.
    AudioCatalogRow { id: String, name: String, family: String, hf_repo: String, encoder_filename: String, #[serde(default, skip_serializing_if = "Option::is_none")] decoder_filename: Option<String>, #[serde(default, skip_serializing_if = "Option::is_none")] preprocessor_filename: Option<String>, tokenizer_filename: String, sample_rate: u32, max_audio_seconds: u32, languages: Vec<String>, size_bytes: u64, min_ram_gb: u32, description: String }
}

catalog_row! {
    /// A video encoder in the catalog.
    VideoCatalogRow { id: String, name: String, family: String, hf_repo: String, hf_filename: String, frame_size: u32, num_frames: u32, fps: u32, embedding_dim: u32, size_bytes: u64, min_ram_gb: u32, description: String }
}

/// A sign-in challenge for an access token.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessChallengeOutput {
    /// Names the challenge in the sign-in that answers it.
    pub challenge_id: String,
    /// The challenge bytes, base64url without padding.
    pub challenge: String,
    /// What the device signs, hex.
    pub device_digest: String,
    /// Seconds until the challenge lapses.
    pub expires_in: u64,
}

/// Gossip counters of this node's network service.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NetworkStatsOutput {
    /// Whether the network service is running; the counters are absent when not.
    pub available: bool,
    /// Why the counters are unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_rejected_invalid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_rejected_duplicate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_published: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers_connected: Option<u64>,
}

/// An address's governance weight: its bonded stake against the total.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VotingPowerOutput {
    /// The address asked about, as given.
    pub address: String,
    /// Its bonded stake, wei, decimal string.
    pub voting_power: String,
    /// All bonded stake, wei, decimal string.
    pub total_bonded: String,
}

/// One disbursement of sponsorship or a grant.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryPayoutRecord {
    /// Position in the log, from zero.
    pub n: u64,
    /// `bond_sponsorship`, `running_cost` or `grant`.
    pub kind: String,
    /// Who received it, hex.
    pub recipient: String,
    /// `validator`, `provider`, `developer`, `contributor` or `community`.
    pub class: String,
    /// How much, wei, decimal string.
    pub amount: String,
    /// The proposal that enacted or released it.
    pub proposal_id: String,
    /// The milestone or the verified hours it was paid against.
    pub milestone: String,
    /// When it was paid, ms.
    pub at_ms: i64,
}

/// The governed caps on sponsorship and grants; 0 disables.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryPayoutCaps {
    /// Whole TNZO sponsorship may commit in a 365-day period.
    pub sponsorship_yearly_max_tnzo: u64,
    /// Wei one verified-available hour backs in a running-cost payment.
    pub running_cost_per_verified_epoch_wei: u64,
    /// Whole TNZO one grantee may be paid in a 365-day period.
    pub per_grantee_yearly_max_tnzo: u64,
    /// Whole TNZO sponsorship and grants may pay together in a 365-day period.
    pub combined_yearly_max_tnzo: u64,
}

/// What an operator was approved on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OperatorCriteriaOutput {
    pub provider_did: String,
    pub region: String,
    pub history_from_epoch: u64,
    pub history_to_epoch: u64,
    pub independence: String,
    pub link: String,
}

/// An approved operator.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OperatorApprovalOutput {
    /// `validator` or `provider`.
    pub class: String,
    pub criteria: OperatorCriteriaOutput,
    /// Verified-available hours the chain counted in the history named.
    pub verified_epochs: u64,
    pub hardware_attested: bool,
    pub approved_ms: i64,
    pub proposal_id: String,
    pub revoked: bool,
}

/// What a grantee was approved on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GranteeCriteriaOutput {
    pub summary: String,
    pub link: String,
}

/// An approved grantee.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GranteeApprovalOutput {
    /// `developer`, `contributor` or `community`.
    pub class: String,
    pub criteria: GranteeCriteriaOutput,
    pub approved_ms: i64,
    pub proposal_id: String,
    pub revoked: bool,
}

/// One address: its approvals and what it has been paid.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryPayoutAddress {
    pub address: String,
    /// Wei paid to it over all time, decimal string.
    pub total_received: String,
    pub operator: Option<OperatorApprovalOutput>,
    pub grantee: Option<GranteeApprovalOutput>,
}

/// Every disbursement of treasury sponsorship and grants.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TreasuryPayoutsOutput {
    /// Disbursements logged so far.
    pub count: u64,
    /// Wei paid per class, decimal strings.
    pub by_class: std::collections::BTreeMap<String, String>,
    /// The page asked for, oldest first.
    pub records: Vec<TreasuryPayoutRecord>,
    pub caps: TreasuryPayoutCaps,
    /// Present when an address was asked about.
    pub address: Option<TreasuryPayoutAddress>,
}

/// A validator's governance-sponsored bond: the treasury TNZO an enacted
/// proposal bonded on its behalf, against the part the validator put up.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SponsoredBondOutput {
    /// The address asked about, as given.
    pub address: String,
    /// The whole bond, wei, decimal string.
    pub bonded: String,
    /// The part the validator put up itself, the part that votes, wei, decimal string.
    pub own_bonded: String,
    /// The part bonded on its behalf by an enacted proposal, wei, decimal string.
    pub sponsored_bonded: String,
    /// Sponsored stake recalled or exiting and still slashable, wei, decimal string.
    pub sponsored_unbonding: String,
    /// Sponsored stake out network-wide, wei, decimal string.
    pub sponsored_outstanding_total: String,
    /// The governed per-validator cap, whole TNZO (0 disables sponsorship).
    pub max_per_validator_tnzo: u64,
    /// The governed network-wide cap, whole TNZO (0 disables sponsorship).
    pub max_total_tnzo: u64,
}

/// This node's hybrid X25519 + ML-KEM-768 key for sealed-model envelopes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRecipientKeyOutput {
    /// The hybrid X25519 + ML-KEM-768 public key, hex (1216 bytes).
    pub recipient_key: String,
    /// The envelope's key-wrapping algorithm.
    pub wrap_alg: String,
}

/// How many nodes hold each MoE expert.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeReplicationPolicyOutput {
    pub min_replication: u32,
    pub max_replication: u32,
    /// Tokens per second above which an expert counts as hot.
    pub hot_threshold_tps: u32,
}

/// A USD price stated in TNZO at the chain's rate.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QuoteResourceOutput {
    /// Always `TNZO`.
    pub asset: String,
    /// Wei, decimal string.
    pub amount: String,
    /// The USD price asked about, in millionths.
    pub usd_e6: u64,
}

/// The version the access policy was stored as.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessPolicyVersionOutput {
    pub version: u64,
}

/// The SLA fault detector's parameters.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlaParamsOutput {
    /// What an unavailability fault costs a provider, wei, decimal string.
    pub unavailable_penalty_wei: String,
    /// The VRF key that picks probe targets, `0x` hex.
    pub vrf_pubkey: String,
}

/// This node's storage-provider state.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StorageStatusOutput {
    pub is_storage_provider: bool,
    /// Its storage rate, wei, decimal string.
    pub effective_rate_wei: String,
    /// Objects it stores.
    pub object_count: u64,
}

/// Whether a regulated token's transfers are halted.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KillSwitchOutput {
    /// The token, `0x` hex.
    pub token_id_hex: String,
    /// True while its transfers are halted.
    pub active: bool,
}

/// A machine-access grant as recorded.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineAccessGrantOutput {
    pub grant_id: String,
    pub owner_did: String,
    pub grantee_did: String,
    /// When the grant lapses, RFC 3339.
    pub not_after: String,
}

/// Whether a token transfer would pass the token's policy now.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CanTransferOutput {
    pub allowed: bool,
    /// The refusal's code, when refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u8>,
    /// Why it would be refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A model removed from this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelDeletedOutput {
    pub success: bool,
    pub model_id: String,
    /// Always `deleted`.
    pub status: String,
}

/// An identity erased from this node's registry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityForgottenOutput {
    pub did: String,
    /// Always `erased`.
    pub status: String,
    pub note: String,
}

/// One proof of a zero-knowledge statement.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkProofOutput {
    /// The proving system.
    pub system: String,
    /// The proof, `0x` hex.
    pub proof: String,
    pub proof_size_bytes: u64,
}

/// A statement proved under one or more proving systems.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreateZkProofOutput {
    pub circuit_id: String,
    /// Public inputs, `0x` hex each.
    pub public_inputs: Vec<String>,
    /// Commitment to the circuit and its public inputs, `0x` hex.
    pub statement_commitment: String,
    pub proofs: Vec<ZkProofOutput>,
}

/// Whether a ZK commitment has been attested to this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ZkAttestationOutput {
    /// The commitment, `0x` hex.
    pub commitment_hex: String,
    pub attested: bool,
}

/// Whether a Permit2 nonce is spent.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Permit2NonceOutput {
    /// The owner, `0x` hex, 20 bytes.
    pub owner: String,
    /// The nonce, `0x` hex, 32 bytes.
    pub nonce: String,
    pub used: bool,
}

/// A Permit2 transfer signature verified and its nonce spent.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Permit2ConsumedOutput {
    pub verified: bool,
    pub consumed: bool,
    /// `0x` hex, 20 bytes.
    pub owner: String,
    /// `0x` hex, 20 bytes.
    pub spender: String,
    /// `0x` hex, 20 bytes.
    pub token: String,
    /// `0x` hex, 32 bytes.
    pub amount: String,
    /// `0x` hex, 32 bytes.
    pub nonce: String,
    /// Unix seconds.
    pub deadline: u64,
    /// The EIP-712 digest signed, `0x` hex.
    pub digest: String,
}

/// A JWT revoked with its delegation chain.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JwtRevokedOutput {
    pub jti: String,
    /// Always `revoked`.
    pub status: String,
    pub cascade: String,
}

/// A machine-access grant revoked.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineAccessRevokedOutput {
    pub grant_id: String,
    /// RFC 3339.
    pub revoked_at: Option<String>,
}

/// The access tokens revoked, by id.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessTokensRevokedOutput {
    pub revoked: Vec<String>,
}

/// A ledger settlement of a payer-signed payment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettlementOutput {
    /// The `PayerSettle` transaction.
    pub tx_hash: String,
    /// `settled` once it executed, else `pending`.
    pub status: String,
    /// What the payer is debited, wei, decimal string.
    pub amount: String,
    /// The network's settlement fee out of it, wei, decimal string.
    pub network_fee: String,
    /// What the payee is credited, wei, decimal string.
    pub payee_credit: String,
    /// The payment record's reference, hex.
    pub pay_ref: String,
    /// `0x` hex.
    pub payer: String,
    /// `0x` hex.
    pub payee: String,
    pub payment_id: String,
}

/// A channel voucher the serving node signed for a delegated agent.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteChannelVoucherOutput {
    pub agent_did: String,
    /// CAIP-2 chain id.
    pub chain: String,
    pub channel_id: u64,
    /// Wei, decimal string.
    pub cumulative_amount: String,
    /// What was signed, hex.
    pub digest: String,
    /// P-256 `r||s`, hex.
    pub signature: String,
    /// The node's P-256 key, uncompressed SEC1 hex.
    pub public_key: String,
    pub operator_did: String,
    pub machine_did: String,
}

/// An SLA probe a provider must answer before its deadline.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlaProbeOutput {
    /// `0x` hex.
    pub issuer: String,
    pub provider_did: String,
    pub epoch: u64,
    pub round: u64,
    /// `0x` hex.
    pub challenge_nonce: String,
    pub deadline_ms: i64,
}

/// A probe issued now, with the VRF key that chose it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlaIssuedProbeOutput {
    /// `0x` hex.
    pub issuer: String,
    pub provider_did: String,
    pub epoch: u64,
    pub round: u64,
    /// `0x` hex.
    pub challenge_nonce: String,
    pub deadline_ms: i64,
    /// `0x` hex.
    pub vrf_pubkey: String,
}

/// The probes not yet answered.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlaProbesOutput {
    pub count: u64,
    pub probes: Vec<SlaProbeOutput>,
}

/// A model withdrawn from serving.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStoppedOutput {
    pub success: bool,
    pub model_id: String,
    /// Always `stopped`.
    pub status: String,
}

/// An object rebuilt from its shards.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StoredObjectOutput {
    pub object_id: String,
    pub size_bytes: u64,
    /// The object, base64.
    pub data: String,
}

/// The storage rate after setting it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StoragePricingOutput {
    /// Always `fixed`.
    pub mode: String,
    /// Wei per byte-epoch, decimal string.
    pub effective_rate_wei: String,
}

/// An object erasure-coded and stored.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObjectStoredOutput {
    pub object_id: String,
    pub size_bytes: u64,
    pub data_shards: u64,
    pub parity_shards: u64,
    pub descriptor_digest: String,
}

/// A reserve attestation recorded.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReserveAttestedOutput {
    pub asset_id: String,
    /// Decimal string.
    pub reserves: String,
    pub source: String,
}

/// The amount of a regulated token frozen on an account.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FrozenTokensOutput {
    /// Base units, decimal string.
    pub frozen_amount: String,
    /// `0x` hex.
    pub token_id_hex: String,
    /// `0x` hex.
    pub account_hex: String,
}

/// Whether a composite signature verifies, and whether its ML-DSA leg did.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignatureCheckOutput {
    pub valid: bool,
    pub pq_leg_verified: bool,
    /// Whether the key carries an ML-DSA key.
    pub pq_enrolled: bool,
}

/// Whether a VRF proof verifies, with its output when it does.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VrfCheckOutput {
    pub valid: bool,
    /// `0x` hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Cosine similarity of an image and a text embedding.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SimilarityOutput {
    pub similarity: f64,
    /// The embedding dimension.
    pub dim: u64,
}

/// Whether an identity's devices can hold a wallet.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WalletReadinessOutput {
    pub identity_did: String,
    pub ready: bool,
    /// Why not, when not.
    pub blocker: Option<String>,
    /// `bind_second_device` or `bind_independent_device`, when not ready.
    pub remedy: Option<String>,
    pub bound_devices: u64,
    pub independent_roots: u64,
    pub hardware_bound_devices: u64,
}

/// A challenge a passkey answers to authorize one custody operation.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CustodyChallengeOutput {
    pub challenge_id: String,
    /// The digest to sign, `0x` hex.
    pub challenge_hex: String,
    /// The same digest as a WebAuthn challenge, base64url.
    pub webauthn_challenge: String,
    /// The custody account, `0x` hex.
    pub account_address: String,
    /// The operation authorized.
    pub operation: String,
    /// `0x` hex.
    pub target_hex: String,
    /// `0x` hex.
    pub nonce_hex: String,
    pub chain_id: u64,
    pub expires_in_secs: u64,
}

/// Bytes fetched by their Tenzro URI.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlobFetchedOutput {
    pub tenzro_uri: String,
    pub size_bytes: u64,
    /// The bytes, base64.
    pub bytes_b64: String,
}

/// Bytes published to this node's blob store.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlobPublishedOutput {
    pub tenzro_uri: String,
    pub size_bytes: u64,
}

/// The confidential-compute hardware on this machine.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DetectTeeOutput {
    pub available: bool,
    pub vendor: Option<String>,
    pub available_vendors: Vec<String>,
}

/// A token's registry entry and supply.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenInfoOutput {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    /// Base units, decimal string.
    pub total_supply: String,
    pub token_type: String,
    pub evm_address: Option<String>,
    /// The ERC-20 facade's address, `0x` hex.
    pub erc20_facade: String,
    pub svm_mint: Option<String>,
    pub tempo_address: Option<String>,
    /// `0x` hex.
    pub creator: String,
}

/// A balance in wei at 18 decimals.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeiBalance {
    /// Decimal string.
    pub balance_wei: String,
    pub decimals: u8,
}

/// A balance in SPL base units.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SplBalance {
    /// Decimal string.
    pub balance_base_units: String,
    pub decimals: u8,
}

/// One TNZO balance as each VM presents it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenBalanceOutput {
    pub address: String,
    pub native: WeiBalance,
    pub evm_wtnzo: WeiBalance,
    pub svm_wtnzo: SplBalance,
}

/// Burned TNZO by source, wei, decimal strings.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BurnBreakdown {
    pub base_fee: String,
    pub local_fee: String,
    pub total: String,
}

/// TNZO supply added, by source, wei, decimal strings. TNZO supply is fixed
/// at genesis and the ledger refuses a block that adds to it, so every
/// figure is 0; pool-paid rewards move existing TNZO and are not counted.
/// The field names are kept for existing readers.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmissionBreakdown {
    pub staking_rewards: String,
    pub treasury_emissions: String,
    pub total: String,
}

/// The supply metrics the adaptive burn reads.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SupplyMetricsOutput {
    pub block_height: u64,
    pub captured_at_ms: i64,
    /// Wei, decimal string.
    pub circulating_supply: String,
    /// Wei, signed decimal string.
    pub epoch_supply_delta: String,
    pub rolling_window_supply_delta_bps: i32,
    pub burn_breakdown: BurnBreakdown,
    pub emission_breakdown: EmissionBreakdown,
}

/// What the adaptive burn would change, and the metrics it read.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BurnRecommendationOutput {
    pub action: String,
    pub is_alarm: bool,
    pub magnitude_bps: i32,
    pub above_proposal_floor: bool,
    pub deviation_bps: i32,
    pub basis: SupplyMetricsOutput,
}

/// This node's OAuth 2.1 authorization-server metadata.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OAuthDiscoveryOutput {
    pub issuer: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub authorization_details_types_supported: Vec<String>,
    pub aap_claims_supported: Vec<String>,
}

/// How each fee divides between burn and treasury, basis points.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BurnSplitConfig {
    pub base_fee_burn_bps: u16,
    pub base_fee_treasury_bps: u16,
    pub local_fee_burn_bps: u16,
    pub local_fee_treasury_bps: u16,
}

/// The supply targets the adaptive burn steers toward.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BurnTargetsConfig {
    pub enabled: bool,
    pub epoch_neutral_band_bps: u16,
    pub rolling_window_epochs: u32,
    /// Supply-increase alarm threshold, bps; any increase is refused by the
    /// ledger, so it fires only on a fault.
    pub inflation_alarm_bps: u16,
    pub deflation_alarm_bps: u16,
    pub target_annual_supply_bps: i32,
    pub gain_bps_per_pct: u16,
    pub magnitude_cap_normal_bps: u16,
    pub magnitude_cap_alarm_bps: u16,
    pub auto_proposal_min_magnitude_bps: u16,
    pub alarm_fast_track_enabled: bool,
}

/// The adaptive burn's configuration.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BurnConfigOutput {
    pub config: BurnSplitConfig,
    pub targets: BurnTargetsConfig,
}

/// A registered token and its supply.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenSummaryOutput {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    /// Base units, decimal string.
    pub total_supply: String,
    pub evm_address: Option<String>,
    pub svm_mint: Option<String>,
    pub tempo_address: Option<String>,
}

/// The registered tokens.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokensOutput {
    pub count: u64,
    pub tokens: Vec<TokenSummaryOutput>,
}

/// A mixture-of-experts layout as the catalog states it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeShapeOutput {
    pub num_experts: u32,
    pub experts_per_token: u8,
    pub shared_experts: u32,
    /// Parameters per expert in tenths of a billion.
    pub params_per_expert_x10: Option<u32>,
}

/// Whether a catalog model is a mixture of experts, and its layout.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeCatalogShapeOutput {
    pub model_id: String,
    pub is_moe: bool,
    pub moe: Option<MoeShapeOutput>,
    pub architecture: String,
}

/// The network insurance pool from chain state.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InsurancePoolOutput {
    /// `0x` hex.
    pub vault: String,
    /// Wei, decimal strings from here on.
    pub balance_wei: String,
    pub claims_paid: u64,
    pub total_paid_wei: String,
    pub from_fees_wei: String,
    pub from_slashes_wei: String,
    /// The most one claim may take now.
    pub max_claim_wei: String,
}

/// One expert blob a prepare job published.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoePreparedExpertOutput {
    pub expert: u32,
    pub uri: String,
    pub bytes: u64,
    /// The coarsest quant tag of the blob; absent when it is dense f32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
}

/// The gating-network blob a prepare job published.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoePreparedGateOutput {
    pub uri: String,
    pub bytes: u64,
}

/// An expert-extraction job as it stands.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoePrepareJobOutput {
    pub model_id: String,
    pub layer: u32,
    /// running, completed or failed.
    pub state: String,
    pub error: Option<String>,
    pub total_experts: u32,
    pub completed_experts: u32,
    pub experts: Vec<MoePreparedExpertOutput>,
    pub gate: Option<MoePreparedGateOutput>,
}

/// An MoE expert loaded on this host.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeLoadedExpertOutput {
    pub model_id: String,
    pub layer: u32,
    pub expert: u32,
    pub d_model: u32,
    pub d_ff: u32,
    pub approx_bytes: u64,
    /// memory or disk.
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

/// An MoE gating network loaded on this host.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeLoadedGateOutput {
    pub model_id: String,
    pub layer: u32,
    pub num_experts: u32,
    pub d_model: u32,
    pub approx_bytes: u64,
}

/// The MoE experts and gates this host holds, and its memory tier.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeExpertStatusOutput {
    pub experts: Vec<MoeLoadedExpertOutput>,
    pub gates: Vec<MoeLoadedGateOutput>,
    pub total_bytes: u64,
    pub memory_bytes: u64,
    pub memory_budget_bytes: u64,
    pub memory_experts: u32,
    pub disk_experts: u32,
    pub compute_backend: String,
    pub gpu: bool,
    pub evicted_to_disk: u64,
    pub evicted_dropped: u64,
    pub admissions_over_budget: u64,
    /// Measured expert-forward throughput, tokens per second.
    pub measured_tps: u32,
}

/// The inference router's counters since start.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouterMetricsOutput {
    pub requests: u64,
    /// Second requests sent when the first ran slow.
    pub hedges_dispatched: u64,
    /// Hedges that answered first.
    pub hedges_won: u64,
    pub deadline_exceeded: u64,
}

/// A data-availability possession challenge.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaChallengeOutput {
    /// `0x` hex.
    pub id: String,
    /// The blob commitment, `0x` hex.
    pub commitment: String,
    pub target_index: u64,
    /// `0x` hex.
    pub target_address: String,
    /// `0x` hex.
    pub nonce: String,
    pub issued_at_ms: i64,
    pub resolved_at_ms: i64,
    /// passed, failed_no_response, failed_not_held or failed_bad_proof.
    pub outcome: String,
}

/// Recorded possession challenges.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaChallengesOutput {
    pub count: u64,
    pub challenges: Vec<DaChallengeOutput>,
}

/// A committee member's possession record.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaAvailabilityOutput {
    /// `0x` hex.
    pub address: String,
    pub score: u32,
    pub max_score: u32,
    pub passes: u64,
    pub failures: u64,
    pub last_outcome: String,
    pub last_challenge_ms: i64,
}

/// One data-availability committee member.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaMemberOutput {
    pub index: u64,
    /// `0x` hex.
    pub address: String,
    pub is_local: bool,
    /// Its possession record, once challenged.
    pub availability: Option<DaAvailabilityOutput>,
}

/// The data-availability committee as this node sees it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaCommitteeOutput {
    /// `0x` hex.
    pub local_address: String,
    pub count: u64,
    pub members: Vec<DaMemberOutput>,
}

/// A blob's availability certificate.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaCertificateOutput {
    pub attesting_indices: Vec<u64>,
    pub quorum: u64,
    pub certified_at_ms: i64,
    /// `0x` hex.
    pub root: String,
}

/// A blob this node knows of.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaBlobOutput {
    /// `0x` hex.
    pub commitment: String,
    /// The sliver this node holds, if any.
    pub held_sliver_index: Option<u64>,
    pub blob_len: Option<u64>,
    pub certificate: Option<DaCertificateOutput>,
}

/// The blobs this node knows of.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaBlobsOutput {
    pub count: u64,
    pub blobs: Vec<DaBlobOutput>,
}

/// A validator as the validator registry records it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ValidatorEntryOutput {
    pub address: String,
    /// Hex.
    pub ml_dsa_pubkey: String,
    /// Hex.
    pub p256_pubkey: String,
    /// Hex.
    pub node_key: String,
    pub withdrawal_address: String,
    /// Wei, decimal string.
    pub self_stake: String,
    pub status: String,
    pub registered_at_epoch: u64,
    pub activated_at_epoch: Option<u64>,
    pub exited_at_epoch: Option<u64>,
    pub jailed_until_epoch: Option<u64>,
    /// Hex.
    pub tee_attestation_hash: Option<String>,
    pub metadata_uri: String,
    /// Unix ms.
    pub updated_at: i64,
}

/// Validators from the registry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ValidatorsOutput {
    pub count: u64,
    pub validators: Vec<ValidatorEntryOutput>,
}

/// A bonded endpoint serving one network role.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleEndpointOutput {
    /// `0x` hex.
    pub account: String,
    pub url: String,
    /// Wei, decimal string.
    pub bonded: String,
}

/// The bonded endpoints of one role.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleEndpointsOutput {
    pub role: String,
    pub endpoints: Vec<RoleEndpointOutput>,
}

/// One JSON-RPC method in the directory.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RpcMethodOutput {
    pub method: String,
    /// admin, owner or open.
    pub gate: String,
    /// The class the access policy decides it under.
    pub class: String,
    pub namespace: String,
}

/// The JSON-RPC methods matching a filter.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RpcMethodsOutput {
    pub methods: Vec<RpcMethodOutput>,
    pub count: u64,
    /// Every method this node dispatches.
    pub total: u64,
    pub namespaces: Vec<String>,
}

/// A state snapshot this node holds.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotSummaryOutput {
    pub height: u64,
    pub state_root: String,
    /// The manifest's blob hash.
    pub manifest_blob: String,
    pub buckets: u64,
}

/// The state snapshots this node holds, and the endpoint that serves them.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotsOutput {
    pub snapshots: Vec<SnapshotSummaryOutput>,
    pub endpoint_id: Option<String>,
}

/// A sealed model's manifest, summarised.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedModelSummaryOutput {
    pub model_id: String,
    pub artifact_name: String,
    /// Hex.
    pub model_hash: String,
    /// Hex.
    pub manifest_hash: String,
    pub total_bytes: u64,
    pub shard_count: u64,
    /// The DIDs it is sealed to.
    pub recipients: Vec<String>,
    pub wrap_alg: String,
    pub owner_did: String,
    /// When it was sealed.
    pub created_at: u64,
}

/// The sealed models this node stores.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedModelsOutput {
    pub count: u64,
    pub sealed_models: Vec<SealedModelSummaryOutput>,
}

/// A passkey device bound to an identity.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BoundDeviceOutput {
    pub credential_id: String,
    pub label: String,
    /// The authenticator model, hex.
    pub aaguid: String,
    pub hardware_bound: bool,
    pub attestation_format: String,
    pub key_protection: String,
    pub chain_verified: bool,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub sign_count: u32,
    pub sign_count_meaningful: bool,
    pub bound_at_ms: u64,
}

/// The devices bound to an identity, and whether they can hold a wallet.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BoundDevicesOutput {
    pub identity_did: String,
    pub count: u64,
    pub independent_roots: u64,
    pub hardware_bound_count: u64,
    pub wallet_ready: bool,
    pub wallet_blocker: Option<String>,
    pub devices: Vec<BoundDeviceOutput>,
}

/// A home relay and whether this node holds a connection to it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RelayLinkOutput {
    pub url: String,
    pub connected: bool,
}

/// A peer that forwards for this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerRelayOutput {
    pub endpoint: String,
    pub rtt_ms: u64,
    pub direct: bool,
}

/// How this node is reachable from outside.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectivityOutput {
    /// public, port_mapped, hole_punch, peer_relay or relay.
    pub reachability: String,
    /// unknown, none, endpoint_independent or endpoint_dependent.
    pub nat: String,
    /// Peers that reported this node's address.
    pub observers: u64,
    pub port_mapped: bool,
    pub external_addresses: u64,
    pub ipv4: bool,
    pub ipv6: bool,
    pub relays: Vec<RelayLinkOutput>,
    /// Paths opened by hole punching.
    pub punched_paths: u64,
    pub peer_relays: Vec<PeerRelayOutput>,
}

/// Where an intent routes: the model, its tier and cost, and the provider.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteDecisionOutput {
    pub model_id: String,
    /// The quality tier, lowercase.
    pub tier: String,
    /// Wei, decimal string.
    pub estimated_cost: String,
    pub alternates: Vec<String>,
    /// The difficulty cluster the request fell in.
    pub cluster: Option<u32>,
    /// The cluster's expected error rate for the chosen model.
    pub expected_error: Option<f64>,
    /// Hex.
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub reason: String,
}

/// What the access policy decides for a caller.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AccessDecisionOutput {
    /// Admitted, under a named tier when one applies.
    Allow { tier: Option<String>, named: bool },
    /// Admitted on payment: via x402 or channel, at the price, in the asset.
    Pay {
        via: String,
        price: String,
        asset: String,
    },
    /// Refused, and why.
    Refuse { reason: String },
}

/// How the access policy treats a caller on a surface and method class.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessPreviewOutput {
    pub surface: String,
    pub class: String,
    /// The caller's DID, when it named one.
    pub caller: Option<String>,
    pub result: AccessDecisionOutput,
}

/// How long each class of data-availability object is retained, ms.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaRetentionWindows {
    pub history: i64,
    pub audit: i64,
}

/// Totals over every data-availability object recorded.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaStatsOutput {
    pub live_objects: u64,
    pub live_bytes: u64,
    pub expired_objects: u64,
    pub expired_bytes: u64,
}

/// Where expiry stands: the next day swept, and how far into it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaSweepOutput {
    pub day: u64,
    pub position: u64,
}

/// The data-availability retention rules and where expiry stands.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaRetentionOutput {
    pub retention_ms: DaRetentionWindows,
    pub stats: DaStatsOutput,
    pub sweep: Option<DaSweepOutput>,
}

/// A delegated agent's bond.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentBondOutput {
    pub agent_did: String,
    pub controller_did: String,
    /// Wei, decimal string.
    pub amount: String,
    pub state: String,
    pub cooldown_until_ms: Option<i64>,
    pub vault: String,
}

/// A compute provider's bond.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComputeBondOutput {
    pub provider_did: String,
    pub provider_address: String,
    /// Wei, decimal string.
    pub amount: String,
    pub status: String,
    /// Unix ms.
    pub cooldown_until: Option<i64>,
    pub vault: String,
    pub is_eligible: bool,
    /// Wei, decimal string.
    pub effective_amount: String,
}

/// One value the randomness beacon took.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BeaconEntryOutput {
    pub round: u64,
    pub mix: String,
    pub at_ms: i64,
    pub contributor: String,
}

/// A beacon round asked for, or the beacon's head with its latest value.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum BeaconOutput {
    /// The value of the round or time asked for.
    Entry(BeaconEntryOutput),
    /// The next round, the running mix and the latest value taken.
    Head {
        round: u64,
        mix: String,
        latest: Option<BeaconEntryOutput>,
    },
}

/// A data-availability object as recorded on chain.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaObjectRecord {
    pub commitment: String,
    /// history or audit.
    pub class: String,
    pub size_bytes: u64,
    pub recorder: String,
    pub recorded_at_ms: i64,
    pub expires_at_ms: i64,
    pub expired_at_ms: Option<i64>,
}

/// A data-availability object and whether it is still retained.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DaObjectOutput {
    pub object: DaObjectRecord,
    pub live: bool,
}

/// A relay this node's identity record names.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityRelayOutput {
    pub did: String,
    pub url: String,
}

/// A boot peer and how to reach it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BootPeerOutput {
    pub did: String,
    pub endpoint_id: String,
    pub relays: Vec<String>,
}

/// This node's iroh endpoint and what it serves.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IrohInfoOutput {
    pub endpoint_id: String,
    pub endpoint_id_hex: String,
    pub machine_did: Option<String>,
    pub relays: Vec<IdentityRelayOutput>,
    pub boot_peers: Vec<BootPeerOutput>,
    /// Identity records this node has learned.
    pub known_identities: u64,
    pub docs_enabled: bool,
    /// The ALPN protocols bound on the endpoint.
    pub bound_alpns: Vec<String>,
}

/// An identity registration submitted for replication.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityRegisteredOutput {
    pub did: String,
    /// human or machine.
    pub identity_type: String,
    pub status: String,
    /// The RegisterIdentity transaction.
    pub tx_hash: String,
}

/// Where a token sits in its delegation chain.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DelegationClaimOutput {
    pub depth: u32,
    pub max_depth: u32,
    /// The DIDs from the root to this token's holder.
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_jti: Option<String>,
}

/// A narrower token issued from a parent token.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenExchangedOutput {
    pub access_token: String,
    /// Seconds.
    pub expires_in: u64,
    /// Always `DPoP`.
    pub token_type: String,
    pub issued_token_type: String,
    pub delegation: DelegationClaimOutput,
}

/// A participant's new identity.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParticipantIdentityOutput {
    pub did: String,
    pub identity_type: String,
    pub display_name: String,
    pub status: String,
}

/// A participant's new wallet.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParticipantWalletOutput {
    pub wallet_id: String,
    pub address: String,
    /// The P-256 key, `0x` hex.
    pub public_key: String,
}

/// What a participant may use.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParticipantCapabilitiesOutput {
    pub inference: bool,
    pub payments: bool,
    pub agent_collaboration: bool,
    pub mcp_tools: bool,
    pub task_execution: bool,
    pub chain_query: bool,
    pub smart_contracts: bool,
    pub tee_services: bool,
    pub bridge: bool,
    pub governance: bool,
}

/// The network's public endpoints.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NetworkEndpointsOutput {
    pub rpc: String,
    pub mcp: String,
    pub a2a: String,
}

/// A participant joined as a micro node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParticipantJoinedOutput {
    pub identity: ParticipantIdentityOutput,
    pub wallet: ParticipantWalletOutput,
    pub capabilities: ParticipantCapabilitiesOutput,
    pub origin: String,
    pub participant_type: String,
    /// Always `micro_node`.
    pub role: String,
    pub network: NetworkEndpointsOutput,
}

/// A block's header and size.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlockOutput {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub state_root: String,
    pub tx_root: String,
    /// Unix ms.
    pub timestamp: i64,
    pub proposer: String,
    pub tx_count: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
}

/// A page of blocks and where the next page starts.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlockRangeOutput {
    pub blocks: Vec<BlockOutput>,
    /// The height to ask for next.
    #[serde(rename = "nextHeight")]
    pub next_height: u64,
    /// Whether the chain holds blocks past `nextHeight`.
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
    /// This node's highest block.
    #[serde(rename = "localTip")]
    pub local_tip: u64,
}

/// One provider and model as validators observed it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComputePriceRowOutput {
    /// `0x` hex.
    pub provider: String,
    pub model_id: String,
    /// As the provider announced it.
    pub hardware_class: String,
    /// As the provider announced it.
    pub region: String,
    pub observations: u64,
    pub distinct_observers: u64,
    pub attested: bool,
    pub success_rate_bps: u32,
    pub latency_p50_ms: Option<u64>,
    pub latency_p90_ms: Option<u64>,
    /// Wei, decimal string.
    pub price_per_1k_output_tokens_wei: Option<String>,
    /// Wei, decimal string.
    pub price_per_compute_second_wei: Option<String>,
    pub last_observed_ms: i64,
}

/// Observed compute prices over the observation window.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComputePriceFeedOutput {
    pub window_ms: i64,
    pub min_distinct_observers: u64,
    /// Rows matching, before the limit.
    pub total: u64,
    pub entries: Vec<ComputePriceRowOutput>,
    pub claims_note: String,
}

// ─── Typed tool outputs (end) ───

#[derive(Clone)]
pub struct TenzroMcpServer {
    node: Arc<TenzroNode>,
    _tool_router: ToolRouter<TenzroMcpServer>,
    /// When true, this server instance is serving the raw iroh MCP transport
    /// (`tenzro/mcp` ALPN), which carries NO credential and NO verified peer
    /// identity — the axum-only `bearer_auth_check` / `ServiceSurface::Mcp`
    /// gate does not apply. In that mode `call_tool`/`list_tools` are
    /// restricted, fail-closed, to the read-only tool allowlist
    /// ([`IROH_READONLY_TOOLS`]); every state-changing / admin / operator /
    /// compute / key-management tool — and `chat` — is refused.
    /// `false` on the HTTP MCP path, which behaves exactly as before.
    iroh_readonly: bool,
    /// When true, this instance serves the compact listing at
    /// `/mcp/compact` ([`super::compact`]): `tools/list` names only `search`
    /// and `call`, and a `call` runs the tool it names as a direct call would.
    compact: bool,
}

/// Tools permitted over the unauthenticated iroh MCP transport
/// (`tenzro/mcp`). This is an ALLOWLIST — anything not listed is refused
/// (fail-closed), so the worst case of an omission is a read-only tool
/// being unavailable over iroh (still reachable over the gated HTTP MCP
/// path), never an unintended exposure.
///
/// Membership rule: pure reads / queries / stateless computations only. It
/// deliberately excludes everything that mutates node, chain, provider,
/// stake, model, site/app, or wallet state; executes compute
/// (`chat`, `*_embed`, `forecast`, `detect`, `segment`,
/// `transcribe`, `moe_forward`, agent runs); manages or exposes
/// keys/wallets/passkeys; or reads user file/database contents.
///
/// `chat` is intentionally NOT listed: gated inference already
/// has the properly-credential-gated `tenzro/infer` ALPN, so exposing it
/// here would only re-open an ungated inference bypass. See the module
/// note in `mcp/iroh_transport.rs`.
const IROH_READONLY_TOOLS: &[&str] = &[
    // ── Network / chain / node reads ──
    "get_node_status",
    "get_node_did_document",
    "get_update_notice",
    "get_network_stats",
    "get_block",
    "get_checkpoint_certificate",
    "get_block_range",
    "get_fee_market",
    "get_transaction",
    "get_validator_state",
    "list_validators",
    "list_active_validators",
    "get_router_metrics",
    "get_provenance",
    "get_economic_policy",
    "node_profile",
    "cluster_plan",
    "list_snapshots",
    "get_snapshot_manifest",
    "query_events",
    "verify_event_proof",
    "get_beacon",
    "get_da_object",
    "get_da_retention",
    "settlement_networks",
    "wallet_readiness",
    // ── Balances / tokens (public reads) ──
    "get_balance",
    "token_balance",
    "get_token_balance",
    "total_supply",
    "get_token_info",
    "list_tokens",
    // ── Models / providers (catalog + status reads) ──
    "list_models",
    "list_model_endpoints",
    "list_providers",
    "get_model_provenance",
    "list_catalog",
    "get_catalog_entry",
    "get_engine_releases",
    "get_sealed_model",
    "list_sealed_models",
    "model_recipient_key",
    "get_download_progress",
    "get_provider_stats",
    "get_compute_bond",
    "get_model_stacks",
    "get_provider_pricing",
    "discover_models",
    "route_difficulty_stats",
    // ── MoE (planning + status reads; execute/load/prepare excluded) ──
    "moe_shard_map",
    "moe_plan_dispatch",
    "moe_replication_policy",
    "moe_catalog_shape",
    "moe_expert_status",
    "moe_prepare_status",
    // ── Multi-modal catalogs (loaded models of every type: list_models) ──
    "list_forecast_catalog",
    "list_vision_catalog",
    "list_text_embedding_catalog",
    "list_segmentation_catalog",
    "list_text_segmentation_catalog",
    "list_detection_catalog",
    "list_audio_catalog",
    "list_video_catalog",
    // ── Governance reads ──
    "list_proposals",
    "get_voting_power",
    "get_sponsored_bond",
    "get_treasury_payouts",
    "get_guardian_state",
    "can_transfer",
    // ── Account recovery reads ──
    "list_guardians",
    // ── Tasks / agents / templates / capabilities (reads) ──
    "list_duties",
    "get_duty",
    "verify_evidence",
    "get_agent_bond",
    "get_agent_terms",
    "quote_inference",
    "list_registry",
    "get_registry_entry",
    "get_price_card",
    "get_insurance_pool",
    // ── Identity reads ──
    "resolve_did",
    // ── Payments / fees / bridge quotes (reads + pure quotes) ──
    "quote_bridge_fee_in_tnzo",
    // ── Settlement and escrow reads ──
    "get_reserve",
    "settle_get_netting_batch",
    "settle_get_reconciliation",
    "settle_list_mismatches",
    "get_escrow",
    "list_escrows_by_payer",
    "list_escrows_by_payee",
    // ── Verification / pure-compute helpers (no state, no key material) ──
    "verify_zk_proof",
    "get_zk_attestation",
    "verify_vrf_proof",
    "verify_signature",
    "verify_did_envelope",
    "verify_tee_attestation",
    "detect_tee",
    "list_tee_providers",
    "get_inference_commitment",
    "get_inference_challenge",
    "list_inference_challenges",
    "list_zk_circuits",
    "governance_get",
    "permit2_nonce_used",
    // ── Cross-chain read/quote helpers (send/dispatch/pay excluded) ──
    "list_bridge_routes",
    "get_bridge_route",
    "urwa_is_kill_switched",
    "urwa_get_frozen_tokens",
    // ── ERC-8004 pure ABI encoders/decoders (stateless) ──
    // ── DA / media / burn / SLA (reads) ──
    "da_list_challenges",
    "da_availability",
    "da_committee",
    "da_list_blobs",
    "media_gen_list_catalog",
    "list_bound_devices",
    "adaptive_burn_get_config",
    "adaptive_burn_get_metrics",
    "adaptive_burn_get_recommendation",
    "sla_list_outstanding_probes",
    "sla_get_params",
    // ── Sites / functions / machines / apps / leases / compute / storage (reads) ──
    "compute_list_claims",
    "compute_price_feed",
    "storage_status",
];

/// Whether `tool` may be invoked over the unauthenticated iroh MCP
/// transport. Fail-closed: unknown tool → not permitted.
fn iroh_tool_allowed(tool: &str) -> bool {
    IROH_READONLY_TOOLS.contains(&tool)
}

impl std::fmt::Debug for TenzroMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenzroMcpServer")
            .field("node", &"<TenzroNode>")
            .finish()
    }
}

fn parse_address(input: &str) -> std::result::Result<Address, ErrorData> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(hex_str).map_err(|e| ErrorData {
        code: ErrorCode::INVALID_PARAMS,
        message: Cow::from(format!("Invalid hex address: {}", e)),
        data: None,
    })?;
    if bytes.len() > 32 {
        return Err(ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from("Address too long (max 32 bytes)"),
            data: None,
        });
    }
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    Ok(Address::new(arr))
}

fn err_internal(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

/// Dispatch an RPC call through the node's JSON-RPC handler and return the result.
/// Headers captured at the MCP HTTP boundary (`Authorization` + `DPoP`),
/// plus the inbound HTTP method and URI. The MCP `bearer_auth_check`
/// middleware (in `mcp/oauth.rs`) wraps each `/mcp` request in
/// `MCP_REQUEST_HEADERS::scope(...)` so that tool handlers running inside
/// the same tokio task can pick them up via [`current_request_headers`]
/// and forward them into [`rpc_dispatch`] — letting MCP-originated calls
/// participate in the same DPoP+JWT auth-mediated signing path that
/// direct RPC clients use, without copying the `private_key` over the
/// wire.
#[derive(Debug, Clone, Default)]
pub struct McpRequestHeaders {
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    pub http_method: String,
    pub http_uri: String,
}

tokio::task_local! {
    /// Per-MCP-request headers. Set by the bearer-auth middleware before
    /// the rmcp service runs, read by [`rpc_dispatch`] when constructing
    /// the `AuthContext` for the inner JSON-RPC handler.
    pub static MCP_REQUEST_HEADERS: McpRequestHeaders;
}

/// Snapshot the current task-local request headers. Returns default-empty
/// values when called outside an MCP request scope (e.g. from internal
/// startup code paths) — the auth-mediated signing path will then return
/// `Unauthenticated` and the handler will reject with `-32001`.
fn current_request_headers() -> McpRequestHeaders {
    MCP_REQUEST_HEADERS
        .try_with(|h| h.clone())
        .unwrap_or_default()
}

fn parse_escrow_id(hex_id: &str) -> std::result::Result<[u8; 32], ErrorData> {
    hex::decode(hex_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| err_internal("escrow_id must be 32 bytes of hex"))
}

/// One escrow operation by the calling delegated agent, paid from its own
/// wallet: `tenzro_agentAct` with the caller's access token, so the serving node
/// checks the action against the agent's terms before it signs.
async fn agent_escrow_act(
    node: &Arc<TenzroNode>,
    operation: &str,
    counterparty: &str,
    amount: u128,
    escrow: serde_json::Value,
) -> std::result::Result<Json<Typed<PayAgentActOutput>>, ErrorData> {
    let result = rpc_dispatch(
        node,
        "tenzro_agentAct",
        serde_json::json!({
            "operation": operation,
            "counterparty": counterparty,
            "amount": amount.to_string(),
            "chain": "tenzro",
            "escrow": escrow,
        }),
    )
    .await?;
    typed_result(result)
}

/// The one path by which an MCP tool reaches node state.
///
/// Runs the request through [`crate::rpc::dispatch_embedded`], the same
/// pipeline the HTTP JSON-RPC endpoint uses (access policy, rate limits,
/// dispatch, usage accounting), carrying the inbound MCP request's
/// `Authorization` / `DPoP` headers. A tool therefore has exactly the authority its caller
/// would have calling the JSON-RPC method directly, never more.
///
/// A JSON-RPC error comes back as an MCP error with the same code, so a
/// refusal by the access policy (`-32004`) stays distinguishable to the tool
/// caller.
/// Complete an unsigned request with the `Payment` transaction carrying `op`.
fn payment_request(
    transaction: serde_json::Value,
    op: tenzro_types::settlement::PaymentOp,
) -> std::result::Result<serde_json::Value, ErrorData> {
    typed_request(
        transaction,
        tenzro_types::transaction::TransactionType::Payment { op },
        tenzro_vm::native::GAS_PAYMENT_OP,
    )
}

async fn rpc_dispatch(
    node: &Arc<TenzroNode>,
    method: &str,
    params: serde_json::Value,
) -> std::result::Result<serde_json::Value, ErrorData> {
    let h = current_request_headers();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let auth = crate::rpc::EmbeddedAuth {
        authorization: h.authorization,
        dpop: h.dpop,
        surface: Some(tenzro_types::node_access::Surface::Mcp),
        http_method: Some(h.http_method),
        http_uri: Some(h.http_uri),
    };
    let mut response = crate::rpc::dispatch_embedded(node, payload, auth).await;
    if let Some(err) = response.get_mut("error").filter(|e| !e.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("RPC error")
            .to_string();
        return Err(ErrorData {
            code: ErrorCode(code),
            message: Cow::from(message),
            data: err.get_mut("data").map(serde_json::Value::take),
        });
    }
    Ok(response
        .get_mut("result")
        .map(serde_json::Value::take)
        .unwrap_or(serde_json::Value::Null))
}

/// Drop top-level `null` members, so an optional MCP argument the caller
/// left out reaches the handler as absent rather than as an explicit null
/// (several handlers treat a present key as a choice of request shape).
fn rpc_args(mut args: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = args.as_object_mut() {
        obj.retain(|_, v| !v.is_null());
    }
    args
}

/// The tools whose input is one JSON-RPC method's params, from
/// [`super::rpc_tools::RPC_TOOLS`]: each forwards `params` to its method under
/// the caller's credentials (see [`rpc_dispatch`]) and returns the result as
/// [`RpcPassthroughOutput`].
fn add_rpc_tool_routes(router: &mut ToolRouter<TenzroMcpServer>) {
    use super::rpc_tools::{Access, RPC_TOOLS};
    use rmcp::handler::server::router::tool::ToolRoute;
    let schema: Arc<JsonObject> = Arc::new(
        serde_json::json!({
            "type": "object",
            "properties": {
                "params": {
                    "type": ["object", "array"],
                    "description": "The method's JSON-RPC params, passed unchanged"
                }
            },
            "additionalProperties": false
        })
        .as_object()
        .cloned()
        .unwrap_or_default(),
    );
    for row in RPC_TOOLS {
        let tool = Tool::new(row.name, row.description, schema.clone())
            .with_output_schema::<RpcPassthroughOutput>()
            .with_annotations(ToolAnnotations::new().read_only(row.access == Access::Read));
        let method = row.method;
        router.add_route(ToolRoute::new_dyn(tool, move |ctx| {
            call_rpc_tool(ctx, method)
        }));
    }
}

/// One call of a mirror tool: its `params` argument goes to `method`
/// unchanged and the result comes back as [`RpcPassthroughOutput`].
fn call_rpc_tool<'a>(
    ctx: rmcp::handler::server::tool::ToolCallContext<'a, TenzroMcpServer>,
    method: &'static str,
) -> futures::future::BoxFuture<'a, std::result::Result<CallToolResponse, ErrorData>> {
    let server = ctx.service;
    let params = ctx
        .arguments
        .and_then(|mut args| args.remove("params"))
        .unwrap_or_else(|| serde_json::json!({}));
    Box::pin(async move {
        let result = rpc_dispatch(&server.node, method, params).await?;
        Ok(CallToolResponse::Complete(CallToolResult::structured(
            serde_json::json!({ "result": result }),
        )))
    })
}

/// `value`, a method's result, as the typed output `T`. A result that does not
/// read as `T` is an internal error naming the mismatch.
#[cfg(feature = "mcp-output-schemas")]
fn typed_result<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> std::result::Result<Json<Typed<T>>, ErrorData> {
    serde_json::from_value(value)
        .map(|result| Json(Typed { result }))
        .map_err(|e| err_internal(format!("result does not match its schema: {e}")))
}

/// `value`, a method's result, under the `result` envelope as it came.
#[cfg(not(feature = "mcp-output-schemas"))]
fn typed_result<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> std::result::Result<Json<Typed<T>>, ErrorData> {
    Ok(Json(Typed {
        result: value,
        shape: std::marker::PhantomData,
    }))
}

/// [`rpc_tool`] for a method whose result has the typed shape `T`.
async fn rpc_tool_typed<T: serde::de::DeserializeOwned>(
    node: &Arc<TenzroNode>,
    method: &str,
    args: serde_json::Value,
) -> std::result::Result<Json<Typed<T>>, ErrorData> {
    typed_result(rpc_dispatch(node, method, rpc_args(args)).await?)
}

// ─── App hosting (sites / functions / machines) params ───

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct HostingSiteRoute {
    #[schemars(description = "Request path, e.g. /index.html or /assets/app.js")]
    pub path: String,
    #[schemars(description = "BLAKE3 blob hash of the asset (from iroh publishBlob)")]
    pub blob_hash: String,
    #[schemars(description = "MIME type served in the Content-Type header")]
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Byte length of the asset")]
    pub size: Option<u64>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct ListProvidersParams {
    #[schemars(description = "Keep only model providers of this type, e.g. ai, tee, storage")]
    pub provider_type: Option<String>,
    #[schemars(description = "Most entries on this page (default 50, at most 200)")]
    pub limit: Option<u32>,
    #[schemars(description = "The next_cursor a prior page returned")]
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct VerifyDidEnvelopeParams {
    #[schemars(
        description = "Hex-encoded Tenzro DID envelope (the X-Tenzro-DID-Envelope header value / TenzroDidEnvelope::to_header_value output)"
    )]
    pub envelope: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct ReserveAttestationParams {
    #[schemars(
        description = "ReserveAttestation: {asset_id, reserves, source(issuer|tee|chainlink_por|oracle), attestor_did, attested_at, signature: composite signature (context ReserveAttestation) by the attestor identity's P-256 key, ML-DSA-65 leg once enrolled}"
    )]
    pub attestation: ReserveAttestationRecord,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct GetReserveParams {
    pub asset_id: String,
}

// ─── Passkey-first wallet MCP tool params ───

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct PasskeyEnrollParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub passkey_public_key_hex: String,
    pub credential_id_hex: String,
    #[schemars(
        description = "For a further wallet (salt above 0): proof the caller holds the passkey, challenge_id, credential_id_hex and the assertion over the webauthn_challenge of an enroll_passkey custody challenge"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<CustodyAuthorizationWire>,
    #[schemars(
        description = "The registration's authenticatorData, hex, as navigator.credentials.create() returned it; required for a first wallet"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_authenticator_data_hex: Option<String>,
    #[schemars(
        description = "The relying party the passkey is registered on: the wallet provider's domain"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub salt: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentDelegationChallengeParams {
    #[schemars(description = "The controller's smart account, hex")]
    pub account_address: String,
    #[schemars(description = "delegate_agent, update_agent_terms or revoke_identity")]
    pub operation: String,
    #[schemars(
        description = "The agent's terms (delegate_agent, update_agent_terms): controller_did, agent_name, delegation_scope, capabilities, serving_nodes as [{machine_did, operator_did}], min_distinct_operators, expires_at_ms"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<AgentTermsWire>,
    #[schemars(description = "The agent (update_agent_terms, revoke_identity)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    #[schemars(
        description = "The reason the revocation records (revoke_identity); the approval covers it. Put the same reason in the RevokeIdentity transaction"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[schemars(description = "Also withdraw the agent's live access tokens (update_agent_terms)")]
    #[serde(default)]
    pub rotate_tokens: bool,
    #[schemars(
        description = "For a machine delegated under the controller (delegate_agent): its hardware key, hex; it becomes the single serving node"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_public_key: Option<String>,
    #[schemars(description = "For a machine delegation: its machine id")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct DelegateAgentParams {
    #[schemars(description = "The completed terms the challenge returned, unchanged")]
    pub delegation: PayAgentTerms,
    #[schemars(
        description = "The root's approval of the challenge: a passkey assertion ({challenge_id, credential_id_hex, assertion, ml_dsa_signature_hex}) for a human root, or {challenge_id, signature} with the composite hardware signature over challenge_hex under the account-owner context for a machine root"
    )]
    pub authorization: PayRootApproval,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct UpdateAgentTermsParams {
    pub agent_did: String,
    #[schemars(description = "The completed terms the challenge returned, unchanged")]
    pub delegation: PayAgentTerms,
    #[schemars(description = "Must match the challenge")]
    #[serde(default)]
    pub rotate_tokens: bool,
    #[schemars(
        description = "The root's approval of the challenge: a passkey assertion ({challenge_id, credential_id_hex, assertion, ml_dsa_signature_hex}) for a human root, or {challenge_id, signature} with the composite hardware signature over challenge_hex under the account-owner context for a machine root"
    )]
    pub authorization: PayRootApproval,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentAccountsParams {
    #[schemars(description = "The agent's DID")]
    pub did: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentRemoteGrantParams {
    #[schemars(
        description = "The chain, CAIP-2 (eip155:8453, solana:..., sui:mainnet, aptos:1, stellar:pubnet, cosmos:..., tvm:-239)"
    )]
    pub chain: String,
    #[schemars(
        description = "The grant: caip19, budget, per_action_max, ttl_ms, targets [{target, selector}], payload_hash (exact grants), relay_fee_max"
    )]
    pub grant: PayRemoteGrantRequest,
    #[schemars(description = "The controller's step-up approval, when the terms require one")]
    pub step_up: Option<PayAgentTermsApproval>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentRemoteActParams {
    #[schemars(description = "The chain, CAIP-2")]
    pub chain: String,
    #[schemars(description = "The account's next action nonce on that chain")]
    pub nonce: u64,
    #[schemars(
        description = "The action: target, selector, data (hex), amount, relay_refund (decimal strings)"
    )]
    pub action: PayRemoteAction,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentWalletConsentParams {
    #[schemars(description = "The agent's DID")]
    pub did: String,
    #[schemars(description = "The EVM chain, CAIP-2 (eip155:<id>)")]
    pub chain: String,
    #[schemars(description = "The ERC-8004 agentId")]
    pub agent_id: u64,
    #[schemars(description = "The address that owns the ERC-8004 entry")]
    pub owner: String,
    #[schemars(description = "Unix seconds the consent expires; at most 300 s after it is used")]
    pub deadline: u64,
    #[schemars(description = "The identity registry; the canonical one when absent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct AgentAccountSyncParams {
    #[schemars(description = "The agent's DID")]
    pub did: String,
    #[schemars(description = "The chain, CAIP-2")]
    pub chain: String,
    #[schemars(
        description = "The checkpoint to prove under; the latest certified one when absent"
    )]
    pub checkpoint: Option<u64>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct RevokeDelegatedAgentParams {
    #[schemars(
        description = "A signed RevokeIdentity transaction, as tenzro_sendRawTransaction takes it (envelope, tx_type {\"RevokeIdentity\":{\"op\":{did, reason, approver_did, approval}}}, public_key, signature). Any account may sign it; the root's approval of the revoke_identity challenge inside op authorises the revocation"
    )]
    pub signed_transaction: PaySignedRevokeIdentity,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct MachineAccessChallengeParams {
    #[schemars(
        description = "The change the machine owner will approve: {\"action\":\"add\"} with the grant terms, {\"action\":\"list\"}, or {\"action\":\"revoke\",\"grant_id\":\"...\"}"
    )]
    pub change: MachineAccessChangeWire,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct MachineAccessAddParams {
    #[schemars(
        description = "The node's machine DID for any sandboxed job on it, or an agent or tool DID"
    )]
    pub grantee_did: String,
    #[schemars(
        description = "Resources: {\"kind\":\"network\",\"cidr\":\"10.20.0.0/16\",\"port\":8080} (port optional) or {\"kind\":\"folder\",\"path\":\"/var/lib/tenzro/inbox\"}"
    )]
    pub resources: Vec<MachineResourceWire>,
    #[schemars(description = "connect for networks; read and/or write for folders")]
    pub operations: Vec<String>,
    #[schemars(description = "When the grant ends, in milliseconds since the Unix epoch")]
    pub expires_at_ms: i64,
    pub max_uses_per_minute: Option<u32>,
    #[schemars(description = "Most bytes moved through the grant")]
    pub max_bytes: Option<u64>,
    #[schemars(
        description = "The owner's approval of the challenge from machine_access_challenge: challenge_id, credential_id_hex, assertion over its webauthn_challenge, and ml_dsa_signature_hex when the owner has a hardware ML-DSA-65 key enrolled"
    )]
    pub authorization: Option<CustodyAuthorizationWire>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct MachineAccessListParams {
    #[schemars(description = "The owner's approval of a list challenge")]
    pub authorization: Option<CustodyAuthorizationWire>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct MachineAccessRevokeParams {
    pub grant_id: String,
    #[schemars(description = "The owner's approval of a revoke challenge for this grant")]
    pub authorization: Option<CustodyAuthorizationWire>,
}

// ─── Browser-launch passkey auth sessions (gcloud-style device flow) ───

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct CreatePasskeySessionParams {
    #[schemars(
        description = "Ceremony kind: \"enroll\" (new account), \"add\" (device credential on an existing account), or \"sign\" (verify an assertion over an op hash)."
    )]
    pub kind: String,
    #[schemars(description = "Enroll: optional display name for the new identity.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[schemars(description = "Enroll: CREATE2 salt (defaults to 0).")]
    #[serde(default)]
    pub salt: u64,
    #[schemars(description = "Add + Sign: target smart-account address (hex).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_address: Option<String>,
    #[schemars(description = "Add: display label for the new credential.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[schemars(description = "Sign: 32-byte op hash (hex) the assertion must attest to.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_hash_hex: Option<String>,
    #[schemars(
        description = "Sign: the hardware ML-DSA-65 leg (hex) over the composite representative of the op hash (context UserOperation), for accounts with a hardware ML-DSA-65 key enrolled."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_signature_hex: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct GetPasskeySessionParams {
    #[schemars(
        description = "Session id returned by create_passkey_session. Poll until status is completed/failed/expired."
    )]
    pub session_id: String,
}

// ─── Identity + credential lifecycle (admin-gated) ───

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct RevokeJwtParams {
    #[schemars(description = "JWT id (jti) to revoke. Cascades to any tokens minted from it.")]
    pub jti: String,
    #[schemars(
        description = "Hex DID envelope proving control of the token's bearer DID or of the controller DID that authorized it, bound to method tenzro_revokeJwt with the jti as the params hash. A jti is an identifier, not a credential."
    )]
    pub did_envelope: String,
    #[schemars(description = "Optional human-readable revocation reason.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─── Institutional-primitive Params structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UrwaTokenIdParams {
    #[schemars(description = "32-byte hex-encoded token_id (with or without 0x prefix)")]
    pub token_id_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UrwaFrozenLookupParams {
    #[schemars(description = "32-byte hex-encoded token_id (with or without 0x prefix)")]
    pub token_id_hex: String,
    #[schemars(
        description = "20-byte hex-encoded EVM account address (with or without 0x prefix)"
    )]
    pub account_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QuoteBridgeFeeParams {
    #[schemars(description = "Route transport: ccip, ibc, deposit or contract")]
    pub adapter: String,
    #[schemars(
        description = "Destination chain identifier (prefer CAIP-2 form, e.g. eip155:1, solana:mainnet-beta)"
    )]
    pub dest_chain: String,
    #[schemars(
        description = "Destination-native fee in the destination chain's smallest unit, as a u128 decimal string"
    )]
    pub native_fee_smallest_unit: String,
}

#[tool_router]
impl TenzroMcpServer {
    #[cfg(test)]
    pub(super) fn typed_tool_names() -> std::collections::BTreeSet<String> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    /// Every tool this server serves: the typed tools and the RPC mirrors.
    fn router() -> ToolRouter<Self> {
        let mut router = Self::tool_router();
        add_rpc_tool_routes(&mut router);
        router
    }

    pub fn new(node: Arc<TenzroNode>) -> Self {
        Self {
            node,
            _tool_router: Self::router(),
            iroh_readonly: false,
            compact: false,
        }
    }

    /// Construct a server for the compact listing at `/mcp/compact`.
    pub fn new_compact(node: Arc<TenzroNode>) -> Self {
        Self {
            node,
            _tool_router: Self::router(),
            iroh_readonly: false,
            compact: true,
        }
    }

    /// Construct a server for the raw iroh MCP transport (`tenzro/mcp`
    /// ALPN). That transport carries no credential and no verified peer
    /// identity, so this instance is locked to the read-only tool allowlist
    /// ([`IROH_READONLY_TOOLS`]): state-changing / admin / operator / compute
    /// / key-management tools and `chat` are refused. The HTTP MCP
    /// path continues to use [`new`](Self::new) and is unaffected.
    pub fn new_iroh(node: Arc<TenzroNode>) -> Self {
        Self {
            node,
            _tool_router: Self::router(),
            iroh_readonly: true,
            compact: false,
        }
    }

    // ─── Wallet & Balance ───

    #[tool(description = "Get the TNZO token balance of an account on the Tenzro ledger")]
    async fn get_balance(
        &self,
        Parameters(params): Parameters<GetBalanceParams>,
    ) -> std::result::Result<Json<Typed<String>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBalance",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    // ─── Transactions ───

    // ─── Identity (TDIP) ───

    #[tool(
        description = "Register a human or machine identity on the Tenzro Decentralized Identity Protocol (TDIP). Human identities are self-sovereign; machine identities require a controller DID and receive a delegation scope. The node submits the RegisterIdentity transaction that replicates the identity and returns its tx_hash; when it cannot, it records nothing and returns the error"
    )]
    async fn register_identity(
        &self,
        Parameters(params): Parameters<RegisterIdentityParams>,
    ) -> std::result::Result<Json<Typed<IdentityRegisteredOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_registerIdentity",
            serde_json::json!({
                "identity_type": params.identity_type,
                "display_name": params.display_name,
                "controller_did": params.controller_did,
                "public_key": params.public_key,
                "credential_id": params.credential_id,
                "did_envelope": params.did_envelope,
            }),
        )
        .await
    }

    #[tool(
        description = "Resolve a DID to its identity information, including display name, type, status, and delegation scope for machine identities"
    )]
    async fn resolve_did(
        &self,
        Parameters(params): Parameters<ResolveDidParams>,
    ) -> std::result::Result<Json<Typed<ResolvedIdentityOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_resolveIdentity",
            serde_json::json!({
                "did": params.did,
            }),
        )
        .await
    }

    #[tool(
        description = "TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously revoked identity from the registry and persistent storage. The DID must already be in `Revoked` status — call `revoke_did` (RPC) first, allow cascading revocation to propagate, then call this. Distinct from revoke (logical delete). Administrators only."
    )]
    async fn forget_identity(
        &self,
        Parameters(params): Parameters<ResolveDidParams>,
    ) -> std::result::Result<Json<Typed<IdentityForgottenOutput>>, ErrorData> {
        // Dispatch through the JSON-RPC layer so the admin-token gate on
        // `tenzro_forgetIdentity` applies identically to MCP callers.
        let result = rpc_dispatch(
            &self.node,
            "tenzro_forgetIdentity",
            serde_json::json!({ "did": params.did }),
        )
        .await?;
        typed_result(result)
    }

    #[tool(
        description = "Read a delegated agent's full consensus Terms (tenzro_getAgentTerms): {agent_did, root_kind (passkey|machine), status (active|quarantined|revoked|expired), version, approval_digest, updated_at_ms, terms, spent {today, this_hour, actions_today, actions_this_hour, remaining_today, remaining_this_hour, assets[{asset, spent_today, remaining_today}]}}, or null when the DID has no Terms on chain. Amounts are wei (or the asset's base units), decimal strings."
    )]
    async fn get_agent_terms(
        &self,
        Parameters(params): Parameters<GetAgentTermsParams>,
    ) -> std::result::Result<Json<Typed<Option<PayAgentTermsView>>>, ErrorData> {
        let req = serde_json::json!({ "agent_did": params.agent_did });
        let result = rpc_dispatch(&self.node, "tenzro_getAgentTerms", req)
            .await
            .map_err(|e| err_internal(format!("getAgentTerms failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Verify a Tenzro DID envelope carried as a tool argument (the hex X-Tenzro-DID-Envelope value). Supports did:tenzro (registry), did:key, did:ethr (recoverable secp256k1), and did:web (resolved over HTTPS). Returns {valid, did, method} or {valid:false, error}. MCP-native carriage: tool calls expose no HTTP headers, so the envelope rides as an argument."
    )]
    async fn verify_did_envelope(
        &self,
        Parameters(params): Parameters<VerifyDidEnvelopeParams>,
    ) -> std::result::Result<Json<Typed<DidEnvelopeVerdictOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_verifyDidEnvelope",
            serde_json::json!({
                "envelope": params.envelope,
            }),
        )
        .await
    }

    // ─── Proof-of-Reserve + attested-mint (1:1 backing invariant) ───

    #[tool(
        description = "Record a signed Proof-of-Reserve attestation backing a tokenized asset, so attested-mint can enforce 1:1 backing. Mirrors tenzro_submitReserveAttestation."
    )]
    async fn submit_reserve_attestation(
        &self,
        Parameters(params): Parameters<ReserveAttestationParams>,
    ) -> std::result::Result<Json<Typed<ReserveAttestedOutput>>, ErrorData> {
        let req = serde_json::to_value(&params)
            .map_err(|e| err_internal(format!("serialize params: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_submitReserveAttestation", req)
            .await
            .map_err(|e| err_internal(format!("submitReserveAttestation failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read the current reserve attestation for a tokenized asset. Mirrors tenzro_getReserve."
    )]
    async fn get_reserve(
        &self,
        Parameters(params): Parameters<GetReserveParams>,
    ) -> std::result::Result<Json<Typed<ReserveAttestationRecord>>, ErrorData> {
        let req = serde_json::to_value(&params)
            .map_err(|e| err_internal(format!("serialize params: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_getReserve", req)
            .await
            .map_err(|e| err_internal(format!("getReserve failed: {}", e)))?;
        typed_result(result)
    }

    // ─── OAuth 2.1 — Token Exchange / Introspection / Discovery ───

    #[tool(
        description = "RFC 8693 OAuth 2.0 Token Exchange. Mint a narrower child JWT from a parent JWT, bound to a different DPoP key with a strict subset of the parent's RAR grants and AAP capabilities. The child token's controller_did is set to the parent's sub, extending the act-chain by one hop. Subset enforcement is performed by the AS; over-scoped requests are rejected."
    )]
    async fn exchange_token(
        &self,
        Parameters(params): Parameters<ExchangeTokenParams>,
    ) -> std::result::Result<Json<Typed<TokenExchangedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_exchangeToken",
            serde_json::json!({
                "subject_token": params.subject_token,
                "child_bearer_did": params.child_bearer_did,
                "child_dpop_jkt": params.child_dpop_jkt,
                "requested_rar": params.requested_rar,
                "requested_aap_capabilities": params.requested_aap_capabilities,
                "requested_ttl_secs": params.requested_ttl_secs,
            }),
        )
        .await
    }

    #[tool(
        description = "RFC 7662 OAuth 2.0 Token Introspection. Ask the AS whether a token is currently active and, if so, return its full claim set (RAR authorization_details, AAP aap_* claims, cnf, controller_did, etc.). Per RFC 7662 §2.2 a failed validation returns `{active: false}` with no other fields — the AS does not leak why the token is inactive."
    )]
    async fn introspect_token(
        &self,
        Parameters(params): Parameters<IntrospectTokenParams>,
    ) -> std::result::Result<Json<Typed<TokenIntrospectionOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_introspectToken",
            serde_json::json!({
                "token": params.token,
            }),
        )
        .await
    }

    #[tool(
        description = "RFC 8414 / RFC 9728 OAuth Authorization Server / Protected Resource Metadata. Returns the same metadata document the AS publishes at `GET /.well-known/openid-configuration`, augmented with AAP-specific extensions (authorization_details_types_supported, aap_claims_supported, dpop_signing_alg_values_supported)."
    )]
    async fn oauth_discovery(
        &self,
    ) -> std::result::Result<Json<Typed<OAuthDiscoveryOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_oauthDiscovery", serde_json::json!({})).await
    }

    // ─── MicroNode Join ───

    #[tool(
        description = "Join the Tenzro Network as a MicroNode — a zero-install full participant. \
        Provisions a TDIP decentralized identity (DID) and a wallet bound to a key you \
        already hold — a passkey for a person, a TPM / Secure Enclave key for an agent. \
        Grants access to all 10 network capabilities: inference, payments, agent collaboration, \
        MCP tools, task execution, chain queries, smart contracts, TEE services, cross-chain bridge, \
        and governance. Works from any entry point: Claude, ClawBot, MCP, A2A, SDK, API, CLI, or app. \
        No binary installation required; you do need a key of your own, which the node \
        never sees the private half of."
    )]
    async fn join_as_participant(
        &self,
        Parameters(params): Parameters<JoinAsMicroNodeParams>,
    ) -> std::result::Result<Json<Typed<ParticipantJoinedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_joinAsMicroNode",
            serde_json::json!({
                "display_name": params.display_name,
                "public_key": params.public_key,
                "credential_id": params.credential_id,
                "origin": params.origin,
                "participant_type": params.participant_type,
            }),
        )
        .await
    }

    // ─── Payments (MPP, x402, Native) ───

    #[tool(
        description = "Create a payment challenge for a protected resource. Supports three protocols:\n- 'mpp' (Machine Payments Protocol): Session-based streaming payments, ideal for per-token AI inference billing\n- 'x402' (HTTP 402): Stateless one-shot payments, ideal for API calls and data downloads\n- 'native': Direct TNZO transfer on the Tenzro ledger"
    )]
    async fn create_payment_challenge(
        &self,
        Parameters(params): Parameters<CreatePaymentChallengeParams>,
    ) -> std::result::Result<Json<Typed<PayPaymentChallenge>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_createPaymentChallenge",
            serde_json::json!({
                "protocol": params.protocol,
                "resource": params.resource,
                "amount": params.amount.to_string(),
                "asset": params.asset,
                "recipient": params.recipient,
                "app_id": params.app_id,
            }),
        )
        .await
    }

    #[tool(
        description = "Verify a payment credential against a previously created challenge, without settling it"
    )]
    async fn verify_payment(
        &self,
        Parameters(params): Parameters<VerifyPaymentParams>,
    ) -> std::result::Result<Json<Typed<PayVerifyPaymentOutput>>, ErrorData> {
        use tenzro_payments::types::PaymentCredential;

        let signature: tenzro_types::account_signature::CompositeSignature =
            serde_json::to_value(&params.signature)
                .and_then(serde_json::from_value)
                .map_err(|e| ErrorData {
                    code: ErrorCode::INVALID_PARAMS,
                    message: Cow::from(format!("Invalid composite signature: {}", e)),
                    data: None,
                })?;

        let credential = PaymentCredential {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: params.challenge_id.clone(),
            protocol: params.protocol.clone(),
            payer_did: params.payer_did.clone(),
            payer_address: params.payer_address.clone(),
            amount: params.amount,
            asset: params.asset.clone(),
            signature: Some(signature),
            extra: std::collections::HashMap::from([(
                tenzro_payments::payer_auth::PUBLIC_KEY_KEY.to_string(),
                serde_json::json!(params.public_key.trim_start_matches("0x")),
            )]),
        };

        rpc_tool_typed(
            &self.node,
            "tenzro_verifyPayment",
            serde_json::json!({ "credential": credential }),
        )
        .await
    }

    // ─── Managed databases ───

    #[tool(
        description = "List all providers discovered on the Tenzro Network: the local node (if serving) and every provider announced on the tenzro/providers gossip topic. Each carries its coarse region (country code or wide region; omitted when undeclared), jurisdiction, served models, the live load of each model (in flight, admission ceiling, warm-up queue depth, state) with the time it was read, its hardware tier when detected, and the kind of hardware its identity key is held in (tpm, enclave, delegated_tpm or passkey) as it declared it. One page at a time: pass `next_cursor` back as `cursor` for the next."
    )]
    async fn list_providers(
        &self,
        Parameters(params): Parameters<ListProvidersParams>,
    ) -> std::result::Result<Json<crate::provider_listing_rpc::ProviderPage>, ErrorData> {
        let page = rpc_dispatch(
            &self.node,
            "tenzro_listProviders",
            rpc_args(serde_json::to_value(params).map_err(|e| err_internal(e.to_string()))?),
        )
        .await?;
        serde_json::from_value(page)
            .map(Json)
            .map_err(|e| err_internal(format!("provider page: {e}")))
    }

    #[tool(
        description = "List every standing entry of one kind in the generic registry (units of metered work, service types, price cards, apps, datasets), in id order, unranked. Each entry carries its owner, version, anchor (the hash of the harness module that interprets it), its data (hex) and digest."
    )]
    async fn list_registry(
        &self,
        Parameters(params): Parameters<ListRegistryParams>,
    ) -> std::result::Result<Json<Typed<RegistryPageOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listRegistry",
            serde_json::json!({ "kind": params.kind, "after": params.after, "limit": params.limit }),
        )
        .await
    }

    #[tool(
        description = "One entry of the generic registry, the latest version or the one named: its kind, owner, version, anchor (the hash of the harness module that interprets it), its data (hex) and digest. Null when there is no such entry."
    )]
    async fn get_registry_entry(
        &self,
        Parameters(params): Parameters<GetRegistryEntryParams>,
    ) -> std::result::Result<Json<Typed<Option<RegistryEntryOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getRegistryEntry",
            serde_json::json!({ "id": params.id, "version": params.version }),
        )
        .await
    }

    #[tool(
        description = "The price card a provider publishes for a model or service: a price per unit of metered work (or unit at a tier), in billionths of a dollar or TNZO base units, with its registry entry."
    )]
    async fn get_price_card(
        &self,
        Parameters(params): Parameters<GetPriceCardParams>,
    ) -> std::result::Result<Json<Typed<Option<PriceCardOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getPriceCard",
            serde_json::json!({ "provider": params.provider, "model_id": params.model_id }),
        )
        .await
    }

    #[tool(
        description = "Price one inference request at every provider serving a model, cheapest first: each provider's announced rate card applied to the request's billable units (input_tokens, output_tokens, cached tokens, image tokens, audio/video ms, ...), plus the governed surcharge for the verification level (none, receipt, optimistic, tee). Only providers that can serve at that level are quoted. Each offer carries the provider's region and the model's live load."
    )]
    async fn quote_inference(
        &self,
        Parameters(params): Parameters<QuoteInferenceParams>,
    ) -> std::result::Result<Json<Typed<InferenceQuoteOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_quoteInference",
            serde_json::json!({
                "model": params.model,
                "units": params.units,
                "verification": params.verification,
                "provider": params.provider,
            }),
        )
        .await
    }

    // ─── Models & Inference ───
    #[tool(
        description = "List AI models available on the Tenzro network. Shows all models with availability: 'local' (served on this node, free), 'network' (available from remote providers, costs TNZO), or 'downloadable' (in catalog but not yet available). Optionally filter by modality. With loaded=true, lists every model this node holds, of every type, with its type, engine, visibility, access and loaded/serving state."
    )]
    async fn list_models(
        &self,
        Parameters(params): Parameters<ListModelsParams>,
    ) -> std::result::Result<Json<Typed<ListModelsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listModels",
            serde_json::json!({
                "modality": params.modality,
                "loaded": params.loaded,
            }),
        )
        .await
    }

    #[tool(
        description = "Discover the best model for an intent (use case + budget + quality floor + cost-quality knob) without naming a model. Returns the selected model_id, tier, estimated cost, fallback chain, the difficulty cluster the prompt landed in, that model's observed error rate in the cluster, and the winning provider's address and endpoint when the offer came from another operator. Discovery only — dispatches nothing and records no spend, though the per-DID budget gate and the wallet-balance ceiling still apply, so an unaffordable request is refused here. Use chat_by_intent to select and run in one call"
    )]
    async fn route_by_intent(
        &self,
        Parameters(p): Parameters<RouteByIntentParams>,
    ) -> std::result::Result<Json<Typed<RouteDecisionOutput>>, ErrorData> {
        let mut params = serde_json::json!({ "use_case": p.use_case });
        if let Some(v) = p.budget {
            params["budget"] = serde_json::json!(v.to_string());
        }
        if let Some(v) = p.optimize {
            params["optimize"] = serde_json::json!(v);
        }
        if let Some(v) = p.quality_floor {
            params["quality_floor"] = serde_json::json!(v);
        }
        if let Some(v) = p.est_input_tokens {
            params["est_input_tokens"] = serde_json::json!(v);
        }
        if let Some(v) = p.est_output_tokens {
            params["est_output_tokens"] = serde_json::json!(v);
        }
        if let Some(v) = p.payer_did {
            params["payer_did"] = serde_json::json!(v);
        }
        if let Some(v) = p.payer_address {
            params["payer_address"] = serde_json::json!(v);
        }
        if let Some(v) = p.prompt {
            params["prompt"] = serde_json::json!(v);
        }
        rpc_tool_typed(&self.node, "tenzro_routeIntent", params).await
    }

    #[tool(
        description = "Resolve an intent to a model and run the chat in one call. Selection walks the cross-model fallback chain, so the intent resolves as long as any model that satisfies it has a live offer, and dispatch is pinned to the offer that was scored — the price quoted is the price settled and the provider share goes to the address that offer named. The chosen decision is attached to the response under 'route'. Difficulty feedback for resolved and failed calls is recorded from the dispatch itself; report an escalation with record_route_outcome"
    )]
    async fn chat_by_intent(
        &self,
        Parameters(p): Parameters<ChatByIntentParams>,
    ) -> std::result::Result<Json<Typed<ChatByIntentOutput>>, ErrorData> {
        if p.message.is_none() && p.messages.is_none() {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Provide 'message' (simple shape) or 'messages' (rich shape)"),
                data: None,
            });
        }
        let mut params = serde_json::json!({ "use_case": p.use_case });
        if let Some(v) = p.message {
            params["message"] = serde_json::json!(v);
        }
        if let Some(v) = p.messages {
            params["messages"] = serde_json::json!(v);
        }
        if let Some(v) = p.budget {
            params["budget"] = serde_json::json!(v.to_string());
        }
        if let Some(v) = p.optimize {
            params["optimize"] = serde_json::json!(v);
        }
        if let Some(v) = p.quality_floor {
            params["quality_floor"] = serde_json::json!(v);
        }
        if let Some(v) = p.est_input_tokens {
            params["est_input_tokens"] = serde_json::json!(v);
        }
        if let Some(v) = p.est_output_tokens {
            params["est_output_tokens"] = serde_json::json!(v);
        }
        if let Some(v) = p.payer_did {
            params["payer_did"] = serde_json::json!(v);
        }
        if let Some(v) = p.payer_address {
            params["payer_address"] = serde_json::json!(v);
        }
        if let Some(v) = p.temperature {
            params["temperature"] = serde_json::json!(v);
        }
        if let Some(v) = p.max_tokens {
            params["max_tokens"] = serde_json::json!(v);
        }
        if let Some(v) = p.jurisdiction {
            params["jurisdiction"] = serde_json::json!(v);
        }
        if let Some(v) = p.jurisdiction_receipt {
            params["jurisdiction_receipt"] = serde_json::json!(v);
        }
        if let Some(v) = p.max_p95_ms {
            params["max_p95_ms"] = serde_json::json!(v);
        }
        if let Some(v) = p.continuity {
            params["continuity"] = serde_json::json!(v);
        }
        if let Some(v) = p.session_id {
            params["session_id"] = serde_json::json!(v);
        }
        rpc_tool_typed(&self.node, "tenzro_chatByIntent", params).await
    }

    #[tool(
        description = "Report how a routed call turned out so per-cluster error rates reflect what happened rather than only what the catalog declares. In practice this carries 'escalated' — the outcome only the caller knows, because it means you took the answer to a stronger model; 'resolved' and 'failed' are already recorded by chat_by_intent from the dispatch itself. Reporting is advisory: retained=false means the node has no difficulty index wired, so the feedback was accepted and discarded"
    )]
    async fn record_route_outcome(
        &self,
        Parameters(p): Parameters<RecordRouteOutcomeParams>,
    ) -> std::result::Result<Json<Typed<RouteOutcomeOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_recordRouteOutcome",
            serde_json::json!({
                "model_id": p.model_id,
                "cluster": p.cluster,
                "outcome": p.outcome,
            }),
        )
        .await
    }

    #[tool(
        description = "Read the node's difficulty index: how many prompt clusters it has discovered and how many prompts landed in each. With model_id, also returns that model's per-cluster outcome counters and error rate. An operator diagnostic — routing does not depend on it. enabled=false means the node has no embedding model loaded and routes on declared metadata alone"
    )]
    async fn route_difficulty_stats(
        &self,
        Parameters(p): Parameters<RouteDifficultyStatsParams>,
    ) -> std::result::Result<Json<Typed<RouteDifficultyStatsOutput>>, ErrorData> {
        let mut params = serde_json::json!({});
        if let Some(v) = p.model_id {
            params["model_id"] = serde_json::json!(v);
        }
        rpc_tool_typed(&self.node, "tenzro_routeDifficultyStats", params).await
    }

    #[tool(
        description = "List all model service endpoints with their API and MCP URLs, model details, and status"
    )]
    async fn list_model_endpoints(
        &self,
    ) -> std::result::Result<Json<Typed<Vec<ModelEndpointOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listModelEndpoints",
            serde_json::json!({}),
        )
        .await
    }

    // ─── Universal RPC gateway ───
    //
    // The node serves several hundred methods; the tools above cover the ones worth a
    // dedicated, documented signature. These two cover the rest, so nothing
    // the node can do is unreachable from MCP.
    //
    // Writing a tool per method instead would make this server worse, not
    // better: tool-selection accuracy falls as the list grows, so hundreds more
    // near-identical entries would cost an agent accuracy on the tools it
    // actually wanted. Discovery plus a gateway keeps the curated list small
    // and the surface complete.

    #[tool(
        description = "Enumerate the JSON-RPC methods this node serves, with how each is gated (admin, owner, open or reserved). Use this to discover capability beyond the named tools, then invoke what you find with call_rpc. Filter with `namespace` or `contains` — the unfiltered directory has several hundred entries."
    )]
    async fn list_rpc_methods(
        &self,
        Parameters(params): Parameters<ListRpcMethodsParams>,
    ) -> std::result::Result<Json<Typed<RpcMethodsOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_listRpcMethods", payload)
            .await
            .map_err(|e| err_internal(format!("listRpcMethods failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Invoke any JSON-RPC method this node serves, by name. The escape hatch for everything without a dedicated tool — discover names with list_rpc_methods first. Authorization is unchanged: the call runs behind the same access policy and default-deny classification as a direct JSON-RPC request, so this reaches exactly what your credentials already allow and nothing more."
    )]
    async fn call_rpc(
        &self,
        Parameters(params): Parameters<CallRpcParams>,
    ) -> std::result::Result<Json<Typed<JsonValue>>, ErrorData> {
        let inner = params
            .params
            .map(|p| p.0)
            .unwrap_or_else(|| serde_json::json!({}));
        let result = rpc_dispatch(&self.node, &params.method, inner)
            .await
            .map_err(|e| err_internal(format!("{} failed: {}", params.method, e)))?;
        typed_result(result)
    }

    // ─── Sealed Models (private encrypted distribution) ───
    // Read/discovery surface only: sealing and installing are operator
    // actions for node administrators on the RPC surface
    // (tenzro_sealModel / tenzro_installSealedModel).

    #[tool(
        description = "List sealed-model manifests stored on this node. Sealed models are distributed as encrypted shards with per-recipient wrapped content keys (x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm); only named recipients can decrypt. Returns summaries — use get_sealed_model for a full manifest"
    )]
    async fn list_sealed_models(
        &self,
    ) -> std::result::Result<Json<Typed<SealedModelsOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_listSealedModels", serde_json::json!({})).await
    }

    #[tool(
        description = "Fetch a full sealed-model manifest by model ID. The manifest carries only ciphertext hashes, blob URIs, and wrapped (encrypted) content keys — safe to share; recipients use it to install the model on their own node"
    )]
    async fn get_sealed_model(
        &self,
        Parameters(params): Parameters<GetSealedModelParams>,
    ) -> std::result::Result<Json<Typed<SealedModelManifestOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getSealedModel",
            serde_json::json!({
                "model_id": params.model_id,
            }),
        )
        .await
    }

    #[tool(
        description = "Get this node's hybrid X25519 + ML-KEM-768 public key for sealed-model distribution. A publisher includes this key in a recipients entry when sealing a model addressed to this node"
    )]
    async fn model_recipient_key(
        &self,
    ) -> std::result::Result<Json<Typed<ModelRecipientKeyOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_modelRecipientKey",
            serde_json::json!({}),
        )
        .await
    }

    #[tool(
        description = "Read a model's provenance: its content-addressed manifests (per-file SHA-256 and BLAKE3 under a BLAKE3 Merkle root), the origin observations for each (model creator, Hugging Face Hub, storage holders, mirrors), and whether independent origins agree so the manifest counts as verified. Loads are checked against the verified manifest. Open — no auth"
    )]
    async fn get_model_provenance(
        &self,
        Parameters(params): Parameters<GetModelProvenanceParams>,
    ) -> std::result::Result<Json<Typed<ModelProvenanceOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getModelProvenance",
            serde_json::json!({ "name": params.name, "root": params.root, "file": params.file }),
        )
        .await?;
        typed_result(result)
    }

    #[tool(
        description = "List the models this node's catalog serves: signed entries from the publishers the operator names (or every bonded publisher), each with its engine family, licence and tier, whether it is gated (the operator's own token is needed) and the SHA-256 of every file it downloads. Also returns the named publishers, its publishers and each published model left out with the reason. Open — no auth"
    )]
    async fn list_catalog(
        &self,
        Parameters(params): Parameters<ListCatalogParams>,
    ) -> std::result::Result<Json<Typed<CatalogListOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listCatalog",
            serde_json::json!({ "engine": params.engine }),
        )
        .await?;
        typed_result(result)
    }

    #[tool(
        description = "Read one model's catalog entry on this node, the publishers that published it and whether a token is needed to fetch it; for a model the node does not serve, the reason. Open — no auth"
    )]
    async fn get_catalog_entry(
        &self,
        Parameters(params): Parameters<GetCatalogEntryParams>,
    ) -> std::result::Result<Json<Typed<CatalogEntryOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getCatalogEntry",
            serde_json::json!({ "model": params.model }),
        )
        .await?;
        typed_result(result)
    }

    #[tool(
        description = "List the engine releases published by the publishers this node's operator trusts for releases (version, per-platform binary SHA-256 and BLAKE3, the signed record), marking those newer than the running build. The node installs nothing: its operator verifies and applies a release. Open — no auth"
    )]
    async fn get_engine_releases(
        &self,
    ) -> std::result::Result<Json<Typed<EngineReleasesOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getEngineReleases",
            serde_json::json!({}),
        )
        .await?;
        typed_result(result)
    }

    // ─── Bridge routes ───

    #[tool(
        description = "List every governed bridge route (transport, external chain, committees, caps, epoch usage, supply record, breaker state). Open — no auth"
    )]
    async fn list_bridge_routes(
        &self,
    ) -> std::result::Result<Json<Typed<PayBridgeRoutesOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_listBridgeRoutes", serde_json::json!({})).await
    }

    #[tool(
        description = "Get one governed bridge route by transport and external chain. Open — no auth"
    )]
    async fn get_bridge_route(
        &self,
        Parameters(params): Parameters<BridgeRouteKeyParams>,
    ) -> std::result::Result<Json<Typed<PayBridgeRouteView>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBridgeRoute",
            serde_json::json!({ "adapter": params.adapter, "source_chain": params.source_chain }),
        )
        .await
    }

    #[tool(
        description = "Get an outbound record of a governed route by sequence, for relayers and signers; for a Bitcoin deposit route, the withdrawal with the digest each input is signed over. Open — no auth"
    )]
    async fn get_bridge_outbound(
        &self,
        Parameters(params): Parameters<BridgeOutboundRecordParams>,
    ) -> std::result::Result<Json<Typed<PayBridgeOutboundRecord>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBridgeOutbound",
            serde_json::json!({
                "adapter": params.adapter,
                "source_chain": params.source_chain,
                "sequence": params.sequence,
            }),
        )
        .await
    }

    // ─── Network & Blocks ───

    #[tool(
        description = "Get this node's DID Document — every way of reaching it in one place. A node is addressed by its TDIP DID, Ed25519 public key, iroh EndpointId and relays, plus its JSON-RPC/MCP/A2A/web service URLs; resolving the DID yields all of them. Unroutable bind addresses are omitted rather than advertised, and an ALPN appears only when a handler is actually installed. Returns an error when the node has no provisioned identity."
    )]
    async fn get_node_did_document(
        &self,
    ) -> std::result::Result<Json<Typed<NodeDidDocumentOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_nodeDidDocument", serde_json::json!({})).await
    }

    #[tool(
        description = "Get the newest signed Tenzro release notice this node holds: the latest version, its severity (normal, security, or required by a named epoch), the release notes link and the archive digests per platform, with the node's position in its epoch. Read only. The notice is signed by the release key and carries data only; verify the signature before relying on it. Use it to tell a person whether a newer Tenzro is available."
    )]
    async fn get_update_notice(
        &self,
    ) -> std::result::Result<Json<Typed<UpdateNoticeOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getUpdateNotice", serde_json::json!({})).await
    }

    #[tool(
        description = "Get the current status of the Tenzro node including health, block height, peer count, uptime, and role"
    )]
    async fn get_node_status(
        &self,
    ) -> std::result::Result<Json<Typed<NodeStatusOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getNodeStatus", serde_json::json!({})).await
    }

    #[tool(
        description = "Get a snapshot of network metrics: gossip publish/accept/reject counters and the number of peers this node gossips with directly"
    )]
    async fn get_network_stats(
        &self,
    ) -> std::result::Result<Json<Typed<NetworkStatsOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getNetworkStats", serde_json::json!({})).await
    }

    #[tool(
        description = "Get a block by height from the Tenzro ledger, including transactions and metadata"
    )]
    async fn get_block(
        &self,
        Parameters(params): Parameters<GetBlockParams>,
    ) -> std::result::Result<Json<Typed<Option<BlockOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBlock",
            serde_json::json!({
                "height": params.height,
            }),
        )
        .await
    }

    #[tool(
        description = "Fetch a contiguous range of blocks by height (default 64, max 256). Returns block summaries plus `next_height` and `more_available` so a lagging client can paginate forward until caught up."
    )]
    async fn get_block_range(
        &self,
        Parameters(params): Parameters<GetBlockRangeParams>,
    ) -> std::result::Result<Json<Typed<BlockRangeOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBlockRange",
            serde_json::json!({
                "start": params.start_height,
                "end": params.end_height,
                "max": params.max_results,
            }),
        )
        .await
    }

    #[tool(
        description = "Inspect the fee markets: current effective gas price (base fee + suggested tip), suggested priority tip, recent base-fee history, and the base fee of each resource market (compute, state growth, bandwidth, proof), each moving with its own use against its own target. A resource priced above compute is paid on top of gas."
    )]
    async fn get_fee_market(
        &self,
        Parameters(params): Parameters<GetFeeMarketParams>,
    ) -> std::result::Result<Json<Typed<FeeMarketOutput>>, ErrorData> {
        let blocks = params.blocks.unwrap_or(10);
        let history = rpc_dispatch(
            &self.node,
            "eth_feeHistory",
            serde_json::json!([
                format!("0x{:x}", blocks),
                "latest",
                params.reward_percentiles.unwrap_or_default(),
            ]),
        )
        .await?;
        let gas_price = rpc_dispatch(&self.node, "eth_gasPrice", serde_json::json!([])).await?;
        let priority = rpc_dispatch(
            &self.node,
            "eth_maxPriorityFeePerGas",
            serde_json::json!([]),
        )
        .await?;
        let resources =
            rpc_dispatch(&self.node, "tenzro_getFeeMarket", serde_json::json!({})).await?;
        typed_result(serde_json::json!({
            "gas_price_wei": gas_price,
            "max_priority_fee_per_gas_wei": priority,
            "fee_history": history,
            "resource_markets": resources,
        }))
    }

    #[tool(
        description = "Look up a transaction by its hash on the Tenzro ledger, returning its type (the transaction type's variant name), its decoded fields as `payload` (integers past 2^53 as decimal strings, byte strings of 16 bytes or more as 0x hex), sender, recipient, amount and status"
    )]
    async fn get_transaction(
        &self,
        Parameters(params): Parameters<GetTransactionParams>,
    ) -> std::result::Result<Json<Typed<Option<ChainTransactionOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getTransaction",
            serde_json::json!({
                "hash": params.tx_hash,
            }),
        )
        .await
    }

    // ─── Verification ───

    #[tool(
        description = "Verify a zero-knowledge proof of an 'identity' or 'settlement' statement. Pass the circuit_id, the public inputs [digest, binding] (32-byte hex each) and one proof leg per proof system ([{system, proof}], systems 'koala-bear-sha256-fri', 'goldilocks-blake3-fri' and 'halo2-ipa-pasta'). A statement is submitted to the ZK_VERIFY attestation quorum only when it verifies in every proof system, which spans two independent implementations (Plonky3 and Halo2)."
    )]
    async fn verify_zk_proof(
        &self,
        Parameters(params): Parameters<VerifyZkProofParams>,
    ) -> std::result::Result<Json<Typed<ZkVerifyOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_verifyZkProof",
            serde_json::json!({
                "circuit_id": params.circuit_id,
                "public_inputs": params.public_inputs,
                "proofs": params.proofs,
            }),
        )
        .await
    }

    #[tool(
        description = "Whether a ZK commitment is admitted to the on-chain ZK_VERIFY registry: an AttestZkProof transaction verified its proof in an executed block."
    )]
    async fn get_zk_attestation(
        &self,
        Parameters(params): Parameters<GetZkAttestationParams>,
    ) -> std::result::Result<Json<Typed<ZkAttestationOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getZkAttestation",
            serde_json::json!({
                "commitment": params.commitment,
            }),
        )
        .await
    }

    #[tool(
        description = "Verify a Tenzro VRF proof (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI). Returns the deterministic 64-byte VRF output if the proof is valid. Used for provably-fair NFT reveals, lotteries, and randomized trait assignment."
    )]
    async fn verify_vrf_proof(
        &self,
        Parameters(params): Parameters<VerifyVrfProofParams>,
    ) -> std::result::Result<Json<Typed<VrfCheckOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_verifyVrfProof",
            serde_json::json!({
                "pubkey": params.pubkey,
                "proof": params.proof,
                "alpha": params.alpha,
            }),
        )
        .await
    }

    // ─── Staking & Provider Management ───

    #[tool(
        description = "Read an account's stake per role from consensus state (bonded, required for its declared capacity, unbonding and when it releases), and every role's network total. Omit address for this node's operator payee."
    )]
    async fn get_role_stakes(
        &self,
        Parameters(params): Parameters<GetRoleStakesParams>,
    ) -> std::result::Result<Json<Typed<RoleStakesOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getRoleStakes",
            rpc_args(serde_json::json!({ "address": params.address })),
        )
        .await
    }

    #[tool(
        description = "List the staked operators of a role (default rpc) and the public URLs they published on chain, most bonded first. Every node answers the same list from consensus state, so a client can choose among independent operators instead of one fixed domain."
    )]
    async fn list_role_endpoints(
        &self,
        Parameters(params): Parameters<ListRoleEndpointsParams>,
    ) -> std::result::Result<Json<Typed<RoleEndpointsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listRoleEndpoints",
            rpc_args(serde_json::json!({ "role": params.role })),
        )
        .await
    }

    #[tool(
        description = "List the relays staked edge operators serve, most bonded first, each with the SLA verdict validators froze for the last closed epoch (an unavailable verdict costs the edge bond the governed SLA penalty), this node's latest check of it (operator record valid and announcing the URL, latency) and whether this node uses it."
    )]
    async fn list_relays(&self) -> std::result::Result<Json<Typed<RelaysOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_listRelays", serde_json::json!({})).await
    }

    #[tool(
        description = "How this node is reached: directly at a public or router-mapped address, after hole punching, through a peer relay, or through relays; the kind of NAT in front of it; how many peers reported its address; IPv4/IPv6; the relays it is connected to and the peer relays it offers paths through. Names no network address."
    )]
    async fn get_connectivity(
        &self,
    ) -> std::result::Result<Json<Typed<ConnectivityOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getConnectivity", serde_json::json!({})).await
    }

    #[tool(
        description = "Get provider statistics including served models, inference count, staking info, and earnings. Omit address to get stats for the local node."
    )]
    async fn get_provider_stats(
        &self,
        Parameters(params): Parameters<GetProviderStatsParams>,
    ) -> std::result::Result<Json<Typed<ProviderStatsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getProviderStats",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    #[tool(
        description = "Read compute bonds — the bond inference faults, frozen SLA verdicts and proven policy violations are slashed from. Pass provider_did for one bond, or omit it to list every bond on the node. Always returns the node's minimum bond and withdrawal cooldown so a caller can see what admission requires."
    )]
    async fn get_compute_bond(
        &self,
        Parameters(params): Parameters<GetComputeBondParams>,
    ) -> std::result::Result<Json<Typed<Option<ComputeBondOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getComputeBond",
            serde_json::json!({
                "provider_did": params.provider_did,
            }),
        )
        .await
    }

    // ─── Duties and Evidence ───

    #[tool(
        description = "Open network duties from chain state: work the chain pays the first prover for (a route's settlement-lock reconciliation each epoch, the install of a voided agent grant on another chain), each with its reward, vault and funder."
    )]
    async fn list_duties(&self) -> std::result::Result<Json<Typed<DutiesOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_listDuties", serde_json::json!({})).await
    }

    #[tool(
        description = "One network duty by id: the work, its reward, and whether it is open, paid (and to whom) or expired."
    )]
    async fn get_duty(
        &self,
        Parameters(params): Parameters<GetDutyParams>,
    ) -> std::result::Result<Json<Typed<Option<DutyOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getDuty",
            serde_json::json!({ "duty_id": params.duty_id }),
        )
        .await
    }

    #[tool(
        description = "Check evidence against chain state: an audit entry against its node's committed epoch root, an agent's terms, a recorded settlement, a device-signed reading against its registered hardware key, a finality proof against the governed finality program. Documents are bound by digest only. Returns what each item checks to."
    )]
    async fn verify_evidence(
        &self,
        Parameters(params): Parameters<VerifyEvidenceParams>,
    ) -> std::result::Result<Json<Typed<EvidenceVerifiedOutput>>, ErrorData> {
        let items = serde_json::to_value(&params.items)
            .map_err(|e| err_internal(format!("serialize items: {e}")))?;
        rpc_tool_typed(
            &self.node,
            "tenzro_verifyEvidence",
            serde_json::json!({ "items": items }),
        )
        .await
    }

    // ─── Governance Tools ───

    #[tool(
        description = "List on-chain governance proposals, newest first, with their track, status, vote tally and voting deadline."
    )]
    async fn list_proposals(
        &self,
        Parameters(params): Parameters<ListProposalsParams>,
    ) -> std::result::Result<Json<Typed<GovProposalsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listProposals",
            serde_json::json!({
                "limit": params.limit,
                "before": params.before,
                "kind": params.kind,
            }),
        )
        .await
    }

    #[tool(
        description = "Get the governance voting power of an address: its bonded stake, and the network total a tally is measured against."
    )]
    async fn get_voting_power(
        &self,
        Parameters(params): Parameters<GetVotingPowerParams>,
    ) -> std::result::Result<Json<Typed<VotingPowerOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getVotingPower",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    #[tool(
        description = "Get the governance-sponsored part of a validator's stake: the existing treasury TNZO an enacted proposal bonded on its behalf (bonded and unbonding), the part the validator put up itself, and the governed caps with what is out network-wide. Sponsored stake counts toward the bond, is slashed with it, never votes, earns nothing and is never minted."
    )]
    async fn get_sponsored_bond(
        &self,
        Parameters(params): Parameters<GetSponsoredBondParams>,
    ) -> std::result::Result<Json<Typed<SponsoredBondOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getSponsoredBond",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    #[tool(
        description = "Get every disbursement of treasury sponsorship and grants, oldest first: recipient, amount, class (validator, provider, developer, contributor, community), the proposal that paid it and the milestone or verified hours it was paid against; the total per class; and the governed caps. With an address, whether it is an approved operator or grantee, the criteria it was approved on, and the total it has been paid. All payouts are existing treasury TNZO, one governance proposal each."
    )]
    async fn get_treasury_payouts(
        &self,
        Parameters(params): Parameters<GetTreasuryPayoutsParams>,
    ) -> std::result::Result<Json<Typed<TreasuryPayoutsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getTreasuryPayouts",
            serde_json::json!({
                "address": params.address,
                "offset": params.offset,
                "limit": params.limit,
            }),
        )
        .await
    }

    #[tool(
        description = "Get the treasury's keyless accounts on every chain with account code (derived from the treasury identity and the chain's governed deployment), each with the last remote grant an enacted TreasuryRemoteAction proposal wrote for it. Bitcoin moves through the deposit route."
    )]
    async fn get_treasury_accounts(
        &self,
    ) -> std::result::Result<Json<Typed<TreasuryAccountsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getTreasuryAccounts",
            serde_json::json!({}),
        )
        .await
    }

    #[tool(
        description = "Get every guardian and Foundation steward seat, the governance enactment pause, the steward treasury hold, the guardian threshold, the steward sunset and seat cap, and optionally the seat an address holds and whether it is live."
    )]
    async fn get_guardian_state(
        &self,
        Parameters(params): Parameters<GetGuardianStateParams>,
    ) -> std::result::Result<Json<Typed<GuardianStateOutput>>, ErrorData> {
        let args = match params.address {
            Some(a) => serde_json::json!({ "address": a }),
            None => serde_json::json!({}),
        };
        rpc_tool_typed(&self.node, "tenzro_getGuardianState", args).await
    }

    // ─── Token Tools ───

    #[tool(
        description = "Get the TNZO token balance for an address. Returns the balance in wei (1 TNZO = 10^18 wei) as a decimal string."
    )]
    async fn token_balance(
        &self,
        Parameters(params): Parameters<TokenBalanceParams>,
    ) -> std::result::Result<Json<Typed<String>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_tokenBalance",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    #[tool(
        description = "Get the total TNZO token supply in wei (1 TNZO = 10^18 wei). Fixed at genesis: it never rises, and falls by what fees burn. Useful for burn monitoring and economic analysis."
    )]
    async fn total_supply(&self) -> std::result::Result<Json<Typed<String>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_totalSupply", serde_json::json!({})).await
    }

    // ─── Settlement Tools ───

    #[tool(
        description = "Settle a payment on the Tenzro ledger with the payer's own signed authorization: an PayerSettle transaction moves the amount from the payer to the payee, less the network's governed settlement fee. The node only relays it and pays the gas."
    )]
    async fn settle_payment(
        &self,
        Parameters(params): Parameters<SettlePaymentParams>,
    ) -> std::result::Result<Json<Typed<SettlementOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_settle",
            serde_json::json!({
                "payee": params.payee,
                "amount": params.amount_wei,
                "payment": params.payment,
            }),
        )
        .await
    }

    #[tool(
        description = "Create an on-chain escrow paid from the calling agent's own wallet. The agent acts with its access token: this node, one of its serving nodes, checks the action against the agent's terms on chain (operation create_escrow, counterparty, per-transaction and daily limits) and signs it for the agent only when it is within them; the VM checks it again. Returns the escrow_id."
    )]
    async fn create_escrow(
        &self,
        Parameters(params): Parameters<CreateEscrowParams>,
    ) -> std::result::Result<Json<Typed<PayAgentActOutput>>, ErrorData> {
        let payee = parse_address(&params.payee)
            .map_err(|e| err_internal(format!("Invalid payee address: {}", e)))?;
        let amount: u128 = params.amount_wei.parse().map_err(|_| {
            err_internal("amount_wei must be a wei decimal string (1 TNZO = 10^18 wei)")
        })?;
        let release_conditions = match params.release_condition.to_lowercase().as_str() {
            "timeout" => serde_json::json!("Timeout"),
            "provider" | "provider_signature" => serde_json::json!("ProviderSignature"),
            "consumer" | "consumer_signature" => serde_json::json!("ConsumerSignature"),
            "both" | "both_signatures" => serde_json::json!("BothSignatures"),
            "custom" => serde_json::json!({ "Custom": { "condition": "" } }),
            other => {
                return Err(err_internal(format!(
                    "unsupported release_condition '{}'",
                    other
                )));
            }
        };
        let expires_at_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64)
            + params.timeout_secs.unwrap_or(3600).saturating_mul(1000);
        agent_escrow_act(
            &self.node,
            "create_escrow",
            &hex::encode(payee.as_bytes()),
            amount,
            serde_json::json!({ "create": {
                "expires_at_ms": expires_at_ms,
                "release_conditions": release_conditions,
            } }),
        )
        .await
    }

    #[tool(
        description = "Release an escrow the calling agent's wallet funded: what remains goes to the payee. Acts with the agent's access token, within its terms (operation release_escrow)."
    )]
    async fn release_escrow(
        &self,
        Parameters(params): Parameters<ReleaseEscrowParams>,
    ) -> std::result::Result<Json<Typed<PayAgentActOutput>>, ErrorData> {
        let escrow_id = parse_escrow_id(&params.escrow_id)?;
        let proof_data = match params.proof_data_hex.as_deref() {
            Some(s) => hex::decode(s.trim_start_matches("0x"))
                .map_err(|e| err_internal(format!("Invalid proof hex: {}", e)))?,
            None => Vec::new(),
        };
        agent_escrow_act(
            &self.node,
            "release_escrow",
            "",
            0,
            serde_json::json!({ "release": {
                "escrow_id": escrow_id,
                "proof": {
                    "proof_type": "Cryptographic",
                    "proof_data": proof_data,
                    "signatures": [],
                    "attestation": null
                }
            } }),
        )
        .await
    }

    #[tool(
        description = "Refund an expired escrow the calling agent's wallet funded: what remains returns to the wallet. Acts with the agent's access token, within its terms (operation refund_escrow)."
    )]
    async fn refund_escrow(
        &self,
        Parameters(params): Parameters<RefundEscrowParams>,
    ) -> std::result::Result<Json<Typed<PayAgentActOutput>>, ErrorData> {
        let escrow_id = parse_escrow_id(&params.escrow_id)?;
        agent_escrow_act(
            &self.node,
            "refund_escrow",
            "",
            0,
            serde_json::json!({ "refund": { "escrow_id": escrow_id } }),
        )
        .await
    }

    #[tool(
        description = "Open a payment channel over an escrow the payer funded on the ledger with its own CreateEscrow transaction, naming this node's payee. Payments on the channel are cumulative vouchers the payer signs."
    )]
    async fn open_payment_channel(
        &self,
        Parameters(params): Parameters<OpenPaymentChannelParams>,
    ) -> std::result::Result<Json<Typed<PayPaymentChannel>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_openPaymentChannel",
            serde_json::json!({ "channel_id": params.channel_id }),
        )
        .await
    }

    #[tool(
        description = "Close a payment channel, signed by its payer. The highest voucher is claimed on-chain; the rest of the escrow returns to the payer when it expires."
    )]
    async fn close_payment_channel(
        &self,
        Parameters(params): Parameters<ClosePaymentChannelParams>,
    ) -> std::result::Result<Json<Typed<PayCloseChannelOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_closePaymentChannel",
            serde_json::json!({
                "channel_id": params.channel_id,
                "public_key": params.public_key,
                "signature": params.signature,
                "timestamp_ms": params.timestamp_ms,
            }),
        )
        .await
    }

    // ─── Model Lifecycle Tools ───

    #[tool(
        description = "Start serving a model for inference. Loads downloaded GGUF weights into this node's own runtime (the model must be downloaded first). Returns the serving status and configuration."
    )]
    async fn serve_model_mcp(
        &self,
        Parameters(params): Parameters<ServeModelMcpParams>,
    ) -> std::result::Result<Json<Typed<ServeModelOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_serveModel",
            serde_json::json!({
                "model_id": params.model_id,
                "max_concurrent": params.max_concurrent,
            }),
        )
        .await
    }

    #[tool(
        description = "Stop serving a model on this node. The model remains downloaded but no longer accepts inference requests. Returns the stop confirmation."
    )]
    async fn stop_model(
        &self,
        Parameters(params): Parameters<StopModelParams>,
    ) -> std::result::Result<Json<Typed<ModelStoppedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_stopModel",
            serde_json::json!({
                "model_id": params.model_id,
            }),
        )
        .await
    }

    #[tool(
        description = "Delete a model from this node's local storage. The model must not be currently serving. Frees disk space. Returns deletion confirmation."
    )]
    async fn delete_model_mcp(
        &self,
        Parameters(params): Parameters<DeleteModelParams>,
    ) -> std::result::Result<Json<Typed<ModelDeletedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_deleteModel",
            serde_json::json!({
                "model_id": params.model_id,
            }),
        )
        .await
    }

    #[tool(
        description = "Get this node's model stacks: the stack serving now and until when, the stack that runs next and when it starts, every configured stack, and whether each member model is serving or still pending."
    )]
    async fn get_model_stacks(
        &self,
    ) -> std::result::Result<Json<Typed<ModelStacksOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getModelStacks", serde_json::json!({})).await
    }

    #[tool(
        description = "Set one of this node's price cards: the default card, or the card for one model. A card prices registered units (or units at a tier) in billionths of a dollar or TNZO base units; the operator sets every price. Administrators only."
    )]
    async fn set_provider_pricing(
        &self,
        Parameters(params): Parameters<SetProviderPricingParams>,
    ) -> std::result::Result<Json<Typed<ProviderPricingOutput>>, ErrorData> {
        // The JSON-RPC setter replaces every card, so read the current ones
        // and replace only the one this call names.
        let mut cards = rpc_dispatch(
            &self.node,
            "tenzro_getProviderPricing",
            serde_json::json!({}),
        )
        .await?;
        let card = serde_json::to_value(&params.card)
            .map_err(|e| err_internal(format!("serialize: {}", e)))?;
        match params.model_id {
            Some(model) => cards["models"][model] = card,
            None => cards["default"] = card,
        }
        let card = cards;
        rpc_tool_typed(&self.node, "tenzro_setProviderPricing", card).await
    }

    #[tool(
        description = "Get this node's price cards: the default card and any per-model cards, each a price per unit (or unit at a tier)."
    )]
    async fn get_provider_pricing(
        &self,
    ) -> std::result::Result<Json<Typed<ProviderPricingOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getProviderPricing",
            serde_json::json!({}),
        )
        .await
    }

    // ─── Agent Advanced Tools ───

    // ─── AgentBond Tools ───
    //
    // Lifecycle interventions (pause, quarantine, terminate) and bond writes
    // are typed transactions the controller signs off-node and submits via
    // tenzro_sendRawTransaction; MCP cannot sign for the controller, so
    // there are no tools for them here.

    #[tool(
        description = "Inspect an AgentBond by agent DID. Returns lifecycle state (Active / Cooldown / Frozen / Slashed / Returned), amount, controller, cooldown_until, last_modified_block, and promotion eligibility. Returns null if no bond exists."
    )]
    async fn get_agent_bond(
        &self,
        Parameters(params): Parameters<GetAgentBondParams>,
    ) -> std::result::Result<Json<Typed<Option<AgentBondOutput>>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getAgentBond",
            serde_json::json!({
                "agent_did": params.agent_did,
            }),
        )
        .await
    }

    #[tool(
        description = "The network insurance pool from chain state: vault, balance, claims paid, total paid, what fees and slashed bonds have credited, and the most one claim may take now."
    )]
    async fn get_insurance_pool(
        &self,
    ) -> std::result::Result<Json<Typed<InsurancePoolOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getInsurancePoolBalance",
            serde_json::json!({}),
        )
        .await
    }

    #[tool(
        description = "Challenge a DA committee member to prove current possession of its Red Stuff sliver for a blob commitment. The target must return the full sliver plus a nonce-bound Ed25519 signature; the challenger re-verifies the sliver against the commitment. The outcome (passed / failed_no_response / failed_not_held / failed_bad_proof) feeds the target's rolling availability score. Validator-only."
    )]
    async fn da_challenge(
        &self,
        Parameters(params): Parameters<DaChallengeParams>,
    ) -> std::result::Result<Json<Typed<DaChallengeOutput>>, ErrorData> {
        let p = serde_json::json!({
            "commitment": params.commitment,
            "target_index": params.target_index,
        });
        let result = rpc_dispatch(&self.node, "tenzro_daChallenge", p)
            .await
            .map_err(|e| err_internal(format!("daChallenge: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List resolved DA possession-challenge records, newest-first. Each record carries the blob commitment, target member index + address, nonce, timestamps, and outcome."
    )]
    async fn da_list_challenges(
        &self,
        Parameters(params): Parameters<DaListChallengesParams>,
    ) -> std::result::Result<Json<Typed<DaChallengesOutput>>, ErrorData> {
        let mut p = serde_json::json!({});
        if let Some(l) = params.limit {
            p["limit"] = serde_json::json!(l);
        }
        let result = rpc_dispatch(&self.node, "tenzro_daListChallenges", p)
            .await
            .map_err(|e| err_internal(format!("daListChallenges: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read DA committee availability scores (0-1000, +1 per passed possession challenge, -5 silence or honest not-held, -25 bad proof). Pass an address for one member's score, omit for all scored members lowest-first."
    )]
    async fn da_availability(
        &self,
        Parameters(params): Parameters<DaAvailabilityParams>,
    ) -> std::result::Result<Json<Typed<DaAvailabilityResult>>, ErrorData> {
        let mut p = serde_json::json!({});
        if let Some(a) = params.address {
            p["address"] = serde_json::json!(a);
        }
        let result = rpc_dispatch(&self.node, "tenzro_daAvailability", p)
            .await
            .map_err(|e| err_internal(format!("daAvailability: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Show the current DA committee roster: each member's index, address, whether it is the local node, and its availability score if it has ever been challenged."
    )]
    async fn da_committee(&self) -> std::result::Result<Json<Typed<DaCommitteeOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_daCommittee", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("daCommittee: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List blob commitments known to the local DA committee store, with the locally-held sliver index (if any) and the availability certificate (attesting member indices, quorum, root, timestamp) when one is held."
    )]
    async fn da_list_blobs(&self) -> std::result::Result<Json<Typed<DaBlobsOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_daListBlobs", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("daListBlobs: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Show the local iroh endpoint id, Pkarr relay URL, and ALPNs registered on the shared router. Returns an internal error iff the iroh transport failed to bind at startup."
    )]
    async fn iroh_get_info(&self) -> std::result::Result<Json<Typed<IrohInfoOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_iroh_getInfo", serde_json::json!({})).await
    }

    #[tool(
        description = "Publish raw bytes to the shared iroh-blobs store. Returns a content-addressed `tenzro://blob/<blake3-hex>` URI that any iroh peer can fetch (subject to NAT/discovery reachability)."
    )]
    async fn iroh_publish_blob(
        &self,
        Parameters(params): Parameters<IrohPublishBlobParams>,
    ) -> std::result::Result<Json<Typed<BlobPublishedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_iroh_publishBlob",
            serde_json::json!({
                "bytes_b64": params.bytes_b64,
            }),
        )
        .await
    }

    #[tool(
        description = "Fetch a content-addressed `tenzro://blob|model|receipt/...` URI from the local iroh-blobs store (auto-populates from peers as needed). Returns base64-encoded bytes plus the parsed URI and size."
    )]
    async fn iroh_fetch_blob(
        &self,
        Parameters(params): Parameters<IrohFetchBlobParams>,
    ) -> std::result::Result<Json<Typed<BlobFetchedOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_iroh_fetchBlob",
            serde_json::json!({
                "tenzro_uri": params.tenzro_uri,
            }),
        )
        .await
    }

    // ---- Operability inspection surface (read-only) -------------------

    #[tool(
        description = "Fetch a single validator's registry entry by hex-encoded 32-byte address (with or without 0x prefix). Returns null when the address is not registered. Read-only — validators self-register via the staking transaction path."
    )]
    async fn get_validator_state(
        &self,
        Parameters(params): Parameters<GetValidatorStateParams>,
    ) -> std::result::Result<Json<Typed<Option<ValidatorEntryOutput>>>, ErrorData> {
        let payload = serde_json::json!({ "address": params.address });
        let result = rpc_dispatch(&self.node, "tenzro_getValidatorState", payload)
            .await
            .map_err(|e| err_internal(format!("getValidatorState failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List validators in the on-chain registry, optionally filtered by status ('Active' | 'Candidate' | 'PendingActive' | 'PendingExit' | 'Exited' | 'Jailed'). Each entry carries base58 address, Ed25519 + ML-DSA-65 pubkeys, self_stake (u128 decimal string), and epoch lifecycle markers."
    )]
    async fn list_validators(
        &self,
        Parameters(params): Parameters<ListValidatorsParams>,
    ) -> std::result::Result<Json<Typed<ValidatorsOutput>>, ErrorData> {
        let payload = match params.status {
            Some(s) => serde_json::json!({ "status": s }),
            None => serde_json::json!({}),
        };
        let result = rpc_dispatch(&self.node, "tenzro_listValidators", payload)
            .await
            .map_err(|e| err_internal(format!("listValidators failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List only currently-Active validators. Convenience over list_validators with status='Active'. Useful for SRE dashboards that need the current committee size and stake distribution."
    )]
    async fn list_active_validators(
        &self,
    ) -> std::result::Result<Json<Typed<ValidatorsOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listActiveValidators",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listActiveValidators failed: {}", e)))?;
        typed_result(result)
    }

    // ---- Generative media ----------------------------------------------

    #[tool(
        description = "List the curated generative-media catalog: ungated diffusers pipelines serving text2image, image2image, text2video, or image2video. Each entry carries id, hf_repo, pipeline_class, kinds, default resolution and steps, min_vram_gb, license, and expert_pair. A non-null expert_pair means the denoising schedule splits across two experts."
    )]
    async fn media_gen_list_catalog(
        &self,
    ) -> std::result::Result<Json<Typed<MediaGenCatalogOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_mediaGen_listCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("mediaGen.listCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Render one generative-media output now, on this node or on a provider serving the model. The answer carries what its signed receipt commits to (mime, output_sha256, output_bytes, the perceptual fingerprint and the tolerance a re-render must agree within), the receipt, the price, and output_blake3, under which the output is fetched with tenzro_iroh_fetchBlob. At verification 'optimistic' a share of renders is re-executed on another provider and a disagreement is filed as an inference fault."
    )]
    async fn media_gen_render(
        &self,
        Parameters(params): Parameters<MediaGenRenderParams>,
    ) -> std::result::Result<Json<Typed<MediaRenderOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "kind": params.kind,
            "params": params.params,
            "inputs_base64": params.inputs_base64.unwrap_or_default(),
            "verification": params.verification,
            "provider": params.provider,
        });
        let result = rpc_dispatch(&self.node, "tenzro_mediaGen_render", payload)
            .await
            .map_err(|e| err_internal(format!("mediaGen.render failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read the inference router's live metrics snapshot: total requests routed, hedges dispatched, hedges won, and requests abandoned on the whole-request deadline. Read-only — safe for monitoring agents."
    )]
    async fn get_router_metrics(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<RouterMetricsOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_getRouterMetrics", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("getRouterMetrics failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Look up the cached provenance manifest for generated content by its 32-byte hex content_hash (with or without 0x prefix). This is the machine-readable synthetic-content marker per EU AI Act Art. 50(2). Returns JSON-RPC -32004 when no manifest is cached for the hash. Read-only."
    )]
    async fn get_provenance(
        &self,
        Parameters(params): Parameters<GetProvenanceParams>,
    ) -> std::result::Result<Json<Typed<ContentProvenanceOutput>>, ErrorData> {
        let payload = serde_json::json!({ "content_hash": params.content_hash });
        let result = rpc_dispatch(&self.node, "tenzro_getContentProvenance", payload)
            .await
            .map_err(|e| err_internal(format!("getProvenance failed: {}", e)))?;
        typed_result(result)
    }

    // ---- adaptive burn-rate governance dial -------------------

    #[tool(
        description = "List the devices bound to an identity and what each proved about its hardware — attestation format, key protection tier, whether the chain reached a pinned vendor root, and the backup flags. A device counts as hardware-bound only when its credential cannot sync off it AND a verified attestation says the key is in a TEE or secure element. Also reports whether a wallet may be created and, if not, why."
    )]
    async fn list_bound_devices(
        &self,
        Parameters(params): Parameters<IdentityDidParams>,
    ) -> std::result::Result<Json<Typed<BoundDevicesOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_listBoundDevices",
            serde_json::json!({ "identity_did": params.identity_did }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Record a settlement, given as its interaction record, on other chains in parallel. A self-contained mirror writes the canonical settlement bytes, so the record stays readable with no Tenzro node in existence — the only form that survives the Tenzro Ledger losing state, which matters while Tenzro is on testnet. A digest-only mirror proves a payload you already hold is the one that settled but cannot say what settled. Returns one Bridge transaction per target for the caller to sign in hardware and submit; each lands independently, so partial success is the normal case."
    )]
    async fn mirror_settlement(
        &self,
        Parameters(params): Parameters<MirrorSettlementParams>,
    ) -> std::result::Result<Json<Typed<PayMirrorSettlementOutput>>, ErrorData> {
        let targets: Vec<serde_json::Value> = params
            .chains
            .iter()
            .map(|c| serde_json::json!({ "chain": c, "self_contained": !params.digest_only }))
            .collect();
        let v = rpc_dispatch(
            &self.node,
            "tenzro_mirrorSettlement",
            serde_json::json!({
                "interaction": params.interaction,
                "targets": targets,
                "primary_committed": true,
            }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "The rails a payment can settle on and the smallest worthwhile payment on each. Supporting x402 and being able to carry a micropayment are different properties: Base speaks x402 and still cannot carry a one-cent charge without roughly 10% overhead. Read this before declaring a settlement asset, because a rail that cannot carry your typical charge will accumulate it in a channel instead of settling it."
    )]
    async fn settlement_networks(
        &self,
    ) -> std::result::Result<Json<Typed<PaySettlementNetworksOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_settlementNetworks",
            serde_json::json!({}),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Whether an identity may create a wallet yet, and what to do if not. A wallet cannot sit behind a single root of control: it needs two separate devices that amount to two independent roots. Synced passkeys count, but passkeys one provider syncs count once between them; a device-bound credential counts on its own. Returns the bound-device count, the independent-root count, and a remedy code alongside the reason."
    )]
    async fn wallet_readiness(
        &self,
        Parameters(params): Parameters<IdentityDidParams>,
    ) -> std::result::Result<Json<Typed<WalletReadinessOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_walletReadiness",
            serde_json::json!({ "identity_did": params.identity_did }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Show this node's economic policy — how a settled payment divides, the network's default settlement asset, and the micro-settlement floor. Also reports the node's visibility and the economic mode it puts the node in: a private node keeps the whole payment, a public validating one shares with the treasury, and a public one that does not validate also pays the RPC provider validating on its behalf. Read this before paying rather than inferring the split from a receipt. Every rate is governance-set."
    )]
    async fn get_economic_policy(
        &self,
    ) -> std::result::Result<Json<Typed<EconomicPolicyOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getEconomicPolicy",
            serde_json::json!({}),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Show the current adaptive burn-rate config — base and local fee burn bps with their treasury complements. The dial moves only via on-chain governance proposals (see adaptive_burn_get_recommendation)."
    )]
    async fn adaptive_burn_get_config(
        &self,
    ) -> std::result::Result<Json<Typed<BurnConfigOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getBurnRateConfig",
            serde_json::json!({}),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Show the latest supply-side metrics snapshot — block height, circulating supply, rolling-window epoch delta, burn breakdown, and supply added (always 0: TNZO supply is fixed; the emission_breakdown field name is kept). Drives the recommendation engine."
    )]
    async fn adaptive_burn_get_metrics(
        &self,
    ) -> std::result::Result<Json<Typed<SupplyMetricsOutput>>, ErrorData> {
        let v = rpc_dispatch(&self.node, "tenzro_getSupplyMetrics", serde_json::json!({})).await?;
        typed_result(v)
    }

    #[tool(
        description = "Show the current adaptive-burn recommendation — action (NoChange / IncreaseBurnPct / DecreaseBurnPct / AlarmHighInflation, a supply increase the ledger refuses, so a fault / AlarmHighDeflation), magnitude bps, and whether it's above the auto-proposal floor. Pure function of metrics + targets, no side effects."
    )]
    async fn adaptive_burn_get_recommendation(
        &self,
    ) -> std::result::Result<Json<Typed<BurnRecommendationOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getBurnRateRecommendation",
            serde_json::json!({}),
        )
        .await?;
        typed_result(v)
    }

    // ---- Settlement plans ---------------------------------------------

    #[tool(
        description = "Preview how a gross amount divides under a split rule with the live fee parameters: the protocol fee once on the gross (burn, treasury, insurance), payee-borne network fees, then each split line's credit, exactly as the chain divides it. Returns the allocation and the rule hash a quote signs."
    )]
    async fn settle_preview_split(
        &self,
        Parameters(params): Parameters<SettlePreviewParams>,
    ) -> std::result::Result<Json<Typed<SettlePreviewSplitOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_previewSplit",
            serde_json::json!({
                "gross": params.gross,
                "split": params.split,
                "network_fees": params.network_fees.unwrap_or_else(|| "0".into()),
            }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Fetch an asset's netting batch: its obligations, close time, and once settled the net instructions, what each paid, defaults and the obligations' Merkle root, with its state-proof key; with a participant, its collateral and gross-to-net statement."
    )]
    async fn settle_get_netting_batch(
        &self,
        Parameters(params): Parameters<SettleNettingBatchParams>,
    ) -> std::result::Result<Json<Typed<SettleNettingBatchOutput>>, ErrorData> {
        let mut req = serde_json::json!({ "asset": params.asset });
        if let Some(seq) = params.seq {
            req["seq"] = seq.into();
        }
        if let Some(p) = params.participant {
            req["participant"] = p.into();
        }
        let v = rpc_dispatch(&self.node, "tenzro_getNettingBatch", req).await?;
        typed_result(v)
    }

    #[tool(
        description = "Check a reconciliation of a route's settlement lock against the route's stored one and return the SettlementPlan reconcile transaction for the caller to sign and send, with the count and running hash the checkpoint must prove."
    )]
    async fn settle_submit_reconciliation(
        &self,
        Parameters(params): Parameters<SettleReconcileParams>,
    ) -> std::result::Result<Json<Typed<SettleSubmitReconciliationOutput>>, ErrorData> {
        let req = serde_json::json!({
            "adapter": params.adapter,
            "chain": params.chain,
            "entries": params.entries,
            "checkpoint": params.checkpoint,
        });
        typed_result(rpc_dispatch(&self.node, "tenzro_submitReconciliation", req).await?)
    }

    #[tool(
        description = "Fetch how far a route's settlement lock is reconciled against Tenzro's books: entry count, running hash, last checkpoint digest and mismatch positions, with its state-proof key."
    )]
    async fn settle_get_reconciliation(
        &self,
        Parameters(params): Parameters<SettleRouteParams>,
    ) -> std::result::Result<Json<Typed<SettleReconciliationOutput>>, ErrorData> {
        let req = serde_json::json!({ "adapter": params.adapter, "chain": params.chain });
        typed_result(rpc_dispatch(&self.node, "tenzro_getReconciliation", req).await?)
    }

    #[tool(
        description = "List the reconciliation mismatches stored for a route's settlement lock: each entry that disagreed with Tenzro's books, why, the account it cost and the loss an insurance claim can pay, with state-proof keys."
    )]
    async fn settle_list_mismatches(
        &self,
        Parameters(params): Parameters<SettleRouteParams>,
    ) -> std::result::Result<Json<Typed<SettleMismatchesOutput>>, ErrorData> {
        let req = serde_json::json!({ "adapter": params.adapter, "chain": params.chain });
        typed_result(rpc_dispatch(&self.node, "tenzro_listMismatches", req).await?)
    }

    #[tool(
        description = "Fetch a settlement plan: legs, split rule, tier, funded value, status, each leg's achieved class, and its state-proof key."
    )]
    async fn settle_get_plan(
        &self,
        Parameters(params): Parameters<SettlePlanIdParams>,
    ) -> std::result::Result<Json<Typed<SettlePlanOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getPlan",
            serde_json::json!({ "plan_id": params.plan_id }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Fetch a settlement plan's one Commit-or-Abort decision (the record remote locks verify), with the division paid on commit and its state-proof key."
    )]
    async fn settle_get_decision(
        &self,
        Parameters(params): Parameters<SettlePlanIdParams>,
    ) -> std::result::Result<Json<Typed<SettleDecisionOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getPlanDecision",
            serde_json::json!({ "plan_id": params.plan_id }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Build the SettlementPlan transaction that opens a plan, for the payer's wallet to sign client-side: completes the caller's unsigned request with tx_type and gas_limit, after the same checks the chain applies to the operation's shape, and returns it with its signing payload. Sign on the payer's device, then send it with tenzro_sendRawTransaction. Nothing is signed or sent here."
    )]
    async fn settle_open_plan(
        &self,
        Parameters(params): Parameters<SettleOpenPlanParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PaySettlementPlanTx<PayPlanOpOpen>>>>,
        ErrorData,
    > {
        let op = serde_json::json!({ "open": params.open });
        let transaction = plan_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            op,
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Build the SettlementPlan transaction that proves one leg of a plan (anyone may send it; the transaction that brings the last leg in commits the plan): returns the completed request and its signing payload for the sender's wallet, as settle_open_plan does. Nothing is signed or sent here."
    )]
    async fn settle_prove_leg(
        &self,
        Parameters(params): Parameters<SettleProveLegParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PaySettlementPlanTx<PayPlanOpProveLeg>>>>,
        ErrorData,
    > {
        let op = serde_json::json!({ "prove_leg": {
            "plan_id": params.plan_id,
            "index": params.index,
            "evidence": params.evidence.unwrap_or_default(),
            "network_fee": params.network_fee.unwrap_or_else(|| "0".into()),
        }});
        let transaction = plan_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            op,
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Build the SettlementPlan transaction by which a rail leg's payee disputes its attestor's confirmation inside the compensation window: on success the payee is paid the leg's reserve and the attestor's bond is slashed into the insurance pool. Returns the completed request and its signing payload for the payee's wallet, as settle_open_plan does. Nothing is signed or sent here."
    )]
    async fn settle_dispute_rail(
        &self,
        Parameters(params): Parameters<SettleDisputeRailParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PaySettlementPlanTx<PayPlanOpDisputeRail>>>>,
        ErrorData,
    > {
        let op = serde_json::json!({ "dispute_rail": {
            "plan_id": params.plan_id,
            "index": params.index,
            "evidence": params.evidence,
        }});
        let transaction = plan_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            op,
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Build the Bridge transaction that sends value out over a governed route, for the holder's wallet to sign client-side: TNZO, or a carried asset (asset: USDC) whose representation is burned here and released from the route's vault on the target chain. Completes the unsigned request with tx_type and gas_limit after the chain's shape checks and returns it with its signing payload. Sign on the holder's device, then send it with tenzro_sendRawTransaction. Nothing is signed or sent here."
    )]
    async fn bridge_outbound(
        &self,
        Parameters(params): Parameters<BridgeOutboundParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PayBridgeTx<PayBridgeOpOutbound>>>>,
        ErrorData,
    > {
        let amount: u128 = params
            .amount
            .trim()
            .parse()
            .map_err(|_| ErrorData::invalid_params("amount must be a decimal integer", None))?;
        let recipient = hex::decode(params.recipient.trim_start_matches("0x"))
            .map_err(|_| ErrorData::invalid_params("recipient must be hex", None))?;
        let op = tenzro_types::bridge_transfer::BridgeOp::Outbound {
            target_chain: params.target_chain.to_ascii_lowercase(),
            recipient,
            amount,
            asset: params.asset.map(|a| a.to_ascii_uppercase()),
        };
        op.validate()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let gas_limit = tenzro_vm::native::bridge_gas(&op);
        let transaction = typed_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            tenzro_types::transaction::TransactionType::Bridge { op },
            gas_limit,
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Build the Payment transaction by which a payee returns part or all of a native payment to its payer, in the asset it was paid in (refunds on one record never exceed what it paid), for the payee's wallet to sign client-side. Returns the completed request and its signing payload, as bridge_outbound does. Nothing is signed or sent here."
    )]
    async fn payment_refund(
        &self,
        Parameters(params): Parameters<PaymentRefundParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PayPaymentTx<PayPaymentOpRefund>>>>,
        ErrorData,
    > {
        let op = serde_json::json!({ "refund": { "pay_ref": params.pay_ref.trim_start_matches("0x"), "amount": params.amount.trim() } });
        let op: tenzro_types::settlement::PaymentOp = serde_json::from_value(op)
            .map_err(|e| ErrorData::invalid_params(format!("refund: {e}"), None))?;
        if matches!(
            op,
            tenzro_types::settlement::PaymentOp::Refund { amount: 0, .. }
        ) {
            return Err(ErrorData::invalid_params("amount must be positive", None));
        }
        let transaction = payment_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            op,
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Build the Payment transaction by which a payee sets the standing split rule every payment it receives is divided by after the fee (rule null clears it), for the payee's wallet to sign client-side. Returns the completed request and its signing payload, as bridge_outbound does. Nothing is signed or sent here."
    )]
    async fn payment_set_split(
        &self,
        Parameters(params): Parameters<PaymentSetSplitParams>,
    ) -> std::result::Result<
        Json<Typed<PayBuiltTransaction<PayPaymentTx<PayPaymentOpSetSplit>>>>,
        ErrorData,
    > {
        let rule: Option<tenzro_types::split::SplitRule> = params
            .rule
            .map(|r| serde_json::to_value(r).and_then(serde_json::from_value))
            .transpose()
            .map_err(|e| ErrorData::invalid_params(format!("rule: {e}"), None))?;
        let transaction = payment_request(
            serde_json::to_value(&params.transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
            tenzro_types::settlement::PaymentOp::SetSplit { rule },
        )?;
        let signing_payload =
            rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction.clone()).await?;
        typed_result(
            serde_json::json!({ "transaction": transaction, "signing_payload": signing_payload }),
        )
    }

    #[tool(
        description = "Fetch one settlement-plan leg's receipt (decision, class achieved, value) and its recorded evidence (class, evidence digest, a hash-locked leg's funding txid and, once the plan commits, the preimage the recipient claims with), each with its state-proof key."
    )]
    async fn settle_get_leg_receipt(
        &self,
        Parameters(params): Parameters<SettleLegReceiptParams>,
    ) -> std::result::Result<Json<Typed<SettleLegReceiptOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_getLegReceipt",
            serde_json::json!({ "plan_id": params.plan_id, "index": params.index }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "List settlement plans, optionally by payer and status (open, committed, aborted)."
    )]
    async fn settle_list_plans(
        &self,
        Parameters(params): Parameters<SettleListPlansParams>,
    ) -> std::result::Result<Json<Typed<SettlePlanListOutput>>, ErrorData> {
        let v = rpc_dispatch(
            &self.node,
            "tenzro_listPlans",
            serde_json::json!({ "payer": params.payer, "status": params.status, "limit": params.limit }),
        )
        .await?;
        typed_result(v)
    }

    #[tool(
        description = "Discover AI models on the Tenzro Network. Filter by free-text query, modality, or serving status."
    )]
    async fn discover_models(
        &self,
        Parameters(params): Parameters<DiscoverModelsParams>,
    ) -> std::result::Result<Json<Typed<DiscoveredModelsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_discoverModels",
            serde_json::json!({
                "query": params.query,
                "modality": params.modality,
                "serving_only": params.serving_only,
            }),
        )
        .await
    }

    // ─── Agent Template Tools ───

    // ─── Token & Contract Tools ───

    #[tool(
        description = "Get information about a token by symbol, token ID, or EVM address. Returns the full token definition including cross-VM addresses."
    )]
    async fn get_token_info(
        &self,
        Parameters(params): Parameters<GetTokenInfoParams>,
    ) -> std::result::Result<Json<Typed<TokenInfoOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getToken",
            serde_json::json!({
                "symbol": params.symbol,
                "evm_address": params.evm_address,
                "token_id": params.token_id,
            }),
        )
        .await
    }

    #[tool(
        description = "List all registered tokens in the unified token registry. Optionally filter by VM type or creator address."
    )]
    async fn list_tokens(
        &self,
        Parameters(params): Parameters<ListTokensParams>,
    ) -> std::result::Result<Json<Typed<TokensOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_listTokens",
            serde_json::json!({
                "vm_type": params.vm_type,
                "limit": params.limit,
            }),
        )
        .await
    }

    #[tool(
        description = "Get the TNZO balance for an address across all VMs. Shows native balance (18 decimals), EVM wTNZO balance (18 decimals), and SVM wTNZO balance (9 decimals)."
    )]
    async fn get_token_balance(
        &self,
        Parameters(params): Parameters<GetTokenBalanceParams>,
    ) -> std::result::Result<Json<Typed<TokenBalanceOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getTokenBalance",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    // ─── Skill & Tool Usage ───

    // ─── Agent Template Marketplace Extended ───

    // ─── NFT Tools ───

    #[tool(
        description = "Check whether a token's rules allow a holder transfer now: halt, frozen balance, lockup and every eligibility rule (claims, jurisdiction, holder kind, holder and balance ceilings, agent Terms level). Returns allowed, and the refusal code and reason when not."
    )]
    async fn can_transfer(
        &self,
        Parameters(params): Parameters<CanTransferParams>,
    ) -> std::result::Result<Json<Typed<CanTransferOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_canTransfer",
            serde_json::json!({
                "token_id": params.token_id,
                "from": params.from,
                "to": params.to,
                "amount": params.amount,
            }),
        )
        .await
    }

    // ─── Events Tools ───

    #[tool(
        description = "Query a range of the chain's events, each with its proof against a certified checkpoint. Page with the returned cursor (pass it back as from_cursor)."
    )]
    async fn query_events(
        &self,
        Parameters(params): Parameters<QueryEventsParams>,
    ) -> std::result::Result<Json<Typed<EventsPageOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_queryEvents",
            serde_json::to_value(params).expect("params encode"),
        )
        .await
    }

    #[tool(
        description = "Read the chain's next events after a cursor, waiting up to wait_ms for new blocks. Keep the returned cursor and pass it back as from_cursor: a restarted reader resumes with no gap. For push notifications, subscribe to the tenzro://events resource instead."
    )]
    async fn subscribe_events(
        &self,
        Parameters(params): Parameters<SubscribeEventsParams>,
    ) -> std::result::Result<Json<Typed<EventsPageOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_subscribe",
            serde_json::to_value(params).expect("params encode"),
        )
        .await
    }

    #[tool(
        description = "The chain's randomness beacon: the next round and current mix, the value taken at a round, or the first value taken at or after a block time. Bonded validators feed it VRF outputs under their node keys; applications draw panels and committees from it."
    )]
    async fn get_beacon(
        &self,
        Parameters(params): Parameters<GetBeaconParams>,
    ) -> std::result::Result<Json<Typed<BeaconOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getBeacon",
            serde_json::to_value(params).expect("params encode"),
        )
        .await
    }

    #[tool(
        description = "A data-availability object as chain state records it: its class (history or audit), size, when it was recorded and when its governed retention expires it."
    )]
    async fn get_da_object(
        &self,
        Parameters(params): Parameters<GetDaObjectParams>,
    ) -> std::result::Result<Json<Typed<DaObjectOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_getDaObject",
            serde_json::to_value(params).expect("params encode"),
        )
        .await
    }

    #[tool(
        description = "Retention of data-availability objects: the governed retention of each class (audit never under 183 days), the live and expired totals, and where expiry stands."
    )]
    async fn get_da_retention(
        &self,
    ) -> std::result::Result<Json<Typed<DaRetentionOutput>>, ErrorData> {
        rpc_tool_typed(&self.node, "tenzro_getDaRetention", serde_json::json!({})).await
    }

    #[tool(
        description = "Check an event proof (from query_events or subscribe_events with proofs) against the certification this node holds for its anchor checkpoint."
    )]
    async fn verify_event_proof(
        &self,
        Parameters(params): Parameters<VerifyEventProofParams>,
    ) -> std::result::Result<Json<Typed<EventProofVerdictOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_verifyEventProof",
            serde_json::json!({ "proof": params.proof }),
        )
        .await
    }

    // ─── SLA Fault Detector ───

    #[tool(
        description = "Administrators only. Issue a VRF-bound SLA liveness probe to a ModelProvider / TeeProvider DID and broadcast it on the `tenzro/sla` gossip topic. The deadline must leave the provider at least 10 seconds to answer, and only answers signed by the hardware identity registered for the bond count. Validator-only — on a non-validator node this returns `-32000 SlaManager not initialized`. The probe is addressed by a 32-byte VRF output (`challenge_nonce`). `deadline_ms` is a Unix-millisecond timestamp; if the provider does not respond before this deadline the probe is counted as missed against the fault-detector's slash threshold."
    )]
    async fn sla_issue_probe(
        &self,
        Parameters(params): Parameters<SlaIssueProbeParams>,
    ) -> std::result::Result<Json<Typed<SlaIssuedProbeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_slaIssueProbe",
            serde_json::json!({
                "provider_did": params.provider_did,
                "epoch": params.epoch,
                "round": params.round,
                "deadline_ms": params.deadline_ms,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("slaIssueProbe failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List every in-flight SLA probe awaiting a response, regardless of issuer. Returns `{count, probes: [...]}` with `challenge_nonce`, `provider_did`, `epoch`, `round`, `deadline_ms`, and `issuer` for each probe. Used by operators to spot stuck probes whose deadline has already elapsed without a matching response."
    )]
    async fn sla_list_outstanding_probes(
        &self,
    ) -> std::result::Result<Json<Typed<SlaProbesOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_slaListOutstandingProbes",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("slaListOutstandingProbes failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read the SLA parameters: `unavailable_penalty_wei` (what a frozen unavailable verdict takes from the provider's compute bond into the insurance pool, decimal string) and this validator's `vrf_pubkey` (0x-prefixed hex)."
    )]
    async fn sla_get_params(&self) -> std::result::Result<Json<Typed<SlaParamsOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_slaGetParams", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("slaGetParams failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Snapshot (State Sync) ───

    #[tool(
        description = "List the state snapshots this node serves over iroh for state sync. Returns `{snapshots: [{height, state_root, manifest_blob, buckets}, ...], endpoint_id}`; a joining node asks `endpoint_id` for a manifest and fetches the blobs it names."
    )]
    async fn list_snapshots(&self) -> std::result::Result<Json<Typed<SnapshotsOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listSnapshots", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listSnapshots failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Fetch the snapshot manifest at `height`: the state root, every bucket's summary and BLAKE3 blob hash, and the blob holding the blocks that commit the root. Returns JSON-RPC error `-32004 no snapshot at height` if none exists. The manifest is only a pointer: a joining node checks it against a block it already trusts before using it."
    )]
    async fn get_snapshot_manifest(
        &self,
        Parameters(params): Parameters<SnapshotManifestParams>,
    ) -> std::result::Result<Json<Typed<SnapshotManifestOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getSnapshotManifest",
            serde_json::json!({ "height": params.height }),
        )
        .await
        .map_err(|e| err_internal(format!("getSnapshotManifest failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Institutional-primitive tools + bridge fee quote ───

    #[tool(
        description = "Read the ERC-7943 (uRWA) kill-switch state for a given token_id (32-byte hex). Returns the kill-switch active flag, the canonical 4-byte selectors for the standard uRWA functions, and the precompile addresses backing the on-chain enforcement path."
    )]
    async fn urwa_is_kill_switched(
        &self,
        Parameters(params): Parameters<UrwaTokenIdParams>,
    ) -> std::result::Result<Json<Typed<KillSwitchOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_urwaIsKillSwitched",
            serde_json::json!({ "token_id_hex": params.token_id_hex }),
        )
        .await
        .map_err(|e| err_internal(format!("urwaIsKillSwitched failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read the ERC-7943 (uRWA) frozen-tokens amount for a (token_id, account) pair. Returns the frozen amount in token smallest unit."
    )]
    async fn urwa_get_frozen_tokens(
        &self,
        Parameters(params): Parameters<UrwaFrozenLookupParams>,
    ) -> std::result::Result<Json<Typed<FrozenTokensOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_urwaGetFrozenTokens",
            serde_json::json!({
                "token_id_hex": params.token_id_hex,
                "account_hex": params.account_hex
            }),
        )
        .await
        .map_err(|e| err_internal(format!("urwaGetFrozenTokens failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Quote the destination-native bridge fee in TNZO for a given (adapter, dest_chain, native_fee_smallest_unit). Read-only; converts at the USD rates validators committed on chain and is refused while the destination's native asset is unpriced."
    )]
    async fn quote_bridge_fee_in_tnzo(
        &self,
        Parameters(params): Parameters<QuoteBridgeFeeParams>,
    ) -> std::result::Result<Json<Typed<PayBridgeFeeQuote>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_quoteBridgeFeeInTnzo",
            serde_json::json!({
                "adapter": params.adapter,
                "dest_chain": params.dest_chain,
                "native_fee_smallest_unit": params.native_fee_smallest_unit,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("quoteBridgeFeeInTnzo failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Permit2 Tools (SignatureTransfer) ───

    #[tool(
        description = "Atomically verify a signed Permit2 message and consume its (owner, nonce) bitmap slot. Returns `{consumed, word_pos, bit_pos}`."
    )]
    async fn permit2_verify_and_consume(
        &self,
        Parameters(params): Parameters<Permit2VerifyAndConsumeParams>,
    ) -> std::result::Result<Json<Typed<Permit2ConsumedOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_permit2VerifyAndConsume",
            serde_json::to_value(&params).unwrap_or(serde_json::Value::Null),
        )
        .await
        .map_err(|e| err_internal(format!("permit2VerifyAndConsume failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Check whether a (owner, nonce) Permit2 slot has been consumed. Returns `{used, owner, nonce}`."
    )]
    async fn permit2_nonce_used(
        &self,
        Parameters(params): Parameters<Permit2NonceUsedParams>,
    ) -> std::result::Result<Json<Typed<Permit2NonceOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_permit2NonceUsed",
            serde_json::json!({ "owner": params.owner, "nonce": params.nonce }),
        )
        .await
        .map_err(|e| err_internal(format!("permit2NonceUsed failed: {}", e)))?;
        typed_result(result)
    }

    // ─── CAIP Discovery Tools (ChainAgnostic/namespaces#184) ───

    // ─── Auth-engine Approval Workflow Tools ───

    // ─── Escrow + Dispute Inspection Tools ───

    #[tool(
        description = "Read a single escrow record by its 32-byte escrow_id (hex, with or without 0x prefix). Returns `{escrow_id, payer, payee, amount, asset_id, status, created_at, expires_at, release_conditions}`."
    )]
    async fn get_escrow(
        &self,
        Parameters(params): Parameters<GetEscrowParams>,
    ) -> std::result::Result<Json<Typed<PayEscrowView>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getEscrow",
            serde_json::json!({ "escrow_id": params.escrow_id }),
        )
        .await
        .map_err(|e| err_internal(format!("getEscrow failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read the standing split rule every payment a payee receives is divided by after the fee (the split engine's lines: role, recipient, basis points, fixed amount or remainder), from consensus state; null when it set none."
    )]
    async fn get_payee_split(
        &self,
        Parameters(params): Parameters<GetPayeeSplitParams>,
    ) -> std::result::Result<Json<Typed<PayPayeeSplitOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getPayeeSplit",
            serde_json::json!({ "payee": params.payee }),
        )
        .await
        .map_err(|e| err_internal(format!("getPayeeSplit failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Read one payment's consensus record, native, proven on another chain or attested on another rail, by its reference (pay_ref) or the payment id it settled under. Returns the payer, payee, asset, amount, settlement fee, the request, quote and USD price the payer signed, the paying agent if any, and the payee's delivery receipts; null when nothing is recorded."
    )]
    async fn get_payment_proof(
        &self,
        Parameters(params): Parameters<GetPaymentProofParams>,
    ) -> std::result::Result<Json<Typed<Option<PayPaymentRecord>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getPayment",
            serde_json::json!({ "pay_ref": params.pay_ref, "payment_id": params.payment_id }),
        )
        .await
        .map_err(|e| err_internal(format!("getPayment failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List consensus payment records in chain order, read from the chain's event index: native, proven and attested payments, optionally only those to a payee, from a payer, by a delegated agent, of one class or asset. Each entry carries its event cursor and, with proofs, the event's proof; `settlement` (the burn and treasury leg its transaction declared) and `work` (the call this node recorded for it: model, units, serving node, hardware tier, latency; node-local), each null when unknown. Pass the returned cursor back as from_cursor to continue."
    )]
    async fn list_payments(
        &self,
        Parameters(params): Parameters<ListPaymentsParams>,
    ) -> std::result::Result<Json<Typed<PayListPaymentsOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listPayments",
            serde_json::to_value(&params).unwrap_or_default(),
        )
        .await
        .map_err(|e| err_internal(format!("listPayments failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "As the calling delegated agent, have this serving node sign the agent's next cumulative voucher on a channel its wallet funded. The node signs only a voucher the ledger would honour now: this machine assigned in the agent's current terms, the agent not revoked or quarantined, the amount within the lock its terms counted at open."
    )]
    async fn agent_voucher(
        &self,
        Parameters(params): Parameters<AgentVoucherParams>,
    ) -> std::result::Result<Json<Typed<PayAgentVoucherOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_agentVoucher",
            serde_json::json!({ "channel_id": params.channel_id, "cumulative_amount": params.cumulative_amount }),
        )
        .await
        .map_err(|e| err_internal(format!("agentVoucher failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "What a USD price (micro-units) costs in TNZO now, with the settlement fee it pays, as a payment settled now counts it. Returns {usd_e6, unit, rate_epoch, assets: [{asset, amount, fee, fee_asset, rate_epoch}]}."
    )]
    async fn quote_resource(
        &self,
        Parameters(params): Parameters<QuoteResourceParams>,
    ) -> std::result::Result<Json<Typed<QuoteResourceOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_quotePayment",
            serde_json::json!({ "usd_e6": params.usd_e6 }),
        )
        .await
        .map_err(|e| err_internal(format!("quotePayment failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "As the calling delegated agent, have this serving node sign a voucher on a channel the agent's account holds on another chain. The account pays it up to the channel's deposit while the agent's grant there is not void; the node signs only while the agent is live and the node is assigned in its terms."
    )]
    async fn sign_remote_channel_voucher(
        &self,
        Parameters(params): Parameters<RemoteChannelVoucherParams>,
    ) -> std::result::Result<Json<Typed<RemoteChannelVoucherOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_signRemoteChannelVoucher",
            serde_json::json!({
                "chain": params.chain,
                "channel_id": params.channel_id,
                "cumulative_amount": params.cumulative_amount,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("signRemoteChannelVoucher failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List every escrow funded by the given payer address. Returns `{payer, escrows: [...], cursor}` in creation order from the EscrowCreated event log; pass `cursor` back as `from_cursor` for the next page."
    )]
    async fn list_escrows_by_payer(
        &self,
        Parameters(params): Parameters<ListEscrowsByPayerParams>,
    ) -> std::result::Result<Json<Typed<PayEscrowsByPayerOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listEscrowsByPayer",
            serde_json::json!({ "payer": params.payer }),
        )
        .await
        .map_err(|e| err_internal(format!("listEscrowsByPayer failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List every escrow held for the given payee address. Returns `{payee, escrows: [...], cursor}` in creation order from the EscrowCreated event log; pass `cursor` back as `from_cursor` for the next page."
    )]
    async fn list_escrows_by_payee(
        &self,
        Parameters(params): Parameters<ListEscrowsByPayeeParams>,
    ) -> std::result::Result<Json<Typed<PayEscrowsByPayeeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listEscrowsByPayee",
            serde_json::json!({ "payee": params.payee }),
        )
        .await
        .map_err(|e| err_internal(format!("listEscrowsByPayee failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Verifiable Inference Tools (TOPLOC commitments + challenges) ───

    #[tool(
        description = "Fetch a stored TOPLOC inference commitment by hash. Returns the envelope {commitment_hash, model_id, provider, created_at, commitment: {k, prompt_tokens, steps}} or null when no commitment is stored under that hash. Mirrors tenzro_getInferenceCommitment."
    )]
    async fn get_inference_commitment(
        &self,
        Parameters(params): Parameters<GetInferenceCommitmentParams>,
    ) -> std::result::Result<Json<Typed<Option<InferenceCommitmentOutput>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getInferenceCommitment",
            serde_json::json!({ "commitment_hash": params.commitment_hash }),
        )
        .await
        .map_err(|e| err_internal(format!("getInferenceCommitment failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Verify a stored inference commitment by re-executing the prompt+output as a single prefill and comparing per-step top-k logits. The caller supplies the exact prompt (never stored). Requires the model loaded in serial (llama.cpp) mode on this node. Returns {commitment_hash, model_id, provider, pass, steps_total, steps_passed, failing_steps}. Mirrors tenzro_verifyInferenceCommitment."
    )]
    async fn verify_inference_commitment(
        &self,
        Parameters(params): Parameters<VerifyInferenceCommitmentParams>,
    ) -> std::result::Result<Json<Typed<CommitmentVerificationOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_verifyInferenceCommitment",
            serde_json::json!({
                "commitment_hash": params.commitment_hash,
                "prompt": params.prompt,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("verifyInferenceCommitment failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "File a challenge against a stored inference commitment. Open to any caller; the model and provider are read from the stored envelope so filings cannot misattribute. Returns the filed challenge record with its challenge_id. Mirrors tenzro_fileInferenceChallenge."
    )]
    async fn file_inference_challenge(
        &self,
        Parameters(params): Parameters<FileInferenceChallengeParams>,
    ) -> std::result::Result<Json<Typed<InferenceChallengeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_fileInferenceChallenge",
            serde_json::json!({
                "commitment_hash": params.commitment_hash,
                "challenger": params.challenger,
                "reason": params.reason,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("fileInferenceChallenge failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Fetch an inference challenge by id. Returns the full record (status, filed_at, resolved_at, verification) or null when unknown. Mirrors tenzro_getInferenceChallenge."
    )]
    async fn get_inference_challenge(
        &self,
        Parameters(params): Parameters<GetInferenceChallengeParams>,
    ) -> std::result::Result<Json<Typed<Option<InferenceChallengeOutput>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getInferenceChallenge",
            serde_json::json!({ "challenge_id": params.challenge_id }),
        )
        .await
        .map_err(|e| err_internal(format!("getInferenceChallenge failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List inference challenges, optionally filtered by status (voting_commit/voting_reveal/upheld/dismissed) and provider. Returns {count, challenges: [...]} sorted newest first. Mirrors tenzro_listInferenceChallenges."
    )]
    async fn list_inference_challenges(
        &self,
        Parameters(params): Parameters<ListInferenceChallengesParams>,
    ) -> std::result::Result<Json<Typed<InferenceChallengesOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listInferenceChallenges",
            serde_json::json!({
                "status": params.status,
                "provider": params.provider,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("listInferenceChallenges failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Commit a committee vote on an inference challenge. Open to drawn committee seats only. `commit_hash` = compute_vote_commit(verdict, salt, challenge_id, voter); the verdict stays hidden until reveal. When committed stake reaches the 2f+1 threshold the challenge advances to the reveal phase. Mirrors tenzro_commitChallengeVote."
    )]
    async fn commit_challenge_vote(
        &self,
        Parameters(params): Parameters<CommitChallengeVoteParams>,
    ) -> std::result::Result<Json<Typed<InferenceChallengeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_commitChallengeVote",
            serde_json::json!({
                "challenge_id": params.challenge_id,
                "voter": params.voter,
                "commit_hash": params.commit_hash,
                "signature": params.signature,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("commitChallengeVote failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Reveal a previously committed committee vote. `(verdict, salt)` must reproduce the earlier commit hash. verdict=true means the commitment did not verify (upholds the challenge). Mirrors tenzro_revealChallengeVote."
    )]
    async fn reveal_challenge_vote(
        &self,
        Parameters(params): Parameters<RevealChallengeVoteParams>,
    ) -> std::result::Result<Json<Typed<InferenceChallengeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_revealChallengeVote",
            serde_json::json!({
                "challenge_id": params.challenge_id,
                "voter": params.voter,
                "verdict": params.verdict,
                "salt": params.salt,
                "signature": params.signature,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("revealChallengeVote failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Finalize an inference challenge by tallying revealed committee votes weighted by stake. No administrator decides: the verdict is the committee's. Idempotent: a decided challenge returns unchanged. An upheld verdict decrements the provider's reputation (response carries reputation_penalized); slashing a compute bond is the consensus InferenceFault path. A challenge with no quorum closes as dismissed once its reveal window has passed. Mirrors tenzro_finalizeChallenge."
    )]
    async fn finalize_challenge(
        &self,
        Parameters(params): Parameters<FinalizeChallengeParams>,
    ) -> std::result::Result<Json<Typed<InferenceChallengeOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_finalizeChallenge",
            serde_json::json!({
                "challenge_id": params.challenge_id,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("finalizeChallenge failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Crypto Tools ───

    #[tool(
        description = "Verify a cryptographic signature against a public key and message. Returns whether the signature is valid."
    )]
    async fn verify_signature(
        &self,
        Parameters(params): Parameters<VerifySignatureParams>,
    ) -> std::result::Result<Json<Typed<SignatureCheckOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_verifySignature",
            serde_json::json!({
                "public_key": params.public_key,
                "message_hex": params.message_hex,
                "signature_hex": params.signature_hex,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("verifySignature failed: {}", e)))?;
        typed_result(result)
    }

    // ─── TEE Tools ───

    #[tool(
        description = "Detect available Trusted Execution Environment (TEE) hardware on this node. Returns detected TEE type (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) or simulation mode."
    )]
    async fn detect_tee(
        &self,
        Parameters(_params): Parameters<DetectTeeParams>,
    ) -> std::result::Result<Json<Typed<DetectTeeOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_detectTee", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("detectTee failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Generate a TEE attestation report from the node's hardware enclave. Returns the report (`report_hex`, as tenzro_verifyTeeAttestation takes it) and its measurement registers (TDX: MRTD and RTMR0-3; SEV-SNP: MEASUREMENT) to compare with the published measurements of the image the node runs."
    )]
    async fn get_tee_attestation(
        &self,
        Parameters(params): Parameters<GetTeeAttestationParams>,
    ) -> std::result::Result<Json<Typed<TeeAttestationOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getTeeAttestation",
            serde_json::json!({
                "user_data": params.user_data,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("getAttestation failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Verify a TEE attestation report against a nonce issued by tenzro_teeAttestationChallenge: vendor signature, certificate chain to the pinned vendor root, collateral, debug state and the challenge binding."
    )]
    async fn verify_tee_attestation(
        &self,
        Parameters(params): Parameters<VerifyTeeAttestationParams>,
    ) -> std::result::Result<Json<Typed<TeeAttestationVerdictOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_verifyTeeAttestation",
            serde_json::json!({
                "report_hex": params.attestation,
                "nonce": params.nonce,
                "bound_data": params.bound_data,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("verifyTeeAttestation failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List all registered TEE providers on the network, including their TEE type, attestation status, and supported capabilities."
    )]
    async fn list_tee_providers(
        &self,
        Parameters(_params): Parameters<ListTeeProvidersParams>,
    ) -> std::result::Result<Json<Typed<TeeProvidersOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listTeeProviders", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listTeeProviders failed: {}", e)))?;
        typed_result(result)
    }

    // ─── ZK Tools ───

    #[tool(
        description = "Prove a `settlement` statement (knowledge of the 32-byte service result whose SHA3-256 under the settlement domain is the public digest) in every proof system. Returns the public inputs [digest, binding] and one proof per system."
    )]
    async fn create_zk_proof(
        &self,
        Parameters(params): Parameters<CreateZkProofParams>,
    ) -> std::result::Result<Json<Typed<CreateZkProofOutput>>, ErrorData> {
        // The identity circuit's witness is the holder's secret key, and a
        // tool argument lands in the model's transcript. Identity proofs
        // are produced on the holder's own device.
        if params.circuit_id == "identity" {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(
                    "the identity circuit's witness is a secret key; prove it on the holder's \
                     device, not through a tool call",
                ),
                data: None,
            });
        }
        let mut payload = serde_json::to_value(&params.witness)
            .map_err(|e| err_internal(format!("serialize witness: {}", e)))?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "circuit_id".to_string(),
                serde_json::Value::String(params.circuit_id),
            );
        } else {
            return Err(err_internal("witness must be a JSON object"));
        }
        let result = rpc_dispatch(&self.node, "tenzro_createZkProof", payload)
            .await
            .map_err(|e| err_internal(format!("createZkProof failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List all available ZK circuits on the node — name, AIR type, field, and hash function."
    )]
    async fn list_zk_circuits(
        &self,
        Parameters(_params): Parameters<ListZkCircuitsParams>,
    ) -> std::result::Result<Json<Typed<ZkCircuitsOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listCircuits", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listCircuits failed: {}", e)))?;
        typed_result(result)
    }

    // ─── App Registry Tools (non-custodial developer payments) ───

    // ─── Contract ABI Tools ───

    // ─── Network funding tools ──────────────────────────────────────────────

    #[tool(
        description = "Read governance state from consensus: a proposal with its tally, the last enacted change of a network policy, a tranched grant, a binary's upgrade readiness, or a proposal's governance receipt (its records with state proofs under a certified checkpoint, for offline verification with `tenzro governance receipt --verify`)."
    )]
    async fn governance_get(
        &self,
        Parameters(params): Parameters<GovernanceGetParams>,
    ) -> std::result::Result<Json<Typed<Option<GovRecordOutput>>>, ErrorData> {
        let id = params.id.trim_start_matches("0x").to_string();
        let (method, body) = match params.kind.as_str() {
            "proposal" => (
                "tenzro_getProposal",
                serde_json::json!({ "proposal_id": id }),
            ),
            "policy" => ("tenzro_getPolicy", serde_json::json!({ "kind": params.id })),
            "grant" => ("tenzro_getGrant", serde_json::json!({ "grant_id": id })),
            "readiness" => (
                "tenzro_getUpgradeReadiness",
                serde_json::json!({ "code_hash": id }),
            ),
            "receipt" => (
                "tenzro_getGovernanceReceipt",
                serde_json::json!({ "proposal_id": id }),
            ),
            other => {
                return Err(err_internal(format!(
                    "unknown kind '{other}' (proposal|policy|grant|readiness|receipt)"
                )));
            }
        };
        let result = rpc_dispatch(&self.node, method, body)
            .await
            .map_err(|e| err_internal(format!("{method} failed: {}", e)))?;
        typed_result(result)
    }

    // ─── AP2 (Agent Payments Protocol) Tools ────────────────────────────────

    // ─── ERC-8004 (Trustless Agents Registry) Tools ─────────────────────────

    // ─── Multi-modal: Forecast (timeseries) ───

    #[tool(
        description = "Browse the curated ONNX forecast (timeseries) catalog. Returns models like TimesFM 2.5 — each with HF repo, context length, max horizon, and quantile support."
    )]
    async fn list_forecast_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<ForecastCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listForecastCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listForecastCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog forecast (timeseries) model by model_id. The node fetches and verifies the ONNX export named by the signed catalog entry; context length, horizon, output tensor and batch size come from the entry, and its licence tier is enforced."
    )]
    async fn load_forecast_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadForecastModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadForecastModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Unload a registered forecast model from this node, freeing its ORT session."
    )]
    async fn unload_forecast_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadForecastModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadForecastModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run a univariate timeseries forecast on a registered model. Pass `history` (most-recent-last context series), `horizon` (steps ahead), and optional `quantiles` (e.g. [0.1, 0.5, 0.9]) and `frequency_seconds`. Returns point forecasts and (when supported) quantile bands."
    )]
    async fn forecast(
        &self,
        Parameters(params): Parameters<ForecastParams>,
    ) -> std::result::Result<Json<Typed<ForecastOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "history": params.history,
            "horizon": params.horizon,
        });
        if let Some(q) = params.quantiles {
            payload["quantiles"] = serde_json::json!(q);
        }
        if let Some(f) = params.frequency_seconds {
            payload["frequency_seconds"] = serde_json::json!(f);
        }
        let result = rpc_dispatch(&self.node, "tenzro_forecast", payload)
            .await
            .map_err(|e| err_internal(format!("forecast failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Vision encoders ───

    #[tool(
        description = "Browse the curated ONNX vision encoder catalog: DINOv3 (small/base/large), SigLIP2 (base/large/so400m), CLIP ViT-B/32 + L/14, DINOv2. Each entry carries input_size, embedding_dim, normalization preset, and license tier."
    )]
    async fn list_vision_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<VisionCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listVisionCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listVisionCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog image encoder (CLIP, SigLIP, DINO) by model_id. The node fetches and verifies the ONNX graph named by the signed catalog entry; input size, embedding dimension and normalization come from the entry. Returns when the ORT session is ready."
    )]
    async fn load_vision_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadVisionModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadVisionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered vision encoder, freeing its ORT session.")]
    async fn unload_vision_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadVisionModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadVisionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Embed a single image with a registered vision encoder. Pass base64-encoded PNG/JPEG/WebP bytes. Returns a dense feature vector (e.g. 768-dim for DINOv3-base, 1152-dim for SigLIP2-so400m)."
    )]
    async fn vision_embed(
        &self,
        Parameters(params): Parameters<VisionEmbedParams>,
    ) -> std::result::Result<Json<Typed<ImageEmbedOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "image_base64": params.image_base64,
            "normalize": params.normalize.unwrap_or(false),
        });
        let result = rpc_dispatch(&self.node, "tenzro_imageEmbed", payload)
            .await
            .map_err(|e| err_internal(format!("imageEmbed failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Compute cosine similarity between an image embedding and a text embedding (must have matching dimension). Pure math — does not load any model. Typical use: pair vision_embed (image) with text_embed against a CLIP/SigLIP text tower."
    )]
    async fn vision_similarity(
        &self,
        Parameters(params): Parameters<VisionSimilarityParams>,
    ) -> std::result::Result<Json<Typed<SimilarityOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "image_embedding": params.image_embedding,
            "text_embedding": params.text_embedding,
        });
        let result = rpc_dispatch(&self.node, "tenzro_imageTextSimilarity", payload)
            .await
            .map_err(|e| err_internal(format!("imageTextSimilarity failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Text embeddings ───

    #[tool(
        description = "Browse the embedding catalog: ONNX text encoders (Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, ModernBERT-embed base/large) and the Qwen3-VL Embedding 2B vision-language embedder on the Praecise engine, which embeds text, pictures and video together. Each entry carries its engine, embedding_dim, supported Matryoshka truncations, and license tier."
    )]
    async fn list_text_embedding_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<TextEmbeddingCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listTextEmbeddingCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listTextEmbeddingCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog embedding model by model_id. The node fetches and verifies the files named by the signed catalog entry (an ONNX graph and tokenizer, or a GGUF model and its vision projector) and loads it on its engine; pooling, dimensions and instruction template come from the entry."
    )]
    async fn load_text_embedding_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<TextEmbeddingLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadTextEmbeddingModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadTextEmbeddingModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered embedding model, freeing its memory.")]
    async fn unload_text_embedding_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadTextEmbeddingModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadTextEmbeddingModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Embed a batch of inputs (text, or pictures and video with a vision-language embedder) with a registered embedding model. Returns one row per input. Optional `requested_dim` enables Matryoshka truncation (e.g. 128/256/512 from a native 768/1024-dim model)."
    )]
    async fn text_embed(
        &self,
        Parameters(params): Parameters<TextEmbedParams>,
    ) -> std::result::Result<Json<Typed<TextEmbedOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "inputs": params.inputs,
            "normalize": params.normalize.unwrap_or(false),
        });
        if let Some(d) = params.requested_dim {
            payload["requested_dim"] = serde_json::json!(d);
        }
        let result = rpc_dispatch(&self.node, "tenzro_textEmbed", payload)
            .await
            .map_err(|e| err_internal(format!("textEmbed failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Segmentation ───

    #[tool(
        description = "Browse the curated ONNX segmentation catalog: SAM 2 (base/large), EdgeSAM, MobileSAM. SAM 3 / 3.1 are text-promptable with a different decoder ABI and are not exposed via this point/box segment tool."
    )]
    async fn list_segmentation_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<SegmentationCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listSegmentationCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listSegmentationCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog segmenter (SAM 2 base/large, EdgeSAM, MobileSAM) by model_id. The node fetches and verifies the encoder and decoder named by the signed catalog entry; family and input resolution come from the entry, and its licence tier is enforced."
    )]
    async fn load_segmentation_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadSegmentationModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadSegmentationModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered segmenter, freeing its ORT session.")]
    async fn unload_segmentation_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadSegmentationModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadSegmentationModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run prompt-driven image segmentation. `prompts` is an array of `{type:'point', x, y, is_foreground}` (is_foreground true for a point inside the object, false for background) or `{type:'box', x0, y0, x1, y1}` objects, in original-image pixels. Returns mask data with IOU scores. The encoder caches the per-image embedding, so repeated prompts against the same image only re-run the decoder."
    )]
    async fn segment(
        &self,
        Parameters(params): Parameters<SegmentParams>,
    ) -> std::result::Result<Json<Typed<SegmentOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "image_base64": params.image_base64,
            "prompts": params.prompts,
        });
        let result = rpc_dispatch(&self.node, "tenzro_segment", payload)
            .await
            .map_err(|e| err_internal(format!("segment failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Text-promptable segmentation (SAM 3 / SAM 3.1) ───

    #[tool(
        description = "Browse the curated ONNX text-promptable segmentation catalog: SAM 3 / SAM 3.1 (Meta) — open-vocabulary text-promptable segmenter, ViT-H backbone, 1008x1008 input, 32-token CLIP BPE language encoder."
    )]
    async fn list_text_segmentation_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<TextSegmentationCatalogRow>>>, ErrorData>
    {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listTextSegmentationCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listTextSegmentationCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog text-promptable segmenter (the SAM 3 family) by model_id. The node fetches and verifies the image encoder, language encoder, decoder and tokenizer named by the signed catalog entry."
    )]
    async fn load_text_segmentation_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_loadTextSegmentationModel",
            params.payload(),
        )
        .await
        .map_err(|e| err_internal(format!("loadTextSegmentationModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Unload a registered SAM-3 segmenter, freeing its three ORT sessions (image encoder, language encoder, decoder)."
    )]
    async fn unload_text_segmentation_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadTextSegmentationModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadTextSegmentationModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run open-vocabulary text-promptable segmentation. Provide a free-text label (e.g. 'person', 'dog') and an image; optionally narrow with a normalized cxcywh box. Returns a variable number of detections, each with a bbox (x0,y0,x1,y1 pixels), score, and binary mask resampled to original image dimensions."
    )]
    async fn text_segment(
        &self,
        Parameters(params): Parameters<TextSegmentParams>,
    ) -> std::result::Result<Json<Typed<TextSegmentOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "image_base64": params.image_base64,
            "text_prompt": params.text_prompt,
        });
        if let Some(b) = params.box_prompt {
            payload["box_prompt"] = serde_json::json!(b);
        }
        if let Some(t) = params.score_threshold {
            payload["score_threshold"] = serde_json::json!(t);
        }
        let result = rpc_dispatch(&self.node, "tenzro_textSegment", payload)
            .await
            .map_err(|e| err_internal(format!("textSegment failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Object detection ───

    #[tool(
        description = "Browse the curated ONNX detection catalog: RF-DETR (nano/small/medium/base/large/2xl) — first real-time detector >60 AP on COCO (ICLR 2026); D-FINE (n/s/m/l/x). All Apache-2.0."
    )]
    async fn list_detection_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<DetectionCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listDetectionCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listDetectionCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog detector (RF-DETR, D-FINE) by model_id. The node fetches and verifies the ONNX graph named by the signed catalog entry; family, input resolution and class count come from the entry, and its licence tier is enforced."
    )]
    async fn load_detection_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadDetectionModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadDetectionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered detector, freeing its ORT session.")]
    async fn unload_detection_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadDetectionModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadDetectionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run object detection on an image. Returns an array of detections with bounding box (x0,y0,x1,y1), label_id, and confidence score. NMS-free for DETR-family models — just sigmoid + score threshold."
    )]
    async fn detect(
        &self,
        Parameters(params): Parameters<DetectParams>,
    ) -> std::result::Result<Json<Typed<DetectOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "image_base64": params.image_base64,
        });
        if let Some(t) = params.score_threshold {
            payload["score_threshold"] = serde_json::json!(t);
        }
        let result = rpc_dispatch(&self.node, "tenzro_detect", payload)
            .await
            .map_err(|e| err_internal(format!("detect failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List the reranker catalog: GGUF cross-encoders the node can load and serve."
    )]
    async fn list_rerank_catalog(
        &self,
    ) -> std::result::Result<Json<Typed<CatalogOutput<RerankCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listRerankCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listRerankCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog reranker by model_id. The node fetches and verifies the GGUF named by the signed catalog entry and serves it on the Praecise engine; its licence tier is enforced."
    )]
    async fn load_rerank_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_loadRerankModel", params.payload())
            .await
            .map_err(|e| err_internal(format!("loadRerankModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a downloaded catalog language model for LoRA training on this node's CUDA device. Training never runs on the CPU: a build or machine without CUDA is refused."
    )]
    async fn load_training_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_loadTrainingModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("loadTrainingModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a model loaded for training.")]
    async fn unload_training_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadTrainingModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadTrainingModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run one supervised LoRA round in deterministic mode on the CUDA device. Returns the round's commitment and state roots, each step's loss, the adapter's SHA-256 and content URI, the ending state's URI, result_digest and this machine's hardware-key attestation of it, shaped as a sensor_data evidence item (pair it with a replay's attestation from another machine), the trained tokens billed, the cost and the signed receipt."
    )]
    async fn training_round(
        &self,
        Parameters(params): Parameters<TrainingRoundParams>,
    ) -> std::result::Result<Json<Typed<TrainingRoundOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "recipe": params.recipe,
            "records": params.records,
            "sample_seed": params.sample_seed,
            "adapter_seed": params.adapter_seed,
            "steps": params.steps,
            "start": params.start,
            "verification": params.verification,
        });
        let result = rpc_dispatch(&self.node, "tenzro_trainRound", payload)
            .await
            .map_err(|e| err_internal(format!("training_round failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a reranker by model_id.")]
    async fn unload_rerank_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadRerankModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadRerankModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Score documents against a query with a reranker; either side may carry text, a picture and a video with a vision-language reranker. Returns the documents best first with their relevance scores, the units billed (pairs and tokens), the cost and, at a verification level other than none, a signed receipt over the request and the scores."
    )]
    async fn rerank(
        &self,
        Parameters(params): Parameters<RerankParams>,
    ) -> std::result::Result<Json<Typed<RerankOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "query": params.query,
            "documents": params.documents,
            "top_n": params.top_n,
            "return_documents": params.return_documents.unwrap_or(false),
            "verification": params.verification,
            "provider": params.provider,
        });
        let result = rpc_dispatch(&self.node, "tenzro_rerank", payload)
            .await
            .map_err(|e| err_internal(format!("rerank failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List the decision-model catalog: GGUF models that answer typed questions (yes/no, choice, score) about a text in one forward pass."
    )]
    async fn list_decision_catalog(
        &self,
    ) -> std::result::Result<Json<Typed<CatalogOutput<DecisionCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listDecisionCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listDecisionCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog decision model by model_id. The node fetches and verifies the GGUF named by the signed catalog entry and serves it on the Praecise engine; its licence tier is enforced."
    )]
    async fn load_decision_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_loadDecisionModel", params.payload())
            .await
            .map_err(|e| err_internal(format!("loadDecisionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a decision model by model_id.")]
    async fn unload_decision_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadDecisionModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadDecisionModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Answer typed questions about a text with a decision model, in one forward pass and without generating text. Each question is yes/no ('noul': probability of yes), a choice (probability of every option and the most probable) or a score (expected level on a 2 to 10 level scale), with a calibrated confidence. Up to 64 questions per request. Returns the answers in request order, the units billed, the cost, the settlement and the signed task receipt."
    )]
    async fn decide(
        &self,
        Parameters(params): Parameters<DecideParams>,
    ) -> std::result::Result<Json<Typed<DecideOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "state": params.state,
            "questions": params.questions,
            "verification": params.verification,
            "provider": params.provider,
        });
        let result = rpc_dispatch(&self.node, "tenzro_decide", payload)
            .await
            .map_err(|e| err_internal(format!("decide failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog speech model (GGUF backbone and audio projector) by model_id; it is served on the Praecise engine and its licence tier is enforced."
    )]
    async fn load_speech_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_loadSpeechModel", params.payload())
            .await
            .map_err(|e| err_internal(format!("loadSpeechModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a speech model by model_id.")]
    async fn unload_speech_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadSpeechModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadSpeechModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Speak text with a loaded speech model. Returns base64 WAV with its SHA-256, length, the units billed (characters and seconds of audio), the cost and, at a verification level other than none, a signed receipt. The same seed, text and voice give the same audio."
    )]
    async fn speak(
        &self,
        Parameters(params): Parameters<SpeakParams>,
    ) -> std::result::Result<Json<Typed<SpeakOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "input": params.input,
            "language": params.language,
            "seed": params.seed,
            "verification": params.verification,
            "provider": params.provider,
        });
        let result = rpc_dispatch(&self.node, "tenzro_speak", payload)
            .await
            .map_err(|e| err_internal(format!("speak failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Audio ASR ───

    #[tool(
        description = "Browse the curated ONNX ASR catalog: Moonshine v2 (tiny/base, MIT, on-device), Distil-Whisper (small.en/medium.en/large-v3, MIT), Whisper Large-v3-turbo (MIT, flagship), Parakeet-TDT-0.6B-v3 (CC-BY-4.0, 25 European langs), Canary-1B-Flash (CC-BY-4.0, multilingual). The catalog is stable; the ORT-backed transcribers are feature-gated (default builds return ProviderNotAvailable)."
    )]
    async fn list_audio_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<AudioCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listAudioCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listAudioCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a catalog speech-recognition model (Moonshine, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT-v3, Canary-1B-Flash) by model_id. The node fetches and verifies the encoder, decoder, tokenizer and (for Parakeet and Canary) the feature extractor named by the signed catalog entry; family and segment length come from the entry, and its licence tier is enforced."
    )]
    async fn load_audio_model(
        &self,
        Parameters(params): Parameters<LoadCatalogModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let payload = params.payload();
        let result = rpc_dispatch(&self.node, "tenzro_loadAudioModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadAudioModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered ASR model, freeing its ORT session.")]
    async fn unload_audio_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadAudioModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadAudioModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Transcribe an audio clip (WAV/MP3/FLAC, base64-encoded) with a registered ASR model. Optional language hint, per-segment timestamps, and decoding temperature. Note: the ORT-backed transcriber is feature-gated — default builds return ProviderNotAvailable."
    )]
    async fn transcribe(
        &self,
        Parameters(params): Parameters<TranscribeParams>,
    ) -> std::result::Result<Json<Typed<TranscribeOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "audio_base64": params.audio_base64,
            "timestamps": params.timestamps.unwrap_or(false),
        });
        if let Some(l) = params.language {
            payload["language"] = serde_json::json!(l);
        }
        if let Some(t) = params.temperature {
            payload["temperature"] = serde_json::json!(t);
        }
        let result = rpc_dispatch(&self.node, "tenzro_transcribe", payload)
            .await
            .map_err(|e| err_internal(format!("transcribe failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Transcribe a recording incrementally over the realtime transport, as a live stream would be: the 16-bit PCM WAV is fed in chunks, and the answer lists every event in order (partial transcripts of the open segment, final segments committed at pauses with their units, cost and signed receipt, then done with the totals). Billed by the second of audio, once per second; partials are not billed. Runs on a node serving the model."
    )]
    async fn transcribe_stream(
        &self,
        Parameters(params): Parameters<TranscribeStreamParams>,
    ) -> std::result::Result<Json<Typed<TranscribeStreamOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "audio_base64": params.audio_base64,
            "language": params.language,
            "chunk_ms": params.chunk_ms,
            "verification": params.verification,
        });
        let result = rpc_dispatch(&self.node, "tenzro_transcribeStream", payload)
            .await
            .map_err(|e| err_internal(format!("transcribeStream failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Multi-modal: Video encoders ───

    #[tool(
        description = "Browse the curated video encoder catalog: the V-JEPA 2 family (vjepa2-vitl-256, vjepa2-vith-256, vjepa2-vitg-384 — Meta AI). Serving is frame-based rather than native — load_video_model composes a clip encoder over an already-loaded image encoder and mean-pools the per-frame embeddings."
    )]
    async fn list_video_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<Json<Typed<CatalogOutput<VideoCatalogRow>>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listVideoCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listVideoCatalog failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Register a clip-level video encoder over an already-loaded image encoder. Video embedding is frame-based: the node extracts `num_frames` evenly-spaced frames, embeds each through the encoder named by `vision_model_id`, and mean-pools. Load that image encoder first with load_vision_model — an unloaded `vision_model_id` is refused with JSON-RPC -32004."
    )]
    async fn load_video_model(
        &self,
        Parameters(params): Parameters<LoadVideoModelParams>,
    ) -> std::result::Result<Json<Typed<ModelLoadedOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "model_id": params.model_id,
            "vision_model_id": params.vision_model_id,
        });
        if let Some(n) = params.num_frames {
            payload["num_frames"] = serde_json::json!(n);
        }
        if let Some(v) = params.visibility {
            payload["visibility"] = serde_json::json!(v);
        }
        let result = rpc_dispatch(&self.node, "tenzro_loadVideoModel", payload)
            .await
            .map_err(|e| err_internal(format!("loadVideoModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(description = "Unload a registered video encoder, freeing its ORT session.")]
    async fn unload_video_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<Json<Typed<ModelUnloaded>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadVideoModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadVideoModel failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Produce a clip-level embedding from a short video (base64-encoded). The node extracts evenly-spaced frames, embeds each through the image encoder the clip encoder was registered over, and mean-pools. `frame_stride` overrides the even spacing with a fixed stride. Billing covers both the decode, which scales with clip duration, and the embedding, which scales with frames kept."
    )]
    async fn video_embed(
        &self,
        Parameters(params): Parameters<VideoEmbedParams>,
    ) -> std::result::Result<Json<Typed<VideoEmbedOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "verification": params.verification,
            "provider": params.provider,
            "model_id": params.model_id,
            "video_base64": params.video_base64,
            "normalize": params.normalize.unwrap_or(false),
        });
        if let Some(s) = params.frame_stride {
            payload["frame_stride"] = serde_json::json!(s);
        }
        let result = rpc_dispatch(&self.node, "tenzro_videoEmbed", payload)
            .await
            .map_err(|e| err_internal(format!("videoEmbed failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Node access ───
    //
    // Sign in with a passkey or a hardware key for a DPoP-bound access token,
    // and, as the node's operator or a policy admin, read and change who may
    // use this node.

    #[tool(
        description = "Start signing in to this node. Returns a single-use challenge for `did`, bound to the DPoP key whose RFC 7638 thumbprint is `dpop_jkt`. Answer it with `issue_access_token`: a passkey signs `challenge` (webauthn.get), a hardware key signs `device_digest`."
    )]
    async fn access_challenge(
        &self,
        Parameters(params): Parameters<AccessChallengeParams>,
    ) -> std::result::Result<Json<Typed<AccessChallengeOutput>>, ErrorData> {
        let payload = serde_json::json!({ "did": params.did, "dpop_jkt": params.dpop_jkt });
        typed_result(rpc_dispatch(&self.node, "tenzro_accessChallenge", payload).await?)
    }

    #[tool(
        description = "Answer a sign-in challenge and receive a short-lived ES256 access token bound to the challenge's DPoP key. `proof` is `{kind: \"passkey\", account_address, credential_id, authenticator_data, client_data_json, signature}` (base64url) or `{kind: \"device\", public_key, signature}` (hex). Optional `credentials` are KYA credentials about the DID. Returns the token, its lifetime and the method classes the policy admits the DID to."
    )]
    async fn issue_access_token(
        &self,
        Parameters(params): Parameters<IssueAccessTokenParams>,
    ) -> std::result::Result<Json<Typed<AccessTokenIssuedOutput>>, ErrorData> {
        let mut payload =
            serde_json::json!({ "challenge_id": params.challenge_id, "proof": params.proof });
        if let Some(credentials) = params.credentials {
            payload["credentials"] = serde_json::to_value(credentials)
                .map_err(|e| err_internal(format!("serialize: {}", e)))?;
        }
        typed_result(rpc_dispatch(&self.node, "tenzro_issueAccessToken", payload).await?)
    }

    #[tool(
        description = "Administrators only. The access policy in force: who may use each surface (rpc, mcp, a2a, openai, files, web, iroh) for each method class, as data and as the access.toml text."
    )]
    async fn get_access_policy(
        &self,
    ) -> std::result::Result<Json<Typed<AccessPolicyOutput>>, ErrorData> {
        typed_result(
            rpc_dispatch(&self.node, "tenzro_getAccessPolicy", serde_json::json!({})).await?,
        )
    }

    #[tool(
        description = "Administrators only. Replace the access policy with `toml` (the access.toml text). The node validates it, writes the file, logs the change and applies it at once, including to tokens already issued. Returns the new version."
    )]
    async fn set_access_policy(
        &self,
        Parameters(params): Parameters<SetAccessPolicyParams>,
    ) -> std::result::Result<Json<Typed<AccessPolicyVersionOutput>>, ErrorData> {
        let payload = serde_json::json!({ "toml": params.toml });
        typed_result(rpc_dispatch(&self.node, "tenzro_setAccessPolicy", payload).await?)
    }

    #[tool(
        description = "Administrators only. What the access policy decides for a caller on a surface, by JSON-RPC method or method class, without serving anything: allow (with tier), pay (with price) or refuse (with reason). Omit `did` for an anonymous caller."
    )]
    async fn preview_access(
        &self,
        Parameters(params): Parameters<PreviewAccessParams>,
    ) -> std::result::Result<Json<Typed<AccessPreviewOutput>>, ErrorData> {
        let mut payload = serde_json::json!({ "surface": params.surface });
        if let Some(method) = params.method {
            payload["method"] = serde_json::Value::String(method);
        }
        if let Some(class) = params.class {
            payload["class"] = serde_json::Value::String(class);
        }
        if let Some(did) = params.did {
            payload["did"] = serde_json::Value::String(did);
        }
        typed_result(rpc_dispatch(&self.node, "tenzro_previewAccess", payload).await?)
    }

    #[tool(
        description = "Administrators only. The live access tokens this node issued: token id, DID and expiry."
    )]
    async fn list_access_tokens(
        &self,
    ) -> std::result::Result<Json<Typed<LiveAccessTokensOutput>>, ErrorData> {
        typed_result(
            rpc_dispatch(&self.node, "tenzro_listAccessTokens", serde_json::json!({})).await?,
        )
    }

    #[tool(
        description = "Administrators only. Withdraw one access token by `jti`, or every live token of `did`. Give exactly one."
    )]
    async fn revoke_access_token(
        &self,
        Parameters(params): Parameters<RevokeAccessTokenParams>,
    ) -> std::result::Result<Json<Typed<AccessTokensRevokedOutput>>, ErrorData> {
        let payload = match (params.jti, params.did) {
            (Some(jti), None) => serde_json::json!({ "jti": jti }),
            (None, Some(did)) => serde_json::json!({ "did": did }),
            _ => {
                return Err(ErrorData::invalid_params(
                    "give exactly one of jti or did",
                    None,
                ));
            }
        };
        typed_result(rpc_dispatch(&self.node, "tenzro_revokeAccessToken", payload).await?)
    }

    // ─── Client-side signing ───

    #[tool(
        description = "What an unsigned transaction is signed over, for a wallet that signs client-side: for a plain transaction the canonical tx_type encoding its digest covers, for a privileged one its typed preimage, and the digest either way. `transaction` is the request tenzro_sendRawTransaction takes (from, to, nonce, chain_id, gas_limit, gas_price, timestamp, valid_until, tx_type), without public_key or signature. Encoding only: nothing is signed or stored."
    )]
    async fn transaction_signing_payload(
        &self,
        Parameters(params): Parameters<TransactionSigningPayloadParams>,
    ) -> std::result::Result<Json<Typed<PaySigningPayload>>, ErrorData> {
        let transaction = serde_json::to_value(&params.transaction)
            .map_err(|e| err_internal(format!("transaction does not encode: {e}")))?;
        typed_result(rpc_dispatch(&self.node, "tenzro_getSigningPayload", transaction).await?)
    }

    // ─── Passkey-first wallet custody ───

    #[tool(
        description = "Ask the node for the challenge a passkey of the account's keystore must sign to authorize one custody change (grant_session_key, revoke_session_key, set_spending_limit, add_hardware_signer). Linking or unlinking passkeys and recovery are KeystoreUpdate transactions instead. A custody change needs proof of control from a device already on the account — the account address is a public identifier, not a credential. The challenge is single-use, time-bounded, and bound to this account and operation."
    )]
    async fn create_custody_challenge(
        &self,
        Parameters(params): Parameters<CustodyChallengeParams>,
    ) -> std::result::Result<Json<Typed<CustodyChallengeOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_createCustodyChallenge", payload)
            .await
            .map_err(|e| err_internal(format!("createCustodyChallenge failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Enroll a passkey-bound smart account. Consumes a WebAuthn registration credential (P-256 public key + opaque credential ID) with proof of possession (an assertion over the webauthn_challenge of an enroll_passkey custody challenge), registers the human identity it derives, and returns the account it derives with that account's keystore and, before the account's first change, the anchor its first KeystoreUpdate carries. Nothing about the account is stored by the node; the signing key never leaves the user's device."
    )]
    async fn enroll_passkey(
        &self,
        Parameters(params): Parameters<PasskeyEnrollParams>,
    ) -> std::result::Result<Json<Typed<PasskeyEnrolledOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_enrollPasskey", payload)
            .await
            .map_err(|e| err_internal(format!("enrollPasskey failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "An agent's account on every other chain the network configures: CAIP-10 and ERC-7930 addresses, what each chain supports, and the live grant there."
    )]
    async fn agent_accounts(
        &self,
        Parameters(params): Parameters<AgentAccountsParams>,
    ) -> std::result::Result<Json<Typed<PayAgentAccountsOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_agentAccounts",
            serde_json::json!({ "did": params.did }),
        )
        .await
    }

    #[tool(
        description = "As the agent (its access token), issue a grant on another chain: a budget of one asset for a limited time, held to the agent's terms and counted against its daily spend. Aptos takes exact grants only. Revoking, pausing, quarantining the agent or changing its terms voids every grant; a remote account stops at the latest when the grant expires."
    )]
    async fn agent_remote_grant(
        &self,
        Parameters(params): Parameters<AgentRemoteGrantParams>,
    ) -> std::result::Result<Json<Typed<PayAgentActOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_requestRemoteGrant", args).await
    }

    #[tool(
        description = "As the agent (its access token), have this serving node sign one action of the agent's account on another chain, checked against the live grant there; returns the signature, the digest and the key and target proofs the account checks. Above the grant's cosign threshold a node of another operator signs too."
    )]
    async fn agent_remote_act(
        &self,
        Parameters(params): Parameters<AgentRemoteActParams>,
    ) -> std::result::Result<Json<Typed<PayAgentRemoteActOutput>>, ErrorData> {
        let args =
            serde_json::to_value(&params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let signed = rpc_dispatch(&self.node, "tenzro_signRemoteAction", args).await?;
        let did = signed.get("agent_did").cloned().unwrap_or_default();
        let built = rpc_dispatch(
            &self.node,
            "tenzro_buildRemoteAction",
            serde_json::json!({ "did": did, "chain": params.chain, "nonce": params.nonce, "action": params.action }),
        )
        .await?;
        typed_result(serde_json::json!({ "signature": signed, "proofs": built }))
    }

    #[tool(
        description = "What a relayer installs with an agent account's sync on its chain: the grant bytes and their state proof under a certified checkpoint's state root."
    )]
    async fn agent_account_sync(
        &self,
        Parameters(params): Parameters<AgentAccountSyncParams>,
    ) -> std::result::Result<Json<Typed<PayAgentGrantProofOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_getAgentGrantProof", args).await
    }

    #[tool(
        description = "The consent that makes an agent's account on an EVM chain the agentWallet of its ERC-8004 entry: the registry's EIP-712 AgentWalletSet digest and the approveHash action that approves it as the account's ERC-1271 signature (sign it with agent_remote_act), and the setAgentWallet calldata the entry's owner sends with an empty signature. The consent ends with the grant it was approved under."
    )]
    async fn agent_wallet_consent(
        &self,
        Parameters(params): Parameters<AgentWalletConsentParams>,
    ) -> std::result::Result<Json<Typed<PayAgentWalletConsentOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_agentWalletConsent", args).await
    }

    #[tool(
        description = "Issue the challenge an agent's root signs to delegate an agent, change its terms or revoke it: a human root's passkey signs webauthn_challenge, a machine root's TPM or Secure Enclave signs challenge_hex under the account-owner context. The account is the human's smart account or the account the machine's hardware key names. For delegate_agent and update_agent_terms the node collects each serving node's key and returns the completed terms as `delegation`; pass them back unchanged. For revoke_identity the target is revocation_target(agent_did, reason), and the account is the controller's."
    )]
    async fn agent_delegation_challenge(
        &self,
        Parameters(params): Parameters<AgentDelegationChallengeParams>,
    ) -> std::result::Result<Json<Typed<CustodyChallengeOutput>>, ErrorData> {
        let mut args =
            serde_json::to_value(&params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        args.as_object_mut().map(|m| m.remove("reason"));
        if params.operation == "revoke_identity" {
            let did = params.agent_did.clone().unwrap_or_default();
            let reason = params
                .reason
                .as_deref()
                .unwrap_or(tenzro_types::identity::DEFAULT_REVOCATION_REASON);
            args = serde_json::json!({
                "account_address": params.account_address,
                "operation": params.operation,
                "target_hex": hex::encode(tenzro_types::identity::revocation_target(&did, reason)),
            });
        } else if params.operation == "delegate_agent" {
            args.as_object_mut().map(|m| m.remove("rotate_tokens"));
        }
        rpc_tool_typed(&self.node, "tenzro_createCustodyChallenge", args).await
    }

    #[tool(
        description = "Create a delegated agent from the completed terms and its root's approval (a human's passkey or a machine's hardware key). Returns the agent's identity, its watch-only wallet and its serving nodes. The agent signs in with its own key (tenzro_issueAccessToken); within the approved terms it acts with no further approval."
    )]
    async fn delegate_agent(
        &self,
        Parameters(params): Parameters<DelegateAgentParams>,
    ) -> std::result::Result<Json<Typed<PayDelegateAgentOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_onboardDelegatedAgent", args).await
    }

    #[tool(
        description = "Replace a delegated agent's terms (limits, scope, capabilities, expiry, serving nodes) with its root's approval (passkey or machine hardware key). The DID stays the same; the agent's live access tokens are withdrawn when rotate_tokens was approved."
    )]
    async fn update_agent_terms(
        &self,
        Parameters(params): Parameters<UpdateAgentTermsParams>,
    ) -> std::result::Result<Json<Typed<PayUpdateAgentTermsOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_updateAgentTerms", args).await
    }

    #[tool(
        description = "Admit a signed RevokeIdentity transaction that revokes a delegated agent with its root's approval (passkey or machine hardware key) of a revoke_identity challenge. The node checks the approval against chain state and admits it; every validator re-verifies it, and once it is in a block every node refuses the agent and revokes its tokens."
    )]
    async fn revoke_delegated_agent(
        &self,
        Parameters(params): Parameters<RevokeDelegatedAgentParams>,
    ) -> std::result::Result<Json<Typed<PayRevokeAgentOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_revokeIdentity",
            serde_json::to_value(&params.signed_transaction)
                .map_err(|e| err_internal(format!("serialize: {e}")))?,
        )
        .await
    }

    #[tool(
        description = "Issue the custody challenge the machine owner signs to add, list or revoke a machine-access grant on this node. The node names the owner's account and binds the challenge to exactly this change; approve it in the owner's wallet and pass the result as authorization to the matching tool."
    )]
    async fn machine_access_challenge(
        &self,
        Parameters(params): Parameters<MachineAccessChallengeParams>,
    ) -> std::result::Result<Json<Typed<CustodyChallengeOutput>>, ErrorData> {
        rpc_tool_typed(
            &self.node,
            "tenzro_createCustodyChallenge",
            serde_json::json!({ "operation": "machine_access", "machine_access": params.change }),
        )
        .await
    }

    #[tool(
        description = "Add a machine-access grant: let the node's jobs, or one agent or tool, reach a network range, a local service or a folder on this machine. Needs the machine owner's approval of a machine_access_challenge for exactly these terms; nothing else can add a grant."
    )]
    async fn add_machine_access(
        &self,
        Parameters(params): Parameters<MachineAccessAddParams>,
    ) -> std::result::Result<Json<Typed<MachineAccessGrantOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_addMachineAccess", args).await
    }

    #[tool(
        description = "List the machine-access grants on this node with their use, refusal and byte counts. Needs the machine owner's approval of a list challenge."
    )]
    async fn list_machine_access(
        &self,
        Parameters(params): Parameters<MachineAccessListParams>,
    ) -> std::result::Result<Json<Typed<MachineGrantsOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_listMachineAccess", args).await
    }

    #[tool(
        description = "Revoke a machine-access grant; it stops applying at once. Needs the machine owner's approval of a revoke challenge for this grant."
    )]
    async fn revoke_machine_access(
        &self,
        Parameters(params): Parameters<MachineAccessRevokeParams>,
    ) -> std::result::Result<Json<Typed<MachineAccessRevokedOutput>>, ErrorData> {
        let args =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        rpc_tool_typed(&self.node, "tenzro_revokeMachineAccess", args).await
    }

    // ─── Browser-launch passkey auth sessions (gcloud-style device flow) ───

    #[tool(
        description = "Create a pending browser-launch passkey ceremony session (enroll a new account, add a device credential, or sign over an op hash). Returns a session id and the node-served /auth/passkey URL to open in a browser; the browser runs navigator.credentials.create()/get() and the caller polls get_passkey_session until the session reaches a terminal status."
    )]
    async fn create_passkey_session(
        &self,
        Parameters(params): Parameters<CreatePasskeySessionParams>,
    ) -> std::result::Result<Json<Typed<PasskeySessionCreatedOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_createPasskeySession", payload)
            .await
            .map_err(|e| err_internal(format!("createPasskeySession failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Poll a browser-launch passkey ceremony session by id. Returns the session kind, status (pending/in_flight/completed/failed/expired), and — once terminal — the handler result or error."
    )]
    async fn get_passkey_session(
        &self,
        Parameters(params): Parameters<GetPasskeySessionParams>,
    ) -> std::result::Result<Json<Typed<PasskeySessionOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_getPasskeySession", payload)
            .await
            .map_err(|e| err_internal(format!("getPasskeySession failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Identity + credential lifecycle (admin-gated) ───

    #[tool(
        description = "Revoke a JWT by its jti. Requires a signed did_envelope from the token's bearer DID or the controller DID that authorized it — a jti travels in every audit row, so knowing one is not authority to destroy it. Cascades to any tokens minted from the revoked token."
    )]
    async fn revoke_jwt(
        &self,
        Parameters(params): Parameters<RevokeJwtParams>,
    ) -> std::result::Result<Json<Typed<JwtRevokedOutput>>, ErrorData> {
        let payload =
            serde_json::to_value(params).map_err(|e| err_internal(format!("serialize: {}", e)))?;
        let result = rpc_dispatch(&self.node, "tenzro_revokeJwt", payload)
            .await
            .map_err(|e| err_internal(format!("revokeJwt failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Storage market ───

    #[tool(
        description = "Administrators only. Store an object on this node's storage provider with an erasure-coded redundancy scheme. Returns the object id, stored size, and shard counts."
    )]
    async fn storage_store_object(
        &self,
        Parameters(params): Parameters<StorageStoreObjectParams>,
    ) -> std::result::Result<Json<Typed<ObjectStoredOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "object_id": params.object_id,
            "data": params.data,
            "owner_did": params.owner_did,
            "did_envelope": params.did_envelope,
        });
        if let Some(owner) = params.owner {
            payload["owner"] = owner.into();
        }
        if let Some(n) = params.data_shards {
            payload["data_shards"] = n.into();
        }
        if let Some(n) = params.parity_shards {
            payload["parity_shards"] = n.into();
        }
        let result = rpc_dispatch(&self.node, "tenzro_storageStoreObject", payload)
            .await
            .map_err(|e| err_internal(format!("storageStoreObject failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Administrators only. Rebuild an object this node's storage provider stored from its shards. Returns the object id, its size and its bytes (base64)."
    )]
    async fn storage_retrieve_object(
        &self,
        Parameters(params): Parameters<StorageRetrieveObjectParams>,
    ) -> std::result::Result<Json<Typed<StoredObjectOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_storageRetrieveObject",
            serde_json::json!({
                "object_id": params.object_id,
                "did_envelope": params.did_envelope,
            }),
        )
        .await
        .map_err(|e| err_internal(format!("storageRetrieveObject failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Administrators only. Set the fixed byte-epoch storage rate deals opened from now on pay. The rate never follows demand."
    )]
    async fn storage_set_pricing(
        &self,
        Parameters(params): Parameters<StorageSetPricingParams>,
    ) -> std::result::Result<Json<Typed<StoragePricingOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "mode": "fixed",
            "rate": params.rate,
        });
        let result = rpc_dispatch(&self.node, "tenzro_storageSetPricing", payload)
            .await
            .map_err(|e| err_internal(format!("storageSetPricing failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Summary of this node's storage-provider state: effective rate and stored object count."
    )]
    async fn storage_status(
        &self,
    ) -> std::result::Result<Json<Typed<StorageStatusOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_storageStatus", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("storageStatus failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Compute price feed ───

    #[tool(
        description = "Discover compute and model providers by observed price, latency and reliability. Every number comes from validators that routed real calls, not from what providers advertise. Filter by model, hardware class or region; rows are cheapest per compute-second first. Hardware class and region are the provider's own claims."
    )]
    async fn compute_price_feed(
        &self,
        Parameters(params): Parameters<ComputePriceFeedParams>,
    ) -> std::result::Result<Json<Typed<ComputePriceFeedOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "hardware_class": params.hardware_class,
            "region": params.region,
            "attested_only": params.attested_only,
            "limit": params.limit,
        });
        let result = rpc_dispatch(&self.node, "tenzro_computePriceFeed", payload)
            .await
            .map_err(|e| err_internal(format!("computePriceFeed failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "List the standardized compute claims an address has written or held, from chain state: hardware class, region, delivery hours, strike, settlement against on-chain SLA verdicts, holder, pledge and vault."
    )]
    async fn compute_list_claims(
        &self,
        Parameters(params): Parameters<ComputeListClaimsParams>,
    ) -> std::result::Result<Json<Typed<ComputeClaimsOutput>>, ErrorData> {
        let payload = serde_json::json!({ "party": params.party, "limit": params.limit });
        let result = rpc_dispatch(&self.node, "tenzro_computeListClaims", payload)
            .await
            .map_err(|e| err_internal(format!("computeListClaims failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Get a checkpoint certificate: the portable proof that a range of heights is final. Returns the encoded certificate (checkpoint plus a quorum of seat signatures) and the session certificates it names, each signed by the seat's hardware key. Verifiable with no Tenzro node against the epoch's committee (tenzro_getCommittee). Omit index for the latest. With decode, also the signers read against that committee: each one's index, account, seats, stake, key fingerprint and session digest, with the signed and total seats and the quorum."
    )]
    async fn get_checkpoint_certificate(
        &self,
        Parameters(params): Parameters<GetCheckpointCertificateParams>,
    ) -> std::result::Result<Json<Typed<CheckpointCertificateOutput>>, ErrorData> {
        let payload = serde_json::json!({ "index": params.index, "decode": params.decode });
        let result = rpc_dispatch(&self.node, "tenzro_getCheckpointCertificate", payload)
            .await
            .map_err(|e| err_internal(format!("getCheckpointCertificate failed: {}", e)))?;
        typed_result(result)
    }

    // ─── MoE serving ───

    #[tool(
        description = "Return the expert shard map for a model: per-expert holders, replication counts, role counts, the replication policy, and lists of under-replicated and hot experts across known providers."
    )]
    async fn moe_shard_map(
        &self,
        Parameters(params): Parameters<MoeModelIdParams>,
    ) -> std::result::Result<Json<Typed<MoeShardMapOutput>>, ErrorData> {
        let payload = serde_json::json!({ "model_id": params.model_id });
        let result = rpc_dispatch(&self.node, "tenzro_moeShardMap", payload)
            .await
            .map_err(|e| err_internal(format!("moeShardMap failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Given per-token top-k routing decisions, return the per-holder batch plan and per-token slot assignments. Set allow_cold to permit routing to experts that are not warm-resident."
    )]
    async fn moe_plan_dispatch(
        &self,
        Parameters(params): Parameters<MoePlanDispatchParams>,
    ) -> std::result::Result<Json<Typed<MoeDispatchPlanOutput>>, ErrorData> {
        let routings: Vec<serde_json::Value> = params
            .routings
            .iter()
            .map(|r| {
                serde_json::json!({
                    "token_index": r.token_index,
                    "experts": r
                        .experts
                        .iter()
                        .map(|e| serde_json::json!({ "layer": e.layer, "expert": e.expert }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "routings": routings,
            "allow_cold": params.allow_cold,
        });
        let result = rpc_dispatch(&self.node, "tenzro_moePlanDispatch", payload)
            .await
            .map_err(|e| err_internal(format!("moePlanDispatch failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Return the current replication policy used by shard-view consumers: min/max replication and the hot-expert tokens-per-second threshold."
    )]
    async fn moe_replication_policy(
        &self,
    ) -> std::result::Result<Json<Typed<MoeReplicationPolicyOutput>>, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_moeReplicationPolicy",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("moeReplicationPolicy failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Return the catalog MoE topology for a model (num_experts, experts_per_token, shared_experts, params_per_expert_x10) and its architecture. The moe field is null for dense models."
    )]
    async fn moe_catalog_shape(
        &self,
        Parameters(params): Parameters<MoeModelIdParams>,
    ) -> std::result::Result<Json<Typed<MoeCatalogShapeOutput>>, ErrorData> {
        let payload = serde_json::json!({ "model_id": params.model_id });
        let result = rpc_dispatch(&self.node, "tenzro_moeCatalogShape", payload)
            .await
            .map_err(|e| err_internal(format!("moeCatalogShape failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a per-expert safetensors weight blob (gate_proj/up_proj/down_proj) into this node's MoE expert runtime, from an inline base64 blob or a tenzro://blob URI. Returns the resident expert's dimensions and byte footprint."
    )]
    async fn moe_expert_load(
        &self,
        Parameters(params): Parameters<MoeExpertLoadParams>,
    ) -> std::result::Result<Json<Typed<MoeLoadedExpertOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "layer": params.layer,
            "expert": params.expert,
            "blob_base64": params.blob_base64,
            "uri": params.uri,
        });
        let result = rpc_dispatch(&self.node, "tenzro_moeExpertLoad", payload)
            .await
            .map_err(|e| err_internal(format!("moeExpertLoad failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Load a gating-network safetensors blob (router.weight) for a model layer into this node's MoE expert runtime, from an inline base64 blob or a tenzro://blob URI."
    )]
    async fn moe_gate_load(
        &self,
        Parameters(params): Parameters<MoeGateLoadParams>,
    ) -> std::result::Result<Json<Typed<MoeLoadedGateOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "layer": params.layer,
            "blob_base64": params.blob_base64,
            "uri": params.uri,
        });
        let result = rpc_dispatch(&self.node, "tenzro_moeGateLoad", payload)
            .await
            .map_err(|e| err_internal(format!("moeGateLoad failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Slice a catalog MoE checkpoint into per-expert safetensors blobs (and optionally the layer gate), optionally block-quantizing each projection (q4_k_m / q8_0 / q4_k / q6_k preset, or a per-projection gate/up/down mix), and publish them as tenzro://blob content so holders can load them. Runs asynchronously; returns a job_id to poll with moe_prepare_status. Omit experts to prepare every expert in the layer."
    )]
    async fn moe_prepare_experts(
        &self,
        Parameters(params): Parameters<MoePrepareExpertsParams>,
    ) -> std::result::Result<Json<Typed<MoePrepareStartedOutput>>, ErrorData> {
        let mut payload = serde_json::json!({
            "model_id": params.model_id,
            "layer": params.layer,
            "include_gate": params.include_gate.unwrap_or(true),
        });
        if let Some(experts) = params.experts
            && !experts.is_empty()
        {
            payload["experts"] = serde_json::json!(experts);
        }
        if let Some(quant) = params.quant {
            payload["quant"] = serde_json::json!(quant);
        }
        let result = rpc_dispatch(&self.node, "tenzro_moePrepareExperts", payload)
            .await
            .map_err(|e| err_internal(format!("moePrepareExperts failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Poll the state of an expert-preparation job started by moe_prepare_experts. Returns the job's model_id, layer, state (running / done / error), any error, and the prepared per-expert tenzro://blob URIs when done."
    )]
    async fn moe_prepare_status(
        &self,
        Parameters(params): Parameters<MoePrepareStatusParams>,
    ) -> std::result::Result<Json<Typed<MoePrepareJobOutput>>, ErrorData> {
        let payload = serde_json::json!({ "job_id": params.job_id });
        let result = rpc_dispatch(&self.node, "tenzro_moePrepareStatus", payload)
            .await
            .map_err(|e| err_internal(format!("moePrepareStatus failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Snapshot of this node's resident MoE experts and gating networks: each entry's residency tier (memory / disk), byte footprint, the total footprint, the memory budget, and whether GPU compute is active."
    )]
    async fn moe_expert_status(
        &self,
    ) -> std::result::Result<Json<Typed<MoeExpertStatusOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_moeExpertStatus", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("moeExpertStatus failed: {}", e)))?;
        typed_result(result)
    }

    #[tool(
        description = "Run a distributed MoE forward for one layer: gate-route the hidden-state batch locally, fan expert sub-batches out to holders (local runtime, iroh tenzro/moe ALPN, or HTTP JSON-RPC), and gather the gate-weighted combined outputs. hidden_states and outputs are base64 of little-endian f32 bytes."
    )]
    async fn moe_forward(
        &self,
        Parameters(params): Parameters<MoeForwardParams>,
    ) -> std::result::Result<Json<Typed<MoeForwardOutput>>, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "layer": params.layer,
            "d_model": params.d_model,
            "hidden_states": params.hidden_states,
            "top_k": params.top_k,
            "allow_cold": params.allow_cold,
        });
        let result = rpc_dispatch(&self.node, "tenzro_moeForward", payload)
            .await
            .map_err(|e| err_internal(format!("moeForward failed: {}", e)))?;
        typed_result(result)
    }

    // ─── Local discovery / cluster ───

    #[tool(
        description = "Return this node's hardware self-profile: linked runtime build commit, CPU architecture, operating system, detected compute devices, and derived serving values (capacity in GB, serving backend, capability key). Each device reports the ggml backend it executes on — CUDA, Metal, Vulkan, ROCm, SYCL, or CPU — and serving_backend is the backend of the strongest GPU-class device, else CPU."
    )]
    async fn node_profile(&self) -> std::result::Result<Json<Typed<NodeProfileOutput>>, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_nodeProfile", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("nodeProfile failed: {}", e)))?;
        typed_result(result)
    }

    // ─── App hosting: functions (wasi:http components) ───

    // ─── App hosting: machines (Firecracker microVMs) ───

    // ─── App hosting: placement leases ───
}

// ─── ServerHandler ───

#[tool_handler]
impl TenzroMcpServer {
    /// The headers of the HTTP request a call arrived on, with the URL as
    /// the client dialled it (the one its DPoP proof covers). A call with no
    /// HTTP request keeps the headers the caller's scope holds.
    fn request_headers(
        &self,
        context: &rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> McpRequestHeaders {
        let Some(parts) = context.extensions.get::<axum::http::request::Parts>() else {
            return current_request_headers();
        };
        let get = |k: &str| {
            parts
                .headers
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let scheme = get("x-forwarded-proto").unwrap_or_else(|| "http".to_string());
        let host = get("host").unwrap_or_else(|| self.node.config().rpc_addr.to_string());
        let path = parts
            .extensions
            .get::<axum::extract::OriginalUri>()
            .map_or_else(|| parts.uri.path().to_string(), |u| u.0.path().to_string());
        McpRequestHeaders {
            authorization: get("authorization"),
            dpop: get("dpop"),
            http_method: parts.method.as_str().to_string(),
            http_uri: format!("{scheme}://{host}{path}"),
        }
    }

    /// Serve one call, leaving the signed record of an authenticated
    /// agent's call: the tool, the digests of its arguments and result, and
    /// whether it ran or was refused and why.
    async fn call_tool_recorded(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, ErrorData> {
        // Every call an authenticated agent makes leaves a signed record:
        // the tool, the digests of its arguments and result, and whether it
        // ran or was refused and why.
        let agent = if self.iroh_readonly {
            None
        } else {
            self.calling_agent().map_err(|why| ErrorData {
                code: ErrorCode(-32001),
                message: Cow::from(why),
                data: None,
            })?
        };
        let Some(agent) = agent else {
            return self.serve_tool_call(request, context).await;
        };
        let signer = crate::tool_call_record::admit(&self.node).map_err(|why| ErrorData {
            code: ErrorCode(crate::tool_call_record::UNRECORDABLE),
            message: Cow::from(why),
            data: None,
        })?;
        let surface = if self.compact {
            crate::tool_call_record::Surface::McpCompact
        } else {
            crate::tool_call_record::Surface::Mcp
        };
        // A compact `call` is recorded as the tool it names, with that
        // tool's arguments.
        let inner = (self.compact && request.name == super::compact::CALL)
            .then_some(request.arguments.as_ref())
            .flatten();
        let tool = inner
            .and_then(|a| a.get("name"))
            .and_then(|n| n.as_str())
            .map_or_else(|| request.name.to_string(), str::to_string);
        let args = match inner {
            Some(a) => serde_json::to_vec(&a.get("arguments")).unwrap_or_default(),
            None => serde_json::to_vec(&request.arguments).unwrap_or_default(),
        };
        // The approval reference, in the request's `_meta`: the transport
        // hands it over on the call or on its context.
        let approval_in = |m: Option<serde_json::Value>| {
            m.and_then(|m| {
                m.get(crate::tool_call_record::APPROVAL_META)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
        };
        let approval = approval_in(
            request
                .meta
                .as_ref()
                .and_then(|m| serde_json::to_value(m).ok()),
        )
        .or_else(|| approval_in(serde_json::to_value(&context.meta).ok()));
        let served = self.serve_tool_call(request, context).await;
        let (outcome, result) = match &served {
            Ok(response) => (
                tenzro_types::agent_audit::ActionOutcome::Allowed,
                Some(match response {
                    CallToolResponse::Complete(result) => {
                        serde_json::to_vec(result).unwrap_or_default()
                    }
                    other => format!("{other:?}").into_bytes(),
                }),
            ),
            Err(e) if crate::tool_call_record::REFUSAL_CODES.contains(&e.code.0) => (
                tenzro_types::agent_audit::ActionOutcome::Refused(e.message.to_string()),
                None,
            ),
            Err(e) => (
                tenzro_types::agent_audit::ActionOutcome::Allowed,
                Some(serde_json::to_vec(e).unwrap_or_default()),
            ),
        };
        crate::tool_call_record::record(
            &self.node,
            &signer,
            crate::tool_call_record::Call {
                surface,
                agent: &agent,
                tool: &tool,
                args: &args,
                outcome,
                result: result.as_deref(),
                approval,
                principal: crate::tool_call_record::principal_of(&self.node, &agent),
            },
        )
        .map_err(|why| ErrorData {
            code: ErrorCode(crate::tool_call_record::UNRECORDABLE),
            message: Cow::from(why),
            data: None,
        })?;
        served
    }

    /// The DID the access token on this request proves: a DPoP-bound token,
    /// or this server's OAuth bearer token. `None` for a request with no
    /// token; a token that names no caller is refused, so no call is served
    /// unattributed on the strength of a token.
    fn calling_agent(&self) -> std::result::Result<Option<String>, String> {
        let h = current_request_headers();
        let Some(authorization) = h.authorization.clone() else {
            return Ok(None);
        };
        if let Some(token) = authorization.trim_start().strip_prefix("Bearer ") {
            let state = self
                .node
                .oauth_state
                .read()
                .clone()
                .ok_or("this server does not take bearer tokens")?;
            return super::oauth::validate_bearer_jwt(&state, token.trim())
                .map(|user| Some(user.did));
        }
        let auth = crate::rpc::AuthContext {
            authorization: h.authorization,
            dpop: h.dpop,
            http_method: h.http_method,
            http_uri: h.http_uri,
        };
        match crate::access::proved_token(&self.node, &auth) {
            Ok(Some(claims)) => Ok(Some(claims.sub)),
            Ok(None) => Err("the access token names no caller: use a DPoP-bound token".to_string()),
            Err(e) => Err(e.message),
        }
    }

    /// Serve one tool call: unwrap a compact call, apply the iroh allowlist
    /// and the agent's pinned tools, and run the tool.
    async fn serve_tool_call(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, ErrorData> {
        let request = if self.compact {
            let name = request.name.to_string();
            match name.as_str() {
                super::compact::SEARCH => {
                    let params = serde_json::from_value(serde_json::Value::Object(
                        request.arguments.unwrap_or_default(),
                    ))
                    .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    let found = super::compact::search(Self::router().list_all(), params);
                    let value =
                        serde_json::to_value(found).map_err(|e| err_internal(e.to_string()))?;
                    return Ok(CallToolResponse::Complete(CallToolResult::structured(
                        value,
                    )));
                }
                super::compact::CALL => {
                    super::compact::unwrap_call(request, &Self::router().list_all())?
                }
                _ => request,
            }
        } else {
            request
        };
        if self.iroh_readonly && !iroh_tool_allowed(request.name.as_ref()) {
            // Fail-closed: over the unauthenticated iroh transport, anything
            // outside the read-only allowlist is refused rather than executed.
            return Err(ErrorData {
                code: ErrorCode::INVALID_REQUEST,
                message: Cow::from(format!(
                    "tool '{}' is not authorized over the iroh MCP transport \
                     (read-only tools only; use the credential-gated HTTP MCP \
                     endpoint or, for inference, the tenzro/infer ALPN)",
                    request.name
                )),
                data: None,
            });
        }
        if !self.iroh_readonly {
            self.check_pinned_tool(request.name.as_ref())?;
        }
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        Self::router().call(tcc).await
    }

    /// A delegated agent whose terms pin tools calls only a pinned tool
    /// that still describes itself as it did when the terms were approved.
    /// A request with no valid access token is left to the access policy,
    /// which refuses it at dispatch.
    fn check_pinned_tool(&self, name: &str) -> std::result::Result<(), ErrorData> {
        let h = current_request_headers();
        let auth = crate::rpc::AuthContext {
            authorization: h.authorization,
            dpop: h.dpop,
            http_method: h.http_method,
            http_uri: h.http_uri,
        };
        let Ok(Some(claims)) = crate::access::proved_token(&self.node, &auth) else {
            return Ok(());
        };
        let router = Self::router();
        let Some(tool) = router.get(name) else {
            return Ok(());
        };
        let schema = serde_json::Value::Object((*tool.input_schema).clone());
        crate::agent_delegation::check_agent_tool(
            &self.node,
            &claims.sub,
            crate::agent_delegation::NODE_TOOL_SERVER,
            name,
            tool.description.as_deref().unwrap_or(""),
            &schema,
        )
        .map_err(|why| ErrorData {
            code: ErrorCode(-32003),
            message: Cow::from(why),
            data: None,
        })
    }
}

impl ServerHandler for TenzroMcpServer {
    // Hand-written `call_tool` / `list_tools`. The `#[tool_handler]` macro
    // only generates these when absent (it checks `has_method`), so defining
    // them here lets us enforce the iroh read-only allowlist at the single
    // dispatch chokepoint without touching any individual tool. On the HTTP
    // path (`iroh_readonly == false`) both methods behave exactly as the
    // macro-generated versions: same `Self::tool_router()` dispatch, same
    // `list_all()` result — no HTTP MCP behavior change.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, ErrorData> {
        // The request's own headers, as the client sent them, for the tool
        // and the JSON-RPC calls it makes: the handler runs outside the
        // middleware's scope, so they are taken from the request parts the
        // transport hands over.
        let headers = self.request_headers(&context);
        let proved = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<crate::rpc::ProvedToken>())
            .cloned();
        let call = MCP_REQUEST_HEADERS.scope(headers, self.call_tool_recorded(request, context));
        match proved {
            // The edge already proved this request's token; the call runs as
            // that proved request, so its proof is not spent a second time.
            Some(p) => crate::rpc::with_proved_token(p.dpop, p.claims, call).await,
            None => call.await,
        }
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            super::event_resources::template(),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ReadResourceResponse, ErrorData> {
        let node = self.node.clone();
        super::event_resources::read(&request.uri, |params| async move {
            rpc_dispatch(&node, "tenzro_subscribe", params).await
        })
        .await
        .map(ReadResourceResponse::from)
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<(), ErrorData> {
        // The first read passes the caller's key gate and agent terms; a
        // subscription the caller could not read is refused here.
        let node = self.node.clone();
        super::event_resources::read(&request.uri, |params| async move {
            rpc_dispatch(&node, "tenzro_subscribe", params).await
        })
        .await?;
        let peer = context.peer.clone();
        super::event_resources::watch(self.node.clone(), request.uri, move |uri| {
            let peer = peer.clone();
            async move {
                peer.notify_resource_updated(ResourceUpdatedNotificationParam::new(uri))
                    .await
                    .is_ok()
            }
        })
        .await
    }

    async fn unsubscribe(
        &self,
        _request: UnsubscribeRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<(), ErrorData> {
        // A watch ends by itself once its peer stops accepting notifications.
        Ok(())
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListToolsResult, ErrorData> {
        let mut tools = if self.compact {
            super::compact::tools()
        } else {
            Self::router().list_all()
        };
        if self.iroh_readonly {
            // Advertise only the tools that can actually be invoked over this
            // transport, so clients never see (and never call) a tool that
            // would be refused.
            tools.retain(|t| iroh_tool_allowed(t.name.as_ref()));
        }
        // The list is the same for every caller on a transport; ttl 0 asks
        // clients not to reuse it across node upgrades.
        Ok(rmcp::model::ListToolsResult::with_all_items(tools)
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Public))
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        super::served_protocol_versions()
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<InitializeResult, ErrorData> {
        Err(super::initialize_refused(&request.protocol_version))
    }

    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder()
            .enable_resources()
            .enable_resources_subscribe()
            .enable_tools()
            .build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro".into();
        impl_info.title = Some("Tenzro Network MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "AI-native blockchain node exposing wallet, identity, payments, staking, provider, bridge, model, and verification tools for the Tenzro Network"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro Network MCP Server — interact with the Tenzro AI-native blockchain.\n\n\
             TOOLS BY CATEGORY:\n\n\
             Wallet & Balance:\n\
             • get_balance — Query TNZO token balance\n\n\
             Identity (TDIP):\n\
             • register_identity — Register human or machine DID\n\
             • resolve_did — Resolve DID to identity data\n\
             OAuth 2.1 / AAP delegation:\n\
             • exchange_token — RFC 8693 token exchange (mint narrower child JWT)\n\
             • introspect_token — RFC 7662 token introspection\n\
             • oauth_discovery — RFC 8414 AS metadata\n\n\
             Payments:\n\
             • create_payment_challenge — Create a payment challenge\n\
             • verify_payment — Verify a payment credential against its challenge\n\n\
             AI Models:\n\
             • list_models — Browse available AI models\n\
             • list_model_endpoints — List model service API/MCP URLs\n\n\
             Verifiable Inference (TOPLOC):\n\
             • get_inference_commitment — Fetch a stored top-k logit commitment by hash\n\
             • verify_inference_commitment — Re-execute a prompt and compare per-step logits\n\
             • file_inference_challenge — Dispute a stored commitment (draws a stake-weighted committee)\n\
             • get_inference_challenge — Fetch a challenge by id\n\
             • list_inference_challenges — List challenges (status/provider filters)\n\
             • commit_challenge_vote — Committee member commits a hidden vote\n\
             • reveal_challenge_vote — Committee member reveals (verdict, salt)\n\
             • finalize_challenge — Tally revealed votes; upheld penalizes the provider\n\n\
             Model Lifecycle:\n\
             • serve_model_mcp — Start serving a downloaded model\n\
             • stop_model — Stop serving a model\n\
             • delete_model_mcp — Delete a downloaded model from disk\n\n\
             Multi-modal AI (every load takes a catalog model_id and an optional visibility;\n\
             list_models with loaded=true lists every loaded model of every type):\n\n\
             Multi-modal AI — Forecast (Timeseries):\n\
             • forecast — Run a univariate timeseries forecast (TimesFM 2.5)\n\
             • list_forecast_catalog — Browse curated forecast catalog\n\
             • load_forecast_model — Load a catalog forecast model\n\
             • unload_forecast_model — Drop a forecast model\n\n\
             Multi-modal AI — Vision:\n\
             • vision_embed — Image → dense feature vector (DINOv3, SigLIP2, CLIP)\n\
             • vision_similarity — Cosine similarity between image & text embeddings\n\
             • list_vision_catalog — Browse curated vision encoder catalog\n\
             • load_vision_model — Load a catalog vision encoder\n\
             • unload_vision_model — Drop a vision encoder\n\n\
             Multi-modal AI — Text Embeddings:\n\
             • text_embed — Strings → dense vectors (Qwen3-Embedding, EmbeddingGemma, BGE-M3)\n\
             • list_text_embedding_catalog — Browse curated text-embedding catalog\n\
             • load_text_embedding_model — Load a catalog text encoder\n\
             • unload_text_embedding_model — Drop a text encoder\n\n\
             Multi-modal AI — Segmentation:\n\
             • segment — Prompt-driven mask segmentation (SAM 2, EdgeSAM, MobileSAM)\n\
             • list_segmentation_catalog — Browse curated segmentation catalog\n\
             • load_segmentation_model — Load a catalog segmenter\n\
             • unload_segmentation_model — Drop a segmenter\n\n\
             Multi-modal AI — Detection:\n\
             • detect — Object detection (RF-DETR, D-FINE)\n\
             • list_detection_catalog — Browse curated detection catalog\n\
             • load_detection_model — Load a catalog detector\n\
             • unload_detection_model — Drop a detector\n\n\
             Multi-modal AI — Audio (ASR):\n\
             • transcribe — Speech-to-text (catalog: Whisper, Distil-Whisper, Moonshine, Parakeet, Canary)\n\
             • list_audio_catalog — Browse curated ASR catalog\n\
             • load_audio_model — Load a catalog ASR model\n\
             • unload_audio_model — Drop an ASR model\n\n\
             Multi-modal AI — Video:\n\
             • video_embed — Clip-level video embedding (frames extracted, embedded, mean-pooled)\n\
             • list_video_catalog — Browse curated video catalog (V-JEPA 2 ViT-L / ViT-H / ViT-g)\n\
             • load_video_model — Compose a clip encoder over an already-loaded image encoder\n\
             • unload_video_model — Drop a video encoder\n\n\
             Committee Data Availability:\n\
             • da_challenge — Nonce-bound possession challenge against a committee member\n\
             • da_list_challenges — Resolved challenge records, newest-first\n\
             • da_availability — Rolling availability scores (0-1000) per member\n\
             • da_committee — Committee roster with per-member availability\n\
             • da_list_blobs — Locally-known blob commitments + certificates\n\n\
             Duties and Evidence:\n\
             • list_duties — Open network duties the chain pays the first prover for\n\
             • get_duty — One duty by id\n\
             • verify_evidence — Check evidence items against chain state\n\n\
             Agent Advanced:\n\
             • discover_models — Discover available AI models (with optional category/price filter)\n\
             Bridge (governed routes):\n\
             • list_bridge_routes — Every governed route with caps, usage and supply\n\
             • get_bridge_route — One route by transport and external chain\n\
             • bridge_outbound — Build a send of TNZO or a carried asset (USDC) over a route, for the holder to sign\n\n\
             Stakes & Providers:\n\
             • get_role_stakes — Read an account's stake per role\n\
             • list_role_endpoints — A role's staked operators and their published URLs\n\
             • get_provider_stats — Get provider performance metrics\n\
             • get_compute_bond — Read compute bonds and the admission minimum\n\n\
             Provider Config:\n\
             • get_model_stacks — Stack serving now, the next one, and when they switch\n\
             • set_provider_pricing — Set token and per-unit pricing for a provider\n\
             • get_provider_pricing — Get current pricing config for a provider\n\n\
             Governance:\n\
             • list_proposals — List on-chain proposals, newest first (filter by kind)\n\
             • governance_get — Read a proposal, enacted policy or grant\n\
             • get_voting_power — Get voting power (bonded stake) for an address\n\
             • get_sponsored_bond — A validator's governance-sponsored bond and the governed caps\n\
             • get_treasury_payouts — Every sponsorship and grant disbursement, by recipient and class\n\
             • get_guardian_state — Guardian seats, threshold and the enactment pause\n\n\
             Token:\n\
             • token_balance — Get TNZO balance for an address\n\
             • total_supply — Get total TNZO token supply\n\n\
             Settlement:\n\
             • settle_payment — Immediately settle a payment between two parties\n\
             • create_escrow — Create an escrow contract for conditional payment\n\
             • release_escrow — Release an escrow with an authorizing signature\n\
             • open_payment_channel — Open a payment channel over an escrow the payer funded\n\
             • close_payment_channel — Close a channel (payer-signed); the highest voucher is claimed on-chain\n\n\
             Network:\n\
             • get_node_status — Node health, block height, peers\n\
             • get_node_did_document — Every way of reaching this node\n\
             • get_network_stats — NetworkMetrics snapshot (gossip counters, direct gossip peers)\n\
             • get_block — Get block by height\n\
             • get_block_range — Fetch a contiguous range of blocks (default 64, max 256)\n\
             • get_transaction — Look up transaction by hash\n\
             • get_fee_market — EIP-1559 fee snapshot (gas price, suggested tip, base-fee history)\n\n\
             Verification:\n\
             • verify_zk_proof — Verify Plonky3 STARK proof (over KoalaBear) for one of the registered AIRs (inference/settlement/identity)\n\
             • verify_vrf_proof — Verify Tenzro VRF proof (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)\n\n\
             Tokens & Contracts:\n\
             • get_token_info — Look up token by symbol, address, or ID\n\
             • list_tokens — List registered tokens with optional VM filter\n\
             • deploy_contract — Submit a signed ContractDeploy transaction\n\
             • get_token_balance — Get TNZO balance across all VMs"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// The routes under `/mcp`: the full listing at `/mcp` and the compact one
/// at `/mcp/compact`, without the OAuth layer [`start_mcp_server`] puts in
/// front of them.
pub fn mcp_routes(node: Arc<TenzroNode>) -> axum::Router {
    axum::Router::new()
        .route_service("/compact", mcp_http_service(node.clone(), true))
        .fallback_service(mcp_http_service(node, false))
}

/// The Streamable HTTP service mounted at `/mcp`, or with `compact` at
/// `/mcp/compact`.
///
/// Stateless with JSON responses: each HTTP POST is independent, with no
/// session and no SSE framing (see [`super::http_config`]).
fn mcp_http_service(
    node: Arc<TenzroNode>,
    compact: bool,
) -> rmcp::transport::streamable_http_server::StreamableHttpService<
    TenzroMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager,
    };
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "0.0.0.0".to_string(),
    ];
    hosts.extend(crate::exposure::mcp_public_host(node.config()));
    let config = super::http_config(hosts);
    StreamableHttpService::new(
        move || {
            Ok(if compact {
                TenzroMcpServer::new_compact(node.clone())
            } else {
                TenzroMcpServer::new(node.clone())
            })
        },
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

/// Start the MCP server on the given address using Streamable HTTP transport
/// Public API method for external use without shutdown signal
pub async fn start_mcp_server(
    listen_addr: String,
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
) -> NodeResult<()> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_mcp_server_with_shutdown(listen_addr, node, web_state, shutdown_rx).await
}

/// Start the MCP server with graceful shutdown support
pub async fn start_mcp_server_with_shutdown(
    listen_addr: String,
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> NodeResult<()> {
    // ── OAuth 2.1 Authentication ──
    let mcp_auth_mode =
        super::oauth::McpAuthMode::from_env().map_err(crate::error::NodeError::Config)?;
    // Create OAuth state *before* the MCP closure moves `node`.
    let oauth_state = Arc::new(super::oauth::OAuthState::new(
        node.clone(),
        web_state.clone(),
    ));
    // Store OAuthState on the node so RPC handlers can use onboarding key methods
    *node.oauth_state.write() = Some(oauth_state.clone());
    let oauth_mw_state = oauth_state.clone();

    // moved into the service factory closure.
    let node_for_gate = node.clone();

    let service = mcp_routes(node);

    let app = axum::Router::new()
        // OAuth discovery & endpoints (unauthenticated)
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(super::oauth::metadata_handler),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(super::oauth::resource_metadata_handler),
        )
        .route(
            "/authorize",
            axum::routing::get(super::oauth::authorize_handler)
                .post(super::oauth::authorize_submit_handler),
        )
        .route("/token", axum::routing::post(super::oauth::token_handler))
        .route("/revoke", axum::routing::post(super::oauth::revoke_handler))
        .with_state(oauth_state)
        // MCP endpoint (protected by bearer auth middleware)
        .nest_service("/mcp", service)
        // Bearer auth layer — only enforces on /mcp paths
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let state = oauth_mw_state.clone();
                async move {
                    super::oauth::bearer_auth_check(state, mcp_auth_mode, req, next).await
                }
            },
        ))
        .layer(axum::middleware::from_fn_with_state(
            (node_for_gate.clone(), tenzro_types::node_access::Surface::Mcp),
            crate::access::http_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            node_for_gate.clone(),
            crate::inference_admission::identify_caller,
        ))
        // Who and where each request came from, for the administrative
        // audit log.
        .layer(axum::middleware::from_fn_with_state(
            (node_for_gate, crate::admin_audit::Transport::Mcp),
            crate::admin_audit::capture_http,
        ))
        // the marker on a particular code path.
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(req).await;
                let (name, value) = crate::eu_ai_disclosure::http_header_pair();
                response.headers_mut().insert(
                    axum::http::HeaderName::from_static(name),
                    axum::http::HeaderValue::from_static(value),
                );
                response
            },
        ))
        // applies. MCP tool calls carry small JSON envelopes, not blobs.
        .layer(tower::limit::ConcurrencyLimitLayer::new(200))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            4 * 1024 * 1024,
        ));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let tool_count = TenzroMcpServer::router().list_all().len();
    tracing::info!(addr = %listen_addr, tools = tool_count, mode = "stateless-json", oauth = true, "MCP Server listening (endpoints: /mcp, compact listing /mcp/compact; OAuth 2.1 enabled)");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.recv().await;
        tracing::info!("MCP server shutting down gracefully");
    })
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_parameter_schemas() {
        let _schema = schemars::schema_for!(GetBalanceParams);
        let _schema = schemars::schema_for!(GetBlockParams);
        let _schema = schemars::schema_for!(RegisterIdentityParams);
        let _schema = schemars::schema_for!(ResolveDidParams);
        let _schema = schemars::schema_for!(VerifyZkProofParams);
        let _schema = schemars::schema_for!(ListModelsParams);
        let _schema = schemars::schema_for!(CreatePaymentChallengeParams);
        let _schema = schemars::schema_for!(VerifyPaymentParams);
        let _schema = schemars::schema_for!(ExchangeTokenParams);
        let _schema = schemars::schema_for!(IntrospectTokenParams);
        // Crypto params
        let _schema = schemars::schema_for!(VerifySignatureParams);
        // TEE params
        let _schema = schemars::schema_for!(DetectTeeParams);
        let _schema = schemars::schema_for!(GetTeeAttestationParams);
        let _schema = schemars::schema_for!(VerifyTeeAttestationParams);
        let _schema = schemars::schema_for!(ListTeeProvidersParams);
        // ZK params
        let _schema = schemars::schema_for!(CreateZkProofParams);
        let _schema = schemars::schema_for!(ListZkCircuitsParams);
    }

    #[test]
    fn test_parse_address_valid() {
        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr.as_bytes()[19], 1);
    }

    #[test]
    fn test_parse_address_no_prefix() {
        let addr = parse_address("0000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr.as_bytes()[19], 1);
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        assert!(parse_address("0xZZZZ").is_err());
    }

    /// Tools that compute locally from constants and touch no node state.
    /// Each entry says why it needs no gate.
    const LOCAL_ONLY_TOOLS: &[(&str, &str)] = &[];

    /// Every tool reaches node state through `rpc_dispatch`, so the JSON-RPC
    /// gate table (access policy, classification, handler authorization)
    /// governs the MCP surface too. A tool body that names `self.node` for
    /// anything but handing it to the dispatcher, or reads `self.web_state`,
    /// fails this test.
    #[test]
    fn every_tool_reaches_node_state_through_rpc_dispatch() {
        let src = include_str!("server.rs");
        let src = &src[..src.find("#[cfg(test)]\nmod tests {").unwrap()];
        let mut tools = 0;
        let mut offenders = Vec::new();
        for (idx, _) in src.match_indices("\n    #[tool(") {
            let fn_at = idx + src[idx..].find("\n    async fn ").unwrap() + 14;
            let name: String = src[fn_at..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let arrow = fn_at + src[fn_at..].find("->").unwrap();
            let body_start = arrow + src[arrow..].find('{').unwrap();
            let body_end = body_start + src[body_start..].find("\n    }\n").unwrap();
            let body = &src[body_start..body_end];
            tools += 1;
            let dispatches = body.contains("rpc_dispatch(")
                || body.contains("rpc_tool(")
                || body.contains("rpc_tool_typed(")
                || body.contains("sign_and_send(")
                || body.contains("agent_escrow_act(");
            let stripped = body.replace("&self.node", "");
            let touches_state = stripped.contains("self.node")
                || stripped.contains("self.web_state")
                || stripped.contains("node.");
            if LOCAL_ONLY_TOOLS.iter().any(|(n, _)| *n == name) {
                assert!(
                    !touches_state && !dispatches,
                    "{name} is listed as local-only"
                );
                continue;
            }
            if !dispatches || touches_state {
                offenders.push(name);
            }
        }
        assert!(
            tools > 240,
            "only {tools} tools found; the scan is not reading the router"
        );
        assert!(
            offenders.is_empty(),
            "tools that bypass rpc_dispatch: {offenders:?}"
        );
    }

    /// What a code-generating harness (a "code mode" wrapper that turns the
    /// tool list into a typed API, e.g. Cloudflare's Code Mode) needs from
    /// every tool regardless of its shape: a name it can bind to a function
    /// identifier without guessing a convention, and a description it can
    /// turn into a doc comment. Every tool this server lists must have both.
    #[test]
    fn every_tool_has_a_snake_case_name_and_a_description() {
        let mut offenders = Vec::new();
        for tool in TenzroMcpServer::router().list_all() {
            let name = tool.name.as_ref();
            let valid_name = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && name.chars().next().is_some_and(|c| c.is_ascii_lowercase());
            let has_description = tool
                .description
                .as_deref()
                .is_some_and(|d| !d.trim().is_empty());
            if !valid_name || !has_description {
                offenders.push(format!(
                    "{name} (valid_name={valid_name}, has_description={has_description})"
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "tools failing naming/description: {offenders:?}"
        );
    }

    /// Tools whose parameters are a genuinely empty struct (or none at all):
    /// `schemars` renders that as a bare `{"type":"object"}`, indistinguishable
    /// at the schema level from a tool that takes one free-form catch-all
    /// object — the only way to tell them apart is to know the struct has no
    /// fields, which this list records by hand, once, reviewed. Every other
    /// hand-typed tool must have named fields in its schema; this is the
    /// only accepted alternative, not a general escape hatch — a tool added
    /// here without actually having zero parameters defeats the test below.
    const ZERO_ARGUMENT_TOOLS: &[&str] = &[
        "adaptive_burn_get_config",
        "adaptive_burn_get_metrics",
        "adaptive_burn_get_recommendation",
        "da_committee",
        "da_list_blobs",
        "detect_tee",
        "get_access_policy",
        "get_connectivity",
        "get_da_retention",
        "get_economic_policy",
        "get_engine_releases",
        "get_insurance_pool",
        "get_model_stacks",
        "get_network_stats",
        "get_node_did_document",
        "get_node_status",
        "get_provider_pricing",
        "get_router_metrics",
        "get_treasury_accounts",
        "get_update_notice",
        "iroh_get_info",
        "list_access_tokens",
        "list_active_validators",
        "list_audio_catalog",
        "list_bridge_routes",
        "list_decision_catalog",
        "list_detection_catalog",
        "list_duties",
        "list_forecast_catalog",
        "list_model_endpoints",
        "list_relays",
        "list_rerank_catalog",
        "list_sealed_models",
        "list_segmentation_catalog",
        "list_snapshots",
        "list_tee_providers",
        "list_text_embedding_catalog",
        "list_text_segmentation_catalog",
        "list_video_catalog",
        "list_vision_catalog",
        "list_zk_circuits",
        "media_gen_list_catalog",
        "model_recipient_key",
        "moe_expert_status",
        "moe_replication_policy",
        "node_profile",
        "oauth_discovery",
        "settlement_networks",
        "sla_get_params",
        "sla_list_outstanding_probes",
        "storage_status",
        "total_supply",
    ];

    /// A tool's own hand-typed parameters (the `#[tool]` functions, not the
    /// generic RPC mirrors below) must describe actual fields a code-mode
    /// harness can bind to typed arguments, not an opaque free-form object.
    /// The generic RPC-mirror tools in `rpc_tools.rs` are a deliberate
    /// exception: each forwards one JSON-RPC method's `params` unchanged by
    /// design (see that module's own doc comment), so their schema is
    /// necessarily `{"params": object | array}` rather than named fields —
    /// giving them typed input would mean describing every served JSON-RPC
    /// method's parameter shape a second time here, which progressive
    /// discovery exists to make unnecessary.
    #[test]
    fn every_hand_typed_tools_input_schema_is_not_free_form() {
        let mirror_names: std::collections::BTreeSet<&str> = super::super::rpc_tools::RPC_TOOLS
            .iter()
            .map(|r| r.name)
            .collect();
        let mut offenders = Vec::new();
        for tool in TenzroMcpServer::router().list_all() {
            if mirror_names.contains(tool.name.as_ref()) {
                continue;
            }
            let has_named_fields = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
                .is_some_and(|p| !p.is_empty());
            let zero_argument = ZERO_ARGUMENT_TOOLS.contains(&tool.name.as_ref());
            if !has_named_fields && !zero_argument {
                offenders.push(tool.name.to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "hand-typed tools with a free-form input schema: {offenders:?}"
        );
    }

    /// The exemption above names exactly the tools whose schema has no
    /// `properties` and no named fields — not a stale list that quietly
    /// stopped matching reality, and not a list broader than it needs to be.
    #[test]
    fn the_zero_argument_tool_list_matches_exactly_the_tools_with_no_named_fields() {
        let mirror_names: std::collections::BTreeSet<&str> = super::super::rpc_tools::RPC_TOOLS
            .iter()
            .map(|r| r.name)
            .collect();
        let actual: std::collections::BTreeSet<String> = TenzroMcpServer::router()
            .list_all()
            .into_iter()
            .filter(|tool| !mirror_names.contains(tool.name.as_ref()))
            .filter(|tool| {
                !tool
                    .input_schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .is_some_and(|p| !p.is_empty())
            })
            .map(|tool| tool.name.to_string())
            .collect();
        let listed: std::collections::BTreeSet<String> =
            ZERO_ARGUMENT_TOOLS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            actual, listed,
            "ZERO_ARGUMENT_TOOLS has drifted from the tools that actually take none"
        );
    }

    thread_local! {
        /// The named schemas being expanded, outermost first.
        static TS_EXPANDING: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// The named schemas found to contain themselves.
        static TS_RECURSIVE: std::cell::RefCell<std::collections::BTreeSet<String>> =
            const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
        /// Each recursive schema's alias body.
        static TS_ALIASES: std::cell::RefCell<std::collections::BTreeMap<String, String>> =
            const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    }

    /// Whether `ts` reads as free-form: it renders `unknown` itself or names a
    /// recursive alias whose body does.
    fn ts_free_form(ts: &str) -> bool {
        if ts.contains("unknown") {
            return true;
        }
        let words: std::collections::BTreeSet<&str> = ts
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        TS_ALIASES.with(|a| {
            a.borrow()
                .iter()
                .any(|(name, body)| words.contains(name.as_str()) && body.contains("unknown"))
        })
    }

    /// One JSON schema as the TypeScript type a code-generating harness
    /// would bind it to, resolving `$ref`s against `root`. `unknown` marks a
    /// value the schema leaves free-form.
    fn ts_type(schema: &serde_json::Value, root: &serde_json::Value, depth: usize) -> String {
        use serde_json::Value;
        let obj = match schema {
            Value::Object(o) if depth < 32 => o,
            Value::Bool(false) => return "never".to_string(),
            _ => return "unknown".to_string(),
        };
        if let Some(r) = obj.get("$ref").and_then(Value::as_str) {
            let Some(target) = r.strip_prefix('#').and_then(|p| root.pointer(p)) else {
                return "unknown".to_string();
            };
            // A type that contains itself is declared once as a named alias
            // and referred to by name, the way a TypeScript generator writes it.
            let name = r.rsplit('/').next().unwrap_or(r).to_string();
            if TS_EXPANDING.with(|e| e.borrow().contains(&name)) {
                TS_RECURSIVE.with(|rec| rec.borrow_mut().insert(name.clone()));
                return name;
            }
            TS_EXPANDING.with(|e| e.borrow_mut().push(name.clone()));
            let body = ts_type(target, root, depth + 1);
            TS_EXPANDING.with(|e| e.borrow_mut().pop());
            if !TS_RECURSIVE.with(|rec| rec.borrow().contains(&name)) {
                return body;
            }
            TS_ALIASES.with(|a| {
                let mut a = a.borrow_mut();
                if let Some(seen) = a.get(&name) {
                    assert_eq!(seen, &body, "two recursive types are both named {name}");
                }
                a.insert(name.clone(), body);
            });
            return name;
        }
        if let Some(c) = obj.get("const") {
            return c.to_string();
        }
        if let Some(values) = obj.get("enum").and_then(Value::as_array) {
            return values
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
        }
        for (key, sep) in [("anyOf", " | "), ("oneOf", " | "), ("allOf", " & ")] {
            if let Some(parts) = obj.get(key).and_then(Value::as_array) {
                return parts
                    .iter()
                    .map(|p| format!("({})", ts_type(p, root, depth + 1)))
                    .collect::<Vec<_>>()
                    .join(sep);
            }
        }
        let types: Vec<&str> = match obj.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
            _ if obj.contains_key("properties") => vec!["object"],
            _ => return "unknown".to_string(),
        };
        types
            .iter()
            .map(|t| match *t {
                "string" => "string".to_string(),
                "integer" | "number" => "number".to_string(),
                "boolean" => "boolean".to_string(),
                "null" => "null".to_string(),
                "array" => format!(
                    "Array<{}>",
                    obj.get("items")
                        .map_or("unknown".to_string(), |i| ts_type(i, root, depth + 1))
                ),
                "object" => {
                    let required: std::collections::BTreeSet<&str> = obj
                        .get("required")
                        .and_then(Value::as_array)
                        .map(|r| r.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    match (
                        obj.get("properties").and_then(Value::as_object),
                        obj.get("additionalProperties"),
                    ) {
                        (Some(props), _) => {
                            let fields: Vec<String> = props
                                .iter()
                                .map(|(k, v)| {
                                    let opt = if required.contains(k.as_str()) {
                                        ""
                                    } else {
                                        "?"
                                    };
                                    format!("{k}{opt}: {};", ts_type(v, root, depth + 1))
                                })
                                .collect();
                            format!("{{ {} }}", fields.join(" "))
                        }
                        (None, Some(extra @ Value::Object(_))) => {
                            format!("Record<string, {}>", ts_type(extra, root, depth + 1))
                        }
                        _ => "Record<string, unknown>".to_string(),
                    }
                }
                _ => "unknown".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// The function name a harness binds a snake_case tool to.
    fn ts_ident(name: &str) -> String {
        let mut out = String::new();
        let mut upper = false;
        for c in name.chars() {
            if c == '_' {
                upper = true;
            } else if upper {
                out.extend(c.to_uppercase());
                upper = false;
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The tool list as TypeScript declarations, one function per tool, the
    /// way a code-mode harness exposes an MCP server to generated code. Also
    /// the tools whose input or output renders free-form, as `input <tool>`
    /// or `output <tool>`; a JSON-RPC mirror tool (`rpc_tools.rs`) forwards
    /// its method's params and result unchanged by design and is checked for
    /// that envelope instead.
    fn ts_declarations() -> (String, std::collections::BTreeSet<String>) {
        let mirrors: std::collections::BTreeSet<&str> = super::super::rpc_tools::RPC_TOOLS
            .iter()
            .map(|r| r.name)
            .collect();
        let mut idents = std::collections::BTreeMap::new();
        let mut out = String::new();
        let mut untyped = std::collections::BTreeSet::new();
        TS_ALIASES.with(|a| a.borrow_mut().clear());
        TS_RECURSIVE.with(|r| r.borrow_mut().clear());
        for tool in TenzroMcpServer::router().list_all() {
            let name = tool.name.to_string();
            let input_root = serde_json::Value::Object((*tool.input_schema).clone());
            let input = if ZERO_ARGUMENT_TOOLS.contains(&name.as_str()) {
                "{}".to_string()
            } else {
                ts_type(&input_root, &input_root, 0)
            };
            let output = match &tool.output_schema {
                Some(s) => {
                    let root = serde_json::Value::Object((**s).clone());
                    ts_type(&root, &root, 0)
                }
                None => "unknown".to_string(),
            };
            let ident = ts_ident(&name);
            if let Some(other) = idents.insert(ident.clone(), name.clone()) {
                panic!("{other} and {name} both bind to {ident}");
            }
            let description = tool
                .description
                .as_deref()
                .unwrap_or("")
                .replace("*/", "* /");
            out.push_str(&format!(
                "/** {description} */\n{ident}(args: {input}): Promise<{output}>;\n"
            ));
            if mirrors.contains(name.as_str()) {
                assert_eq!(
                    (input.as_str(), output.as_str()),
                    (
                        "{ params?: Record<string, unknown> | Array<unknown>; }",
                        "{ result: unknown; }"
                    ),
                    "mirror tool {name} does not carry the forwarding envelope"
                );
                continue;
            }
            if ts_free_form(&input) {
                untyped.insert(format!("input {name}"));
            }
            if ts_free_form(&output) {
                untyped.insert(format!("output {name}"));
            }
        }
        let aliases: String = TS_ALIASES.with(|a| {
            a.borrow()
                .iter()
                .map(|(name, body)| format!("type {name} = {body};\n"))
                .collect()
        });
        (aliases + &out, untyped)
    }

    /// Every catalog row reads as its typed row and back without losing a
    /// field, so a catalog field added later fails here, not in a caller.
    #[test]
    fn typed_catalog_rows_carry_every_field() {
        fn check<R: serde::de::DeserializeOwned + Serialize>(rows: Vec<serde_json::Value>) {
            for row in rows {
                let mut want = row.clone();
                want.as_object_mut().unwrap().retain(|_, v| !v.is_null());
                let typed: R = serde_json::from_value(row).unwrap();
                assert_eq!(serde_json::to_value(typed).unwrap(), want);
            }
        }
        use crate::catalog_rpc::with_licence;
        check::<VisionCatalogRow>(with_licence(&tenzro_model::get_vision_catalog()));
        check::<ForecastCatalogRow>(with_licence(&tenzro_model::get_forecast_catalog()));
        check::<SegmentationCatalogRow>(with_licence(&tenzro_model::get_segmentation_catalog()));
        check::<TextSegmentationCatalogRow>(with_licence(
            &tenzro_model::get_text_segmentation_catalog(),
        ));
        check::<DetectionCatalogRow>(with_licence(&tenzro_model::get_detection_catalog()));
        check::<AudioCatalogRow>(with_licence(&tenzro_model::get_audio_catalog()));
        check::<VideoCatalogRow>(with_licence(&tenzro_model::get_video_catalog()));
    }

    /// Code-generating harnesses turn this tool list into a TypeScript API,
    /// so every tool must convert to a declaration with a typed input and a
    /// typed result. `untyped_tool_schemas.txt` names the hand-typed tools
    /// that still convert to a free-form side; it must match exactly, so a
    /// new free-form tool fails here and a tool that gains a typed schema
    /// leaves the list.
    // The typed output schemas these read are the `mcp-output-schemas` feature's.
    #[cfg(feature = "mcp-output-schemas")]
    #[test]
    fn the_tool_list_converts_to_typed_typescript_declarations() {
        let (declarations, untyped) = ts_declarations();
        let listed_text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/mcp/untyped_tool_schemas.txt"
        ))
        .unwrap();
        let listed: std::collections::BTreeSet<String> = listed_text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        let new_untyped: Vec<_> = untyped.difference(&listed).collect();
        let now_typed: Vec<_> = listed.difference(&untyped).collect();
        eprintln!(
            "{} tool declarations, {} bytes; {} free-form sides listed",
            declarations.lines().filter(|l| l.ends_with(';')).count(),
            declarations.len(),
            listed.len()
        );
        assert!(
            new_untyped.is_empty() && now_typed.is_empty(),
            "free-form and not listed: {new_untyped:?}; listed but typed now: {now_typed:?}"
        );
    }

    /// A type that contains itself converts to one named alias that the
    /// declarations refer to, so it reads as typed rather than free-form.
    // The typed output schemas these read are the `mcp-output-schemas` feature's.
    #[cfg(feature = "mcp-output-schemas")]
    #[test]
    fn recursive_types_convert_to_named_aliases() {
        let (declarations, _) = ts_declarations();
        assert!(declarations.contains(
            "type JsonValue = (null) | (boolean) | (number) | (string) | (Array<JsonValue>) | (Record<string, JsonValue>);"
        ));
        let rule = declarations
            .lines()
            .find(|l| l.starts_with("type AccessRule = "))
            .expect("the access rule alias");
        assert!(rule.contains("rules: Array<AccessRule>;") && rule.contains("inner: AccessRule;"));
        assert!(!rule.contains("unknown"));
    }

    /// No tool takes key material as an argument: a key in a tool call ends
    /// up in the model's transcript.
    #[test]
    fn no_tool_accepts_a_private_key() {
        for tool in TenzroMcpServer::router().list_all() {
            let props = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
                .cloned()
                .unwrap_or_default();
            for key in props.keys() {
                assert!(
                    !matches!(
                        key.as_str(),
                        "private_key" | "private_key_hex" | "secret_key" | "secret_key_hex"
                    ),
                    "tool {} takes key material in '{key}'",
                    tool.name
                );
            }
        }
    }

    #[tokio::test]
    async fn create_zk_proof_refuses_the_secret_key_witness() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let server = TenzroMcpServer::new(Arc::new(TenzroNode::new(cfg).await.unwrap()));
        let err = server
            .create_zk_proof(Parameters(CreateZkProofParams {
                circuit_id: "identity".to_string(),
                witness: ZkSettlementWitness {
                    witness: format!("0x{}", "07".repeat(32)),
                    binding: format!("0x{}", "02".repeat(32)),
                },
            }))
            .await
            .err()
            .expect("identity witness refused");
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn node_side_signing_is_not_a_tool() {
        let names: Vec<_> = TenzroMcpServer::router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n == "sign_message" || n == "sign_transaction")
        );
    }

    #[test]
    fn omitted_optional_arguments_reach_the_handler_as_absent() {
        let args = rpc_args(serde_json::json!({ "message": "hi", "messages": null }));
        assert!(args.get("messages").is_none());
        assert_eq!(args["message"], "hi");
    }

    async fn post_mcp(url: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
        let mut params = params;
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        reqwest::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", method)
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// A node's MCP routes on an ephemeral port; the base URL of `/mcp`.
    async fn serve_mcp() -> (String, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let node = Arc::new(TenzroNode::new(cfg).await.unwrap());
        let app = axum::Router::new().nest_service("/mcp", mcp_routes(node));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/mcp",
            listener.local_addr().unwrap().port()
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, tmp)
    }

    async fn call_tool(url: &str, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        });
        reqwest::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", name)
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// The compact listing names two tools, and costs a small fraction of
    /// the full listing in an agent's context. Sizes are the `tools/list`
    /// replies on the wire; tokens are estimated at four bytes each.
    #[tokio::test]
    async fn the_compact_listing_is_two_tools_under_two_thousand_tokens() {
        let (url, _tmp) = serve_mcp().await;
        let full = post_mcp(&url, "tools/list", serde_json::json!({})).await;
        let compact = post_mcp(
            &format!("{url}/compact"),
            "tools/list",
            serde_json::json!({}),
        )
        .await;
        let names: Vec<&str> = compact["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert_eq!(names, vec!["search", "call"], "{compact}");
        let full_names: Vec<&str> = full["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(!full_names.contains(&"search") && !full_names.contains(&"call"));
        let full_bytes = full["result"]["tools"].to_string().len();
        let compact_bytes = compact["result"]["tools"].to_string().len();
        eprintln!(
            "tools/list: full {} tools, {full_bytes} bytes (~{} tokens); compact {compact_bytes} bytes (~{} tokens)",
            full_names.len(),
            full_bytes / 4,
            compact_bytes / 4
        );
        assert!(
            compact_bytes / 4 < 2000,
            "compact listing is ~{} tokens",
            compact_bytes / 4
        );
    }

    /// `search` returns a tool with the schemas the full listing states, and
    /// `call` runs it exactly as a direct call does: the same result for an
    /// open read, the same refusal for an operator-only method and a paid
    /// one called without credentials. An unknown tool and arguments its
    /// schema refuses are invalid params naming the reason.
    #[tokio::test]
    async fn a_compact_call_takes_the_same_path_as_a_direct_call() {
        let (url, _tmp) = serve_mcp().await;
        let compact = format!("{url}/compact");

        let found = call_tool(
            &compact,
            "search",
            serde_json::json!({ "query": "list providers" }),
        )
        .await;
        let first = &found["result"]["structuredContent"]["matches"][0];
        assert_eq!(first["name"], "list_providers", "{found}");
        let full = post_mcp(&url, "tools/list", serde_json::json!({})).await;
        let listed = full["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "list_providers")
            .unwrap()
            .clone();
        assert_eq!(first["input_schema"], listed["inputSchema"]);
        assert_eq!(first["output_schema"], listed["outputSchema"]);

        let pairs = [
            ("list_providers", serde_json::json!({ "limit": 5 })),
            ("list_admin_audit", serde_json::json!({ "params": {} })),
            (
                "chat",
                serde_json::json!({ "params": { "model_id": "qwen3-4b", "message": "hi" } }),
            ),
        ];
        for (tool, args) in pairs {
            let direct = call_tool(&url, tool, args.clone()).await;
            let via_call = call_tool(
                &compact,
                "call",
                serde_json::json!({ "name": tool, "arguments": args }),
            )
            .await;
            assert_eq!(
                direct["result"], via_call["result"],
                "{tool}: {direct} / {via_call}"
            );
            assert_eq!(
                direct["error"], via_call["error"],
                "{tool}: {direct} / {via_call}"
            );
        }
        let admin = call_tool(
            &url,
            "list_admin_audit",
            serde_json::json!({ "params": {} }),
        )
        .await;
        assert!(
            admin["error"].is_object(),
            "operator-only method answered: {admin}"
        );

        let unknown = call_tool(
            &compact,
            "call",
            serde_json::json!({ "name": "no_such_tool" }),
        )
        .await;
        assert_eq!(unknown["error"]["code"], -32602, "{unknown}");
        assert_eq!(
            unknown["error"]["data"]["reason"], "unknown_tool",
            "{unknown}"
        );
        let invalid = call_tool(
            &compact,
            "call",
            serde_json::json!({ "name": "list_providers", "arguments": { "limit": "five" } }),
        )
        .await;
        assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
        assert_eq!(
            invalid["error"]["data"]["reason"], "invalid_arguments",
            "{invalid}"
        );
    }

    /// The HTTP surface speaks revision 2026-07-28: stateless discovery, and
    /// every result names its `resultType`.
    #[tokio::test]
    async fn http_surface_serves_the_2026_07_28_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let node = Arc::new(TenzroNode::new(cfg).await.unwrap());
        let app = axum::Router::new().nest_service("/mcp", mcp_routes(node));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/mcp",
            listener.local_addr().unwrap().port()
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let discover = post_mcp(&url, "server/discover", serde_json::json!({})).await;
        let result = &discover["result"];
        assert_eq!(result["resultType"], "complete", "{discover}");
        let versions: Vec<&str> = result["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(versions, vec!["2026-07-28"]);
        assert!(result["capabilities"]["tools"].is_object());

        // A client of an earlier revision gets no session.
        let old = reqwest::Client::new()
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 9, "method": "initialize",
                "params": { "protocolVersion": "2025-11-25", "capabilities": {},
                            "clientInfo": { "name": "old", "version": "0" } }
            }))
            .send()
            .await
            .unwrap();
        let status = old.status();
        let body = old.text().await.unwrap();
        let negotiated_old = status.is_success()
            && serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["result"]["protocolVersion"].as_str().map(str::to_string))
                .is_some_and(|v| v == "2025-11-25");
        assert!(!negotiated_old, "{status} {body}");

        let list = post_mcp(&url, "tools/list", serde_json::json!({})).await;
        assert_eq!(list["result"]["resultType"], "complete", "{list}");
        assert!(list["result"]["tools"].as_array().unwrap().len() > 250);
    }

    /// `initialize` has no place in the revision the HTTP surface speaks. It
    /// is refused with -32022, naming the supported revisions and the
    /// request that opens a session, whichever version the client asks for.
    #[tokio::test]
    async fn http_initialize_is_refused_naming_the_supported_versions() {
        let (url, _tmp) = serve_mcp().await;
        for version in ["2026-07-28", "2025-11-25"] {
            let reply = reqwest::Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .json(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 3, "method": "initialize",
                    "params": { "protocolVersion": version, "capabilities": {},
                                "clientInfo": { "name": "t", "version": "0" } }
                }))
                .send()
                .await
                .unwrap();
            let body = reply.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).expect(&body);
            assert!(json["result"].is_null(), "{version}: {body}");
            assert_eq!(json["error"]["code"], -32022, "{body}");
            assert_eq!(
                json["error"]["data"]["supported"],
                serde_json::json!(["2026-07-28"]),
                "{body}"
            );
            assert_eq!(json["error"]["data"]["opener"], "server/discover", "{body}");
        }
    }

    /// Every listed revision opens over HTTP with `server/discover`, and a
    /// request naming another revision is refused naming the listed ones.
    #[tokio::test]
    async fn http_serves_each_listed_version_and_refuses_others() {
        let (url, _tmp) = serve_mcp().await;
        for version in crate::mcp::served_protocol_versions().iter() {
            let version = version.as_str();
            let params = serde_json::json!({ "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
                "io.modelcontextprotocol/clientCapabilities": {},
            }});
            let reply: serde_json::Value = reqwest::Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", version)
                .header("Mcp-Method", "server/discover")
                .json(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": params
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(
                reply["result"]["supportedVersions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v == version),
                "{reply}"
            );
        }
        let other = reqwest::Client::new()
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2024-11-05")
            .header("Mcp-Method", "tools/list")
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2024-11-05",
                    "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {},
                }}
            }))
            .send()
            .await
            .unwrap();
        let body = other.text().await.unwrap();
        assert!(
            body.contains("-32022") || body.contains("nsupported"),
            "{body}"
        );
    }

    /// Resources over HTTP: the event template is listed and `resources/list`
    /// answers.
    #[tokio::test]
    async fn http_resources_are_reachable() {
        let (url, _tmp) = serve_mcp().await;
        let templates = post_mcp(&url, "resources/templates/list", serde_json::json!({})).await;
        assert!(
            templates["result"]["resourceTemplates"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t["name"] == "chain-events")),
            "{templates}"
        );
        let list = post_mcp(&url, "resources/list", serde_json::json!({})).await;
        assert!(list["result"]["resources"].is_array(), "{list}");
    }

    /// A typed tool's result reads the same in the edge build as in the full
    /// build: the method's result under `result`. Only its schema differs.
    #[test]
    fn a_typed_result_keeps_the_result_envelope_in_every_build() {
        let value = serde_json::json!(42);
        let Json(typed) =
            typed_result::<crate::mcp::tool_types_models::ModelsWideUint>(value.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(typed).unwrap(),
            serde_json::json!({ "result": value })
        );
    }
}
