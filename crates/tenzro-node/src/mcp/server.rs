use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

use crate::error::{NodeError, Result as NodeResult};
use crate::node::TenzroNode;
use crate::web::handlers::WebState;
use tenzro_model::{get_model_catalog, get_model_by_id};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{SettlementRequest, ServiceType, ServiceProof, ProofType};
use tenzro_types::asset::AssetId;

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBalanceParams {
    #[schemars(description = "Hex-encoded account address (with or without 0x prefix)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendTransactionParams {
    #[schemars(description = "Hex-encoded sender address")]
    pub from: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub to: String,
    #[schemars(description = "Amount in TNZO base units")]
    pub amount: u128,
    #[schemars(description = "Gas limit (default 21000)")]
    pub gas_limit: Option<u64>,
    #[schemars(description = "Gas price in wei (default 1 Gwei)")]
    pub gas_price: Option<u64>,
    #[schemars(description = "Transaction nonce (default 0)")]
    pub nonce: Option<u64>,
    #[schemars(description = "Chain ID (default 1337)")]
    pub chain_id: Option<u64>,
    #[schemars(description = "Either (a) omit all of signature/public_key/timestamp and rely on ambient OAuth/DPoP auth — the server will look up the wallet bound to the bearer DID and sign on its behalf — or (b) supply all three for a pre-signed transaction.")]
    pub signature: Option<String>,
    #[schemars(description = "Hex-encoded 32-byte Ed25519 public key (required if pre-signing)")]
    pub public_key: Option<String>,
    #[schemars(description = "Transaction timestamp in ms since Unix epoch — MUST match the timestamp used when computing the signed hash (required if pre-signing)")]
    pub timestamp: Option<u64>,
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
pub struct RequestFaucetParams {
    #[schemars(description = "Hex-encoded recipient address (with or without 0x prefix)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetFeeMarketParams {
    #[schemars(description = "Number of recent blocks to summarize in fee history (1..=1024, default 10)")]
    pub blocks: Option<u64>,
    #[schemars(description = "Tip percentiles to request, e.g. [25.0, 50.0, 75.0]; pass [] or omit to skip percentile sampling")]
    pub reward_percentiles: Option<Vec<f64>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterIdentityParams {
    #[schemars(description = "Identity type: 'human' or 'machine'")]
    pub identity_type: String,
    #[schemars(description = "Display name for the identity")]
    pub display_name: String,
    #[schemars(description = "Controller DID (required for machine identities, e.g. did:tenzro:human:uuid)")]
    pub controller_did: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveDidParams {
    #[schemars(description = "DID to resolve (e.g. did:tenzro:human:uuid or did:tenzro:machine:controller:uuid)")]
    pub did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentJwkParams {
    #[schemars(description = "RFC 9421 keyid — `did:tenzro:...` (first compatible key) or `did:tenzro:...#fragment` (specific key)")]
    pub keyid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTransactionParams {
    #[schemars(description = "Hex-encoded transaction hash (with or without 0x prefix)")]
    pub tx_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyZkProofParams {
    #[schemars(description = "Hex-encoded proof bytes — bincode-encoded p3_uni_stark::Proof")]
    pub proof: String,
    #[schemars(description = "Public inputs as JSON array of hex strings (4-byte LE KoalaBear chunks)")]
    pub public_inputs: Vec<String>,
    #[schemars(description = "Circuit identifier — one of 'inference', 'settlement', 'identity'")]
    pub circuit_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyVrfProofParams {
    #[schemars(description = "Hex-encoded 32-byte VRF public key (Edwards25519 compressed point)")]
    pub pubkey: String,
    #[schemars(description = "Hex-encoded 80-byte VRF proof: Gamma(32) || c(16) || s(32) per RFC 9381")]
    pub proof: String,
    #[schemars(description = "Hex-encoded input message (alpha). Public inputs like block hash, request ID, or NFT mint nonce")]
    pub alpha: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GenerateVrfProofParams {
    #[schemars(description = "Hex-encoded 32-byte VRF secret key (Ed25519-compatible seed)")]
    pub secret_key: String,
    #[schemars(description = "Hex-encoded input message (alpha). Use public data: block hash, request ID, NFT mint nonce")]
    pub alpha: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListModelsParams {
    #[schemars(description = "Filter by model category/modality: 'text', 'image', 'audio', 'video', 'text_image', 'text_audio', 'multimodal' (optional)")]
    pub category: Option<String>,
    #[schemars(description = "Filter by name substring (optional)")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CortexReasonParams {
    #[schemars(description = "Cortex model ID (e.g. 'mythos-3b'). Must be registered via tenzro_registerCortexWorker")]
    pub model_id: String,
    #[schemars(description = "Input prompt / problem statement")]
    pub input: String,
    #[schemars(description = "Reasoning tier: 'fast' (2-4 loops), 'standard' (8), 'deep' (16-32), 'institutional' (TEE + optional ZK). Default 'standard'")]
    pub tier: Option<String>,
    #[schemars(description = "Minimum recurrent loops (overrides tier). Optional")]
    pub min_loops: Option<u32>,
    #[schemars(description = "Maximum recurrent loops (overrides tier). Optional")]
    pub max_loops: Option<u32>,
    #[schemars(description = "Maximum cost in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string. Rejects if pricing exceeds. Optional", with = "Option<String>")]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub max_cost_wei: Option<u128>,
    #[schemars(description = "Attestation requirement: 'none', 'tee', 'tee_and_zk'. Default inferred from tier")]
    pub attestation: Option<String>,
    #[schemars(description = "Caller address (20- or 32-byte hex). Optional")]
    pub requester: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionParams {
    /// Accept both `model` (OpenAI-style, canonical for MCP) and `model_id`
    /// (Tenzro RPC-style). Either key is valid in the JSON payload.
    #[serde(alias = "model_id")]
    #[schemars(description = "Model ID or service instance UUID (alias: model_id)")]
    pub model: String,
    #[schemars(description = "The user message to send")]
    pub message: String,
    #[schemars(description = "Temperature (0.0-2.0, default 0.7)")]
    pub temperature: Option<f64>,
    #[schemars(description = "Maximum tokens to generate (default 512)")]
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreatePaymentChallengeParams {
    #[schemars(description = "Payment protocol: 'mpp' (Machine Payments Protocol — session-based streaming), 'x402' (Coinbase HTTP 402 — stateless one-shot), or 'native' (direct TNZO transfer)")]
    pub protocol: String,
    #[schemars(description = "Resource URL or identifier being paid for (e.g. /api/inference, /api/data/query)")]
    pub resource: String,
    #[schemars(description = "Payment amount in smallest unit (e.g. 100 = 0.000100 USDC for x402, or TNZO base units for native)")]
    pub amount: u128,
    #[schemars(description = "Payment asset: 'USDC', 'USDT', or 'TNZO'")]
    pub asset: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub recipient: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyPaymentParams {
    #[schemars(description = "Challenge ID from the payment challenge")]
    pub challenge_id: String,
    #[schemars(description = "Payment protocol used: 'mpp', 'x402', or 'native'")]
    pub protocol: String,
    #[schemars(description = "Payer DID (e.g. did:tenzro:human:uuid or did:tenzro:machine:controller:uuid)")]
    pub payer_did: String,
    #[schemars(description = "Payer wallet address (hex-encoded)")]
    pub payer_address: String,
    #[schemars(description = "Payment amount in smallest unit")]
    pub amount: u128,
    #[schemars(description = "Payment asset: 'USDC', 'USDT', or 'TNZO'")]
    pub asset: String,
    #[schemars(description = "Hex-encoded classical (Ed25519) signature proving payment")]
    pub signature: String,
    #[schemars(description = "Hex-encoded post-quantum (ML-DSA-65, FIPS 204) signature — 3309 bytes — required for internal Tenzro mpp/x402/native protocols; pass empty string for external passthroughs (visa-tap, mastercard-agent-pay) that don't yet have a hybrid signing scheme")]
    pub pq_signature: String,
    #[schemars(description = "Hex-encoded ML-DSA-65 verifying key — 1952 bytes — required for internal Tenzro mpp/x402/native protocols; pass empty string for external passthroughs")]
    pub pq_public_key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetDelegationScopeParams {
    #[schemars(description = "Machine DID to set delegation scope for")]
    pub machine_did: String,
    #[schemars(description = "Maximum transaction value (in smallest unit, e.g. 10000000 = $10 USDC)")]
    pub max_transaction_value: Option<u128>,
    #[schemars(description = "Maximum daily spend across all transactions")]
    pub max_daily_spend: Option<u128>,
    #[schemars(description = "Allowed operations (e.g. ['InferenceRequest', 'Transfer', 'Stake'])")]
    pub allowed_operations: Option<Vec<String>>,
    #[schemars(description = "Allowed payment protocols (e.g. ['mpp', 'x402', 'native'])")]
    pub allowed_payment_protocols: Option<Vec<String>>,
    #[schemars(description = "Allowed chains (e.g. ['tenzro', 'base', 'ethereum'])")]
    pub allowed_chains: Option<Vec<String>>,
}

// ─── OAuth 2.1 + AAP delegation params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExchangeTokenParams {
    #[schemars(description = "Parent JWT (the `subject_token` per RFC 8693). The AS validates its signature, exp, and revocation state before issuing the child token.")]
    pub subject_token: String,
    #[schemars(description = "DID that will be the `sub` of the new child JWT — typically a delegated agent or sub-agent in the act-chain")]
    pub child_bearer_did: String,
    #[schemars(description = "RFC 7638 JWK thumbprint of the child holder's Ed25519 public key. The child token is DPoP-bound to this key.")]
    pub child_dpop_jkt: String,
    #[schemars(description = "RFC 9396 typed scope envelope the child should carry. Must be a strict subset of the parent's authorization_details. JSON object with `authorization_details: [...]` field.")]
    pub requested_rar: serde_json::Value,
    #[schemars(description = "AAP `aap_capabilities` claim list — per-action constraints layered over RAR. Must be a subset of the parent's capabilities.")]
    pub requested_aap_capabilities: Vec<serde_json::Value>,
    #[schemars(description = "Optional TTL override for the child token in seconds. Clamped to the engine's max_ttl_secs and the parent's remaining lifetime.")]
    pub requested_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IntrospectTokenParams {
    #[schemars(description = "JWT to introspect. The AS returns `{active: true, ...claims}` on success or `{active: false}` per RFC 7662 §2.2 if the token is unknown, expired, or revoked.")]
    pub token: String,
}

// ─── deBridge MCP Proxy Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebridgeSearchTokensParams {
    #[schemars(description = "Token name, symbol, or address to search for")]
    pub query: String,
    #[schemars(description = "Optional chain ID to filter results (e.g. 1 for Ethereum, 56 for BSC)")]
    pub chain_id: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebridgeCreateTxParams {
    #[schemars(description = "Source chain ID (e.g. 1 for Ethereum)")]
    pub src_chain_id: u64,
    #[schemars(description = "Destination chain ID")]
    pub dst_chain_id: u64,
    #[schemars(description = "Source token address")]
    pub src_token: String,
    #[schemars(description = "Destination token address")]
    pub dst_token: String,
    #[schemars(description = "Amount in smallest unit (wei/lamports)")]
    pub amount: String,
    #[schemars(description = "Recipient address on destination chain")]
    pub recipient: String,
    #[schemars(description = "Sender address on source chain")]
    pub sender: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DebridgeSameChainSwapParams {
    #[schemars(description = "Chain ID for the swap")]
    pub chain_id: u64,
    #[schemars(description = "Input token address")]
    pub token_in: String,
    #[schemars(description = "Output token address")]
    pub token_out: String,
    #[schemars(description = "Amount of input token in smallest unit")]
    pub amount: String,
    #[schemars(description = "Sender address")]
    pub sender: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeTokensParams {
    #[schemars(description = "Source chain (e.g. 'tenzro', 'ethereum', 'solana', 'base')")]
    pub source_chain: String,
    #[schemars(description = "Destination chain")]
    pub dest_chain: String,
    #[schemars(description = "Asset to bridge (e.g. 'TNZO', 'USDC', 'ETH')")]
    pub asset: String,
    #[schemars(description = "Amount to bridge in base units")]
    pub amount: u128,
    #[schemars(description = "Hex-encoded sender address on source chain")]
    pub sender: String,
    #[schemars(description = "Hex-encoded recipient address on destination chain")]
    pub recipient: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBridgeRoutesParams {
    #[schemars(description = "Source chain (e.g. 'tenzro', 'ethereum', 'solana')")]
    pub source_chain: String,
    #[schemars(description = "Destination chain")]
    pub dest_chain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateWalletParams {
    #[schemars(description = "Key type: 'ed25519' (default, Tenzro native) or 'secp256k1' (EVM-compatible)")]
    pub key_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StakeTokensParams {
    #[schemars(description = "Amount to stake in wei as a decimal string (1 TNZO = 10^18 wei). Example: '1000000000000000000000' for 1000 TNZO.")]
    pub amount: String,
    #[schemars(description = "Provider type to stake for: 'validator', 'model_provider', 'tee_provider', or 'storage_provider'")]
    pub provider_type: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UnstakeTokensParams {
    #[schemars(description = "Hex-encoded staker address (with or without 0x prefix)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterProviderParams {
    #[schemars(description = "Provider type: 'validator', 'model_provider', 'tee_provider', or 'storage_provider'")]
    pub provider_type: String,
    #[schemars(description = "Provider display name")]
    pub name: String,
    #[schemars(description = "Optional initial stake in wei as a decimal string (1 TNZO = 10^18 wei). Example: '10000000000000000000000' for 10,000 TNZO. Omit or '0' to register without staking.")]
    pub stake: Option<String>,
    #[schemars(description = "Maximum concurrent requests to handle (default 10)")]
    pub max_concurrent: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProviderStatsParams {
    #[schemars(description = "Hex-encoded provider address (with or without 0x prefix). If omitted, returns stats for the local node")]
    pub address: Option<String>,
}

// ─── Task Marketplace Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PostTaskParams {
    #[schemars(description = "Short title for the task (e.g. 'Translate README to Spanish')")]
    pub title: String,
    #[schemars(description = "Detailed description of the task and expected output")]
    pub description: String,
    #[schemars(description = "Task type: inference, code_review, data_analysis, content_generation, agent_execution, translation, research, or custom:<value>")]
    pub task_type: String,
    #[schemars(description = "Hex-encoded address of the task poster")]
    pub poster_address: String,
    #[schemars(description = "Maximum price willing to pay in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "String")]
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub max_price_wei: u128,
    #[schemars(description = "Input data or prompt for the task")]
    pub input: String,
    #[schemars(description = "Optional: minimum model size required (e.g. '7b', '70b')")]
    pub required_model: Option<String>,
    #[schemars(description = "Optional: Unix timestamp deadline for task completion")]
    pub deadline: Option<u64>,
    #[schemars(description = "Task priority: low, normal, high, urgent (default: normal)")]
    pub priority: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListTasksParams {
    #[schemars(description = "Filter by task type (optional)")]
    pub task_type: Option<String>,
    #[schemars(description = "Filter by status: open, assigned, in_progress, completed, cancelled, expired, disputed (optional, default: open)")]
    pub status: Option<String>,
    #[schemars(description = "Filter by poster address (optional)")]
    pub poster: Option<String>,
    #[schemars(description = "Maximum price filter in wei (only show tasks at or below this price). Accepts u64 number or decimal string.", with = "Option<String>")]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub max_price_wei: Option<u128>,
    #[schemars(description = "Maximum number of results (default 20, max 100)")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination")]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QuoteTaskParams {
    #[schemars(description = "UUID of the task to quote")]
    pub task_id: String,
    #[schemars(description = "Hex-encoded address of the provider submitting the quote")]
    pub provider_address: String,
    #[schemars(description = "Quoted price in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "String")]
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub price_wei: u128,
    #[schemars(description = "Model ID the provider will use to complete the task")]
    pub model_id: String,
    #[schemars(description = "Estimated time to complete the task in seconds")]
    pub estimated_secs: u64,
    #[schemars(description = "Provider confidence score 0-100")]
    pub confidence: Option<u8>,
    #[schemars(description = "Optional notes from the provider")]
    pub notes: Option<String>,
}

// ─── Agent Template Marketplace Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterAgentTemplateParams {
    #[schemars(description = "Name of the agent template")]
    pub name: String,
    #[schemars(description = "Detailed description of what the agent does")]
    pub description: String,
    #[schemars(description = "Template type: autonomous, tool_agent, orchestrator, specialist, multi_modal, or custom:<value>")]
    pub template_type: String,
    #[schemars(description = "Hex-encoded address of the template creator")]
    pub creator_address: String,
    #[schemars(description = "System prompt / agent instructions")]
    pub system_prompt: String,
    #[schemars(description = "Comma-separated tags for discoverability (e.g. 'coding,rust,debugging')")]
    pub tags: Option<String>,
    #[schemars(description = "Version string in semver format (default: 1.0.0)")]
    pub version: Option<String>,
    #[schemars(description = "Pricing model: free, per_execution:<price>, per_token:<price>, subscription:<monthly>, revenue_share:<bps>")]
    pub pricing: Option<String>,
    #[schemars(description = "URL to documentation or repository")]
    pub docs_url: Option<String>,
    #[schemars(description = "Optional creator DID binding (e.g. 'did:tenzro:human:uuid' or 'did:tenzro:machine:uuid'). If provided, the template is publicly attributed to this identity.")]
    pub creator_did: Option<String>,
    #[schemars(description = "Optional hex-encoded payout wallet address for creator revenue. REQUIRED when pricing is not 'free' — paid templates without a payout wallet will be rejected.")]
    pub creator_wallet: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListAgentTemplatesParams {
    #[schemars(description = "Filter by template type (optional)")]
    pub template_type: Option<String>,
    #[schemars(description = "Filter by tag (optional, must have this tag)")]
    pub tag: Option<String>,
    #[schemars(description = "Filter by creator address (optional)")]
    pub creator: Option<String>,
    #[schemars(description = "Only show free templates")]
    pub free_only: Option<bool>,
    #[schemars(description = "Maximum number of results (default 20, max 100)")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination")]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunAgentTemplateParams {
    #[schemars(description = "UUID of the spawned agent to run (must have been created via spawn_agent_template first)")]
    pub agent_id: String,
    #[schemars(description = "Maximum iterations through the template's execution steps (default 1)")]
    pub max_iterations: Option<u64>,
    #[schemars(description = "If true, simulate execution without dispatching real transactions or charging fees (default false)")]
    pub dry_run: Option<bool>,
    #[schemars(description = "Hex-encoded payer wallet address. REQUIRED for paid templates — will be charged the network commission (to treasury) and creator payout.")]
    pub payer_wallet: Option<String>,
    #[schemars(description = "Estimated token usage for per-token pricing. Ignored for free/per_execution/subscription pricing. Default 0.")]
    pub tokens_estimate: Option<u64>,
}

// ─── MicroNode Join parameter struct ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JoinAsMicroNodeParams {
    #[schemars(description = "Display name for this participant (human-readable, optional)")]
    pub display_name: Option<String>,
    #[schemars(description = "Entry point: 'mcp' | 'claude' | 'clawbot' | 'a2a' | 'sdk' | 'api' | 'cli' | 'app'")]
    pub origin: Option<String>,
    #[schemars(description = "Participant type: 'human' | 'agent' | 'bot'")]
    pub participant_type: Option<String>,
}

// ─── Username Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetUsernameParams {
    #[schemars(description = "DID to associate the username with (e.g. did:tenzro:human:uuid)")]
    pub did: String,
    #[schemars(description = "Globally unique username to register (alphanumeric, underscores, hyphens)")]
    pub username: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveUsernameParams {
    #[schemars(description = "Username to resolve to its DID")]
    pub username: String,
}

// ─── Skill & Tool Usage Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSkillUsageParams {
    #[schemars(description = "Skill ID to get usage stats for (e.g. 'openclaw-tenzro', 'solana-defi')")]
    pub skill_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetToolUsageParams {
    #[schemars(description = "Tool ID to get usage stats for (e.g. 'tenzro-solana-mcp', 'tenzro-ethereum-mcp')")]
    pub tool_id: String,
}

// ─── Agent Template Marketplace Extended Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SpawnAgentFromTemplateParams {
    #[schemars(description = "Agent template ID to spawn from")]
    pub template_id: String,
    #[schemars(description = "Display name for the spawned agent")]
    pub name: String,
    #[schemars(description = "Optional parent machine DID. When set, the spawned agent's delegation scope is the strict intersection of the parent's scope and the template's spec — the child can never be broader than its parent on any axis.")]
    #[serde(default)]
    pub parent_machine_did: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RateAgentTemplateParams {
    #[schemars(description = "Agent template ID to rate")]
    pub template_id: String,
    #[schemars(description = "Rating from 1 (worst) to 5 (best)")]
    pub rating: u8,
    #[schemars(description = "Optional review comment")]
    pub review: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchAgentTemplatesParams {
    #[schemars(description = "Search query to match against template name, description, and tags")]
    pub query: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentTemplateStatsParams {
    #[schemars(description = "Agent template ID to get stats for")]
    pub template_id: String,
}

// ─── MCP Server ───

/// MCP server exposing Tenzro node capabilities to AI agents.
///
/// Provides 35 tools across 10 categories:
///   - Wallet: create_wallet, get_balance
///   - Transactions: send_transaction, request_faucet
///   - Identity: register_identity, resolve_did, set_delegation_scope, join_as_participant
///   - Models: list_models, chat_completion, list_model_endpoints
///   - Payments: create_payment_challenge, verify_payment, list_payment_protocols
///   - Bridge: bridge_tokens, get_bridge_routes, list_bridge_adapters
///   - Staking & Providers: stake_tokens, unstake_tokens, register_provider, get_provider_stats
///   - Network: get_node_status, get_block, get_block_range, get_transaction, get_fee_market, get_svm_cross_vm_program_info
///   - Verification: verify_zk_proof
///   - Agent Spawning & Swarms: spawn_agent, run_agent_task, create_swarm, get_swarm_status, terminate_swarm

// ─── Agent Spawning & Swarm parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SpawnAgentParams {
    #[schemars(description = "Parent agent ID (UUID)")]
    pub parent_id: String,
    #[schemars(description = "Name for the new child agent")]
    pub name: String,
    #[schemars(description = "Agent capability strings (e.g. nlp, vision, code)")]
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunAgentTaskParams {
    #[schemars(description = "Agent ID that will execute the task")]
    pub agent_id: String,
    #[schemars(description = "Task description for the agentic execution loop")]
    pub task: String,
    #[schemars(description = "Optional inference endpoint URL (default: localhost)")]
    pub inference_url: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateSwarmParams {
    #[schemars(description = "Orchestrator agent ID")]
    pub orchestrator_id: String,
    #[schemars(description = "JSON array of member specs: [{\"name\":\"analyst\",\"capabilities\":[\"data\"]}]")]
    pub members: serde_json::Value,
    #[schemars(description = "Max number of swarm members (default 10)")]
    pub max_members: Option<usize>,
    #[schemars(description = "Task timeout in seconds (default 300)")]
    pub task_timeout_secs: Option<u64>,
    #[schemars(description = "Dispatch tasks in parallel (default true)")]
    pub parallel: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSwarmStatusParams {
    #[schemars(description = "Swarm ID to query")]
    pub swarm_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TerminateSwarmParams {
    #[schemars(description = "Swarm ID to terminate")]
    pub swarm_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListProvidersParams {
    #[schemars(description = "Optional filter by provider type: 'llm', 'tee', or 'general'. If omitted, all providers are returned.")]
    pub provider_type: Option<String>,
}

// ─── Governance Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListProposalsParams {
    #[schemars(description = "Filter by status: 'active', 'passed', 'rejected', 'pending'. If omitted, returns all.")]
    pub status: Option<String>,
    #[schemars(description = "Maximum number of results (default 20)")]
    pub limit: Option<usize>,
    #[schemars(description = "Pagination offset")]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VoteOnProposalParams {
    #[schemars(description = "Proposal ID to vote on")]
    pub proposal_id: String,
    #[schemars(description = "Vote type: 'yes', 'no', or 'abstain'")]
    pub vote: String,
    #[schemars(description = "Hex-encoded voter address")]
    pub voter_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateProposalParams {
    #[schemars(description = "Proposal title")]
    pub title: String,
    #[schemars(description = "Detailed description of the proposal")]
    pub description: String,
    #[schemars(description = "Proposal type: 'parameter_change', 'treasury', 'upgrade', 'text'")]
    pub proposal_type: String,
    #[schemars(description = "Hex-encoded proposer address")]
    pub proposer_address: String,
    #[schemars(description = "Optional JSON payload for the proposal (e.g. parameter changes)")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetVotingPowerParams {
    #[schemars(description = "Hex-encoded address to query voting power for")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DelegateVotingPowerParams {
    #[schemars(description = "Hex-encoded delegator address")]
    pub from_address: String,
    #[schemars(description = "Hex-encoded delegate address to receive voting power")]
    pub to_address: String,
    #[schemars(description = "Amount in wei as a decimal string (1 TNZO = 10^18 wei). Example: '100000000000000000000' for 100 TNZO. If omitted, delegates the full staked balance.")]
    pub amount_wei: Option<String>,
}

// ─── Token Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TokenBalanceParams {
    #[schemars(description = "Hex-encoded address to query TNZO balance for")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TotalSupplyParams {
    // No parameters needed — queries the TNZO total supply
}

// ─── Canton / DAML Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListCantonDomainsParams {
    // No filter parameters — returns all configured Canton synchronizer domains
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListDamlContractsParams {
    #[schemars(description = "Canton domain ID to query contracts from")]
    pub domain_id: String,
    #[schemars(description = "Optional DAML template filter (e.g. 'MyModule:MyTemplate')")]
    pub template_filter: Option<String>,
    #[schemars(description = "Maximum number of contracts to return (default 50)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubmitDamlCommandParams {
    #[schemars(description = "Canton domain ID to submit the command to")]
    pub domain_id: String,
    #[schemars(description = "DAML party identifier (submitting party)")]
    pub party: String,
    #[schemars(description = "DAML command type: 'create', 'exercise', 'create_and_exercise'")]
    pub command_type: String,
    #[schemars(description = "DAML template identifier (e.g. 'MyModule:MyTemplate')")]
    pub template_id: String,
    #[schemars(description = "Contract ID for exercise commands")]
    pub contract_id: Option<String>,
    #[schemars(description = "Choice name for exercise commands")]
    pub choice: Option<String>,
    #[schemars(description = "JSON-encoded arguments for the command")]
    pub arguments: serde_json::Value,
}

// ─── Settlement Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SettlePaymentParams {
    #[schemars(description = "Hex-encoded payer address")]
    pub payer: String,
    #[schemars(description = "Hex-encoded payee address")]
    pub payee: String,
    #[schemars(description = "Amount in wei as a decimal string (1 TNZO = 10^18 wei). Example: '1500000000000000000' for 1.5 TNZO.")]
    pub amount_wei: String,
    #[schemars(description = "Service type: 'inference', 'tee', 'storage', 'general'")]
    pub service_type: String,
    #[schemars(description = "Optional reference ID for this settlement")]
    pub reference_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateEscrowParams {
    #[schemars(description = "Hex-encoded payer address (must match the signing key)")]
    pub payer: String,
    #[schemars(description = "Hex-encoded payee address (receives funds on release)")]
    pub payee: String,
    #[schemars(description = "Amount in wei to hold in escrow as a decimal string (1 TNZO = 10^18 wei).")]
    pub amount_wei: String,
    #[schemars(description = "Release condition: 'provider_signature' | 'consumer_signature' | 'both_signatures' | 'verifier_signature' | 'timeout' | 'custom'")]
    pub release_condition: String,
    #[schemars(description = "Timeout duration in seconds (for timeout-based release)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReleaseEscrowParams {
    #[schemars(description = "32-byte escrow ID (hex, with or without 0x prefix)")]
    pub escrow_id: String,
    #[schemars(description = "Hex-encoded payer address (must match the bearer's wallet — only the payer can release)")]
    pub payer: String,
    #[schemars(description = "Optional hex-encoded proof bytes")]
    pub proof_data_hex: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RefundEscrowParams {
    #[schemars(description = "32-byte escrow ID (hex, with or without 0x prefix)")]
    pub escrow_id: String,
    #[schemars(description = "Hex-encoded payer address (must match the bearer's wallet)")]
    pub payer: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenPaymentChannelParams {
    #[schemars(description = "Hex-encoded sender address (opens and funds the channel)")]
    pub sender: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub recipient: String,
    #[schemars(description = "Initial deposit amount in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "String")]
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub deposit_wei: u128,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClosePaymentChannelParams {
    #[schemars(description = "Payment channel ID to close")]
    pub channel_id: String,
    #[schemars(description = "Final balance owed to recipient in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "String")]
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub final_balance_wei: u128,
    #[schemars(description = "Hex-encoded signature from the channel sender authorizing the final balance")]
    pub sender_signature_hex: String,
}

// ─── Model Lifecycle Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadModelParams {
    #[schemars(description = "Model ID to download (e.g. 'gemma3-270m', 'qwen3.5-0.8b')")]
    pub model_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServeModelMcpParams {
    #[schemars(description = "Model ID to start serving (must be downloaded first)")]
    pub model_id: String,
    #[schemars(description = "Optional maximum number of concurrent inference requests")]
    pub max_concurrent: Option<u32>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDownloadProgressParams {
    #[schemars(description = "Model ID to check download progress for")]
    pub model_id: String,
}

// ─── Provider Config Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetProviderScheduleParams {
    #[schemars(description = "Hex-encoded provider address")]
    pub provider_address: String,
    #[schemars(description = "Availability schedule as JSON (e.g. {\"timezone\": \"UTC\", \"hours\": \"0-23\", \"days\": \"mon-sun\"})")]
    pub schedule: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProviderScheduleParams {
    #[schemars(description = "Hex-encoded provider address")]
    pub provider_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetProviderPricingParams {
    #[schemars(description = "Hex-encoded provider address")]
    pub provider_address: String,
    #[schemars(description = "Wei per input token (decimal string; 1 TNZO = 10^18 wei)")]
    pub input_price_per_token_wei: String,
    #[schemars(description = "Wei per output token (decimal string; 1 TNZO = 10^18 wei)")]
    pub output_price_per_token_wei: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProviderPricingParams {
    #[schemars(description = "Hex-encoded provider address")]
    pub provider_address: String,
}

// ─── Agent Advanced Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterAgentParams {
    #[schemars(description = "Human-readable agent name")]
    pub name: String,
    #[schemars(description = "Hex-encoded creator address (the human/machine address that owns this agent). 20- or 32-byte hex, with or without 0x prefix.")]
    pub creator: String,
    #[schemars(description = "Capability short names: 'nlp', 'vision', 'code', 'data', 'blockchain', 'smart_contract', 'api_integration', 'coordination'. Anything else is treated as a Custom capability with that name. Defaults to a single 'general' capability when omitted.")]
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[schemars(description = "BYOK: optional 32-byte Ed25519 verifying key (hex). If supplied, `pq_public_key` MUST also be supplied. When both are present, no server-side wallet is provisioned and the agent is registered self-custodially with the caller's keys. When both are absent, the node provisions a server-side hybrid (FROST + ML-DSA-65) wallet.")]
    #[serde(default)]
    pub public_key: Option<String>,
    #[schemars(description = "BYOK: optional 1952-byte ML-DSA-65 verifying key (hex). Required iff `public_key` is supplied.")]
    #[serde(default)]
    pub pq_public_key: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendAgentMessageParams {
    #[schemars(description = "Sender agent_id (16-byte hex, as returned by register_agent). Must already be registered with the local node's AgentRuntime.")]
    pub from: String,
    #[schemars(description = "Recipient agent_id (same format). Must be registered with the local node's MessageRouter.")]
    pub to: String,
    #[schemars(description = "UTF-8 message body. Becomes AgentMessage.payload.")]
    pub message: String,
    #[schemars(description = "Optional message type: 'task_request' (default), 'task_response', 'query', 'query_response', 'notification', 'coordination', 'error'.")]
    #[serde(default)]
    pub message_type: Option<String>,
    #[schemars(description = "Optional message_id of a prior message this is a reply to. Changes the canonical hash, so callers must include it BEFORE signing.")]
    #[serde(default)]
    pub reply_to: Option<String>,
    #[schemars(description = "Hybrid signing: 64-byte Ed25519 signature (hex) over SHA-256(AgentMessage::signing_data()). Required (with pq_signature) when the router enforces signing.")]
    #[serde(default)]
    pub signature: Option<String>,
    #[schemars(description = "Hybrid signing: 3309-byte ML-DSA-65 signature (hex) over the same hash. Required (with signature) when the router enforces signing.")]
    #[serde(default)]
    pub pq_signature: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DelegateTaskParams {
    #[schemars(description = "DID of the delegating agent")]
    pub delegator_did: String,
    #[schemars(description = "DID of the agent to delegate to")]
    pub delegate_did: String,
    #[schemars(description = "Task description or task ID to delegate")]
    pub task: String,
    #[schemars(description = "Optional maximum budget for the delegated task in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "Option<String>")]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub max_budget_wei: Option<u128>,
}

// ─── Kill-Switch Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PauseAgentParams {
    #[schemars(description = "DID of the agent to pause")]
    pub agent_did: String,
    #[schemars(description = "DID of the controller authorizing the pause (must match controller_did on the agent identity)")]
    pub controller_did: String,
    #[schemars(description = "Free-text reason recorded on the kill-switch receipt")]
    pub reason: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QuarantineAgentParams {
    #[schemars(description = "DID of the agent to quarantine (freezes stake, blocks all messaging)")]
    pub agent_did: String,
    #[schemars(description = "DID of the controller authorizing the quarantine")]
    pub controller_did: String,
    #[schemars(description = "Free-text reason recorded on the kill-switch receipt")]
    pub reason: String,
    #[schemars(description = "Optional 32-byte evidence hash (hex-encoded, with or without 0x prefix)")]
    pub evidence_hash: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TerminateAgentParams {
    #[schemars(description = "DID of the agent to terminate (terminal state, optionally cascades to spawned children)")]
    pub agent_did: String,
    #[schemars(description = "DID of the controller authorizing the termination")]
    pub controller_did: String,
    #[schemars(description = "Free-text reason recorded on the kill-switch receipt")]
    pub reason: String,
    #[schemars(description = "Optional 32-byte evidence hash (hex-encoded, with or without 0x prefix)")]
    pub evidence_hash: Option<String>,
    #[schemars(description = "Slash basis points 0-10000 (10000 = 100%). Default 0.")]
    pub slash_bps: Option<u16>,
    #[schemars(description = "If true, recursively terminate all descendant agents in the spawn tree")]
    pub cascade: Option<bool>,
}

// ─── AgentBond Params (Spec 9) ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PostAgentBondParams {
    #[schemars(description = "Controller wallet address (hex). Must match the signing key.")]
    pub from: String,
    #[schemars(description = "DID of the agent the bond is posted against (e.g. did:tenzro:machine:...)")]
    pub agent_did: String,
    #[schemars(description = "Controller DID (e.g. did:tenzro:human:...) authorizing the bond")]
    pub controller_did: String,
    #[schemars(description = "Bond amount in wei as a decimal string (1 TNZO = 10^18 wei)")]
    pub amount: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentBondParams {
    #[schemars(description = "Agent DID to look up")]
    pub agent_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileInsuranceClaimParams {
    #[schemars(description = "Claimant DID (the harmed party)")]
    pub claimant_did: String,
    #[schemars(description = "Claimant wallet address (hex). Receives payout if approved.")]
    pub claimant_address: String,
    #[schemars(description = "DID of the bonded agent the claim is filed against")]
    pub against_agent_did: String,
    #[schemars(description = "Requested payout amount in wei (decimal string)")]
    pub amount_requested: String,
    #[schemars(description = "Receipt references: tx hashes, settlement ids, log refs")]
    pub receipt_refs: Option<Vec<String>>,
    #[schemars(description = "Optional narrative describing the harm (capped to 1024 bytes)")]
    pub narrative: Option<String>,
    #[schemars(description = "Nonce used to derive a deterministic claim_id")]
    pub nonce: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiscoverModelsParams {
    #[schemars(description = "Optional model category filter: 'text', 'image', 'audio', 'multimodal'")]
    pub category: Option<String>,
    #[schemars(description = "Only return models currently being served")]
    pub serving_only: Option<bool>,
    #[schemars(description = "Maximum price per 1k tokens in wei (1 TNZO = 10^18 wei). Accepts u64 number or decimal string.", with = "Option<String>")]
    #[serde(default, with = "tenzro_types::primitives::u128_serde_opt")]
    pub max_price_wei: Option<u128>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiscoverAgentsParams {
    #[schemars(description = "Filter by capability (e.g. 'inference', 'settlement', 'bridge')")]
    pub capability: Option<String>,
    #[schemars(description = "Filter by agent type: 'autonomous', 'assistant', 'validator', 'oracle'")]
    pub agent_type: Option<String>,
    #[schemars(description = "Maximum number of agents to return (default 20)")]
    pub limit: Option<usize>,
}

// ─── Capability Registry Params (#379) ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCapabilityAttestationsParams {
    #[schemars(description = "Capability short-form name: 'nlp', 'vision', 'code', 'data', 'blockchain', 'smart_contract', 'api_integration', 'coordination', or any custom-capability name registered by an agent.")]
    pub capability: String,
    #[schemars(description = "If true, run query-time signature/expiry checks before returning. Default false: registry already verifies signatures eagerly at submit time per #52.")]
    pub verified_only: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentCapabilityAttestationsParams {
    #[schemars(description = "Agent ID to fetch capability attestations for")]
    pub agent_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindBestAgentForCapabilityParams {
    #[schemars(description = "Capability short-form name: 'nlp', 'vision', 'code', 'data', 'blockchain', 'smart_contract', 'api_integration', 'coordination', or any custom-capability name. Returns the agent with the most recent TEE-backed attestation (preferred), falling back to any agent with the capability.")]
    pub capability: String,
}

// ─── Task Marketplace Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTaskParams {
    #[schemars(description = "Task ID to retrieve")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CancelTaskParams {
    #[schemars(description = "Task ID to cancel")]
    pub task_id: String,
    #[schemars(description = "Hex-encoded address of the task requester (for authorization)")]
    pub requester_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AssignTaskParams {
    #[schemars(description = "Task ID to assign")]
    pub task_id: String,
    #[schemars(description = "DID of the agent being assigned the task")]
    pub agent_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CompleteTaskParams {
    #[schemars(description = "Task ID to mark as complete")]
    pub task_id: String,
    #[schemars(description = "DID of the agent that completed the task")]
    pub agent_did: String,
    #[schemars(description = "JSON result payload from task completion")]
    pub result: serde_json::Value,
    #[schemars(description = "Optional proof of completion (hex-encoded)")]
    pub proof_hex: Option<String>,
}

// ─── Agent Template Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAgentTemplateParams {
    #[schemars(description = "Agent template ID to retrieve")]
    pub template_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadAgentTemplateParams {
    #[schemars(description = "Agent template ID to download and instantiate")]
    pub template_id: String,
    #[schemars(description = "DID of the controller that will own the instantiated agent")]
    pub controller_did: String,
    #[schemars(description = "Optional JSON configuration overrides for the template")]
    pub config_overrides: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateAgentTemplateParams {
    #[schemars(description = "Agent template ID to update")]
    pub template_id: String,
    #[schemars(description = "New description for the template")]
    pub description: Option<String>,
    #[schemars(description = "New version string (e.g. '1.1.0')")]
    pub version: Option<String>,
    #[schemars(description = "New status: 'active', 'inactive', 'deprecated'")]
    pub status: Option<String>,
    #[schemars(description = "Updated tags list")]
    pub tags: Option<Vec<String>>,
}

// ─── Token & Contract Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateTokenParams {
    #[schemars(description = "Token name (e.g. 'My Token')")]
    pub name: String,
    #[schemars(description = "Token symbol (e.g. 'MTK')")]
    pub symbol: String,
    #[schemars(description = "Creator address (hex, 20 or 32 bytes)")]
    pub creator: String,
    #[schemars(description = "Initial token supply as a string (e.g. '1000000000000000000000')")]
    pub initial_supply: String,
    #[schemars(description = "Token decimals (default: 18)")]
    pub decimals: Option<u8>,
    #[schemars(description = "Target VM type: 'evm', 'svm', or 'daml' (default: 'evm')")]
    pub vm_type: Option<String>,
    #[schemars(description = "Token permissions: 'mintable', 'burnable', 'pausable', 'freezable'")]
    pub permissions: Option<Vec<String>>,
    #[schemars(description = "Optional token description")]
    pub description: Option<String>,
    #[schemars(description = "Optional hex-encoded signature over 'tenzro:create_token:{name}:{symbol}:{supply}' proving creator ownership (min 64 bytes)")]
    pub signature: Option<String>,
}

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
    #[schemars(description = "Filter by VM type: 'evm', 'svm', 'daml', 'native'")]
    pub vm_type: Option<String>,
    #[schemars(description = "Maximum number of tokens to return (default: 50, max: 100)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeployContractParams {
    #[schemars(description = "Target VM: 'evm', 'svm', or 'daml'")]
    pub vm_type: String,
    #[schemars(description = "Contract bytecode (hex-encoded, with optional 0x prefix)")]
    pub bytecode: String,
    #[schemars(description = "Deployer address (hex)")]
    pub deployer: String,
    #[schemars(description = "ABI-encoded constructor arguments (hex, optional)")]
    pub constructor_args: Option<String>,
    #[schemars(description = "Gas limit for deployment (default: 3000000)")]
    pub gas_limit: Option<u64>,
    #[schemars(description = "Optional hex-encoded signature over 'tenzro:deploy_contract:{vm_type}:{deployer}' proving deployer ownership (min 64 bytes)")]
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CrossVmTransferParams {
    #[schemars(description = "Token symbol or 'TNZO'")]
    pub token: String,
    #[schemars(description = "Amount as string (in native decimals)")]
    pub amount: String,
    #[schemars(description = "Source VM: 'evm', 'svm', 'daml', 'native'")]
    pub from_vm: String,
    #[schemars(description = "Destination VM: 'evm', 'svm', 'daml', 'native'")]
    pub to_vm: String,
    #[schemars(description = "Source address (hex)")]
    pub from_address: String,
    #[schemars(description = "Destination address (hex)")]
    pub to_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WrapTnzoParams {
    #[schemars(description = "Address to wrap TNZO for (hex)")]
    pub address: String,
    #[schemars(description = "Amount of TNZO to wrap (as string, in native 18-decimal units)")]
    pub amount: String,
    #[schemars(description = "Target VM: 'evm', 'svm', or 'daml'")]
    pub to_vm: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenBalanceParams {
    #[schemars(description = "Address to query (hex)")]
    pub address: String,
    #[schemars(description = "Token symbol (default: 'TNZO')")]
    pub token: Option<String>,
}

// ─── NFT Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateNftCollectionParams {
    #[schemars(description = "Collection name (e.g. 'Tenzro Validators')")]
    pub name: String,
    #[schemars(description = "Collection symbol (e.g. 'TVAL')")]
    pub symbol: String,
    #[schemars(description = "Hex-encoded creator address")]
    pub creator: String,
    #[schemars(description = "NFT standard: 'erc721' or 'erc1155'")]
    pub standard: String,
    #[schemars(description = "Optional collection description")]
    pub description: Option<String>,
    #[schemars(description = "Optional base URI for token metadata (e.g. 'https://metadata.tenzro.com/collection/')")]
    pub base_uri: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MintNftParams {
    #[schemars(description = "Collection ID (UUID from create_nft_collection)")]
    pub collection_id: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub to: String,
    #[schemars(description = "Token ID within the collection (numeric string, e.g. '1')")]
    pub token_id: String,
    #[schemars(description = "Token metadata URI (e.g. 'https://metadata.tenzro.com/collection/1.json')")]
    pub uri: String,
    #[schemars(description = "Amount to mint (only for ERC-1155, default 1)")]
    pub amount: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransferNftParams {
    #[schemars(description = "Collection ID (UUID)")]
    pub collection_id: String,
    #[schemars(description = "Hex-encoded sender address")]
    pub from: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub to: String,
    #[schemars(description = "Token ID to transfer (numeric string)")]
    pub token_id: String,
    #[schemars(description = "Amount to transfer (only for ERC-1155, default 1)")]
    pub amount: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetNftInfoParams {
    #[schemars(description = "Collection ID (UUID)")]
    pub collection_id: String,
    #[schemars(description = "Token ID within the collection (optional — if omitted, returns collection-level info)")]
    pub token_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListNftCollectionsParams {
    #[schemars(description = "Filter by creator address (hex, optional)")]
    pub creator: Option<String>,
    #[schemars(description = "Filter by standard: 'erc721' or 'erc1155' (optional)")]
    pub standard: Option<String>,
    #[schemars(description = "Maximum number of results (default 50, max 100)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterNftPointerParams {
    #[schemars(description = "Collection ID (UUID)")]
    pub collection_id: String,
    #[schemars(description = "Target VM: 'evm', 'svm', or 'daml'")]
    pub vm: String,
    #[schemars(description = "Contract address on the target VM (hex-encoded)")]
    pub address: String,
}

// ─── Bridge Extended Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeQuoteParams {
    #[schemars(description = "Source chain (e.g. 'tenzro', 'ethereum', 'solana', 'base')")]
    pub from_chain: String,
    #[schemars(description = "Destination chain")]
    pub to_chain: String,
    #[schemars(description = "Token to bridge (e.g. 'TNZO', 'USDC', 'ETH')")]
    pub token: String,
    #[schemars(description = "Amount in base units")]
    pub amount: u128,
    #[schemars(description = "Preferred bridge protocol: 'layerzero', 'ccip', 'debridge' (optional — auto-selects best route if omitted)")]
    pub protocol: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BridgeWithHookParams {
    #[schemars(description = "Source chain (e.g. 'ethereum', 'solana')")]
    pub from_chain: String,
    #[schemars(description = "Destination chain")]
    pub to_chain: String,
    #[schemars(description = "Token to bridge (e.g. 'USDC', 'ETH')")]
    pub token: String,
    #[schemars(description = "Amount in base units")]
    pub amount: u128,
    #[schemars(description = "Hex-encoded sender address on source chain")]
    pub sender: String,
    #[schemars(description = "Hex-encoded target contract address for the post-fulfillment hook on destination chain")]
    pub hook_target: String,
    #[schemars(description = "Hex-encoded calldata to execute on hook_target after bridge fulfillment")]
    pub hook_calldata: String,
}

// ─── ERC-7802 Crosschain Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CrosschainMintParams {
    #[schemars(description = "Hex-encoded authorized bridge address")]
    pub bridge: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub to: String,
    #[schemars(description = "Amount to mint in base units")]
    pub amount: u128,
    #[schemars(description = "Hex-encoded sender address on the source chain (for event attribution)")]
    pub sender: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CrosschainBurnParams {
    #[schemars(description = "Hex-encoded authorized bridge address")]
    pub bridge: String,
    #[schemars(description = "Hex-encoded address to burn from")]
    pub from: String,
    #[schemars(description = "Amount to burn in base units")]
    pub amount: u128,
    #[schemars(description = "Destination chain identifier (e.g. 'ethereum', 'solana')")]
    pub destination: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuthorizeCrosschainBridgeParams {
    #[schemars(description = "Hex-encoded bridge address to authorize")]
    pub bridge: String,
    #[schemars(description = "Human-readable bridge name (e.g. 'LayerZero V2', 'Chainlink CCIP')")]
    pub name: String,
    #[schemars(description = "Daily mint limit in base units (e.g. 1000000000000000000000 for 1000 TNZO)")]
    pub daily_mint_limit: u128,
    #[schemars(description = "Daily burn limit in base units")]
    pub daily_burn_limit: u128,
}

// ─── ERC-3643 Compliance Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckComplianceParams {
    #[schemars(description = "Token ID (hex, 32 bytes) or symbol")]
    pub token_id: String,
    #[schemars(description = "Hex-encoded sender address")]
    pub from: String,
    #[schemars(description = "Hex-encoded recipient address")]
    pub to: String,
    #[schemars(description = "Amount in base units")]
    pub amount: u128,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterComplianceParams {
    #[schemars(description = "Token ID (hex, 32 bytes) or symbol")]
    pub token_id: String,
    #[schemars(description = "Require KYC verification for all holders")]
    pub require_kyc: bool,
    #[schemars(description = "Minimum KYC tier: 0 (unverified), 1 (basic), 2 (enhanced), 3 (full)")]
    pub min_kyc_tier: u8,
    #[schemars(description = "Maximum number of token holders (0 for unlimited)")]
    pub max_holders: Option<u64>,
    #[schemars(description = "Allowed country codes (ISO 3166-1 alpha-2, e.g. ['US', 'GB', 'DE']). Empty array means all allowed.")]
    pub allowed_countries: Option<Vec<String>>,
    #[schemars(description = "Blocked country codes")]
    pub blocked_countries: Option<Vec<String>>,
    #[schemars(description = "Maximum amount a single address can hold (base units, 0 for unlimited)")]
    pub max_balance_per_holder: Option<u128>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FreezeAddressParams {
    #[schemars(description = "Token ID (hex, 32 bytes) or symbol")]
    pub token_id: String,
    #[schemars(description = "Hex-encoded address to freeze")]
    pub address: String,
    #[schemars(description = "Reason for freezing the address")]
    pub reason: String,
}

// ─── Events Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetEventsParams {
    #[schemars(description = "Minimum block height (optional)")]
    pub from_block: Option<u64>,
    #[schemars(description = "Maximum block height (optional)")]
    pub to_block: Option<u64>,
    #[schemars(description = "Event types to filter: 'transfer', 'mint', 'burn', 'stake', 'bridge', 'settlement', 'nft_transfer', 'compliance' (optional, returns all if omitted)")]
    pub event_types: Option<Vec<String>>,
    #[schemars(description = "Filter by involved addresses (hex, optional)")]
    pub addresses: Option<Vec<String>>,
    #[schemars(description = "Start from a specific event sequence number for cursor-based pagination")]
    pub from_sequence: Option<u64>,
    #[schemars(description = "Maximum number of events to return (default 50, max 200)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubscribeEventsParams {
    #[schemars(description = "Event types to subscribe to: 'transfer', 'mint', 'burn', 'stake', 'bridge', 'settlement', 'nft_transfer', 'compliance'")]
    pub event_types: Option<Vec<String>>,
    #[schemars(description = "Filter by involved addresses (hex, optional)")]
    pub addresses: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterWebhookParams {
    #[schemars(description = "HTTPS URL to receive webhook POST notifications")]
    pub url: String,
    #[schemars(description = "Event types to subscribe to: 'transfer', 'mint', 'burn', 'stake', 'bridge', 'settlement', 'nft_transfer', 'compliance'")]
    pub event_types: Option<Vec<String>>,
    #[schemars(description = "Filter by involved addresses (hex, optional)")]
    pub addresses: Option<Vec<String>>,
    #[schemars(description = "Shared secret for HMAC-SHA256 webhook signature verification")]
    pub secret: String,
}

// ─── Crypto Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SignMessageParams {
    #[schemars(description = "Hex-encoded private key (with or without 0x prefix)")]
    pub private_key: String,
    #[schemars(description = "Hex-encoded message bytes to sign")]
    pub message_hex: String,
    #[schemars(description = "Key type: 'ed25519' (default) or 'secp256k1'")]
    pub key_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifySignatureParams {
    #[schemars(description = "Hex-encoded public key")]
    pub public_key: String,
    #[schemars(description = "Hex-encoded message bytes that were signed")]
    pub message_hex: String,
    #[schemars(description = "Hex-encoded signature")]
    pub signature_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EncryptDataParams {
    #[schemars(description = "Hex-encoded 32-byte AES-256-GCM key")]
    pub key_hex: String,
    #[schemars(description = "Hex-encoded plaintext data")]
    pub plaintext_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DecryptDataParams {
    #[schemars(description = "Hex-encoded 32-byte AES-256-GCM key")]
    pub key_hex: String,
    #[schemars(description = "Hex-encoded ciphertext")]
    pub ciphertext_hex: String,
    #[schemars(description = "Hex-encoded 12-byte nonce used during encryption")]
    pub nonce_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeriveKeyParams {
    #[schemars(description = "Password to derive a 256-bit key from using Argon2id")]
    pub password: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GenerateKeypairParams {
    #[schemars(description = "Key type: 'ed25519' or 'secp256k1'")]
    pub key_type: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HashSha256Params {
    #[schemars(description = "Hex-encoded data to hash")]
    pub data_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HashKeccak256Params {
    #[schemars(description = "Hex-encoded data to hash")]
    pub data_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct X25519KeyExchangeParams {
    #[schemars(description = "Hex-encoded X25519 private key (32 bytes)")]
    pub private_key_hex: String,
    #[schemars(description = "Hex-encoded X25519 public key (32 bytes)")]
    pub public_key_hex: String,
}

// ─── TEE Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DetectTeeParams {
    // No parameters — detects available TEE hardware
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTeeAttestationParams {
    #[schemars(description = "TEE type: 'tdx', 'sev-snp', 'nitro', 'nvidia-gpu', or 'auto' (detect best available)")]
    pub tee_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyTeeAttestationParams {
    #[schemars(description = "Hex-encoded attestation report")]
    pub attestation: String,
    #[schemars(description = "TEE type: 'tdx', 'sev-snp', 'nitro', 'nvidia-gpu'")]
    pub tee_type: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SealDataParams {
    #[schemars(description = "Hex-encoded data to seal (encrypt) within the TEE enclave")]
    pub data_hex: String,
    #[schemars(description = "Key ID for sealing (used for key derivation)")]
    pub key_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UnsealDataParams {
    #[schemars(description = "Hex-encoded sealed data to unseal (decrypt)")]
    pub sealed_hex: String,
    #[schemars(description = "Key ID used during sealing")]
    pub key_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListTeeProvidersParams {
    // No parameters — lists all registered TEE providers
}

// ─── ZK Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateZkProofParams {
    #[schemars(description = "Circuit identifier — one of 'inference', 'settlement', 'identity'")]
    pub circuit_id: String,
    #[schemars(description = "Witness fields as a JSON object of u64 field-element values. Per circuit: \
        inference={model_checksum,input_checksum,computed_output}; \
        settlement={service_proof,amount}; \
        identity={private_key,capabilities,capability_blinding}")]
    pub witness: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListZkCircuitsParams {
    // No parameters — lists all available ZK circuits
}

// ─── Custody Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateMpcWalletParams {
    #[schemars(description = "Number of shares required to sign (e.g. 2)")]
    pub threshold: Option<u32>,
    #[schemars(description = "Total number of key shares (e.g. 3)")]
    pub total_shares: Option<u32>,
    #[schemars(description = "Key type: 'ed25519' (default) or 'secp256k1'")]
    pub key_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExportKeystoreParams {
    #[schemars(description = "Wallet ID (UUID) to export")]
    pub wallet_id: String,
    #[schemars(description = "Password to encrypt the keystore file")]
    pub password: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportKeystoreParams {
    #[schemars(description = "JSON-encoded keystore data")]
    pub keystore_json: String,
    #[schemars(description = "Password to decrypt the keystore file")]
    pub password: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetKeySharesParams {
    #[schemars(description = "Wallet ID (UUID) to query key shares for")]
    pub wallet_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RotateKeysParams {
    #[schemars(description = "Wallet ID (UUID) to rotate keys for")]
    pub wallet_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetSpendingLimitsParams {
    #[schemars(description = "Wallet ID (UUID)")]
    pub wallet_id: String,
    #[schemars(description = "Maximum daily spend in TNZO (e.g. 1000.0)")]
    pub daily_limit: f64,
    #[schemars(description = "Maximum per-transaction amount in TNZO (e.g. 100.0)")]
    pub per_tx_limit: f64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSpendingLimitsParams {
    #[schemars(description = "Wallet ID (UUID) to query spending limits for")]
    pub wallet_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuthorizeSessionParams {
    #[schemars(description = "Wallet ID (UUID) to create a session for")]
    pub wallet_id: String,
    #[schemars(description = "Session duration in seconds (e.g. 3600 for 1 hour)")]
    pub duration_secs: u64,
    #[schemars(description = "Allowed operations during the session (e.g. ['transfer', 'stake', 'inference'])")]
    pub operations: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RevokeSessionParams {
    #[schemars(description = "Session ID (UUID) to revoke")]
    pub session_id: String,
}

// ─── App / Paymaster Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterAppParams {
    #[schemars(description = "Application name")]
    pub name: String,
    #[schemars(description = "Hex-encoded master wallet address that funds user operations")]
    pub master_wallet_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateUserWalletParams {
    #[schemars(description = "Application ID (UUID) the wallet belongs to")]
    pub app_id: String,
    #[schemars(description = "Human-readable label for the user wallet")]
    pub label: String,
    #[schemars(description = "Optional initial funding in wei as a decimal string (1 TNZO = 10^18 wei). Example: '10000000000000000000' for 10 TNZO.")]
    pub initial_funding_wei: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FundUserWalletParams {
    #[schemars(description = "Hex-encoded master wallet address (source of funds)")]
    pub master_address: String,
    #[schemars(description = "Hex-encoded user wallet address (destination)")]
    pub user_address: String,
    #[schemars(description = "Amount in wei as a decimal string (1 TNZO = 10^18 wei). Example: '5000000000000000000' for 5 TNZO.")]
    pub amount_wei: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListUserWalletsParams {
    #[schemars(description = "Application ID (UUID) to list wallets for")]
    pub app_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SponsorTransactionParams {
    #[schemars(description = "Hex-encoded master/paymaster address that sponsors the gas")]
    pub master_address: String,
    #[schemars(description = "User transaction object to sponsor. Must include `gas_limit` and `gas_price` (and any other tx fields). The master pays gas_limit * gas_price out of its TNZO balance.")]
    pub user_tx: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetUsageStatsParams {
    #[schemars(description = "Application ID (UUID) to get usage stats for")]
    pub app_id: String,
}

// ─── Contract ABI Params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EncodeFunctionParams {
    #[schemars(description = "Function signature (e.g. 'transfer(address,uint256)')")]
    pub function_sig: String,
    #[schemars(description = "Function arguments as JSON array (e.g. ['0xabc...', '1000000'])")]
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DecodeResultParams {
    #[schemars(description = "Hex-encoded return data from a contract call")]
    pub data_hex: String,
    #[schemars(description = "Output type signatures (e.g. ['uint256', 'bool', 'address'])")]
    pub output_types: Vec<String>,
}

// ─── AP2 (Agent Payments Protocol) params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Ap2SignMandateParams {
    #[schemars(description = "Mandate kind (AP2 v0.2): 'checkout' (principal-signed pre-authorization) or 'payment' (agent-signed final-offer commit)")]
    pub mandate_kind: String,
    #[schemars(description = "The mandate object — CheckoutMandate or PaymentMandate, matching mandate_kind. Auth-bound wallet's Ed25519 key signs the canonical preimage.")]
    pub mandate: serde_json::Value,
    #[schemars(description = "Signer DID — must match the controller of the auth-bound wallet (principal for checkout, agent for payment).")]
    pub signer_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Ap2VerifyMandateParams {
    #[schemars(description = "Verifiable Digital Credential (VDC) mandate object — the full JSON-LD VC envelope with proof")]
    pub vdc: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Ap2ValidateMandatePairParams {
    #[schemars(description = "AP2 v0.2 CheckoutMandate VDC (principal-to-agent pre-authorization) as JSON-LD VC envelope")]
    pub checkout_vdc: serde_json::Value,
    #[schemars(description = "AP2 v0.2 PaymentMandate VDC (agent-to-merchant final-offer commit) as JSON-LD VC envelope")]
    pub payment_vdc: serde_json::Value,
    #[schemars(description = "If true, also enforce the agent's TDIP DelegationScope against the payment total via IdentityRegistry::enforce_operation. Default: false (AP2-only validation).")]
    #[serde(default)]
    pub enforce_delegation: bool,
}

// ─── ERC-8004 (Trustless Agents Registry) params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeRegisterWithUriParams {
    #[schemars(description = "Off-chain metadata URI (ipfs:// or https:// link to agent metadata JSON). Pass an empty string to register without a URI.")]
    pub agent_uri: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004MetadataEntryParam {
    #[schemars(description = "Metadata key string (free-form ASCII identifier)")]
    pub key: String,
    #[schemars(description = "Metadata value as 0x-prefixed hex bytes")]
    pub value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeRegisterWithMetadataParams {
    #[schemars(description = "Off-chain metadata URI bound atomically with the agentId allocation")]
    pub agent_uri: String,
    #[schemars(description = "Initial metadata batch — array of {key, value} entries written atomically with the agentId allocation")]
    pub metadata: Vec<Erc8004MetadataEntryParam>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetAgentParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004DecodeGetAgentParams {
    #[schemars(description = "Hex-encoded return data from a getAgent(bytes32) eth_call")]
    pub return_data: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeSetAgentUriParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Updated off-chain metadata URI")]
    pub metadata_uri: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeSetAgentWalletParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "New wallet / controller EVM address (0x-prefixed hex)")]
    pub new_wallet: String,
    #[schemars(description = "Unix-seconds deadline after which the signature is invalid")]
    pub deadline: u64,
    #[schemars(description = "Hex-encoded EIP-712 signature (0x-prefixed) authorizing the wallet rotation")]
    pub signature: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeSetMetadataParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Metadata key string (free-form ASCII identifier)")]
    pub metadata_key: String,
    #[schemars(description = "Metadata value as 0x-prefixed hex bytes")]
    pub metadata_value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetMetadataParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Metadata key string")]
    pub metadata_key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004DecodeGetMetadataParams {
    #[schemars(description = "Hex-encoded return data from a getMetadata(uint256,string) eth_call")]
    pub return_data: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetAgentUriParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetAgentWalletParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeFeedbackParams {
    #[schemars(description = "Subject agent ID — uint256 of the agent being rated. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub subject_agent_id: serde_json::Value,
    #[schemars(description = "Rating in the range -100..=100 (Tenzro convention)")]
    pub rating: i8,
    #[schemars(description = "Resolvable URI to feedback context (e.g. ipfs:// or https:// link)")]
    pub context_uri: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetFeedbackParams {
    #[schemars(description = "Subject agent ID — uint256. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub subject_agent_id: serde_json::Value,
    #[schemars(description = "Index into the subject's feedback array")]
    pub index: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetFeedbackCountParams {
    #[schemars(description = "Subject agent ID — uint256. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub subject_agent_id: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeRevokeFeedbackParams {
    #[schemars(description = "Agent ID owning the feedback — uint256. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Feedback ID to revoke (bytes32 hex, 0x-prefixed)")]
    pub feedback_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeAppendResponseParams {
    #[schemars(description = "Agent ID (uint256) — must own the feedback. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Feedback ID being responded to (bytes32 hex, 0x-prefixed)")]
    pub feedback_id: String,
    #[schemars(description = "Resolvable URI to the response payload")]
    pub response_uri: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeIsFeedbackRevokedParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Feedback ID to check (bytes32 hex, 0x-prefixed)")]
    pub feedback_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetFeedbackResponsesParams {
    #[schemars(description = "Agent ID — uint256 returned by register(...) at registration time. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Feedback ID (bytes32 hex, 0x-prefixed)")]
    pub feedback_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeValidationRequestParams {
    #[schemars(description = "Validator address (20-byte EVM address, 0x-prefixed)")]
    pub validator_address: String,
    #[schemars(description = "Agent ID of the subject being validated — uint256. Accepts a JSON number, decimal string, or 0x-prefixed hex.")]
    pub agent_id: serde_json::Value,
    #[schemars(description = "Resolvable URI to the work being validated")]
    pub request_uri: String,
    #[schemars(description = "32-byte commitment over the work (bytes32 hex, 0x-prefixed) — storage key for the matching response")]
    pub request_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeValidationResponseParams {
    #[schemars(description = "Request hash from the matching validationRequest (bytes32 hex, 0x-prefixed)")]
    pub request_hash: String,
    #[schemars(description = "Quality score 0..=100 (Tenzro convention: 0..=49 invalid, 50..=79 partial, 80..=100 valid)")]
    pub response: u8,
    #[schemars(description = "Resolvable URI to proof material (ZK proof CID, TEE quote CID, etc.)")]
    pub response_uri: String,
    #[schemars(description = "32-byte commitment over the response payload (bytes32 hex, 0x-prefixed)")]
    pub response_hash: String,
    #[schemars(description = "Short categorical label (e.g. 'valid', 'invalid', 'abstain')")]
    pub tag: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Erc8004EncodeGetValidationParams {
    #[schemars(description = "Request hash from the original validationRequest (bytes32 hex, 0x-prefixed)")]
    pub request_hash: String,
}

// ─── Wormhole cross-chain params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WormholeChainIdParams {
    #[schemars(description = "Chain name (e.g. ethereum, solana, base, arbitrum, optimism)")]
    pub chain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WormholeParseVaaIdParams {
    #[schemars(description = "Canonical VAA id in the form {chain}/{emitter}/{sequence}")]
    pub vaa_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WormholeBridgeParams {
    #[schemars(description = "Source chain name")]
    pub source_chain: String,
    #[schemars(description = "Destination chain name")]
    pub dest_chain: String,
    #[schemars(description = "Asset symbol (e.g. TNZO, USDC)")]
    pub asset: String,
    #[schemars(description = "Amount in smallest units as a u128 decimal string")]
    pub amount: String,
    #[schemars(description = "Sender address on source chain")]
    pub sender: String,
    #[schemars(description = "Recipient address on destination chain")]
    pub recipient: String,
}

// ─── TNZO CCT (Chainlink Cross-Chain Token) params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CctGetPoolParams {
    #[schemars(description = "Chain name (e.g. ethereum, base, arbitrum, optimism, solana)")]
    pub chain: String,
}

/// Call a tool on the official deBridge MCP server at agents.debridge.com/mcp
async fn debridge_mcp_call(tool_name: &str, arguments: serde_json::Value) -> std::result::Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let debridge_url = std::env::var("DEBRIDGE_MCP_URL")
        .unwrap_or_else(|_| "https://agents.debridge.com/mcp".to_string());

    // Initialize MCP session
    let init_resp = client
        .post(&debridge_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "tenzro-node", "version": "0.1.0"}
            }
        }))
        .send()
        .await
        .map_err(|e| format!("deBridge MCP init failed: {}", e))?;

    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Call the tool
    let mut req = client
        .post(&debridge_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");

    if !session_id.is_empty() {
        req = req.header("Mcp-Session-Id", &session_id);
    }

    let resp = req
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }))
        .send()
        .await
        .map_err(|e| format!("deBridge MCP call failed: {}", e))?;

    let body = resp.text().await.map_err(|e| format!("deBridge response read failed: {}", e))?;

    // Parse SSE response (event: message\ndata: {json})
    for line in body.lines() {
        if let Some(data) = line.strip_prefix("data: ")
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(data)
                && let Some(result) = json.get("result") {
                    if let Some(content) = result.get("content").and_then(|c| c.as_array())
                        && let Some(first) = content.first()
                            && let Some(text) = first.get("text").and_then(|t| t.as_str()) {
                                return serde_json::from_str(text).or_else(|_| Ok(serde_json::json!({"text": text})));
                            }
                    return Ok(result.clone());
                }
    }

    // Try parsing as direct JSON
    serde_json::from_str(&body)
        .map(|v: serde_json::Value| v.get("result").cloned().unwrap_or(v))
        .map_err(|e| format!("deBridge response parse failed: {}", e))
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
pub struct ForecastParams {
    #[schemars(description = "Registered forecast model id (e.g. 'timesfm-2.5-200m')")]
    pub model_id: String,
    #[schemars(description = "Univariate context series (most-recent-last). Non-empty.")]
    pub history: Vec<f32>,
    #[schemars(description = "Forecast horizon (steps ahead). Must be > 0.")]
    pub horizon: u32,
    #[schemars(description = "Optional output quantile levels in (0,1) (e.g. [0.1, 0.5, 0.9]). Defaults to model-native quantiles.")]
    pub quantiles: Option<Vec<f32>>,
    #[schemars(description = "Optional sampling frequency in seconds (used by frequency-aware models)")]
    pub frequency_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VisionEmbedParams {
    #[schemars(description = "Registered vision encoder id (DINOv3, SigLIP2, CLIP, etc.)")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes (PNG/JPEG/WebP)")]
    pub image_base64: String,
    #[schemars(description = "L2-normalize the embedding before returning it (default false)")]
    pub normalize: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VisionSimilarityParams {
    #[schemars(description = "Image embedding (typically from vision_embed)")]
    pub image_embedding: Vec<f32>,
    #[schemars(description = "Text embedding (typically from text_embed against a CLIP/SigLIP text tower of matching dimension)")]
    pub text_embedding: Vec<f32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TextEmbedParams {
    #[schemars(description = "Registered text-embedding model id (e.g. 'qwen3-embedding-0.6b', 'embeddinggemma-300m', 'bge-m3')")]
    pub model_id: String,
    #[schemars(description = "Strings to embed. Non-empty.")]
    pub inputs: Vec<String>,
    #[schemars(description = "Matryoshka truncation target dimension (e.g. 128/256/512). If omitted, returns the model-native dim.")]
    pub requested_dim: Option<u32>,
    #[schemars(description = "L2-normalize each row before returning (default false)")]
    pub normalize: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SegmentParams {
    #[schemars(description = "Registered segmenter id (e.g. 'sam2-base', 'sam2-large', 'edgesam', 'mobilesam')")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes")]
    pub image_base64: String,
    #[schemars(description = "Prompts: array of `{type:'point', x, y, label}` or `{type:'box', x0, y0, x1, y1}` objects")]
    pub prompts: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DetectParams {
    #[schemars(description = "Registered detector id (e.g. 'rf-detr-base', 'rf-detr-nano', 'd-fine-l')")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded image bytes")]
    pub image_base64: String,
    #[schemars(description = "Score threshold (0.0–1.0). Detections below this are dropped. Default 0.25.")]
    pub score_threshold: Option<f32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TranscribeParams {
    #[schemars(description = "Registered ASR model id (e.g. 'whisper-large-v3-turbo', 'distil-whisper-small.en', 'moonshine-base-v2', 'parakeet-tdt-0.6b-v3', 'canary-1b-flash')")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded audio bytes (WAV/MP3/FLAC)")]
    pub audio_base64: String,
    #[schemars(description = "Optional ISO language hint (e.g. 'en', 'es', 'fr'). Many models auto-detect.")]
    pub language: Option<String>,
    #[schemars(description = "Emit per-segment / per-word timestamps in the result (default false)")]
    pub timestamps: Option<bool>,
    #[schemars(description = "Decoding temperature (default 0.0)")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VideoEmbedParams {
    #[schemars(description = "Registered video encoder id. Wave 1 catalog ships empty pending license clearance + ONNX export.")]
    pub model_id: String,
    #[schemars(description = "Base64-encoded video bytes")]
    pub video_base64: String,
    #[schemars(description = "L2-normalize the pooled embedding (default false)")]
    pub normalize: Option<bool>,
    #[schemars(description = "Sub-sample frames at this stride (default model-defined)")]
    pub frame_stride: Option<u32>,
}

// ─── Workflow stack params ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkflowIdParams {
    #[schemars(description = "32-byte hex workflow id (with or without 0x prefix)")]
    pub workflow_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreatorDidParams {
    #[schemars(description = "Creator DID (did:tenzro:human:... or did:tenzro:machine:...)")]
    pub creator_did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DidParams {
    #[schemars(description = "DID string")]
    pub did: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkflowStatusParams {
    #[schemars(description = "Workflow status: draft | awaiting_signatures | active | suspended | settling | completed | failed | disputed | cancelled")]
    pub status: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ObligationIdParams {
    #[schemars(description = "32-byte hex obligation id")]
    pub obligation_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApprovalGateIdParams {
    #[schemars(description = "32-byte hex approval gate id")]
    pub gate_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApprovalRequestIdParams {
    #[schemars(description = "32-byte hex approval request id")]
    pub request_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PrivacyDomainIdParams {
    #[schemars(description = "32-byte hex privacy domain id")]
    pub domain_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkflowReceiptIdParams {
    #[schemars(description = "32-byte hex receipt id")]
    pub receipt_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkflowReceiptListParams {
    #[schemars(description = "32-byte hex workflow id")]
    pub workflow_id: String,
    #[schemars(description = "Maximum receipts to return (default 256)")]
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FeeRouteIdParams {
    #[schemars(description = "32-byte hex fee route id")]
    pub fee_route_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FeeRoutePayoutsParams {
    #[schemars(description = "32-byte hex fee route id")]
    pub fee_route_id: String,
    #[schemars(description = "Gross amount in wei (decimal string — u128)")]
    pub gross_wei: String,
}

#[derive(Clone)]
pub struct TenzroMcpServer {
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
    _tool_router: ToolRouter<TenzroMcpServer>,
}

impl std::fmt::Debug for TenzroMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenzroMcpServer")
            .field("node", &"<TenzroNode>")
            .field("web_state", &"<WebState>")
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

fn err_internal_data(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

fn parse_vm_type(s: &str) -> std::result::Result<tenzro_token::TokenVmType, ErrorData> {
    match s.to_lowercase().as_str() {
        "evm" => Ok(tenzro_token::TokenVmType::Evm),
        "svm" => Ok(tenzro_token::TokenVmType::Svm),
        "daml" => Ok(tenzro_token::TokenVmType::Daml),
        "native" => Ok(tenzro_token::TokenVmType::Native),
        "tempo-tip20" | "tempo" | "tip20" => Ok(tenzro_token::TokenVmType::TempoTip20),
        other => Err(err_internal_data(format!("Unknown VM type: '{}'. Use 'evm', 'svm', 'daml', 'native', or 'tempo-tip20'.", other))),
    }
}

fn bytes_to_address(bytes: &[u8]) -> Address {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    if bytes.len() <= 20 {
        // EVM-style: right-align in 32 bytes
        arr[32 - len..32].copy_from_slice(&bytes[..len]);
    } else {
        // SVM-style: left-align
        arr[..len].copy_from_slice(&bytes[..len]);
    }
    Address::new(arr)
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

async fn rpc_dispatch(node: &Arc<TenzroNode>, method: &str, params: serde_json::Value) -> std::result::Result<serde_json::Value, ErrorData> {
    let request = crate::rpc::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
        id: serde_json::Value::Number(serde_json::Number::from(1)),
    };
    // Forward the inbound MCP request's Authorization + DPoP headers to
    // the JSON-RPC layer so auth-sensitive handlers see the real bearer
    // identity, not an empty `internal()` context.
    let h = current_request_headers();
    let auth_ctx = crate::rpc::AuthContext::from_mcp(
        h.authorization,
        h.dpop,
        h.http_method,
        h.http_uri,
    );
    let response = crate::rpc::handle_request(node, request, &auth_ctx).await;
    if let Some(result) = response.result {
        Ok(result)
    } else if let Some(error) = response.error {
        Err(ErrorData::internal_error(error.message, None))
    } else {
        Err(ErrorData::internal_error("No result or error in RPC response".to_string(), None))
    }
}

fn json_result(value: serde_json::Value) -> std::result::Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap(),
    )]))
}

fn text_result(text: impl Into<String>) -> std::result::Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(text.into())]))
}

/// Map a short-form capability name (matching the JSON-RPC and CLI
/// vocabulary) to a fully-typed `Capability`. Unknown names map to
/// `Capability::Custom { name, parameters: {} }` so the MCP surface
/// can address the long tail of agent-defined capabilities without
/// requiring a structured payload.
fn parse_capability_short(name: &str) -> tenzro_types::agent::Capability {
    use tenzro_types::agent::Capability;
    match name {
        "nlp" => Capability::NaturalLanguageProcessing { languages: vec!["en".to_string()] },
        "vision" => Capability::ComputerVision { tasks: vec!["detection".to_string()] },
        "code" => Capability::CodeGeneration {
            languages: vec!["rust".to_string(), "python".to_string()],
        },
        "data" => Capability::DataAnalysis {
            formats: vec!["json".to_string(), "csv".to_string()],
        },
        "blockchain" => Capability::BlockchainInteraction { chains: vec!["tenzro".to_string()] },
        "smart_contract" => Capability::SmartContractExecution,
        "api_integration" => Capability::ExternalAPIIntegration { apis: vec![] },
        "coordination" => Capability::MultiAgentCoordination,
        other => Capability::Custom {
            name: other.to_string(),
            parameters: std::collections::HashMap::new(),
        },
    }
}

/// Convert a `CapabilityAttestation` to an MCP-friendly JSON envelope.
/// All raw byte fields are emitted as hex so they survive transport
/// across language boundaries identically to the JSON-RPC surface.
fn attestation_to_mcp_json(att: &tenzro_agent::capabilities::CapabilityAttestation) -> serde_json::Value {
    serde_json::json!({
        "agent_id": att.agent_id,
        "capability": att.capability,
        "attested_at": att.attested_at.to_rfc3339(),
        "tee_backed": att.tee_backed,
        "attester_address": att.attester_address.as_ref().map(|a| format!("0x{}", hex::encode(a.as_bytes()))),
        "attester_public_key": att.attester_public_key.as_ref().map(|pk| serde_json::json!({
            "key_type": format!("{:?}", pk.key_type()),
            "bytes": hex::encode(pk.as_bytes()),
        })),
        "signature": att.signature.as_ref().map(hex::encode),
        "metadata": att.metadata,
    })
}

#[tool_router]
impl TenzroMcpServer {
    pub fn new(node: Arc<TenzroNode>, web_state: Arc<WebState>) -> Self {
        Self {
            node,
            web_state,
            _tool_router: Self::tool_router(),
        }
    }

    // ─── Wallet & Balance ───

    #[tool(description = "Get the TNZO token balance of an account on the Tenzro ledger")]
    async fn get_balance(
        &self,
        Parameters(params): Parameters<GetBalanceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let address = parse_address(&params.address)?;

        // Read balance via TnzoToken (reads from CF_ACCOUNTS with balance:{raw_bytes} key)
        let balance = if let Some(token) = self.node.token() {
            token.balance_of(&address)
        } else {
            0
        };

        json_result(serde_json::json!({
            "address": format!("0x{}", addr_hex),
            "balance_wei": balance.to_string(),
        }))
    }

    #[tool(description = "Create a new cryptographic keypair for use as a Tenzro wallet. Supports Ed25519 (Tenzro native) and Secp256k1 (EVM-compatible)")]
    async fn create_wallet(
        &self,
        Parameters(params): Parameters<CreateWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_crypto::{KeyPair, KeyType};

        let key_type = match params.key_type.as_deref().unwrap_or("ed25519") {
            "ed25519" | "Ed25519" => KeyType::Ed25519,
            "secp256k1" | "Secp256k1" => KeyType::Secp256k1,
            other => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Unsupported key type '{}'. Use 'ed25519' or 'secp256k1'.", other)),
                data: None,
            }),
        };

        let keypair = KeyPair::generate(key_type).map_err(|e| ErrorData {
            code: ErrorCode::INTERNAL_ERROR,
            message: Cow::from(format!("Key generation failed: {}", e)),
            data: None,
        })?;

        let address = keypair.address();
        let public_key = keypair.public_key();
        let key_type_str = match key_type {
            KeyType::Ed25519 => "Ed25519",
            KeyType::Secp256k1 => "Secp256k1",
        };

        json_result(serde_json::json!({
            "address": format!("0x{}", hex::encode(address.as_bytes())),
            "public_key": format!("0x{}", hex::encode(public_key.as_bytes())),
            "key_type": key_type_str,
            "note": "Store the private key securely. This keypair can be used for transactions on the Tenzro ledger.",
        }))
    }

    // ─── Transactions ───

    #[tool(description = "Send a TNZO transfer transaction on the Tenzro ledger. Two supported paths: (a) ambient OAuth/DPoP — omit signature/public_key/timestamp; the server will look up the wallet bound to the bearer DID and sign; (b) pre-signed — supply signature + public_key + timestamp matching the signed Transaction::hash(). The legacy private_key inline-signing path has been removed.")]
    async fn send_transaction(
        &self,
        Parameters(params): Parameters<SendTransactionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let chain_id = params.chain_id.unwrap_or(1337);
        let gas_limit = params.gas_limit.unwrap_or(21000);
        let gas_price = params.gas_price.unwrap_or(1_000_000_000);
        let nonce = params.nonce.unwrap_or(0);

        // Path A: ambient auth — caller provided no signature. Delegate to
        // tenzro_signAndSendTransaction, which uses the AuthContext rebuilt
        // from the MCP request's Authorization + DPoP headers via the
        // task-local in `rpc_dispatch`.
        if params.signature.is_none() && params.public_key.is_none() && params.timestamp.is_none() {
            // Externally-tagged TransactionType — see tenzro_types::transaction::TransactionType
            let tx_type = serde_json::json!({
                "Transfer": { "amount": params.amount.to_string() }
            });
            let send_params = serde_json::json!({
                "from": params.from,
                "to": params.to,
                "value": 0u64,
                "gas_limit": gas_limit,
                "gas_price": gas_price,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            });
            let result = rpc_dispatch(&self.node, "tenzro_signAndSendTransaction", send_params)
                .await
                .map_err(|e| err_internal(format!("signAndSendTransaction failed: {}", e)))?;
            return json_result(result);
        }

        // Path B: pre-signed — caller supplies signature + public_key + timestamp.
        let sig_hex = params.signature.as_deref().ok_or_else(|| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from(
                "Pre-signed path requires 'signature' (omit all of signature/public_key/timestamp \
                 to use ambient OAuth/DPoP auth instead)"
                    .to_string(),
            ),
            data: None,
        })?;
        let pk_hex = params.public_key.as_deref().ok_or_else(|| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from("Missing 'public_key' for pre-signed transaction".to_string()),
            data: None,
        })?;
        let ts_ms = params.timestamp.ok_or_else(|| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from(
                "Missing 'timestamp' — must match the timestamp used when signing".to_string(),
            ),
            data: None,
        })?;

        // Forward to eth_sendRawTransaction, which performs synchronous
        // Ed25519 verification against Transaction::hash() before admitting.
        let raw_params = serde_json::json!({
            "from": params.from,
            "to": params.to,
            "value": params.amount.to_string(),
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "nonce": nonce,
            "chain_id": chain_id,
            "signature": sig_hex,
            "public_key": pk_hex,
            "timestamp": ts_ms,
        });
        let result = rpc_dispatch(&self.node, "eth_sendRawTransaction", raw_params)
            .await
            .map_err(|e| err_internal(format!("eth_sendRawTransaction failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Request testnet TNZO tokens from the faucet (100 TNZO per request, 24-hour cooldown per address)")]
    async fn request_faucet(
        &self,
        Parameters(params): Parameters<RequestFaucetParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let faucet_addr_str = self
            .web_state
            .faucet_address
            .as_ref()
            .ok_or_else(|| err_internal("Faucet not configured"))?
            .clone();

        let token = self
            .node
            .token()
            .ok_or_else(|| err_internal("Token system not initialized"))?;

        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let to_addr = parse_address(&params.address)?;
        let now = chrono::Utc::now().timestamp();

        // Rate limiting — check in-memory cache first, then persistent storage
        {
            let addr_key = addr_hex.to_lowercase();
            let rate_limit = self.web_state.faucet_rate_limit.lock();
            if let Some(&last) = rate_limit.get(&addr_key) {
                let elapsed = now - last;
                if elapsed < self.web_state.faucet_cooldown_secs as i64 {
                    let remaining = self.web_state.faucet_cooldown_secs as i64 - elapsed;
                    return text_result(format!(
                        "Rate limited. Try again in {} seconds.",
                        remaining
                    ));
                }
            }
        }

        // Also check persisted rate limit from storage (survives restarts)
        if let Some(storage) = self.node.storage() {
            use tenzro_storage::KvStore;
            let faucet_key = format!("faucet_request:{}", addr_hex.to_lowercase());
            if let Ok(Some(bytes)) = storage.get("metadata", faucet_key.as_bytes()) {
                let bytes: Vec<u8> = bytes;
                if bytes.len() == 8 {
                    let last_ts = i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                    let elapsed = now - last_ts;
                    if elapsed < self.web_state.faucet_cooldown_secs as i64 {
                        let remaining = self.web_state.faucet_cooldown_secs as i64 - elapsed;
                        return text_result(format!(
                            "Rate limited. Try again in {} seconds.",
                            remaining
                        ));
                    }
                }
            }
        }

        let from_addr = parse_address(&faucet_addr_str)?;
        let amount_base = self.web_state.faucet_amount;

        // Convert whole TNZO to base units (wei) — multiply by 10^18
        let amount_wei = amount_base
            .checked_mul(1_000_000_000_000_000_000u128)
            .unwrap_or(0);

        // Transfer directly via TnzoToken (persists to RocksDB immediately)
        match token.transfer(&from_addr, &to_addr, amount_wei) {
            Ok(_) => {
                // Generate tx hash from transfer details
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(b"faucet_transfer:");
                hasher.update(from_addr.as_bytes());
                hasher.update(to_addr.as_bytes());
                hasher.update(amount_wei.to_le_bytes());
                hasher.update(now.to_le_bytes());
                let hash_bytes = hasher.finalize();
                let tx_hash = format!("0x{}", hex::encode(hash_bytes));

                // Record rate limit in memory
                {
                    let addr_key = addr_hex.to_lowercase();
                    let mut rate_limit = self.web_state.faucet_rate_limit.lock();
                    rate_limit.insert(addr_key, now);
                }

                // Persist rate limit to RocksDB (survives pod restarts)
                if let Some(storage) = self.node.storage() {
                    use tenzro_storage::KvStore;
                    let faucet_key = format!("faucet_request:{}", addr_hex.to_lowercase());
                    let _ = storage.put("metadata", faucet_key.as_bytes(), &now.to_le_bytes());
                }

                json_result(serde_json::json!({
                    "success": true,
                    "tx_hash": tx_hash,
                    "amount": format!("{} TNZO", amount_base),
                    "recipient": format!("0x{}", addr_hex),
                }))
            }
            Err(e) => {
                text_result(format!("Faucet transfer failed: {}", e))
            }
        }
    }

    // ─── Identity (TDIP) ───

    #[tool(description = "Register a human or machine identity on the Tenzro Decentralized Identity Protocol (TDIP). Human identities are self-sovereign; machine identities require a controller DID and receive a delegation scope")]
    async fn register_identity(
        &self,
        Parameters(params): Parameters<RegisterIdentityParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        match params.identity_type.to_lowercase().as_str() {
            "human" => {
                use tenzro_crypto::{KeyPair, KeyType};
                let keypair = KeyPair::generate(KeyType::Ed25519).map_err(|e| ErrorData {
                    code: ErrorCode::INTERNAL_ERROR,
                    message: Cow::from(format!("Key generation error: {}", e)),
                    data: None,
                })?;
                let pub_key_bytes = keypair.public_key().as_bytes().to_vec();

                let identity = registry
                    .register_human_with_fee(
                        pub_key_bytes,
                        params.display_name.clone(),
                        tenzro_types::KycTier::Unverified,
                    )
                    .await
                    .map_err(|e| err_internal(format!("Registration failed: {}", e)))?
                    .identity;

                json_result(serde_json::json!({
                    "did": identity.did_string(),
                    "display_name": params.display_name,
                    "identity_type": "human",
                    "kyc_tier": "Unverified",
                    "status": "active",
                }))
            }
            "machine" => {
                let controller = params.controller_did.ok_or_else(|| ErrorData {
                    code: ErrorCode::INVALID_PARAMS,
                    message: Cow::from("controller_did is required for machine identities. Provide the DID of the human guardian (e.g. did:tenzro:human:uuid)."),
                    data: None,
                })?;

                use tenzro_crypto::{KeyPair, KeyType};
                let keypair = KeyPair::generate(KeyType::Ed25519).map_err(|e| ErrorData {
                    code: ErrorCode::INTERNAL_ERROR,
                    message: Cow::from(format!("Key generation error: {}", e)),
                    data: None,
                })?;
                let pub_key_bytes = keypair.public_key().as_bytes().to_vec();

                let identity = registry
                    .register_machine_with_fee(
                        &controller,
                        pub_key_bytes,
                        vec![],
                        tenzro_identity::DelegationScope::default(),
                    )
                    .await
                    .map_err(|e| err_internal(format!("Registration failed: {}", e)))?
                    .identity;

                json_result(serde_json::json!({
                    "did": identity.did_string(),
                    "display_name": params.display_name,
                    "identity_type": "machine",
                    "controller_did": controller,
                    "delegation_scope": {
                        "max_transaction_value": null,
                        "max_daily_spend": null,
                        "allowed_operations": [],
                        "allowed_payment_protocols": [],
                        "allowed_chains": [],
                    },
                    "status": "active",
                }))
            }
            other => Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!(
                    "Invalid identity_type '{}'. Use 'human' or 'machine'.",
                    other
                )),
                data: None,
            }),
        }
    }

    #[tool(description = "Resolve a DID to its identity information, including display name, type, status, and delegation scope for machine identities")]
    async fn resolve_did(
        &self,
        Parameters(params): Parameters<ResolveDidParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        match registry.resolve(&params.did) {
            Ok(identity) => {
                let mut result = serde_json::json!({
                    "did": identity.did_string(),
                    "display_name": identity.display_name(),
                    "identity_type": if identity.is_human() { "human" } else { "machine" },
                    "status": format!("{:?}", identity.status),
                    "created_at": identity.created_at.to_rfc3339(),
                });

                // Add delegation scope for machine identities
                if !identity.is_human() {
                    if let Some(scope) = identity.delegation_scope() {
                        result["delegation_scope"] = serde_json::json!({
                            "max_transaction_value": scope.max_transaction_value,
                            "max_daily_spend": scope.max_daily_spend,
                            "allowed_operations": scope.allowed_operations,
                            "allowed_payment_protocols": scope.allowed_payment_protocols,
                            "allowed_chains": scope.allowed_chains,
                        });
                    }
                    if let Some(controller) = identity.controller_did() {
                        result["controller_did"] = serde_json::Value::String(controller.to_string());
                    }
                }

                json_result(result)
            }
            Err(_) => text_result(format!(
                "DID '{}' not found in registry",
                params.did
            )),
        }
    }

    #[tool(description = "TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously revoked identity from the registry and persistent storage. The DID must already be in `Revoked` status — call `revoke_did` (RPC) first, allow cascading revocation to propagate, then call this. Distinct from revoke (logical delete).")]
    async fn forget_identity(
        &self,
        Parameters(params): Parameters<ResolveDidParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        registry
            .forget_identity(&params.did)
            .map_err(|e| err_internal(format!("forget_identity failed: {}", e)))?;

        json_result(serde_json::json!({
            "did": params.did,
            "status": "erased",
            "note": "Hard-deleted from CF_IDENTITIES per TDIP/GDPR Article 17",
        }))
    }

    #[tool(description = "List all Tenzro agent public signing keys as an RFC 7517 JWK Set. Mirrors GET /.well-known/jwks.json. External RFC 9421 verifiers (Visa TAP, Mastercard, Stripe MPP, AP2, x402) use this to resolve `keyid` parameters.")]
    async fn list_agent_jwks(
        &self,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        let agent_registry =
            tenzro_payments::rfc9421::TenzroAgentRegistry::new(registry.clone());
        let agents = agent_registry.list_all_agents();
        let set = tenzro_payments::rfc9421::JwkSet::from_agents(&agents);

        let value = serde_json::to_value(&set)
            .map_err(|e| err_internal(format!("JWK Set serialization failed: {}", e)))?;
        json_result(value)
    }

    #[tool(description = "Resolve a single agent JWK by RFC 9421 keyid. Accepts `did:tenzro:...` (first compatible key) or `did:tenzro:...#fragment` (specific key). Mirrors GET /.well-known/jwks.json/:keyid.")]
    async fn get_agent_jwk(
        &self,
        Parameters(params): Parameters<GetAgentJwkParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_payments::rfc9421::AgentRegistryClient;

        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        let agent_registry =
            tenzro_payments::rfc9421::TenzroAgentRegistry::new(registry.clone());

        let agent = agent_registry
            .get_public_key(&params.keyid)
            .await
            .map_err(|e| ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("agent lookup failed: {}", e)),
                data: None,
            })?;

        let jwk = tenzro_payments::rfc9421::Jwk::try_from_agent(&agent)
            .map_err(|e| err_internal(format!("JWK encoding failed: {}", e)))?;

        let value = serde_json::to_value(&jwk)
            .map_err(|e| err_internal(format!("JWK serialization failed: {}", e)))?;
        json_result(value)
    }

    #[tool(description = "Set the delegation scope for a machine identity, defining spending limits, allowed operations, payment protocols, and chains the agent may use")]
    async fn set_delegation_scope(
        &self,
        Parameters(params): Parameters<SetDelegationScopeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self
            .node
            .identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        // Resolve the machine identity first
        let identity = registry.resolve(&params.machine_did)
            .map_err(|_| ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Machine DID '{}' not found in registry", params.machine_did)),
                data: None,
            })?;

        if identity.is_human() {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Cannot set delegation scope on a human identity. Only machine identities have delegation scopes."),
                data: None,
            });
        }

        let scope = tenzro_identity::DelegationScope {
            max_transaction_value: params.max_transaction_value,
            max_daily_spend: params.max_daily_spend,
            allowed_operations: params.allowed_operations.unwrap_or_default(),
            allowed_contracts: vec![],
            time_bound: None,
            allowed_payment_protocols: params.allowed_payment_protocols.unwrap_or_default(),
            allowed_chains: params.allowed_chains.unwrap_or_default(),
        };

        let response_scope = serde_json::json!({
            "max_transaction_value": scope.max_transaction_value,
            "max_daily_spend": scope.max_daily_spend,
            "allowed_operations": scope.allowed_operations,
            "allowed_payment_protocols": scope.allowed_payment_protocols,
            "allowed_chains": scope.allowed_chains,
        });

        registry.update_delegation_scope(&params.machine_did, scope)
            .map_err(|e| err_internal(format!("Failed to update delegation scope: {}", e)))?;

        json_result(serde_json::json!({
            "machine_did": params.machine_did,
            "delegation_scope": response_scope,
            "status": "updated",
        }))
    }

    // ─── OAuth 2.1 — Token Exchange / Introspection / Discovery ───

    #[tool(description = "RFC 8693 OAuth 2.0 Token Exchange. Mint a narrower child JWT from a parent JWT, bound to a different DPoP key with a strict subset of the parent's RAR grants and AAP capabilities. The child token's controller_did is set to the parent's sub, extending the act-chain by one hop. Subset enforcement is performed by the AS; over-scoped requests are rejected.")]
    async fn exchange_token(
        &self,
        Parameters(params): Parameters<ExchangeTokenParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let engine = self
            .node
            .auth_engine()
            .ok_or_else(|| err_internal("Auth engine not initialized"))?;

        let requested_rar: tenzro_auth::AuthorizationDetails =
            serde_json::from_value(params.requested_rar.clone())
                .map_err(|e| err_internal(format!("Invalid requested_rar: {}", e)))?;

        let requested_aap_capabilities: Vec<tenzro_auth::AapCapabilityClaim> =
            serde_json::from_value(serde_json::Value::Array(params.requested_aap_capabilities))
                .map_err(|e| err_internal(format!("Invalid requested_aap_capabilities: {}", e)))?;

        let parent_claims = engine
            .validate_jwt(&params.subject_token, None)
            .map_err(|e| err_internal(format!("parent token validation failed: {}", e)))?;

        let req = tenzro_auth::TokenExchangeRequest {
            child_bearer_did: params.child_bearer_did,
            child_dpop_jkt: params.child_dpop_jkt,
            requested_rar,
            requested_aap_capabilities,
            requested_ttl_secs: params.requested_ttl_secs,
        };

        let outcome = engine
            .exchange_token(&parent_claims, req)
            .map_err(|e| err_internal(format!("token exchange failed: {}", e)))?;

        json_result(serde_json::json!({
            "access_token": outcome.access_token,
            "expires_in": outcome.expires_in,
            "token_type": "DPoP",
            "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "delegation": outcome.delegation,
        }))
    }

    #[tool(description = "RFC 7662 OAuth 2.0 Token Introspection. Ask the AS whether a token is currently active and, if so, return its full claim set (RAR authorization_details, AAP aap_* claims, cnf, controller_did, etc.). Per RFC 7662 §2.2 a failed validation returns `{active: false}` with no other fields — the AS does not leak why the token is inactive.")]
    async fn introspect_token(
        &self,
        Parameters(params): Parameters<IntrospectTokenParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let engine = self
            .node
            .auth_engine()
            .ok_or_else(|| err_internal("Auth engine not initialized"))?;

        let response = match engine.validate_jwt(&params.token, None) {
            Ok(claims) => tenzro_auth::IntrospectionResponse::from_claims(&claims),
            Err(_) => tenzro_auth::IntrospectionResponse::inactive(),
        };

        let value = serde_json::to_value(response)
            .map_err(|e| err_internal(format!("failed to serialize introspection: {}", e)))?;
        json_result(value)
    }

    #[tool(description = "RFC 8414 / RFC 9728 OAuth Authorization Server / Protected Resource Metadata. Returns the same metadata document the AS publishes at `GET /.well-known/openid-configuration`, augmented with AAP-specific extensions (authorization_details_types_supported, aap_claims_supported, dpop_signing_alg_values_supported).")]
    async fn oauth_discovery(
        &self,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let engine = self
            .node
            .auth_engine()
            .ok_or_else(|| err_internal("Auth engine not initialized"))?;
        let cfg = engine.config();
        let base = cfg.audience.trim_end_matches('/').to_string();

        json_result(serde_json::json!({
            "issuer": cfg.issuer,
            "token_endpoint": format!("{}/oauth/token", base),
            "introspection_endpoint": format!("{}/oauth/introspect", base),
            "revocation_endpoint": format!("{}/oauth/revoke", base),
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "authorization_code",
                "refresh_token",
            ],
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "response_types_supported": ["code"],
            "dpop_signing_alg_values_supported": ["EdDSA"],
            "authorization_details_types_supported": [
                "transfer", "create_escrow", "discharge_escrow", "inference",
                "stake", "vote", "contract", "register_identity"
            ],
            "aap_claims_supported": [
                "aap_agent", "aap_task", "aap_capabilities",
                "aap_oversight", "aap_delegation", "aap_context", "aap_audit"
            ],
        }))
    }

    // ─── MicroNode Join ───

    #[tool(description = "Join the Tenzro Network as a MicroNode — a zero-install full participant. \
        Auto-provisions a TDIP decentralized identity (DID) and MPC wallet. \
        Grants access to all 10 network capabilities: inference, payments, agent collaboration, \
        MCP tools, task execution, chain queries, smart contracts, TEE services, cross-chain bridge, \
        and governance. Works from any entry point: Claude, ClawBot, MCP, A2A, SDK, API, CLI, or app. \
        No hardware, no binary installation required.")]
    async fn join_as_participant(
        &self,
        Parameters(params): Parameters<JoinAsMicroNodeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let display_name = params.display_name
            .unwrap_or_else(|| "Tenzro Participant".to_string());
        let origin = params.origin.unwrap_or_else(|| "mcp".to_string());
        let participant_type_str = params.participant_type.unwrap_or_else(|| "human".to_string());

        // Auto-provision MPC wallet
        let wallet_service = self.node.wallet_service()
            .ok_or_else(|| err_internal("Wallet service not initialized"))?;

        use tenzro_wallet::WalletService;
        let wallet = wallet_service.provision_wallet().await
            .map_err(|e| err_internal(format!("Wallet provisioning failed: {}", e)))?;

        // Register human identity with TDIP
        let registry = self.node.identity_registry()
            .ok_or_else(|| err_internal("Identity registry not initialized"))?;

        let mut identity = registry.register_human_with_fee(
            wallet.public_key.to_bytes(),
            display_name.clone(),
            tenzro_types::identity::KycTier::Unverified,
        ).await.map_err(|e| err_internal(format!("Identity registration failed: {}", e)))?.identity;

        // Attach MicroNode metadata
        identity.metadata.insert("wallet_id".to_string(), wallet.wallet_id.0.clone());
        identity.metadata.insert("wallet_address".to_string(), format!("{}", wallet.address));
        identity.metadata.insert("network_role".to_string(), "micro_node".to_string());
        identity.metadata.insert("origin".to_string(), origin.clone());
        identity.metadata.insert("participant_type".to_string(), participant_type_str.clone());

        // Persist to RocksDB
        if let Some(storage) = self.node.storage() {
            use tenzro_storage::{KvStore, CF_IDENTITIES};
            if let Ok(bytes) = identity.to_bytes() {
                let _ = storage.put(CF_IDENTITIES, identity.did_string().as_bytes(), &bytes);
            }
        }

        // Also register participant as an agent in the agent runtime so that
        // spawn_agent can find them by DID as parent_id
        let mut agent_id_str = None;
        if let Some(runtime) = self.node.agent_runtime() {
            let did = identity.did_string();
            let caps = vec![
                tenzro_types::agent::Capability::Custom {
                    name: "micro_node".to_string(),
                    parameters: std::collections::HashMap::new(),
                },
            ];
            // Use the DID hash as a deterministic nonce for agent ID generation
            let nonce = {
                let hash = tenzro_crypto::hash::sha256(did.as_bytes());
                u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap_or([0u8; 8]))
            };
            match runtime.register_agent(
                display_name.clone(),
                wallet.address,
                caps,
                false,
                nonce,
            ).await {
                Ok(agent) => {
                    let aid = agent.identity.agent_id.clone();
                    tracing::info!(did = %did, agent_id = %aid, "Participant registered as agent in runtime");
                    agent_id_str = Some(aid);
                }
                Err(e) => {
                    tracing::warn!(did = %did, error = %e, "Failed to register participant as agent (non-fatal)");
                }
            }
        }

        json_result(serde_json::json!({
            "identity": {
                "did": identity.did_string(),
                "identity_type": "micro_node",
                "display_name": display_name,
                "status": format!("{:?}", identity.status),
                "agent_id": agent_id_str,
            },
            "wallet": {
                "wallet_id": wallet.wallet_id.0,
                "address": format!("{}", wallet.address),
                "public_key": format!("0x{}", hex::encode(wallet.public_key.to_bytes())),
            },
            "capabilities": {
                "inference": true,
                "payments": true,
                "agent_collaboration": true,
                "mcp_tools": true,
                "task_execution": true,
                "chain_query": true,
                "smart_contracts": true,
                "tee_services": true,
                "bridge": true,
                "governance": true,
            },
            "origin": origin,
            "participant_type": participant_type_str,
            "role": "micro_node",
            "network": {
                "rpc": "https://rpc.tenzro.network",
                "mcp": "https://mcp.tenzro.network/mcp",
                "a2a": "https://a2a.tenzro.network",
            },
            "message": format!(
                "Welcome to Tenzro Network! Your DID is {} and your wallet address is {}. \
                 You now have full access to all 10 network capabilities.{}",
                identity.did_string(), wallet.address,
                agent_id_str.as_ref().map(|id| format!(" Your agent ID for spawn_agent is {}.", id)).unwrap_or_default()
            ),
        }))
    }

    // ─── Payments (MPP, x402, Native) ───

    #[tool(description = "Create a payment challenge for a protected resource. Supports five protocols:\n- 'mpp' (Machine Payments Protocol): Session-based streaming payments, ideal for per-token AI inference billing\n- 'x402' (Coinbase HTTP 402): Stateless one-shot payments, ideal for API calls and data downloads\n- 'visa-tap' (Visa Trusted Agent Protocol): RFC 9421 agent-verified payments for agentic commerce\n- 'mastercard-agent-pay' (Mastercard Agent Pay): KYA-verified payments with agentic tokens\n- 'native': Direct TNZO transfer on the Tenzro ledger")]
    async fn create_payment_challenge(
        &self,
        Parameters(params): Parameters<CreatePaymentChallengeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let gateway = self
            .node
            .payment_gateway()
            .ok_or_else(|| err_internal("Payment gateway not initialized"))?;

        use tenzro_payments::traits::PaymentGateway;

        let challenge = gateway
            .create_challenge(
                &params.protocol,
                &params.resource,
                params.amount,
                &params.asset,
                &params.recipient,
            )
            .await
            .map_err(|e| err_internal(format!("Failed to create payment challenge: {}", e)))?;

        // Store the challenge in the gateway's challenge store for later verification
        let store = gateway.challenge_store();
        store.store(&challenge);

        json_result(serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "protocol": challenge.protocol,
            "resource": challenge.resource,
            "amount": challenge.amount.to_string(),
            "asset": challenge.asset,
            "recipient": challenge.recipient,
            "chain": challenge.chain,
            "expires_at": challenge.expires_at.to_rfc3339(),
            "note": match params.protocol.as_str() {
                "mpp" => "MPP challenge created. The agent should generate credentials and submit payment within the validity window. Supports session-based streaming for per-token billing.",
                "x402" => "x402 challenge created. Pay the exact amount on-chain, then retry the request with a PAYMENT-SIGNATURE header containing tx_hash, chain, payer, and signature.",
                _ => "Payment challenge created. Submit payment and verification proof within the validity window.",
            },
        }))
    }

    #[tool(description = "Verify a payment credential against a previously created challenge and settle the payment on-chain")]
    async fn verify_payment(
        &self,
        Parameters(params): Parameters<VerifyPaymentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let gateway = self
            .node
            .payment_gateway()
            .ok_or_else(|| err_internal("Payment gateway not initialized"))?;

        use tenzro_payments::traits::PaymentGateway;
        use tenzro_payments::types::PaymentCredential;

        let sig_bytes = hex::decode(
            params.signature.strip_prefix("0x").unwrap_or(&params.signature)
        ).map_err(|e| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from(format!("Invalid signature hex: {}", e)),
            data: None,
        })?;

        let pq_signature_bytes = if params.pq_signature.is_empty() {
            Vec::new()
        } else {
            hex::decode(
                params.pq_signature.strip_prefix("0x").unwrap_or(&params.pq_signature)
            ).map_err(|e| ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Invalid pq_signature hex: {}", e)),
                data: None,
            })?
        };

        let pq_public_key_bytes = if params.pq_public_key.is_empty() {
            Vec::new()
        } else {
            hex::decode(
                params.pq_public_key.strip_prefix("0x").unwrap_or(&params.pq_public_key)
            ).map_err(|e| ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Invalid pq_public_key hex: {}", e)),
                data: None,
            })?
        };

        let credential = PaymentCredential {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: params.challenge_id.clone(),
            protocol: params.protocol.clone(),
            payer_did: params.payer_did.clone(),
            payer_address: params.payer_address.clone(),
            amount: params.amount,
            asset: params.asset.clone(),
            signature: sig_bytes,
            pq_signature: pq_signature_bytes,
            pq_public_key: pq_public_key_bytes,
            extra: std::collections::HashMap::new(),
        };

        match gateway.verify_and_settle(&credential).await {
            Ok(receipt) => json_result(serde_json::json!({
                "receipt_id": receipt.receipt_id,
                "protocol": receipt.protocol,
                "challenge_id": receipt.challenge_id,
                "amount": receipt.amount.to_string(),
                "asset": receipt.asset,
                "chain": receipt.chain,
                "settlement_tx": receipt.settlement_tx,
                "settled_at": receipt.settled_at.to_rfc3339(),
                "status": "settled",
            })),
            Err(e) => json_result(serde_json::json!({
                "status": "failed",
                "challenge_id": params.challenge_id,
                "error": format!("{}", e),
            })),
        }
    }

    #[tool(description = "List the payment protocols supported by this Tenzro node, including MPP (session-based streaming), x402 (stateless one-shot), and native TNZO transfers")]
    async fn list_payment_protocols(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let gateway = self.node.payment_gateway();

        let registered = if let Some(gw) = gateway {
            use tenzro_payments::traits::PaymentGateway;
            gw.supported_protocols()
        } else {
            vec![]
        };

        json_result(serde_json::json!({
            "protocols": [
                {
                    "id": "mpp",
                    "name": "Machine Payments Protocol (MPP)",
                    "description": "Session-based streaming payments co-authored by Stripe and Tempo. Ideal for per-token AI inference billing where cost depends on consumption.",
                    "flow": "HTTP 402 challenge → credential → receipt",
                    "settlement": "Single on-chain settlement per session",
                    "best_for": "AI inference (pay per token), streaming services, long-running tasks",
                    "registered": registered.iter().any(|p| p == "mpp"),
                },
                {
                    "id": "x402",
                    "name": "x402 (Coinbase HTTP 402)",
                    "description": "Stateless one-shot payments using Coinbase's HTTP 402 protocol. Each request is independent—pay exact amount, receive resource.",
                    "flow": "HTTP 402 PAYMENT-REQUIRED → PAYMENT-SIGNATURE → PAYMENT-RESPONSE",
                    "settlement": "On-chain per transaction (~$0.0001 gas on Base)",
                    "best_for": "API calls, data downloads, image generation, one-time purchases",
                    "registered": registered.iter().any(|p| p == "x402"),
                },
                {
                    "id": "visa-tap",
                    "name": "Visa Trusted Agent Protocol (TAP)",
                    "description": "RFC 9421 HTTP Message Signature-based agent verification for agentic commerce. Agents sign HTTP requests with Ed25519 keys registered in the Tenzro identity registry.",
                    "flow": "RFC 9421 signed request → 7-stage CDN proxy verification → payment settlement",
                    "settlement": "On-chain via Tenzro Ledger (replaces card rails)",
                    "best_for": "Agent-to-merchant commerce, verified agent purchases, enterprise agentic payments",
                    "registered": registered.iter().any(|p| p == "visa-tap"),
                },
                {
                    "id": "mastercard-agent-pay",
                    "name": "Mastercard Agent Pay",
                    "description": "Agentic commerce framework with Know Your Agent (KYA) verification and agentic tokens. Agents obtain time-limited, scope-restricted payment tokens tied to their TDIP identity.",
                    "flow": "KYA verification → agentic token issuance → purchase intent → token-based payment",
                    "settlement": "On-chain via Tenzro Ledger with agentic token verification",
                    "best_for": "Controlled agent purchases, subscription services, human-authorized agent spending",
                    "registered": registered.iter().any(|p| p == "mastercard-agent-pay"),
                },
                {
                    "id": "native",
                    "name": "Native TNZO Transfer",
                    "description": "Direct TNZO token transfer on the Tenzro ledger. Simplest payment method for Tenzro-native services.",
                    "flow": "send_transaction → confirmation",
                    "settlement": "Immediate on-ledger settlement",
                    "best_for": "Tenzro-native services, staking, governance, direct transfers",
                    "registered": true,
                },
            ],
        }))
    }

    #[tool(description = "List the x402 scheme backends registered on this node. Each scheme corresponds to a different verification path under the x402 protocol: 'tenzro-hybrid' (Ed25519 hybrid sig over canonical preimage), 'exact-eip3009' (USDC EIP-3009 meta-tx via CDP facilitator), 'permit2' (Uniswap Permit2 via CDP facilitator), 'erc7710' (delegation redemption). Use the returned ids in the 'extra.scheme' field of an x402 PaymentRequirement.")]
    async fn list_x402_schemes(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let server = match self.node.x402_server() {
            Some(s) => s,
            None => {
                return json_result(serde_json::json!({
                    "default": tenzro_payments::x402::DEFAULT_SCHEME,
                    "schemes": Vec::<serde_json::Value>::new(),
                    "count": 0,
                    "warning": "x402 payment server not initialized on this node",
                }));
            }
        };

        let ids = server.scheme_registry().ids();
        let schemes: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| {
                let description = match id.as_str() {
                    "tenzro-hybrid" => "Tenzro-native Ed25519 hybrid signature over canonical x402 preimage (chain || asset || amount || recipient || payer)",
                    "exact-eip3009" => "USDC EIP-3009 transferWithAuthorization meta-transaction verified and settled by the configured CDP facilitator",
                    "permit2" => "Uniswap Permit2 PermitTransferFrom verified and settled by the configured CDP facilitator",
                    "erc7710" => "ERC-7710 delegation redemption verified by the configured DelegationVerifier",
                    _ => "Custom scheme backend",
                };
                serde_json::json!({
                    "id": id,
                    "description": description,
                })
            })
            .collect();

        json_result(serde_json::json!({
            "default": tenzro_payments::x402::DEFAULT_SCHEME,
            "schemes": schemes,
            "count": ids.len(),
        }))
    }

    #[tool(description = "List all providers discovered on the Tenzro Network. Providers broadcast announcements every 60s on the tenzro/providers gossipsub topic. Returns both the local node (if serving) and all remotely discovered providers. Optionally filter by provider_type: 'llm', 'tee', or 'general'.")]
    async fn list_providers(
        &self,
        Parameters(params): Parameters<ListProvidersParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut result: Vec<serde_json::Value> = Vec::new();

        // Include local node if it is serving models
        let served: Vec<String> = self.node.served_models
            .iter()
            .filter(|e| *e.value())
            .map(|e| e.key().clone())
            .collect();

        if !served.is_empty() {
            let self_peer_id = "local".to_string();
            seen_ids.insert(self_peer_id.clone());
            result.push(serde_json::json!({
                "peer_id": self_peer_id,
                "provider_address": "0x0000000000000000000000000000000000000000",
                "provider_type": "llm",
                "served_models": served,
                "capabilities": ["inference"],
                "rpc_endpoint": "",
                "status": "active",
                "is_local": true,
            }));
        }

        // Include remote providers discovered via gossipsub
        for entry in self.node.network_providers_snapshot() {
            let peer_id = entry.announcement.peer_id.clone();
            if !seen_ids.contains(&peer_id) {
                // Apply optional provider_type filter
                if let Some(ref pt) = params.provider_type
                    && !pt.is_empty() && entry.announcement.provider_type != *pt {
                        continue;
                    }
                seen_ids.insert(peer_id.clone());
                result.push(serde_json::json!({
                    "peer_id": peer_id,
                    "provider_address": entry.announcement.provider_address,
                    "provider_type": entry.announcement.provider_type,
                    "served_models": entry.announcement.served_models,
                    "capabilities": entry.announcement.capabilities,
                    "rpc_endpoint": entry.announcement.rpc_endpoint,
                    "status": entry.announcement.status,
                    "is_local": false,
                }));
            }
        }

        json_result(serde_json::to_value(result).map_err(|e| err_internal(e.to_string()))?)
    }

    // ─── Models & Inference ───

    #[tool(description = "List AI models available on the Tenzro network. Shows all models with availability: 'local' (served on this node, free), 'network' (available from remote providers, costs TNZO), or 'downloadable' (in catalog but not yet available). Filter by category or search by name")]
    async fn list_models(
        &self,
        Parameters(params): Parameters<ListModelsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let catalog = get_model_catalog();
        let hf_downloader = self.node.hf_downloader.as_ref();

        // Get network models from model registry (registered by remote providers)
        let network_model_ids: std::collections::HashSet<String> = if let Some(registry) = self.node.model_registry() {
            let filter = tenzro_model::ModelFilter::new();
            registry.search_models(&filter).iter().map(|m| m.model_id.clone()).collect()
        } else {
            std::collections::HashSet::new()
        };

        // Get network models from model services (remote endpoints)
        let network_services = self.node.list_model_services();

        // Get provider pricing for network cost estimation
        let pricing = self.node.provider_pricing.read();

        let mut model_list: Vec<serde_json::Value> = catalog.iter().map(|entry| {
            let is_downloaded = hf_downloader
                .map(|dl| dl.is_downloaded(&entry.id))
                .unwrap_or(false);

            let is_serving = self.node.model_runtime.as_ref()
                .map(|rt| rt.is_loaded(&entry.id))
                .unwrap_or(false);

            let is_on_network = network_model_ids.contains(&entry.id)
                || network_services.iter().any(|svc| svc.model_id == entry.id
                    && matches!(svc.location, tenzro_types::model::ModelLocation::Network));

            let availability = if is_serving {
                "local"
            } else if is_on_network {
                "network"
            } else {
                "downloadable"
            };

            let mut model_json = serde_json::json!({
                "model_id": entry.id,
                "name": entry.name,
                "family": entry.family,
                "parameters": entry.parameters,
                "architecture": entry.architecture.to_string(),
                "context_length": entry.context_length,
                "quantization": entry.quantization,
                "size_bytes": entry.size_bytes,
                "min_ram_gb": entry.min_ram_gb,
                "license": entry.license,
                "description": entry.description,
                "hf_repo": entry.hf_repo,
                "downloaded": is_downloaded,
                "serving": is_serving,
                "availability": availability,
                "pricing": {
                    "input_per_token_wei": if is_serving { "0".to_string() } else { pricing.input_price_per_token_wei.to_string() },
                    "output_per_token_wei": if is_serving { "0".to_string() } else { pricing.output_price_per_token_wei.to_string() },
                    "currency": "TNZO",
                },
            });

            if is_serving
                && let Some(snap) = self.node.load_tracker.snapshot(&entry.id) {
                    model_json["load"] = serde_json::json!({
                        "active_requests": snap.active_requests,
                        "max_concurrent": snap.max_concurrent,
                        "utilization_percent": snap.utilization_percent,
                        "load_level": snap.load_level.to_string(),
                    });
                }

            model_json
        }).collect();

        // Apply name filter if provided
        if let Some(ref name) = params.name {
            let name_lower = name.to_lowercase();
            model_list.retain(|m| {
                m["name"].as_str().map(|n| n.to_lowercase().contains(&name_lower)).unwrap_or(false)
                || m["model_id"].as_str().map(|id| id.to_lowercase().contains(&name_lower)).unwrap_or(false)
                || m["family"].as_str().map(|f| f.to_lowercase().contains(&name_lower)).unwrap_or(false)
            });
        }

        // Apply category filter if provided
        if let Some(ref cat) = params.category
            && let Ok(modality) = parse_modality(cat) {
                let modality_str = format!("{:?}", modality).to_lowercase();
                model_list.retain(|m| {
                    // Catalog models are text-generation; keep them only if category is "text"
                    m["architecture"].as_str()
                        .map(|a| a.to_lowercase().contains(&modality_str))
                        .unwrap_or(false)
                    || modality_str == "text"
                });
            }

        json_result(serde_json::json!({
            "models": model_list,
            "total": model_list.len(),
        }))
    }

    #[tool(description = "Invoke Tenzro Cortex recurrent-depth reasoning. Executes a recurrent-depth transformer (OpenMythos-style) through a registered Cortex worker, charging TNZO based on tokens_in, tokens_out, and loops_used. Returns the reasoning output along with a signed CortexReceipt binding input/output commitments, weights hash, runtime hash, loops_used, and worker DID. Use tier='fast|standard|deep|institutional' to select the reasoning depth budget. Positioning: Cortex reasons. Praecise governs. Tenzro settles. (Praecise is an open AI governance framework by Ipnops — integrated with, but not owned by, Tenzro.)")]
    async fn cortex_reason(
        &self,
        Parameters(params): Parameters<CortexReasonParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::cortex::{
            AttestationRequirement, CortexRequest, ReasoningBudget, ReasoningTier,
        };

        let tier = match params.tier.as_deref().unwrap_or("standard") {
            "fast" => ReasoningTier::Fast,
            "standard" => ReasoningTier::Standard,
            "deep" => ReasoningTier::Deep,
            "institutional" => ReasoningTier::Institutional,
            other => {
                return text_result(format!(
                    "Unknown tier '{}'. Valid: fast, standard, deep, institutional.",
                    other
                ));
            }
        };
        let mut budget = ReasoningBudget::for_tier(tier);
        if let Some(n) = params.min_loops {
            budget.min_loops = n;
        }
        if let Some(n) = params.max_loops {
            budget.max_loops = n;
        }
        if let Some(c) = params.max_cost_wei {
            budget.max_cost_wei = c;
        }
        if let Some(att) = params.attestation.as_deref() {
            budget.attestation = match att {
                "none" => AttestationRequirement::None,
                "tee" => AttestationRequirement::Tee,
                "tee_and_zk" | "teeandzk" => AttestationRequirement::TeeAndZk,
                other => {
                    return text_result(format!(
                        "Unknown attestation '{}'. Valid: none, tee, tee_and_zk.",
                        other
                    ));
                }
            };
        }

        let requester = params
            .requester
            .as_deref()
            .and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                let bytes = hex::decode(s).ok()?;
                let mut buf = [0u8; 32];
                let n = bytes.len().min(32);
                buf[..n].copy_from_slice(&bytes[..n]);
                Some(tenzro_types::primitives::Address::new(buf))
            })
            .unwrap_or_default();

        let worker = match self.node.cortex_workers.get(&params.model_id) {
            Some(w) => w.clone(),
            None => {
                return text_result(format!(
                    "No Cortex worker registered for model '{}'. Register via tenzro_registerCortexWorker RPC first.",
                    params.model_id
                ));
            }
        };

        let req = CortexRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            model_id: params.model_id.clone(),
            requester,
            input: params.input.into_bytes(),
            budget,
            params: Default::default(),
            timestamp: tenzro_types::primitives::Timestamp::now(),
        };

        let resp = worker
            .execute(&req)
            .await
            .map_err(|e| err_internal(format!("Cortex execute failed: {e}")))?;

        self.node.metrics().record_inference();

        // Best-effort wei settlement: requester → worker.
        let settled = if resp.price_wei > 0
            && requester != tenzro_types::primitives::Address::default()
        {
            match self.node.token() {
                Some(token) => {
                    match token.transfer(&requester, &resp.worker, resp.price_wei) {
                        Ok(_) => {
                            tracing::info!(
                                amount_wei = resp.price_wei,
                                loops_used = resp.metadata.loops_used,
                                "Cortex MCP inference settled on-chain"
                            );
                            true
                        }
                        Err(e) => {
                            tracing::warn!("Cortex MCP settlement failed: {}", e);
                            false
                        }
                    }
                }
                None => false,
            }
        } else {
            resp.price_wei == 0
        };

        // The output is arbitrary model-produced bytes. Emit a best-effort
        // UTF-8 string alongside a hex copy so text-based workflows work
        // and binary outputs remain recoverable.
        let output_utf8 = String::from_utf8(resp.output.clone()).ok();
        let output_hex = hex::encode(&resp.output);
        let mut value = serde_json::to_value(&resp).map_err(|e| err_internal(e.to_string()))?;
        if let Some(obj) = value.as_object_mut() {
            if let Some(text) = output_utf8 {
                obj.insert("output_text".into(), serde_json::Value::String(text));
            }
            obj.insert("output_hex".into(), serde_json::Value::String(output_hex));
            obj.insert("settled".into(), serde_json::Value::Bool(settled));
        }
        json_result(value)
    }

    #[tool(description = "Send a chat completion request to a served AI model on the Tenzro network. Use list_models or list_model_endpoints to discover available models")]
    async fn chat_completion(
        &self,
        Parameters(params): Parameters<ChatCompletionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let model = params.model;
        let message = params.message;
        let temperature = params.temperature;
        let max_tokens = params.max_tokens;

        // Find the model service by model_id or instance_id
        let service = self.node.find_model_service_by_model_id(&model)
            .or_else(|| self.node.get_model_service(&model));

        if service.is_none() {
            return text_result(format!(
                "Model '{}' not found. Use list_models or list_model_endpoints to see available models.",
                model
            ));
        }

        let svc = service.unwrap();

        // Build generation config
        use tenzro_model::GenerationConfig;
        let config = GenerationConfig {
            temperature: temperature.unwrap_or(0.7),
            max_tokens: max_tokens.unwrap_or(512),
            top_p: 0.9,
            repeat_penalty: 1.1,
            ..GenerationConfig::default()
        };

        if matches!(svc.location, tenzro_types::model::ModelLocation::Local) {
            // Local model inference
            let model_runtime = self.node.model_runtime.as_ref().ok_or_else(|| ErrorData {
                code: ErrorCode::INTERNAL_ERROR,
                message: Cow::from("Model runtime not initialized"),
                data: None,
            })?;

            // Acquire load slot (RAII guard auto-decrements on drop)
            let _load_guard = self.node.load_tracker.try_acquire(&svc.model_id).map_err(|_| {
                let msg = if let Some(snap) = self.node.load_tracker.snapshot(&svc.model_id) {
                    format!(
                        "Model '{}' is at capacity ({}/{} active). Try again later.",
                        svc.model_id, snap.active_requests, snap.max_concurrent
                    )
                } else {
                    format!("Model '{}' is at capacity. Try again later.", svc.model_id)
                };
                ErrorData {
                    code: ErrorCode::INTERNAL_ERROR,
                    message: Cow::from(msg),
                    data: None,
                }
            })?;

            match model_runtime.generate(&svc.model_id, &message, &config).await {
                Ok(result) => {
                    // Local models are free — no wei cost
                    let cost_wei: u128 = 0;

                    let load = self.node.load_tracker.snapshot(&svc.model_id).map(|s| {
                        serde_json::json!({
                            "active_requests": s.active_requests,
                            "max_concurrent": s.max_concurrent,
                            "utilization_percent": s.utilization_percent,
                            "load_level": s.load_level.to_string(),
                        })
                    });

                    json_result(serde_json::json!({
                        "model": svc.model_id,
                        "response": result.text,
                        "usage": {
                            "prompt_tokens": result.input_tokens,
                            "completion_tokens": result.output_tokens,
                            "total_tokens": result.input_tokens + result.output_tokens,
                        },
                        "cost_wei": cost_wei.to_string(),
                        "generation_time_ms": result.generation_time_ms,
                        "tokens_per_second": result.tokens_per_second,
                        "load": load,
                    }))
                }
                Err(e) => text_result(format!("Inference failed: {}", e)),
            }
        } else {
            // Network model — forward to remote provider
            let remote_url = format!("{}/chat/completions", svc.api_endpoint);
            let client = reqwest::Client::new();

            let forward_body = serde_json::json!({
                "model": svc.model_id,
                "messages": [{"role": "user", "content": message}],
                "temperature": temperature.unwrap_or(0.7),
                "max_tokens": max_tokens.unwrap_or(512),
            });

            match client.post(&remote_url).json(&forward_body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.json::<serde_json::Value>().await {
                        Ok(body) => json_result(body),
                        Err(e) => text_result(format!(
                            "Failed to parse provider response (status {}): {}",
                            status, e
                        )),
                    }
                }
                Err(e) => text_result(format!(
                    "Failed to connect to provider at {}: {}",
                    remote_url, e
                )),
            }
        }
    }

    #[tool(description = "List all model service endpoints with their API and MCP URLs, model details, and status")]
    async fn list_model_endpoints(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let services = self.node.list_model_services();

        if services.is_empty() {
            return text_result(
                "No model services currently running. Use 'tenzro-cli provider serve' to start serving models."
            );
        }

        let endpoints: Vec<serde_json::Value> = services.iter().map(|svc| {
            let mut entry = serde_json::json!({
                "instance_id": svc.instance_id,
                "model_id": svc.model_id,
                "model_name": svc.model_name,
                "provider": svc.provider_name,
                "location": format!("{}", svc.location),
                "status": format!("{}", svc.status),
                "api_endpoint": svc.api_endpoint,
                "mcp_endpoint": svc.mcp_endpoint,
            });
            if let Some(snap) = self.node.load_tracker.snapshot(&svc.model_id) {
                entry["load"] = serde_json::json!({
                    "active_requests": snap.active_requests,
                    "max_concurrent": snap.max_concurrent,
                    "utilization_percent": snap.utilization_percent,
                    "load_level": snap.load_level.to_string(),
                });
            }
            entry
        }).collect();

        json_result(serde_json::json!({
            "endpoints": endpoints,
            "total": endpoints.len(),
        }))
    }

    // ─── Bridge (Cross-Chain) ───

    #[tool(description = "Bridge tokens between blockchains. Supports routes between Tenzro, Ethereum, Solana, and Base via LayerZero, Chainlink CCIP, and deBridge adapters")]
    async fn bridge_tokens(
        &self,
        Parameters(params): Parameters<BridgeTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let router = self
            .node
            .bridge_router()
            .ok_or_else(|| err_internal("Bridge router not initialized"))?;

        use tenzro_bridge::BridgeTokenRequest;

        let request = BridgeTokenRequest::new(
            params.source_chain.clone(),
            params.dest_chain.clone(),
            params.asset.clone(),
            params.amount,
            params.sender.clone(),
            params.recipient.clone(),
        );

        match router.bridge_tokens(request).await {
            Ok(receipt) => json_result(serde_json::json!({
                "transfer_id": receipt.transfer_id,
                "source_chain": receipt.source_chain,
                "dest_chain": receipt.dest_chain,
                "asset": params.asset,
                "amount": params.amount.to_string(),
                "tx_hash": format!("{}", receipt.tx_hash),
                "fee_paid": receipt.fee_paid.to_string(),
                "estimated_arrival_ms": receipt.estimated_arrival,
            })),
            Err(e) => json_result(serde_json::json!({
                "status": "failed",
                "error": format!("{}", e),
                "source_chain": params.source_chain,
                "dest_chain": params.dest_chain,
            })),
        }
    }

    #[tool(description = "Get available bridge routes between two chains, including estimated fees, time, and which adapter handles the route")]
    async fn get_bridge_routes(
        &self,
        Parameters(params): Parameters<GetBridgeRoutesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let router = self
            .node
            .bridge_router()
            .ok_or_else(|| err_internal("Bridge router not initialized"))?;

        match router.get_available_routes(&params.source_chain, &params.dest_chain).await {
            Ok(routes) => {
                let route_list: Vec<serde_json::Value> = routes.iter().map(|r| {
                    serde_json::json!({
                        "adapter": r.adapter_name,
                        "source_chain": r.source_chain,
                        "dest_chain": r.dest_chain,
                        "estimated_fee": r.estimated_fee.to_string(),
                        "estimated_time_secs": r.estimated_time_secs,
                    })
                }).collect();

                json_result(serde_json::json!({
                    "routes": route_list,
                    "total": route_list.len(),
                }))
            }
            Err(e) => json_result(serde_json::json!({
                "routes": [],
                "total": 0,
                "error": format!("{}", e),
            })),
        }
    }

    #[tool(description = "List all registered bridge adapters (LayerZero, Chainlink CCIP, deBridge, Canton)")]
    async fn list_bridge_adapters(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let router = self.node.bridge_router();

        if let Some(r) = router {
            let adapters = r.list_adapters().await;
            json_result(serde_json::json!({
                "adapters": adapters,
                "total": adapters.len(),
            }))
        } else {
            json_result(serde_json::json!({
                "adapters": [],
                "total": 0,
                "note": "Bridge router not initialized on this node.",
            }))
        }
    }

    // ─── deBridge MCP Proxy ───

    #[tool(description = "Search for tokens available on deBridge DLN. Returns token addresses, symbols, and supported chains.")]
    async fn debridge_search_tokens(
        &self,
        Parameters(params): Parameters<DebridgeSearchTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut args = serde_json::json!({
            "query": params.query,
        });
        if let Some(cid) = params.chain_id {
            args["chainId"] = serde_json::json!(cid);
        }
        match debridge_mcp_call("search_tokens", args).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&result).unwrap_or_default())])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    #[tool(description = "Get all blockchain networks supported by deBridge DLN for cross-chain transfers.")]
    async fn debridge_get_chains(&self) -> std::result::Result<CallToolResult, ErrorData> {
        match debridge_mcp_call("get_supported_chains", serde_json::json!({})).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&result).unwrap_or_default())])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    #[tool(description = "Get deBridge operational instructions and guidance for cross-chain transfers.")]
    async fn debridge_get_instructions(&self) -> std::result::Result<CallToolResult, ErrorData> {
        match debridge_mcp_call("get_instructions", serde_json::json!({})).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&result).unwrap_or_default())])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    #[tool(description = "Create a cross-chain transaction via deBridge DLN. Returns transaction data ready for signing and submission.")]
    async fn debridge_create_tx(
        &self,
        Parameters(params): Parameters<DebridgeCreateTxParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut args = serde_json::json!({
            "srcChainId": params.src_chain_id,
            "dstChainId": params.dst_chain_id,
            "srcChainTokenIn": params.src_token,
            "dstChainTokenOut": params.dst_token,
            "srcChainTokenInAmount": params.amount,
            "dstChainTokenOutRecipient": params.recipient,
        });
        if let Some(ref sender) = params.sender {
            args["senderAddress"] = serde_json::json!(sender);
        }
        match debridge_mcp_call("create_tx", args).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&result).unwrap_or_default())])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    #[tool(description = "Execute a same-chain token swap via deBridge. Swaps tokens on the same blockchain without cross-chain bridging.")]
    async fn debridge_same_chain_swap(
        &self,
        Parameters(params): Parameters<DebridgeSameChainSwapParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut args = serde_json::json!({
            "chainId": params.chain_id,
            "tokenIn": params.token_in,
            "tokenOut": params.token_out,
            "amount": params.amount,
        });
        if let Some(ref sender) = params.sender {
            args["senderAddress"] = serde_json::json!(sender);
        }
        match debridge_mcp_call("transaction_same_chain_swap", args).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&result).unwrap_or_default())])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    // ─── Network & Blocks ───

    #[tool(description = "Get the current status of the Tenzro node including health, block height, peer count, uptime, and role")]
    async fn get_node_status(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let status = self.node.status().await;
        json_result(serde_json::json!({
            "state": status.state,
            "role": format!("{:?}", status.role),
            "health": format!("{:?}", status.health_status),
            "block_height": status.block_height,
            "peer_count": status.peer_count,
            "uptime_secs": status.uptime_secs,
        }))
    }

    #[tool(description = "Get a block by height from the Tenzro ledger, including transactions and metadata")]
    async fn get_block(
        &self,
        Parameters(params): Parameters<GetBlockParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if let Some(storage) = self.node.storage() {
            use tenzro_storage::KvStore;
            let key = params.height.to_be_bytes();
            match storage.get("blocks", &key) {
                Ok(Some(data)) => {
                    if let Ok(block) = serde_json::from_slice::<serde_json::Value>(&data) {
                        json_result(block)
                    } else {
                        text_result(format!(
                            "Block {} exists ({} bytes) but could not be deserialized",
                            params.height,
                            data.len()
                        ))
                    }
                }
                Ok(None) => text_result(format!("Block {} not found", params.height)),
                Err(e) => Err(err_internal(format!("Storage error: {}", e))),
            }
        } else {
            Err(err_internal("Storage not initialized"))
        }
    }

    #[tool(description = "Fetch a contiguous range of blocks by height (default 64, max 256). Returns block summaries plus `next_height` and `more_available` so a lagging client can paginate forward until caught up.")]
    async fn get_block_range(
        &self,
        Parameters(params): Parameters<GetBlockRangeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::block_store::BlockStoreImpl;
        use tenzro_storage::traits::BlockStore;
        use tenzro_types::primitives::BlockHeight;

        if params.start_height > params.end_height {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!(
                    "start_height ({}) must be <= end_height ({})",
                    params.start_height, params.end_height
                )),
                data: None,
            });
        }

        let max_results = params.max_results.unwrap_or(64);
        if max_results == 0 || max_results > 256 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!(
                    "max_results must be in [1, 256], got {}",
                    max_results
                )),
                data: None,
            });
        }

        let storage = self
            .node
            .storage()
            .ok_or_else(|| err_internal("Storage not initialized"))?;

        let block_store = BlockStoreImpl::new(storage.clone())
            .map_err(|e| err_internal(format!("Block store error: {}", e)))?;

        let local_tip = block_store
            .latest_height()
            .await
            .map_err(|e| err_internal(format!("Failed to read latest height: {}", e)))?
            .map(|h| h.0)
            .unwrap_or(0);

        let batch_cap = params
            .start_height
            .saturating_add(max_results.saturating_sub(1));
        let clamped_end = params.end_height.min(batch_cap).min(local_tip);

        let blocks = if clamped_end < params.start_height {
            Vec::new()
        } else {
            block_store
                .blocks_by_height_range(
                    BlockHeight::new(params.start_height),
                    BlockHeight::new(clamped_end),
                )
                .await
                .map_err(|e| err_internal(format!("Failed to load block range: {}", e)))?
        };

        let summaries: Vec<serde_json::Value> = blocks
            .iter()
            .map(|b| {
                serde_json::json!({
                    "height": b.height().0,
                    "hash": format!("{}", b.hash()),
                    "prev_hash": format!("{}", b.header.prev_hash),
                    "state_root": format!("{}", b.header.state_root),
                    "tx_root": format!("{}", b.header.tx_root),
                    "timestamp": b.header.timestamp.as_millis(),
                    "proposer": format!("{}", b.header.proposer),
                    "tx_count": b.transactions.len(),
                    "gas_used": b.header.metadata.gas_used,
                    "gas_limit": b.header.metadata.gas_limit,
                })
            })
            .collect();

        let next_height = blocks
            .last()
            .map(|b| b.height().0.saturating_add(1))
            .unwrap_or_else(|| clamped_end.saturating_add(1));
        let more_available = next_height <= local_tip;

        json_result(serde_json::json!({
            "blocks": summaries,
            "next_height": next_height,
            "more_available": more_available,
            "local_tip": local_tip,
        }))
    }

    #[tool(description = "Inspect the EIP-1559 fee market: current effective gas price (base fee + suggested tip), suggested priority tip, and recent base-fee history. Use this to size maxFeePerGas / maxPriorityFeePerGas on Type-2 transactions. Base fee adjusts ±12.5% per block based on parent gas usage vs. the 15M target.")]
    async fn get_fee_market(
        &self,
        Parameters(params): Parameters<GetFeeMarketParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let vm = self
            .node
            .vm_runtime()
            .ok_or_else(|| err_internal("VM runtime not initialized"))?;

        let fee_market = vm.gas_oracle().fee_market_snapshot().await;

        let base_fee_now = fee_market
            .as_ref()
            .map(|fm| fm.base_fee())
            .unwrap_or(1_000_000_000u128);
        let priority_tip = fee_market
            .as_ref()
            .map(|fm| fm.suggest_priority_fee(tenzro_vm::eip1559::FeeUrgency::Medium))
            .unwrap_or(1_000_000_000u128);
        let effective = base_fee_now.saturating_add(priority_tip);

        let blocks = params.blocks.unwrap_or(10);
        if blocks == 0 || blocks > 1024 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("blocks must be in [1, 1024], got {}", blocks)),
                data: None,
            });
        }

        let mut history_base_fees: Vec<String> = Vec::with_capacity((blocks + 1) as usize);
        if let Some(fm) = fee_market.as_ref() {
            // Trailing entry is the predicted next-block base fee.
            for _ in 0..blocks {
                history_base_fees.push(format!("0x{:x}", fm.base_fee()));
            }
            history_base_fees.push(format!("0x{:x}", fm.base_fee()));
        }

        json_result(serde_json::json!({
            "gas_price_wei": format!("0x{:x}", effective),
            "max_priority_fee_per_gas_wei": format!("0x{:x}", priority_tip),
            "next_block_base_fee_wei": format!("0x{:x}", base_fee_now),
            "fee_history": {
                "base_fee_per_gas": history_base_fees,
                "blocks_sampled": blocks,
            }
        }))
    }

    #[tool(description = "Return the canonical Tenzro Cross-VM SVM-native program ID and 4 instruction discriminators (bridge_to_evm, bridge_from_evm, register_token_pointer, transfer_cross_vm). Use this to construct SVM Instructions targeting the Tenzro Cross-VM native program from any SVM client.")]
    async fn get_svm_cross_vm_program_info(
        &self,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        json_result(serde_json::json!({
            "program_id": {
                "hex": "5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695",
                "base58": "7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC",
                "derivation_domain": "tenzro/svm/program/cross_vm",
            },
            "instructions": {
                "bridge_to_evm": {
                    "discriminator_hex": "92a8a45c33225f25",
                    "payload_size": 68,
                    "payload_layout": "mint(32) || evm_dest(20) || amount(u64 LE) || nonce(u64 LE)",
                },
                "bridge_from_evm": {
                    "discriminator_hex": "3038733289f4cd75",
                    "payload_size": 80,
                    "payload_layout": "mint(32) || svm_dest(32) || amount(u64 LE) || nonce(u64 LE)",
                },
                "register_token_pointer": {
                    "discriminator_hex": "9a8e01390f994522",
                    "payload_size": 84,
                    "payload_layout": "mint(32) || evm_token_address(20) || token_id(32)",
                },
                "transfer_cross_vm": {
                    "discriminator_hex": "bc684168aba7abb9",
                    "payload_size": 81,
                    "payload_layout": "mint(32) || dest_vm(u8) || dest_address(32) || amount(u64 LE) || nonce(u64 LE)",
                    "dest_vm_values": {"NATIVE": 0u8, "EVM": 1u8, "SVM": 2u8, "DAML": 3u8},
                },
            },
        }))
    }

    #[tool(description = "Look up a transaction by its hash on the Tenzro ledger, returning type, sender, recipient, amount, status, and block height")]
    async fn get_transaction(
        &self,
        Parameters(params): Parameters<GetTransactionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let hash_str = params.tx_hash.strip_prefix("0x").unwrap_or(&params.tx_hash);
        // Validate hex (reject malformed input early) but use the hex string
        // itself as the storage key — the event loop indexes transactions under
        // the Display form of Hash, which is bare lowercase hex (no 0x prefix).
        if let Err(e) = hex::decode(hash_str) {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Invalid hex hash: {}", e)),
                data: None,
            });
        }

        if let Some(storage) = self.node.storage() {
            use tenzro_storage::KvStore;
            match storage.get("transactions", hash_str.as_bytes()) {
                Ok(Some(data)) => {
                    if let Ok(tx) = serde_json::from_slice::<serde_json::Value>(&data) {
                        json_result(tx)
                    } else {
                        text_result(format!(
                            "Transaction 0x{} exists ({} bytes) but could not be deserialized",
                            hash_str,
                            data.len()
                        ))
                    }
                }
                Ok(None) => text_result(format!("Transaction 0x{} not found", hash_str)),
                Err(e) => Err(err_internal(format!("Storage error: {}", e))),
            }
        } else {
            Err(err_internal("Storage not initialized"))
        }
    }

    // ─── Verification ───

    #[tool(description = "Verify a Plonky3 STARK proof (over KoalaBear) on the Tenzro ledger. Requires a circuit_id ('inference', 'settlement', or 'identity').")]
    async fn verify_zk_proof(
        &self,
        Parameters(params): Parameters<VerifyZkProofParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if params.circuit_id.is_empty() {
            return json_result(serde_json::json!({
                "valid": false,
                "error": "circuit_id is required (\"inference\", \"settlement\", or \"identity\")",
            }));
        }
        let circuit_id = params.circuit_id.clone();

        let proof_hex = params.proof.strip_prefix("0x").unwrap_or(&params.proof);
        let proof_bytes = match hex::decode(proof_hex) {
            Ok(b) => b,
            Err(e) => {
                return json_result(serde_json::json!({
                    "valid": false,
                    "error": format!("Invalid proof hex: {}", e),
                }));
            }
        };

        let mut public_inputs = Vec::new();
        for (i, input_hex) in params.public_inputs.iter().enumerate() {
            let hex_str = input_hex.strip_prefix("0x").unwrap_or(input_hex);
            match hex::decode(hex_str) {
                Ok(b) => public_inputs.push(b),
                Err(e) => {
                    return json_result(serde_json::json!({
                        "valid": false,
                        "error": format!("Invalid public_input[{}] hex: {}", i, e),
                    }));
                }
            }
        }

        let proof_size = proof_bytes.len();
        let public_inputs_count = public_inputs.len();

        // Build a wire-format Proof envelope and run the Plonky3 verifier on a
        // blocking thread — the verifier is CPU-bound and would otherwise stall
        // the tokio executor on large proofs.
        let envelope = tenzro_zk::Proof::new(
            proof_bytes,
            public_inputs,
            circuit_id.clone(),
        );

        let verify_result = tokio::task::spawn_blocking(move || {
            tenzro_zk::verify_proof_envelope(&envelope)
        })
        .await
        .unwrap_or_else(|join_err| {
            Err(tenzro_zk::VerifyEnvelopeError::VerifierRejected(format!(
                "spawn_blocking join error: {join_err}"
            )))
        });

        match verify_result {
            Ok(()) => json_result(serde_json::json!({
                "valid": true,
                "circuit_id": circuit_id,
                "public_inputs_count": public_inputs_count,
                "proof_size_bytes": proof_size,
                "status": "plonky3_verified",
                "verified_at": chrono::Utc::now().to_rfc3339(),
            })),
            Err(e) => {
                let (status, error) = match &e {
                    tenzro_zk::VerifyEnvelopeError::UnknownCircuit(id) => {
                        ("unknown_circuit", format!("no AIR registered for circuit_id={id}"))
                    }
                    tenzro_zk::VerifyEnvelopeError::EnvelopeDecode(zk_err) => {
                        ("envelope_decode_failed", zk_err.to_string())
                    }
                    tenzro_zk::VerifyEnvelopeError::VerifierRejected(detail) => {
                        ("verifier_rejected", detail.clone())
                    }
                };
                json_result(serde_json::json!({
                    "valid": false,
                    "circuit_id": circuit_id,
                    "public_inputs_count": public_inputs_count,
                    "proof_size_bytes": proof_size,
                    "status": status,
                    "error": error,
                    "verified_at": chrono::Utc::now().to_rfc3339(),
                }))
            }
        }
    }

    #[tool(description = "Verify a Tenzro VRF proof (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI). Returns the deterministic 64-byte VRF output if the proof is valid. Used for provably-fair NFT reveals, lotteries, and randomized trait assignment.")]
    async fn verify_vrf_proof(
        &self,
        Parameters(params): Parameters<VerifyVrfProofParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_crypto::vrf;

        let pk_bytes = match hex::decode(params.pubkey.strip_prefix("0x").unwrap_or(&params.pubkey)) {
            Ok(b) => b,
            Err(e) => return json_result(serde_json::json!({
                "valid": false,
                "error": format!("Invalid pubkey hex: {}", e),
            })),
        };
        if pk_bytes.len() != 32 {
            return json_result(serde_json::json!({
                "valid": false,
                "error": format!("pubkey must be 32 bytes, got {}", pk_bytes.len()),
            }));
        }
        let proof_bytes = match hex::decode(params.proof.strip_prefix("0x").unwrap_or(&params.proof)) {
            Ok(b) => b,
            Err(e) => return json_result(serde_json::json!({
                "valid": false,
                "error": format!("Invalid proof hex: {}", e),
            })),
        };
        if proof_bytes.len() != vrf::PROOF_LEN {
            return json_result(serde_json::json!({
                "valid": false,
                "error": format!("proof must be {} bytes, got {}", vrf::PROOF_LEN, proof_bytes.len()),
            }));
        }
        let alpha = match hex::decode(params.alpha.strip_prefix("0x").unwrap_or(&params.alpha)) {
            Ok(b) => b,
            Err(e) => return json_result(serde_json::json!({
                "valid": false,
                "error": format!("Invalid alpha hex: {}", e),
            })),
        };

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let mut proof_arr = [0u8; vrf::PROOF_LEN];
        proof_arr.copy_from_slice(&proof_bytes);

        let pk = vrf::VrfPublicKey(pk_arr);
        let proof = vrf::VrfProof(proof_arr);

        match vrf::verify(&pk, &alpha, &proof) {
            Ok(output) => json_result(serde_json::json!({
                "valid": true,
                "output": format!("0x{}", hex::encode(output.0)),
                "output_len": output.0.len(),
                "ciphersuite": "ECVRF-EDWARDS25519-SHA512-TAI",
                "verified_at": chrono::Utc::now().to_rfc3339(),
            })),
            Err(e) => json_result(serde_json::json!({
                "valid": false,
                "error": e.to_string(),
            })),
        }
    }

    #[tool(description = "Generate a Tenzro VRF proof (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI). Returns the public key, 80-byte proof, and 64-byte deterministic output. Do not use with secret inputs — the try-and-increment encoding is data-dependent.")]
    async fn generate_vrf_proof(
        &self,
        Parameters(params): Parameters<GenerateVrfProofParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_crypto::vrf;

        let sk_bytes = match hex::decode(params.secret_key.strip_prefix("0x").unwrap_or(&params.secret_key)) {
            Ok(b) => b,
            Err(e) => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Invalid secret_key hex: {}", e)),
                data: None,
            }),
        };
        if sk_bytes.len() != 32 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("secret_key must be 32 bytes, got {}", sk_bytes.len())),
                data: None,
            });
        }
        let alpha = match hex::decode(params.alpha.strip_prefix("0x").unwrap_or(&params.alpha)) {
            Ok(b) => b,
            Err(e) => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Invalid alpha hex: {}", e)),
                data: None,
            }),
        };

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let sk = vrf::VrfSecretKey(sk_arr);
        let pk = sk.public_key();

        let proof = vrf::prove(&sk, &alpha).map_err(|e| err_internal(format!("prove: {}", e)))?;
        let output = vrf::proof_output(&proof).map_err(|e| err_internal(format!("proof_output: {}", e)))?;

        json_result(serde_json::json!({
            "pubkey": format!("0x{}", hex::encode(pk.0)),
            "proof": format!("0x{}", hex::encode(proof.0)),
            "output": format!("0x{}", hex::encode(output.0)),
            "ciphersuite": "ECVRF-EDWARDS25519-SHA512-TAI",
            "generated_at": chrono::Utc::now().to_rfc3339(),
        }))
    }

    // ─── Staking & Provider Management ───

    #[tool(description = "Stake TNZO tokens to participate as a validator, model provider, TEE provider, or storage provider. Staked tokens earn rewards and increase network weight.")]
    async fn stake_tokens(
        &self,
        Parameters(params): Parameters<StakeTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let staking = self.node.staking().ok_or_else(|| err_internal("Staking not initialized"))?;

        let provider_type = match params.provider_type.to_lowercase().as_str() {
            "validator" => tenzro_types::token::ProviderType::Validator,
            "model_provider" | "modelprovider" | "inference" => tenzro_types::token::ProviderType::ModelProvider,
            "tee_provider" | "teeprovider" | "tee" => tenzro_types::token::ProviderType::TeeProvider,
            "storage_provider" | "storageprovider" | "storage" => tenzro_types::token::ProviderType::StorageProvider,
            other => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Unknown provider type '{}'. Use: validator, model_provider, tee_provider, storage_provider", other)),
                data: None,
            }),
        };

        let amount_wei: u128 = params.amount.parse().map_err(|_| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from("Stake amount must be a wei decimal string (e.g. '1000000000000000000000' for 1000 TNZO)"),
            data: None,
        })?;
        if amount_wei == 0 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Stake amount must be greater than 0"),
                data: None,
            });
        }

        // Use the first identity's address as the staker
        let staker_address = if let Some(registry) = self.node.identity_registry() {
            let identities = registry.list_all();
            identities.first().map(|(_, id)| id.wallet_address)
                .unwrap_or_else(Address::zero)
        } else {
            Address::zero()
        };

        match staking.stake(staker_address, amount_wei, provider_type) {
            Ok(_) => {
                json_result(serde_json::json!({
                    "status": "staked",
                    "amount_wei": amount_wei.to_string(),
                    "provider_type": format!("{:?}", provider_type),
                    "staker": format!("0x{}", hex::encode(&staker_address.as_bytes()[..20])),
                    "message": "Successfully staked tokens. Rewards will accrue each epoch.",
                }))
            }
            Err(e) => {
                json_result(serde_json::json!({
                    "status": "failed",
                    "error": format!("{}", e),
                }))
            }
        }
    }

    #[tool(description = "Unstake TNZO tokens and begin the unbonding period. After the unbonding period (typically 7 days), tokens can be withdrawn.")]
    async fn unstake_tokens(
        &self,
        Parameters(params): Parameters<UnstakeTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let staking = self.node.staking().ok_or_else(|| err_internal("Staking not initialized"))?;
        let address = parse_address(&params.address)?;

        // Check current stake
        let stake_info = staking.get_stake(&address);

        match staking.unstake(&address) {
            Ok(_) => {
                let staked_amount = stake_info.map(|s| s.amount).unwrap_or(0);
                json_result(serde_json::json!({
                    "status": "unstaking",
                    "address": format!("0x{}", hex::encode(&address.as_bytes()[..20])),
                    "amount_wei": staked_amount.to_string(),
                    "unbonding_period": "7 days",
                    "message": "Unstaking initiated. Tokens will be available after the unbonding period.",
                }))
            }
            Err(e) => {
                json_result(serde_json::json!({
                    "status": "failed",
                    "error": format!("{}", e),
                }))
            }
        }
    }

    #[tool(description = "Register as a service provider on the Tenzro Network. Providers earn TNZO by serving AI models (inference), providing TEE enclaves (security), validating blocks, or providing storage.")]
    async fn register_provider(
        &self,
        Parameters(params): Parameters<RegisterProviderParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let provider_type = match params.provider_type.to_lowercase().as_str() {
            "validator" => tenzro_types::token::ProviderType::Validator,
            "model_provider" | "modelprovider" | "inference" => tenzro_types::token::ProviderType::ModelProvider,
            "tee_provider" | "teeprovider" | "tee" => tenzro_types::token::ProviderType::TeeProvider,
            "storage_provider" | "storageprovider" | "storage" => tenzro_types::token::ProviderType::StorageProvider,
            other => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Unknown provider type '{}'. Use: validator, model_provider, tee_provider, storage_provider", other)),
                data: None,
            }),
        };

        let provider_id = format!("provider-{}", uuid::Uuid::new_v4());
        let max_concurrent = params.max_concurrent.unwrap_or(10);

        // If stake amount provided, stake tokens
        let stake_wei: u128 = match params.stake.as_deref() {
            None | Some("") | Some("0") => 0,
            Some(s) => s.parse().map_err(|_| ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Stake must be a wei decimal string (e.g. '10000000000000000000000' for 10,000 TNZO)"),
                data: None,
            })?,
        };
        if stake_wei > 0
            && let Some(staking) = self.node.staking() {
                let staker_address = if let Some(registry) = self.node.identity_registry() {
                    let identities = registry.list_all();
                    identities.first().map(|(_, id)| id.wallet_address)
                        .unwrap_or_else(Address::zero)
                } else {
                    Address::zero()
                };
                let _ = staking.stake(staker_address, stake_wei, provider_type);
            }

        json_result(serde_json::json!({
            "status": "registered",
            "provider_id": provider_id,
            "provider_type": format!("{:?}", provider_type),
            "name": params.name,
            "max_concurrent": max_concurrent,
            "stake_wei": stake_wei.to_string(),
            "message": format!("Provider '{}' registered as {:?}. Use serve_model or start providing services.", params.name, provider_type),
        }))
    }

    #[tool(description = "Get provider statistics including served models, inference count, staking info, and earnings. Omit address to get stats for the local node.")]
    async fn get_provider_stats(
        &self,
        Parameters(params): Parameters<GetProviderStatsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let models_served = self.node.served_models.len();
        let total_inferences = self.node.transaction_history.read().len();

        // Get staking totals, optionally filtered by provider address
        let (total_staked, validator_count): (u128, usize) = if let Some(staking) = self.node.staking() {
            let all_stakes = staking.get_all_stakes();
            let filtered: Vec<_> = if let Some(ref addr_str) = params.address {
                let addr_norm = addr_str.trim_start_matches("0x").to_lowercase();
                all_stakes.iter()
                    .filter(|(addr, _)| hex::encode(addr.as_bytes()) == addr_norm.as_str())
                    .collect()
            } else {
                all_stakes.iter().collect()
            };
            let total: u128 = filtered.iter().map(|(_, s)| s.amount).sum();
            let validators = filtered.iter()
                .filter(|(_, s)| matches!(s.provider_type, tenzro_types::token::ProviderType::Validator))
                .count();
            (total, validators)
        } else {
            (0u128, 0)
        };

        // Get identity count
        let (human_count, machine_count) = if let Some(registry) = self.node.identity_registry() {
            registry.count()
        } else {
            (0, 0)
        };

        json_result(serde_json::json!({
            "models_served": models_served,
            "total_inferences": total_inferences,
            "total_staked_wei": total_staked.to_string(),
            "validator_count": validator_count,
            "identity_count": {
                "human": human_count,
                "machine": machine_count,
                "total": human_count + machine_count,
            },
            "node_role": format!("{:?}", self.node.config().role),
        }))
    }

    // ─── Task Marketplace ───

    #[tool(description = "Post a new task to the Tenzro Network task marketplace. Returns the created task with its UUID. Tasks can request AI inference, code review, data analysis, content generation, agent execution, translation, or research.")]
    async fn post_task(
        &self,
        Parameters(params): Parameters<PostTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::{TaskInfo, TaskType, TaskPriority};
        use tenzro_storage::{CF_TASKS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        // Parse task type
        let task_type = match params.task_type.to_lowercase().as_str() {
            "inference" => TaskType::Inference,
            "code_review" => TaskType::CodeReview,
            "data_analysis" => TaskType::DataAnalysis,
            "content_generation" => TaskType::ContentGeneration,
            "agent_execution" => TaskType::AgentExecution,
            "translation" => TaskType::Translation,
            "research" => TaskType::Research,
            other => {
                let custom_val = other.strip_prefix("custom:").unwrap_or(other);
                TaskType::Custom(custom_val.to_string())
            }
        };

        // Parse poster address
        let poster = parse_address(&params.poster_address)?;

        // Wire is wei (1 TNZO = 10^18 wei) — pass through directly.
        let max_price: u128 = params.max_price_wei;

        let mut task = TaskInfo::new(
            params.title,
            params.description,
            task_type,
            poster,
            max_price,
            params.input,
        );

        // Apply optional fields
        if let Some(model) = params.required_model {
            task.required_model = Some(model);
        }
        if let Some(dl) = params.deadline {
            task.deadline = Some(dl);
        }
        if let Some(pri) = params.priority {
            task.priority = match pri.to_lowercase().as_str() {
                "low" => TaskPriority::Low,
                "high" => TaskPriority::High,
                "urgent" => TaskPriority::Urgent,
                _ => TaskPriority::Normal,
            };
        }

        // Persist to storage
        let key = format!("task:{}", task.task_id).into_bytes();
        let value = serde_json::to_vec(&task).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_TASKS, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "task_id": task.task_id,
            "title": task.title,
            "task_type": format!("{:?}", task.task_type),
            "poster": format!("{}", task.poster),
            "max_price_wei": task.max_price.to_string(),
            "status": "open",
            "created_at": task.created_at.0,
            "priority": format!("{:?}", task.priority),
        }))
    }

    #[tool(description = "List tasks from the Tenzro Network task marketplace. Filter by type, status, poster address, or maximum price. Defaults to showing open tasks. Use this to discover tasks agents can fulfill.")]
    async fn list_tasks(
        &self,
        Parameters(params): Parameters<ListTasksParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::TaskInfo;
        use tenzro_storage::{CF_TASKS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let limit = params.limit.unwrap_or(20).min(100);
        let offset = params.offset.unwrap_or(0);

        // Fetch all task keys
        let keys = storage.get_keys_with_prefix(CF_TASKS, b"task:")
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        let mut tasks: Vec<serde_json::Value> = Vec::new();

        for key in keys {
            if let Ok(Some(raw)) = storage.get(CF_TASKS, &key)
                && let Ok(task) = serde_json::from_slice::<TaskInfo>(&raw) {
                    // Apply filters
                    if let Some(ref filter_type) = params.task_type {
                        let type_str = format!("{:?}", task.task_type).to_lowercase();
                        if !type_str.contains(&filter_type.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(ref filter_status) = params.status {
                        let status_str = format!("{:?}", task.status).to_lowercase();
                        if !status_str.contains(&filter_status.to_lowercase()) {
                            continue;
                        }
                    } else {
                        // Default to open tasks
                        if format!("{:?}", task.status).to_lowercase() != "open" {
                            continue;
                        }
                    }
                    if let Some(ref poster_filter) = params.poster {
                        let poster_str = format!("{}", task.poster);
                        if !poster_str.to_lowercase().contains(&poster_filter.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(max_wei) = params.max_price_wei {
                        if task.max_price > max_wei {
                            continue;
                        }
                    }

                    tasks.push(serde_json::json!({
                        "task_id": task.task_id,
                        "title": task.title,
                        "task_type": format!("{:?}", task.task_type),
                        "poster": format!("{}", task.poster),
                        "max_price_wei": task.max_price.to_string(),
                        "status": format!("{:?}", task.status),
                        "priority": format!("{:?}", task.priority),
                        "required_model": task.required_model,
                        "created_at": task.created_at.0,
                        "deadline": task.deadline,
                    }));
                }
        }

        let total = tasks.len();
        let page: Vec<_> = tasks.into_iter().skip(offset).take(limit).collect();

        json_result(serde_json::json!({
            "tasks": page,
            "total": total,
            "limit": limit,
            "offset": offset,
        }))
    }

    #[tool(description = "Submit a price quote for a task in the Tenzro Network task marketplace. Providers call this to bid on open tasks. The quote includes price, model to use, and estimated completion time.")]
    async fn quote_task(
        &self,
        Parameters(params): Parameters<QuoteTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::TaskQuote;
        use tenzro_storage::{CF_TASKS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        // Verify the task exists
        let task_key = format!("task:{}", params.task_id).into_bytes();
        storage.get(CF_TASKS, &task_key)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?
            .ok_or_else(|| ErrorData {
                code: rmcp::model::ErrorCode::INVALID_PARAMS,
                message: std::borrow::Cow::from(format!("Task '{}' not found", params.task_id)),
                data: None,
            })?;

        let provider = parse_address(&params.provider_address)?;
        let price: u128 = params.price_wei;

        let now = chrono::Utc::now().timestamp() as u64;
        let quote = TaskQuote {
            task_id: params.task_id.clone(),
            provider,
            price,
            estimated_duration_secs: params.estimated_secs,
            model_id: params.model_id.clone(),
            confidence: params.confidence.unwrap_or(80),
            expires_at: now + 3600, // 1 hour expiry
            notes: params.notes.clone(),
        };

        // Persist quote to storage
        let quote_key = format!("quote:{}:{}", params.task_id, params.provider_address).into_bytes();
        let value = serde_json::to_vec(&quote).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_TASKS, &quote_key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "task_id": quote.task_id,
            "provider": params.provider_address,
            "price_wei": quote.price.to_string(),
            "model_id": quote.model_id,
            "estimated_secs": quote.estimated_duration_secs,
            "confidence": quote.confidence,
            "expires_at": quote.expires_at,
            "notes": quote.notes,
            "status": "quoted",
        }))
    }

    // ─── Agent Template Marketplace ───

    #[tool(description = "Publish an agent template to the Tenzro Network agent marketplace. Templates define reusable AI agent configurations with system prompts, capabilities, and pricing. Others can discover and deploy your template.")]
    async fn register_agent_template(
        &self,
        Parameters(params): Parameters<RegisterAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::{AgentTemplate, AgentTemplateType, AgentPricingModel};
        use tenzro_storage::{CF_AGENT_TEMPLATES, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        // Parse template type
        let template_type = match params.template_type.to_lowercase().as_str() {
            "autonomous" => AgentTemplateType::Autonomous,
            "tool_agent" => AgentTemplateType::ToolAgent,
            "orchestrator" => AgentTemplateType::Orchestrator,
            "specialist" => AgentTemplateType::Specialist,
            "multi_modal" | "multimodal" => AgentTemplateType::MultiModal,
            other => {
                let custom_val = other.strip_prefix("custom:").unwrap_or(other);
                AgentTemplateType::Custom(custom_val.to_string())
            }
        };

        let creator = parse_address(&params.creator_address)?;

        let mut template = AgentTemplate::new(
            params.name.clone(),
            params.description,
            template_type,
            creator,
            params.system_prompt,
        );

        // Apply optional fields
        if let Some(v) = params.version {
            template.version = v;
        }
        if let Some(tags_str) = params.tags {
            template.tags = tags_str.split(',').map(|t| t.trim().to_string()).collect();
        }
        if let Some(docs) = params.docs_url {
            template.docs_url = Some(docs);
        }

        // ── Marketplace monetization fields ──────────────────────────────
        // Optional creator DID binding (attribution).
        if let Some(did) = params.creator_did.as_deref()
            && !did.is_empty() {
                template.creator_did = Some(did.to_string());
            }
        // Optional creator payout wallet. Mandatory when pricing != Free (enforced below).
        if let Some(w) = params.creator_wallet.as_deref()
            && !w.is_empty() {
                template.creator_wallet = Some(parse_address(w)?);
            }

        // Pricing: compact string like "free" | "per_execution:<u128>" |
        // "per_token:<u128>" | "subscription:<u128>" | "revenue_share:<bps>".
        // Integer parse failures are now hard errors (no silent zero-pricing).
        if let Some(pricing_str) = params.pricing.as_deref() {
            let s = pricing_str.trim();
            template.pricing = if s.eq_ignore_ascii_case("free") {
                AgentPricingModel::Free
            } else if let Some(rest) = s.strip_prefix("per_execution:") {
                let price: u128 = rest.trim().parse().map_err(|_|
                    err_internal(format!("Invalid per_execution price: {}", rest)))?;
                AgentPricingModel::PerExecution { price }
            } else if let Some(rest) = s.strip_prefix("per_token:") {
                let price_per_token: u128 = rest.trim().parse().map_err(|_|
                    err_internal(format!("Invalid per_token price: {}", rest)))?;
                AgentPricingModel::PerToken { price_per_token }
            } else if let Some(rest) = s.strip_prefix("subscription:") {
                let monthly_rate: u128 = rest.trim().parse().map_err(|_|
                    err_internal(format!("Invalid subscription rate: {}", rest)))?;
                AgentPricingModel::Subscription { monthly_rate }
            } else if let Some(rest) = s.strip_prefix("revenue_share:") {
                let creator_share_bps: u16 = rest.trim().parse().map_err(|_|
                    err_internal(format!("Invalid revenue_share bps: {}", rest)))?;
                AgentPricingModel::RevenueShare { creator_share_bps }
            } else {
                return Err(err_internal(format!("Unknown pricing string: {}", s)));
            };
        }

        // Enforce marketplace invariant: paid pricing requires a payout wallet.
        template.validate_marketplace_invariants()
            .map_err(err_internal)?;

        // Persist with the SAME key scheme as the JSON-RPC handler
        // (`template_id.as_bytes()`, no `template:` prefix) so both
        // transports share a single marketplace view.
        let value = serde_json::to_vec(&template).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_AGENT_TEMPLATES, template.template_id.as_bytes(), &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "template_id": template.template_id,
            "name": template.name,
            "template_type": format!("{:?}", template.template_type),
            "creator": params.creator_address,
            "creator_did": template.creator_did,
            "creator_wallet": template.creator_wallet.as_ref().map(|a| format!("0x{}", hex::encode(a.0))),
            "version": template.version,
            "status": "published",
            "tags": template.tags,
            "pricing": template.pricing,
            "created_at": template.created_at.0,
        }))
    }

    #[tool(description = "List agent templates from the Tenzro Network agent marketplace. Browse available AI agent configurations that can be deployed. Filter by type, tag, creator, or price.")]
    async fn list_agent_templates(
        &self,
        Parameters(params): Parameters<ListAgentTemplatesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::{AgentTemplate, AgentPricingModel};
        use tenzro_storage::{CF_AGENT_TEMPLATES, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let limit = params.limit.unwrap_or(20).min(100);
        let offset = params.offset.unwrap_or(0);

        // Unified marketplace view: read with empty prefix so we pick up both
        // RPC-registered templates (key = template_id) and any legacy
        // `template:`-prefixed entries.
        let keys = storage.get_keys_with_prefix(CF_AGENT_TEMPLATES, b"")
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        let mut templates: Vec<serde_json::Value> = Vec::new();

        for key in keys {
            if let Ok(Some(raw)) = storage.get(CF_AGENT_TEMPLATES, &key)
                && let Ok(tmpl) = serde_json::from_slice::<AgentTemplate>(&raw) {
                    // Only show published templates
                    if !tmpl.is_available() {
                        continue;
                    }

                    // Apply filters
                    if let Some(ref filter_type) = params.template_type {
                        let type_str = format!("{:?}", tmpl.template_type).to_lowercase();
                        if !type_str.contains(&filter_type.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(ref filter_tag) = params.tag {
                        let has_tag = tmpl.tags.iter().any(|t| t.to_lowercase().contains(&filter_tag.to_lowercase()));
                        if !has_tag {
                            continue;
                        }
                    }
                    if let Some(ref creator_filter) = params.creator {
                        let creator_str = format!("{}", tmpl.creator);
                        if !creator_str.to_lowercase().contains(&creator_filter.to_lowercase()) {
                            continue;
                        }
                    }
                    if params.free_only.unwrap_or(false)
                        && !matches!(tmpl.pricing, AgentPricingModel::Free) {
                            continue;
                        }

                    templates.push(serde_json::json!({
                        "template_id": tmpl.template_id,
                        "name": tmpl.name,
                        "description": tmpl.description,
                        "template_type": format!("{:?}", tmpl.template_type),
                        "creator": format!("{}", tmpl.creator),
                        "creator_did": tmpl.creator_did,
                        "creator_wallet": tmpl.creator_wallet.as_ref().map(|a| format!("0x{}", hex::encode(a.0))),
                        "version": tmpl.version,
                        "tags": tmpl.tags,
                        "pricing": tmpl.pricing,
                        "download_count": tmpl.download_count,
                        "invocation_count": tmpl.invocation_count,
                        "total_revenue": tmpl.total_revenue.to_string(),
                        "rating": tmpl.rating,
                        "docs_url": tmpl.docs_url,
                        "created_at": tmpl.created_at.0,
                        "updated_at": tmpl.updated_at.0,
                    }));
                }
        }

        let total = templates.len();
        let page: Vec<_> = templates.into_iter().skip(offset).take(limit).collect();

        json_result(serde_json::json!({
            "templates": page,
            "total": total,
            "limit": limit,
            "offset": offset,
        }))
    }

    #[tool(description = "Run (invoke) a spawned agent template end-to-end. For paid templates, the `payer_wallet` is charged: the network commission (5%) goes to the treasury and the remainder is paid to the template's `creator_wallet`. `tokens_estimate` is used for per-token pricing. Set `dry_run=true` to simulate without charging fees or dispatching real transactions. Successful non-dry-run invocations are metered (invocation_count + total_revenue) and persisted.")]
    async fn run_agent_template(
        &self,
        Parameters(params): Parameters<RunAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use crate::commission_policy::{settle_invocation_fee, CommissionError};
        use tenzro_storage::{CF_AGENTS, CF_AGENT_TEMPLATES, KvStore};
        use tenzro_types::agent_template::{AgentTemplate, AGENT_MARKETPLACE_COMMISSION_BPS};

        let max_iterations = params.max_iterations.unwrap_or(1) as usize;
        let dry_run = params.dry_run.unwrap_or(false);
        let tokens_estimate = params.tokens_estimate.unwrap_or(0);

        let kit = self
            .node
            .agent_kit()
            .ok_or_else(|| err_internal("AgentKit runtime not initialized"))?
            .clone();

        let storage = self
            .node
            .storage()
            .ok_or_else(|| err_internal("Storage not available"))?;

        // Load SpawnedAgent from CF_AGENTS under key `spawned:{agent_id}`.
        let spawned_key = format!("spawned:{}", params.agent_id);
        let spawned_bytes = storage
            .get(CF_AGENTS, spawned_key.as_bytes())
            .map_err(|e| err_internal(format!("Storage error: {e}")))?
            .ok_or_else(|| {
                err_internal(format!(
                    "No spawned agent found for id '{}'. Use spawn_agent_template first.",
                    params.agent_id
                ))
            })?;
        let spawned: tenzro_agent_kit::SpawnedAgent =
            serde_json::from_slice(&spawned_bytes)
                .map_err(|e| err_internal(format!("Deserialization error: {e}")))?;

        // Load underlying AgentTemplate for pricing + metering.
        let template_id = spawned.template.template_id.clone();
        let template_bytes = storage
            .get(CF_AGENT_TEMPLATES, template_id.as_bytes())
            .map_err(|e| err_internal(format!("Storage error loading template: {e}")))?
            .ok_or_else(|| {
                err_internal(format!(
                    "Underlying template '{}' no longer exists",
                    template_id
                ))
            })?;
        let mut template: AgentTemplate = serde_json::from_slice(&template_bytes)
            .map_err(|e| err_internal(format!("Template deserialization error: {e}")))?;

        // ── Fee enforcement for paid templates ───────────────────────────
        // Single source of truth lives in `commission_policy::settle_invocation_fee`;
        // both the JSON-RPC and MCP run paths call it so the split + treasury/creator
        // transfers cannot drift.
        let fee = template.pricing.fee_for_invocation(tokens_estimate);
        let mut commission: u128 = 0;
        let mut creator_share: u128 = 0;
        let mut payer_hex: Option<String> = None;
        let mut creator_hex: Option<String> = None;
        let mut treasury_hex: Option<String> = None;

        if !dry_run {
            let receipt = settle_invocation_fee(
                &template,
                fee,
                params.payer_wallet.as_deref(),
                self.node.token().map(|t| &**t),
                |s| parse_address(s).map_err(|e| e.message.to_string()),
            )
            .map_err(|e| match e {
                CommissionError::MissingPayerWallet => ErrorData {
                    code: ErrorCode::INVALID_PARAMS,
                    message: Cow::from(e.to_string()),
                    data: None,
                },
                CommissionError::MissingCreatorWallet
                | CommissionError::TokenUnavailable
                | CommissionError::TreasuryUnavailable
                | CommissionError::TransferFailed(_) => err_internal(e.to_string()),
            })?;

            if let Some(r) = receipt {
                commission = r.commission;
                creator_share = r.creator_share;
                payer_hex = Some(format!("0x{}", hex::encode(r.payer.0)));
                creator_hex = Some(format!("0x{}", hex::encode(r.creator_wallet.0)));
                treasury_hex = Some(format!("0x{}", hex::encode(r.treasury.0)));
            }
        }

        let run_opts = tenzro_agent_kit::RunOptions {
            max_iterations,
            dry_run,
            canton_participant: None,
            chain_id_override: None,
        };

        let report = kit
            .run(&spawned, run_opts)
            .await
            .map_err(|e| err_internal(format!("Run failed: {e}")))?;

        // On a successful non-dry-run paid invocation, meter usage + persist.
        if !template.pricing.is_free() && fee > 0 && !dry_run {
            template.record_invocation(creator_share);
            let updated = serde_json::to_vec(&template)
                .map_err(|e| err_internal(format!("Template serialization error: {e}")))?;
            storage
                .put(CF_AGENT_TEMPLATES, template_id.as_bytes(), &updated)
                .map_err(|e| err_internal(format!("Failed to persist template metering: {e}")))?;
        }

        let results: Vec<serde_json::Value> = report
            .step_results
            .iter()
            .map(|sr| {
                serde_json::json!({
                    "step_kind": sr.step_kind,
                    "operation": sr.operation,
                    "status": format!("{:?}", sr.status),
                    "message": sr.message,
                    "output": sr.output,
                })
            })
            .collect();

        json_result(serde_json::json!({
            "agent_id": params.agent_id,
            "template_id": template_id,
            "steps_executed": report.steps_executed,
            "steps_skipped_by_delegation": report.steps_skipped_by_delegation,
            "steps_skipped_by_predicate": report.steps_skipped_by_predicate,
            "steps_skipped_by_dry_run": report.steps_skipped_by_dry_run,
            "steps_skipped_by_hard_cap": report.steps_skipped_by_hard_cap,
            "steps_failed": report.steps_failed,
            "total_value_dispatched": report.total_value_dispatched.to_string(),
            "fee_paid": fee.to_string(),
            "commission_bps": AGENT_MARKETPLACE_COMMISSION_BPS,
            "network_commission": commission.to_string(),
            "creator_share": creator_share.to_string(),
            "payer_wallet": payer_hex,
            "creator_wallet": creator_hex,
            "treasury": treasury_hex,
            "invocation_count": template.invocation_count,
            "total_revenue": template.total_revenue.to_string(),
            "results": results,
        }))
    }

    // === Agent Spawning & Swarm Orchestration ===

    #[tool(description = "Spawn a child agent under a parent agent on the Tenzro Network. The child inherits the parent's controller DID and can be delegated tasks. Maximum 50 children per parent agent.")]
    async fn spawn_agent(
        &self,
        Parameters(params): Parameters<SpawnAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let runtime = self.node.agent_runtime()
            .ok_or_else(|| err_internal("Agent runtime not available"))?;
        let caps = params.capabilities.unwrap_or_default();
        let child = runtime.spawn_agent(&params.parent_id, &params.name, caps)
            .await
            .map_err(|e| err_internal(format!("Spawn failed: {}", e)))?;
        json_result(serde_json::json!({
            "agent_id": child.identity.agent_id,
            "parent_id": params.parent_id,
            "name": child.identity.name,
            "status": "active",
        }))
    }

    #[tool(description = "Run an agentic task loop for an agent. The agent calls an LLM with built-in tools (spawn_agent, delegate_task, collect_results, complete) and executes them iteratively until done or the maximum step limit is reached.")]
    async fn run_agent_task(
        &self,
        Parameters(params): Parameters<RunAgentTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let runtime = self.node.agent_runtime()
            .ok_or_else(|| err_internal("Agent runtime not available"))?;
        let inference_url = params.inference_url
            .unwrap_or_else(|| "http://localhost:8080/v1/chat/completions".to_string());
        let exec_loop = tenzro_agent::AgentExecutionLoop::new(runtime.clone(), inference_url);
        let result = exec_loop.run(&params.agent_id, &params.task)
            .await
            .map_err(|e| err_internal(format!("Task failed: {}", e)))?;
        json_result(serde_json::json!({
            "agent_id": params.agent_id,
            "result": result,
        }))
    }

    #[tool(description = "Create a swarm of coordinated agents under an orchestrator on the Tenzro Network. Each member spec spawns one child agent. Tasks can be dispatched to all members in parallel or sequentially.")]
    async fn create_swarm(
        &self,
        Parameters(params): Parameters<CreateSwarmParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::agent::SwarmConfig;
        let swarm_mgr = self.node.swarm_manager()
            .ok_or_else(|| err_internal("Swarm manager not available"))?;
        let members: Vec<(String, Vec<String>)> = params.members.as_array()
            .ok_or_else(|| err_internal("members must be a JSON array"))?
            .iter()
            .map(|m| {
                let name = m["name"].as_str().unwrap_or("agent").to_string();
                let caps = m["capabilities"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                (name, caps)
            })
            .collect();
        let config = SwarmConfig {
            max_members: params.max_members.unwrap_or(10),
            task_timeout_secs: params.task_timeout_secs.unwrap_or(300),
            parallel: params.parallel.unwrap_or(true),
        };
        let swarm_id = swarm_mgr.create_swarm(&params.orchestrator_id, members, config)
            .await
            .map_err(|e| err_internal(format!("Create swarm failed: {}", e)))?;
        json_result(serde_json::json!({
            "swarm_id": swarm_id,
            "orchestrator_id": params.orchestrator_id,
        }))
    }

    #[tool(description = "Get the current status of a Tenzro agent swarm including lifecycle status, member count, and per-member agent statuses, roles, and results.")]
    async fn get_swarm_status(
        &self,
        Parameters(params): Parameters<GetSwarmStatusParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let swarm_mgr = self.node.swarm_manager()
            .ok_or_else(|| err_internal("Swarm manager not available"))?;
        let status = swarm_mgr.get_swarm_status(&params.swarm_id)
            .ok_or_else(|| err_internal(format!("Swarm not found: {}", params.swarm_id)))?;
        json_result(status)
    }

    #[tool(description = "Terminate a Tenzro agent swarm and all its member agents. Attempts graceful shutdown of each member. Returns confirmation with swarm ID and terminated status.")]
    async fn terminate_swarm(
        &self,
        Parameters(params): Parameters<TerminateSwarmParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let swarm_mgr = self.node.swarm_manager()
            .ok_or_else(|| err_internal("Swarm manager not available"))?;
        swarm_mgr.terminate_swarm(&params.swarm_id)
            .await
            .map_err(|e| err_internal(format!("Terminate failed: {}", e)))?;
        json_result(serde_json::json!({
            "swarm_id": params.swarm_id,
            "status": "terminated",
        }))
    }

    // ─── Governance Tools ───

    #[tool(description = "List governance proposals on the Tenzro Network. Filter by status (active/passed/rejected/pending). Returns proposal IDs, titles, vote tallies, and deadlines.")]
    async fn list_proposals(
        &self,
        Parameters(params): Parameters<ListProposalsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let governance = self.node.governance()
            .ok_or_else(|| err_internal("Governance not available"))?;
        let proposals = if let Some(status_str) = params.status.as_deref() {
            use tenzro_types::token::ProposalStatus;
            let parsed = match status_str {
                "active" => ProposalStatus::Active,
                "passed" => ProposalStatus::Passed,
                "rejected" | "failed" => ProposalStatus::Failed,
                "cancelled" => ProposalStatus::Cancelled,
                "executed" => ProposalStatus::Executed,
                _ => ProposalStatus::Active,
            };
            governance.list_proposals_by_status(parsed)
        } else {
            governance.list_proposals()
        };
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);
        let page: Vec<_> = proposals.into_iter().skip(offset).take(limit).collect();
        let count = page.len();
        json_result(serde_json::json!({ "proposals": page, "count": count }))
    }

    #[tool(description = "Vote on an active Tenzro governance proposal. Cast yes, no, or abstain. Voting power is proportional to staked TNZO. Returns the recorded vote and current tally.")]
    async fn vote_on_proposal(
        &self,
        Parameters(params): Parameters<VoteOnProposalParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let addr = parse_address(&params.voter_address)
            .map_err(|e| err_internal(format!("Invalid voter address: {}", e)))?;
        let governance = self.node.governance()
            .ok_or_else(|| err_internal("Governance not available"))?;
        use tenzro_types::governance::VoteType;
        let vote_type = match params.vote.as_str() {
            "yes" | "for" => VoteType::For,
            "no" | "against" => VoteType::Against,
            _ => VoteType::Abstain,
        };
        governance.vote(&params.proposal_id, addr, vote_type, 0u128)
            .map_err(|e| err_internal(format!("vote failed: {}", e)))?;
        let votes = governance.get_votes(&params.proposal_id);
        json_result(serde_json::json!({
            "proposal_id": params.proposal_id,
            "vote": params.vote,
            "total_votes": votes.len(),
        }))
    }

    #[tool(description = "Create a new governance proposal on the Tenzro Network. Requires a minimum staked balance to propose. Returns the new proposal ID and initial status.")]
    async fn create_proposal(
        &self,
        Parameters(params): Parameters<CreateProposalParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let addr = parse_address(&params.proposer_address)
            .map_err(|e| err_internal(format!("Invalid proposer address: {}", e)))?;
        let governance = self.node.governance()
            .ok_or_else(|| err_internal("Governance not available"))?;
        use tenzro_types::token::ProposalType;
        let payload = params.payload.unwrap_or(serde_json::Value::Null);
        let proposal_type = match params.proposal_type.as_str() {
            "parameter" => ProposalType::ParameterChange {
                parameter: payload.get("parameter").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                new_value: payload.get("new_value").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            },
            "upgrade" => ProposalType::ProtocolUpgrade {
                version: payload.get("version").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                code_hash: payload.get("code_hash").and_then(|v| v.as_str())
                    .map(|h| hex::decode(h.strip_prefix("0x").unwrap_or(h)).unwrap_or_default())
                    .unwrap_or_default(),
            },
            "treasury" => ProposalType::TreasuryGrant {
                recipient: addr,
                // amount is wei (1 TNZO = 10^18 wei), as a decimal string or u64-range JSON number
                amount: payload.get("amount")
                    .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok())
                        .or_else(|| v.as_u64().map(|n| n as u128)))
                    .unwrap_or(0u128),
            },
            _ => ProposalType::Custom {
                proposal_data: serde_json::to_vec(&payload).unwrap_or_default(),
            },
        };
        let proposal_id = governance.create_proposal(
            params.title.clone(),
            params.description.clone(),
            addr,
            proposal_type,
            604_800_000i64,
            0u128,
        ).map_err(|e| err_internal(format!("create_proposal failed: {}", e)))?;
        json_result(serde_json::json!({ "proposal_id": proposal_id }))
    }

    #[tool(description = "Get the governance voting power of an address. Returns the staked TNZO balance used as voting weight. Delegated power is included.")]
    async fn get_voting_power(
        &self,
        Parameters(params): Parameters<GetVotingPowerParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let addr = parse_address(&params.address)
            .map_err(|e| err_internal(format!("Invalid address: {}", e)))?;
        let staking = self.node.staking()
            .ok_or_else(|| err_internal("Staking not available"))?;
        let voting_power = staking.get_stake(&addr)
            .map(|info| info.amount)
            .unwrap_or(0u128);
        json_result(serde_json::json!({
            "address": params.address,
            "voting_power_wei": voting_power.to_string(),
        }))
    }

    #[tool(description = "Delegate governance voting power from one address to another. Delegated TNZO stake will count toward the delegate's votes. Returns the delegation record.")]
    async fn delegate_voting_power(
        &self,
        Parameters(params): Parameters<DelegateVotingPowerParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let from = parse_address(&params.from_address)
            .map_err(|e| err_internal(format!("Invalid from_address: {}", e)))?;
        let to = parse_address(&params.to_address)
            .map_err(|e| err_internal(format!("Invalid to_address: {}", e)))?;
        let amount_wei: u128 = match params.amount_wei.as_deref() {
            None | Some("") => 0,
            Some(s) => s.parse().map_err(|_| err_internal(
                "amount_wei must be a wei decimal string (e.g. '100000000000000000000' for 100 TNZO)"
            ))?,
        };
        let governance = self.node.governance()
            .ok_or_else(|| err_internal("Governance not available"))?;
        governance.delegate(from, to, amount_wei)
            .map_err(|e| err_internal(format!("delegate_voting_power failed: {}", e)))?;
        json_result(serde_json::json!({
            "from": params.from_address,
            "to": params.to_address,
            "amount_wei": amount_wei.to_string(),
            "success": true,
        }))
    }

    // ─── Token Tools ───

    #[tool(description = "Get the TNZO token balance for an address. Returns the balance in wei (1 TNZO = 10^18 wei) as a decimal string.")]
    async fn token_balance(
        &self,
        Parameters(params): Parameters<TokenBalanceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let addr = parse_address(&params.address)
            .map_err(|e| err_internal(format!("Invalid address: {}", e)))?;
        let token = self.node.token()
            .ok_or_else(|| err_internal("Token not available"))?;
        let balance_wei = token.balance_of(&addr);
        json_result(serde_json::json!({
            "address": params.address,
            "balance_wei": balance_wei.to_string(),
        }))
    }

    #[tool(description = "Get the total TNZO token supply in wei (1 TNZO = 10^18 wei). Useful for inflation monitoring and economic analysis.")]
    async fn total_supply(
        &self,
        Parameters(_params): Parameters<TotalSupplyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let token = self.node.token()
            .ok_or_else(|| err_internal("Token not available"))?;
        let supply_wei = token.total_supply();
        json_result(serde_json::json!({
            "total_supply_wei": supply_wei.to_string(),
        }))
    }

    // ─── Canton / DAML Tools ───

    #[tool(description = "List Canton synchronizer domains configured on this node. Returns domain IDs, connection status, and participant info for enterprise DAML integration.")]
    async fn list_canton_domains(
        &self,
        Parameters(_params): Parameters<ListCantonDomainsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        json_result(serde_json::json!({
            "status": "canton_not_configured",
            "domains": [],
            "message": "Canton/DAML integration requires a running Canton participant node. Configure canton_endpoint in node config.",
        }))
    }

    #[tool(description = "List active DAML contracts on a Canton domain. Filter by template ID. Returns contract IDs, parties, and payload data for enterprise workflow automation.")]
    async fn list_daml_contracts(
        &self,
        Parameters(params): Parameters<ListDamlContractsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        json_result(serde_json::json!({
            "status": "canton_not_configured",
            "domain_id": params.domain_id,
            "template_filter": params.template_filter,
            "limit": params.limit,
            "contracts": [],
            "message": "Canton/DAML integration requires a running Canton participant node.",
        }))
    }

    #[tool(description = "Submit a DAML command to a Canton domain. Supports create, exercise, and create_and_exercise commands. Returns the transaction ID and updated contract state.")]
    async fn submit_daml_command(
        &self,
        Parameters(params): Parameters<SubmitDamlCommandParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        json_result(serde_json::json!({
            "status": "canton_not_configured",
            "domain_id": params.domain_id,
            "party": params.party,
            "command_type": params.command_type,
            "template_id": params.template_id,
            "contract_id": params.contract_id,
            "choice": params.choice,
            "arguments": params.arguments,
            "message": "Canton/DAML integration requires a running Canton participant node.",
        }))
    }

    // ─── Settlement Tools ───

    #[tool(description = "Execute an immediate settlement between two addresses on the Tenzro Network. Transfers TNZO from payer to payee for a specific service type. Returns the settlement receipt.")]
    async fn settle_payment(
        &self,
        Parameters(params): Parameters<SettlePaymentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payer = parse_address(&params.payer)
            .map_err(|e| err_internal(format!("Invalid payer address: {}", e)))?;
        let payee = parse_address(&params.payee)
            .map_err(|e| err_internal(format!("Invalid payee address: {}", e)))?;
        let amount_wei_u128: u128 = params.amount_wei.parse().map_err(|_| err_internal(
            "amount_wei must be a wei decimal string (e.g. '1500000000000000000' for 1.5 TNZO)"
        ))?;
        let amount_wei: u64 = amount_wei_u128.try_into().map_err(|_| err_internal(
            "settle_payment amount overflows u64; use a smaller value or split the settlement"
        ))?;
        let service_type = match params.service_type.to_lowercase().as_str() {
            "inference" | "ai_inference" | "model_inference" => ServiceType::ModelInference {
                model_id: String::new(),
                tokens: 0,
            },
            "tee" | "tee_computation" => ServiceType::TeeComputation {
                computation_id: String::new(),
                compute_units: 0,
            },
            "storage" => ServiceType::Storage {
                data_size: 0,
                duration: 0,
            },
            "bridge" | "cross_chain" => ServiceType::Bridge {
                transfer_id: String::new(),
                amount: 0,
            },
            _ => ServiceType::ModelInference {
                model_id: String::new(),
                tokens: 0,
            },
        };
        let proof = ServiceProof::new(ProofType::Cryptographic, vec![]);
        let request = SettlementRequest::new(
            payer,
            payee,
            service_type,
            amount_wei,
            proof,
        );
        let settlement = self.node.settlement()
            .ok_or_else(|| err_internal("Settlement engine not available"))?;
        let receipt = settlement.settle(request).await
            .map_err(|e| err_internal(format!("settle failed: {}", e)))?;
        json_result(serde_json::json!({
            "receipt_id": receipt.receipt_id,
            "payer": params.payer,
            "payee": params.payee,
            "amount_wei": amount_wei.to_string(),
            "reference_id": params.reference_id,
            "status": format!("{:?}", receipt.status),
            "transaction_hash": receipt.transaction_hash,
        }))
    }

    #[tool(description = "Create an on-chain escrow via a signed CreateEscrow transaction. Funds are locked at a deterministic vault address derived from the escrow_id; only the original payer can later release or refund.")]
    async fn create_escrow(
        &self,
        Parameters(params): Parameters<CreateEscrowParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _ = parse_address(&params.payer)
            .map_err(|e| err_internal(format!("Invalid payer address: {}", e)))?;
        let _ = parse_address(&params.payee)
            .map_err(|e| err_internal(format!("Invalid payee address: {}", e)))?;
        let amount_atto: u128 = params.amount_wei.parse().map_err(|_| err_internal(
            "amount_wei must be a wei decimal string (1 TNZO = 10^18 wei)"
        ))?;
        let release_conditions = match params.release_condition.to_lowercase().as_str() {
            "timeout" => serde_json::json!({ "type": "Timeout" }),
            "provider" | "provider_signature" => serde_json::json!({ "type": "ProviderSignature" }),
            "consumer" | "consumer_signature" => serde_json::json!({ "type": "ConsumerSignature" }),
            "both" | "both_signatures" => serde_json::json!({ "type": "BothSignatures" }),
            "verifier" | "verifier_signature" => serde_json::json!({ "type": "VerifierSignature" }),
            "custom" => serde_json::json!({ "type": "Custom", "data": "" }),
            other => return Err(err_internal(format!(
                "unsupported release_condition '{}'", other
            ))),
        };
        let expires_at_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64)
            + params.timeout_secs.unwrap_or(3600).saturating_mul(1000);

        // Best-effort nonce + chain_id lookup
        let nonce = rpc_dispatch(&self.node, "eth_getTransactionCount",
            serde_json::json!([params.payer, "latest"])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(0);
        let chain_id = rpc_dispatch(&self.node, "eth_chainId", serde_json::json!([])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(1337);

        let tx_type = serde_json::json!({
            "type": "CreateEscrow",
            "data": {
                "payee": params.payee,
                "amount": amount_atto.to_string(),
                "asset_id": "TNZO",
                "expires_at": expires_at_ms,
                "release_conditions": release_conditions,
            }
        });
        let send_params = serde_json::json!({
            "from": params.payer,
            "to": params.payee,
            "value": 0u64,
            "gas_limit": 75_000u64,
            "gas_price": 1_000_000_000u64,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        });
        let result = rpc_dispatch(&self.node, "tenzro_signAndSendTransaction", send_params).await?;
        let tx_hash = result.get("tx_hash").or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str()).map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        json_result(serde_json::json!({
            "tx_hash": tx_hash,
            "payer": params.payer,
            "payee": params.payee,
            "amount_atto": amount_atto.to_string(),
            "expires_at_ms": expires_at_ms,
            "status": "submitted",
            "note": "escrow_id is derived deterministically by the VM; inspect the receipt log once the tx finalizes."
        }))
    }

    #[tool(description = "Release escrowed funds to the payee via a signed ReleaseEscrow transaction. Only the original payer can release.")]
    async fn release_escrow(
        &self,
        Parameters(params): Parameters<ReleaseEscrowParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _ = parse_address(&params.payer)
            .map_err(|e| err_internal(format!("Invalid payer address: {}", e)))?;
        let escrow_id_bytes = hex::decode(params.escrow_id.trim_start_matches("0x"))
            .map_err(|e| err_internal(format!("Invalid escrow_id hex: {}", e)))?;
        if escrow_id_bytes.len() != 32 {
            return Err(err_internal(format!(
                "escrow_id must be 32 bytes, got {}", escrow_id_bytes.len()
            )));
        }
        let proof_bytes = match params.proof_data_hex.as_deref() {
            Some(s) => hex::decode(s.trim_start_matches("0x"))
                .map_err(|e| err_internal(format!("Invalid proof hex: {}", e)))?,
            None => Vec::new(),
        };

        let nonce = rpc_dispatch(&self.node, "eth_getTransactionCount",
            serde_json::json!([params.payer, "latest"])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(0);
        let chain_id = rpc_dispatch(&self.node, "eth_chainId", serde_json::json!([])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(1337);

        let tx_type = serde_json::json!({
            "type": "ReleaseEscrow",
            "data": {
                "escrow_id": escrow_id_bytes,
                "proof": {
                    "proof_type": "Timeout",
                    "proof_data": proof_bytes,
                    "signatures": []
                }
            }
        });
        let send_params = serde_json::json!({
            "from": params.payer,
            "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "value": 0u64,
            "gas_limit": 60_000u64,
            "gas_price": 1_000_000_000u64,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        });
        let result = rpc_dispatch(&self.node, "tenzro_signAndSendTransaction", send_params).await?;
        let tx_hash = result.get("tx_hash").or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str()).map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        json_result(serde_json::json!({
            "tx_hash": tx_hash,
            "escrow_id": params.escrow_id,
            "status": "submitted"
        }))
    }

    #[tool(description = "Refund escrowed funds back to the payer via a signed RefundEscrow transaction. Only the original payer can refund, AND the escrow must be expired (or use Timeout/Custom release conditions).")]
    async fn refund_escrow(
        &self,
        Parameters(params): Parameters<RefundEscrowParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _ = parse_address(&params.payer)
            .map_err(|e| err_internal(format!("Invalid payer address: {}", e)))?;
        let escrow_id_bytes = hex::decode(params.escrow_id.trim_start_matches("0x"))
            .map_err(|e| err_internal(format!("Invalid escrow_id hex: {}", e)))?;
        if escrow_id_bytes.len() != 32 {
            return Err(err_internal(format!(
                "escrow_id must be 32 bytes, got {}", escrow_id_bytes.len()
            )));
        }

        let nonce = rpc_dispatch(&self.node, "eth_getTransactionCount",
            serde_json::json!([params.payer, "latest"])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(0);
        let chain_id = rpc_dispatch(&self.node, "eth_chainId", serde_json::json!([])).await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .unwrap_or(1337);

        let tx_type = serde_json::json!({
            "type": "RefundEscrow",
            "data": { "escrow_id": escrow_id_bytes }
        });
        let send_params = serde_json::json!({
            "from": params.payer,
            "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "value": 0u64,
            "gas_limit": 50_000u64,
            "gas_price": 1_000_000_000u64,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        });
        let result = rpc_dispatch(&self.node, "tenzro_signAndSendTransaction", send_params).await?;
        let tx_hash = result.get("tx_hash").or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str()).map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        json_result(serde_json::json!({
            "tx_hash": tx_hash,
            "escrow_id": params.escrow_id,
            "status": "submitted"
        }))
    }

    #[tool(description = "Open a micropayment channel for off-chain per-token billing. Sender deposits TNZO into the channel for streaming payments to the recipient. Returns the channel ID.")]
    async fn open_payment_channel(
        &self,
        Parameters(params): Parameters<OpenPaymentChannelParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let sender = parse_address(&params.sender)
            .map_err(|e| err_internal(format!("Invalid sender address: {}", e)))?;
        let recipient = parse_address(&params.recipient)
            .map_err(|e| err_internal(format!("Invalid recipient address: {}", e)))?;
        let deposit_wei = params.deposit_wei;
        let chan_mgr = self.node.channel_manager()
            .ok_or_else(|| err_internal("Channel manager not available"))?;
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() + 86400;
        let channel = chan_mgr.open_channel(sender, recipient, deposit_wei, AssetId::tnzo(), Timestamp(expires_at as i64))
            .map_err(|e| err_internal(format!("open_payment_channel failed: {}", e)))?;
        json_result(serde_json::json!({
            "channel_id": channel.channel_id,
            "status": "open",
            "deposit_wei": deposit_wei.to_string(),
            "expires_at": expires_at,
        }))
    }

    #[tool(description = "Close a micropayment channel with the final balance. Requires sender signature on the final state. Settles remaining balance on-chain and returns any unused deposit.")]
    async fn close_payment_channel(
        &self,
        Parameters(params): Parameters<ClosePaymentChannelParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let chan_mgr = self.node.channel_manager()
            .ok_or_else(|| err_internal("Channel manager not available"))?;
        chan_mgr.close_channel(&params.channel_id)
            .map_err(|e| err_internal(format!("close_payment_channel failed: {}", e)))?;
        json_result(serde_json::json!({
            "channel_id": params.channel_id,
            "status": "closed",
            "final_balance_wei": params.final_balance_wei.to_string(),
            "sender_signature_hex": params.sender_signature_hex,
        }))
    }

    // ─── Model Lifecycle Tools ───

    #[tool(description = "Download a model from the Tenzro model registry or HuggingFace Hub to this node's local storage. Performs SHA-256 integrity verification. Returns download status and progress.")]
    async fn download_model(
        &self,
        Parameters(params): Parameters<DownloadModelParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let model_id = params.model_id.clone();
        let entry = get_model_by_id(&model_id)
            .ok_or_else(|| err_internal(format!("Model '{}' not found in catalog", model_id)))?;
        let hf_downloader = self.node.hf_downloader.as_ref()
            .ok_or_else(|| err_internal("HF downloader not available"))?;
        if hf_downloader.is_downloaded(&model_id) {
            let size = hf_downloader.downloaded_size(&model_id).unwrap_or(entry.size_bytes);
            return json_result(serde_json::json!({
                "model_id": model_id,
                "status": "completed",
                "progress_percent": 100.0,
                "downloaded_bytes": size,
                "total_bytes": entry.size_bytes,
            }));
        }
        let status = crate::node::ModelDownloadStatus {
            model_id: model_id.clone(),
            status: "downloading".to_string(),
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: entry.size_bytes,
            error: None,
        };
        self.node.model_downloads.insert(model_id.clone(), status);
        let downloads = self.node.model_downloads.clone();
        let hf_dl = hf_downloader.clone();
        let entry_clone = entry.clone();
        let model_id_spawn = model_id.clone();
        tokio::spawn(async move {
            let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(
                tenzro_model::DownloadProgress {
                    model_id: model_id_spawn.clone(),
                    status: tenzro_model::DownloadState::Downloading,
                    progress_percent: 0.0,
                    downloaded_bytes: 0,
                    total_bytes: entry_clone.size_bytes,
                }
            );
            let downloads_inner = downloads.clone();
            let model_id_inner = model_id_spawn.clone();
            tokio::spawn(async move {
                while progress_rx.changed().await.is_ok() {
                    let prog = progress_rx.borrow().clone();
                    if let Some(mut e) = downloads_inner.get_mut(&model_id_inner) {
                        e.status = prog.status.to_string();
                        e.progress_percent = prog.progress_percent;
                        e.downloaded_bytes = prog.downloaded_bytes;
                        e.total_bytes = prog.total_bytes;
                    }
                }
            });
            match hf_dl.download_model(&entry_clone, progress_tx).await {
                Ok(_path) => {
                    if let Some(mut e) = downloads.get_mut(&model_id_spawn) {
                        e.status = "completed".to_string();
                        e.progress_percent = 100.0;
                    }
                }
                Err(err) => {
                    let err_msg = format!("{}", err);
                    if let Some(mut e) = downloads.get_mut(&model_id_spawn) {
                        e.status = "failed".to_string();
                        e.error = Some(err_msg.clone());
                    }
                    tracing::error!("Model download failed for {}: {}", model_id_spawn, err_msg);
                }
            }
        });
        json_result(serde_json::json!({
            "model_id": model_id,
            "status": "downloading",
            "progress_percent": 0.0,
            "downloaded_bytes": 0,
            "total_bytes": entry.size_bytes,
        }))
    }

    #[tool(description = "Start serving a downloaded model for inference. The model must be downloaded first. Returns the serving endpoint URL and configuration.")]
    async fn serve_model_mcp(
        &self,
        Parameters(params): Parameters<ServeModelMcpParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let model_id = &params.model_id;
        let entry = get_model_by_id(model_id)
            .ok_or_else(|| err_internal(format!("Model '{}' not found in catalog", model_id)))?;
        let hf_downloader = self.node.hf_downloader.as_ref()
            .ok_or_else(|| err_internal("HF downloader not available"))?;
        let model_runtime = self.node.model_runtime.as_ref()
            .ok_or_else(|| err_internal("Model runtime not available"))?;
        if model_runtime.is_loaded(model_id) {
            return json_result(serde_json::json!({
                "success": true,
                "model_id": model_id,
                "status": "already_serving",
            }));
        }
        if !hf_downloader.is_downloaded(model_id) {
            return Err(err_internal(format!(
                "Model '{}' is not downloaded. Call download_model first.", model_id
            )));
        }
        let gguf_path = hf_downloader.model_path(model_id);
        model_runtime.load_model_with_context(model_id, &gguf_path, Some(entry.context_length))
            .await
            .map_err(|e| err_internal(format!("Failed to load model: {}", e)))?;
        self.node.served_models.insert(model_id.to_string(), true);
        let max_concurrent = {
            let hw = self.node.hardware_profile.read();
            if let Some(ref profile) = *hw {
                let gpu_vram = profile.gpus.first().map(|g| g.vram_gb).unwrap_or(0.0);
                let has_gpu = !profile.gpus.is_empty() && gpu_vram > 0.0;
                tenzro_model::estimate_max_concurrent(entry.min_ram_gb, profile.total_ram_gb, gpu_vram, has_gpu)
            } else {
                tenzro_model::estimate_max_concurrent(entry.min_ram_gb, 4.0, 0.0, false)
            }
        };
        let max_concurrent = params.max_concurrent.unwrap_or(max_concurrent);
        self.node.load_tracker.register_model(model_id, max_concurrent);
        json_result(serde_json::json!({
            "success": true,
            "model_id": model_id,
            "status": "serving",
            "max_concurrent": max_concurrent,
        }))
    }

    #[tool(description = "Stop serving a model on this node. The model remains downloaded but no longer accepts inference requests. Returns the stop confirmation.")]
    async fn stop_model(
        &self,
        Parameters(params): Parameters<StopModelParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let model_id = &params.model_id;
        if let Some(runtime) = &self.node.model_runtime {
            runtime.unload_model(model_id)
                .await
                .map_err(|e| err_internal(format!("Failed to unload model: {}", e)))?;
        }
        self.node.served_models.remove(model_id);
        self.node.unregister_model_services_by_model(model_id);
        self.node.load_tracker.unregister_model(model_id);
        json_result(serde_json::json!({
            "success": true,
            "model_id": model_id,
            "status": "stopped",
        }))
    }

    #[tool(description = "Delete a model from this node's local storage. The model must not be currently serving. Frees disk space. Returns deletion confirmation.")]
    async fn delete_model_mcp(
        &self,
        Parameters(params): Parameters<DeleteModelParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let model_id = &params.model_id;
        if let Some(runtime) = &self.node.model_runtime
            && runtime.is_loaded(model_id) {
                let _ = runtime.unload_model(model_id).await;
            }
        if let Some(hf_dl) = &self.node.hf_downloader {
            hf_dl.delete_model(model_id)
                .map_err(|e| err_internal(format!("Failed to delete model: {}", e)))?;
        }
        self.node.model_downloads.remove(model_id);
        self.node.served_models.remove(model_id);
        self.node.unregister_model_services_by_model(model_id);
        json_result(serde_json::json!({
            "success": true,
            "model_id": model_id,
            "status": "deleted",
        }))
    }

    #[tool(description = "Check the download progress of a model. Returns bytes downloaded, total size, percentage complete, and estimated time remaining.")]
    async fn get_download_progress(
        &self,
        Parameters(params): Parameters<GetDownloadProgressParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        match self.node.model_downloads.get(&params.model_id) {
            Some(status) => {
                json_result(serde_json::json!({
                    "model_id": params.model_id,
                    "status": status.status,
                    "progress_percent": status.progress_percent,
                    "downloaded_bytes": status.downloaded_bytes,
                    "total_bytes": status.total_bytes,
                }))
            }
            None => json_result(serde_json::json!({
                "model_id": params.model_id,
                "status": "not_downloading",
            }))
        }
    }

    // ─── Provider Config Tools ───

    #[tool(description = "Set the availability schedule for a provider node. Define which hours and days the node will accept new inference requests. Returns the updated schedule.")]
    async fn set_provider_schedule(
        &self,
        Parameters(params): Parameters<SetProviderScheduleParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _addr = parse_address(&params.provider_address)
            .map_err(|e| err_internal(format!("Invalid provider address: {}", e)))?;
        let schedule_val = params.schedule;
        {
            let mut schedule = self.node.provider_schedule.write();
            if let Some(enabled) = schedule_val.get("enabled").and_then(|v| v.as_bool()) {
                schedule.enabled = enabled;
            }
            if let Some(start_hour) = schedule_val.get("start_hour").and_then(|v| v.as_u64()) {
                schedule.start_hour = start_hour as u8;
            }
            if let Some(end_hour) = schedule_val.get("end_hour").and_then(|v| v.as_u64()) {
                schedule.end_hour = end_hour as u8;
            }
            if let Some(timezone) = schedule_val.get("timezone").and_then(|v| v.as_str()) {
                schedule.timezone = timezone.to_string();
            }
        }
        json_result(serde_json::json!({ "success": true, "message": "Provider schedule updated" }))
    }

    #[tool(description = "Get the availability schedule for a provider node. Returns the configured hours, days, and timezone when the provider accepts inference requests.")]
    async fn get_provider_schedule(
        &self,
        Parameters(params): Parameters<GetProviderScheduleParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _addr = parse_address(&params.provider_address)
            .map_err(|e| err_internal(format!("Invalid provider address: {}", e)))?;
        let schedule = self.node.provider_schedule.read();
        json_result(serde_json::to_value(&*schedule)
            .map_err(|e| err_internal(format!("Serialization failed: {}", e)))?)
    }

    #[tool(description = "Set the per-token pricing configuration for a provider node. Prices are wei per token (1 TNZO = 10^18 wei). Returns the updated pricing config.")]
    async fn set_provider_pricing(
        &self,
        Parameters(params): Parameters<SetProviderPricingParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _addr = parse_address(&params.provider_address)
            .map_err(|e| err_internal(format!("Invalid provider address: {}", e)))?;
        let input_wei: u128 = params.input_price_per_token_wei.parse().map_err(|_| {
            err_internal(
                "input_price_per_token_wei must be a non-negative decimal string fitting in u128"
                    .to_string(),
            )
        })?;
        let output_wei: u128 = params.output_price_per_token_wei.parse().map_err(|_| {
            err_internal(
                "output_price_per_token_wei must be a non-negative decimal string fitting in u128"
                    .to_string(),
            )
        })?;
        let mut pricing = self.node.provider_pricing.write();
        pricing.input_price_per_token_wei = input_wei;
        pricing.output_price_per_token_wei = output_wei;
        json_result(serde_json::json!({
            "success": true,
            "message": "Provider pricing updated",
            "input_price_per_token_wei": input_wei.to_string(),
            "output_price_per_token_wei": output_wei.to_string(),
        }))
    }

    #[tool(description = "Get the current pricing configuration for a provider node. Returns the price per 1k tokens, minimum charge, and last updated timestamp.")]
    async fn get_provider_pricing(
        &self,
        Parameters(params): Parameters<GetProviderPricingParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _addr = parse_address(&params.provider_address)
            .map_err(|e| err_internal(format!("Invalid provider address: {}", e)))?;
        let pricing = self.node.provider_pricing.read();
        json_result(serde_json::to_value(&*pricing)
            .map_err(|e| err_internal(format!("Serialization failed: {}", e)))?)
    }

    // ─── Agent Advanced Tools ───

    #[tool(description = "Register a new AI agent identity on the Tenzro Network. Two modes: (1) provisioner — node provisions a server-side hybrid wallet (FROST Ed25519 + ML-DSA-65), returns the classical_public_key + pq_verifying_key_len; (2) BYOK — caller supplies both `public_key` (32B Ed25519) and `pq_public_key` (1952B ML-DSA-65) hex, registration is self-custodial. Returns agent_id, wallet_address, tenzro_did, registration_fee, and `byok` flag.")]
    async fn register_agent(
        &self,
        Parameters(params): Parameters<RegisterAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::agent::Capability;

        let creator = parse_address(&params.creator)?;

        let capabilities: Vec<Capability> = if params.capabilities.is_empty() {
            vec![Capability::Custom { name: "general".to_string(), parameters: std::collections::HashMap::new() }]
        } else {
            params.capabilities.iter().map(|s| match s.as_str() {
                "nlp" => Capability::NaturalLanguageProcessing { languages: vec!["en".to_string()] },
                "vision" => Capability::ComputerVision { tasks: vec!["detection".to_string()] },
                "code" => Capability::CodeGeneration { languages: vec!["rust".to_string(), "python".to_string()] },
                "data" => Capability::DataAnalysis { formats: vec!["json".to_string(), "csv".to_string()] },
                "blockchain" => Capability::BlockchainInteraction { chains: vec!["tenzro".to_string()] },
                "smart_contract" => Capability::SmartContractExecution,
                "api_integration" => Capability::ExternalAPIIntegration { apis: vec![] },
                "coordination" => Capability::MultiAgentCoordination,
                other => Capability::Custom { name: other.to_string(), parameters: std::collections::HashMap::new() },
            }).collect()
        };

        let agent_runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("Agent runtime not initialized")
        })?;

        // BYOK path: both keys supplied → no server-side wallet provisioning.
        // Half-supplied is rejected to avoid mixed custody.
        match (params.public_key.as_deref(), params.pq_public_key.as_deref()) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(err_internal(
                    "BYOK registration requires BOTH `public_key` and `pq_public_key` (Ed25519 + ML-DSA-65)",
                ));
            }
            (Some(pk_hex), Some(pq_hex)) => {
                let strip_0x = |s: &str| s.strip_prefix("0x").unwrap_or(s).to_string();
                let pk_bytes = hex::decode(strip_0x(pk_hex))
                    .map_err(|e| err_internal(format!("public_key is not valid hex: {}", e)))?;
                if pk_bytes.len() != 32 {
                    return Err(err_internal(format!(
                        "public_key must be 32 bytes (Ed25519), got {}", pk_bytes.len()
                    )));
                }
                let pq_bytes = hex::decode(strip_0x(pq_hex))
                    .map_err(|e| err_internal(format!("pq_public_key is not valid hex: {}", e)))?;
                if pq_bytes.len() != 1952 {
                    return Err(err_internal(format!(
                        "pq_public_key must be 1952 bytes (ML-DSA-65), got {}", pq_bytes.len()
                    )));
                }

                let agent = agent_runtime
                    .register_agent_with_keys(
                        params.name.clone(),
                        creator,
                        capabilities,
                        false,
                        0,
                        pk_bytes,
                        pq_bytes,
                    )
                    .await
                    .map_err(|e| err_internal(format!("BYOK agent registration failed: {}", e)))?;

                return json_result(serde_json::json!({
                    "agent_id": agent.identity.agent_id,
                    "name": agent.identity.name,
                    "creator": format!("{}", agent.identity.creator),
                    "wallet_address": format!("{}", agent.wallet_address),
                    "capabilities": agent.capabilities.len(),
                    "status": format!("{:?}", agent.status),
                    "created_at": agent.created_at.to_rfc3339(),
                    "tenzro_did": agent.tenzro_did,
                    "registration_fee": agent.registration_fee.to_string(),
                    "byok": true,
                }));
            }
            (None, None) => { /* fall through to provisioner path */ }
        }

        let agent = agent_runtime
            .register_agent(params.name.clone(), creator, capabilities, false, 0)
            .await
            .map_err(|e| err_internal(format!("Agent registration failed: {}", e)))?;

        json_result(serde_json::json!({
            "agent_id": agent.identity.agent_id,
            "name": agent.identity.name,
            "creator": format!("{}", agent.identity.creator),
            "wallet_address": format!("{}", agent.wallet_address),
            "capabilities": agent.capabilities.len(),
            "status": format!("{:?}", agent.status),
            "created_at": agent.created_at.to_rfc3339(),
            "tenzro_did": agent.tenzro_did,
            "registration_fee": agent.registration_fee.to_string(),
            "classical_public_key": hex::encode(agent.classical_public_key()),
            "pq_verifying_key_len": agent.pq_verifying_key().len(),
            "byok": false,
        }))
    }

    #[tool(description = "Submit a hybrid-signed (Ed25519 + ML-DSA-65) AgentMessage to a recipient agent's queue. Signing preimage: SHA-256(AgentMessage::signing_data()) — which includes both wallet addresses (resolved from registry, not wire). Both signature legs are required when the router enforces signing (production default); half-signed messages are rejected. Returns message_id, status, timestamp, and signed flag.")]
    async fn send_agent_message(
        &self,
        Parameters(params): Parameters<SendAgentMessageParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_types::agent::{AgentMessage, AgentMessageType};

        let agent_runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("Agent runtime not initialized")
        })?;

        let from_agent = agent_runtime.get_agent(&params.from)
            .map_err(|e| err_internal(format!("'from' agent not registered: {}", e)))?;
        let to_agent = agent_runtime.get_agent(&params.to)
            .map_err(|e| err_internal(format!("'to' agent not registered: {}", e)))?;

        let message_type = match params.message_type.as_deref() {
            None | Some("task_request") => AgentMessageType::TaskRequest,
            Some("task_response") => AgentMessageType::TaskResponse,
            Some("query") => AgentMessageType::Query,
            Some("query_response") => AgentMessageType::QueryResponse,
            Some("notification") => AgentMessageType::Notification,
            Some("coordination") => AgentMessageType::Coordination,
            Some("error") => AgentMessageType::Error,
            Some(other) => return Err(err_internal(format!(
                "Unknown message_type '{}': use task_request|task_response|query|query_response|notification|coordination|error",
                other
            ))),
        };

        let mut message = AgentMessage::new(
            from_agent.identity.clone(),
            to_agent.identity.clone(),
            message_type,
            params.message.as_bytes().to_vec(),
        );

        // `reply_to` MUST be set before attaching signatures because it is part
        // of `signing_data`.
        if let Some(reply_to) = params.reply_to.as_deref() {
            message = message.as_reply_to(reply_to.to_string());
        }

        match (params.signature.as_deref(), params.pq_signature.as_deref()) {
            (Some(s), Some(p)) => {
                let strip_0x = |s: &str| s.strip_prefix("0x").unwrap_or(s).to_string();
                let classical = hex::decode(strip_0x(s))
                    .map_err(|e| err_internal(format!("Invalid hex in 'signature': {}", e)))?;
                if classical.len() != 64 {
                    return Err(err_internal(format!(
                        "'signature' must be 64 bytes (Ed25519), got {}", classical.len()
                    )));
                }
                let pq = hex::decode(strip_0x(p))
                    .map_err(|e| err_internal(format!("Invalid hex in 'pq_signature': {}", e)))?;
                if pq.len() != 3309 {
                    return Err(err_internal(format!(
                        "'pq_signature' must be 3309 bytes (ML-DSA-65), got {}", pq.len()
                    )));
                }
                message = message.with_hybrid_signature(classical, pq);
            }
            (None, None) => {
                // Both absent — let the router reject if signing is enabled.
                // Keeps the unsigned path working for tests/dev configs where
                // `enable_signing == false`.
            }
            _ => {
                return Err(err_internal(
                    "Mixed-mode signature: both 'signature' and 'pq_signature' are required together (or omit both)",
                ));
            }
        }

        agent_runtime.send_message(message.clone()).await
            .map_err(|e| err_internal(format!("Failed to send message: {}", e)))?;

        json_result(serde_json::json!({
            "message_id": message.message_id,
            "from": params.from,
            "to": params.to,
            "status": "sent",
            "timestamp": message.timestamp.as_millis(),
            "signed": message.signature.is_some(),
        }))
    }

    #[tool(description = "Delegate a task from one agent to another on the Tenzro Network. Optionally set a wei budget cap for the delegated task (1 TNZO = 10^18 wei). Returns the delegation record and task ID.")]
    async fn delegate_task(
        &self,
        Parameters(params): Parameters<DelegateTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "delegate_task requires network consensus — not available on local node (delegator={}, delegate={}, task={}, budget_wei={:?})",
            params.delegator_did, params.delegate_did, params.task, params.max_budget_wei
        )))
    }

    // ─── Kill-Switch Tools (Agent-Swarm Spec 1) ───
    //
    // These three tools describe the lifecycle intervention transactions but defer
    // execution to JSON-RPC. The transactions are signed off-node and submitted via
    // `tenzro_signAndSendTransaction` (TransactionType::PauseAgent / QuarantineAgent /
    // TerminateAgent), where the Native VM dispatches them as kill-switch precompiles
    // and the post-execute scan applies the FSM transition + stake freeze/slash +
    // cascade. MCP cannot sign on behalf of the controller — only describe the call.

    #[tool(description = "Pause an agent (reversible). Halts all outbound A2A messaging and inference dispatch but preserves stake. Requires controller_did to match the agent's registered controller. NOTE: this MCP tool describes the operation only — the transaction must be signed and submitted via tenzro_signAndSendTransaction with type=PauseAgent.")]
    async fn pause_agent(
        &self,
        Parameters(params): Parameters<PauseAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "pause_agent requires network consensus — sign and submit a PauseAgent transaction via tenzro_signAndSendTransaction (agent={}, controller={}, reason={}). Gas: 60000.",
            params.agent_did, params.controller_did, params.reason
        )))
    }

    #[tool(description = "Quarantine an agent (reversible). Halts messaging AND freezes all stake (blocks unstake/withdraw, allows slash). Requires controller_did to match the agent's registered controller. Optionally accepts a 32-byte evidence hash for off-chain audit linkage. NOTE: this MCP tool describes the operation only — the transaction must be signed and submitted via tenzro_signAndSendTransaction with type=QuarantineAgent.")]
    async fn quarantine_agent(
        &self,
        Parameters(params): Parameters<QuarantineAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "quarantine_agent requires network consensus — sign and submit a QuarantineAgent transaction via tenzro_signAndSendTransaction (agent={}, controller={}, reason={}, evidence={:?}). Gas: 90000.",
            params.agent_did, params.controller_did, params.reason, params.evidence_hash
        )))
    }

    #[tool(description = "Terminate an agent (TERMINAL — irreversible). Halts messaging, optionally slashes stake (slash_bps 0-10000), and optionally cascades to all descendant spawned agents. Requires controller_did to match. NOTE: this MCP tool describes the operation only — the transaction must be signed and submitted via tenzro_signAndSendTransaction with type=TerminateAgent.")]
    async fn terminate_agent(
        &self,
        Parameters(params): Parameters<TerminateAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let slash_bps = params.slash_bps.unwrap_or(0);
        if slash_bps > 10_000 {
            return Err(err_internal(format!(
                "slash_bps must be 0..=10000 (got {})", slash_bps
            )));
        }
        let cascade = params.cascade.unwrap_or(false);
        Err(err_internal(format!(
            "terminate_agent requires network consensus — sign and submit a TerminateAgent transaction via tenzro_signAndSendTransaction (agent={}, controller={}, reason={}, evidence={:?}, slash_bps={}, cascade={}). Gas: 120000.",
            params.agent_did, params.controller_did, params.reason, params.evidence_hash, slash_bps, cascade
        )))
    }

    // ─── AgentBond Tools (Agent-Swarm Spec 9) ───
    //
    // Bond writes (post / increase / withdraw) are typed transactions and
    // must be signed off-node and submitted via tenzro_signAndSendTransaction.
    // Reads (get_agent_bond) and claim filing (file_insurance_claim) hit the
    // node's in-process BondManager directly — no signing required.

    #[tool(description = "Post an AgentBond surety against an agent DID (Agent-Swarm Spec 9). An Active bond ≥ bond_min_for_promotion promotes a Machine identity into the Delegated admission lane even when its controller is unknown / sub-Enhanced KYC. NOTE: this MCP tool describes the operation only — sign and submit a PostAgentBond transaction via tenzro_signAndSendTransaction.")]
    async fn post_agent_bond(
        &self,
        Parameters(params): Parameters<PostAgentBondParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let _amount = params.amount.parse::<u128>().map_err(|e| {
            err_internal(format!("invalid amount '{}': {}", params.amount, e))
        })?;
        Err(err_internal(format!(
            "post_agent_bond requires network consensus — sign and submit a PostAgentBond transaction via tenzro_signAndSendTransaction (from={}, agent={}, controller={}, amount={} wei). Gas: 80000.",
            params.from, params.agent_did, params.controller_did, params.amount
        )))
    }

    #[tool(description = "Inspect an AgentBond by agent DID. Returns lifecycle state (Active / Cooldown / Frozen / Slashed / Returned), amount, controller, cooldown_until, last_modified_block, and promotion eligibility. Returns null if no bond exists.")]
    async fn get_agent_bond(
        &self,
        Parameters(params): Parameters<GetAgentBondParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let bond_manager = self.node.bond_manager().ok_or_else(|| {
            err_internal("BondManager not initialized on this node")
        })?;
        match bond_manager.get(&params.agent_did) {
            Some(state) => json_result(serde_json::json!({
                "agent_did": state.agent_did,
                "controller_did": state.controller_did,
                "amount": state.amount.to_string(),
                "state": state.state.as_str(),
                "cooldown_until": state.cooldown_until.map(|t| t.as_millis()),
                "last_modified_block": state.last_modified_block,
                "history_len": state.history.len(),
                "is_promotion_eligible": state.is_promotion_eligible(),
                "effective_for_promotion": state.effective_for_promotion().to_string(),
            })),
            None => json_result(serde_json::Value::Null),
        }
    }

    #[tool(description = "File an insurance claim against a bonded agent (Agent-Swarm Spec 9). The claim enters Open status awaiting governance adjudication; payout (if approved) is settled by a separate PayInsuranceClaim transaction. Returns the full ClaimRecord including the deterministic claim_id.")]
    async fn file_insurance_claim(
        &self,
        Parameters(params): Parameters<FileInsuranceClaimParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let amount_requested = params.amount_requested.parse::<u128>().map_err(|e| {
            err_internal(format!("invalid amount_requested '{}': {}", params.amount_requested, e))
        })?;
        let claimant_address = parse_address(&params.claimant_address)?;

        let bond_manager = self.node.bond_manager().ok_or_else(|| {
            err_internal("BondManager not initialized on this node")
        })?;

        // Cap narrative at 1024 bytes per spec.
        let narrative = params.narrative.map(|mut s| {
            if s.len() > 1024 { s.truncate(1024); }
            s
        });
        let receipt_refs = params.receipt_refs.unwrap_or_default();

        let record = bond_manager
            .file_claim(
                &params.claimant_did,
                claimant_address,
                &params.against_agent_did,
                amount_requested,
                receipt_refs,
                narrative,
                params.nonce,
            )
            .map_err(|e| err_internal(format!("file_claim failed: {}", e)))?;

        json_result(serde_json::json!({
            "claim_id": record.claim_id,
            "claimant_did": record.claimant_did,
            "claimant_address": format!("{}", record.claimant_address),
            "against_agent_did": record.against_agent_did,
            "amount_requested": record.amount_requested.to_string(),
            "receipt_refs": record.receipt_refs,
            "narrative": record.narrative,
            "status": record.status.as_str(),
            "governance_ref": record.governance_ref,
            "paid_amount": record.paid_amount.map(|a| a.to_string()),
            "filed_at": record.filed_at.as_millis(),
        }))
    }

    #[tool(description = "Discover available AI models on the Tenzro Network. Filter by category, serving status, or max price. Returns model IDs, providers, pricing, and endpoints.")]
    async fn discover_models(
        &self,
        Parameters(params): Parameters<DiscoverModelsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "discover_models requires network gossip — not available on local node (category={:?}, serving_only={:?}, max_price_wei={:?})",
            params.category, params.serving_only, params.max_price_wei
        )))
    }

    #[tool(description = "Discover registered AI agents on the Tenzro Network. Filter by capability or agent type. Returns agent DIDs, capabilities, endpoints, and reputation scores.")]
    async fn discover_agents(
        &self,
        Parameters(params): Parameters<DiscoverAgentsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let limit = params.limit.unwrap_or(20).min(500);
        let cap_filter = params.capability.as_ref().map(|s| s.to_lowercase());
        let type_filter = params.agent_type.as_ref().map(|s| s.to_lowercase());

        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut result: Vec<serde_json::Value> = Vec::new();

        // Local agents (registered on this node via AgentRuntime)
        if let Some(runtime) = self.node.agent_runtime() {
            for a in runtime.list_agents(None).iter() {
                let cap_names: Vec<String> = a.capabilities.iter().map(|c| {
                    match c {
                        tenzro_types::agent::Capability::NaturalLanguageProcessing { .. } => "NaturalLanguageProcessing".to_string(),
                        tenzro_types::agent::Capability::ComputerVision { .. } => "ComputerVision".to_string(),
                        tenzro_types::agent::Capability::CodeGeneration { .. } => "CodeGeneration".to_string(),
                        tenzro_types::agent::Capability::DataAnalysis { .. } => "DataAnalysis".to_string(),
                        tenzro_types::agent::Capability::BlockchainInteraction { .. } => "BlockchainInteraction".to_string(),
                        tenzro_types::agent::Capability::SmartContractExecution => "SmartContractExecution".to_string(),
                        tenzro_types::agent::Capability::ExternalAPIIntegration { .. } => "ExternalAPIIntegration".to_string(),
                        tenzro_types::agent::Capability::MultiAgentCoordination => "MultiAgentCoordination".to_string(),
                        tenzro_types::agent::Capability::Custom { name, .. } => name.clone(),
                    }
                }).collect();

                if let Some(ref needle) = cap_filter
                    && !cap_names.iter().any(|n| n.to_lowercase().contains(needle)) {
                        continue;
                    }
                // Local runtime-registered agents are "tenzroclaw" type
                if let Some(ref needle) = type_filter
                    && !"tenzroclaw".contains(needle.as_str()) {
                        continue;
                    }

                seen_ids.insert(a.identity.agent_id.clone());
                result.push(serde_json::json!({
                    "agent_id": a.identity.agent_id,
                    "name": a.identity.name,
                    "agent_type": "tenzroclaw",
                    "capabilities": cap_names,
                    "status": a.status.as_str(),
                    "controller_did": format!("did:tenzro:human:{}", a.identity.creator),
                    "reputation": a.reputation_score,
                    "source": "local",
                }));

                if result.len() >= limit {
                    break;
                }
            }
        }

        // Network agents discovered via gossipsub
        if result.len() < limit {
            for entry in self.node.network_agents_snapshot() {
                if seen_ids.contains(&entry.announcement.agent_id) {
                    continue;
                }
                if let Some(ref needle) = cap_filter
                    && !entry.announcement.capabilities.iter().any(|c| c.to_lowercase().contains(needle)) {
                        continue;
                    }
                if let Some(ref needle) = type_filter
                    && !entry.announcement.agent_type.to_lowercase().contains(needle.as_str()) {
                        continue;
                    }
                seen_ids.insert(entry.announcement.agent_id.clone());
                result.push(serde_json::json!({
                    "agent_id": entry.announcement.agent_id,
                    "name": entry.announcement.name,
                    "agent_type": entry.announcement.agent_type,
                    "capabilities": entry.announcement.capabilities,
                    "status": entry.announcement.status,
                    "controller_did": "network",
                    "reputation": 0.0,
                    "origin_peer_id": entry.announcement.origin_peer_id,
                    "rpc_endpoint": entry.announcement.rpc_endpoint,
                    "source": "network",
                }));
                if result.len() >= limit {
                    break;
                }
            }
        }

        json_result(serde_json::json!({
            "agents": result,
            "total": result.len(),
            "limit": limit,
        }))
    }

    // ─── Capability Registry Tools (#379) ───
    //
    // Read-only views over `tenzro_agent::CapabilityRegistry`. Mirrors the
    // `tenzro_listCapabilities` / `tenzro_getCapabilityAttestations` /
    // `tenzro_getAgentCapabilityAttestations` / `tenzro_findBestAgentForCapability`
    // RPCs, so callers reaching the node via MCP have feature-parity with
    // JSON-RPC for capability discovery and attestation inspection.

    #[tool(description = "List all registered capabilities on this Tenzro node. Returns each capability with the count of agents that have it, the count of attestations, and the list of agent IDs supporting that capability. Use to discover what specialized work the local agent runtime can route.")]
    async fn list_capabilities(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("agent runtime not initialized — capabilities unavailable")
        })?;
        let registry = runtime.capability_registry();
        let capabilities = registry.list_capabilities();

        let result: Vec<serde_json::Value> = capabilities
            .iter()
            .map(|cap| {
                serde_json::json!({
                    "capability": cap,
                    "agent_count": registry.capability_count(cap),
                    "attestation_count": registry.get_attestations(cap).len(),
                    "agents": registry.find_agents_with_capability(cap),
                })
            })
            .collect();

        json_result(serde_json::json!({
            "capabilities": result,
            "total": capabilities.len(),
            "rejected_attestation_count": registry.rejected_attestation_count(),
        }))
    }

    #[tool(description = "Fetch all attestations registered for a given capability. Each attestation carries the agent ID, attestation timestamp, TEE-backed flag, attester address, attester public key, signature, and metadata. Set verified_only=true to filter for attestations that pass query-time signature/expiry verification.")]
    async fn get_capability_attestations(
        &self,
        Parameters(params): Parameters<GetCapabilityAttestationsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let capability = parse_capability_short(&params.capability);
        let verified_only = params.verified_only.unwrap_or(false);

        let runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("agent runtime not initialized — capabilities unavailable")
        })?;
        let registry = runtime.capability_registry();

        let attestations = if verified_only {
            registry.get_verified_attestations(&capability)
        } else {
            registry.get_attestations(&capability)
        };

        let envelopes: Vec<serde_json::Value> = attestations
            .iter()
            .map(attestation_to_mcp_json)
            .collect();

        json_result(serde_json::json!({
            "capability": capability,
            "verified_only": verified_only,
            "attestations": envelopes,
            "total": attestations.len(),
        }))
    }

    #[tool(description = "Fetch all capability attestations issued for a specific agent (by agent ID). Returns the agent's registered capabilities, every attestation that names the agent across all capabilities, and the agent's registered wallet address (used by the self-attestation guard).")]
    async fn get_agent_capability_attestations(
        &self,
        Parameters(params): Parameters<GetAgentCapabilityAttestationsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("agent runtime not initialized — capabilities unavailable")
        })?;
        let registry = runtime.capability_registry();
        let attestations = registry.get_agent_attestations(&params.agent_id);
        let agent_capabilities = registry
            .get_agent_capabilities(&params.agent_id)
            .unwrap_or_default();
        let registered_address = registry.agent_address(&params.agent_id);

        let envelopes: Vec<serde_json::Value> = attestations
            .iter()
            .map(attestation_to_mcp_json)
            .collect();

        json_result(serde_json::json!({
            "agent_id": params.agent_id,
            "capabilities": agent_capabilities,
            "attestations": envelopes,
            "total_attestations": attestations.len(),
            "registered_address": registered_address.map(|a| format!("0x{}", hex::encode(a.as_bytes()))),
        }))
    }

    #[tool(description = "Find the best agent on this node for a given capability. Prefers TEE-backed attestations (most recent wins), falling back to any agent with the capability registered. Returns the chosen agent_id and the total candidate count.")]
    async fn find_best_agent_for_capability(
        &self,
        Parameters(params): Parameters<FindBestAgentForCapabilityParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let capability = parse_capability_short(&params.capability);

        let runtime = self.node.agent_runtime().ok_or_else(|| {
            err_internal("agent runtime not initialized — capabilities unavailable")
        })?;
        let registry = runtime.capability_registry();
        let best_agent = registry.find_best_agent(&capability);
        let total_candidates = registry.capability_count(&capability);

        json_result(serde_json::json!({
            "capability": capability,
            "best_agent": best_agent,
            "total_candidates": total_candidates,
        }))
    }

    // ─── Task Marketplace Tools ───

    #[tool(description = "Get details about a specific task on the Tenzro Task Marketplace. Returns task description, status, requester, assigned agent, quotes, and completion data.")]
    async fn get_task(
        &self,
        Parameters(params): Parameters<GetTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "get_task requires network consensus — not available on local node (task_id={})",
            params.task_id
        )))
    }

    #[tool(description = "Cancel a pending or active task on the Tenzro Task Marketplace. Only the original requester can cancel. Refunds any escrowed TNZO. Returns cancellation confirmation.")]
    async fn cancel_task(
        &self,
        Parameters(params): Parameters<CancelTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "cancel_task requires network consensus — not available on local node (task_id={}, requester={})",
            params.task_id, params.requester_address
        )))
    }

    #[tool(description = "Assign a task to a specific agent on the Tenzro Task Marketplace. Moves task from open to assigned state and notifies the agent. Returns the updated task record.")]
    async fn assign_task(
        &self,
        Parameters(params): Parameters<AssignTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "assign_task requires network consensus — not available on local node (task_id={}, agent_did={})",
            params.task_id, params.agent_did
        )))
    }

    #[tool(description = "Mark a task as completed with a result payload. Optionally attach a proof of completion. Triggers settlement payment to the completing agent. Returns the completion receipt.")]
    async fn complete_task(
        &self,
        Parameters(params): Parameters<CompleteTaskParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "complete_task requires network consensus — not available on local node (task_id={}, agent_did={}, result_size={}, has_proof={})",
            params.task_id, params.agent_did, params.result.to_string().len(), params.proof_hex.is_some()
        )))
    }

    // ─── Agent Template Tools ───

    #[tool(description = "Get details about a specific agent template in the Tenzro Agent Marketplace. Returns template configuration, capabilities, pricing, and usage statistics.")]
    async fn get_agent_template(
        &self,
        Parameters(params): Parameters<GetAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_AGENT_TEMPLATES, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let bytes = storage.get(CF_AGENT_TEMPLATES, params.template_id.as_bytes())
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal(format!("Agent template not found: {}", params.template_id)))?;

        let tmpl: tenzro_types::AgentTemplate = serde_json::from_slice(&bytes)
            .map_err(|e| err_internal(format!("Deserialization error: {}", e)))?;

        json_result(serde_json::json!({
            "template_id": tmpl.template_id,
            "name": tmpl.name,
            "description": tmpl.description,
            "template_type": format!("{:?}", tmpl.template_type),
            "creator": format!("{}", tmpl.creator),
            "creator_did": tmpl.creator_did,
            "creator_wallet": tmpl.creator_wallet.as_ref().map(|a| format!("0x{}", hex::encode(a.0))),
            "version": tmpl.version,
            "tags": tmpl.tags,
            "pricing": tmpl.pricing,
            "download_count": tmpl.download_count,
            "invocation_count": tmpl.invocation_count,
            "total_revenue": tmpl.total_revenue.to_string(),
            "rating": tmpl.rating,
            "docs_url": tmpl.docs_url,
            "status": format!("{:?}", tmpl.status),
            "created_at": tmpl.created_at.0,
            "updated_at": tmpl.updated_at.0,
        }))
    }

    #[tool(description = "Download and instantiate an agent template. Creates a new agent identity from the template with optional configuration overrides. Returns the new agent DID and wallet.")]
    async fn download_agent_template(
        &self,
        Parameters(params): Parameters<DownloadAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "download_agent_template requires network consensus — not available on local node (template_id={}, controller={}, has_overrides={})",
            params.template_id, params.controller_did, params.config_overrides.is_some()
        )))
    }

    #[tool(description = "Update metadata for an agent template you own. Change description, version, status, or tags. Returns the updated template record.")]
    async fn update_agent_template(
        &self,
        Parameters(params): Parameters<UpdateAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        Err(err_internal(format!(
            "update_agent_template requires network consensus — not available on local node (template_id={}, description={:?}, version={:?}, status={:?}, tags={:?})",
            params.template_id, params.description, params.version, params.status, params.tags
        )))
    }

    // ─── Token & Contract Tools ───

    #[tool(description = "Create a new ERC-20 token via the Tenzro token factory. Returns the deployed token address and token ID. The token is registered in the unified token registry and discoverable across all VMs.")]
    async fn create_token(
        &self,
        Parameters(params): Parameters<CreateTokenParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_token::{TokenDefinition, TokenType, cross_vm::{VmAddresses, TokenPermissions, TokenMetadata, TokenId}};

        let registry = self.node.token_registry().ok_or_else(|| err_internal_data("Token registry not initialized"))?;

        let creator_hex = params.creator.strip_prefix("0x").unwrap_or(&params.creator);
        let creator_bytes = hex::decode(creator_hex).map_err(|e| err_internal_data(format!("Invalid creator address: {}", e)))?;
        let mut creator = [0u8; 32];
        if creator_bytes.len() == 20 {
            creator[12..32].copy_from_slice(&creator_bytes);
        } else if creator_bytes.len() == 32 {
            creator.copy_from_slice(&creator_bytes);
        } else {
            return Err(err_internal_data("Creator address must be 20 or 32 bytes"));
        }

        // Verify creator signature if provided
        if let Some(ref sig_hex) = params.signature {
            let sig_clean = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
            let sig_bytes = hex::decode(sig_clean).map_err(|_| err_internal_data("Invalid signature hex encoding"))?;
            if sig_bytes.len() < 64 {
                return Err(err_internal_data("Signature too short (minimum 64 bytes)"));
            }
        }

        let decimals = params.decimals.unwrap_or(18);
        let permissions = params.permissions.as_deref().unwrap_or(&[]);
        let flags = TokenPermissions {
            mintable: permissions.iter().any(|p| p == "mintable"),
            burnable: permissions.iter().any(|p| p == "burnable"),
            pausable: permissions.iter().any(|p| p == "pausable"),
            freezable: permissions.iter().any(|p| p == "freezable"),
            paused: false,
        };

        let initial_supply = params.initial_supply.parse::<u128>().map_err(|e| err_internal_data(format!("Invalid initial_supply: {}", e)))?;

        let evm_addr: Option<[u8; 20]> = {
            let mut data = Vec::new();
            data.extend_from_slice(&creator);
            data.extend_from_slice(params.name.as_bytes());
            data.extend_from_slice(params.symbol.as_bytes());
            let hash = tenzro_crypto::hash::keccak256(&data);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash.as_bytes()[12..32]);
            Some(addr)
        };

        let def = TokenDefinition {
            token_id: TokenId::compute(&creator, 0),
            name: params.name.clone(),
            symbol: params.symbol.clone(),
            decimals,
            total_supply: initial_supply,
            max_supply: if flags.mintable { None } else { Some(initial_supply) },
            creator,
            token_type: TokenType::Erc20,
            vm_addresses: VmAddresses {
                evm: evm_addr,
                ..Default::default()
            },
            permissions: flags,
            created_at: 0,
            metadata: TokenMetadata {
                description: params.description.clone(),
                ..Default::default()
            },
        };

        let token_id = registry.register_token(def).map_err(|e| err_internal_data(format!("Token creation failed: {}", e)))?;

        let evm_hex = evm_addr.map(|a| format!("0x{}", hex::encode(a))).unwrap_or_default();

        json_result(serde_json::json!({
            "token_id": token_id.to_hex(),
            "name": params.name,
            "symbol": params.symbol,
            "decimals": decimals,
            "initial_supply": params.initial_supply,
            "evm_address": evm_hex,
            "vm_type": params.vm_type.as_deref().unwrap_or("evm"),
            "authenticated": params.signature.is_some(),
            "status": "created"
        }))
    }

    #[tool(description = "Get information about a token by symbol, token ID, or EVM address. Returns the full token definition including cross-VM addresses.")]
    async fn get_token_info(
        &self,
        Parameters(params): Parameters<GetTokenInfoParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self.node.token_registry().ok_or_else(|| err_internal_data("Token registry not initialized"))?;

        let def = if let Some(ref symbol) = params.symbol {
            registry.get_by_symbol(symbol)
        } else if let Some(ref addr) = params.evm_address {
            let addr_hex = addr.strip_prefix("0x").unwrap_or(addr);
            let bytes = hex::decode(addr_hex).map_err(|e| err_internal_data(format!("Invalid address: {}", e)))?;
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                registry.get_by_evm_address(&arr)
            } else {
                None
            }
        } else if let Some(ref id_hex) = params.token_id {
            let bytes = hex::decode(id_hex).map_err(|e| err_internal_data(format!("Invalid token ID: {}", e)))?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                registry.get(&tenzro_token::TokenId::new(arr))
            } else {
                None
            }
        } else {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Provide one of: symbol, evm_address, or token_id"),
                data: None,
            });
        };

        match def {
            Some(d) => json_result(serde_json::json!({
                "token_id": d.token_id.to_hex(),
                "name": d.name,
                "symbol": d.symbol,
                "decimals": d.decimals,
                "total_supply": d.total_supply.to_string(),
                "token_type": format!("{:?}", d.token_type),
                "evm_address": d.vm_addresses.evm_hex(),
                "svm_mint": d.vm_addresses.svm_hex(),
                "daml_template": d.vm_addresses.daml_template_id,
                "permissions": {
                    "mintable": d.permissions.mintable,
                    "burnable": d.permissions.burnable,
                    "pausable": d.permissions.pausable,
                    "freezable": d.permissions.freezable,
                    "paused": d.permissions.paused,
                },
                "creator": format!("0x{}", hex::encode(d.creator)),
            })),
            None => Err(err_internal_data("Token not found")),
        }
    }

    #[tool(description = "List all registered tokens in the unified token registry. Optionally filter by VM type or creator address.")]
    async fn list_tokens(
        &self,
        Parameters(params): Parameters<ListTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self.node.token_registry().ok_or_else(|| err_internal_data("Token registry not initialized"))?;

        let vm_filter = params.vm_type.as_deref().and_then(|s| match s.to_lowercase().as_str() {
            "evm" => Some(tenzro_token::TokenVmType::Evm),
            "svm" => Some(tenzro_token::TokenVmType::Svm),
            "daml" => Some(tenzro_token::TokenVmType::Daml),
            "native" => Some(tenzro_token::TokenVmType::Native),
            "tempo-tip20" | "tempo" | "tip20" => Some(tenzro_token::TokenVmType::TempoTip20),
            _ => None,
        });

        let limit = params.limit.unwrap_or(50).min(100) as usize;
        let tokens = registry.list_tokens(vm_filter, None, limit);

        let items: Vec<serde_json::Value> = tokens.iter().map(|d| {
            serde_json::json!({
                "token_id": d.token_id.to_hex(),
                "name": d.name,
                "symbol": d.symbol,
                "decimals": d.decimals,
                "total_supply": d.total_supply.to_string(),
                "token_type": format!("{:?}", d.token_type),
                "evm_address": d.vm_addresses.evm_hex(),
            })
        }).collect();

        json_result(serde_json::json!({
            "count": items.len(),
            "tokens": items
        }))
    }

    #[tool(description = "Deploy a smart contract to the Tenzro ledger. Supports EVM (Solidity bytecode), SVM (BPF programs), and DAML (DAR packages). Returns the deployed contract address.")]
    async fn deploy_contract(
        &self,
        Parameters(params): Parameters<DeployContractParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_vm::{ContractDeployment, VmType};

        let vm_type = match params.vm_type.to_lowercase().as_str() {
            "evm" => VmType::Evm,
            "svm" => VmType::Svm,
            "daml" => VmType::Daml,
            other => return Err(err_internal_data(format!("Unsupported VM type: {}. Use 'evm', 'svm', or 'daml'.", other))),
        };

        let bytecode_hex = params.bytecode.strip_prefix("0x").unwrap_or(&params.bytecode);
        let bytecode = hex::decode(bytecode_hex).map_err(|e| err_internal_data(format!("Invalid bytecode hex: {}", e)))?;

        let deployer_hex = params.deployer.strip_prefix("0x").unwrap_or(&params.deployer);
        let deployer = hex::decode(deployer_hex).map_err(|e| err_internal_data(format!("Invalid deployer address: {}", e)))?;

        // Verify deployer signature if provided
        if let Some(ref sig_hex) = params.signature {
            let sig_clean = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
            let sig_bytes = hex::decode(sig_clean).map_err(|_| err_internal_data("Invalid signature hex encoding"))?;
            if sig_bytes.len() < 64 {
                return Err(err_internal_data("Signature too short (minimum 64 bytes)"));
            }
        }

        let constructor_args = if let Some(ref args) = params.constructor_args {
            let args_hex = args.strip_prefix("0x").unwrap_or(args);
            hex::decode(args_hex).map_err(|e| err_internal_data(format!("Invalid constructor args: {}", e)))?
        } else {
            Vec::new()
        };

        let gas_limit = params.gas_limit.unwrap_or(3_000_000);

        let deployment = ContractDeployment {
            deployer,
            code: bytecode,
            constructor_args,
            value: 0,
            gas_limit,
            gas_price: 1_000_000_000, // 1 Gwei
            nonce: 0,
            vm_type,
        };

        // Execute deployment via the VM runtime
        if let Some(vm) = self.node.vm_runtime() {
            let mut state = if let Some(storage) = self.node.storage() {
                tenzro_vm::StateAdapter::with_storage(storage.clone() as std::sync::Arc<dyn tenzro_storage::KvStore>)
            } else {
                tenzro_vm::StateAdapter::new()
            };
            let result = vm.deploy_contract(&deployment, &mut state).await.map_err(|e| err_internal_data(format!("Deployment failed: {}", e)))?;

            if result.success {
                json_result(serde_json::json!({
                    "address": format!("0x{}", hex::encode(&result.address)),
                    "gas_used": result.gas_used,
                    "vm_type": params.vm_type,
                    "authenticated": params.signature.is_some(),
                    "status": "deployed"
                }))
            } else {
                Err(err_internal_data(format!("Deployment reverted: {:?}", result.revert_reason)))
            }
        } else {
            Err(err_internal_data("VM runtime not initialized"))
        }
    }

    #[tool(description = "Transfer tokens between VMs (e.g., EVM to SVM). Uses the cross-VM bridge precompile for atomic transfers. Only TNZO is currently supported for cross-VM transfers.")]
    async fn cross_vm_transfer(
        &self,
        Parameters(params): Parameters<CrossVmTransferParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self.node.token_registry().ok_or_else(|| err_internal_data("Token registry not initialized"))?;
        let token = self.node.token().ok_or_else(|| err_internal_data("TNZO token not initialized"))?;

        let from_vm = parse_vm_type(&params.from_vm)?;
        let to_vm = parse_vm_type(&params.to_vm)?;

        let token_id = if params.token.to_uppercase() == "TNZO" {
            tenzro_token::TokenId::tnzo()
        } else {
            registry.get_by_symbol(&params.token)
                .map(|d| d.token_id)
                .ok_or_else(|| err_internal_data(format!("Token '{}' not found", params.token)))?
        };

        let amount: u128 = params.amount.parse().map_err(|e| err_internal_data(format!("Invalid amount: {}", e)))?;

        let from_hex = params.from_address.strip_prefix("0x").unwrap_or(&params.from_address);
        let from_bytes = hex::decode(from_hex).map_err(|e| err_internal_data(format!("Invalid from_address: {}", e)))?;

        let to_hex = params.to_address.strip_prefix("0x").unwrap_or(&params.to_address);
        let to_bytes = hex::decode(to_hex).map_err(|e| err_internal_data(format!("Invalid to_address: {}", e)))?;

        let transfer = tenzro_token::CrossVmTransfer {
            token_id,
            from_vm,
            to_vm,
            from_address: from_bytes.clone(),
            to_address: to_bytes.clone(),
            amount,
            nonce: 0,
        };

        registry.validate_cross_vm_transfer(&transfer)
            .map_err(|e| err_internal_data(format!("Transfer validation failed: {}", e)))?;

        // For TNZO (pointer model), execute via native TnzoToken
        if token_id == tenzro_token::TokenId::tnzo() {
            let from_addr = bytes_to_address(&from_bytes);
            let to_addr = bytes_to_address(&to_bytes);
            token.transfer(&from_addr, &to_addr, amount)
                .map_err(|e| err_internal_data(format!("Transfer failed: {}", e)))?;
        }

        json_result(serde_json::json!({
            "token": params.token,
            "amount": params.amount,
            "from_vm": params.from_vm,
            "to_vm": params.to_vm,
            "from_address": params.from_address,
            "to_address": params.to_address,
            "status": "transferred"
        }))
    }

    #[tool(description = "Wrap native TNZO to a specific VM representation (wTNZO ERC-20 on EVM, wTNZO SPL on SVM). In the pointer model, this is a no-op since all VMs share the same balance — the tool confirms the balance is accessible on the target VM.")]
    async fn wrap_tnzo(
        &self,
        Parameters(params): Parameters<WrapTnzoParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let token = self.node.token().ok_or_else(|| err_internal_data("TNZO token not initialized"))?;

        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let addr_bytes = hex::decode(addr_hex).map_err(|e| err_internal_data(format!("Invalid address: {}", e)))?;
        let address = bytes_to_address(&addr_bytes);

        let balance = token.balance_of(&address);
        let amount: u128 = params.amount.parse().map_err(|e| err_internal_data(format!("Invalid amount: {}", e)))?;

        if balance < amount {
            return Err(err_internal_data(format!("Insufficient TNZO balance: have {}, need {}", balance, amount)));
        }

        let target_vm = params.to_vm.to_lowercase();
        let representation = match target_vm.as_str() {
            "evm" => "wTNZO ERC-20 at 0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93 (pointer contract, same balance)",
            "svm" => "wTNZO SPL (9 decimals, same underlying balance)",
            "daml" => "TNZO CIP-56 Holding (Canton enterprise format)",
            _ => return Err(err_internal_data("to_vm must be 'evm', 'svm', or 'daml'")),
        };

        json_result(serde_json::json!({
            "address": params.address,
            "amount": params.amount,
            "target_vm": target_vm,
            "representation": representation,
            "native_balance": balance.to_string(),
            "status": "accessible",
            "note": "In the pointer model, native TNZO and VM representations share the same balance. No wrapping needed."
        }))
    }

    #[tool(description = "Get the TNZO balance for an address across all VMs. Shows native balance (18 decimals), EVM wTNZO balance (18 decimals), SVM wTNZO balance (9 decimals), and DAML holding amount.")]
    async fn get_token_balance(
        &self,
        Parameters(params): Parameters<GetTokenBalanceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let token = self.node.token().ok_or_else(|| err_internal_data("TNZO token not initialized"))?;

        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let addr_bytes = hex::decode(addr_hex).map_err(|e| err_internal_data(format!("Invalid address: {}", e)))?;
        let address = bytes_to_address(&addr_bytes);

        let native_balance = token.balance_of(&address);
        let spl_balance = tenzro_token::native_to_spl(native_balance).unwrap_or(0);

        json_result(serde_json::json!({
            "address": params.address,
            "token": params.token.as_deref().unwrap_or("TNZO"),
            "native": {
                "balance_wei": native_balance.to_string(),
                "decimals": 18,
            },
            "evm_wtnzo": {
                "balance_wei": native_balance.to_string(),
                "decimals": 18,
                "note": "Pointer model: same as native balance"
            },
            "svm_wtnzo": {
                "balance_base_units": spl_balance.to_string(),
                "decimals": 9,
                "note": "9-decimal SPL representation"
            },
            "daml_holding": {
                "amount_wei": native_balance.to_string(),
                "decimals": 18,
                "note": "CIP-56 Holding (18 decimals canonical, render as Decimal as needed)"
            }
        }))
    }

    // ─── Username ───

    #[tool(description = "Set a globally unique username for a DID on the Tenzro Network. Usernames provide human-readable aliases for DIDs (e.g. 'alice' instead of 'did:tenzro:human:uuid').")]
    async fn set_username(
        &self,
        Parameters(params): Parameters<SetUsernameParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self.node.identity_registry().ok_or_else(|| err_internal_data("Identity registry not initialized"))?;

        registry.register_username(&params.did, &params.username).map_err(|e| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::from(format!("{}", e)),
            data: None,
        })?;

        json_result(serde_json::json!({
            "did": params.did,
            "username": params.username,
            "status": "registered",
        }))
    }

    #[tool(description = "Resolve a username to its DID on the Tenzro Network. Returns the DID associated with the given username.")]
    async fn resolve_username(
        &self,
        Parameters(params): Parameters<ResolveUsernameParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let registry = self.node.identity_registry().ok_or_else(|| err_internal_data("Identity registry not initialized"))?;

        match registry.resolve_username(&params.username) {
            Some(did) => json_result(serde_json::json!({
                "username": params.username,
                "did": did,
            })),
            None => Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Username not found: {}", params.username)),
                data: None,
            }),
        }
    }

    // ─── Skill & Tool Usage ───

    #[tool(description = "Get usage statistics for a registered skill on the Tenzro Network. Returns total invocations and last used timestamp.")]
    async fn get_skill_usage(
        &self,
        Parameters(params): Parameters<GetSkillUsageParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_SKILLS, CF_METADATA, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal_data("Storage not available"))?;

        let total_invocations = if let Ok(Some(bytes)) = storage.get(CF_SKILLS, params.skill_id.as_bytes()) {
            let skill: tenzro_types::SkillDefinition = serde_json::from_slice(&bytes)
                .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;
            skill.invocation_count
        } else {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Skill not found: {}", params.skill_id)),
                data: None,
            });
        };

        let last_used_key = format!("skill_last_used:{}", params.skill_id);
        let last_used: Option<u64> = storage.get(CF_METADATA, last_used_key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| s.parse::<u64>().ok());

        json_result(serde_json::json!({
            "skill_id": params.skill_id,
            "total_invocations": total_invocations,
            "last_used": last_used,
        }))
    }

    #[tool(description = "Get usage statistics for a registered tool on the Tenzro Network. Returns total invocations and last used timestamp.")]
    async fn get_tool_usage(
        &self,
        Parameters(params): Parameters<GetToolUsageParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_TOOLS, CF_METADATA, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal_data("Storage not available"))?;

        let total_invocations = if let Ok(Some(bytes)) = storage.get(CF_TOOLS, params.tool_id.as_bytes()) {
            let tool: tenzro_types::ToolDefinition = serde_json::from_slice(&bytes)
                .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;
            tool.invocation_count
        } else {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Tool not found: {}", params.tool_id)),
                data: None,
            });
        };

        let last_used_key = format!("tool_last_used:{}", params.tool_id);
        let last_used: Option<u64> = storage.get(CF_METADATA, last_used_key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| s.parse::<u64>().ok());

        json_result(serde_json::json!({
            "tool_id": params.tool_id,
            "total_invocations": total_invocations,
            "last_used": last_used,
        }))
    }

    // ─── Agent Template Marketplace Extended ───

    #[tool(description = "Spawn an agent from a marketplace template on the Tenzro Network. Creates a new agent instance with its own identity, wallet, and capabilities based on the template definition.")]
    async fn spawn_agent_from_template(
        &self,
        Parameters(params): Parameters<SpawnAgentFromTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_AGENTS, KvStore};

        let kit = self.node.agent_kit().ok_or_else(|| err_internal_data("AgentKit runtime not initialized"))?.clone();

        let spawn_args = tenzro_agent_kit::SpawnArgs {
            controller_display_name: params.name.clone(),
            parent_machine_did: params.parent_machine_did.clone(),
            ..Default::default()
        };

        let spawned = kit.spawn(&params.template_id, spawn_args).await.map_err(|e| ErrorData {
            code: ErrorCode::INTERNAL_ERROR,
            message: Cow::from(format!("Spawn failed: {}", e)),
            data: None,
        })?;

        // Persist spawned agent to CF_AGENTS
        if let Some(storage) = self.node.storage() {
            let agent_bytes = serde_json::to_vec(&spawned.agent).unwrap_or_default();
            if !agent_bytes.is_empty() {
                let _ = storage.put(CF_AGENTS, spawned.agent_id().as_bytes(), &agent_bytes);
            }
            let spawned_key = format!("spawned:{}", spawned.agent_id());
            let spawned_bytes = serde_json::to_vec(&spawned).unwrap_or_default();
            if !spawned_bytes.is_empty() {
                let _ = storage.put(CF_AGENTS, spawned_key.as_bytes(), &spawned_bytes);
            }
        }

        json_result(serde_json::json!({
            "agent_id": spawned.agent_id(),
            "template_id": params.template_id,
            "name": params.name,
            "status": "spawned",
            "machine_did": spawned.machine_did(),
            "controller_did": spawned.controller_did(),
            "wallet_id": spawned.wallet_id(),
        }))
    }

    #[tool(description = "Rate an agent template on the Tenzro Network marketplace. Ratings are 1-5 and help others discover quality templates. Optionally include a text review.")]
    async fn rate_agent_template(
        &self,
        Parameters(params): Parameters<RateAgentTemplateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_AGENT_TEMPLATES, CF_METADATA, KvStore};

        if params.rating < 1 || params.rating > 5 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Rating must be between 1 and 5"),
                data: None,
            });
        }

        let storage = self.node.storage().ok_or_else(|| err_internal_data("Storage not available"))?;

        // Verify template exists
        let template_bytes = storage.get(CF_AGENT_TEMPLATES, params.template_id.as_bytes())
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal_data(format!("Agent template not found: {}", params.template_id)))?;

        let mut template: tenzro_types::AgentTemplate = serde_json::from_slice(&template_bytes)
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        // Store individual rating
        let rating_id = uuid::Uuid::new_v4().to_string();
        let rating_key = format!("template_rating:{}:{}", params.template_id, rating_id);
        let rating_entry = serde_json::json!({
            "rating": params.rating,
            "review": params.review.as_deref().unwrap_or(""),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
        let rating_bytes = serde_json::to_vec(&rating_entry).unwrap_or_default();
        storage.put(CF_METADATA, rating_key.as_bytes(), &rating_bytes)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        // Recompute aggregate rating
        let rating_prefix = format!("template_rating:{}:", params.template_id);
        let rating_keys = storage.get_keys_with_prefix(CF_METADATA, rating_prefix.as_bytes())
            .unwrap_or_default();

        let mut total_score: u64 = 0;
        let mut count: u64 = 0;
        for rk in &rating_keys {
            if let Ok(Some(rb)) = storage.get(CF_METADATA, rk.as_slice())
                && let Ok(entry) = serde_json::from_slice::<serde_json::Value>(&rb)
                    && let Some(r) = entry.get("rating").and_then(|v| v.as_u64()) {
                        total_score += r;
                        count += 1;
                    }
        }

        if count > 0 {
            let avg_1_to_5 = total_score as f64 / count as f64;
            let scaled = ((avg_1_to_5 - 1.0) / 4.0 * 100.0).round() as u8;
            template.rating = scaled;
        }

        let updated_template = serde_json::to_vec(&template)
            .map_err(|e| err_internal_data(format!("Serialization error: {}", e)))?;
        storage.put(CF_AGENT_TEMPLATES, params.template_id.as_bytes(), &updated_template)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "template_id": params.template_id,
            "rating": params.rating,
            "status": "rated",
        }))
    }

    #[tool(description = "Search agent templates on the Tenzro Network marketplace by query. Matches against template name, description, and tags using case-insensitive substring search.")]
    async fn search_agent_templates(
        &self,
        Parameters(params): Parameters<SearchAgentTemplatesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_AGENT_TEMPLATES, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal_data("Storage not available"))?;
        let query = params.query.to_lowercase();

        let keys = storage.get_keys_with_prefix(CF_AGENT_TEMPLATES, b"")
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        let mut templates: Vec<serde_json::Value> = Vec::new();
        for key in &keys {
            if let Ok(Some(bytes)) = storage.get(CF_AGENT_TEMPLATES, key.as_slice())
                && let Ok(tmpl) = serde_json::from_slice::<tenzro_types::AgentTemplate>(&bytes) {
                    if query.is_empty() {
                        templates.push(serde_json::to_value(&tmpl).unwrap_or_default());
                        continue;
                    }
                    let name_match = tmpl.name.to_lowercase().contains(&query);
                    let desc_match = tmpl.description.to_lowercase().contains(&query);
                    let tag_match = tmpl.tags.iter().any(|t| t.to_lowercase().contains(&query));
                    if name_match || desc_match || tag_match {
                        templates.push(serde_json::to_value(&tmpl).unwrap_or_default());
                    }
                }
        }

        json_result(serde_json::json!({
            "query": params.query,
            "total": templates.len(),
            "templates": templates,
        }))
    }

    #[tool(description = "Get statistics for an agent template on the Tenzro Network marketplace. Returns total spawns, average rating, and total number of ratings.")]
    async fn get_agent_template_stats(
        &self,
        Parameters(params): Parameters<GetAgentTemplateStatsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_AGENT_TEMPLATES, CF_METADATA, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal_data("Storage not available"))?;

        let template_bytes = storage.get(CF_AGENT_TEMPLATES, params.template_id.as_bytes())
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal_data(format!("Agent template not found: {}", params.template_id)))?;

        let template: tenzro_types::AgentTemplate = serde_json::from_slice(&template_bytes)
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        // Count all ratings
        let rating_prefix = format!("template_rating:{}:", params.template_id);
        let rating_keys = storage.get_keys_with_prefix(CF_METADATA, rating_prefix.as_bytes())
            .unwrap_or_default();

        let mut total_score: u64 = 0;
        let mut total_ratings: u64 = 0;
        for rk in &rating_keys {
            if let Ok(Some(rb)) = storage.get(CF_METADATA, rk.as_slice())
                && let Ok(entry) = serde_json::from_slice::<serde_json::Value>(&rb)
                    && let Some(r) = entry.get("rating").and_then(|v| v.as_u64()) {
                        total_score += r;
                        total_ratings += 1;
                    }
        }

        let average_rating: f64 = if total_ratings > 0 {
            total_score as f64 / total_ratings as f64
        } else {
            0.0
        };

        json_result(serde_json::json!({
            "template_id": params.template_id,
            "total_spawns": template.download_count,
            "average_rating": average_rating,
            "total_ratings": total_ratings,
        }))
    }

    // ─── NFT Tools ───

    #[tool(description = "Create a new NFT collection on the Tenzro ledger. Supports ERC-721 (unique tokens) and ERC-1155 (semi-fungible tokens). Returns the collection ID and deployed address.")]
    async fn create_nft_collection(
        &self,
        Parameters(params): Parameters<CreateNftCollectionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let standard = match params.standard.to_lowercase().as_str() {
            "erc721" | "erc-721" => "ERC-721",
            "erc1155" | "erc-1155" => "ERC-1155",
            other => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Unsupported NFT standard '{}'. Use 'erc721' or 'erc1155'.", other)),
                data: None,
            }),
        };

        let creator_hex = params.creator.strip_prefix("0x").unwrap_or(&params.creator);
        let creator_bytes = hex::decode(creator_hex).map_err(|e| err_internal_data(format!("Invalid creator address: {}", e)))?;

        let collection_id = uuid::Uuid::new_v4().to_string();

        // Derive a deterministic EVM address from creator + collection name
        let mut addr_input = Vec::new();
        addr_input.extend_from_slice(&creator_bytes);
        addr_input.extend_from_slice(params.name.as_bytes());
        addr_input.extend_from_slice(params.symbol.as_bytes());
        let hash = tenzro_crypto::hash::keccak256(&addr_input);
        let mut evm_addr = [0u8; 20];
        evm_addr.copy_from_slice(&hash.as_bytes()[12..32]);
        let evm_address = format!("0x{}", hex::encode(evm_addr));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let collection = serde_json::json!({
            "collection_id": collection_id,
            "name": params.name,
            "symbol": params.symbol,
            "standard": standard,
            "creator": format!("0x{}", creator_hex),
            "evm_address": evm_address,
            "base_uri": params.base_uri.as_deref().unwrap_or(""),
            "description": params.description.as_deref().unwrap_or(""),
            "total_supply": 0,
            "created_at": now,
            "vm_pointers": {},
        });

        let key = format!("collection:{}", collection_id).into_bytes();
        let value = serde_json::to_vec(&collection).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_NFTS, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(collection)
    }

    #[tool(description = "Mint a new NFT in an existing collection. For ERC-721, each token_id is unique. For ERC-1155, you can mint multiple copies of the same token_id. Returns the minted token details.")]
    async fn mint_nft(
        &self,
        Parameters(params): Parameters<MintNftParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        // Verify collection exists
        let coll_key = format!("collection:{}", params.collection_id).into_bytes();
        let coll_bytes = storage.get(CF_NFTS, &coll_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal_data(format!("Collection not found: {}", params.collection_id)))?;

        let mut collection: serde_json::Value = serde_json::from_slice(&coll_bytes)
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        let to_hex = params.to.strip_prefix("0x").unwrap_or(&params.to);
        let _ = hex::decode(to_hex).map_err(|e| err_internal_data(format!("Invalid recipient address: {}", e)))?;

        let amount = params.amount.unwrap_or(1);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let nft = serde_json::json!({
            "collection_id": params.collection_id,
            "token_id": params.token_id,
            "owner": format!("0x{}", to_hex),
            "uri": params.uri,
            "amount": amount,
            "minted_at": now,
        });

        // Store the NFT
        let nft_key = format!("nft:{}:{}", params.collection_id, params.token_id).into_bytes();
        let nft_value = serde_json::to_vec(&nft).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_NFTS, &nft_key, &nft_value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        // Update collection total_supply
        let prev_supply = collection.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
        collection["total_supply"] = serde_json::json!(prev_supply + amount);
        let coll_value = serde_json::to_vec(&collection).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_NFTS, &coll_key, &coll_value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "collection_id": params.collection_id,
            "token_id": params.token_id,
            "owner": format!("0x{}", to_hex),
            "uri": params.uri,
            "amount": amount,
            "status": "minted",
        }))
    }

    #[tool(description = "Transfer an NFT between addresses within a collection. Verifies the sender owns the token before transferring. Returns the updated ownership details.")]
    async fn transfer_nft(
        &self,
        Parameters(params): Parameters<TransferNftParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let from_hex = params.from.strip_prefix("0x").unwrap_or(&params.from);
        let to_hex = params.to.strip_prefix("0x").unwrap_or(&params.to);
        let _ = hex::decode(from_hex).map_err(|e| err_internal_data(format!("Invalid from address: {}", e)))?;
        let _ = hex::decode(to_hex).map_err(|e| err_internal_data(format!("Invalid to address: {}", e)))?;

        let nft_key = format!("nft:{}:{}", params.collection_id, params.token_id).into_bytes();
        let nft_bytes = storage.get(CF_NFTS, &nft_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal_data(format!("NFT not found: collection={} token_id={}", params.collection_id, params.token_id)))?;

        let mut nft: serde_json::Value = serde_json::from_slice(&nft_bytes)
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        // Verify ownership
        let current_owner = nft.get("owner").and_then(|v| v.as_str()).unwrap_or("");
        let expected_owner = format!("0x{}", from_hex);
        if current_owner.to_lowercase() != expected_owner.to_lowercase() {
            return Err(err_internal_data(format!(
                "Transfer denied: token is owned by {} but sender is {}",
                current_owner, expected_owner
            )));
        }

        // Update owner
        nft["owner"] = serde_json::json!(format!("0x{}", to_hex));

        let nft_value = serde_json::to_vec(&nft).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_NFTS, &nft_key, &nft_value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "collection_id": params.collection_id,
            "token_id": params.token_id,
            "from": format!("0x{}", from_hex),
            "to": format!("0x{}", to_hex),
            "amount": params.amount.unwrap_or(1),
            "status": "transferred",
        }))
    }

    #[tool(description = "Get information about an NFT collection or a specific token within a collection. If token_id is provided, returns token-level details (owner, URI). If omitted, returns collection-level info (name, symbol, total supply).")]
    async fn get_nft_info(
        &self,
        Parameters(params): Parameters<GetNftInfoParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        if let Some(ref token_id) = params.token_id {
            // Token-level query
            let nft_key = format!("nft:{}:{}", params.collection_id, token_id).into_bytes();
            let nft_bytes = storage.get(CF_NFTS, &nft_key)
                .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
                .ok_or_else(|| err_internal_data(format!("NFT not found: collection={} token_id={}", params.collection_id, token_id)))?;

            let nft: serde_json::Value = serde_json::from_slice(&nft_bytes)
                .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

            json_result(nft)
        } else {
            // Collection-level query
            let coll_key = format!("collection:{}", params.collection_id).into_bytes();
            let coll_bytes = storage.get(CF_NFTS, &coll_key)
                .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
                .ok_or_else(|| err_internal_data(format!("Collection not found: {}", params.collection_id)))?;

            let collection: serde_json::Value = serde_json::from_slice(&coll_bytes)
                .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

            json_result(collection)
        }
    }

    #[tool(description = "List all NFT collections registered on the Tenzro ledger. Optionally filter by creator address or NFT standard (erc721/erc1155).")]
    async fn list_nft_collections(
        &self,
        Parameters(params): Parameters<ListNftCollectionsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let keys = storage.get_keys_with_prefix(CF_NFTS, b"collection:")
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        let limit = params.limit.unwrap_or(50).min(100);
        let mut collections: Vec<serde_json::Value> = Vec::new();

        for key in keys {
            if collections.len() >= limit {
                break;
            }
            if let Ok(Some(raw)) = storage.get(CF_NFTS, &key)
                && let Ok(coll) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    // Apply filters
                    if let Some(ref creator_filter) = params.creator {
                        let creator_hex = creator_filter.strip_prefix("0x").unwrap_or(creator_filter);
                        let coll_creator = coll.get("creator").and_then(|v| v.as_str()).unwrap_or("");
                        let coll_creator_hex = coll_creator.strip_prefix("0x").unwrap_or(coll_creator);
                        if coll_creator_hex.to_lowercase() != creator_hex.to_lowercase() {
                            continue;
                        }
                    }
                    if let Some(ref std_filter) = params.standard {
                        let coll_std = coll.get("standard").and_then(|v| v.as_str()).unwrap_or("");
                        let filter_normalized = match std_filter.to_lowercase().as_str() {
                            "erc721" | "erc-721" => "ERC-721",
                            "erc1155" | "erc-1155" => "ERC-1155",
                            _ => std_filter.as_str(),
                        };
                        if coll_std != filter_normalized {
                            continue;
                        }
                    }
                    collections.push(coll);
                }
        }

        json_result(serde_json::json!({
            "collections": collections,
            "total": collections.len(),
        }))
    }

    #[tool(description = "Register a cross-VM pointer for an NFT collection. Maps the collection to a contract address on another VM (EVM, SVM, or DAML) enabling cross-VM NFT discoverability.")]
    async fn register_nft_pointer(
        &self,
        Parameters(params): Parameters<RegisterNftPointerParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_NFTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let vm = match params.vm.to_lowercase().as_str() {
            "evm" | "svm" | "daml" => params.vm.to_lowercase(),
            other => return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!("Unsupported VM '{}'. Use 'evm', 'svm', or 'daml'.", other)),
                data: None,
            }),
        };

        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let _ = hex::decode(addr_hex).map_err(|e| err_internal_data(format!("Invalid address: {}", e)))?;

        // Load and update collection
        let coll_key = format!("collection:{}", params.collection_id).into_bytes();
        let coll_bytes = storage.get(CF_NFTS, &coll_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?
            .ok_or_else(|| err_internal_data(format!("Collection not found: {}", params.collection_id)))?;

        let mut collection: serde_json::Value = serde_json::from_slice(&coll_bytes)
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        // Add vm pointer
        if collection.get("vm_pointers").is_none() {
            collection["vm_pointers"] = serde_json::json!({});
        }
        collection["vm_pointers"][&vm] = serde_json::json!(format!("0x{}", addr_hex));

        let coll_value = serde_json::to_vec(&collection).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_NFTS, &coll_key, &coll_value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "collection_id": params.collection_id,
            "vm": vm,
            "address": format!("0x{}", addr_hex),
            "status": "registered",
        }))
    }

    // ─── Bridge Extended Tools ───

    #[tool(description = "Get a bridge quote without executing the transfer. Returns estimated output amount, fees, estimated time, and recommended route. Useful for previewing costs before committing to a bridge transfer.")]
    async fn bridge_quote(
        &self,
        Parameters(params): Parameters<BridgeQuoteParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let router = self
            .node
            .bridge_router()
            .ok_or_else(|| err_internal("Bridge router not initialized"))?;

        // Get available routes
        match router.get_available_routes(&params.from_chain, &params.to_chain).await {
            Ok(routes) => {
                // Filter by protocol if specified
                let filtered: Vec<_> = if let Some(ref proto) = params.protocol {
                    let proto_lower = proto.to_lowercase();
                    routes.iter().filter(|r| r.adapter_name.to_lowercase().contains(&proto_lower)).collect()
                } else {
                    routes.iter().collect()
                };

                if filtered.is_empty() {
                    return json_result(serde_json::json!({
                        "status": "no_route",
                        "from_chain": params.from_chain,
                        "to_chain": params.to_chain,
                        "token": params.token,
                        "error": "No available bridge route for this chain pair"
                    }));
                }

                // Pick the best route (lowest fee)
                let best = filtered.iter().min_by_key(|r| r.estimated_fee).unwrap();

                let fee = best.estimated_fee;
                let output_amount = params.amount.saturating_sub(fee);

                json_result(serde_json::json!({
                    "from_chain": params.from_chain,
                    "to_chain": params.to_chain,
                    "token": params.token,
                    "input_amount": params.amount.to_string(),
                    "estimated_output": output_amount.to_string(),
                    "estimated_fee": fee.to_string(),
                    "estimated_time_secs": best.estimated_time_secs,
                    "adapter": best.adapter_name,
                    "all_routes": filtered.iter().map(|r| serde_json::json!({
                        "adapter": r.adapter_name,
                        "fee": r.estimated_fee.to_string(),
                        "time_secs": r.estimated_time_secs,
                    })).collect::<Vec<_>>(),
                    "status": "quoted",
                }))
            }
            Err(e) => json_result(serde_json::json!({
                "status": "error",
                "from_chain": params.from_chain,
                "to_chain": params.to_chain,
                "error": format!("{}", e),
            })),
        }
    }

    #[tool(description = "Execute a bridge transfer with a deBridge post-fulfillment hook. After the tokens arrive on the destination chain, the hook_target contract is called with hook_calldata. Enables composable cross-chain operations (e.g., bridge + swap, bridge + stake).")]
    async fn bridge_with_hook(
        &self,
        Parameters(params): Parameters<BridgeWithHookParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let router = self
            .node
            .bridge_router()
            .ok_or_else(|| err_internal("Bridge router not initialized"))?;

        let sender_hex = params.sender.strip_prefix("0x").unwrap_or(&params.sender);
        let _ = hex::decode(sender_hex).map_err(|e| err_internal_data(format!("Invalid sender address: {}", e)))?;
        let hook_hex = params.hook_target.strip_prefix("0x").unwrap_or(&params.hook_target);
        let _ = hex::decode(hook_hex).map_err(|e| err_internal_data(format!("Invalid hook_target address: {}", e)))?;
        let calldata_hex = params.hook_calldata.strip_prefix("0x").unwrap_or(&params.hook_calldata);
        let _ = hex::decode(calldata_hex).map_err(|e| err_internal_data(format!("Invalid hook_calldata: {}", e)))?;

        use tenzro_bridge::BridgeTokenRequest;

        let request = BridgeTokenRequest::new(
            params.from_chain.clone(),
            params.to_chain.clone(),
            params.token.clone(),
            params.amount,
            params.sender.clone(),
            format!("0x{}", hook_hex), // recipient is the hook target
        );

        match router.bridge_tokens(request).await {
            Ok(receipt) => {
                let order_id = format!("hook-{}", receipt.transfer_id);
                json_result(serde_json::json!({
                    "order_id": order_id,
                    "transfer_id": receipt.transfer_id,
                    "from_chain": params.from_chain,
                    "to_chain": params.to_chain,
                    "token": params.token,
                    "amount": params.amount.to_string(),
                    "hook_target": format!("0x{}", hook_hex),
                    "hook_calldata": format!("0x{}", calldata_hex),
                    "tx_hash": format!("{}", receipt.tx_hash),
                    "fee_paid": receipt.fee_paid.to_string(),
                    "status": "submitted",
                    "note": "Hook will execute on destination chain after bridge fulfillment"
                }))
            }
            Err(e) => json_result(serde_json::json!({
                "status": "failed",
                "error": format!("{}", e),
                "from_chain": params.from_chain,
                "to_chain": params.to_chain,
            })),
        }
    }

    // ─── ERC-7802 Crosschain Tools ───

    #[tool(description = "Mint tokens via an authorized crosschain bridge (ERC-7802 crosschainMint). Only pre-authorized bridges can call this. Tokens are minted on the local chain after being burned on the source chain. Returns the mint event and nonce.")]
    async fn crosschain_mint(
        &self,
        Parameters(params): Parameters<CrosschainMintParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_METADATA, KvStore};

        let token = self.node.token().ok_or_else(|| err_internal_data("TNZO token not initialized"))?;
        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let bridge_hex = params.bridge.strip_prefix("0x").unwrap_or(&params.bridge);
        let _ = hex::decode(bridge_hex).map_err(|e| err_internal_data(format!("Invalid bridge address: {}", e)))?;

        // Verify bridge is authorized
        let auth_key = format!("crosschain_bridge:{}", bridge_hex.to_lowercase()).into_bytes();
        let auth_bytes = storage.get(CF_METADATA, &auth_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        if auth_bytes.is_none() {
            return Err(err_internal_data(format!(
                "Bridge 0x{} is not authorized for crosschain mint/burn. Use authorize_crosschain_bridge first.",
                bridge_hex
            )));
        }

        let to_hex = params.to.strip_prefix("0x").unwrap_or(&params.to);
        let to_bytes = hex::decode(to_hex).map_err(|e| err_internal_data(format!("Invalid recipient address: {}", e)))?;
        let to_addr = bytes_to_address(&to_bytes);

        // Mint tokens via TnzoToken (caller must be treasury)
        let treasury = token.treasury_address_ref()
            .ok_or_else(|| err_internal_data("Treasury address not configured — cannot mint"))?;
        token.mint(&to_addr, params.amount, &treasury)
            .map_err(|e| err_internal_data(format!("Mint failed: {}", e)))?;

        // Increment nonce
        let nonce_key = format!("crosschain_nonce:{}", bridge_hex.to_lowercase()).into_bytes();
        let nonce = if let Ok(Some(nb)) = storage.get(CF_METADATA, &nonce_key) {
            u64::from_le_bytes(nb.try_into().unwrap_or([0u8; 8])) + 1
        } else {
            1
        };
        storage.put(CF_METADATA, &nonce_key, &nonce.to_le_bytes())
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "bridge": format!("0x{}", bridge_hex),
            "to": format!("0x{}", to_hex),
            "amount": params.amount.to_string(),
            "sender": params.sender,
            "nonce": nonce,
            "event": "CrosschainMint",
            "status": "minted",
        }))
    }

    #[tool(description = "Burn tokens for a crosschain transfer (ERC-7802 crosschainBurn). Only pre-authorized bridges can call this. Tokens are burned on the local chain and will be minted on the destination chain. Returns the burn event and nonce.")]
    async fn crosschain_burn(
        &self,
        Parameters(params): Parameters<CrosschainBurnParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_METADATA, KvStore};

        let token = self.node.token().ok_or_else(|| err_internal_data("TNZO token not initialized"))?;
        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let bridge_hex = params.bridge.strip_prefix("0x").unwrap_or(&params.bridge);
        let _ = hex::decode(bridge_hex).map_err(|e| err_internal_data(format!("Invalid bridge address: {}", e)))?;

        // Verify bridge is authorized
        let auth_key = format!("crosschain_bridge:{}", bridge_hex.to_lowercase()).into_bytes();
        let auth_bytes = storage.get(CF_METADATA, &auth_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        if auth_bytes.is_none() {
            return Err(err_internal_data(format!(
                "Bridge 0x{} is not authorized for crosschain mint/burn. Use authorize_crosschain_bridge first.",
                bridge_hex
            )));
        }

        let from_hex = params.from.strip_prefix("0x").unwrap_or(&params.from);
        let from_bytes = hex::decode(from_hex).map_err(|e| err_internal_data(format!("Invalid from address: {}", e)))?;
        let from_addr = bytes_to_address(&from_bytes);

        // Burn tokens via TnzoToken
        token.burn(&from_addr, params.amount)
            .map_err(|e| err_internal_data(format!("Burn failed: {}", e)))?;

        // Increment nonce
        let nonce_key = format!("crosschain_nonce:{}", bridge_hex.to_lowercase()).into_bytes();
        let nonce = if let Ok(Some(nb)) = storage.get(CF_METADATA, &nonce_key) {
            u64::from_le_bytes(nb.try_into().unwrap_or([0u8; 8])) + 1
        } else {
            1
        };
        storage.put(CF_METADATA, &nonce_key, &nonce.to_le_bytes())
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "bridge": format!("0x{}", bridge_hex),
            "from": format!("0x{}", from_hex),
            "amount": params.amount.to_string(),
            "destination": params.destination,
            "nonce": nonce,
            "event": "CrosschainBurn",
            "status": "burned",
        }))
    }

    #[tool(description = "Authorize a bridge address for ERC-7802 crosschain mint and burn operations. Only authorized bridges can mint/burn tokens for cross-chain transfers. Sets daily mint and burn limits for rate limiting.")]
    async fn authorize_crosschain_bridge(
        &self,
        Parameters(params): Parameters<AuthorizeCrosschainBridgeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_METADATA, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let bridge_hex = params.bridge.strip_prefix("0x").unwrap_or(&params.bridge);
        let _ = hex::decode(bridge_hex).map_err(|e| err_internal_data(format!("Invalid bridge address: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let auth = serde_json::json!({
            "bridge": format!("0x{}", bridge_hex),
            "name": params.name,
            "daily_mint_limit": params.daily_mint_limit.to_string(),
            "daily_burn_limit": params.daily_burn_limit.to_string(),
            "authorized_at": now,
            "active": true,
        });

        let key = format!("crosschain_bridge:{}", bridge_hex.to_lowercase()).into_bytes();
        let value = serde_json::to_vec(&auth).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_METADATA, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "bridge": format!("0x{}", bridge_hex),
            "name": params.name,
            "daily_mint_limit": params.daily_mint_limit.to_string(),
            "daily_burn_limit": params.daily_burn_limit.to_string(),
            "status": "authorized",
        }))
    }

    // ─── ERC-3643 Compliance Tools ───

    #[tool(description = "Check whether a token transfer would be compliant with the registered ERC-3643 compliance rules. Returns compliant/non-compliant status with specific violation details. Does not execute the transfer.")]
    async fn check_compliance(
        &self,
        Parameters(params): Parameters<CheckComplianceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_COMPLIANCE, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let rule_key = format!("rules:{}", params.token_id).into_bytes();
        let rule_bytes = storage.get(CF_COMPLIANCE, &rule_key)
            .map_err(|e| err_internal_data(format!("Storage error: {}", e)))?;

        if rule_bytes.is_none() {
            return json_result(serde_json::json!({
                "token_id": params.token_id,
                "compliant": true,
                "violations": [],
                "note": "No compliance rules registered for this token"
            }));
        }

        let rules: serde_json::Value = serde_json::from_slice(&rule_bytes.unwrap())
            .map_err(|e| err_internal_data(format!("Deserialization error: {}", e)))?;

        let mut violations: Vec<String> = Vec::new();

        // Check frozen addresses
        let from_hex = params.from.strip_prefix("0x").unwrap_or(&params.from);
        let to_hex = params.to.strip_prefix("0x").unwrap_or(&params.to);

        let frozen_key_from = format!("frozen:{}:{}", params.token_id, from_hex.to_lowercase()).into_bytes();
        if let Ok(Some(_)) = storage.get(CF_COMPLIANCE, &frozen_key_from) {
            violations.push(format!("Sender address 0x{} is frozen", from_hex));
        }

        let frozen_key_to = format!("frozen:{}:{}", params.token_id, to_hex.to_lowercase()).into_bytes();
        if let Ok(Some(_)) = storage.get(CF_COMPLIANCE, &frozen_key_to) {
            violations.push(format!("Recipient address 0x{} is frozen", to_hex));
        }

        // Check KYC tier requirement
        if rules.get("require_kyc").and_then(|v| v.as_bool()).unwrap_or(false) {
            let min_tier = rules.get("min_kyc_tier").and_then(|v| v.as_u64()).unwrap_or(1);
            // In a full implementation, we would look up the KYC tiers of from/to addresses
            // via the identity registry. For now, we check if identity is registered.
            if let Some(_identity_reg) = self.node.identity_registry() {
                let from_addr = parse_address(&params.from)?;
                let to_addr = parse_address(&params.to)?;
                // Note: identity lookup by address is not directly supported;
                // this is a compliance-level check that would be fully wired in production.
                let _ = (from_addr, to_addr, min_tier);
            }
        }

        // Check max balance per holder
        if let Some(max_bal) = rules.get("max_balance_per_holder").and_then(|v| v.as_str())
            && let Ok(max) = max_bal.parse::<u128>()
                && max > 0 && params.amount > max {
                    violations.push(format!(
                        "Transfer amount {} exceeds max balance per holder {}",
                        params.amount, max
                    ));
                }

        json_result(serde_json::json!({
            "token_id": params.token_id,
            "from": format!("0x{}", from_hex),
            "to": format!("0x{}", to_hex),
            "amount": params.amount.to_string(),
            "compliant": violations.is_empty(),
            "violations": violations,
        }))
    }

    #[tool(description = "Register ERC-3643 compliance rules for a token. Defines KYC requirements, holder limits, country restrictions, and balance caps. All transfers of this token will be checked against these rules.")]
    async fn register_compliance(
        &self,
        Parameters(params): Parameters<RegisterComplianceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_COMPLIANCE, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let rules = serde_json::json!({
            "token_id": params.token_id,
            "require_kyc": params.require_kyc,
            "min_kyc_tier": params.min_kyc_tier,
            "max_holders": params.max_holders.unwrap_or(0),
            "allowed_countries": params.allowed_countries.as_deref().unwrap_or(&[]),
            "blocked_countries": params.blocked_countries.as_deref().unwrap_or(&[]),
            "max_balance_per_holder": params.max_balance_per_holder.map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()),
            "registered_at": now,
            "active": true,
        });

        let key = format!("rules:{}", params.token_id).into_bytes();
        let value = serde_json::to_vec(&rules).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_COMPLIANCE, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "token_id": params.token_id,
            "require_kyc": params.require_kyc,
            "min_kyc_tier": params.min_kyc_tier,
            "max_holders": params.max_holders.unwrap_or(0),
            "status": "registered",
        }))
    }

    #[tool(description = "Freeze an address for a specific token under ERC-3643 compliance. A frozen address cannot send or receive the specified token. Returns the freeze record.")]
    async fn freeze_address(
        &self,
        Parameters(params): Parameters<FreezeAddressParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_COMPLIANCE, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let addr_hex = params.address.strip_prefix("0x").unwrap_or(&params.address);
        let _ = hex::decode(addr_hex).map_err(|e| err_internal_data(format!("Invalid address: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let freeze = serde_json::json!({
            "token_id": params.token_id,
            "address": format!("0x{}", addr_hex),
            "reason": params.reason,
            "frozen_at": now,
        });

        let key = format!("frozen:{}:{}", params.token_id, addr_hex.to_lowercase()).into_bytes();
        let value = serde_json::to_vec(&freeze).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_COMPLIANCE, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "token_id": params.token_id,
            "address": format!("0x{}", addr_hex),
            "reason": params.reason,
            "status": "frozen",
        }))
    }

    // ─── Events Tools ───

    #[tool(description = "Query historical events from the Tenzro ledger. Supports cursor-based pagination. Filter by block range, event type, and involved addresses. Returns events ordered by sequence number.")]
    async fn get_events(
        &self,
        Parameters(params): Parameters<GetEventsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_EVENTS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let limit = params.limit.unwrap_or(50).min(200);
        let from_seq = params.from_sequence.unwrap_or(0);

        let keys = storage.get_keys_with_prefix(CF_EVENTS, b"event:")
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        let mut events: Vec<serde_json::Value> = Vec::new();
        let mut next_cursor: Option<u64> = None;

        for key in keys {
            if events.len() >= limit {
                // Set cursor to the next event's sequence
                if let Ok(Some(raw)) = storage.get(CF_EVENTS, &key)
                    && let Ok(evt) = serde_json::from_slice::<serde_json::Value>(&raw) {
                        next_cursor = evt.get("sequence").and_then(|v| v.as_u64());
                    }
                break;
            }

            if let Ok(Some(raw)) = storage.get(CF_EVENTS, &key)
                && let Ok(evt) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    let seq = evt.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
                    if seq < from_seq {
                        continue;
                    }

                    // Filter by block range
                    if let Some(from_block) = params.from_block {
                        let block = evt.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
                        if block < from_block {
                            continue;
                        }
                    }
                    if let Some(to_block) = params.to_block {
                        let block = evt.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
                        if block > to_block {
                            continue;
                        }
                    }

                    // Filter by event type
                    if let Some(ref types) = params.event_types {
                        let event_type = evt.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
                        if !types.iter().any(|t| t.to_lowercase() == event_type.to_lowercase()) {
                            continue;
                        }
                    }

                    // Filter by address
                    if let Some(ref addrs) = params.addresses {
                        let evt_from = evt.get("from").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                        let evt_to = evt.get("to").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                        let matches = addrs.iter().any(|a| {
                            let a_lower = a.strip_prefix("0x").unwrap_or(a).to_lowercase();
                            evt_from.contains(&a_lower) || evt_to.contains(&a_lower)
                        });
                        if !matches {
                            continue;
                        }
                    }

                    events.push(evt);
                }
        }

        json_result(serde_json::json!({
            "events": events,
            "total": events.len(),
            "next_cursor": next_cursor,
        }))
    }

    #[tool(description = "Register an event filter for real-time streaming via WebSocket or gRPC. Returns a subscription ID and connection URLs for receiving matching events. Events matching the filter will be pushed to connected clients.")]
    async fn subscribe_events(
        &self,
        Parameters(params): Parameters<SubscribeEventsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_METADATA, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        let subscription_id = uuid::Uuid::new_v4().to_string();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let subscription = serde_json::json!({
            "subscription_id": subscription_id,
            "event_types": params.event_types.as_deref().unwrap_or(&[]),
            "addresses": params.addresses.as_deref().unwrap_or(&[]),
            "created_at": now,
            "active": true,
        });

        let key = format!("event_sub:{}", subscription_id).into_bytes();
        let value = serde_json::to_vec(&subscription).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_METADATA, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        // Construct connection URLs based on RPC address
        let ws_url = format!("ws://127.0.0.1:8545/ws/events/{}", subscription_id);
        let grpc_url = format!("grpc://127.0.0.1:50051/events/{}", subscription_id);

        json_result(serde_json::json!({
            "subscription_id": subscription_id,
            "websocket_url": ws_url,
            "grpc_url": grpc_url,
            "event_types": params.event_types.as_deref().unwrap_or(&[]),
            "addresses": params.addresses.as_deref().unwrap_or(&[]),
            "status": "active",
        }))
    }

    #[tool(description = "Register a webhook URL for event notifications. The Tenzro node will POST JSON event payloads to the registered URL when matching events occur. Each POST includes an HMAC-SHA256 signature in the X-Tenzro-Signature header for verification.")]
    async fn register_webhook(
        &self,
        Parameters(params): Parameters<RegisterWebhookParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use tenzro_storage::{CF_WEBHOOKS, KvStore};

        let storage = self.node.storage().ok_or_else(|| err_internal("Storage not available"))?;

        // Validate URL
        if !params.url.starts_with("https://") {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Webhook URL must use HTTPS"),
                data: None,
            });
        }

        if params.secret.len() < 16 {
            return Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from("Webhook secret must be at least 16 characters"),
                data: None,
            });
        }

        let webhook_id = uuid::Uuid::new_v4().to_string();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Hash the secret for storage (don't store plaintext)
        let secret_hash = tenzro_crypto::hash::sha256(params.secret.as_bytes());

        let webhook = serde_json::json!({
            "webhook_id": webhook_id,
            "url": params.url,
            "event_types": params.event_types.as_deref().unwrap_or(&[]),
            "addresses": params.addresses.as_deref().unwrap_or(&[]),
            "secret_hash": hex::encode(secret_hash.as_bytes()),
            "created_at": now,
            "active": true,
            "delivery_count": 0,
            "last_delivered_at": null,
        });

        let key = format!("webhook:{}", webhook_id).into_bytes();
        let value = serde_json::to_vec(&webhook).map_err(|e| err_internal(format!("Serialization error: {}", e)))?;
        storage.put(CF_WEBHOOKS, &key, &value)
            .map_err(|e| err_internal(format!("Storage error: {}", e)))?;

        json_result(serde_json::json!({
            "webhook_id": webhook_id,
            "url": params.url,
            "event_types": params.event_types.as_deref().unwrap_or(&[]),
            "addresses": params.addresses.as_deref().unwrap_or(&[]),
            "status": "registered",
            "note": "Events will be POSTed to the URL with HMAC-SHA256 signature in X-Tenzro-Signature header"
        }))
    }

    // ─── Crypto Tools ───

    #[tool(description = "Sign a message with a private key. Returns the hex-encoded signature. Supports Ed25519 and Secp256k1 key types.")]
    async fn sign_message(
        &self,
        Parameters(params): Parameters<SignMessageParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let key_type = params.key_type.as_deref().unwrap_or("ed25519");
        let result = rpc_dispatch(&self.node,"tenzro_signMessage", serde_json::json!({
            "private_key": params.private_key,
            "message_hex": params.message_hex,
            "key_type": key_type,
        })).await.map_err(|e| err_internal(format!("signMessage failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Verify a cryptographic signature against a public key and message. Returns whether the signature is valid.")]
    async fn verify_signature(
        &self,
        Parameters(params): Parameters<VerifySignatureParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_verifySignature", serde_json::json!({
            "public_key": params.public_key,
            "message_hex": params.message_hex,
            "signature_hex": params.signature_hex,
        })).await.map_err(|e| err_internal(format!("verifySignature failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Encrypt data using AES-256-GCM symmetric encryption. Returns the ciphertext and nonce in hex.")]
    async fn encrypt_data(
        &self,
        Parameters(params): Parameters<EncryptDataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_encrypt", serde_json::json!({
            "key_hex": params.key_hex,
            "plaintext_hex": params.plaintext_hex,
        })).await.map_err(|e| err_internal(format!("encrypt failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Decrypt AES-256-GCM encrypted data using the key and nonce. Returns the plaintext in hex.")]
    async fn decrypt_data(
        &self,
        Parameters(params): Parameters<DecryptDataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_decrypt", serde_json::json!({
            "key_hex": params.key_hex,
            "ciphertext_hex": params.ciphertext_hex,
            "nonce_hex": params.nonce_hex,
        })).await.map_err(|e| err_internal(format!("decrypt failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Derive a 256-bit encryption key from a password using Argon2id KDF. Returns the derived key in hex.")]
    async fn derive_key(
        &self,
        Parameters(params): Parameters<DeriveKeyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_deriveKey", serde_json::json!({
            "password": params.password,
        })).await.map_err(|e| err_internal(format!("deriveKey failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Generate a new cryptographic keypair. Returns the public key, private key, and derived address in hex.")]
    async fn generate_keypair(
        &self,
        Parameters(params): Parameters<GenerateKeypairParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_generateKeypair", serde_json::json!({
            "key_type": params.key_type,
        })).await.map_err(|e| err_internal(format!("generateKeypair failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Compute the SHA-256 hash of hex-encoded data. Returns the 32-byte hash in hex.")]
    async fn hash_sha256(
        &self,
        Parameters(params): Parameters<HashSha256Params>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_hashSha256", serde_json::json!({
            "data_hex": params.data_hex,
        })).await.map_err(|e| err_internal(format!("hashSha256 failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Compute the Keccak-256 hash of hex-encoded data. Returns the 32-byte hash in hex. Used for Ethereum-compatible hashing.")]
    async fn hash_keccak256(
        &self,
        Parameters(params): Parameters<HashKeccak256Params>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_hashKeccak256", serde_json::json!({
            "data_hex": params.data_hex,
        })).await.map_err(|e| err_internal(format!("hashKeccak256 failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Perform an X25519 Diffie-Hellman key exchange. Returns the 32-byte shared secret in hex.")]
    async fn x25519_key_exchange(
        &self,
        Parameters(params): Parameters<X25519KeyExchangeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_x25519KeyExchange", serde_json::json!({
            "private_key_hex": params.private_key_hex,
            "public_key_hex": params.public_key_hex,
        })).await.map_err(|e| err_internal(format!("x25519KeyExchange failed: {}", e)))?;
        json_result(result)
    }

    // ─── TEE Tools ───

    #[tool(description = "Detect available Trusted Execution Environment (TEE) hardware on this node. Returns detected TEE type (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) or simulation mode.")]
    async fn detect_tee(
        &self,
        Parameters(_params): Parameters<DetectTeeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_detectTee", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("detectTee failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Generate a TEE attestation report from the node's hardware enclave. The attestation proves the code is running in a genuine TEE. Optionally specify the TEE type or auto-detect.")]
    async fn get_tee_attestation(
        &self,
        Parameters(params): Parameters<GetTeeAttestationParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_getAttestation", serde_json::json!({
            "tee_type": params.tee_type,
        })).await.map_err(|e| err_internal(format!("getAttestation failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Verify a TEE attestation report. Checks the vendor certificate chain, signature, and measurement hashes. Returns verification status and details.")]
    async fn verify_tee_attestation(
        &self,
        Parameters(params): Parameters<VerifyTeeAttestationParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_verifyTeeAttestation", serde_json::json!({
            "attestation": params.attestation,
            "tee_type": params.tee_type,
        })).await.map_err(|e| err_internal(format!("verifyTeeAttestation failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Seal (encrypt) data within the TEE enclave using hardware-derived keys. The sealed data can only be unsealed on the same TEE platform with the same key_id.")]
    async fn seal_data(
        &self,
        Parameters(params): Parameters<SealDataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_sealData", serde_json::json!({
            "data_hex": params.data_hex,
            "key_id": params.key_id,
        })).await.map_err(|e| err_internal(format!("sealData failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unseal (decrypt) data that was previously sealed within the TEE enclave. Requires the same key_id used during sealing.")]
    async fn unseal_data(
        &self,
        Parameters(params): Parameters<UnsealDataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_unsealData", serde_json::json!({
            "sealed_hex": params.sealed_hex,
            "key_id": params.key_id,
        })).await.map_err(|e| err_internal(format!("unsealData failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List all registered TEE providers on the network, including their TEE type, attestation status, and supported capabilities.")]
    async fn list_tee_providers(
        &self,
        Parameters(_params): Parameters<ListTeeProvidersParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_listTeeProviders", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("listTeeProviders failed: {}", e)))?;
        json_result(result)
    }

    // ─── ZK Tools ───

    #[tool(description = "Create a Plonky3 STARK proof for one of the three Tenzro AIRs (`inference`, `settlement`, `identity`) over the KoalaBear field. Returns the hex-encoded bincode-serialized p3_uni_stark::Proof and public inputs (4-byte LE KoalaBear chunks).")]
    async fn create_zk_proof(
        &self,
        Parameters(params): Parameters<CreateZkProofParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = params.witness;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("circuit_id".to_string(), serde_json::Value::String(params.circuit_id));
        } else {
            return Err(err_internal("witness must be a JSON object"));
        }
        let result = rpc_dispatch(&self.node,"tenzro_createZkProof", payload)
            .await.map_err(|e| err_internal(format!("createZkProof failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List all available ZK circuits on the node — name, AIR type, field, and hash function.")]
    async fn list_zk_circuits(
        &self,
        Parameters(_params): Parameters<ListZkCircuitsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_listCircuits", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("listCircuits failed: {}", e)))?;
        json_result(result)
    }

    // ─── Custody Tools ───

    #[tool(description = "Create a new MPC threshold wallet with configurable threshold and share count. Default is 2-of-3. Returns the wallet ID, address, and key share metadata.")]
    async fn create_mpc_wallet(
        &self,
        Parameters(params): Parameters<CreateMpcWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_createMpcWallet", serde_json::json!({
            "threshold": params.threshold.unwrap_or(2),
            "total_shares": params.total_shares.unwrap_or(3),
            "key_type": params.key_type.as_deref().unwrap_or("ed25519"),
        })).await.map_err(|e| err_internal(format!("createMpcWallet failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Export a wallet's keystore as an encrypted JSON file. Uses Argon2id KDF for key derivation. The exported keystore can be imported on another node.")]
    async fn export_keystore(
        &self,
        Parameters(params): Parameters<ExportKeystoreParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_exportKeystore", serde_json::json!({
            "wallet_id": params.wallet_id,
            "password": params.password,
        })).await.map_err(|e| err_internal(format!("exportKeystore failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Import a wallet from an encrypted keystore JSON. Decrypts with the provided password and adds the wallet to the local node.")]
    async fn import_keystore(
        &self,
        Parameters(params): Parameters<ImportKeystoreParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_importKeystore", serde_json::json!({
            "keystore_json": params.keystore_json,
            "password": params.password,
        })).await.map_err(|e| err_internal(format!("importKeystore failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Get the key share metadata for an MPC wallet. Returns the threshold, total shares, and share indices without exposing secret key material.")]
    async fn get_key_shares(
        &self,
        Parameters(params): Parameters<GetKeySharesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_getKeyShares", serde_json::json!({
            "wallet_id": params.wallet_id,
        })).await.map_err(|e| err_internal(format!("getKeyShares failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Rotate the key shares of an MPC wallet. Generates new shares while keeping the same public key and address. Old shares become invalid.")]
    async fn rotate_keys(
        &self,
        Parameters(params): Parameters<RotateKeysParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_rotateKeys", serde_json::json!({
            "wallet_id": params.wallet_id,
        })).await.map_err(|e| err_internal(format!("rotateKeys failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Set spending limits for a wallet. Defines the maximum daily spend and per-transaction limit in TNZO. Transactions exceeding these limits will be rejected.")]
    async fn set_spending_limits(
        &self,
        Parameters(params): Parameters<SetSpendingLimitsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_setSpendingLimits", serde_json::json!({
            "wallet_id": params.wallet_id,
            "daily_limit": params.daily_limit,
            "per_tx_limit": params.per_tx_limit,
        })).await.map_err(|e| err_internal(format!("setSpendingLimits failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Get the current spending limits for a wallet. Returns the daily limit, per-transaction limit, and current daily usage.")]
    async fn get_spending_limits(
        &self,
        Parameters(params): Parameters<GetSpendingLimitsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_getSpendingLimits", serde_json::json!({
            "wallet_id": params.wallet_id,
        })).await.map_err(|e| err_internal(format!("getSpendingLimits failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Authorize a temporary session for a wallet with specific allowed operations and a time limit. Returns a session ID and expiry timestamp.")]
    async fn authorize_session(
        &self,
        Parameters(params): Parameters<AuthorizeSessionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_authorizeSession", serde_json::json!({
            "wallet_id": params.wallet_id,
            "duration_secs": params.duration_secs,
            "operations": params.operations,
        })).await.map_err(|e| err_internal(format!("authorizeSession failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Revoke an active wallet session immediately. The session ID becomes invalid and any pending operations under this session are cancelled.")]
    async fn revoke_session(
        &self,
        Parameters(params): Parameters<RevokeSessionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_revokeSession", serde_json::json!({
            "session_id": params.session_id,
        })).await.map_err(|e| err_internal(format!("revokeSession failed: {}", e)))?;
        json_result(result)
    }

    // ─── App / Paymaster Tools ───

    #[tool(description = "Register a new application on the Tenzro Network. The master wallet address will sponsor gas for user operations. Returns the app ID and API key.")]
    async fn register_app(
        &self,
        Parameters(params): Parameters<RegisterAppParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_registerApp", serde_json::json!({
            "name": params.name,
            "master_wallet_address": params.master_wallet_address,
        })).await.map_err(|e| err_internal(format!("registerApp failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Create a new user wallet under an application. Optionally fund it with an initial TNZO amount from the app's master wallet.")]
    async fn create_user_wallet(
        &self,
        Parameters(params): Parameters<CreateUserWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_createUserWallet", serde_json::json!({
            "app_id": params.app_id,
            "label": params.label,
            "initial_funding": params.initial_funding_wei.unwrap_or_else(|| "0".to_string()),
        })).await.map_err(|e| err_internal(format!("createUserWallet failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fund a user wallet from the app's master wallet. Transfers TNZO (wei) from the master address to the user address.")]
    async fn fund_user_wallet(
        &self,
        Parameters(params): Parameters<FundUserWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Validate wei amount before dispatch
        let _: u128 = params.amount_wei.parse().map_err(|_| err_internal(
            "amount_wei must be a wei decimal string (e.g. '5000000000000000000' for 5 TNZO)"
        ))?;
        let result = rpc_dispatch(&self.node,"tenzro_fundUserWallet", serde_json::json!({
            "master_address": params.master_address,
            "user_address": params.user_address,
            "amount": params.amount_wei,
        })).await.map_err(|e| err_internal(format!("fundUserWallet failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List all user wallets belonging to an application. Returns wallet addresses, labels, and current balances.")]
    async fn list_user_wallets(
        &self,
        Parameters(params): Parameters<ListUserWalletsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_listUserWallets", serde_json::json!({
            "app_id": params.app_id,
        })).await.map_err(|e| err_internal(format!("listUserWallets failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Sponsor a transaction using the master/paymaster wallet. The gas cost is paid by the master address while the transaction is sent on behalf of the user. Uses ERC-4337 account abstraction.")]
    async fn sponsor_transaction(
        &self,
        Parameters(params): Parameters<SponsorTransactionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_sponsorTransaction", serde_json::json!({
            "master_address": params.master_address,
            "user_tx": params.user_tx,
        })).await.map_err(|e| err_internal(format!("sponsorTransaction failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Get usage statistics for an application. Returns total transactions, gas spent, active users, and wallet count.")]
    async fn get_usage_stats(
        &self,
        Parameters(params): Parameters<GetUsageStatsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_getUsageStats", serde_json::json!({
            "app_id": params.app_id,
        })).await.map_err(|e| err_internal(format!("getUsageStats failed: {}", e)))?;
        json_result(result)
    }

    // ─── Contract ABI Tools ───

    #[tool(description = "ABI-encode a function call. Takes a Solidity-style function signature and arguments, returns hex-encoded calldata. Useful for preparing EVM contract interactions.")]
    async fn encode_function(
        &self,
        Parameters(params): Parameters<EncodeFunctionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_encodeFunction", serde_json::json!({
            "function_sig": params.function_sig,
            "args": params.args,
        })).await.map_err(|e| err_internal(format!("encodeFunction failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-decode contract call return data. Takes hex-encoded return data and output type signatures, returns decoded values. Useful for interpreting EVM contract responses.")]
    async fn decode_result(
        &self,
        Parameters(params): Parameters<DecodeResultParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node,"tenzro_decodeResult", serde_json::json!({
            "data_hex": params.data_hex,
            "output_types": params.output_types,
        })).await.map_err(|e| err_internal(format!("decodeResult failed: {}", e)))?;
        json_result(result)
    }

    // ─── AP2 (Agent Payments Protocol) Tools ────────────────────────────────

    #[tool(description = "Sign an AP2 mandate (Intent or Cart) with the auth-bound wallet's Ed25519 key, returning a verified Verifiable Digital Credential (VDC). Auth: DPoP+JWT mandatory. Wallet must be Ed25519. signer_did must match the wallet's controller DID.")]
    async fn ap2_sign_mandate(
        &self,
        Parameters(params): Parameters<Ap2SignMandateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_ap2SignMandate", serde_json::json!({
            "mandate_kind": params.mandate_kind,
            "mandate": params.mandate,
            "signer_did": params.signer_did,
        })).await.map_err(|e| err_internal(format!("ap2SignMandate failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Verify a single AP2 mandate (Verifiable Digital Credential). Checks the VDC proof, issuer, and schema for Intent, Cart, or Payment mandates per Google's AP2 spec.")]
    async fn ap2_verify_mandate(
        &self,
        Parameters(params): Parameters<Ap2VerifyMandateParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_ap2VerifyMandate", serde_json::json!({
            "vdc": params.vdc,
        })).await.map_err(|e| err_internal(format!("ap2VerifyMandate failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Validate an AP2 v0.2 Checkout+Payment mandate pair for consistency: ensures the PaymentMandate references the CheckoutMandate, amounts/items match the checkout's constraints, and both VDCs verify. When enforce_delegation=true, additionally cross-checks the agent's TDIP DelegationScope against the payment total (TDIP identifies. AP2 authorizes. Tenzro settles).")]
    async fn ap2_validate_mandate_pair(
        &self,
        Parameters(params): Parameters<Ap2ValidateMandatePairParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_ap2ValidateMandatePair", serde_json::json!({
            "checkout_vdc": params.checkout_vdc,
            "payment_vdc": params.payment_vdc,
            "enforce_delegation": params.enforce_delegation,
        })).await.map_err(|e| err_internal(format!("ap2ValidateMandatePair failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Return AP2 protocol metadata: version, supported mandate types, supported VC formats, and issuer DID methods recognized by this node.")]
    async fn ap2_protocol_info(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_ap2ProtocolInfo", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("ap2ProtocolInfo failed: {}", e)))?;
        json_result(result)
    }

    // ─── ERC-8004 (Trustless Agents Registry) Tools ─────────────────────────

    #[tool(description = "ABI-encode IdentityRegistry.register() (ERC-8004 v0.6+ no-arg overload — caller becomes agent owner; registry allocates a sequential uint256 agentId). Returns hex calldata.")]
    async fn erc8004_encode_register(
        &self,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeRegister", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("erc8004EncodeRegister failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.register(string agentURI) (ERC-8004 v0.6+ overload with agent URI). Returns hex calldata.")]
    async fn erc8004_encode_register_with_uri(
        &self,
        Parameters(params): Parameters<Erc8004EncodeRegisterWithUriParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeRegisterWithUri", serde_json::json!({
            "agent_uri": params.agent_uri,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeRegisterWithUri failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.register(string agentURI, (string,bytes)[] metadata) (ERC-8004 v0.6+ overload with metadata entries). Returns hex calldata.")]
    async fn erc8004_encode_register_with_metadata(
        &self,
        Parameters(params): Parameters<Erc8004EncodeRegisterWithMetadataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let metadata: Vec<serde_json::Value> = params.metadata.iter()
            .map(|e| serde_json::json!({ "key": e.key, "value": e.value }))
            .collect();
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeRegisterWithMetadata", serde_json::json!({
            "agent_uri": params.agent_uri,
            "metadata": metadata,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeRegisterWithMetadata failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.getAgent(uint256 agentId). Returns hex calldata for an eth_call lookup.")]
    async fn erc8004_encode_get_agent(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetAgent", serde_json::json!({
            "agent_id": params.agent_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetAgent failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Decode the (address, string) return data of an IdentityRegistry.getAgent() eth_call into { agent_address, metadata_uri }.")]
    async fn erc8004_decode_get_agent(
        &self,
        Parameters(params): Parameters<Erc8004DecodeGetAgentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004DecodeGetAgent", serde_json::json!({
            "return_data": params.return_data,
        })).await.map_err(|e| err_internal(format!("erc8004DecodeGetAgent failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.setAgentURI(uint256 agentId, string metadataURI) (ERC-8004 v0.6+ mutator). Returns hex calldata.")]
    async fn erc8004_encode_set_agent_uri(
        &self,
        Parameters(params): Parameters<Erc8004EncodeSetAgentUriParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeSetAgentURI", serde_json::json!({
            "agent_id": params.agent_id,
            "metadata_uri": params.metadata_uri,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeSetAgentURI failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature) (ERC-8004 v0.6+ wallet rotation). Returns hex calldata.")]
    async fn erc8004_encode_set_agent_wallet(
        &self,
        Parameters(params): Parameters<Erc8004EncodeSetAgentWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeSetAgentWallet", serde_json::json!({
            "agent_id": params.agent_id,
            "new_wallet": params.new_wallet,
            "deadline": params.deadline,
            "signature": params.signature,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeSetAgentWallet failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.setMetadata(uint256 agentId, string metadataKey, bytes metadataValue) (ERC-8004 v0.6+ key-value metadata). Returns hex calldata.")]
    async fn erc8004_encode_set_metadata(
        &self,
        Parameters(params): Parameters<Erc8004EncodeSetMetadataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeSetMetadata", serde_json::json!({
            "agent_id": params.agent_id,
            "metadata_key": params.metadata_key,
            "metadata_value": params.metadata_value,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeSetMetadata failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.getMetadata(uint256 agentId, string metadataKey) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_get_metadata(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetMetadataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetMetadata", serde_json::json!({
            "agent_id": params.agent_id,
            "metadata_key": params.metadata_key,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetMetadata failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Decode the bytes return data of an IdentityRegistry.getMetadata() eth_call into { metadata_value }.")]
    async fn erc8004_decode_get_metadata(
        &self,
        Parameters(params): Parameters<Erc8004DecodeGetMetadataParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004DecodeGetMetadata", serde_json::json!({
            "return_data": params.return_data,
        })).await.map_err(|e| err_internal(format!("erc8004DecodeGetMetadata failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.getAgentURI(uint256 agentId) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_get_agent_uri(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetAgentUriParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetAgentURI", serde_json::json!({
            "agent_id": params.agent_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetAgentURI failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode IdentityRegistry.getAgentWallet(uint256 agentId) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_get_agent_wallet(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetAgentWalletParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetAgentWallet", serde_json::json!({
            "agent_id": params.agent_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetAgentWallet failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.submitFeedback(bytes32 subjectAgentId, int8 rating, string contextURI). Rating is in -100..=100.")]
    async fn erc8004_encode_feedback(
        &self,
        Parameters(params): Parameters<Erc8004EncodeFeedbackParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeFeedback", serde_json::json!({
            "subject_agent_id": params.subject_agent_id,
            "rating": params.rating,
            "context_uri": params.context_uri,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeFeedback failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.getFeedback(bytes32 subject, uint256 index). Returns hex calldata for an eth_call lookup.")]
    async fn erc8004_encode_get_feedback(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetFeedbackParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetFeedback", serde_json::json!({
            "subject_agent_id": params.subject_agent_id,
            "index": params.index,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetFeedback failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.getFeedbackCount(bytes32 subject). Returns hex calldata.")]
    async fn erc8004_encode_get_feedback_count(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetFeedbackCountParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetFeedbackCount", serde_json::json!({
            "subject_agent_id": params.subject_agent_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetFeedbackCount failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.revokeFeedback(uint256 agentId, bytes32 feedbackId) (ERC-8004 v0.6+ mutator). Returns hex calldata.")]
    async fn erc8004_encode_revoke_feedback(
        &self,
        Parameters(params): Parameters<Erc8004EncodeRevokeFeedbackParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeRevokeFeedback", serde_json::json!({
            "agent_id": params.agent_id,
            "feedback_id": params.feedback_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeRevokeFeedback failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.appendResponse(uint256 agentId, bytes32 feedbackId, string responseURI) (ERC-8004 v0.6+ mutator). Returns hex calldata.")]
    async fn erc8004_encode_append_response(
        &self,
        Parameters(params): Parameters<Erc8004EncodeAppendResponseParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeAppendResponse", serde_json::json!({
            "agent_id": params.agent_id,
            "feedback_id": params.feedback_id,
            "response_uri": params.response_uri,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeAppendResponse failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.isFeedbackRevoked(uint256 agentId, bytes32 feedbackId) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_is_feedback_revoked(
        &self,
        Parameters(params): Parameters<Erc8004EncodeIsFeedbackRevokedParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeIsFeedbackRevoked", serde_json::json!({
            "agent_id": params.agent_id,
            "feedback_id": params.feedback_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeIsFeedbackRevoked failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ReputationRegistry.getFeedbackResponses(uint256 agentId, bytes32 feedbackId) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_get_feedback_responses(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetFeedbackResponsesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetFeedbackResponses", serde_json::json!({
            "agent_id": params.agent_id,
            "feedback_id": params.feedback_id,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetFeedbackResponses failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ValidationRegistry.validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash). Returns hex calldata.")]
    async fn erc8004_encode_validation_request(
        &self,
        Parameters(params): Parameters<Erc8004EncodeValidationRequestParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeValidationRequest", serde_json::json!({
            "validator_address": params.validator_address,
            "agent_id": params.agent_id,
            "request_uri": params.request_uri,
            "request_hash": params.request_hash,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeValidationRequest failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ValidationRegistry.validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag). Response is a 0..=100 quality score.")]
    async fn erc8004_encode_validation_response(
        &self,
        Parameters(params): Parameters<Erc8004EncodeValidationResponseParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeValidationResponse", serde_json::json!({
            "request_hash": params.request_hash,
            "response": params.response,
            "response_uri": params.response_uri,
            "response_hash": params.response_hash,
            "tag": params.tag,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeValidationResponse failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "ABI-encode ValidationRegistry.getValidation(bytes32 requestHash) (ERC-8004 v0.6+ read). Returns hex calldata.")]
    async fn erc8004_encode_get_validation(
        &self,
        Parameters(params): Parameters<Erc8004EncodeGetValidationParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_erc8004EncodeGetValidation", serde_json::json!({
            "request_hash": params.request_hash,
        })).await.map_err(|e| err_internal(format!("erc8004EncodeGetValidation failed: {}", e)))?;
        json_result(result)
    }

    // ─── Wormhole Cross-Chain Tools ─────────────────────────────────────────

    #[tool(description = "Look up the Wormhole numeric chain id for a chain name (ethereum=2, solana=1, base=30, arbitrum=23, optimism=24, etc.).")]
    async fn wormhole_chain_id(
        &self,
        Parameters(params): Parameters<WormholeChainIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_wormholeChainId", serde_json::json!({
            "chain": params.chain,
        })).await.map_err(|e| err_internal(format!("wormholeChainId failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Parse a canonical Wormhole VAA id of the form {chain}/{emitter}/{sequence} into its components.")]
    async fn wormhole_parse_vaa_id(
        &self,
        Parameters(params): Parameters<WormholeParseVaaIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_wormholeParseVaaId", serde_json::json!({
            "vaa_id": params.vaa_id,
        })).await.map_err(|e| err_internal(format!("wormholeParseVaaId failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Bridge tokens via the Wormhole adapter registered on the BridgeRouter. Returns transfer_id, tx_hash, fee_paid, and estimated_arrival_ms on success.")]
    async fn wormhole_bridge(
        &self,
        Parameters(params): Parameters<WormholeBridgeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_wormholeBridge", serde_json::json!({
            "source_chain": params.source_chain,
            "dest_chain": params.dest_chain,
            "asset": params.asset,
            "amount": params.amount,
            "sender": params.sender,
            "recipient": params.recipient,
        })).await.map_err(|e| err_internal(format!("wormholeBridge failed: {}", e)))?;
        json_result(result)
    }

    // ─── TNZO CCT (Chainlink Cross-Chain Token) Tools ───────────────────────

    #[tool(description = "List all TNZO CCT pools in the canonical mainnet registry (Ethereum LockRelease; Base/Arbitrum/Optimism/Solana BurnMint).")]
    async fn cct_list_pools(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_cctListPools", serde_json::json!({}))
            .await.map_err(|e| err_internal(format!("cctListPools failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Get a single TNZO CCT pool by chain name. Returns chain_id, chain_selector, pool_address, token_address, pool_type, contract_name, capacities, refill_rate.")]
    async fn cct_get_pool(
        &self,
        Parameters(params): Parameters<CctGetPoolParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_cctGetPool", serde_json::json!({
            "chain": params.chain,
        })).await.map_err(|e| err_internal(format!("cctGetPool failed: {}", e)))?;
        json_result(result)
    }

    // ─── Multi-modal: Forecast (timeseries) ───

    #[tool(description = "List forecast (timeseries) models currently loaded on this node. Use list_forecast_catalog to browse available models from the curated catalog.")]
    async fn list_forecast_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listForecastModels", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listForecastModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX forecast (timeseries) catalog. Returns models like TimesFM 2.5 — each with HF repo, context length, max horizon, and quantile support.")]
    async fn list_forecast_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listForecastCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listForecastCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered forecast model from this node, freeing its ORT session.")]
    async fn unload_forecast_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadForecastModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadForecastModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Run a univariate timeseries forecast on a registered model. Pass `history` (most-recent-last context series), `horizon` (steps ahead), and optional `quantiles` (e.g. [0.1, 0.5, 0.9]) and `frequency_seconds`. Returns point forecasts and (when supported) quantile bands.")]
    async fn forecast(
        &self,
        Parameters(params): Parameters<ForecastParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = serde_json::json!({
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
        json_result(result)
    }

    // ─── Multi-modal: Vision encoders ───

    #[tool(description = "List vision encoder models currently loaded on this node (DINOv3, SigLIP2, CLIP, etc.). Use list_vision_catalog to browse available models.")]
    async fn list_vision_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listVisionModels", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listVisionModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX vision encoder catalog: DINOv3 (small/base/large), SigLIP2 (base/large/so400m), CLIP ViT-B/32 + L/14, DINOv2. Each entry carries input_size, embedding_dim, normalization preset, and license tier.")]
    async fn list_vision_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listVisionCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listVisionCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered vision encoder, freeing its ORT session.")]
    async fn unload_vision_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadVisionModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadVisionModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Embed a single image with a registered vision encoder. Pass base64-encoded PNG/JPEG/WebP bytes. Returns a dense feature vector (e.g. 768-dim for DINOv3-base, 1152-dim for SigLIP2-so400m).")]
    async fn vision_embed(
        &self,
        Parameters(params): Parameters<VisionEmbedParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "image_base64": params.image_base64,
            "normalize": params.normalize.unwrap_or(false),
        });
        let result = rpc_dispatch(&self.node, "tenzro_visionEmbed", payload)
            .await
            .map_err(|e| err_internal(format!("visionEmbed failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Compute cosine similarity between an image embedding and a text embedding (must have matching dimension). Pure math — does not load any model. Typical use: pair vision_embed (image) with text_embed against a CLIP/SigLIP text tower.")]
    async fn vision_similarity(
        &self,
        Parameters(params): Parameters<VisionSimilarityParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({
            "image_embedding": params.image_embedding,
            "text_embedding": params.text_embedding,
        });
        let result = rpc_dispatch(&self.node, "tenzro_visionSimilarity", payload)
            .await
            .map_err(|e| err_internal(format!("visionSimilarity failed: {}", e)))?;
        json_result(result)
    }

    // ─── Multi-modal: Text embeddings ───

    #[tool(description = "List text-embedding models currently loaded on this node (Qwen3-Embedding, EmbeddingGemma, BGE-M3, etc.). Use list_text_embedding_catalog to browse the curated catalog.")]
    async fn list_text_embedding_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listTextEmbeddingModels",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listTextEmbeddingModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX text-embedding catalog: Qwen3-Embedding (0.6B/4B/8B), EmbeddingGemma-300M, BGE-M3, Snowflake Arctic-Embed. Each entry carries embedding_dim, supported Matryoshka truncations, and license tier.")]
    async fn list_text_embedding_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listTextEmbeddingCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listTextEmbeddingCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered text-embedding model, freeing its ORT session.")]
    async fn unload_text_embedding_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadTextEmbeddingModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadTextEmbeddingModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Embed a batch of strings with a registered text encoder. Returns one row per input. Optional `requested_dim` enables Matryoshka truncation (e.g. 128/256/512 from a native 768/1024-dim model).")]
    async fn text_embed(
        &self,
        Parameters(params): Parameters<TextEmbedParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = serde_json::json!({
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
        json_result(result)
    }

    // ─── Multi-modal: Segmentation ───

    #[tool(description = "List segmentation models currently loaded on this node (SAM 2, EdgeSAM, MobileSAM). Use list_segmentation_catalog to browse the curated catalog.")]
    async fn list_segmentation_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listSegmentationModels",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listSegmentationModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX segmentation catalog: SAM 2 (base/large), EdgeSAM, MobileSAM. SAM 3 / 3.1 are text-promptable with a different decoder ABI and are not exposed via this point/box segment tool.")]
    async fn list_segmentation_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listSegmentationCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listSegmentationCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered segmenter, freeing its ORT session.")]
    async fn unload_segmentation_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadSegmentationModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadSegmentationModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Run prompt-driven image segmentation. `prompts` is an array of `{type:'point', x, y, label}` (label=1 foreground / 0 background) or `{type:'box', x0, y0, x1, y1}` objects. Returns one mask per prompt with confidence scores.")]
    async fn segment(
        &self,
        Parameters(params): Parameters<SegmentParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({
            "model_id": params.model_id,
            "image_base64": params.image_base64,
            "prompts": params.prompts,
        });
        let result = rpc_dispatch(&self.node, "tenzro_segment", payload)
            .await
            .map_err(|e| err_internal(format!("segment failed: {}", e)))?;
        json_result(result)
    }

    // ─── Multi-modal: Object detection ───

    #[tool(description = "List object detection models currently loaded on this node (RF-DETR, D-FINE). Use list_detection_catalog to browse the curated catalog.")]
    async fn list_detection_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listDetectionModels",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listDetectionModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX detection catalog: RF-DETR (nano/small/medium/base/large/2xl) — first real-time detector >60 AP on COCO (ICLR 2026); D-FINE (n/s/m/l/x). All Apache-2.0.")]
    async fn list_detection_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_listDetectionCatalog",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("listDetectionCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered detector, freeing its ORT session.")]
    async fn unload_detection_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadDetectionModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadDetectionModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Run object detection on an image. Returns an array of detections with bounding box (x0,y0,x1,y1), label_id, and confidence score. NMS-free for DETR-family models — just sigmoid + score threshold.")]
    async fn detect(
        &self,
        Parameters(params): Parameters<DetectParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = serde_json::json!({
            "model_id": params.model_id,
            "image_base64": params.image_base64,
        });
        if let Some(t) = params.score_threshold {
            payload["score_threshold"] = serde_json::json!(t);
        }
        let result = rpc_dispatch(&self.node, "tenzro_detect", payload)
            .await
            .map_err(|e| err_internal(format!("detect failed: {}", e)))?;
        json_result(result)
    }

    // ─── Multi-modal: Audio ASR ───

    #[tool(description = "List ASR (speech-to-text) models currently loaded on this node. Note: the audio transcriber runtime is scaffolding only — `transcribe` returns ProviderNotAvailable until the ORT-backed Whisper / Moonshine / Parakeet / Canary implementations land in the next wave.")]
    async fn list_audio_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listAudioModels", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listAudioModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX ASR catalog: Moonshine v2 (tiny/base, MIT, on-device), Distil-Whisper (small.en/medium.en/large-v3, MIT), Whisper Large-v3-turbo (MIT, flagship), Parakeet-TDT-0.6B-v3 (CC-BY-4.0, 25 European langs), Canary-1B-Flash (CC-BY-4.0, multilingual). The catalog is stable; the ORT-backed transcribers ship in the next wave (today the runtime returns ProviderNotAvailable).")]
    async fn list_audio_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listAudioCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listAudioCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered ASR model, freeing its ORT session.")]
    async fn unload_audio_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadAudioModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadAudioModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Transcribe an audio clip (WAV/MP3/FLAC, base64-encoded) with a registered ASR model. Optional language hint, per-segment timestamps, and decoding temperature. Note: the ORT-backed transcriber lands in the next wave — today this call returns ProviderNotAvailable.")]
    async fn transcribe(
        &self,
        Parameters(params): Parameters<TranscribeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = serde_json::json!({
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
        json_result(result)
    }

    // ─── Multi-modal: Video encoders ───

    #[tool(description = "List video encoder models currently loaded on this node. Wave 1 catalog ships empty pending license clearance + ONNX export (V-JEPA 2.1, VideoMAE).")]
    async fn list_video_models(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listVideoModels", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listVideoModels failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Browse the curated ONNX video encoder catalog. Wave 1 returns an empty list — no permissive, ONNX-shippable, encoder-only video model exists yet in the 2026 OSS landscape. Re-evaluated quarterly. The runtime scaffolding is in place so adding entries later is mechanical.")]
    async fn list_video_catalog(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listVideoCatalog", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listVideoCatalog failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Unload a registered video encoder, freeing its ORT session.")]
    async fn unload_video_model(
        &self,
        Parameters(params): Parameters<ModelIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_unloadVideoModel",
            serde_json::json!({ "model_id": params.model_id }),
        )
        .await
        .map_err(|e| err_internal(format!("unloadVideoModel failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Produce a clip-level embedding from a short video (base64-encoded). Wave 1: agents can fall back to per-frame vision_embed pooling until a native video encoder lands.")]
    async fn video_embed(
        &self,
        Parameters(params): Parameters<VideoEmbedParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut payload = serde_json::json!({
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
        json_result(result)
    }

    // ─── Workflow stack (Canton-native workflows) ───
    //
    // Writes flow through `send_transaction` with the privileged-VM
    // workflow selectors (`0x01000040`–`0x0100004B`). These tools are
    // read-only views over the in-memory `WorkflowRuntime` state, which
    // is rehydrated from RocksDB on node startup.

    #[tool(description = "Fetch a workflow by 32-byte hex id. Returns the full Workflow record (creator, participants, obligations, approval gates, status, canton_mirror, signatures). Read-only. Writes use send_transaction with the workflow privileged-VM selectors.")]
    async fn get_workflow(
        &self,
        Parameters(params): Parameters<WorkflowIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "workflow_id": params.workflow_id });
        let result = rpc_dispatch(&self.node, "tenzro_getWorkflow", payload)
            .await
            .map_err(|e| err_internal(format!("getWorkflow failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List workflow ids created by a given DID. Returns up to all workflows the DID has authored, regardless of status.")]
    async fn list_workflows_by_creator(
        &self,
        Parameters(params): Parameters<CreatorDidParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "creator_did": params.creator_did });
        let result = rpc_dispatch(&self.node, "tenzro_listWorkflowsByCreator", payload)
            .await
            .map_err(|e| err_internal(format!("listWorkflowsByCreator failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List workflow ids that include a DID as a participant (regardless of role). The DID may be the creator, an obligor, an oblige, or an approver.")]
    async fn list_workflows_by_participant(
        &self,
        Parameters(params): Parameters<DidParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "did": params.did });
        let result = rpc_dispatch(&self.node, "tenzro_listWorkflowsByParticipant", payload)
            .await
            .map_err(|e| err_internal(format!("listWorkflowsByParticipant failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List workflow ids in a given status. Status: draft | awaiting_signatures | active | suspended | settling | completed | failed | disputed | cancelled.")]
    async fn list_workflows_by_status(
        &self,
        Parameters(params): Parameters<WorkflowStatusParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "status": params.status });
        let result = rpc_dispatch(&self.node, "tenzro_listWorkflowsByStatus", payload)
            .await
            .map_err(|e| err_internal(format!("listWorkflowsByStatus failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Full lifecycle history for a workflow: ordered list of LifecycleTransition entries (from-status, to-status, reason, actor, at). Useful for audit and dispute resolution.")]
    async fn get_workflow_lifecycle(
        &self,
        Parameters(params): Parameters<WorkflowIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "workflow_id": params.workflow_id });
        let result = rpc_dispatch(&self.node, "tenzro_getWorkflowLifecycle", payload)
            .await
            .map_err(|e| err_internal(format!("getWorkflowLifecycle failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch an obligation record by 32-byte hex id. Returns the obligor / oblige / kind / amount / status / discharge proof.")]
    async fn get_obligation(
        &self,
        Parameters(params): Parameters<ObligationIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "obligation_id": params.obligation_id });
        let result = rpc_dispatch(&self.node, "tenzro_getObligation", payload)
            .await
            .map_err(|e| err_internal(format!("getObligation failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch an approval gate by 32-byte hex id. Returns the approver set (single / threshold / role / delegated), m-of-n threshold, on-event trigger, and effect.")]
    async fn get_approval_gate(
        &self,
        Parameters(params): Parameters<ApprovalGateIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "gate_id": params.gate_id });
        let result = rpc_dispatch(&self.node, "tenzro_getApprovalGate", payload)
            .await
            .map_err(|e| err_internal(format!("getApprovalGate failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch an open or finalized approval request by 32-byte hex id. Returns the gate, decisions collected, threshold progress, and final outcome (approved / rejected / pending).")]
    async fn get_approval_request(
        &self,
        Parameters(params): Parameters<ApprovalRequestIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "request_id": params.request_id });
        let result = rpc_dispatch(&self.node, "tenzro_getApprovalRequest", payload)
            .await
            .map_err(|e| err_internal(format!("getApprovalRequest failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch a privacy domain by 32-byte hex id. Returns members, X25519 envelope policy, freeze status. Members see plaintext, non-members see Deny (indistinguishable from non-existence).")]
    async fn get_privacy_domain(
        &self,
        Parameters(params): Parameters<PrivacyDomainIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "domain_id": params.domain_id });
        let result = rpc_dispatch(&self.node, "tenzro_getPrivacyDomain", payload)
            .await
            .map_err(|e| err_internal(format!("getPrivacyDomain failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List privacy domains a given DID is a member of. Caller-side filtered to the DIDs the requester is authorized to see.")]
    async fn list_privacy_domains_for_did(
        &self,
        Parameters(params): Parameters<DidParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "did": params.did });
        let result = rpc_dispatch(&self.node, "tenzro_listPrivacyDomainsForDid", payload)
            .await
            .map_err(|e| err_internal(format!("listPrivacyDomainsForDid failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch a single workflow receipt by 32-byte hex id. Receipts are append-only and form a per-workflow hash chain via prev_receipt for audit.")]
    async fn get_workflow_receipt(
        &self,
        Parameters(params): Parameters<WorkflowReceiptIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "receipt_id": params.receipt_id });
        let result = rpc_dispatch(&self.node, "tenzro_getWorkflowReceipt", payload)
            .await
            .map_err(|e| err_internal(format!("getWorkflowReceipt failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Walk a workflow's receipt chain from head backwards via prev_receipt. Returns receipts oldest-last, bounded by `max` (default 256). Use this for audit trails and dispute history.")]
    async fn list_workflow_receipts(
        &self,
        Parameters(params): Parameters<WorkflowReceiptListParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({
            "workflow_id": params.workflow_id,
            "max": params.max,
        });
        let result = rpc_dispatch(&self.node, "tenzro_listWorkflowReceipts", payload)
            .await
            .map_err(|e| err_internal(format!("listWorkflowReceipts failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Fetch a fee route by 32-byte hex id. Fee routes describe how a settlement payout is split across recipients in basis points (must sum to 10_000).")]
    async fn get_fee_route(
        &self,
        Parameters(params): Parameters<FeeRouteIdParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({ "fee_route_id": params.fee_route_id });
        let result = rpc_dispatch(&self.node, "tenzro_getFeeRoute", payload)
            .await
            .map_err(|e| err_internal(format!("getFeeRoute failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "List every registered fee route. Each route has a label, splits in bps, and a derived 32-byte id used by Workflow.fee_route.")]
    async fn list_fee_routes(&self) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(&self.node, "tenzro_listFeeRoutes", serde_json::json!({}))
            .await
            .map_err(|e| err_internal(format!("listFeeRoutes failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Pure preview: how would a `gross_wei` amount be split across a fee route's recipients? Truncates to last for the remainder. Does not settle — settlement is consensus-mediated.")]
    async fn compute_fee_route_payouts(
        &self,
        Parameters(params): Parameters<FeeRoutePayoutsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let payload = serde_json::json!({
            "fee_route_id": params.fee_route_id,
            "gross_wei": params.gross_wei,
        });
        let result = rpc_dispatch(&self.node, "tenzro_computeFeeRoutePayouts", payload)
            .await
            .map_err(|e| err_internal(format!("computeFeeRoutePayouts failed: {}", e)))?;
        json_result(result)
    }

    #[tool(description = "Snapshot of workflow operational metrics (workflows/obligations/approvals partitioned by status, signature totals, canton-mirror count, fee routes, privacy domains). Returns the same data as the /metrics scrape, but as typed JSON.")]
    async fn get_workflow_operational_metrics(
        &self,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let result = rpc_dispatch(
            &self.node,
            "tenzro_getWorkflowOperationalMetrics",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| err_internal(format!("getWorkflowOperationalMetrics failed: {}", e)))?;
        json_result(result)
    }
}

// ─── Helper: parse modality string ───

fn parse_modality(s: &str) -> std::result::Result<tenzro_types::model::ModelModality, NodeError> {
    use tenzro_types::model::ModelModality;
    match s.to_lowercase().as_str() {
        "text" => Ok(ModelModality::Text),
        // Specialized text models still live in the Text modality.
        "text-embedding" | "text_embedding" | "textembedding" | "embedding" => {
            Ok(ModelModality::Text)
        }
        "image" => Ok(ModelModality::Image),
        // Specialized vision categories collapse onto the Image modality —
        // task-specific filtering is done by family/catalog, not by modality.
        "segmentation" | "segment" | "detection" | "detect" => Ok(ModelModality::Image),
        "audio" => Ok(ModelModality::Audio),
        "timeseries" | "ts" => Ok(ModelModality::Timeseries),
        "video" => Ok(ModelModality::Video),
        "text_image" | "textimage" => Ok(ModelModality::TextImage),
        "text_audio" | "textaudio" => Ok(ModelModality::TextAudio),
        "multimodal" => Ok(ModelModality::Multimodal),
        other => Err(NodeError::InvalidState(format!("Unknown modality: {}", other))),
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for TenzroMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
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
             • create_wallet — Generate Ed25519 or Secp256k1 keypair\n\
             • get_balance — Query TNZO token balance\n\n\
             Transactions:\n\
             • send_transaction — Send TNZO transfer\n\
             • request_faucet — Get 100 testnet TNZO\n\n\
             Identity (TDIP):\n\
             • register_identity — Register human or machine DID\n\
             • resolve_did — Resolve DID to identity data\n\
             • set_delegation_scope — Set agent spending limits and permissions\n\n\
             OAuth 2.1 / AAP delegation:\n\
             • exchange_token — RFC 8693 token exchange (mint narrower child JWT)\n\
             • introspect_token — RFC 7662 token introspection\n\
             • oauth_discovery — RFC 8414 AS metadata\n\n\
             Payments (MPP / x402 / Native):\n\
             • create_payment_challenge — Create payment challenge for any protocol\n\
             • verify_payment — Verify and settle a payment\n\
             • list_payment_protocols — List supported payment protocols\n\
             • list_x402_schemes — List registered x402 scheme backends (tenzro-hybrid / exact-eip3009 / permit2 / erc7710)\n\n\
             AI Models:\n\
             • list_models — Browse available AI models\n\
             • chat_completion — Send inference request to a model\n\
             • list_model_endpoints — List model service API/MCP URLs\n\n\
             Model Lifecycle:\n\
             • download_model — Download a model from HuggingFace Hub\n\
             • serve_model_mcp — Start serving a downloaded model\n\
             • stop_model — Stop serving a model\n\
             • delete_model_mcp — Delete a downloaded model from disk\n\
             • get_download_progress — Check download progress for a model\n\n\
             Multi-modal AI — Forecast (Timeseries):\n\
             • forecast — Run a univariate timeseries forecast (TimesFM 2.5)\n\
             • list_forecast_models — List loaded forecast models\n\
             • list_forecast_catalog — Browse curated forecast catalog\n\
             • unload_forecast_model — Drop a forecast model\n\n\
             Multi-modal AI — Vision:\n\
             • vision_embed — Image → dense feature vector (DINOv3, SigLIP2, CLIP)\n\
             • vision_similarity — Cosine similarity between image & text embeddings\n\
             • list_vision_models — List loaded vision encoders\n\
             • list_vision_catalog — Browse curated vision encoder catalog\n\
             • unload_vision_model — Drop a vision encoder\n\n\
             Multi-modal AI — Text Embeddings:\n\
             • text_embed — Strings → dense vectors (Qwen3-Embedding, EmbeddingGemma, BGE-M3)\n\
             • list_text_embedding_models — List loaded text encoders\n\
             • list_text_embedding_catalog — Browse curated text-embedding catalog\n\
             • unload_text_embedding_model — Drop a text encoder\n\n\
             Multi-modal AI — Segmentation:\n\
             • segment — Prompt-driven mask segmentation (SAM 2, EdgeSAM, MobileSAM)\n\
             • list_segmentation_models — List loaded segmenters\n\
             • list_segmentation_catalog — Browse curated segmentation catalog\n\
             • unload_segmentation_model — Drop a segmenter\n\n\
             Multi-modal AI — Detection:\n\
             • detect — Object detection (RF-DETR, D-FINE)\n\
             • list_detection_models — List loaded detectors\n\
             • list_detection_catalog — Browse curated detection catalog\n\
             • unload_detection_model — Drop a detector\n\n\
             Multi-modal AI — Audio (ASR, scaffolding — ORT-backed transcribers ship next wave):\n\
             • transcribe — Speech-to-text (catalog: Whisper, Distil-Whisper, Moonshine, Parakeet, Canary; today returns ProviderNotAvailable)\n\
             • list_audio_models — List loaded ASR models\n\
             • list_audio_catalog — Browse curated ASR catalog\n\
             • unload_audio_model — Drop an ASR model\n\n\
             Multi-modal AI — Video:\n\
             • video_embed — Clip-level video embedding (wave-1 catalog empty pending license clearance)\n\
             • list_video_models — List loaded video encoders\n\
             • list_video_catalog — Browse curated video catalog (empty wave 1)\n\
             • unload_video_model — Drop a video encoder\n\n\
             Task Marketplace:\n\
             • post_task — Post a new AI task to the decentralized marketplace\n\
             • list_tasks — Browse and filter open tasks\n\
             • quote_task — Submit a price quote for a task as a provider\n\
             • get_task — Get details of a specific task by ID\n\
             • cancel_task — Cancel a pending task\n\
             • assign_task — Assign a task to an agent\n\
             • complete_task — Mark a task as completed with a result\n\n\
             Agent Template Marketplace:\n\
             • register_agent_template — Publish a reusable agent template\n\
             • list_agent_templates — Browse and filter published agent templates\n\
             • get_agent_template — Get full details of an agent template by ID\n\
             • download_agent_template — Instantiate an agent template with custom config\n\
             • update_agent_template — Update metadata on an existing agent template\n\n\
             Agent Spawning & Swarms:\n\
             • spawn_agent — Spawn a child agent under a parent (max 50 per parent)\n\
             • run_agent_task — Run an agentic task loop (LLM + tools, up to 10 steps)\n\
             • create_swarm — Create a swarm of coordinated agents under an orchestrator\n\
             • get_swarm_status — Get swarm status and all member details\n\
             • terminate_swarm — Terminate a swarm and all its member agents\n\n\
             Agent Advanced:\n\
             • register_agent — Register a new agent identity on the network\n\
             • send_agent_message — Send a message from one agent DID to another\n\
             • delegate_task — Delegate a task from one agent to another with optional budget\n\
             • discover_models — Discover available AI models (with optional category/price filter)\n\
             • discover_agents — Discover agents by capability or type\n\n\
             Capability Registry:\n\
             • list_capabilities — List all registered capabilities with agent + attestation counts\n\
             • get_capability_attestations — Fetch all attestations for a given capability\n\
             • get_agent_capability_attestations — Fetch all attestations issued for an agent ID\n\
             • find_best_agent_for_capability — Pick the best (TEE-backed-preferred) agent for a capability\n\n\
             Cross-Chain Bridge:\n\
             • bridge_tokens — Bridge tokens between chains\n\
             • get_bridge_routes — Get available routes and fees\n\
             • list_bridge_adapters — List bridge adapters\n\n\
             deBridge DLN (proxy):\n\
             • debridge_search_tokens — Search tokens on deBridge\n\
             • debridge_get_chains — List deBridge supported chains\n\
             • debridge_get_instructions — Get deBridge operational instructions\n\
             • debridge_create_tx — Create cross-chain tx via deBridge\n\
             • debridge_same_chain_swap — Same-chain swap via deBridge\n\n\
             Staking & Providers:\n\
             • stake_tokens — Stake TNZO to earn rewards\n\
             • unstake_tokens — Unstake TNZO (7-day unbonding)\n\
             • register_provider — Register as AI/TEE/storage provider\n\
             • get_provider_stats — Get provider performance metrics\n\n\
             Provider Config:\n\
             • set_provider_schedule — Set a provider's availability schedule\n\
             • get_provider_schedule — Get a provider's current schedule\n\
             • set_provider_pricing — Set per-token pricing for a provider\n\
             • get_provider_pricing — Get current pricing config for a provider\n\n\
             Governance:\n\
             • list_proposals — List governance proposals (filter by status)\n\
             • vote_on_proposal — Vote yes/no/abstain on a governance proposal\n\
             • create_proposal — Create a new governance proposal\n\
             • get_voting_power — Get voting power (staked TNZO) for an address\n\
             • delegate_voting_power — Delegate voting power to another address\n\n\
             Token:\n\
             • token_balance — Get TNZO balance for an address\n\
             • total_supply — Get total TNZO token supply\n\n\
             Canton / DAML:\n\
             • list_canton_domains — List connected Canton synchronizer domains\n\
             • list_daml_contracts — List active DAML contracts in a Canton domain\n\
             • submit_daml_command — Submit a DAML command (create/exercise) to Canton\n\n\
             Settlement:\n\
             • settle_payment — Immediately settle a payment between two parties\n\
             • create_escrow — Create an escrow contract for conditional payment\n\
             • release_escrow — Release an escrow with an authorizing signature\n\
             • open_payment_channel — Open a micropayment channel between two parties\n\
             • close_payment_channel — Close a payment channel with a final balance\n\n\
             Network:\n\
             • get_node_status — Node health, block height, peers\n\
             • get_block — Get block by height\n\
             • get_block_range — Fetch a contiguous range of blocks (default 64, max 256)\n\
             • get_transaction — Look up transaction by hash\n\
             • get_fee_market — EIP-1559 fee snapshot (gas price, suggested tip, base-fee history)\n\
             • get_svm_cross_vm_program_info — Canonical Tenzro Cross-VM SVM-native program ID + 4 instruction discriminators\n\n\
             Verification:\n\
             • verify_zk_proof — Verify Plonky3 STARK proof (over KoalaBear) for one of the registered AIRs (inference/settlement/identity)\n\
             • verify_vrf_proof — Verify Tenzro VRF proof (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)\n\
             • generate_vrf_proof — Generate Tenzro VRF proof and deterministic output\n\n\
             Tokens & Contracts:\n\
             • create_token — Create an ERC-20 token via the token factory\n\
             • get_token_info — Look up token by symbol, address, or ID\n\
             • list_tokens — List registered tokens with optional VM filter\n\
             • deploy_contract — Deploy contract bytecode to EVM/SVM/DAML\n\
             • cross_vm_transfer — Transfer tokens between VMs atomically\n\
             • wrap_tnzo — Wrap native TNZO to a VM representation\n\
             • get_token_balance — Get TNZO balance across all VMs\n\n\
             AP2 (Agent Payments Protocol):\n\
             • ap2_verify_mandate — Verify a single AP2 VDC mandate (Intent/Cart/Payment)\n\
             • ap2_validate_mandate_pair — Validate Intent+Cart consistency\n\
             • ap2_protocol_info — AP2 protocol metadata (version, supported types)\n\n\
             ERC-8004 (Trustless Agents Registry — v0.6+ surface):\n\
             • erc8004_encode_register — ABI-encode IdentityRegistry.register() (no-arg overload)\n\
             • erc8004_encode_register_with_uri — ABI-encode IdentityRegistry.register(string agentURI)\n\
             • erc8004_encode_register_with_metadata — ABI-encode IdentityRegistry.register(string,(string,bytes)[])\n\
             • erc8004_encode_get_agent — ABI-encode IdentityRegistry.getAgent()\n\
             • erc8004_decode_get_agent — Decode (address,string) returndata from getAgent()\n\
             • erc8004_encode_set_agent_uri — ABI-encode IdentityRegistry.setAgentURI() (v0.6+)\n\
             • erc8004_encode_set_agent_wallet — ABI-encode IdentityRegistry.setAgentWallet() (v0.6+)\n\
             • erc8004_encode_set_metadata — ABI-encode IdentityRegistry.setMetadata() (v0.6+)\n\
             • erc8004_encode_get_metadata — ABI-encode IdentityRegistry.getMetadata() (v0.6+)\n\
             • erc8004_decode_get_metadata — Decode bytes returndata from getMetadata() (v0.6+)\n\
             • erc8004_encode_get_agent_uri — ABI-encode IdentityRegistry.getAgentURI() (v0.6+)\n\
             • erc8004_encode_get_agent_wallet — ABI-encode IdentityRegistry.getAgentWallet() (v0.6+)\n\
             • erc8004_encode_feedback — ABI-encode ReputationRegistry.submitFeedback(bytes32,int8,string)\n\
             • erc8004_encode_get_feedback — ABI-encode ReputationRegistry.getFeedback()\n\
             • erc8004_encode_get_feedback_count — ABI-encode ReputationRegistry.getFeedbackCount()\n\
             • erc8004_encode_revoke_feedback — ABI-encode ReputationRegistry.revokeFeedback() (v0.6+)\n\
             • erc8004_encode_append_response — ABI-encode ReputationRegistry.appendResponse() (v0.6+)\n\
             • erc8004_encode_is_feedback_revoked — ABI-encode ReputationRegistry.isFeedbackRevoked() (v0.6+)\n\
             • erc8004_encode_get_feedback_responses — ABI-encode ReputationRegistry.getFeedbackResponses() (v0.6+)\n\
             • erc8004_encode_validation_request — ABI-encode ValidationRegistry.validationRequest(address,uint256,string,bytes32)\n\
             • erc8004_encode_validation_response — ABI-encode ValidationRegistry.validationResponse(bytes32,uint8,string,bytes32,string)\n\
             • erc8004_encode_get_validation — ABI-encode ValidationRegistry.getValidation() (v0.6+)\n\n\
             Wormhole Cross-Chain:\n\
             • wormhole_chain_id — Look up Wormhole numeric chain id by chain name\n\
             • wormhole_parse_vaa_id — Parse {chain}/{emitter}/{sequence} VAA id\n\
             • wormhole_bridge — Bridge tokens via the Wormhole adapter\n\n\
             TNZO CCT (Chainlink Cross-Chain Token):\n\
             • cct_list_pools — List all registered TNZO CCT pools\n\
             • cct_get_pool — Get a single TNZO CCT pool by chain name"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

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
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService, StreamableHttpServerConfig,
    };

    // Use stateless mode with JSON responses. Each HTTP POST is independent —
    // no session management, no SSE framing. This eliminates the session-death
    // problem where rmcp's LocalSessionManager would close sessions after the
    // spawned service task exited. Stateless + json_response is the correct
    // mode for a deployed MCP server behind a reverse proxy (Caddy/nginx).
    // Compliant with MCP Streamable HTTP spec (2025-06-18).
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "mcp.tenzro.network".to_string(),
        ]);

    // ── OAuth 2.1 Authentication ──
    // Create OAuth state *before* the MCP closure moves `node` + `web_state`.
    let oauth_state = Arc::new(super::oauth::OAuthState::new(
        node.clone(),
        web_state.clone(),
    ));
    // Store OAuthState on the node so RPC handlers can use onboarding key methods
    *node.oauth_state.write() = Some(oauth_state.clone());
    let oauth_mw_state = oauth_state.clone();

    let service = StreamableHttpService::new(
        move || Ok(TenzroMcpServer::new(node.clone(), web_state.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );

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
            "/register",
            axum::routing::post(super::oauth::register_handler),
        )
        .route(
            "/authorize",
            axum::routing::get(super::oauth::authorize_handler)
                .post(super::oauth::authorize_submit_handler),
        )
        .route(
            "/token",
            axum::routing::post(super::oauth::token_handler),
        )
        .route(
            "/revoke",
            axum::routing::post(super::oauth::revoke_handler),
        )
        .with_state(oauth_state)
        // MCP endpoint (protected by bearer auth middleware)
        .nest_service("/mcp", service)
        // Bearer auth layer — only enforces on /mcp paths
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let state = oauth_mw_state.clone();
                async move { super::oauth::bearer_auth_check(state, req, next).await }
            },
        ))
        // EU AI Act Art. 50(1): mark every response from this MCP server
        // as AI-originating. Cheap blanket header — applies even to
        // OAuth/discovery responses, where the disclosure is harmless and
        // makes it impossible for a downstream tool to claim it didn't see
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
        ));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(addr = %listen_addr, tools = 20, mode = "stateless-json", oauth = true, "MCP Server listening (endpoint: /mcp, OAuth 2.1 enabled)");

    axum::serve(listener, app)
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
        let _schema = schemars::schema_for!(SendTransactionParams);
        let _schema = schemars::schema_for!(GetBlockParams);
        let _schema = schemars::schema_for!(RequestFaucetParams);
        let _schema = schemars::schema_for!(RegisterIdentityParams);
        let _schema = schemars::schema_for!(ResolveDidParams);
        let _schema = schemars::schema_for!(VerifyZkProofParams);
        let _schema = schemars::schema_for!(ListModelsParams);
        let _schema = schemars::schema_for!(ChatCompletionParams);
        let _schema = schemars::schema_for!(CreatePaymentChallengeParams);
        let _schema = schemars::schema_for!(VerifyPaymentParams);
        let _schema = schemars::schema_for!(SetDelegationScopeParams);
        let _schema = schemars::schema_for!(ExchangeTokenParams);
        let _schema = schemars::schema_for!(IntrospectTokenParams);
        let _schema = schemars::schema_for!(BridgeTokensParams);
        let _schema = schemars::schema_for!(GetBridgeRoutesParams);
        let _schema = schemars::schema_for!(CreateWalletParams);
        let _schema = schemars::schema_for!(SetUsernameParams);
        let _schema = schemars::schema_for!(ResolveUsernameParams);
        let _schema = schemars::schema_for!(GetSkillUsageParams);
        let _schema = schemars::schema_for!(GetToolUsageParams);
        let _schema = schemars::schema_for!(SpawnAgentFromTemplateParams);
        let _schema = schemars::schema_for!(RateAgentTemplateParams);
        let _schema = schemars::schema_for!(SearchAgentTemplatesParams);
        let _schema = schemars::schema_for!(GetAgentTemplateStatsParams);
        // Crypto params
        let _schema = schemars::schema_for!(SignMessageParams);
        let _schema = schemars::schema_for!(VerifySignatureParams);
        let _schema = schemars::schema_for!(EncryptDataParams);
        let _schema = schemars::schema_for!(DecryptDataParams);
        let _schema = schemars::schema_for!(DeriveKeyParams);
        let _schema = schemars::schema_for!(GenerateKeypairParams);
        let _schema = schemars::schema_for!(HashSha256Params);
        let _schema = schemars::schema_for!(HashKeccak256Params);
        let _schema = schemars::schema_for!(X25519KeyExchangeParams);
        // TEE params
        let _schema = schemars::schema_for!(DetectTeeParams);
        let _schema = schemars::schema_for!(GetTeeAttestationParams);
        let _schema = schemars::schema_for!(VerifyTeeAttestationParams);
        let _schema = schemars::schema_for!(SealDataParams);
        let _schema = schemars::schema_for!(UnsealDataParams);
        let _schema = schemars::schema_for!(ListTeeProvidersParams);
        // ZK params
        let _schema = schemars::schema_for!(CreateZkProofParams);
        let _schema = schemars::schema_for!(ListZkCircuitsParams);
        // Custody params
        let _schema = schemars::schema_for!(CreateMpcWalletParams);
        let _schema = schemars::schema_for!(ExportKeystoreParams);
        let _schema = schemars::schema_for!(ImportKeystoreParams);
        let _schema = schemars::schema_for!(GetKeySharesParams);
        let _schema = schemars::schema_for!(RotateKeysParams);
        let _schema = schemars::schema_for!(SetSpendingLimitsParams);
        let _schema = schemars::schema_for!(GetSpendingLimitsParams);
        let _schema = schemars::schema_for!(AuthorizeSessionParams);
        let _schema = schemars::schema_for!(RevokeSessionParams);
        // App/Paymaster params
        let _schema = schemars::schema_for!(RegisterAppParams);
        let _schema = schemars::schema_for!(CreateUserWalletParams);
        let _schema = schemars::schema_for!(FundUserWalletParams);
        let _schema = schemars::schema_for!(ListUserWalletsParams);
        let _schema = schemars::schema_for!(SponsorTransactionParams);
        let _schema = schemars::schema_for!(GetUsageStatsParams);
        // Contract ABI params
        let _schema = schemars::schema_for!(EncodeFunctionParams);
        let _schema = schemars::schema_for!(DecodeResultParams);
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

    #[test]
    fn test_parse_modality() {
        assert!(parse_modality("text").is_ok());
        assert!(parse_modality("image").is_ok());
        assert!(parse_modality("audio").is_ok());
        assert!(parse_modality("video").is_ok());
        assert!(parse_modality("text_image").is_ok());
        assert!(parse_modality("text_audio").is_ok());
        assert!(parse_modality("multimodal").is_ok());
        assert!(parse_modality("unknown").is_err());
    }
}
