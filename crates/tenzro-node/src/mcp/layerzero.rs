//! LayerZero V2 MCP Server — Model Context Protocol tools for cross-chain messaging
//!
//! Provides 20 MCP tools for interacting with the LayerZero V2 protocol:
//! - Messaging: fee quoting, send transaction building, message tracking
//! - OFT: omnichain fungible token transfers, listing, options encoding, send calldata
//! - Value Transfer API: unified cross-chain quotes, build user steps, status tracking
//!   (replaces deprecated Stargate REST API — supports 130+ chains including Solana)
//! - Stargate V2: native ETH/USDC bridging via StargatePoolNative contracts
//! - Network: deployments, DVNs, chain info, wallet messages
//!
//! All tools communicate with LayerZero's EndpointV2 contract (via eth_call),
//! the Scan API, the Metadata API, the Value Transfer API, and Stargate V2
//! contracts via HTTP/JSON using reqwest.

use std::borrow::Cow;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_router, Json,
};
use serde::Deserialize;

use super::server::RpcPassthroughOutput;

// ─── Constants ───

/// LayerZero EndpointV2 universal deployment address (same on all EVM chains).
const ENDPOINT_V2: &str = "0x1a44076050125825900e736c501f859c50fE728c";

/// LayerZero Scan API base URL for message tracking.
const SCAN_API: &str = "https://scan.layerzero-api.com/v1";

/// LayerZero Metadata API base URL for deployments, DVNs, and OFT info.
const METADATA_API: &str = "https://metadata.layerzero-api.com/v1/metadata";

/// LayerZero Value Transfer API base URL (replaces deprecated Stargate REST API).
/// Supports 130+ chains including Solana, unified quotes, and pre-built transaction steps.
const TRANSFER_API: &str = "https://transfer.layerzero-api.com/v1";

// ─── Stargate V2 StargatePoolNative contract addresses ───

/// Stargate V2 StargatePoolNative contract for ETH on various chains.
fn stargate_eth_pool(chain: &str) -> Option<&'static str> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => Some("0x77b2043768d28E9C9aB44E1aBfC95944bcE57931"),
        "optimism" | "op" => Some("0xe8CDF27AcD73a434D661C84887215F7598e7d0d3"),
        "arbitrum" | "arb" => Some("0xA45B5130f36CDcA45667738e2a258AB09f4A27F5"),
        "base" => Some("0xdc181Bd607330aeeBEF6ea62e03e5e1Fb4B6F7C7"),
        _ => None,
    }
}

/// Stargate V2 StargatePool contract for USDC on various chains.
fn stargate_usdc_pool(chain: &str) -> Option<&'static str> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => Some("0xc026395860Db2d07ee33e05fE50ed7bD583189C7"),
        "optimism" | "op" => Some("0xcE8CcA271Ebc0533920C83d39F417ED6A0abB7D0"),
        "arbitrum" | "arb" => Some("0xe8CDF27AcD73a434D661C84887215F7598e7d0d3"),
        "base" => Some("0x27a16dc786820B16E5c9028b75B99F6f604b5d26"),
        "polygon" | "matic" => Some("0x9Aa02D4Fae7F58b8E8f34c66E756cC734DAc7fe4"),
        "avalanche" | "avax" => Some("0x5634c4a5FEd09819E3c46D86A965Dd9447d86e47"),
        _ => None,
    }
}

/// Stargate V2 StargatePool contract for USDT on various chains.
fn stargate_usdt_pool(chain: &str) -> Option<&'static str> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => Some("0x933597a323Eb81cAe705C5bC29985172fd5A3973"),
        "optimism" | "op" => Some("0x19cFCE47eD54a88614648DC3f19A5980097007dD"),
        "arbitrum" | "arb" => Some("0xcE8CcA271Ebc0533920C83d39F417ED6A0abB7D0"),
        "bsc" | "bnb" => Some("0x138EB30f73BC423c6455C53df6D89CB01898B71B"),
        "polygon" | "matic" => Some("0xd47b03ee6d86Cf251ee7860FB2ACf9f91B9fD4d7"),
        "avalanche" | "avax" => Some("0x12dC9256Acc9895B076f6638D628382881e62CeE"),
        _ => None,
    }
}

/// Resolve a Stargate pool address by token symbol and chain.
fn stargate_pool(token: &str, chain: &str) -> Option<&'static str> {
    match token.to_uppercase().as_str() {
        "ETH" | "WETH" => stargate_eth_pool(chain),
        "USDC" => stargate_usdc_pool(chain),
        "USDT" => stargate_usdt_pool(chain),
        _ => None,
    }
}

/// Whether a token is native (ETH) on a given chain — determines if msg.value includes the amount.
fn is_native_token(token: &str, chain: &str) -> bool {
    matches!(token.to_uppercase().as_str(), "ETH" | "WETH")
        && matches!(
            chain.to_lowercase().as_str(),
            "ethereum" | "eth" | "optimism" | "op" | "arbitrum" | "arb" | "base"
        )
}

// ─── EID / RPC helpers ───

/// Return the LayerZero V2 Endpoint ID (EID) for a chain name.
fn chain_eid(name: &str) -> Option<u32> {
    match name.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(30101),
        "arbitrum" | "arb" => Some(30110),
        "optimism" | "op" => Some(30111),
        "polygon" | "matic" => Some(30109),
        "bsc" | "bnb" => Some(30102),
        "avalanche" | "avax" => Some(30106),
        "base" => Some(30184),
        "solana" | "sol" => Some(30168),
        "zksync" | "zksync_era" => Some(30165),
        "sei" => Some(30280),
        "sonic" => Some(30332),
        "berachain" | "bera" => Some(30362),
        "story" => Some(30364),
        "monad" => Some(30390),
        "megaeth" => Some(30398),
        "tron" | "trx" => Some(30420),
        _ => None,
    }
}

/// Build a dRPC URL for a given chain slug, falling back to public RPCs when
/// the `DRPC_API_KEY` environment variable is not set.
fn drpc_url(chain: &str) -> String {
    let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
    if key.is_empty() {
        // Fallback to public RPC when no dRPC key configured
        return match chain {
            "ethereum" => "https://eth.llamarpc.com".to_string(),
            "arbitrum" => "https://arb1.arbitrum.io/rpc".to_string(),
            "base" => "https://mainnet.base.org".to_string(),
            "optimism" => "https://mainnet.optimism.io".to_string(),
            "polygon" => "https://polygon-rpc.com".to_string(),
            "bsc" => "https://bsc-dataseed.binance.org".to_string(),
            "avalanche" => "https://api.avax.network/ext/bc/C/rpc".to_string(),
            "zksync" => "https://mainnet.era.zksync.io".to_string(),
            "solana" => "https://api.mainnet-beta.solana.com".to_string(),
            _ => format!("https://{}.drpc.org", chain),
        };
    }
    format!("https://lb.drpc.live/{}/{}", chain, key)
}

/// Return an RPC URL for a chain name.
fn chain_rpc(name: &str) -> Option<String> {
    let slug = match name.to_lowercase().as_str() {
        "ethereum" | "eth" => "ethereum",
        "arbitrum" | "arb" => "arbitrum",
        "base" => "base",
        "optimism" | "op" => "optimism",
        "polygon" | "matic" => "polygon",
        "bsc" | "bnb" => "bsc",
        "avalanche" | "avax" => "avalanche",
        "zksync" | "zksync_era" => "zksync",
        "sei" => "sei",
        "sonic" => "sonic",
        "berachain" | "bera" => "berachain",
        "story" => "story",
        "monad" => "monad",
        "megaeth" => "megaeth",
        "tron" | "trx" => "tron",
        _ => return None,
    };
    Some(drpc_url(slug))
}

/// All supported chains with their EIDs.
fn all_chains() -> Vec<(&'static str, u32)> {
    vec![
        ("ethereum", 30101),
        ("arbitrum", 30110),
        ("optimism", 30111),
        ("polygon", 30109),
        ("bsc", 30102),
        ("avalanche", 30106),
        ("base", 30184),
        ("solana", 30168),
        ("zksync", 30165),
        ("sei", 30280),
        ("sonic", 30332),
        ("berachain", 30362),
        ("story", 30364),
        ("monad", 30390),
        ("megaeth", 30398),
        ("tron", 30420),
    ]
}

// ─── ABI encoding helpers ───

/// Left-pad a byte slice to 32 bytes (ABI word).
fn pad_left_32(data: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    let start = 32usize.saturating_sub(data.len());
    let copy_len = data.len().min(32);
    word[start..start + copy_len].copy_from_slice(&data[data.len() - copy_len..]);
    word
}

/// Encode a `uint256` from a `u128` value.
fn encode_u256(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&value.to_be_bytes());
    out
}

/// Encode a `uint32` as a 32-byte ABI word.
fn encode_u32(value: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&value.to_be_bytes());
    out
}

/// Encode a `uint64` as a 32-byte ABI word (used for OFT V2 amountSD).
fn encode_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

/// Encode a `bool` as a 32-byte ABI word.
fn encode_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    if value {
        word[31] = 1;
    }
    word
}

/// Strip optional 0x prefix and return the hex body.
fn strip_0x(input: &str) -> &str {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
}

/// Decode a hex string (with or without 0x prefix) into bytes.
fn decode_hex(hex: &str) -> std::result::Result<Vec<u8>, ErrorData> {
    let hex = strip_0x(hex);
    if hex.is_empty() {
        return Ok(vec![]);
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(hex.get(i..i + 2).unwrap_or("00"), 16)
                .map_err(|e| err_invalid_params(format!("invalid hex at position {}: {}", i, e)))
        })
        .collect()
}

/// Encode bytes to hex string with 0x prefix.
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// ABI-encode a dynamic `bytes` value: `length_word || padded_data`.
fn encode_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let length_word = encode_u256(data.len() as u128);
    let padded_len = data.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    out.extend_from_slice(&length_word);
    out.extend_from_slice(data);
    let padding = padded_len - data.len();
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// Decode a `uint256` from a 32-byte ABI word, returning as u128 (upper 16 bytes ignored).
fn decode_u256_to_u128(word: &[u8]) -> u128 {
    if word.len() < 32 {
        return 0;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(buf)
}

/// Resolve EID to human-readable chain name.
fn eid_to_name(eid: u32) -> &'static str {
    match eid {
        30101 => "Ethereum",
        30102 => "BSC",
        30106 => "Avalanche",
        30109 => "Polygon",
        30110 => "Arbitrum",
        30111 => "Optimism",
        30165 => "zkSync",
        30168 => "Solana",
        30184 => "Base",
        30280 => "Sei",
        30332 => "Sonic",
        30362 => "Berachain",
        30364 => "Story",
        30390 => "Monad",
        30398 => "MegaETH",
        30420 => "Tron",
        _ => "Unknown",
    }
}

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzQuoteFeeParams {
    #[schemars(description = "Source chain name (e.g. 'ethereum', 'arbitrum', 'base')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain LayerZero Endpoint ID (e.g. 30110 for Arbitrum)")]
    pub dst_eid: u32,
    #[schemars(description = "Hex-encoded message payload (with or without 0x prefix)")]
    pub message_hex: String,
    #[schemars(description = "Hex-encoded LayerZero V3 options bytes (default: lzReceive with 200000 gas if omitted)")]
    pub options_hex: Option<String>,
    #[schemars(description = "Hex-encoded sender address (20 bytes, with or without 0x prefix)")]
    pub sender_hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzSendMessageParams {
    #[schemars(description = "Source chain name (e.g. 'ethereum', 'arbitrum', 'base')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain LayerZero Endpoint ID")]
    pub dst_eid: u32,
    #[schemars(description = "Hex-encoded receiver address as bytes32 (left-padded to 32 bytes)")]
    pub receiver: String,
    #[schemars(description = "Hex-encoded message payload")]
    pub message_hex: String,
    #[schemars(description = "Hex-encoded LayerZero V3 options bytes (default: lzReceive with 200000 gas if omitted)")]
    pub options_hex: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTrackMessageParams {
    #[schemars(description = "Transaction hash to track LayerZero message for (with or without 0x prefix)")]
    pub tx_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzGetMessageParams {
    #[schemars(description = "LayerZero message GUID (hex, with or without 0x prefix)")]
    pub guid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzOftQuoteParams {
    #[schemars(description = "Source chain name (e.g. 'ethereum')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain name (e.g. 'arbitrum')")]
    pub dst_chain: String,
    #[schemars(description = "Amount to transfer (in base units as string)")]
    pub amount: String,
    #[schemars(description = "Token symbol (e.g. 'USDC', 'USDT', 'ETH')")]
    pub token_symbol: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzOftListParams {
    // No parameters — lists all available OFTs
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzEncodeOptionsParams {
    #[schemars(description = "Gas limit for lzReceive execution on destination (default: 200000)")]
    pub gas_limit: Option<u128>,
    #[schemars(description = "Native token amount to drop on destination in wei (default: 0)")]
    pub native_drop: Option<u128>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzGetDeploymentsParams {
    // No parameters — returns all LayerZero deployment addresses
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzListDvnsParams {
    // No parameters — lists all DVNs
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzGetMessagesByAddressParams {
    #[schemars(description = "Wallet address to get LayerZero messages for (hex, with or without 0x prefix)")]
    pub address: String,
    #[schemars(description = "Maximum number of messages to return (default: 10)")]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzListChainsParams {
    // No parameters — lists all supported chains with EIDs
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzGetChainRpcParams {
    #[schemars(description = "Chain name to get RPC URL for (e.g. 'ethereum', 'arbitrum', 'base')")]
    pub chain_name: String,
}

// ─── Value Transfer API parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTransferQuoteParams {
    #[schemars(description = "Source chain key (e.g. 'optimism', 'ethereum', 'base', 'solana')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain key (e.g. 'base', 'solana', 'ethereum')")]
    pub dst_chain: String,
    #[schemars(description = "Source token address (use 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE for native ETH, or contract address for ERC-20)")]
    pub src_token: String,
    #[schemars(description = "Destination token address (use 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE for native ETH)")]
    pub dst_token: String,
    #[schemars(description = "Amount to transfer in base units (wei for ETH, smallest unit for tokens)")]
    pub amount: String,
    #[schemars(description = "Sender wallet address on the source chain")]
    pub src_address: String,
    #[schemars(description = "Recipient wallet address on the destination chain")]
    pub dst_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTransferBuildParams {
    #[schemars(description = "Quote ID returned from lz_transfer_quote")]
    pub quote_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTransferStatusParams {
    #[schemars(description = "Quote ID or transfer ID to check status for")]
    pub quote_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTransferChainsParams {
    // No parameters — returns all supported chains
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzTransferTokensParams {
    #[schemars(description = "Filter tokens by chain key (optional, e.g. 'optimism', 'solana')")]
    pub chain: Option<String>,
}

// ─── Stargate V2 parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzStargateQuoteParams {
    #[schemars(description = "Source chain name (e.g. 'optimism', 'ethereum', 'base', 'arbitrum')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain name (e.g. 'base', 'ethereum', 'arbitrum')")]
    pub dst_chain: String,
    #[schemars(description = "Token symbol: 'ETH', 'USDC', or 'USDT'")]
    pub token: String,
    #[schemars(description = "Amount to bridge in base units (wei for ETH, micro-units for USDC/USDT)")]
    pub amount: String,
    #[schemars(description = "Sender/recipient wallet address (hex, 20 bytes)")]
    pub wallet_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzStargateSendParams {
    #[schemars(description = "Source chain name (e.g. 'optimism', 'ethereum', 'base', 'arbitrum')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain name (e.g. 'base', 'ethereum', 'arbitrum')")]
    pub dst_chain: String,
    #[schemars(description = "Token symbol: 'ETH', 'USDC', or 'USDT'")]
    pub token: String,
    #[schemars(description = "Amount to bridge in base units (wei for ETH, micro-units for USDC/USDT)")]
    pub amount: String,
    #[schemars(description = "Sender/recipient wallet address (hex, 20 bytes)")]
    pub wallet_address: String,
    #[schemars(description = "Slippage tolerance in basis points (default: 50 = 0.5%)")]
    pub slippage_bps: Option<u32>,
}

// ─── OFT send parameter struct ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzOftSendParams {
    #[schemars(description = "Source chain name (e.g. 'ethereum', 'arbitrum', 'base')")]
    pub src_chain: String,
    #[schemars(description = "Destination chain name (e.g. 'arbitrum', 'base', 'solana')")]
    pub dst_chain: String,
    #[schemars(description = "OFT contract address on the source chain (hex, 20 bytes)")]
    pub oft_address: String,
    #[schemars(description = "Recipient address (hex, 20 bytes for EVM — will be left-padded to bytes32)")]
    pub recipient: String,
    #[schemars(description = "Amount to send in shared decimals (amountSD, uint64 — OFT V2 uses shared decimals, not local decimals)")]
    pub amount: String,
    #[schemars(description = "Minimum amount to receive in shared decimals (minAmountSD, uint64 — default: 90% of amount)")]
    pub min_amount: Option<String>,
    #[schemars(description = "Gas limit for lzReceive on destination (default: 200000)")]
    pub gas_limit: Option<u128>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LzBroadcastSignedTxParams {
    #[schemars(description = "Source chain name (e.g. 'ethereum', 'arbitrum', 'base', 'optimism', 'polygon', 'avalanche', 'bsc')")]
    pub src_chain: String,
    #[schemars(description = "Pre-signed Ethereum transaction in hex format (the 0x-prefixed RLP-encoded signed transaction). Construct calldata via lz_send_message / lz_oft_send / lz_stargate_send / lz_transfer_build, sign locally with msg.value = nativeFee, then submit here.")]
    pub signed_tx_hex: String,
}

// ─── Helper functions ───

fn err_internal(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

fn err_invalid_params(msg: impl Into<String>) -> ErrorData {
    ErrorData {
        code: ErrorCode::INVALID_PARAMS,
        message: Cow::from(msg.into()),
        data: None,
    }
}

fn json_result(value: serde_json::Value) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput { result: value }))
}

/// Wrap a plain string into a successful tool result.
///
/// Used by `lz_broadcast_signed_tx` to return the raw transaction hash from
/// `eth_sendRawTransaction`. The hex calldata builders (`lz_send_message`,
/// `lz_oft_send`, `lz_stargate_send`, `lz_transfer_build`) all instruct the
/// caller to sign and broadcast — `lz_broadcast_signed_tx` is the canonical
/// broadcast path.
fn text_result(text: impl Into<String>) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput {
        result: serde_json::json!({ "message": text.into() }),
    }))
}

// ─── LayerZero MCP Server ───

/// LayerZero V2 MCP Server providing 20 tools for cross-chain messaging,
/// OFT transfers, Stargate V2 native bridging, Value Transfer API, message
/// tracking, and network information.
///
/// Communicates with:
/// - LayerZero EndpointV2 contract via eth_call on chain RPCs
/// - LayerZero Scan API for message tracking
/// - LayerZero Metadata API for deployments, DVNs, and OFT data
/// - LayerZero Value Transfer API for unified cross-chain quotes (130+ chains)
/// - Stargate V2 StargatePoolNative contracts for ETH/USDC/USDT bridging
#[derive(Clone)]
pub struct LayerZeroMcpServer {
    /// HTTP client for API and RPC calls
    http: reqwest::Client,
    /// Tool router
    _tool_router: ToolRouter<LayerZeroMcpServer>,
}

impl Default for LayerZeroMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LayerZeroMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerZeroMcpServer").finish()
    }
}

#[tool_router]
impl LayerZeroMcpServer {
    /// Create a new LayerZero MCP server.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            _tool_router: Self::tool_router(),
        }
    }

    // ─── Internal helpers ───

    /// Execute an `eth_call` against a chain RPC and return raw response hex bytes.
    async fn eth_call(
        &self,
        rpc_url: &str,
        to: &str,
        calldata: &[u8],
    ) -> std::result::Result<Vec<u8>, ErrorData> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{
                "to": to,
                "data": encode_hex(calldata),
            }, "latest"]
        });

        let resp = self
            .http
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("RPC request to {} failed: {}", rpc_url, e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read RPC response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "RPC returned HTTP {}: {}",
                status, body_text
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(err_internal(format!("RPC error: {}", error)));
        }

        let result_hex = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err_internal("RPC response missing 'result' field"))?;

        decode_hex(result_hex)
    }

    /// Execute an HTTP GET against the Scan API.
    async fn scan_api_get(
        &self,
        path: &str,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let url = format!("{}{}", SCAN_API, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Scan API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Scan API response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Scan API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Scan API response: {}", e)))
    }

    /// Execute an HTTP GET against the Metadata API.
    async fn metadata_api_get(
        &self,
        path: &str,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let url = format!("{}{}", METADATA_API, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Metadata API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Metadata API response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Metadata API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Metadata API response: {}", e)))
    }

    /// Build default LayerZero V3 options: version 3 + lzReceive(gas, value).
    ///
    /// Wire format:
    /// ```text
    /// 0x0003              — version 3 tag
    /// 0x01                — worker ID (executor)
    /// 0x0021              — option length = 33 bytes
    /// 0x01                — option type 1 (lzReceive)
    /// <uint128 gas>       — gas limit (16 bytes, big-endian)
    /// <uint128 value>     — native drop value (16 bytes, big-endian)
    /// ```
    fn build_default_options(gas_limit: u128, native_drop: u128) -> Vec<u8> {
        let mut opts = Vec::with_capacity(38);
        // Version 3 tag
        opts.extend_from_slice(&[0x00, 0x03]);
        // Worker ID = 0x01 (executor)
        opts.push(0x01);
        // Option length: 1 (type) + 16 (gas) + 16 (value) = 33 bytes
        opts.extend_from_slice(&33u16.to_be_bytes());
        // Option type 1 = lzReceive
        opts.push(0x01);
        // uint128 gas
        opts.extend_from_slice(&gas_limit.to_be_bytes());
        // uint128 value (native drop)
        opts.extend_from_slice(&native_drop.to_be_bytes());
        opts
    }

    /// ABI-encode MessagingParams tuple:
    /// `(uint32 dstEid, bytes32 receiver, bytes message, bytes options, bool payInLzToken)`
    ///
    /// Layout (offsets relative to start of tuple):
    /// - word 0: dstEid (uint32)
    /// - word 1: receiver (bytes32)
    /// - word 2: offset to message bytes data
    /// - word 3: offset to options bytes data
    /// - word 4: payInLzToken (bool = false)
    /// - tail:   message_len || message_padded || options_len || options_padded
    fn encode_messaging_params(
        dst_eid: u32,
        receiver: &[u8; 32],
        message: &[u8],
        options: &[u8],
    ) -> Vec<u8> {
        let head_size: usize = 5 * 32; // 160 bytes

        // Tail offsets (relative to start of the tuple encoding)
        let message_offset = head_size;
        let message_padded_len = message.len().div_ceil(32) * 32;
        let options_offset = message_offset + 32 + message_padded_len;

        let options_padded_len = options.len().div_ceil(32) * 32;
        let total = options_offset + 32 + options_padded_len;
        let mut data = Vec::with_capacity(total);

        // Head words
        data.extend_from_slice(&encode_u32(dst_eid));
        data.extend_from_slice(receiver);
        data.extend_from_slice(&encode_u256(message_offset as u128));
        data.extend_from_slice(&encode_u256(options_offset as u128));
        data.extend_from_slice(&encode_bool(false)); // payInLzToken = false

        // Message tail (length + padded data)
        data.extend_from_slice(&encode_dynamic_bytes(message));

        // Options tail (length + padded data)
        data.extend_from_slice(&encode_dynamic_bytes(options));

        data
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Messaging Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Estimate cross-chain messaging fee via LayerZero EndpointV2.quote() eth_call. Returns the native fee and LZ token fee required to send a message from the source chain to the destination endpoint. Uses the on-chain EndpointV2 contract at 0x1a44076050125825900e736c501f859c50fE728c. Selector: 0xdb9d28c6.")]
    async fn lz_quote_fee(
        &self,
        Parameters(params): Parameters<LzQuoteFeeParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!(
                "Unsupported source chain '{}'. Supported: ethereum, arbitrum, optimism, polygon, bsc, avalanche, base, zksync, sei, sonic, berachain, story, monad, megaeth, tron",
                params.src_chain
            ))
        })?;

        let message = decode_hex(&params.message_hex)?;

        let options = if let Some(ref opts_hex) = params.options_hex {
            decode_hex(opts_hex)?
        } else {
            Self::build_default_options(200_000, 0)
        };

        let sender_bytes = decode_hex(&params.sender_hex)?;
        if sender_bytes.len() != 20 {
            return Err(err_invalid_params("Sender address must be 20 bytes"));
        }

        // Use sender padded to bytes32 as the receiver for quoting (receiver does not affect fee)
        let receiver = pad_left_32(&sender_bytes);

        let params_encoded = Self::encode_messaging_params(
            params.dst_eid,
            &receiver,
            &message,
            &options,
        );

        // quote(MessagingParams calldata _params, address _sender)
        //   returns (MessagingFee memory fee)
        // Selector: 0xdb9d28c6
        let selector: [u8; 4] = [0xdb, 0x9d, 0x28, 0xc6];

        // ABI layout: selector || offset_to_params(32) || sender_address(32) || params_encoded
        let mut calldata = Vec::with_capacity(4 + 64 + params_encoded.len());
        calldata.extend_from_slice(&selector);
        // Offset to MessagingParams tuple = 64 (two words: the offset slot + the sender slot)
        calldata.extend_from_slice(&encode_u256(64));
        // Sender address (left-padded to 32 bytes)
        calldata.extend_from_slice(&pad_left_32(&sender_bytes));
        // MessagingParams data
        calldata.extend_from_slice(&params_encoded);

        let result = self.eth_call(&rpc_url, ENDPOINT_V2, &calldata).await?;

        // Decode MessagingFee(uint256 nativeFee, uint256 lzTokenFee)
        if result.len() < 64 {
            return Err(err_internal(format!(
                "Unexpected quote() response length: {} bytes (expected >= 64)",
                result.len()
            )));
        }

        let native_fee = decode_u256_to_u128(&result[0..32]);
        let lz_token_fee = decode_u256_to_u128(&result[32..64]);
        let native_fee_eth = native_fee as f64 / 1e18;

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_eid": params.dst_eid,
            "dst_chain": eid_to_name(params.dst_eid),
            "endpoint_v2": ENDPOINT_V2,
            "native_fee_wei": native_fee.to_string(),
            "native_fee_eth": format!("{:.8}", native_fee_eth),
            "lz_token_fee_wei": lz_token_fee.to_string(),
            "message_size": message.len(),
            "options_size": options.len(),
        }))
    }

    #[tool(description = "Build transaction calldata for EndpointV2.send() to dispatch a cross-chain message via LayerZero V2. Returns the hex-encoded calldata that should be submitted as a transaction to the EndpointV2 contract on the source chain. The caller must sign and broadcast the transaction with msg.value set to the nativeFee from lz_quote_fee. Selector: 0x5e280f11.")]
    async fn lz_send_message(
        &self,
        Parameters(params): Parameters<LzSendMessageParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        // Validate source chain
        let _rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!(
                "Unsupported source chain '{}'. Supported: ethereum, arbitrum, optimism, polygon, bsc, avalanche, base, zksync, sei, sonic, berachain, story, monad, megaeth, tron",
                params.src_chain
            ))
        })?;

        let receiver_bytes = decode_hex(&params.receiver)?;
        if receiver_bytes.len() != 32 {
            return Err(err_invalid_params(
                "Receiver must be 32 bytes (bytes32). Left-pad a 20-byte EVM address with 12 zero bytes.",
            ));
        }
        let mut receiver = [0u8; 32];
        receiver.copy_from_slice(&receiver_bytes);

        let message = decode_hex(&params.message_hex)?;

        let options = if let Some(ref opts_hex) = params.options_hex {
            decode_hex(opts_hex)?
        } else {
            Self::build_default_options(200_000, 0)
        };

        let params_encoded = Self::encode_messaging_params(
            params.dst_eid,
            &receiver,
            &message,
            &options,
        );

        // send(MessagingParams calldata _params, address _refundAddress)
        //   returns (MessagingReceipt memory receipt)
        // Selector: 0x5e280f11
        let selector: [u8; 4] = [0x5e, 0x28, 0x0f, 0x11];

        // ABI layout: selector || offset_to_params(32) || refund_address(32) || params_encoded
        // Refund address is set to zero — the caller must replace bytes 36..68 with their wallet.
        let mut calldata = Vec::with_capacity(4 + 64 + params_encoded.len());
        calldata.extend_from_slice(&selector);
        // Offset to MessagingParams = 64
        calldata.extend_from_slice(&encode_u256(64));
        // Refund address placeholder (zero — caller replaces with their address)
        calldata.extend_from_slice(&[0u8; 32]);
        // MessagingParams
        calldata.extend_from_slice(&params_encoded);

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_eid": params.dst_eid,
            "dst_chain": eid_to_name(params.dst_eid),
            "endpoint_v2": ENDPOINT_V2,
            "calldata": encode_hex(&calldata),
            "calldata_length": calldata.len(),
            "receiver": encode_hex(&receiver),
            "message_size": message.len(),
            "options_size": options.len(),
            "note": "Submit this calldata as a transaction to the EndpointV2 contract on the source chain. Set msg.value to the nativeFee from lz_quote_fee. Replace the refund address (bytes 36..68 of calldata) with your wallet address.",
        }))
    }

    #[tool(description = "Track a cross-chain LayerZero message by the source transaction hash. Queries the LayerZero Scan API for message status: INFLIGHT, CONFIRMING, DELIVERED, FAILED, or BLOCKED. Returns the full message details including source/destination chains, GUID, and current status.")]
    async fn lz_track_message(
        &self,
        Parameters(params): Parameters<LzTrackMessageParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let tx_hash = if params.tx_hash.starts_with("0x") || params.tx_hash.starts_with("0X") {
            params.tx_hash.clone()
        } else {
            format!("0x{}", params.tx_hash)
        };

        let response = self
            .scan_api_get(&format!("/messages/tx/{}", tx_hash))
            .await?;

        // The Scan API returns { messages: [...] } or { data: [...] }
        let messages = response
            .get("messages")
            .or_else(|| response.get("data"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        json_result(serde_json::json!({
            "tx_hash": tx_hash,
            "messages": messages,
            "scan_url": format!("https://layerzeroscan.com/tx/{}", tx_hash),
        }))
    }

    #[tool(description = "Get a LayerZero message by its GUID (Global Unique Identifier). The GUID is returned by EndpointV2.send() and can also be found in the Scan API message tracking response.")]
    async fn lz_get_message(
        &self,
        Parameters(params): Parameters<LzGetMessageParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let guid = if params.guid.starts_with("0x") || params.guid.starts_with("0X") {
            params.guid.clone()
        } else {
            format!("0x{}", params.guid)
        };

        let response = self
            .scan_api_get(&format!("/messages/guid/{}", guid))
            .await?;

        json_result(serde_json::json!({
            "guid": guid,
            "message": response,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  OFT (Omnichain Fungible Token)
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Quote an OFT (Omnichain Fungible Token) transfer via the LayerZero Metadata API. Returns estimated fees, exchange rates, and transfer details for bridging tokens between chains using LayerZero's OFT standard.")]
    async fn lz_oft_quote(
        &self,
        Parameters(params): Parameters<LzOftQuoteParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        // Validate chain names
        if chain_eid(&params.src_chain).is_none() {
            return Err(err_invalid_params(format!(
                "Unsupported source chain '{}'. Supported: ethereum, arbitrum, optimism, polygon, bsc, avalanche, base, solana, zksync, sei, sonic, berachain, story, monad, megaeth, tron",
                params.src_chain
            )));
        }
        if chain_eid(&params.dst_chain).is_none() {
            return Err(err_invalid_params(format!(
                "Unsupported destination chain '{}'. Supported: ethereum, arbitrum, optimism, polygon, bsc, avalanche, base, solana, zksync, sei, sonic, berachain, story, monad, megaeth, tron",
                params.dst_chain
            )));
        }

        let path = format!(
            "/experiment/ofts/transfer?srcChainName={}&dstChainName={}&amount={}&tokenSymbol={}",
            params.src_chain, params.dst_chain, params.amount, params.token_symbol
        );

        let response = self.metadata_api_get(&path).await?;

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_chain": params.dst_chain,
            "token_symbol": params.token_symbol,
            "amount": params.amount,
            "quote": response,
        }))
    }

    #[tool(description = "List all available OFT (Omnichain Fungible Token) deployments registered in the LayerZero Metadata API. Returns token symbols, contract addresses, supported chains, and deployment details.")]
    async fn lz_oft_list(
        &self,
        Parameters(_params): Parameters<LzOftListParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let response = self.metadata_api_get("/experiment/ofts/list").await?;

        json_result(serde_json::json!({
            "ofts": response,
        }))
    }

    #[tool(description = "Encode LayerZero TYPE_3 options bytes for use with EndpointV2.quote() and EndpointV2.send(). TYPE_3 (version tag 0x0003) is the current standard options format for LayerZero V2. Builds binary options with executor worker ID 0x01 and option type 1 (lzReceive) with configurable gas limit and native token drop amount. Returns the hex-encoded options bytes.")]
    async fn lz_encode_options(
        &self,
        Parameters(params): Parameters<LzEncodeOptionsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let gas_limit = params.gas_limit.unwrap_or(200_000);
        let native_drop = params.native_drop.unwrap_or(0);

        let options = Self::build_default_options(gas_limit, native_drop);

        json_result(serde_json::json!({
            "options_hex": encode_hex(&options),
            "options_length": options.len(),
            "version": 3,
            "type": "TYPE_3",
            "option_type": 1,
            "option_type_name": "lzReceive",
            "gas_limit": gas_limit.to_string(),
            "native_drop_wei": native_drop.to_string(),
            "description": "TYPE_3 options (version tag 0x0003) with lzReceive(gas, nativeDrop). This is the current standard options format for LayerZero V2. Use this hex value as the options_hex parameter in lz_quote_fee and lz_send_message.",
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Network Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Get LayerZero V2 deployment addresses across all supported chains. Returns EndpointV2, SendLib, ReceiveLib, DVN, and Executor addresses from the LayerZero Metadata API.")]
    async fn lz_get_deployments(
        &self,
        Parameters(_params): Parameters<LzGetDeploymentsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let response = self.metadata_api_get("/deployments").await?;

        json_result(serde_json::json!({
            "endpoint_v2": ENDPOINT_V2,
            "deployments": response,
        }))
    }

    #[tool(description = "List all Decentralized Verifier Networks (DVNs) registered in the LayerZero V2 protocol. DVNs verify cross-chain messages by attesting to source chain state on the destination chain. Returns DVN names, addresses, supported chains, and configuration details.")]
    async fn lz_list_dvns(
        &self,
        Parameters(_params): Parameters<LzListDvnsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let response = self.metadata_api_get("/dvns").await?;

        json_result(serde_json::json!({
            "dvns": response,
        }))
    }

    #[tool(description = "Get LayerZero messages for a specific wallet address. Queries the Scan API for all messages sent or received by the given address. Returns message details including status, source/destination chains, and timestamps.")]
    async fn lz_get_messages_by_address(
        &self,
        Parameters(params): Parameters<LzGetMessagesByAddressParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let address = if params.address.starts_with("0x") || params.address.starts_with("0X") {
            params.address.clone()
        } else {
            format!("0x{}", params.address)
        };

        let limit = params.limit.unwrap_or(10).min(100);

        let response = self
            .scan_api_get(&format!("/messages/wallet/{}?limit={}", address, limit))
            .await?;

        let messages = response
            .get("messages")
            .or_else(|| response.get("data"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        json_result(serde_json::json!({
            "address": address,
            "limit": limit,
            "messages": messages,
        }))
    }

    #[tool(description = "List all 16 chains supported by this LayerZero MCP server with their Endpoint IDs (EIDs). Includes Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base, Solana, zkSync, Sei, Sonic, Berachain, Story, Monad, MegaETH, and Tron. EIDs are used in EndpointV2.quote() and EndpointV2.send() to identify destination chains.")]
    async fn lz_list_chains(
        &self,
        Parameters(_params): Parameters<LzListChainsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chains: Vec<serde_json::Value> = all_chains()
            .into_iter()
            .map(|(name, eid)| {
                serde_json::json!({
                    "name": name,
                    "eid": eid,
                    "rpc_url": chain_rpc(name).unwrap_or_else(|| "N/A".to_string()),
                })
            })
            .collect();

        json_result(serde_json::json!({
            "chains": chains,
            "endpoint_v2": ENDPOINT_V2,
            "note": "EIDs are used as dst_eid in lz_quote_fee and lz_send_message. Solana (EID 30168) uses a different transport and does not have an EVM RPC.",
        }))
    }

    #[tool(description = "Get the public RPC URL for a supported chain by name. These RPC URLs are used by the server for eth_call queries against EndpointV2.")]
    async fn lz_get_chain_rpc(
        &self,
        Parameters(params): Parameters<LzGetChainRpcParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.chain_name).ok_or_else(|| {
            err_invalid_params(format!(
                "No RPC URL for chain '{}'. Supported: ethereum, arbitrum, optimism, polygon, bsc, avalanche, base, zksync, sei, sonic, berachain, story, monad, megaeth, tron. Solana does not use EVM RPC.",
                params.chain_name
            ))
        })?;

        let eid = chain_eid(&params.chain_name);

        json_result(serde_json::json!({
            "chain": params.chain_name,
            "rpc_url": rpc_url,
            "eid": eid,
            "endpoint_v2": ENDPOINT_V2,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Value Transfer API (replaces deprecated Stargate REST API)
    //  Base URL: https://transfer.layerzero-api.com/v1
    //  Supports 130+ chains including Solana, unified quoting + build steps
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Get a cross-chain transfer quote from the LayerZero Value Transfer API. This is the newest LayerZero API (replaces deprecated Stargate REST API) supporting 130+ chains including Solana. Returns quotes with fees, estimated times, and a quote ID for building transaction steps. Use 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE as the token address for native ETH.")]
    async fn lz_transfer_quote(
        &self,
        Parameters(params): Parameters<LzTransferQuoteParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let body = serde_json::json!({
            "srcChainKey": params.src_chain,
            "dstChainKey": params.dst_chain,
            "srcTokenAddress": params.src_token,
            "dstTokenAddress": params.dst_token,
            "amount": params.amount,
            "srcWalletAddress": params.src_address,
            "dstWalletAddress": params.dst_address,
        });

        let url = format!("{}/quotes", TRANSFER_API);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Value Transfer API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Value Transfer API returned HTTP {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse response: {}", e)))?;

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_chain": params.dst_chain,
            "src_token": params.src_token,
            "dst_token": params.dst_token,
            "amount": params.amount,
            "quote": response,
            "note": "Use the quoteId from this response with lz_transfer_build to get signable transaction steps.",
        }))
    }

    #[tool(description = "Build signable transaction steps from a Value Transfer API quote. Takes a quoteId from lz_transfer_quote and returns pre-built transaction calldata (to, data, value) that the caller can sign and broadcast. Handles approval and bridge steps automatically.")]
    async fn lz_transfer_build(
        &self,
        Parameters(params): Parameters<LzTransferBuildParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let body = serde_json::json!({
            "quoteId": params.quote_id,
        });

        let url = format!("{}/build-user-steps", TRANSFER_API);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Value Transfer API build request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Value Transfer API build returned HTTP {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse response: {}", e)))?;

        json_result(serde_json::json!({
            "quote_id": params.quote_id,
            "steps": response,
            "note": "Sign and broadcast each transaction step in order. For EVM: use eth_sendRawTransaction. For Solana: use sendTransaction.",
        }))
    }

    #[tool(description = "Check the status of a Value Transfer API transfer by its quote ID. Returns current transfer status, source/destination transaction hashes, and delivery progress.")]
    async fn lz_transfer_status(
        &self,
        Parameters(params): Parameters<LzTransferStatusParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = format!("{}/status/{}", TRANSFER_API, params.quote_id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Value Transfer API status request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Value Transfer API status returned HTTP {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse response: {}", e)))?;

        json_result(serde_json::json!({
            "quote_id": params.quote_id,
            "status": response,
        }))
    }

    #[tool(description = "List all chains supported by the LayerZero Value Transfer API. Returns 130+ chains including Solana, all EVM L1s and L2s, and their chain keys for use in lz_transfer_quote.")]
    async fn lz_transfer_chains(
        &self,
        Parameters(_params): Parameters<LzTransferChainsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = format!("{}/chains", TRANSFER_API);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Value Transfer API chains request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Value Transfer API chains returned HTTP {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse response: {}", e)))?;

        json_result(serde_json::json!({
            "chains": response,
            "note": "Use chain keys from this list as src_chain and dst_chain in lz_transfer_quote.",
        }))
    }

    #[tool(description = "List tokens available for cross-chain transfer via the LayerZero Value Transfer API. Optionally filter by chain. Returns token addresses, symbols, decimals, and which chains they're available on.")]
    async fn lz_transfer_tokens(
        &self,
        Parameters(params): Parameters<LzTransferTokensParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = if let Some(ref chain) = params.chain {
            format!("{}/tokens?chainKey={}", TRANSFER_API, chain)
        } else {
            format!("{}/tokens", TRANSFER_API)
        };

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Value Transfer API tokens request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Value Transfer API tokens returned HTTP {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse response: {}", e)))?;

        json_result(serde_json::json!({
            "chain_filter": params.chain,
            "tokens": response,
            "note": "Use token addresses from this list as src_token and dst_token in lz_transfer_quote. For native ETH use 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE.",
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Stargate V2 Native Bridging (StargatePoolNative contracts)
    //  Direct on-chain quoteSend/sendToken for ETH, USDC, USDT
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Quote a Stargate V2 native bridge transfer fee. Calls quoteSend() on the StargatePoolNative contract (ETH, USDC, or USDT) to get the exact LayerZero messaging fee for bridging between supported EVM chains. Returns the fee in wei and the minimum amount received after slippage. Supported tokens: ETH (Ethereum/Optimism/Arbitrum/Base), USDC (6 chains), USDT (6 chains).")]
    async fn lz_stargate_quote(
        &self,
        Parameters(params): Parameters<LzStargateQuoteParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported source chain '{}'", params.src_chain))
        })?;

        let dst_eid = chain_eid(&params.dst_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported destination chain '{}'", params.dst_chain))
        })?;

        let pool = stargate_pool(&params.token, &params.src_chain).ok_or_else(|| {
            err_invalid_params(format!(
                "No Stargate V2 pool for {} on {}. Supported: ETH (ethereum/optimism/arbitrum/base), USDC (6 chains), USDT (6 chains)",
                params.token, params.src_chain
            ))
        })?;

        let amount: u128 = params.amount.parse().map_err(|_| {
            err_invalid_params("Amount must be a valid integer in base units (wei)")
        })?;

        let wallet_bytes = decode_hex(&params.wallet_address)?;
        if wallet_bytes.len() != 20 {
            return Err(err_invalid_params("wallet_address must be 20 bytes"));
        }

        let min_amount = amount * 95 / 100; // 5% slippage default for quote

        // Build SendParam tuple for quoteSend
        let to_bytes32 = pad_left_32(&wallet_bytes);

        // quoteSend(SendParam, bool _payInLzToken)
        // SendParam: (uint32 dstEid, bytes32 to, uint256 amountLD, uint256 minAmountLD, bytes extraOptions, bytes composeMsg, bytes oftCmd)
        // selector: 0x3b6f743b

        let selector: [u8; 4] = [0x3b, 0x6f, 0x74, 0x3b];

        // Head: offset to SendParam (0x40), payInLzToken (false)
        // SendParam is dynamic (contains bytes fields), needs offset
        let mut calldata = Vec::with_capacity(512);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&encode_u256(64)); // offset to SendParam
        calldata.extend_from_slice(&encode_bool(false)); // payInLzToken = false

        // SendParam tuple:
        // 7 head words + 3 dynamic tails (all empty bytes)
        calldata.extend_from_slice(&encode_u32(dst_eid));       // dstEid
        calldata.extend_from_slice(&to_bytes32);                 // to
        calldata.extend_from_slice(&encode_u256(amount));        // amountLD
        calldata.extend_from_slice(&encode_u256(min_amount));    // minAmountLD
        // Offsets for dynamic bytes (relative to tuple start = 7 * 32 = 224)
        calldata.extend_from_slice(&encode_u256(7 * 32));       // offset extraOptions
        calldata.extend_from_slice(&encode_u256(7 * 32 + 32));  // offset composeMsg
        calldata.extend_from_slice(&encode_u256(7 * 32 + 64));  // offset oftCmd
        // Empty bytes: extraOptions (len=0), composeMsg (len=0), oftCmd (len=0)
        calldata.extend_from_slice(&encode_u256(0)); // extraOptions length
        calldata.extend_from_slice(&encode_u256(0)); // composeMsg length
        calldata.extend_from_slice(&encode_u256(0)); // oftCmd length (empty = taxi mode)

        let result = self.eth_call(&rpc_url, pool, &calldata).await?;

        // Decode: quoteSend returns (MessagingFee, OFTReceipt)
        // MessagingFee: (uint256 nativeFee, uint256 lzTokenFee)
        // OFTReceipt: (uint256 amountSentLD, uint256 amountReceivedLD)
        if result.len() < 128 {
            return Err(err_internal(format!(
                "Unexpected quoteSend response length: {} bytes (expected >= 128)",
                result.len()
            )));
        }

        let native_fee = decode_u256_to_u128(&result[0..32]);
        let lz_token_fee = decode_u256_to_u128(&result[32..64]);
        let amount_sent = decode_u256_to_u128(&result[64..96]);
        let amount_received = decode_u256_to_u128(&result[96..128]);

        let is_native = is_native_token(&params.token, &params.src_chain);
        let total_value = if is_native {
            native_fee + amount
        } else {
            native_fee
        };

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_chain": params.dst_chain,
            "token": params.token,
            "pool_contract": pool,
            "amount_in": amount.to_string(),
            "amount_sent": amount_sent.to_string(),
            "amount_received": amount_received.to_string(),
            "native_fee_wei": native_fee.to_string(),
            "native_fee_eth": format!("{:.8}", native_fee as f64 / 1e18),
            "lz_token_fee": lz_token_fee.to_string(),
            "total_msg_value_wei": total_value.to_string(),
            "total_msg_value_eth": format!("{:.8}", total_value as f64 / 1e18),
            "is_native_token": is_native,
            "dst_eid": dst_eid,
            "note": format!(
                "To execute: call sendToken() on {} with msg.value = {}. Use lz_stargate_send to build the full calldata.",
                pool, total_value
            ),
        }))
    }

    #[tool(description = "Build transaction calldata for a Stargate V2 sendToken() bridge transfer. Returns hex-encoded calldata, the target contract address, and the msg.value to include. The caller must sign and broadcast the transaction. For native ETH, msg.value = nativeFee + bridgeAmount. For ERC-20 tokens (USDC/USDT), approve the pool contract first, then msg.value = nativeFee only. Supported: ETH (4 chains), USDC (6 chains), USDT (6 chains).")]
    async fn lz_stargate_send(
        &self,
        Parameters(params): Parameters<LzStargateSendParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported source chain '{}'", params.src_chain))
        })?;

        let dst_eid = chain_eid(&params.dst_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported destination chain '{}'", params.dst_chain))
        })?;

        let pool = stargate_pool(&params.token, &params.src_chain).ok_or_else(|| {
            err_invalid_params(format!(
                "No Stargate V2 pool for {} on {}",
                params.token, params.src_chain
            ))
        })?;

        let amount: u128 = params.amount.parse().map_err(|_| {
            err_invalid_params("Amount must be a valid integer in base units")
        })?;

        let wallet_bytes = decode_hex(&params.wallet_address)?;
        if wallet_bytes.len() != 20 {
            return Err(err_invalid_params("wallet_address must be 20 bytes"));
        }

        let slippage_bps = params.slippage_bps.unwrap_or(50);
        let min_amount = amount * (10000 - slippage_bps as u128) / 10000;

        let to_bytes32 = pad_left_32(&wallet_bytes);

        // Step 1: Quote fee first
        let quote_selector: [u8; 4] = [0x3b, 0x6f, 0x74, 0x3b];
        let mut quote_calldata = Vec::with_capacity(512);
        quote_calldata.extend_from_slice(&quote_selector);
        quote_calldata.extend_from_slice(&encode_u256(64));
        quote_calldata.extend_from_slice(&encode_bool(false));
        quote_calldata.extend_from_slice(&encode_u32(dst_eid));
        quote_calldata.extend_from_slice(&to_bytes32);
        quote_calldata.extend_from_slice(&encode_u256(amount));
        quote_calldata.extend_from_slice(&encode_u256(min_amount));
        quote_calldata.extend_from_slice(&encode_u256(7 * 32));
        quote_calldata.extend_from_slice(&encode_u256(7 * 32 + 32));
        quote_calldata.extend_from_slice(&encode_u256(7 * 32 + 64));
        quote_calldata.extend_from_slice(&encode_u256(0));
        quote_calldata.extend_from_slice(&encode_u256(0));
        quote_calldata.extend_from_slice(&encode_u256(0));

        let quote_result = self.eth_call(&rpc_url, pool, &quote_calldata).await?;
        if quote_result.len() < 128 {
            return Err(err_internal("quoteSend returned invalid data"));
        }

        let native_fee = decode_u256_to_u128(&quote_result[0..32]);
        let amount_received = decode_u256_to_u128(&quote_result[96..128]);

        // Step 2: Build sendToken calldata
        // sendToken(SendParam, MessagingFee, address refundAddress)
        // selector: 0xcbef2aa9
        let send_selector: [u8; 4] = [0xcb, 0xef, 0x2a, 0xa9];

        // ABI layout:
        // [0] offset to SendParam (dynamic — 3 args × 32 = 96, but MessagingFee is static tuple inline)
        // Actually: arg1=SendParam(dynamic), arg2=MessagingFee(static tuple), arg3=address(static)
        // Head: sendParam_offset(32) + nativeFee(32) + lzTokenFee(32) + refundAddr(32) = 128
        let head_size: u128 = 32 + 64 + 32; // offset + MessagingFee(2 words) + address

        let mut calldata = Vec::with_capacity(768);
        calldata.extend_from_slice(&send_selector);
        // Offset to SendParam tuple
        calldata.extend_from_slice(&encode_u256(head_size));
        // MessagingFee inline: (nativeFee, lzTokenFee=0)
        calldata.extend_from_slice(&encode_u256(native_fee));
        calldata.extend_from_slice(&encode_u256(0)); // lzTokenFee = 0
        // Refund address (left-padded)
        calldata.extend_from_slice(&pad_left_32(&wallet_bytes));

        // SendParam tuple (same as quote):
        calldata.extend_from_slice(&encode_u32(dst_eid));
        calldata.extend_from_slice(&to_bytes32);
        calldata.extend_from_slice(&encode_u256(amount));
        calldata.extend_from_slice(&encode_u256(min_amount));
        calldata.extend_from_slice(&encode_u256(7 * 32));       // extraOptions offset
        calldata.extend_from_slice(&encode_u256(7 * 32 + 32));  // composeMsg offset
        calldata.extend_from_slice(&encode_u256(7 * 32 + 64));  // oftCmd offset
        calldata.extend_from_slice(&encode_u256(0)); // extraOptions length
        calldata.extend_from_slice(&encode_u256(0)); // composeMsg length
        calldata.extend_from_slice(&encode_u256(0)); // oftCmd length

        let is_native = is_native_token(&params.token, &params.src_chain);
        let msg_value = if is_native {
            native_fee + amount
        } else {
            native_fee
        };

        let mut result = serde_json::json!({
            "src_chain": params.src_chain,
            "dst_chain": params.dst_chain,
            "token": params.token,
            "pool_contract": pool,
            "calldata": encode_hex(&calldata),
            "calldata_length": calldata.len(),
            "msg_value_wei": msg_value.to_string(),
            "msg_value_eth": format!("{:.8}", msg_value as f64 / 1e18),
            "native_fee_wei": native_fee.to_string(),
            "amount_in": amount.to_string(),
            "amount_received": amount_received.to_string(),
            "min_amount": min_amount.to_string(),
            "slippage_bps": slippage_bps,
            "dst_eid": dst_eid,
            "is_native_token": is_native,
        });

        // Add ERC-20 approval info if not native
        if !is_native {
            // ERC-20 approve(spender, amount) selector: 0x095ea7b3
            let mut approve_calldata = Vec::with_capacity(68);
            approve_calldata.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
            let pool_bytes = decode_hex(pool).unwrap_or_default();
            approve_calldata.extend_from_slice(&pad_left_32(&pool_bytes));
            approve_calldata.extend_from_slice(&encode_u256(amount));

            let token_contract = match params.token.to_uppercase().as_str() {
                "USDC" => match params.src_chain.to_lowercase().as_str() {
                    "optimism" | "op" => "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
                    "arbitrum" | "arb" => "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
                    "base" => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "ethereum" | "eth" => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "polygon" | "matic" => "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
                    "avalanche" | "avax" => "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
                    _ => "unknown",
                },
                "USDT" => match params.src_chain.to_lowercase().as_str() {
                    "optimism" | "op" => "0x94b008aA00579c1307B0EF2c499aD98a8cE58e58",
                    "arbitrum" | "arb" => "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
                    "ethereum" | "eth" => "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                    "bsc" | "bnb" => "0x55d398326f99059fF775485246999027B3197955",
                    "polygon" | "matic" => "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
                    "avalanche" | "avax" => "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7",
                    _ => "unknown",
                },
                _ => "unknown",
            };

            result["approval_step"] = serde_json::json!({
                "note": format!("Before calling sendToken, approve the pool ({}) to spend your {} tokens", pool, params.token),
                "token_contract": token_contract,
                "approve_calldata": encode_hex(&approve_calldata),
                "approve_msg_value": "0",
            });
        }

        result["note"] = serde_json::json!(format!(
            "Sign and submit as a transaction to {}. Set msg.value = {}{}.",
            pool,
            msg_value,
            if is_native { " (includes bridge amount + LZ fee)" } else { " (LZ fee only — approve ERC-20 first)" }
        ));

        json_result(result)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  OFT Send Tool (build calldata for any OFT contract)
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Build transaction calldata for an OFT (Omnichain Fungible Token) send() call on any OFT contract. OFT V2 uses uint64 amountSD (shared decimals) instead of uint256 amountLD. Returns the hex-encoded calldata for OFT.send(SendParam, MessagingFee, refundAddress). The caller must first call lz_quote_fee or lz_oft_quote to get the messaging fee, then sign and broadcast this transaction with msg.value = nativeFee.")]
    async fn lz_oft_send(
        &self,
        Parameters(params): Parameters<LzOftSendParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported source chain '{}'", params.src_chain))
        })?;

        let dst_eid = chain_eid(&params.dst_chain).ok_or_else(|| {
            err_invalid_params(format!("Unsupported destination chain '{}'", params.dst_chain))
        })?;

        // OFT V2 uses uint64 amountSD (shared decimals), not uint256 amountLD
        let amount_sd: u64 = params.amount.parse().map_err(|_| {
            err_invalid_params("Amount must be a valid uint64 integer in shared decimals (amountSD)")
        })?;

        let min_amount_sd: u64 = if let Some(ref min) = params.min_amount {
            min.parse().map_err(|_| err_invalid_params("min_amount must be a valid uint64 integer (amountSD)"))?
        } else {
            amount_sd * 90 / 100
        };

        let recipient_bytes = decode_hex(&params.recipient)?;
        if recipient_bytes.len() != 20 {
            return Err(err_invalid_params("Recipient must be 20 bytes (EVM address)"));
        }
        let to_bytes32 = pad_left_32(&recipient_bytes);

        let gas_limit = params.gas_limit.unwrap_or(200_000);
        let options = Self::build_default_options(gas_limit, 0);

        let oft_address = &params.oft_address;

        // Step 1: Quote fee via quoteSend on the OFT contract
        let quote_selector: [u8; 4] = [0x3b, 0x6f, 0x74, 0x3b];

        // Encode SendParam with options
        // OFT V2 SendParam: (uint32 dstEid, bytes32 to, uint64 amountSD, uint64 minAmountSD, bytes extraOptions, bytes composeMsg, bytes oftCmd)
        let extra_options_encoded = encode_dynamic_bytes(&options);
        let empty_bytes_encoded = encode_dynamic_bytes(&[]);

        // Dynamic offsets within SendParam (relative to tuple start)
        let extra_options_offset = 7 * 32;
        let compose_msg_offset = extra_options_offset + extra_options_encoded.len();
        let oft_cmd_offset = compose_msg_offset + empty_bytes_encoded.len();

        let mut quote_calldata = Vec::with_capacity(512);
        quote_calldata.extend_from_slice(&quote_selector);
        quote_calldata.extend_from_slice(&encode_u256(64)); // offset to SendParam
        quote_calldata.extend_from_slice(&encode_bool(false)); // payInLzToken
        quote_calldata.extend_from_slice(&encode_u32(dst_eid));
        quote_calldata.extend_from_slice(&to_bytes32);
        quote_calldata.extend_from_slice(&encode_u64(amount_sd));       // amountSD (uint64)
        quote_calldata.extend_from_slice(&encode_u64(min_amount_sd));   // minAmountSD (uint64)
        quote_calldata.extend_from_slice(&encode_u256(extra_options_offset as u128));
        quote_calldata.extend_from_slice(&encode_u256(compose_msg_offset as u128));
        quote_calldata.extend_from_slice(&encode_u256(oft_cmd_offset as u128));
        quote_calldata.extend_from_slice(&extra_options_encoded);
        quote_calldata.extend_from_slice(&empty_bytes_encoded); // composeMsg
        quote_calldata.extend_from_slice(&empty_bytes_encoded); // oftCmd

        let quote_result = self.eth_call(&rpc_url, oft_address, &quote_calldata).await?;
        if quote_result.len() < 64 {
            return Err(err_internal("quoteSend returned invalid data"));
        }
        let native_fee = decode_u256_to_u128(&quote_result[0..32]);

        // Step 2: Build send calldata
        // send(SendParam, MessagingFee, address refundAddress)
        // selector: 0xcbef2aa9
        let send_selector: [u8; 4] = [0xcb, 0xef, 0x2a, 0xa9];
        let head_size: u128 = 32 + 64 + 32;

        let mut calldata = Vec::with_capacity(768);
        calldata.extend_from_slice(&send_selector);
        calldata.extend_from_slice(&encode_u256(head_size)); // offset to SendParam
        calldata.extend_from_slice(&encode_u256(native_fee)); // MessagingFee.nativeFee
        calldata.extend_from_slice(&encode_u256(0)); // MessagingFee.lzTokenFee
        calldata.extend_from_slice(&pad_left_32(&recipient_bytes)); // refund to sender

        // SendParam tuple with options (OFT V2: uint64 amountSD)
        calldata.extend_from_slice(&encode_u32(dst_eid));
        calldata.extend_from_slice(&to_bytes32);
        calldata.extend_from_slice(&encode_u64(amount_sd));         // amountSD (uint64)
        calldata.extend_from_slice(&encode_u64(min_amount_sd));     // minAmountSD (uint64)
        calldata.extend_from_slice(&encode_u256(extra_options_offset as u128));
        calldata.extend_from_slice(&encode_u256(compose_msg_offset as u128));
        calldata.extend_from_slice(&encode_u256(oft_cmd_offset as u128));
        calldata.extend_from_slice(&extra_options_encoded);
        calldata.extend_from_slice(&empty_bytes_encoded);
        calldata.extend_from_slice(&empty_bytes_encoded);

        json_result(serde_json::json!({
            "src_chain": params.src_chain,
            "dst_chain": params.dst_chain,
            "oft_contract": oft_address,
            "dst_eid": dst_eid,
            "calldata": encode_hex(&calldata),
            "calldata_length": calldata.len(),
            "msg_value_wei": native_fee.to_string(),
            "msg_value_eth": format!("{:.8}", native_fee as f64 / 1e18),
            "amount_sd": amount_sd.to_string(),
            "min_amount_sd": min_amount_sd.to_string(),
            "gas_limit_dst": gas_limit.to_string(),
            "note": format!(
                "OFT V2 uses uint64 amountSD (shared decimals). Sign and submit to {} with msg.value = {} wei. Approve the OFT contract to spend your tokens first if it's an ERC-20.",
                oft_address, native_fee
            ),
        }))
    }

    #[tool(description = "Broadcast a pre-signed Ethereum transaction via eth_sendRawTransaction on the source chain RPC. Use this as the canonical broadcast path for calldata produced by lz_send_message (EndpointV2.send), lz_oft_send (OFT.send), lz_stargate_send (StargatePoolNative.sendToken), and lz_transfer_build (Value Transfer API steps). Returns the transaction hash on success. The caller must construct calldata, sign locally with msg.value = nativeFee from the corresponding quote tool, then submit the RLP-encoded signed tx hex here.")]
    async fn lz_broadcast_signed_tx(
        &self,
        Parameters(params): Parameters<LzBroadcastSignedTxParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_url = chain_rpc(&params.src_chain).ok_or_else(|| {
            err_invalid_params(format!("Unknown chain: {}", params.src_chain))
        })?;

        let raw = if params.signed_tx_hex.starts_with("0x") || params.signed_tx_hex.starts_with("0X") {
            params.signed_tx_hex.clone()
        } else {
            format!("0x{}", params.signed_tx_hex)
        };

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw],
        });

        let resp = self
            .http
            .post(&rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("RPC request to {} failed: {}", rpc_url, e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read RPC response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "RPC returned HTTP {}: {}",
                status, body_text
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(err_internal(format!("eth_sendRawTransaction error: {}", error)));
        }

        let tx_hash = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err_internal("eth_sendRawTransaction response missing 'result' field"))?
            .to_string();

        text_result(tx_hash)
    }
}

// ─── ServerHandler ───

#[rmcp::tool_handler]
impl rmcp::ServerHandler for LayerZeroMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-layerzero".into();
        impl_info.title = Some("Tenzro LayerZero MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "LayerZero V2 cross-chain messaging — fee quoting, message tracking, OFT transfers, DVN configuration"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro LayerZero MCP Server — the most complete LayerZero V2 MCP available. \
             20 tools for cross-chain messaging, native bridging, and token transfers.\n\n\
             TOOLS BY CATEGORY:\n\n\
             Messaging (4 tools):\n\
             - lz_quote_fee — Estimate cross-chain messaging fee via EndpointV2.quote()\n\
             - lz_send_message — Build transaction calldata for EndpointV2.send()\n\
             - lz_track_message — Track message status by source transaction hash\n\
             - lz_get_message — Get message details by GUID\n\n\
             OFT Omnichain Fungible Token (4 tools):\n\
             - lz_oft_quote — Quote an OFT transfer between chains\n\
             - lz_oft_send — Build OFT send() calldata with auto fee quoting\n\
             - lz_oft_list — List available OFT deployments\n\
             - lz_encode_options — Encode LayerZero V3 options bytes\n\n\
             Value Transfer API (5 tools) — replaces deprecated Stargate REST API:\n\
             - lz_transfer_quote — Get cross-chain transfer quote (130+ chains incl Solana)\n\
             - lz_transfer_build — Build signable transaction steps from a quote\n\
             - lz_transfer_status — Check transfer status by quote ID\n\
             - lz_transfer_chains — List all 130+ supported chains\n\
             - lz_transfer_tokens — List available tokens, filter by chain\n\n\
             Stargate V2 Native Bridging (2 tools):\n\
             - lz_stargate_quote — Quote native ETH/USDC/USDT bridge via StargatePoolNative\n\
             - lz_stargate_send — Build sendToken() calldata with auto fee + approval steps\n\n\
             Network (5 tools):\n\
             - lz_get_deployments — Get LayerZero deployment addresses\n\
             - lz_list_dvns — List Decentralized Verifier Networks\n\
             - lz_get_messages_by_address — Get messages for a wallet address\n\
             - lz_list_chains — List supported chains with EIDs\n\
             - lz_get_chain_rpc — Get RPC URL for a chain\n\n\
             Transaction Submission (1 tool):\n\
             - lz_broadcast_signed_tx — Broadcast a pre-signed transaction via eth_sendRawTransaction on the source chain RPC"
                .to_string(),
        );
        info
    }
}

// ─── Startup ───

/// Start the LayerZero MCP server on the given address using Streamable HTTP transport.
pub async fn start_layerzero_mcp_server(
    listen_addr: String,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService, StreamableHttpServerConfig,
    };

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "layerzero-mcp.tenzro.network".to_string(),
        ]);

    let service = StreamableHttpService::new(
        move || Ok(LayerZeroMcpServer::new()),
        std::sync::Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| format!("Failed to bind LayerZero MCP server to {}: {}", listen_addr, e))?;

    tracing::info!(
        "LayerZero MCP server listening on {} (Streamable HTTP, stateless)",
        listen_addr
    );

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("LayerZero MCP server error: {}", e))?;

    Ok(())
}
