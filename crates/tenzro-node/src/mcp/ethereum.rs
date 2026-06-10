//! Ethereum MCP Server — Model Context Protocol tools for Ethereum mainnet interaction
//!
//! Provides 16 MCP tools for interacting with Ethereum:
//! - DeFi tools (Chainlink price feeds, gas price, gas estimation, fee history)
//! - Account tools (balance, ERC-20, transactions, blocks, receipts)
//! - ENS tools (resolve, reverse lookup)
//! - Smart contract tools (eth_call, ABI encoding)
//! - ERC-8004 Agent Registry (register, lookup)
//! - EAS Ethereum Attestation Service (query attestations)
//!
//! All tools communicate with an Ethereum JSON-RPC endpoint via HTTP using reqwest.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, Json, ServerHandler,
};
use serde::Deserialize;

use super::server::RpcPassthroughOutput;

// ─── Tool parameter structs ───

// DeFi Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetPriceParams {
    #[schemars(description = "Chainlink AggregatorV3Interface data feed address (default: ETH/USD 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419)")]
    pub feed_address: Option<String>,
    #[schemars(description = "Chain ID — 1 for mainnet (default), 8453 for Base, 42161 for Arbitrum. Selects the dRPC chain-specific URL for the feed read.")]
    pub chain_id: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetGasPriceParams {
    // No parameters — returns current gas price
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthEstimateGasParams {
    #[schemars(description = "Sender address (hex, with or without 0x prefix)")]
    pub from: Option<String>,
    #[schemars(description = "Recipient/contract address (hex, with or without 0x prefix)")]
    pub to: String,
    #[schemars(description = "Hex-encoded calldata (with or without 0x prefix)")]
    pub data: Option<String>,
    #[schemars(description = "Value in wei (hex string, e.g. '0xde0b6b3a7640000' for 1 ETH)")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetFeeHistoryParams {
    #[schemars(description = "Number of blocks to return (default '5')")]
    pub block_count: Option<String>,
    #[schemars(description = "Newest block ('latest' by default, or hex block number)")]
    pub newest_block: Option<String>,
    #[schemars(description = "Reward percentiles as JSON array of floats (e.g. [25.0, 50.0, 75.0])")]
    pub reward_percentiles: Option<Vec<f64>>,
}

// Account Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetBalanceParams {
    #[schemars(description = "Ethereum address (hex, with or without 0x prefix)")]
    pub address: String,
    #[schemars(description = "Block parameter ('latest', 'earliest', 'pending', or hex block number). Default: 'latest'")]
    pub block: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetTokenBalanceParams {
    #[schemars(description = "ERC-20 token contract address (hex, with or without 0x prefix)")]
    pub token_address: String,
    #[schemars(description = "Owner address to check balance for (hex, with or without 0x prefix)")]
    pub owner_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetTransactionParams {
    #[schemars(description = "Transaction hash (hex, with or without 0x prefix)")]
    pub tx_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetBlockParams {
    #[schemars(description = "Block number as hex string (e.g. '0x10d4f') or tag ('latest', 'earliest', 'pending'). Default: 'latest'")]
    pub block_number: Option<String>,
    #[schemars(description = "If true, return full transaction objects instead of just hashes. Default: false")]
    pub full_transactions: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetTransactionReceiptParams {
    #[schemars(description = "Transaction hash (hex, with or without 0x prefix)")]
    pub tx_hash: String,
}

// ENS Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthResolveEnsParams {
    #[schemars(description = "ENS name to resolve (e.g. 'vitalik.eth')")]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthLookupEnsParams {
    #[schemars(description = "Ethereum address to reverse-lookup (hex, with or without 0x prefix)")]
    pub address: String,
}

// Smart Contract Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthCallContractParams {
    #[schemars(description = "Contract address (hex, with or without 0x prefix)")]
    pub to: String,
    #[schemars(description = "Hex-encoded calldata (with or without 0x prefix)")]
    pub data: String,
    #[schemars(description = "Block parameter ('latest', 'earliest', 'pending', or hex block number). Default: 'latest'")]
    pub block: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthEncodeFunctionParams {
    #[schemars(description = "Canonical function signature (e.g. 'transfer(address,uint256)', 'approve(address,uint256)', 'balanceOf(address)')")]
    pub function_sig: String,
    #[schemars(description = "Arguments as JSON array of hex-encoded values (each will be left-padded to 32 bytes). E.g. ['0xRecipientAddress', '0xde0b6b3a7640000']")]
    pub args: Vec<String>,
}

// ERC-8004 Agent Registry

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthRegisterAgent8004Params {
    #[schemars(description = "Human-readable agent name")]
    pub agent_name: String,
    #[schemars(description = "List of capability strings (e.g. ['nlp', 'code-generation', 'web-search'])")]
    pub capabilities: Vec<String>,
    #[schemars(description = "IPFS or HTTPS URI pointing to full agent metadata JSON")]
    pub metadata_uri: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthLookupAgent8004Params {
    #[schemars(description = "Agent ID (uint256 hex) or owner address (hex) to look up")]
    pub agent_id_or_address: String,
}

// EAS (Ethereum Attestation Service)

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthGetAttestationParams {
    #[schemars(description = "Attestation UID (bytes32 hex, with or without 0x prefix)")]
    pub uid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EthSendRawTransactionParams {
    #[schemars(description = "Signed RLP-encoded transaction as hex (0x-prefixed). Build with the tenzro_signTransaction helper or any EIP-1559/legacy signer.")]
    pub raw_tx: String,
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

/// Wrap a plain-text status string as a successful tool result.
///
/// Used by tools that return a single textual value (e.g. transaction hash,
/// confirmation message) rather than a structured JSON envelope.
fn text_result(text: impl Into<String>) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput {
        result: serde_json::json!({ "message": text.into() }),
    }))
}

/// Normalize a hex string to have the `0x` prefix.
fn normalize_hex(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

/// Strip 0x prefix if present.
fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Resolve a chain ID to a dRPC HTTPS URL for Chainlink data-feed reads.
///
/// Used by `eth_get_price` when the caller passes a non-default `chain_id`.
/// Falls back to the public LlamaRPC endpoint for that chain when
/// `DRPC_API_KEY` is not set. Unknown chain IDs fall back to mainnet.
fn chainlink_chain_rpc_url(chain_id: u64) -> String {
    let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
    let chain_slug = match chain_id {
        1 => "ethereum",
        8453 => "base",
        42161 => "arbitrum",
        10 => "optimism",
        137 => "polygon",
        43114 => "avalanche",
        56 => "bsc",
        _ => "ethereum",
    };
    if key.is_empty() {
        match chain_slug {
            "base" => "https://base.llamarpc.com".to_string(),
            "arbitrum" => "https://arbitrum.llamarpc.com".to_string(),
            "optimism" => "https://optimism.llamarpc.com".to_string(),
            "polygon" => "https://polygon.llamarpc.com".to_string(),
            "avalanche" => "https://avalanche.llamarpc.com".to_string(),
            "bsc" => "https://binance.llamarpc.com".to_string(),
            _ => "https://eth.llamarpc.com".to_string(),
        }
    } else {
        format!("https://lb.drpc.live/{}/{}", chain_slug, key)
    }
}

/// Left-pad a hex value (without 0x) to 32 bytes (64 hex chars).
fn pad_to_32_bytes(hex_val: &str) -> String {
    let clean = strip_0x(hex_val);
    if clean.len() >= 64 {
        clean[..64].to_string()
    } else {
        format!("{:0>64}", clean)
    }
}

/// Parse a hex quantity string (e.g. "0x1a4") to u128.
fn hex_to_u128(hex: &str) -> Result<u128, String> {
    let clean = strip_0x(hex);
    if clean.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(clean, 16).map_err(|e| format!("Invalid hex '{}': {}", hex, e))
}

/// Parse a hex quantity string to i128 (for signed values like Chainlink answer).
fn hex_to_i128(hex: &str) -> Result<i128, String> {
    let clean = strip_0x(hex);
    if clean.is_empty() {
        return Ok(0);
    }
    // Handle two's complement for negative values in 256-bit words
    if clean.len() == 64 && clean.starts_with(['8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F']) {
        // Negative value — parse as unsigned then convert
        let unsigned = u128::from_str_radix(clean, 16)
            .map_err(|e| format!("Invalid hex '{}': {}", hex, e))?;
        Ok(unsigned as i128)
    } else {
        i128::from_str_radix(clean, 16).map_err(|e| format!("Invalid hex '{}': {}", hex, e))
    }
}

/// Format wei as ETH string with 18 decimal places.
fn wei_to_eth(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let remainder = wei % 1_000_000_000_000_000_000;
    format!("{}.{:018}", eth, remainder)
}

/// Format wei as Gwei string.
fn wei_to_gwei(wei: u128) -> String {
    let gwei = wei / 1_000_000_000;
    let remainder = wei % 1_000_000_000;
    format!("{}.{:09}", gwei, remainder)
}

/// Compute the 4-byte function selector from a Solidity function signature
fn function_selector(sig: &str) -> [u8; 4] {
    let hash = tenzro_crypto::hash::keccak256(sig.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash.as_bytes()[..4]);
    selector
}

/// Compute ENS namehash for a domain.
/// namehash('') = 0x0000...0000
/// namehash('eth') = keccak256(namehash('') + keccak256('eth'))
/// namehash('vitalik.eth') = keccak256(namehash('eth') + keccak256('vitalik'))
fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in labels.iter().rev() {
        let label_hash = tenzro_crypto::hash::keccak256(label.as_bytes());
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&node);
        combined.extend_from_slice(label_hash.as_bytes());
        let new_node = tenzro_crypto::hash::keccak256(&combined);
        node = new_node.to_bytes();
    }
    node
}

/// Convert an ENS name (e.g. "vitalik.eth") to DNS wire format.
/// DNS wire format: each label is prefixed by its length byte, terminated by 0x00.
fn dns_encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        encoded.push(len as u8);
        encoded.extend_from_slice(&bytes[..len]);
    }
    encoded.push(0x00);
    encoded
}

/// ABI-encode resolve(bytes,bytes) calldata for the ENS Universal Resolver.
/// selector: 0x9061b923
fn encode_resolve_calldata(name_bytes: &[u8], inner_data: &[u8]) -> String {
    let selector = "9061b923";

    let name_padded_len = name_bytes.len().div_ceil(32) * 32;
    let inner_padded_len = inner_data.len().div_ceil(32) * 32;
    let offset_name: u64 = 64; // 0x40 — after the two offset words
    let offset_data: u64 = offset_name + 32 + name_padded_len as u64;

    let mut result = String::new();
    result.push_str(selector);

    // offset for name
    result.push_str(&format!("{:064x}", offset_name));
    // offset for data
    result.push_str(&format!("{:064x}", offset_data));

    // name length + padded data
    result.push_str(&format!("{:064x}", name_bytes.len()));
    result.push_str(&hex::encode(name_bytes));
    let name_padding = name_padded_len - name_bytes.len();
    for _ in 0..name_padding {
        result.push_str("00");
    }

    // inner data length + padded data
    result.push_str(&format!("{:064x}", inner_data.len()));
    result.push_str(&hex::encode(inner_data));
    let data_padding = inner_padded_len - inner_data.len();
    for _ in 0..data_padding {
        result.push_str("00");
    }

    result
}

/// Try to extract an Ethereum address from a Universal Resolver result.
/// Scans 32-byte slots for the pattern: 24 zero chars + 40 non-zero hex chars.
fn extract_address_from_resolver(hex_str: &str) -> Option<String> {
    if hex_str.len() < 128 {
        return None;
    }
    let slots = hex_str.len() / 64;
    // Scan from the end — ABI offsets/lengths occupy early slots,
    // actual address data is in later slots.
    for i in (0..slots).rev() {
        let start = i * 64;
        if start + 64 > hex_str.len() {
            continue;
        }
        let slot = &hex_str[start..start + 64];
        let prefix = &slot[..24];
        let addr = &slot[24..64];
        if prefix == "000000000000000000000000"
            && addr != "0000000000000000000000000000000000000000"
            && addr.chars().any(|c| c != '0')
        {
            // Skip values that look like small ABI offset/length words
            // (first non-zero digit appears very late in the address)
            let non_zero_start = addr.find(|c: char| c != '0').unwrap_or(40);
            if non_zero_start < 30 {
                return Some(format!("0x{}", addr));
            }
        }
    }
    None
}

/// Try to extract a string (ENS name) from Universal Resolver reverse-resolution result.
fn extract_string_from_resolver(hex_str: &str) -> Option<String> {
    if hex_str.len() < 128 {
        return None;
    }
    let slots = hex_str.len() / 64;
    for i in 0..slots {
        let start = i * 64;
        if start + 64 > hex_str.len() {
            break;
        }
        let slot = &hex_str[start..start + 64];
        let trimmed = slot.trim_start_matches('0');
        if let Ok(len) = usize::from_str_radix(if trimmed.is_empty() { "0" } else { trimmed }, 16)
            && len > 0
            && len <= 253
        {
            let data_start = (i + 1) * 64;
            let data_end = data_start + len * 2;
            if data_end <= hex_str.len()
                && let Ok(bytes) = hex::decode(&hex_str[data_start..data_end])
                && let Ok(s) = String::from_utf8(bytes)
                && s.contains('.')
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Some(s);
            }
        }
    }
    None
}

// ─── Well-known addresses ───

/// ENS Universal Resolver address on Ethereum mainnet
const ENS_UNIVERSAL_RESOLVER: &str = "0xc0497E381f536Be9ce14B0dD3817cBcAe57d2F62";

/// Chainlink ETH/USD price feed address on Ethereum mainnet
const CHAINLINK_ETH_USD: &str = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419";

// ─── Ethereum MCP Server ───

/// Ethereum MCP Server providing 16 tools for Ethereum mainnet interaction.
///
/// Communicates with an Ethereum JSON-RPC endpoint (default: dRPC with `DRPC_API_KEY` env var, or public fallback)
/// via HTTP/JSON using reqwest.
#[derive(Clone)]
pub struct EthereumMcpServer {
    /// Ethereum JSON-RPC endpoint URL
    rpc_url: String,
    /// HTTP client for API calls
    http: reqwest::Client,
    /// Tool router
    _tool_router: ToolRouter<EthereumMcpServer>,
}

impl std::fmt::Debug for EthereumMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthereumMcpServer")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

#[tool_router]
impl EthereumMcpServer {
    /// Create a new Ethereum MCP server with the given RPC URL.
    /// If the URL is empty, defaults to dRPC with `DRPC_API_KEY` env var, or a public fallback.
    pub fn new(rpc_url: String) -> Self {
        let url = if rpc_url.is_empty() {
            let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
            if key.is_empty() {
                "https://eth.llamarpc.com".to_string()
            } else {
                format!("https://lb.drpc.live/ethereum/{}", key)
            }
        } else {
            rpc_url
        };
        Self {
            rpc_url: url,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            _tool_router: Self::tool_router(),
        }
    }

    /// Create with the default public RPC endpoint (Ethereum mainnet).
    ///
    /// Used by `start_ethereum_mcp_server` when no `ETHEREUM_RPC_URL` env var
    /// is set — equivalent to `Self::new(String::new())` but reads as intent.
    pub fn default_mainnet() -> Self {
        Self::new(String::new())
    }

    /// Set a custom RPC URL.
    ///
    /// Used by `eth_get_price` to scope a single price-feed read to a
    /// non-mainnet chain (Base, Arbitrum, etc.) without mutating the
    /// long-lived server's default RPC.
    pub fn with_rpc_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_url = url.into();
        self
    }

    // ─── Internal JSON-RPC helper ───

    /// Send a JSON-RPC 2.0 request and return the `result` field.
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("RPC request to {} failed: {}", self.rpc_url, e)))?;

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
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown RPC error");
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            return Err(err_internal(format!("RPC error {}: {}", code, msg)));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| err_internal("RPC response missing 'result' field"))
    }

    /// Perform an eth_call and return the hex result string.
    async fn eth_call_raw(
        &self,
        to: &str,
        data: &str,
        block: &str,
    ) -> std::result::Result<String, ErrorData> {
        let result = self
            .rpc_call(
                "eth_call",
                serde_json::json!([
                    { "to": to, "data": data },
                    block,
                ]),
            )
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| err_internal("eth_call result is not a string"))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  1. DeFi Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Get token price from a Chainlink AggregatorV3Interface data feed via eth_call to latestRoundData(). Default feed: ETH/USD on mainnet (0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419). Returns price with 8 decimal precision, round ID, and update timestamps.")]
    async fn eth_get_price(
        &self,
        Parameters(params): Parameters<EthGetPriceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let feed_address = params
            .feed_address
            .unwrap_or_else(|| CHAINLINK_ETH_USD.to_string());
        let feed_address = normalize_hex(&feed_address);

        // Honor explicit chain_id by dispatching the price read against the
        // per-chain dRPC URL via a transient `with_rpc_url` clone — keeps the
        // read scoped to that chain without mutating the long-lived server
        // (the next tool call falls back to the default RPC).
        let result = match params.chain_id {
            Some(chain_id) if chain_id != 1 => {
                let chain_rpc = chainlink_chain_rpc_url(chain_id);
                let scoped = self.clone().with_rpc_url(chain_rpc);
                scoped
                    .eth_call_raw(&feed_address, "0xfeaf968c", "latest")
                    .await?
            }
            _ => {
                self.eth_call_raw(&feed_address, "0xfeaf968c", "latest")
                    .await?
            }
        };

        // Decode ABI return: (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
        // Each slot is 32 bytes = 64 hex chars. Result starts with 0x.
        let hex_data = strip_0x(&result);
        if hex_data.len() < 320 {
            return Err(err_internal(format!(
                "Chainlink response too short ({} hex chars, expected >= 320)",
                hex_data.len()
            )));
        }

        let round_id_hex = &hex_data[0..64];
        let answer_hex = &hex_data[64..128];
        let started_at_hex = &hex_data[128..192];
        let updated_at_hex = &hex_data[192..256];
        let answered_in_round_hex = &hex_data[256..320];

        let round_id = hex_to_u128(round_id_hex).map_err(err_internal)?;
        let answer_raw = hex_to_i128(answer_hex).map_err(err_internal)?;
        let started_at = hex_to_u128(started_at_hex).map_err(err_internal)?;
        let updated_at = hex_to_u128(updated_at_hex).map_err(err_internal)?;
        let answered_in_round = hex_to_u128(answered_in_round_hex).map_err(err_internal)?;

        // Chainlink price feeds use 8 decimals
        let price_dollars = answer_raw as f64 / 1e8;

        json_result(serde_json::json!({
            "feed_address": feed_address,
            "price_usd": format!("{:.8}", price_dollars),
            "answer_raw": answer_raw.to_string(),
            "decimals": 8,
            "round_id": round_id.to_string(),
            "started_at": started_at.to_string(),
            "updated_at": updated_at.to_string(),
            "answered_in_round": answered_in_round.to_string(),
        }))
    }

    #[tool(description = "Get the current gas price from the Ethereum network via eth_gasPrice JSON-RPC. Returns the gas price in wei, Gwei, and hex.")]
    async fn eth_get_gas_price(
        &self,
        Parameters(_params): Parameters<EthGetGasPriceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let result = self.rpc_call("eth_gasPrice", serde_json::json!([])).await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| err_internal("eth_gasPrice result is not a string"))?;
        let wei = hex_to_u128(hex_str).map_err(err_internal)?;

        json_result(serde_json::json!({
            "gas_price_wei": wei.to_string(),
            "gas_price_gwei": wei_to_gwei(wei),
            "gas_price_hex": hex_str,
        }))
    }

    #[tool(description = "Estimate gas required for a transaction via eth_estimateGas. Params: to (required), from/data/value (optional). Returns estimated gas in decimal and hex.")]
    async fn eth_estimate_gas(
        &self,
        Parameters(params): Parameters<EthEstimateGasParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let mut tx_obj = serde_json::json!({
            "to": normalize_hex(&params.to),
        });

        if let Some(ref from) = params.from {
            tx_obj["from"] = serde_json::Value::String(normalize_hex(from));
        }
        if let Some(ref data) = params.data {
            tx_obj["data"] = serde_json::Value::String(normalize_hex(data));
        }
        if let Some(ref value) = params.value {
            tx_obj["value"] = serde_json::Value::String(normalize_hex(value));
        }

        let result = self
            .rpc_call("eth_estimateGas", serde_json::json!([tx_obj]))
            .await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| err_internal("eth_estimateGas result is not a string"))?;
        let gas = hex_to_u128(hex_str).map_err(err_internal)?;

        json_result(serde_json::json!({
            "estimated_gas": gas.to_string(),
            "estimated_gas_hex": hex_str,
        }))
    }

    #[tool(description = "Get fee history for recent blocks via eth_feeHistory. Returns base fees per gas, gas used ratios, and reward percentiles for EIP-1559 gas estimation.")]
    async fn eth_get_fee_history(
        &self,
        Parameters(params): Parameters<EthGetFeeHistoryParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let block_count = params.block_count.unwrap_or_else(|| "5".to_string());
        let newest_block = params.newest_block.unwrap_or_else(|| "latest".to_string());
        let percentiles = params.reward_percentiles.unwrap_or_else(|| vec![25.0, 50.0, 75.0]);

        // eth_feeHistory expects block_count as hex
        let block_count_num: u64 = block_count
            .parse()
            .map_err(|_| err_invalid_params("block_count must be a decimal number"))?;
        let block_count_hex = format!("0x{:x}", block_count_num);

        let result = self
            .rpc_call(
                "eth_feeHistory",
                serde_json::json!([block_count_hex, newest_block, percentiles]),
            )
            .await?;

        json_result(result)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  2. Account Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Get the ETH balance of an address via eth_getBalance. Returns balance in wei, Gwei, and ETH.")]
    async fn eth_get_balance(
        &self,
        Parameters(params): Parameters<EthGetBalanceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let address = normalize_hex(&params.address);
        let block = params.block.unwrap_or_else(|| "latest".to_string());

        let result = self
            .rpc_call("eth_getBalance", serde_json::json!([address, block]))
            .await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| err_internal("eth_getBalance result is not a string"))?;
        let wei = hex_to_u128(hex_str).map_err(err_internal)?;

        json_result(serde_json::json!({
            "address": address,
            "balance_wei": wei.to_string(),
            "balance_gwei": wei_to_gwei(wei),
            "balance_eth": wei_to_eth(wei),
            "block": block,
        }))
    }

    #[tool(description = "Get ERC-20 token balance for an address via eth_call to balanceOf(address). Params: token_address (ERC-20 contract), owner_address. Returns raw balance (caller must divide by 10^decimals for human-readable amount).")]
    async fn eth_get_token_balance(
        &self,
        Parameters(params): Parameters<EthGetTokenBalanceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let token = normalize_hex(&params.token_address);
        let owner = normalize_hex(&params.owner_address);

        // balanceOf(address) selector: 0x70a08231
        let owner_padded = pad_to_32_bytes(&params.owner_address);
        let calldata = format!("0x70a08231{}", owner_padded);

        let result = self.eth_call_raw(&token, &calldata, "latest").await?;

        let hex_data = strip_0x(&result);
        let balance = if hex_data.is_empty() || hex_data == "0" {
            0u128
        } else {
            hex_to_u128(hex_data).map_err(err_internal)?
        };

        json_result(serde_json::json!({
            "token_address": token,
            "owner_address": owner,
            "balance_raw": balance.to_string(),
            "balance_hex": result,
            "note": "Divide balance_raw by 10^decimals to get the human-readable amount. Call decimals() on the token contract to get the decimal count.",
        }))
    }

    #[tool(description = "Get transaction details by hash via eth_getTransactionByHash. Returns sender, recipient, value, gas, input data, block number, and nonce.")]
    async fn eth_get_transaction(
        &self,
        Parameters(params): Parameters<EthGetTransactionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let tx_hash = normalize_hex(&params.tx_hash);

        let result = self
            .rpc_call(
                "eth_getTransactionByHash",
                serde_json::json!([tx_hash]),
            )
            .await?;

        if result.is_null() {
            return json_result(serde_json::json!({
                "error": "Transaction not found",
                "tx_hash": tx_hash,
            }));
        }

        json_result(result)
    }

    #[tool(description = "Get block by number via eth_getBlockByNumber. Params: block_number (hex or 'latest'), full_transactions (bool, default false). Returns block header, transactions, and metadata.")]
    async fn eth_get_block(
        &self,
        Parameters(params): Parameters<EthGetBlockParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let block_number = params
            .block_number
            .unwrap_or_else(|| "latest".to_string());
        let full_txs = params.full_transactions.unwrap_or(false);

        let result = self
            .rpc_call(
                "eth_getBlockByNumber",
                serde_json::json!([block_number, full_txs]),
            )
            .await?;

        if result.is_null() {
            return json_result(serde_json::json!({
                "error": "Block not found",
                "block_number": block_number,
            }));
        }

        json_result(result)
    }

    #[tool(description = "Get transaction receipt by hash via eth_getTransactionReceipt. Returns status (0x0=failure, 0x1=success), gas used, logs, contract address (if deployment), and block info.")]
    async fn eth_get_transaction_receipt(
        &self,
        Parameters(params): Parameters<EthGetTransactionReceiptParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let tx_hash = normalize_hex(&params.tx_hash);

        let result = self
            .rpc_call(
                "eth_getTransactionReceipt",
                serde_json::json!([tx_hash]),
            )
            .await?;

        if result.is_null() {
            return json_result(serde_json::json!({
                "error": "Transaction receipt not found (transaction may be pending or does not exist)",
                "tx_hash": tx_hash,
            }));
        }

        json_result(result)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  3. ENS Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Resolve an ENS name to an Ethereum address. Tries the ENS Universal Resolver on-chain via eth_call (resolve(bytes,bytes) at 0xc0497E381f536Be9ce14B0dD3817cBcAe57d2F62). Falls back to the OnchainKit ENS API as a secondary source. Params: name (e.g. 'vitalik.eth').")]
    async fn eth_resolve_ens(
        &self,
        Parameters(params): Parameters<EthResolveEnsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let name = params.name.trim().to_lowercase();
        if name.is_empty() {
            return Err(err_invalid_params("ENS name cannot be empty"));
        }

        // Primary: Universal Resolver on-chain call
        // resolve(bytes name, bytes data) where data = addr(bytes32 node)
        let dns_name = dns_encode_name(&name);
        let node = namehash(&name);
        // addr(bytes32) selector: 0x3b3b57de
        let mut inner_data = vec![0x3b, 0x3b, 0x57, 0xde];
        inner_data.extend_from_slice(&node);

        let calldata = encode_resolve_calldata(&dns_name, &inner_data);

        match self
            .eth_call_raw(ENS_UNIVERSAL_RESOLVER, &format!("0x{}", calldata), "latest")
            .await
        {
            Ok(result) => {
                let hex_data = strip_0x(&result);
                if let Some(addr) = extract_address_from_resolver(hex_data) {
                    return json_result(serde_json::json!({
                        "name": name,
                        "address": addr,
                        "source": "universal-resolver-onchain",
                    }));
                }
            }
            Err(_) => {
                // Fall through to API fallback
            }
        }

        // Fallback: OnchainKit ENS resolution API
        // ENS names are ASCII-safe so no percent-encoding needed
        let api_url = format!(
            "https://ens.api.onchainkit.com/api/resolve?name={}",
            &name
        );

        if let Ok(resp) = self.http.get(&api_url).send().await
            && resp.status().is_success()
            && let Ok(body) = resp.text().await
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(address) = json
                .get("address")
                .or_else(|| json.get("addr"))
                .and_then(|v| v.as_str())
            && !address.is_empty()
            && address != "0x0000000000000000000000000000000000000000"
        {
            return json_result(serde_json::json!({
                "name": name,
                "address": address,
                "source": "onchainkit-ens-api",
            }));
        }

        json_result(serde_json::json!({
            "name": name,
            "address": null,
            "error": "ENS name not found or not configured",
        }))
    }

    #[tool(description = "Reverse-lookup an Ethereum address to its ENS name via the Universal Resolver on-chain. Constructs <address>.addr.reverse and calls resolve(). Falls back to OnchainKit ENS API. Params: address (hex).")]
    async fn eth_lookup_ens(
        &self,
        Parameters(params): Parameters<EthLookupEnsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let address = normalize_hex(&params.address);
        let clean_addr = strip_0x(&address).to_lowercase();

        // On-chain reverse resolution: resolve <addr>.addr.reverse
        let reverse_name = format!("{}.addr.reverse", clean_addr);
        let dns_name = dns_encode_name(&reverse_name);
        let node = namehash(&reverse_name);

        // name(bytes32) selector: 0x691f3431
        let mut inner_data = vec![0x69, 0x1f, 0x34, 0x31];
        inner_data.extend_from_slice(&node);

        let calldata = encode_resolve_calldata(&dns_name, &inner_data);

        match self
            .eth_call_raw(ENS_UNIVERSAL_RESOLVER, &format!("0x{}", calldata), "latest")
            .await
        {
            Ok(result) => {
                let hex_data = strip_0x(&result);
                if let Some(ens_name) = extract_string_from_resolver(hex_data) {
                    return json_result(serde_json::json!({
                        "address": address,
                        "name": ens_name,
                        "source": "universal-resolver-onchain",
                    }));
                }
            }
            Err(_) => {
                // Fall through to API fallback
            }
        }

        // Fallback: OnchainKit ENS reverse API
        let api_url = format!(
            "https://ens.api.onchainkit.com/api/reverse?address={}",
            &address
        );

        if let Ok(resp) = self.http.get(&api_url).send().await
            && resp.status().is_success()
                && let Ok(body) = resp.text().await
                    && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
                        && let Some(ens_name) = json
                            .get("name")
                            .or_else(|| json.get("ens"))
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            return json_result(serde_json::json!({
                                "address": address,
                                "name": ens_name,
                                "source": "onchainkit-ens-api",
                            }));
                        }

        json_result(serde_json::json!({
            "address": address,
            "name": null,
            "error": "No ENS name found for this address",
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  4. Smart Contract Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Execute a read-only eth_call against a smart contract. Params: to (contract address), data (hex-encoded calldata), block (default 'latest'). Returns the raw hex result. Use eth_encode_function to build calldata from a function signature and arguments.")]
    async fn eth_call_contract(
        &self,
        Parameters(params): Parameters<EthCallContractParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let to = normalize_hex(&params.to);
        let data = normalize_hex(&params.data);
        let block = params.block.unwrap_or_else(|| "latest".to_string());

        let result = self.eth_call_raw(&to, &data, &block).await?;

        json_result(serde_json::json!({
            "to": to,
            "data": data,
            "block": block,
            "result": result,
        }))
    }

    #[tool(description = "ABI-encode a function call. Computes the 4-byte selector from the canonical function signature via Keccak-256, then left-pads each argument to 32 bytes. Returns the complete hex-encoded calldata ready for eth_call or a transaction. Example: function_sig='transfer(address,uint256)', args=['0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', '0xde0b6b3a7640000'].")]
    async fn eth_encode_function(
        &self,
        Parameters(params): Parameters<EthEncodeFunctionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let sig = params.function_sig.trim();
        if sig.is_empty() || !sig.contains('(') || !sig.contains(')') {
            return Err(err_invalid_params(
                "function_sig must be a canonical Solidity signature like 'transfer(address,uint256)'",
            ));
        }

        // Compute 4-byte selector via Keccak-256
        let sel = function_selector(sig);
        let selector_hex = hex::encode(sel);

        // Encode arguments: each arg is left-padded to 32 bytes
        let mut encoded_args = String::new();
        for (i, arg) in params.args.iter().enumerate() {
            let clean = strip_0x(arg.trim());
            if clean.is_empty() {
                return Err(err_invalid_params(format!(
                    "Argument {} is empty",
                    i
                )));
            }
            if clean.len() > 64 {
                return Err(err_invalid_params(format!(
                    "Argument {} exceeds 32 bytes (got {} hex chars)",
                    i,
                    clean.len()
                )));
            }
            encoded_args.push_str(&pad_to_32_bytes(clean));
        }

        let calldata = format!("0x{}{}", selector_hex, encoded_args);

        json_result(serde_json::json!({
            "function_sig": sig,
            "selector": format!("0x{}", selector_hex),
            "args_count": params.args.len(),
            "calldata": calldata,
            "calldata_length_bytes": 4 + params.args.len() * 32,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  5. ERC-8004 Agent Registry
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Build transaction data for registering an AI agent via ERC-8004 Agent Registry. ERC-8004 defines an on-chain registry for autonomous AI agents with capabilities, metadata URI, and owner tracking. Returns the ABI-encoded function selector and parameter breakdown for registerAgent(string,string[],string). The caller must sign and submit the transaction to the registry contract.")]
    async fn eth_register_agent_8004(
        &self,
        Parameters(params): Parameters<EthRegisterAgent8004Params>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        if params.agent_name.is_empty() {
            return Err(err_invalid_params("agent_name cannot be empty"));
        }
        if params.metadata_uri.is_empty() {
            return Err(err_invalid_params("metadata_uri cannot be empty"));
        }

        // registerAgent(string name, string[] capabilities, string metadataURI)
        let sig = "registerAgent(string,string[],string)";
        let sel = function_selector(sig);
        let selector_hex = hex::encode(sel);

        json_result(serde_json::json!({
            "erc_standard": "ERC-8004",
            "function": sig,
            "selector": format!("0x{}", selector_hex),
            "parameters": {
                "name": params.agent_name,
                "capabilities": params.capabilities,
                "metadataURI": params.metadata_uri,
            },
            "note": "This is a state-changing transaction. You must ABI-encode the dynamic parameters (string, string[], string), sign, and send the transaction to an ERC-8004 registry contract. Use a library like ethers.js, viem, or cast to produce the full calldata with dynamic type encoding.",
            "example_registry_addresses": {
                "ethereum_mainnet": "TBD — ERC-8004 is a draft standard",
                "sepolia_testnet": "TBD — ERC-8004 is a draft standard",
            },
        }))
    }

    #[tool(description = "Look up an AI agent in the ERC-8004 Agent Registry by agent ID (uint256) or owner address. Builds the calldata for getAgent(uint256) or getAgentsByOwner(address) that can be used with eth_call_contract against a deployed ERC-8004 registry.")]
    async fn eth_lookup_agent_8004(
        &self,
        Parameters(params): Parameters<EthLookupAgent8004Params>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let input = params.agent_id_or_address.trim();
        if input.is_empty() {
            return Err(err_invalid_params(
                "agent_id_or_address cannot be empty",
            ));
        }

        let clean = strip_0x(input);
        let is_address = clean.len() == 40
            && clean.chars().all(|c| c.is_ascii_hexdigit());

        if is_address {
            // getAgentsByOwner(address)
            let sig = "getAgentsByOwner(address)";
            let sel = function_selector(sig);
            let selector_hex = hex::encode(sel);
            let padded_addr = pad_to_32_bytes(clean);
            let calldata = format!("0x{}{}", selector_hex, padded_addr);

            json_result(serde_json::json!({
                "erc_standard": "ERC-8004",
                "lookup_type": "by_owner",
                "function": sig,
                "selector": format!("0x{}", selector_hex),
                "address": normalize_hex(input),
                "calldata": calldata,
                "note": "Send this calldata via eth_call_contract to an ERC-8004 registry contract to retrieve agents owned by this address. ERC-8004 is a draft standard — registry contracts may not be deployed on all chains.",
            }))
        } else {
            // getAgent(uint256 agentId)
            let sig = "getAgent(uint256)";
            let sel = function_selector(sig);
            let selector_hex = hex::encode(sel);

            let agent_id_hex = if input.starts_with("0x") || input.starts_with("0X") {
                pad_to_32_bytes(clean)
            } else {
                let id: u128 = input
                    .parse()
                    .map_err(|_| err_invalid_params("agent_id must be a decimal number or hex value"))?;
                format!("{:064x}", id)
            };

            let calldata = format!("0x{}{}", selector_hex, agent_id_hex);

            json_result(serde_json::json!({
                "erc_standard": "ERC-8004",
                "lookup_type": "by_id",
                "function": sig,
                "selector": format!("0x{}", selector_hex),
                "agent_id": input,
                "calldata": calldata,
                "note": "Send this calldata via eth_call_contract to an ERC-8004 registry contract to retrieve agent details. ERC-8004 is a draft standard — registry contracts may not be deployed on all chains.",
            }))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  6. EAS (Ethereum Attestation Service)
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Query an attestation from Ethereum Attestation Service (EAS) by UID. Posts a GraphQL query to the EAS indexer at easscan.org. Returns attester, recipient, schema, data, timestamp, revocation status, and decoded data when available.")]
    async fn eth_get_attestation(
        &self,
        Parameters(params): Parameters<EthGetAttestationParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let uid = normalize_hex(&params.uid);

        let graphql_query = serde_json::json!({
            "query": r#"
                query GetAttestation($uid: String!) {
                    attestation(where: { id: $uid }) {
                        id
                        attester
                        recipient
                        refUID
                        revocable
                        revoked
                        revocationTime
                        expirationTime
                        time
                        txid
                        data
                        decodedDataJson
                        schemaId
                        schema {
                            id
                            schema
                            creator
                            resolver
                            revocable
                        }
                    }
                }
            "#,
            "variables": {
                "uid": uid,
            },
        });

        let resp = self
            .http
            .post("https://easscan.org/graphql")
            .json(&graphql_query)
            .send()
            .await
            .map_err(|e| err_internal(format!("EAS GraphQL request failed: {}", e)))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read EAS response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "EAS GraphQL returned HTTP {}: {}",
                status, body
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| err_internal(format!("Failed to parse EAS response: {}", e)))?;

        if let Some(attestation) = json
            .pointer("/data/attestation")
            .filter(|v| !v.is_null())
        {
            json_result(serde_json::json!({
                "uid": uid,
                "attestation": attestation,
                "source": "easscan.org",
            }))
        } else {
            let errors = json.get("errors");
            json_result(serde_json::json!({
                "uid": uid,
                "attestation": null,
                "error": "Attestation not found",
                "graphql_errors": errors,
                "source": "easscan.org",
            }))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  7. Transaction submission
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Broadcast a pre-signed Ethereum transaction via eth_sendRawTransaction. Params: raw_tx (hex-encoded RLP-signed transaction, with or without 0x prefix). Returns the resulting transaction hash as plain text. Use eth_encode_function + eth_estimate_gas + an external signer (or tenzro_signTransaction with chain_id matching the target EVM chain) to build the raw_tx.")]
    async fn eth_send_raw_transaction(
        &self,
        Parameters(params): Parameters<EthSendRawTransactionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let raw = normalize_hex(&params.raw_tx);
        let resp_value = self
            .rpc_call("eth_sendRawTransaction", serde_json::json!([raw]))
            .await
            .map_err(|e| err_internal(format!("eth_sendRawTransaction failed: {}", e)))?;

        let tx_hash = resp_value
            .as_str()
            .ok_or_else(|| err_internal(format!(
                "eth_sendRawTransaction returned non-string result: {}",
                resp_value
            )))?
            .to_string();

        text_result(tx_hash)
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for EthereumMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-ethereum".into();
        impl_info.title = Some("Tenzro Ethereum MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "Ethereum blockchain tools — DeFi, ERC-20/721, ENS, ERC-8004 agent registry, EAS attestations"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro Ethereum MCP Server — interact with Ethereum mainnet and EVM chains.\n\n\
             TOOLS BY CATEGORY:\n\n\
             DeFi Tools:\n\
             - eth_get_price — Get token price from Chainlink data feed (default: ETH/USD)\n\
             - eth_get_gas_price — Get current gas price in Gwei\n\
             - eth_estimate_gas — Estimate gas for a transaction\n\
             - eth_get_fee_history — Get EIP-1559 fee history for recent blocks\n\n\
             Account Tools:\n\
             - eth_get_balance — Get ETH balance of an address\n\
             - eth_get_token_balance — Get ERC-20 token balance via balanceOf()\n\
             - eth_get_transaction — Get transaction details by hash\n\
             - eth_get_block — Get block by number with header and transactions\n\
             - eth_get_transaction_receipt — Get transaction receipt with logs and status\n\n\
             ENS Tools:\n\
             - eth_resolve_ens — Resolve ENS name to Ethereum address\n\
             - eth_lookup_ens — Reverse-lookup address to ENS name\n\n\
             Smart Contract Tools:\n\
             - eth_call_contract — Execute read-only eth_call with custom calldata\n\
             - eth_encode_function — ABI-encode a function call (selector + padded args)\n\n\
             ERC-8004 Agent Registry:\n\
             - eth_register_agent_8004 — Build registerAgent() calldata for ERC-8004\n\
             - eth_lookup_agent_8004 — Build getAgent()/getAgentsByOwner() calldata for ERC-8004\n\n\
             EAS (Ethereum Attestation Service):\n\
             - eth_get_attestation — Query attestation by UID from easscan.org GraphQL\n\n\
             Transaction Submission:\n\
             - eth_send_raw_transaction — Broadcast a pre-signed RLP transaction; returns the tx hash"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// Start the Ethereum MCP server as a standalone Streamable HTTP service.
pub async fn start_ethereum_mcp_server(listen_addr: String) -> crate::error::Result<()> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_ethereum_mcp_server_with_shutdown(listen_addr, shutdown_rx).await
}

/// Start the Ethereum MCP server with a graceful-shutdown channel.
pub async fn start_ethereum_mcp_server_with_shutdown(
    listen_addr: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> crate::error::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService, StreamableHttpServerConfig,
    };

    // If `ETHEREUM_RPC_URL` is set, scope the per-session server to it via
    // `with_rpc_url`. Otherwise fall back to `default_mainnet()`, which
    // resolves the dRPC/LlamaRPC mainnet URL via the same logic
    // `EthereumMcpServer::new("")` uses internally.
    let rpc_url_override = std::env::var("ETHEREUM_RPC_URL").ok();

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "ethereum-mcp.tenzro.network".to_string(),
        ]);

    let service = StreamableHttpService::new(
        move || {
            let server = match rpc_url_override.clone() {
                Some(url) => EthereumMcpServer::default_mainnet().with_rpc_url(url),
                None => EthereumMcpServer::default_mainnet(),
            };
            Ok(server)
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .route(
            "/health",
            axum::routing::get(|| async { "ok" }),
        )
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        tools = 16,
        mode = "stateless-json",
        "Ethereum MCP Server listening (endpoint: /mcp)"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Ethereum MCP server shutting down gracefully");
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_parameter_schemas() {
        let _schema = schemars::schema_for!(EthGetPriceParams);
        let _schema = schemars::schema_for!(EthGetGasPriceParams);
        let _schema = schemars::schema_for!(EthEstimateGasParams);
        let _schema = schemars::schema_for!(EthGetFeeHistoryParams);
        let _schema = schemars::schema_for!(EthGetBalanceParams);
        let _schema = schemars::schema_for!(EthGetTokenBalanceParams);
        let _schema = schemars::schema_for!(EthGetTransactionParams);
        let _schema = schemars::schema_for!(EthGetBlockParams);
        let _schema = schemars::schema_for!(EthGetTransactionReceiptParams);
        let _schema = schemars::schema_for!(EthResolveEnsParams);
        let _schema = schemars::schema_for!(EthLookupEnsParams);
        let _schema = schemars::schema_for!(EthCallContractParams);
        let _schema = schemars::schema_for!(EthEncodeFunctionParams);
        let _schema = schemars::schema_for!(EthRegisterAgent8004Params);
        let _schema = schemars::schema_for!(EthLookupAgent8004Params);
        let _schema = schemars::schema_for!(EthGetAttestationParams);
    }

    #[test]
    fn test_normalize_hex() {
        assert_eq!(normalize_hex("abc"), "0xabc");
        assert_eq!(normalize_hex("0xabc"), "0xabc");
        assert_eq!(normalize_hex("0XABC"), "0XABC");
    }

    #[test]
    fn test_strip_0x() {
        assert_eq!(strip_0x("0xabc"), "abc");
        assert_eq!(strip_0x("0XABC"), "ABC");
        assert_eq!(strip_0x("abc"), "abc");
    }

    #[test]
    fn test_pad_to_32_bytes() {
        assert_eq!(pad_to_32_bytes("1"), format!("{:0>64}", "1"));
        assert_eq!(pad_to_32_bytes("0x1"), format!("{:0>64}", "1"));
        let full = "a".repeat(64);
        assert_eq!(pad_to_32_bytes(&full), full);
    }

    #[test]
    fn test_hex_to_u128() {
        assert_eq!(hex_to_u128("0x1").unwrap(), 1);
        assert_eq!(hex_to_u128("0xff").unwrap(), 255);
        assert_eq!(hex_to_u128("0xde0b6b3a7640000").unwrap(), 1_000_000_000_000_000_000);
        assert_eq!(hex_to_u128("").unwrap(), 0);
        assert!(hex_to_u128("0xZZZ").is_err());
    }

    #[test]
    fn test_wei_to_eth() {
        assert_eq!(wei_to_eth(1_000_000_000_000_000_000), "1.000000000000000000");
        assert_eq!(wei_to_eth(0), "0.000000000000000000");
        assert_eq!(wei_to_eth(500_000_000_000_000_000), "0.500000000000000000");
    }

    #[test]
    fn test_wei_to_gwei() {
        assert_eq!(wei_to_gwei(1_000_000_000), "1.000000000");
        assert_eq!(wei_to_gwei(20_000_000_000), "20.000000000");
    }

    #[test]
    fn test_function_selector() {
        // transfer(address,uint256) => 0xa9059cbb
        let sel = function_selector("transfer(address,uint256)");
        assert_eq!(hex::encode(sel), "a9059cbb");

        // balanceOf(address) => 0x70a08231
        let sel2 = function_selector("balanceOf(address)");
        assert_eq!(hex::encode(sel2), "70a08231");

        // approve(address,uint256) => 0x095ea7b3
        let sel3 = function_selector("approve(address,uint256)");
        assert_eq!(hex::encode(sel3), "095ea7b3");
    }

    #[test]
    fn test_namehash_empty() {
        let hash = namehash("");
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn test_namehash_eth() {
        // Well-known: namehash('eth') = 0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae
        let hash = namehash("eth");
        let expected =
            hex::decode("93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_namehash_vitalik_eth() {
        let hash = namehash("vitalik.eth");
        assert_ne!(hash, [0u8; 32]);
        assert_ne!(hash, namehash("eth"));
    }

    #[test]
    fn test_dns_encode_name() {
        let encoded = dns_encode_name("vitalik.eth");
        assert_eq!(encoded[0], 7); // "vitalik" length
        assert_eq!(&encoded[1..8], b"vitalik");
        assert_eq!(encoded[8], 3); // "eth" length
        assert_eq!(&encoded[9..12], b"eth");
        assert_eq!(encoded[12], 0); // root terminator
    }

    #[test]
    fn test_extract_address_from_resolver() {
        let hex = format!(
            "{}{}{}",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045",
        );
        let addr = extract_address_from_resolver(&hex);
        assert_eq!(
            addr,
            Some("0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_string())
        );
    }

    #[test]
    fn test_extract_address_from_resolver_not_found() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000040\
                    0000000000000000000000000000000000000000000000000000000000000000";
        assert!(extract_address_from_resolver(hex).is_none());
    }

    #[test]
    fn test_encode_resolve_calldata_structure() {
        let name = dns_encode_name("vitalik.eth");
        let node = namehash("vitalik.eth");
        let mut inner = vec![0x3b, 0x3b, 0x57, 0xde];
        inner.extend_from_slice(&node);

        let calldata = encode_resolve_calldata(&name, &inner);

        // Should start with resolve() selector
        assert!(calldata.starts_with("9061b923"));
        // Should contain the offset words and encoded data
        assert!(calldata.len() > 8 + 128); // selector + at least two offsets and some data
    }
}
